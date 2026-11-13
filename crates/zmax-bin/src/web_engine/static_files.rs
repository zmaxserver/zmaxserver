use super::cache_policy::append_domain_and_uri_cache_tags;
use super::context::ResolvedVHostContext;
use super::http_write::{write_http_head, write_http_response};
use super::static_stream::stream_file_range_pooled;
use super::{MAX_GZIP_IN_MEMORY_BYTES, MAX_STATIC_CACHE_BYTES};
use crate::api::{ParsedHttpRequest, ServerState};
use crate::modules_runtime::select_negotiated_image_path;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use zmax_cache::CachedResponse;
use zmax_compress::{gzip_compress, is_compressible_mime};
use zmax_httpparser::extract_header;
use zmax_static::{check_if_none_match, parse_byte_range, ByteRangeResult, StaticFileHandler};

/// Önceden `zmax-rewrite` tarafından decode/doğrulanmış yolu (ör. dosya adında literal `%` varsa) çözer.
pub(super) fn resolve_predecoded_static_file(
    doc_root: &Path,
    clean_path: &str,
) -> Option<zmax_static::StaticFileInfo> {
    let rel = clean_path.trim_matches('/');
    if rel.is_empty() || rel.contains('\0') || rel.contains('\\') || rel.contains("..") {
        return None;
    }
    let canon_root = std::fs::canonicalize(doc_root).ok()?;
    let canon_file = std::fs::canonicalize(doc_root.join(rel)).ok()?;
    if !canon_file.starts_with(&canon_root) || !canon_file.is_file() {
        return None;
    }
    let meta = std::fs::metadata(&canon_file).ok()?;
    let size = meta.len();
    let last_modified_secs = meta
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Some(zmax_static::StaticFileInfo {
        path: canon_file,
        mime_type: StaticFileHandler::detect_mime(Path::new(rel)),
        size,
        etag: format!("\"{:x}-{:x}\"", size, last_modified_secs),
        last_modified_secs,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_static_file<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    orig_info: &zmax_static::StaticFileInfo,
    vhost_ctx: &ResolvedVHostContext,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    can_use_cache: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
) -> Result<(u16, usize), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin + 'static,
{
    let sec_ref = vhost_ctx.headers_policy.as_ref();
    let accept_hdr = extract_header(&req.headers, "accept");
    let mut info = orig_info.clone();
    let image_negotiation_candidate =
        (vhost_ctx.auto_avif || vhost_ctx.auto_webp) && is_negotiable_image_path(&orig_info.path);

    if image_negotiation_candidate {
        if let Some((alt_path, alt_mime)) = select_negotiated_image_path(
            &orig_info.path,
            accept_hdr,
            vhost_ctx.auto_avif,
            vhost_ctx.auto_webp,
        ) {
            if let Ok(meta) = tokio::fs::metadata(&alt_path).await {
                let size = meta.len();
                let last_modified_secs = meta
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                info = zmax_static::StaticFileInfo {
                    path: alt_path,
                    mime_type: alt_mime,
                    size,
                    etag: format!("\"{:x}-{:x}\"", size, last_modified_secs),
                    last_modified_secs,
                };
            }
        }
    }

    let last_mod = info.last_modified_http();

    // 1. ETag / If-None-Match -> 304 Not Modified
    if vhost_ctx.etag_enabled && check_if_none_match(&req.headers, &info.etag) {
        let mut hdrs = vec![("Accept-Ranges".into(), "bytes".into())];
        hdrs.push(("ETag".into(), info.etag.clone()));
        if vhost_ctx.last_modified_header {
            hdrs.push(("Last-Modified".into(), last_mod));
        }
        if image_negotiation_candidate {
            hdrs.push(("Vary".into(), "Accept".into()));
        }
        write_http_response(
            socket,
            304,
            "Not Modified",
            &hdrs,
            b"",
            Some(0),
            true, // 304 gövdesizdir
            is_https,
            keep_alive,
            keep_alive_timeout_sec,
            sec_ref,
            None,
        )
        .await?;
        return Ok((304, 0));
    }

    // 2. Range başlığı -> 206 Partial Content veya 416 Range Not Satisfiable
    if let Some(range_val) = extract_header(&req.headers, "range") {
        match parse_byte_range(range_val, info.size) {
            ByteRangeResult::Single {
                start,
                end_inclusive,
            } => {
                let slice_len = (end_inclusive - start + 1) as usize;
                let mut hdrs = vec![
                    ("Content-Type".into(), info.mime_type.to_string()),
                    (
                        "Content-Range".into(),
                        format!("bytes {}-{}/{}", start, end_inclusive, info.size),
                    ),
                    ("Accept-Ranges".into(), "bytes".into()),
                ];
                if vhost_ctx.etag_enabled {
                    hdrs.push(("ETag".into(), info.etag.clone()));
                }
                if vhost_ctx.last_modified_header {
                    hdrs.push(("Last-Modified".into(), last_mod));
                }
                if image_negotiation_candidate {
                    hdrs.push(("Vary".into(), "Accept".into()));
                }
                if is_head {
                    write_http_response(
                        socket,
                        206,
                        "Partial Content",
                        &hdrs,
                        b"",
                        Some(slice_len),
                        true,
                        is_https,
                        keep_alive,
                        keep_alive_timeout_sec,
                        sec_ref,
                        None,
                    )
                    .await?;
                    // [kart-2] HEAD yanitlarinda govde gonderilmez; gercek bayt 0
                    return Ok((206, 0));
                }

                let mut file = tokio::fs::File::open(&info.path).await?;
                file.seek(std::io::SeekFrom::Start(start)).await?;
                if slice_len <= MAX_STATIC_CACHE_BYTES {
                    let mut part = Vec::with_capacity(slice_len);
                    let mut limited = file.take(slice_len as u64);
                    limited.read_to_end(&mut part).await?;
                    write_http_response(
                        socket,
                        206,
                        "Partial Content",
                        &hdrs,
                        &part,
                        Some(part.len()),
                        false,
                        is_https,
                        keep_alive,
                        keep_alive_timeout_sec,
                        sec_ref,
                        None,
                    )
                    .await?;
                } else {
                    write_http_head(
                        socket,
                        206,
                        "Partial Content",
                        &hdrs,
                        Some(slice_len),
                        is_https,
                        keep_alive,
                        keep_alive_timeout_sec,
                        sec_ref,
                        None,
                    )
                    .await?;
                    // [kart-8] Büyük byte-range aktarımı: düz TCP üzerinde gerçek sendfile(2), TLS'te tamponlu yedek
                    stream_file_range_pooled(
                        socket,
                        state,
                        &mut file,
                        start,
                        slice_len as u64,
                        is_https,
                    )
                    .await?;
                    let _ = socket.flush().await;
                    if !keep_alive {
                        let _ = socket.shutdown().await;
                    }
                }
                return Ok((206, slice_len));
            }
            ByteRangeResult::Unsatisfiable => {
                let hdrs = vec![
                    ("Content-Range".into(), format!("bytes */{}", info.size)),
                    ("Accept-Ranges".into(), "bytes".into()),
                ];
                write_http_response(
                    socket,
                    416,
                    "Range Not Satisfiable",
                    &hdrs,
                    b"",
                    Some(0),
                    is_head,
                    is_https,
                    keep_alive,
                    keep_alive_timeout_sec,
                    sec_ref,
                    None,
                )
                .await?;
                return Ok((416, 0));
            }
            ByteRangeResult::None => {}
        }
    }

    // 3. Tam dosya sunumu (HEAD isteğinde diskten gövdeyi okumaya gerek yok!)
    if is_head {
        let mut hdrs = vec![
            ("Content-Type".into(), info.mime_type.to_string()),
            ("Accept-Ranges".into(), "bytes".into()),
        ];
        if vhost_ctx.etag_enabled {
            hdrs.push(("ETag".into(), info.etag.clone()));
        }
        if vhost_ctx.last_modified_header {
            hdrs.push(("Last-Modified".into(), last_mod));
        }
        if image_negotiation_candidate {
            hdrs.push(("Vary".into(), "Accept".into()));
        }
        write_http_response(
            socket,
            200,
            "OK",
            &hdrs,
            b"",
            Some(info.size as usize),
            true,
            is_https,
            keep_alive,
            keep_alive_timeout_sec,
            sec_ref,
            Some("MISS"),
        )
        .await?;
        // [kart-2] HEAD yanitinda Content-Length gonderilir ancak gercek gonderilen govde bayti 0'dir
        return Ok((200, 0));
    }

    let can_try_gzip = wants_gzip
        && (info.size as usize) >= gzip_policy.min_length
        && (info.size as usize) <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(info.mime_type, &gzip_policy.mime_types);

    // Büyük ve sıkıştırılmayacak dosyaları RAM'e almadan 64 KiB havuzlu parçalarla akıt (OOM koruması).
    if (info.size as usize) > MAX_STATIC_CACHE_BYTES && !can_try_gzip {
        let mut hdrs = vec![
            ("Content-Type".into(), info.mime_type.to_string()),
            ("Accept-Ranges".into(), "bytes".into()),
        ];
        if vhost_ctx.etag_enabled {
            hdrs.push(("ETag".into(), info.etag.clone()));
        }
        if vhost_ctx.last_modified_header {
            hdrs.push(("Last-Modified".into(), last_mod));
        }
        if image_negotiation_candidate {
            hdrs.push(("Vary".into(), "Accept".into()));
        } else if gzip_policy.vary_header {
            hdrs.push(("Vary".into(), "Accept-Encoding".into()));
        }

        write_http_head(
            socket,
            200,
            "OK",
            &hdrs,
            Some(info.size as usize),
            is_https,
            keep_alive,
            keep_alive_timeout_sec,
            sec_ref,
            Some("BYPASS"),
        )
        .await?;
        let mut file = tokio::fs::File::open(&info.path).await?;
        // [kart-8] Büyük tam dosya aktarımı: düz TCP üzerinde gerçek sendfile(2), TLS'te tamponlu yedek
        stream_file_range_pooled(socket, state, &mut file, 0, info.size, is_https).await?;
        let _ = socket.flush().await;
        if !keep_alive {
            let _ = socket.shutdown().await;
        }
        return Ok((200, info.size as usize));
    }

    let raw_bytes = tokio::fs::read(&info.path).await?;
    let can_gzip = can_try_gzip
        && raw_bytes.len() >= gzip_policy.min_length
        && raw_bytes.len() <= MAX_GZIP_IN_MEMORY_BYTES;

    let (final_bytes, encoded_gzip) = if can_gzip {
        let gz = gzip_compress(&raw_bytes);
        if gz.len() < raw_bytes.len() {
            (gz, true)
        } else {
            (raw_bytes, false)
        }
    } else {
        (raw_bytes, false)
    };

    if can_use_cache && final_bytes.len() <= cache_max_object_bytes.min(MAX_STATIC_CACHE_BYTES) {
        let mut tags = Vec::new();
        append_domain_and_uri_cache_tags(&mut tags, &vhost_ctx.vhost_name, &req.path);
        if vhost_ctx.etag_enabled {
            tags.push(format!("__etag:{}", info.etag));
        }
        if vhost_ctx.last_modified_header {
            tags.push(format!("__lm:{}", last_mod));
        }
        if encoded_gzip {
            tags.push("__enc:gzip".to_string());
        }
        if image_negotiation_candidate {
            tags.push("__vary:accept".to_string());
        }
        state
            .cache
            .set_with_ttl_and_stale(
                cache_key.to_string(),
                CachedResponse {
                    status: 200,
                    content_type: info.mime_type.to_string(),
                    body: bytes::Bytes::from(final_bytes.clone()),
                    tags,
                },
                vhost_ctx.cache_expire,
                vhost_ctx.cache_stale_sec,
            )
            .await;
    }

    let mut hdrs = vec![
        ("Content-Type".into(), info.mime_type.to_string()),
        ("Accept-Ranges".into(), "bytes".into()),
    ];
    if vhost_ctx.etag_enabled {
        hdrs.push(("ETag".into(), info.etag.clone()));
    }
    if vhost_ctx.last_modified_header {
        hdrs.push(("Last-Modified".into(), last_mod));
    }
    if encoded_gzip {
        hdrs.push(("Content-Encoding".into(), "gzip".into()));
    }
    match (gzip_policy.vary_header, image_negotiation_candidate) {
        (true, true) => hdrs.push(("Vary".into(), "Accept-Encoding, Accept".into())),
        (true, false) => hdrs.push(("Vary".into(), "Accept-Encoding".into())),
        (false, _) => hdrs.push(("Vary".into(), "Accept".into())),
    }

    let sent_len = final_bytes.len();
    let cache_status = if can_use_cache {
        Some("MISS")
    } else {
        Some("BYPASS")
    };
    write_http_response(
        socket,
        200,
        "OK",
        &hdrs,
        &final_bytes,
        Some(sent_len),
        false,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_ref,
        cache_status,
    )
    .await?;
    Ok((200, sent_len))
}

fn is_negotiable_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            ext.eq_ignore_ascii_case("jpg")
                || ext.eq_ignore_ascii_case("jpeg")
                || ext.eq_ignore_ascii_case("png")
        })
        .unwrap_or(false)
}

pub(super) fn negotiable_image_cache_tag(
    static_path: &str,
    accept_header: Option<&str>,
    auto_avif: bool,
    auto_webp: bool,
) -> &'static str {
    if !is_negotiable_image_path(Path::new(static_path)) || (!auto_avif && !auto_webp) {
        return "";
    }
    let lower = accept_header.unwrap_or("").to_ascii_lowercase();
    if auto_avif && lower.contains("image/avif") {
        return "+avif";
    }
    if auto_webp && lower.contains("image/webp") {
        return "+webp";
    }
    ""
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn revalidate_static_cache(
    state: &Arc<ServerState>,
    vhost_ctx: &ResolvedVHostContext,
    static_path: &str,
    accept_header: Option<&str>,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    cache_key: &str,
    cache_max_object_bytes: usize,
) {
    let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
    let Some(orig_info) = handler
        .resolve_with_index(static_path, &vhost_ctx.index_files)
        .or_else(|| resolve_predecoded_static_file(&vhost_ctx.doc_root, static_path))
    else {
        return;
    };

    let image_negotiation_candidate =
        (vhost_ctx.auto_avif || vhost_ctx.auto_webp) && is_negotiable_image_path(&orig_info.path);
    let mut info = orig_info;
    if image_negotiation_candidate {
        if let Some((alt_path, alt_mime)) = select_negotiated_image_path(
            &info.path,
            accept_header,
            vhost_ctx.auto_avif,
            vhost_ctx.auto_webp,
        ) {
            if let Ok(meta) = tokio::fs::metadata(&alt_path).await {
                let size = meta.len();
                let last_modified_secs = meta
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                info = zmax_static::StaticFileInfo {
                    path: alt_path,
                    mime_type: alt_mime,
                    size,
                    etag: format!("\"{:x}-{:x}\"", size, last_modified_secs),
                    last_modified_secs,
                };
            }
        }
    }

    if (info.size as usize) > MAX_STATIC_CACHE_BYTES {
        return;
    }
    let Ok(raw_bytes) = tokio::fs::read(&info.path).await else {
        return;
    };
    let can_gzip = wants_gzip
        && raw_bytes.len() >= gzip_policy.min_length
        && raw_bytes.len() <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(info.mime_type, &gzip_policy.mime_types);
    let (final_bytes, encoded_gzip) = if can_gzip {
        let gz = gzip_compress(&raw_bytes);
        if gz.len() < raw_bytes.len() {
            (gz, true)
        } else {
            (raw_bytes, false)
        }
    } else {
        (raw_bytes, false)
    };
    if final_bytes.len() > cache_max_object_bytes.min(MAX_STATIC_CACHE_BYTES) {
        return;
    }

    let mut tags = Vec::new();
    append_domain_and_uri_cache_tags(&mut tags, &vhost_ctx.vhost_name, static_path);
    if vhost_ctx.etag_enabled {
        tags.push(format!("__etag:{}", info.etag));
    }
    if vhost_ctx.last_modified_header {
        tags.push(format!("__lm:{}", info.last_modified_http()));
    }
    if encoded_gzip {
        tags.push("__enc:gzip".to_string());
    }
    if image_negotiation_candidate {
        tags.push("__vary:accept".to_string());
    }

    state
        .cache
        .set_with_ttl_and_stale(
            cache_key.to_string(),
            CachedResponse {
                status: 200,
                content_type: info.mime_type.to_string(),
                body: bytes::Bytes::from(final_bytes),
                tags,
            },
            vhost_ctx.cache_expire,
            vhost_ctx.cache_stale_sec,
        )
        .await;
}
