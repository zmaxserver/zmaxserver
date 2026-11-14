//! L7 — Statik Dosya Sunumu ve Müzakere İşleyicisi
//! `sendfile(2)` sıfır-kopya aktarımı, byte-range (206), ETag / 304, WebP/AVIF içerik müzakeresi.

use crate::api::{ParsedHttpRequest, ServerState};
use crate::pipeline::l8_response::{write_http_head, write_http_response};
use crate::pipeline::l6_cache::append_domain_and_uri_cache_tags;
use crate::pipeline::l5_router::ResolvedVHostContext;
use crate::web_engine::{MAX_GZIP_IN_MEMORY_BYTES, MAX_STATIC_CACHE_BYTES};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
use tokio::io::AsyncSeekExt;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zmax_cache::CachedResponse;
use zmax_compress::{gzip_compress, is_compressible_mime};
use zmax_httpparser::extract_header;
use zmax_static::{check_if_none_match, is_sendfile_supported, parse_byte_range, ByteRangeResult, StaticFileHandler};

// =========================================================================
// 1. WEBP / AVIF GÖRSEL İÇERİK MÜZAKERESİ (Image Negotiation)
// =========================================================================

pub fn accept_supports_media_type(accept_lower: &str, media_type: &str) -> bool {
    accept_lower.split(',').any(|item| {
        let mut parts = item.split(';');
        let mime = parts.next().unwrap_or("").trim();
        if mime != media_type {
            return false;
        }
        for param in parts {
            let Some((key, val)) = param.split_once('=') else {
                continue;
            };
            if key.trim() != "q" {
                continue;
            }
            if let Ok(q) = val.trim().parse::<f32>() {
                if q.is_finite() && q <= 0.0 {
                    return false;
                }
            }
        }
        true
    })
}

pub fn find_safe_negotiated_variant(
    orig_path: &Path,
    orig_parent: &Path,
    canon_parent: &Path,
    target_ext: &str,
) -> Option<PathBuf> {
    let file_name = orig_path.file_name()?;
    let stem = orig_path.file_stem()?;

    let mut append_name = file_name.to_os_string();
    append_name.push(".");
    append_name.push(target_ext);

    let mut replace_name = stem.to_os_string();
    replace_name.push(".");
    replace_name.push(target_ext);

    let candidates = [
        orig_parent.join(append_name),
        orig_parent.join(replace_name),
    ];

    for cand in candidates {
        let Ok(canon_cand) = std::fs::canonicalize(&cand) else {
            continue;
        };
        let is_regular_file = std::fs::metadata(&canon_cand).is_ok_and(|m| m.is_file());
        if is_regular_file && canon_cand.parent() == Some(canon_parent) {
            return Some(canon_cand);
        }
    }
    None
}

/// Tarayıcının `Accept` başlığına göre `.jpg`, `.jpeg` ve `.png` dosyaları için güvenli biçimde `.avif` veya `.webp` varyantını seçer.
pub fn select_negotiated_image_path(
    orig_path: &Path,
    accept_header: Option<&str>,
    allow_avif: bool,
    allow_webp: bool,
) -> Option<(PathBuf, &'static str)> {
    if !allow_avif && !allow_webp {
        return None;
    }
    let ext = orig_path.extension().and_then(|e| e.to_str())?;
    if !(ext.eq_ignore_ascii_case("jpg")
        || ext.eq_ignore_ascii_case("jpeg")
        || ext.eq_ignore_ascii_case("png"))
    {
        return None;
    }

    let accept = accept_header?.trim();
    if accept.is_empty() {
        return None;
    }
    let accept_lower = accept.to_ascii_lowercase();

    let orig_parent = orig_path.parent()?;
    let parent_for_canon = if orig_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        orig_parent
    };
    let canon_parent = std::fs::canonicalize(parent_for_canon).ok()?;

    if allow_avif && accept_supports_media_type(&accept_lower, "image/avif") {
        if let Some(canon_avif) =
            find_safe_negotiated_variant(orig_path, orig_parent, &canon_parent, "avif")
        {
            return Some((canon_avif, "image/avif"));
        }
    }

    if allow_webp && accept_supports_media_type(&accept_lower, "image/webp") {
        if let Some(canon_webp) =
            find_safe_negotiated_variant(orig_path, orig_parent, &canon_parent, "webp")
        {
            return Some((canon_webp, "image/webp"));
        }
    }

    None
}

pub fn is_negotiable_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            ext.eq_ignore_ascii_case("jpg")
                || ext.eq_ignore_ascii_case("jpeg")
                || ext.eq_ignore_ascii_case("png")
        })
        .unwrap_or(false)
}

pub fn negotiable_image_cache_tag(
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

// =========================================================================
// 2. SENDFILE VE TAMPONLU AKIŞ (Stream & Zero-Copy)
// =========================================================================

#[cfg(target_os = "linux")]
pub async fn try_stream_tcp_sendfile(
    tcp_stream: &mut TcpStream,
    file: &tokio::fs::File,
    offset: &mut u64,
    remaining: &mut u64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::io::AsRawFd;

    tcp_stream.flush().await?;
    let out_fd = tcp_stream.as_raw_fd();
    let in_fd = file.as_raw_fd();
    let sendfile_write_timeout = Duration::from_secs(30);

    while *remaining > 0 {
        tokio::time::timeout(sendfile_write_timeout, tcp_stream.writable())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "sendfile soket yazma zaman aşımı",
                )
            })??;
        let chunk_cap = usize::try_from(*remaining)
            .unwrap_or(usize::MAX)
            .min(1024 * 1024);
        match tcp_stream.try_io(tokio::io::Interest::WRITABLE, || {
            zmax_static::try_sendfile_chunk(out_fd, in_fd, offset, chunk_cap)
        }) {
            Ok(0) => {
                return Ok(false);
            }
            Ok(n) => {
                let n_u64 = u64::try_from(n).unwrap_or(*remaining);
                *remaining = remaining.saturating_sub(n_u64);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
                ) || matches!(
                    err.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSOCK | libc::EOPNOTSUPP)
                ) =>
            {
                return Ok(false);
            }
            Err(err) => return Err(Box::new(err)),
        }
    }

    Ok(true)
}

pub async fn stream_file_range_pooled<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    file: &mut tokio::fs::File,
    file_offset: u64,
    mut remaining: u64,
    is_https: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin + 'static,
{
    // [kart-8] Linux düz TCP (!is_https) statik aktarımında gerçek `sendfile(2)` sıfır-kopya yolu.
    if !is_https && is_sendfile_supported() {
        if let Some(_tcp_stream) = (socket as &mut dyn std::any::Any).downcast_mut::<TcpStream>() {
            #[cfg(target_os = "linux")]
            {
                let mut cur_offset = file_offset;
                if try_stream_tcp_sendfile(_tcp_stream, file, &mut cur_offset, &mut remaining)
                    .await?
                {
                    return Ok(());
                }
                file.seek(std::io::SeekFrom::Start(cur_offset)).await?;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file_offset;

    let mut buf = state.buffer_pool.acquire();
    while remaining > 0 {
        let chunk_cap = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.capacity());
        let read_n = file.read(&mut buf[..chunk_cap]).await?;
        if read_n == 0 {
            break;
        }
        socket.write_all(&buf[..read_n]).await?;
        remaining = remaining.saturating_sub(read_n as u64);
    }
    Ok(())
}

// =========================================================================
// 3. STATİK DOSYA SUNUMU (Serve Static File)
// =========================================================================

/// Önceden `zmax-rewrite` tarafından decode/doğrulanmış yolu çözer.
pub fn resolve_predecoded_static_file(
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
pub async fn serve_static_file<S>(
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
            true,
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

    // 3. Tam dosya sunumu (HEAD)
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
        return Ok((200, 0));
    }

    let can_try_gzip = wants_gzip
        && (info.size as usize) >= gzip_policy.min_length
        && (info.size as usize) <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(info.mime_type, &gzip_policy.mime_types);

    // Büyük ve sıkıştırılmayacak dosyaları RAM'e almadan parçalarla akıt
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

#[allow(clippy::too_many_arguments)]
pub async fn revalidate_static_cache(
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

// =========================================================================
// 4. GERİYE DÖNÜK UYUMLULUK ALT MODÜLLERİ
// =========================================================================

pub mod serve {
    pub use super::{
        is_negotiable_image_path, negotiable_image_cache_tag, resolve_predecoded_static_file,
        revalidate_static_cache, serve_static_file,
    };
}

pub mod stream {
    pub use super::stream_file_range_pooled;
    #[cfg(target_os = "linux")]
    pub use super::try_stream_tcp_sendfile;
}

pub mod image_negotiation {
    pub use super::{
        accept_supports_media_type, find_safe_negotiated_variant, select_negotiated_image_path,
    };
}
