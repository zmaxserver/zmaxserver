use crate::web_engine::cache_policy::{append_domain_and_uri_cache_tags, response_forbids_cache};
use crate::web_engine::context::ResolvedVHostContext;
use crate::web_engine::http_write::{write_http_response, write_not_found};
use crate::web_engine::MAX_GZIP_IN_MEMORY_BYTES;
use crate::api::{ParsedHttpRequest, ServerState};
use crate::modules_runtime::append_error_log_limit;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWrite;
use zmax_cache::{parse_lscache_headers, CachedResponse};
use zmax_compress::{gzip_compress, is_compressible_mime};
use zmax_fastcgi::{FastCgiClient, FastCgiRequest};

pub(crate) struct PreparedPhpResponse {
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) content_type: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) applied_gzip: bool,
    /// Yanıt (Set-Cookie, Cache-Control, X-LiteSpeed-Cache-Control) önbelleğe alınmayı yasaklıyor.
    pub(crate) cache_forbidden: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn execute_and_prepare_php(
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    vhost_ctx: &ResolvedVHostContext,
    script_rel_path: &str,
    path_info: &str,
    effective_query: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    php_cacheable_req: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
    is_head: bool,
) -> Result<Option<PreparedPhpResponse>, Box<dyn std::error::Error + Send + Sync>> {
    let clean_rel = script_rel_path.trim_start_matches('/');
    let script_filename = vhost_ctx.doc_root.join(clean_rel);
    if !script_filename.is_file() {
        return Ok(None);
    }

    let script_str = script_filename.to_string_lossy().into_owned();
    let doc_root_str = vhost_ctx.doc_root.to_string_lossy().into_owned();
    let script_name = format!("/{}", clean_rel);
    let request_uri = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let remote_ip_str = real_ip.to_string();

    // [kart-8] FastCGI havuzlu bağlantı yürütme (PooledClient / execute_php_pooled)
    let fcgi_req = {
        let mut r = FastCgiRequest::new(
            &req.method,
            &request_uri,
            &script_name,
            &script_str,
            &doc_root_str,
        )
        .query_string(effective_query)
        .host(&req.host)
        .remote_addr(&remote_ip_str)
        .remote_port(remote_port)
        .server_port(server_port)
        .is_https(is_https)
        .headers(req.headers.clone())
        .body(req.body.clone());

        if !path_info.trim().is_empty() {
            let translated = vhost_ctx
                .doc_root
                .join(path_info.trim_start_matches('/'))
                .to_string_lossy()
                .into_owned();
            r = r.path_info(path_info).path_translated(translated);
        }
        r
    };

    let fcgi_client =
        FastCgiClient::with_pool(&vhost_ctx.php_upstream, Arc::clone(&state.upstream_pool));
    // [kart-8] Sabit 5 sn yerine yapılandırmadan (vhost.php.dial_timeout_ms / mod_fastcgi) gelen bağlantı zaman aşımı
    let dial_timeout = Duration::from_millis(vhost_ctx.php_dial_timeout_ms.max(1));
    let fcgi_resp = fcgi_client
        .execute_php_pooled(
            fcgi_req,
            dial_timeout,
            Duration::from_secs(vhost_ctx.php_timeout),
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    if !fcgi_resp.stderr.trim().is_empty() {
        append_error_log_limit(
            &state.base_dir,
            &format!(
                "[PHP STDERR] ({}): {}",
                script_name,
                fcgi_resp.stderr.trim()
            ),
            vhost_ctx.max_log_size_bytes,
        )
        .await;
    }

    let (status, reason, cgi_headers, php_body) =
        FastCgiClient::split_cgi_headers_with_reason(&fcgi_resp.raw_stdout);

    let content_type = cgi_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("text/html; charset=utf-8")
        .to_string();

    let upstream_encoded = cgi_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"));

    let should_gzip = wants_gzip
        && !is_head
        && !upstream_encoded
        && php_body.len() >= gzip_policy.min_length
        && php_body.len() <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(&content_type, &gzip_policy.mime_types);

    let (final_body, applied_gzip) = if should_gzip {
        let gz = gzip_compress(php_body);
        if gz.len() < php_body.len() {
            (gz, true)
        } else {
            (php_body.to_vec(), false)
        }
    } else {
        (php_body.to_vec(), false)
    };

    let mut out_headers: Vec<(String, String)> = cgi_headers
        .into_iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-length"))
        .collect();

    if applied_gzip {
        out_headers.push(("Content-Encoding".into(), "gzip".into()));
        out_headers.push(("Vary".into(), "Accept-Encoding".into()));
    }

    // [matris-cache-tags] LSCache başlık köprüsü (X-LiteSpeed-Cache-Control / -Tag / -Purge)
    let lscache = {
        let hdr_refs: Vec<(&str, &str)> = out_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        parse_lscache_headers(hdr_refs)
    };

    // Uygulamanın tetiklediği temizlik yalnız bu vhost'un `alan::etiket` kayıtlarını siler.
    if lscache.purge_all || !lscache.purge_tags.is_empty() {
        state
            .cache
            .apply_lscache_purge(&vhost_ctx.vhost_name, &lscache)
            .await;
    }

    // `public` yönergesi Set-Cookie / Cache-Control: private|no-store|no-cache yasaklarını ASLA aşmaz.
    let cache_forbidden = response_forbids_cache(&out_headers)
        || lscache.cacheable == Some(false)
        || lscache.is_private;
    let effective_ttl = lscache.max_age_secs.unwrap_or(vhost_ctx.cache_expire);

    let cache_eligible = php_cacheable_req
        && status == 200
        && !cache_forbidden
        && effective_ttl > 0
        && final_body.len() <= cache_max_object_bytes;

    if cache_eligible {
        let mut tags = Vec::new();
        append_domain_and_uri_cache_tags(&mut tags, &vhost_ctx.vhost_name, &req.path);
        for tag in &lscache.tags {
            let domain_tag = zmax_cache::ZMaxCache::format_domain_tag(&vhost_ctx.vhost_name, tag);
            for t in [tag.clone(), domain_tag] {
                if !tags.iter().any(|existing| existing == &t) {
                    tags.push(t);
                }
            }
        }
        if applied_gzip {
            tags.push("__enc:gzip".to_string());
        }
        state
            .cache
            .set_with_ttl_and_stale(
                cache_key.to_string(),
                CachedResponse {
                    status,
                    content_type: content_type.clone(),
                    body: bytes::Bytes::from(final_body.clone()),
                    tags,
                },
                effective_ttl,
                vhost_ctx.cache_stale_sec,
            )
            .await;
    }

    // Dahili LSCache yönergeleri istemciye sızdırılmaz.
    out_headers.retain(|(k, _)| {
        !(k.eq_ignore_ascii_case("x-litespeed-tag")
            || k.eq_ignore_ascii_case("x-litespeed-purge")
            || k.eq_ignore_ascii_case("x-litespeed-cache-control"))
    });

    Ok(Some(PreparedPhpResponse {
        status,
        reason,
        content_type,
        headers: out_headers,
        body: final_body,
        applied_gzip,
        cache_forbidden,
    }))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_and_cache_php(
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    vhost_ctx: &ResolvedVHostContext,
    script_rel_path: &str,
    path_info: &str,
    effective_query: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    php_cacheable_req: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let prepared = execute_and_prepare_php(
        state,
        req,
        real_ip,
        remote_port,
        server_port,
        is_https,
        vhost_ctx,
        script_rel_path,
        path_info,
        effective_query,
        wants_gzip,
        gzip_policy,
        php_cacheable_req,
        cache_key,
        cache_max_object_bytes,
        false,
    )
    .await?;
    let _ = prepared.as_ref().map(|p| (&p.content_type, p.applied_gzip));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_php_request<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    vhost_ctx: &ResolvedVHostContext,
    script_rel_path: &str,
    path_info: &str,
    effective_query: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    php_cacheable_req: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
) -> Result<(u16, usize), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let sec_ref = vhost_ctx.headers_policy.as_ref();

    match execute_and_prepare_php(
        state,
        req,
        real_ip,
        remote_port,
        server_port,
        is_https,
        vhost_ctx,
        script_rel_path,
        path_info,
        effective_query,
        wants_gzip,
        gzip_policy,
        php_cacheable_req,
        cache_key,
        cache_max_object_bytes,
        is_head,
    )
    .await
    {
        Ok(Some(prep)) => {
            let status = prep.status;
            // [kart-2] FastCGI yanitinda HEAD, 204 veya 304 durumunda govde bayti 0 iletilir
            let body_len = if is_head || status == 204 || status == 304 {
                0
            } else {
                prep.body.len()
            };
            let cache_status = if !php_cacheable_req || prep.cache_forbidden {
                Some("BYPASS")
            } else {
                Some("MISS")
            };
            write_http_response(
                socket,
                status,
                &prep.reason,
                &prep.headers,
                &prep.body,
                Some(prep.body.len()),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
                cache_status,
            )
            .await?;
            Ok((status, body_len))
        }
        Ok(None) => {
            let bytes_written = write_not_found(
                socket,
                Some(vhost_ctx),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
            )
            .await?;
            Ok((404, bytes_written))
        }
        Err(err) => {
            append_error_log_limit(
                &state.base_dir,
                &format!(
                    "[FastCGI Hata] upstream={} err={}",
                    vhost_ctx.php_upstream, err
                ),
                vhost_ctx.max_log_size_bytes,
            )
            .await;
            let err_msg = b"<!DOCTYPE html><html><body style='font-family:sans-serif;background:#090d16;color:#f8fafc;padding:40px;'><h2>502 Bad Gateway - FastCGI Upstream Kapali</h2><p>PHP-FPM/LSPHP servisi baglanti kuramadi.</p></body></html>";
            write_http_response(
                socket,
                502,
                "Bad Gateway",
                &[("Content-Type".into(), "text/html; charset=utf-8".into())],
                err_msg,
                Some(err_msg.len()),
                is_head,
                is_https,
                false,
                keep_alive_timeout_sec,
                sec_ref,
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_msg.len() };
            Ok((502, sent_err_bytes))
        }
    }
}
