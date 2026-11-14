//! L8 — Yanıt Katmanı (Response Layer)
//! İstemciye yanıt yazımı, güvenlik başlıkları, hata sayfaları, NCSA loglama ve sıkıştırma.

use crate::api::ServerState;
use crate::web_engine::context::ResolvedVHostContext;
use crate::web_engine::DEFAULT_LOG_MAX_BYTES;
use crate::modules_runtime::append_access_log_limit;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use zmax_config::VHostEntry;
use zmax_header::SecurityHeadersPolicy;
use zmax_static::StaticFileHandler;

// =========================================================================
// 1. GÜVENLİK BAŞLIKLARI (Security Headers)
// =========================================================================

/// Sanal konak ve küresel `mod_headers` kurallarını birleştirerek yanıt başlığı politikası üretir.
pub fn resolve_vhost_security_headers(
    global_enabled: bool,
    global_policy: &SecurityHeadersPolicy,
    vhost: Option<&VHostEntry>,
) -> Option<SecurityHeadersPolicy> {
    let vh_sec = vhost.map(|v| v.headers.security_headers).unwrap_or(true);
    let vh_hsts = vhost.map(|v| v.headers.hsts).unwrap_or(false);
    if !global_enabled || !vh_sec {
        if vh_hsts {
            return Some(SecurityHeadersPolicy {
                hsts_enabled: true,
                x_frame_options: None,
                x_content_type_options: false,
                referrer_policy: None,
                content_security_policy: None,
                permissions_policy: None,
                ..SecurityHeadersPolicy::default()
            });
        }
        return None;
    }
    let mut p = global_policy.clone();
    p.hsts_enabled = global_policy.hsts_enabled || vh_hsts;
    Some(p)
}

// =========================================================================
// 2. DİNAMİK SIKIŞTIRMA (Dynamic Compression)
// =========================================================================

/// Gzip dinamik sıkıştırma yardımcısı (bellek içi sınır kontrollü).
pub fn compress_dynamic_content(
    body: &[u8],
    content_type: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    max_memory_bytes: usize,
) -> (Vec<u8>, bool) {
    if !wants_gzip || !gzip_policy.enabled || body.len() > max_memory_bytes || body.len() < 128 {
        return (body.to_vec(), false);
    }
    if !zmax_compress::is_compressible_mime(content_type) {
        return (body.to_vec(), false);
    }
    match zmax_compress::gzip_compress(body) {
        Ok(compressed) if compressed.len() < body.len() => (compressed, true),
        _ => (body.to_vec(), false),
    }
}

// =========================================================================
// 3. HTTP YANIT BAŞLIĞI VE GÖVDE YAZIMI (HTTP Write)
// =========================================================================

#[allow(clippy::too_many_arguments)]
pub fn format_http_response_head(
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    content_length: Option<usize>,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
    cache_status: Option<&str>,
) -> String {
    let mut head = format!("HTTP/1.1 {} {}\r\n", status, reason);
    if let Some(cs) = cache_status {
        head.push_str(&format!("X-Cache: {}\r\n", cs));
    }

    for (k, v) in headers {
        if k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("keep-alive")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let clean_val = v.replace(['\r', '\n'], "");
        head.push_str(&format!("{}: {}\r\n", k, clean_val));
    }

    if let Some(len) = content_length {
        head.push_str(&format!("Content-Length: {}\r\n", len));
    }

    if keep_alive {
        head.push_str(&format!(
            "Connection: keep-alive\r\nKeep-Alive: timeout={}\r\n",
            keep_alive_timeout_sec.max(1)
        ));
    } else {
        head.push_str("Connection: close\r\n");
    }

    head.push_str("\r\n");

    if let Some(policy) = sec_policy {
        policy.append_headers(&mut head, is_https);
    } else if !head.to_ascii_lowercase().contains("\r\nserver:") {
        head.truncate(head.len() - 2);
        head.push_str("Server: zmaxserver\r\n\r\n");
    }

    head
}

#[allow(clippy::too_many_arguments)]
pub async fn write_http_head<S>(
    socket: &mut S,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    explicit_content_length: Option<usize>,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
    cache_status: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let head = format_http_response_head(
        status,
        reason,
        headers,
        explicit_content_length,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
        cache_status,
    );
    socket.write_all(head.as_bytes()).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn write_http_response<S>(
    socket: &mut S,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    body: &[u8],
    explicit_content_length: Option<usize>,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
    cache_status: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let fallback_len = (status != 204 && status != 304).then_some(body.len());
    let head = format_http_response_head(
        status,
        reason,
        headers,
        explicit_content_length.or(fallback_len),
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
        cache_status,
    );

    socket.write_all(head.as_bytes()).await?;
    if !is_head && !body.is_empty() && status != 204 && status != 304 {
        socket.write_all(body).await?;
    }
    let _ = socket.flush().await;
    if !keep_alive {
        let _ = socket.shutdown().await;
    }
    Ok(())
}

pub async fn write_not_found<S>(
    socket: &mut S,
    vhost_ctx: Option<&ResolvedVHostContext>,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    write_error_response(
        socket,
        404,
        "Not Found",
        b"404 Not Found - ZMax Server",
        vhost_ctx,
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
    )
    .await
}

pub fn default_status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

/// VHost özel hata dokümanını (error_docs) arar; yoksa varsayılan hata mesajını döndürür.
pub async fn write_error_response<S>(
    socket: &mut S,
    status: u16,
    reason: &str,
    default_msg: &[u8],
    vhost_ctx: Option<&ResolvedVHostContext>,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let body_bytes: Vec<u8> = if let Some(ctx) = vhost_ctx {
        let rel_page_opt = ctx.error_docs.pages.get(&status).or_else(|| {
            if status == 404 {
                ctx.error_docs.not_found.as_ref()
            } else {
                None
            }
        });
        if let Some(rel_page) = rel_page_opt {
            let custom_dir = if ctx.error_docs.dir.trim().is_empty() {
                None
            } else {
                Some(Path::new(ctx.error_docs.dir.trim()))
            };
            let handler = StaticFileHandler::new(&ctx.doc_root);
            let loaded = handler
                .resolve_error_doc_file(&ctx.doc_root, custom_dir, rel_page)
                .unwrap_or_else(|_| default_msg.to_vec());
            if loaded.is_empty() {
                if default_msg.is_empty() {
                    format!("{} {}\n", status, reason).into_bytes()
                } else {
                    default_msg.to_vec()
                }
            } else {
                loaded
            }
        } else if default_msg.is_empty() {
            format!("{} {}\n", status, reason).into_bytes()
        } else {
            default_msg.to_vec()
        }
    } else if default_msg.is_empty() {
        format!("{} {}\n", status, reason).into_bytes()
    } else {
        default_msg.to_vec()
    };

    let content_type = if body_bytes.starts_with(b"<!DOCTYPE") || body_bytes.starts_with(b"<html") {
        "text/html; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };

    let written = if is_head || status == 204 || status == 304 {
        0
    } else {
        body_bytes.len()
    };
    write_http_response(
        socket,
        status,
        reason,
        &[("Content-Type".into(), content_type.into())],
        &body_bytes,
        Some(body_bytes.len()),
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
        None,
    )
    .await?;

    Ok(written)
}

// =========================================================================
// 4. ERİŞİM VE HATA LOGLAMA (Access & Error Logging)
// =========================================================================

#[allow(clippy::too_many_arguments)]
pub async fn record_and_log(
    state: &Arc<ServerState>,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    started: Instant,
    vhost_ctx: Option<&ResolvedVHostContext>,
    bytes_sent: usize,
    referer: Option<&str>,
    user_agent: Option<&str>,
    http_version: &str,
    req_id: &str,
) {
    let max_log_size_bytes = vhost_ctx
        .map(|v| v.max_log_size_bytes)
        .unwrap_or(DEFAULT_LOG_MAX_BYTES);
    let is_zero_body =
        bytes_sent == 0 || status == 304 || status == 204 || method.eq_ignore_ascii_case("HEAD");
    let bytes_str = if is_zero_body {
        "-".to_string()
    } else {
        bytes_sent.to_string()
    };
    let actual_bytes = if is_zero_body { 0 } else { bytes_sent };
    let safe_path_owned = zmax_security::waf_events::redact_sensitive_url_target(path);
    let safe_path = if safe_path_owned.is_empty() {
        "/"
    } else {
        safe_path_owned.as_str()
    };
    state.record_access_log_detailed(
        ip,
        method,
        safe_path,
        status,
        started.elapsed(),
        actual_bytes,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );
    let line = format!(
        "{} - - \"{} {} {}\" {} {}\r\n",
        ip, method, safe_path, http_version, status, bytes_str
    );
    append_access_log_limit(&state.base_dir, &line, max_log_size_bytes).await;

    record_and_log_vhost(
        state,
        ip,
        method,
        safe_path,
        status,
        started,
        actual_bytes,
        referer,
        user_agent,
        http_version,
        req_id,
        vhost_ctx,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub async fn record_and_log_vhost(
    state: &Arc<ServerState>,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    started: Instant,
    bytes_sent: usize,
    referer: Option<&str>,
    user_agent: Option<&str>,
    http_version: &str,
    req_id: &str,
    vhost_ctx: Option<&ResolvedVHostContext>,
) {
    let elapsed = started.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    state.record_access_log_detailed(
        ip,
        method,
        path,
        status,
        elapsed,
        bytes_sent,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );

    let Some(ctx) = vhost_ctx else {
        return;
    };
    let Some(access_log_rel) = &ctx.access_log else {
        return;
    };

    let log_path = if access_log_rel.is_absolute() {
        access_log_rel.clone()
    } else {
        ctx.doc_root.join(access_log_rel)
    };

    let referer_clean = referer.unwrap_or("-").replace(['\r', '\n'], "");
    let ua_clean = user_agent.unwrap_or("-").replace(['\r', '\n'], "");
    let bytes_str = if bytes_sent == 0 {
        "-".to_string()
    } else {
        bytes_sent.to_string()
    };

    let line = format!(
        "{} - - \"{} {} {}\" {} {} \"{}\" \"{}\" {:.3}ms [{}]\r\n",
        ip, method, path, http_version, status, bytes_str, referer_clean, ua_clean, duration_ms, req_id
    );

    append_access_log_limit(&log_path, &line, ctx.max_log_size_bytes).await;
}

// =========================================================================
// 5. GERİYE DÖNÜK UYUMLULUK ALT MODÜLLERİ
// =========================================================================

pub mod headers {
    pub use super::resolve_vhost_security_headers;
}

pub mod http_write {
    pub use super::{
        default_status_reason, format_http_response_head, write_error_response, write_http_head,
        write_http_response, write_not_found,
    };
}

pub mod logging {
    pub use super::{record_and_log, record_and_log_vhost};
}
