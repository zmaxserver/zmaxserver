use crate::pipeline::l5_router::ResolvedVHostContext;
use std::path::Path;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use zmax_header::SecurityHeadersPolicy;
use zmax_static::StaticFileHandler;

#[allow(clippy::too_many_arguments)]
fn format_http_response_head(
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
pub(super) async fn write_http_head<S>(
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

pub(super) async fn write_not_found<S>(
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

pub(crate) fn default_status_reason(status: u16) -> &'static str {
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

// =========================================================================
// 8-MADDE KABUL STANDARDI: HATA SAYFALARI, ASENKRON LOG VE HTTP/2 MOTORU
// =========================================================================

/// VHost ozel hata dokumanini (error_docs) arar; yoksa varsayilan hata mesajini dondurur.
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

    // [kart-2] HEAD, 204 veya 304 isteklerinde govde yazilmaz; gercek bayt 0 olarak raporlanir
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
