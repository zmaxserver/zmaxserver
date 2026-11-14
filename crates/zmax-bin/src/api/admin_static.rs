use crate::api::*;
use zmax_httpparser::{resolve_real_ip, HttpReadLimits};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

/// Vue 3 WebAdmin Yönetim Paneli Yöneticisi (Varsayılan: 127.0.0.1:19485)
pub async fn handle_admin_connection<S>(
    mut socket: S,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
    is_https: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (proxy_prefix, trusted_proxies) = {
        let rt = state.runtime.read().await;
        (
            rt.config.listeners.admin.proxy_prefix.clone(),
            rt.config.listeners.admin.trusted_proxies.clone(),
        )
    };
    let mut leftover = Vec::with_capacity(4096);
    let limits = HttpReadLimits {
        max_header_bytes: 64 * 1024,
        max_body_bytes: 4 * 1024 * 1024,
        header_timeout: Duration::from_secs(10),
        body_timeout: Duration::from_secs(15),
    };
    let req = match read_http_request_with_limits(&mut socket, &mut leftover, limits).await {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(err) => {
            send_http_read_error(&mut socket, &err).await;
            return Ok(());
        }
    };
    let real_ip = resolve_real_ip(
        peer_addr.ip(),
        &req.headers,
        "x-forwarded-for",
        &trusted_proxies,
        true,
    );
    let is_local_control = peer_addr.ip().is_loopback() && real_ip.is_loopback();
    if !is_local_control
        && (state.ban_manager.is_banned(peer_addr.ip()) || state.ban_manager.is_banned(real_ip))
    {
        crate::web_engine::write_http_response(
            &mut socket,
            403,
            "Forbidden",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            b"403 Forbidden - IP Blocked",
            None,
            req.method.eq_ignore_ascii_case("HEAD"),
            is_https,
            false,
            0,
            None,
            None,
        )
        .await?;
        return Ok(());
    }

    if handle_api_route(&mut socket, &req, &state, false, is_local_control).await? {
        return Ok(());
    }

    let normalized_path = normalize_panel_request_path(&req.path, &proxy_prefix);
    let req_file = if normalized_path == "/" || normalized_path == "/index.html" {
        "/index.html"
    } else {
        normalized_path.as_str()
    };

    let indexes = vec!["index.html".to_string()];
    let resolved = {
        let handler = state.admin_static_handler.read().await;
        handler
            .resolve_with_index(req_file, &indexes)
            .or_else(|| handler.resolve("/index.html"))
    };

    if let Some(file_info) = resolved {
        if let Ok(content) = tokio::fs::read(&file_info.path).await {
            let mime = if req_file.ends_with(".js") {
                "application/javascript; charset=utf-8"
            } else if req_file.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if req_file.ends_with(".html") || req_file == "/index.html" {
                "text/html; charset=utf-8"
            } else {
                file_info.mime_type
            };

            crate::web_engine::write_http_response(
                &mut socket,
                200,
                "OK",
                &[
                    ("Content-Type".into(), mime.to_string()),
                    ("X-Content-Type-Options".into(), "nosniff".into()),
                ],
                &content,
                Some(content.len()),
                req.method.eq_ignore_ascii_case("HEAD"),
                is_https,
                false,
                0,
                None,
                None,
            )
            .await?;
            return Ok(());
        }
    }

    let not_found = b"404 Admin File Not Found";
    crate::web_engine::write_http_response(
        &mut socket,
        404,
        "Not Found",
        &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
        not_found,
        Some(not_found.len()),
        req.method.eq_ignore_ascii_case("HEAD"),
        is_https,
        false,
        0,
        None,
        None,
    )
    .await?;
    Ok(())
}
