//! L7 — Reverse Proxy / Ters Vekil İşleyicisi
//! HTTP/1.1 akışlı vekil, HTTP/2 artımlı vekil (`H2BodyReceiver`), WebSocket tünelleme ve havuz yönetimi.

use crate::api::{ParsedHttpRequest, ServerState};
use crate::pipeline::l8_response::write_http_response;
use crate::web_engine::context::ResolvedVHostContext;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use zmax_httpparser::extract_header;
use zmax_proxy::{ProxyError, ReverseProxy};

pub const PROXY_BUFFER_SIZE: usize = 64 * 1024;
pub const H2_PROXY_STREAM_QUEUE_CHUNKS: usize = 8;

pub type H2BodyReceiver = tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>;

/// Arka uç bağlantı yuvası (`max_conns` / `max_ws`); yanıt akışı görevine taşınabilsin diye sahiplidir.
pub struct OwnedConnSlot {
    state: Arc<ServerState>,
    addr: String,
    active: bool,
}

impl Drop for OwnedConnSlot {
    fn drop(&mut self) {
        if self.active {
            self.state.upstream_pool.release_conns_slot(&self.addr);
        }
    }
}

pub fn h2_text_reply(
    status: u16,
    msg: &'static [u8],
) -> (
    u16,
    Vec<(String, String)>,
    bytes::Bytes,
    Option<H2BodyReceiver>,
) {
    (
        status,
        vec![("content-type".into(), "text/plain; charset=utf-8".into())],
        bytes::Bytes::from_static(msg),
        None,
    )
}

pub fn h2_proxy_error_reply(
    err: &ProxyError,
) -> (
    u16,
    Vec<(String, String)>,
    bytes::Bytes,
    Option<H2BodyReceiver>,
) {
    match err {
        ProxyError::BadRequest => h2_text_reply(400, b"400 Bad Request\n"),
        ProxyError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            h2_text_reply(504, b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
        }
        _ => h2_text_reply(502, b"502 Bad Gateway - Proxy Upstream Unavailable\n"),
    }
}

// =========================================================================
// 1. HTTP/1.1 TERS VEKİL VE WEBSOCKET TÜNELİ
// =========================================================================

#[allow(clippy::too_many_arguments)]
pub async fn serve_proxy_request<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    is_https: bool,
    vhost_ctx: &ResolvedVHostContext,
    connect_timeout_sec: u64,
    keep_alive: bool,
) -> Result<(u16, bool, usize), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let is_ws = vhost_ctx.proxy_websocket
        && extract_header(&req.headers, "upgrade")
            .map(|u| u.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
    let is_head = req.method.eq_ignore_ascii_case("HEAD");

    // RFC 9110 §7.6.1: Connection, çerçeveleme/Host alanı adlandırıyorsa istek reddedilir;
    // sessizce soymak vekil ile arka uç arasında istek çerçevesi ayrışmasına yol açar.
    if zmax_proxy::connection_names_protected_field(
        req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ) {
        let err_body = b"400 Bad Request - Connection header names a protected field\n";
        write_http_response(
            socket,
            400,
            "Bad Request",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            err_body,
            Some(err_body.len()),
            is_head,
            is_https,
            false,
            0,
            vhost_ctx.headers_policy.as_ref(),
            None,
        )
        .await?;
        let sent_err_bytes = if is_head { 0 } else { err_body.len() };
        return Ok((400, false, sent_err_bytes));
    }

    let raw_target = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let mut connection_tokens = Vec::new();
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("connection") {
            for tok in v.split(',') {
                let t = tok.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    connection_tokens.push(t);
                }
            }
        }
    }

    let mut raw_head = format!(
        "{} {} HTTP/1.{}\r\n",
        req.method,
        raw_target,
        req.version.min(1)
    );
    for (k, v) in &req.headers {
        let kl = k.to_ascii_lowercase();
        // [kart-10: P0 request smuggling & RFC 9110 hop-by-hop temizliği]
        // Connection başlığındaki özel belirteçler ve hop-by-hop alanları elenir.
        // WebSocket durumunda Upgrade belirteci korunur.
        if !(is_ws && kl == "upgrade") && connection_tokens.contains(&kl) {
            continue;
        }
        // Gövde decode_chunked_stream ile çözüldüğünden, transfer-encoding başlığı upstream'e aktarılmaz!
        if matches!(
            kl.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "trailers"
        ) {
            continue;
        }
        if kl == "upgrade" && !is_ws {
            continue;
        }
        raw_head.push_str(&format!("{}: {}\r\n", k, v));
    }
    // Çözülmüş gerçek gövde uzunluğu Content-Length olarak eklenir
    if !req.body.is_empty()
        || req.method.eq_ignore_ascii_case("POST")
        || req.method.eq_ignore_ascii_case("PUT")
        || req.method.eq_ignore_ascii_case("PATCH")
    {
        raw_head.push_str(&format!("content-length: {}\r\n", req.body.len()));
    }
    raw_head.push_str("\r\n");

    // [kart-10: vhost'ta yoksa mod_proxy.toml genel değeri]
    let conn_sec = vhost_ctx
        .proxy_ext
        .connect_timeout_sec
        .unwrap_or(connect_timeout_sec);
    let conn_dur = Duration::from_secs(conn_sec.max(1));
    let init_dur = Duration::from_secs(vhost_ctx.proxy_ext.init_timeout_sec.max(1));
    let ka_dur = Duration::from_secs(vhost_ctx.proxy_ext.keep_alive_timeout_sec.max(1));

    // [kart-10: max_conns eşzamanlı aktif bağlantı denetimi; WebSocket tünelleri max_ws ile sınırlanır]
    if !is_ws
        && vhost_ctx.proxy_ext.max_conns > 0
        && !state
            .upstream_pool
            .try_acquire_conns_slot(&vhost_ctx.proxy_upstream, vhost_ctx.proxy_ext.max_conns)
    {
        let err_body = b"503 Service Unavailable - Upstream Connection Limit Reached\n";
        write_http_response(
            socket,
            503,
            "Service Unavailable",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            err_body,
            Some(err_body.len()),
            is_head,
            is_https,
            false,
            0,
            vhost_ctx.headers_policy.as_ref(),
            None,
        )
        .await?;
        let sent_err_bytes = if is_head { 0 } else { err_body.len() };
        return Ok((503, false, sent_err_bytes));
    }

    struct UpstreamConnGuard<'a> {
        pool: &'a zmax_pool::UpstreamSocketPool,
        addr: &'a str,
        active: bool,
    }
    impl<'a> Drop for UpstreamConnGuard<'a> {
        fn drop(&mut self) {
            if self.active {
                self.pool.release_conns_slot(self.addr);
            }
        }
    }
    let _conn_guard = UpstreamConnGuard {
        pool: &state.upstream_pool,
        addr: &vhost_ctx.proxy_upstream,
        active: !is_ws && vhost_ctx.proxy_ext.max_conns > 0,
    };

    let proxy = ReverseProxy::new(&vhost_ctx.proxy_upstream)
        .with_timeouts(conn_dur, init_dur)
        .with_init_timeout(init_dur)
        .with_keep_alive_timeout(ka_dur)
        .with_resp_buffer(vhost_ctx.proxy_ext.resp_buffer)
        .with_preserve_host(vhost_ctx.proxy_preserve_host)
        .with_max_conns(vhost_ctx.proxy_ext.max_conns)
        .with_ws_idle_timeout(Duration::from_secs(
            vhost_ctx.proxy_ext.ws_idle_timeout_sec.max(1),
        ))
        .with_https(is_https);

    if is_ws {
        // [kart-10: vhost başına eşzamanlı WebSocket tüneli sınırı]
        let ws_key = format!("ws:{}", vhost_ctx.vhost_name);
        if !state
            .upstream_pool
            .try_acquire_conns_slot(&ws_key, vhost_ctx.proxy_ext.max_ws)
        {
            let err_body = b"503 Service Unavailable - WebSocket Connection Limit Reached\n";
            write_http_response(
                socket,
                503,
                "Service Unavailable",
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                err_body,
                Some(err_body.len()),
                is_head,
                is_https,
                false,
                0,
                vhost_ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_body.len() };
            return Ok((503, false, sent_err_bytes));
        }
        let _ws_guard = UpstreamConnGuard {
            pool: &state.upstream_pool,
            addr: &ws_key,
            active: true,
        };
        match proxy
            .tunnel_websocket_request(
                socket,
                raw_head.as_bytes(),
                &req.body,
                SocketAddr::new(real_ip, 0),
            )
            .await
        {
            Ok((status, body_bytes)) => return Ok((status, false, body_bytes)),
            Err(err) => {
                if err.headers_sent {
                    if let Err(e) = socket.shutdown().await {
                        tracing::debug!(error = %e, "ters vekil: istemci soketi kapatilamadi");
                    }
                    return Ok((err.status.unwrap_or(502), false, err.body_bytes_sent));
                }
                let (code, reason, err_body): (u16, &str, &[u8]) = match &err.error {
                    ProxyError::BadRequest => (400, "Bad Request", b"400 Bad Request"),
                    ProxyError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        (504, "Gateway Timeout", b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
                    }
                    _ => (502, "Bad Gateway", b"502 Bad Gateway - Upstream Unavailable\n"),
                };
                write_http_response(
                    socket,
                    code,
                    reason,
                    &[("Content-Type".into(), "text/plain".into())],
                    err_body,
                    Some(err_body.len()),
                    is_head,
                    is_https,
                    false,
                    0,
                    vhost_ctx.headers_policy.as_ref(),
                    None,
                )
                .await?;
                let sent_err_bytes = if is_head { 0 } else { err_body.len() };
                return Ok((code, false, sent_err_bytes));
            }
        }
    }

    let mut upstream_stream = match state
        .upstream_pool
        .acquire(&vhost_ctx.proxy_upstream, conn_dur)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            let is_timeout = err.kind() == std::io::ErrorKind::TimedOut;
            let (code, reason, err_body): (u16, &str, &[u8]) = if is_timeout {
                (504, "Gateway Timeout", b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
            } else {
                (502, "Bad Gateway", b"502 Bad Gateway - Proxy Upstream Unavailable\n")
            };
            write_http_response(
                socket,
                code,
                reason,
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                err_body,
                Some(err_body.len()),
                is_head,
                is_https,
                false,
                0,
                vhost_ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_body.len() };
            return Ok((code, false, sent_err_bytes));
        }
    };

    match proxy
        .forward_streaming_on_stream(
            &mut upstream_stream,
            socket,
            raw_head.as_bytes(),
            &req.body,
            SocketAddr::new(real_ip, 0),
            keep_alive,
        )
        .await
    {
        Ok(res) => {
            if res.upstream_reusable {
                state
                    .upstream_pool
                    .release_with_ttl(&vhost_ctx.proxy_upstream, upstream_stream, ka_dur);
            }
            if !res.client_keep_alive {
                if let Err(e) = socket.shutdown().await {
                    tracing::debug!(error = %e, "ters vekil: istemci soketi kapatilamadi");
                }
            }
            Ok((res.status, res.client_keep_alive, res.body_bytes))
        }
        Err(err) => {
            if err.headers_sent {
                if let Err(e) = socket.shutdown().await {
                    tracing::debug!(error = %e, "ters vekil: istemci soketi kapatilamadi");
                }
                return Ok((err.status.unwrap_or(502), false, err.body_bytes_sent));
            }
            let (code, reason, err_body): (u16, &str, &[u8]) = match &err.error {
                ProxyError::BadRequest => (400, "Bad Request", b"400 Bad Request"),
                ProxyError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    (504, "Gateway Timeout", b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
                }
                _ => (502, "Bad Gateway", b"502 Bad Gateway - Proxy Upstream Unavailable\n"),
            };
            write_http_response(
                socket,
                code,
                reason,
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                err_body,
                Some(err_body.len()),
                is_head,
                is_https,
                false,
                0,
                vhost_ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_body.len() };
            Ok((code, false, sent_err_bytes))
        }
    }
}

// =========================================================================
// 2. HTTP/2 TERS VEKİL (H2 Proxy)
// =========================================================================

/// HTTP/2 üzerinden gelen vekil vhost isteklerini arka uç HTTP/1.1 sunucusuna iletir.
pub async fn serve_h2_proxy_request(
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    vhost_ctx: &ResolvedVHostContext,
    default_connect_timeout_sec: u64,
) -> Result<
    (
        u16,
        Vec<(String, String)>,
        bytes::Bytes,
        Option<H2BodyReceiver>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // RFC 9110 §7.6.1: Connection, çerçeveleme/Host alanı adlandırıyorsa istek reddedilir.
    if zmax_proxy::connection_names_protected_field(
        req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ) {
        return Ok(h2_text_reply(
            400,
            b"400 Bad Request - Connection header names a protected field\n",
        ));
    }
    let raw_target = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let mut connection_tokens = Vec::new();
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("connection") {
            for tok in v.split(',') {
                let t = tok.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    connection_tokens.push(t);
                }
            }
        }
    }

    let mut raw_head = format!("{} {} HTTP/1.1\r\n", req.method, raw_target);
    for (k, v) in &req.headers {
        let kl = k.to_ascii_lowercase();
        // [kart-10: RFC 9110 hop-by-hop ve smuggling temizliği]
        if connection_tokens.contains(&kl) {
            continue;
        }
        if matches!(
            kl.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "trailers"
                | "upgrade"
        ) {
            continue;
        }
        raw_head.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !req.body.is_empty()
        || req.method.eq_ignore_ascii_case("POST")
        || req.method.eq_ignore_ascii_case("PUT")
        || req.method.eq_ignore_ascii_case("PATCH")
    {
        raw_head.push_str(&format!("content-length: {}\r\n", req.body.len()));
    }
    raw_head.push_str("\r\n");

    let conn_sec = vhost_ctx
        .proxy_ext
        .connect_timeout_sec
        .unwrap_or(default_connect_timeout_sec);
    let conn_dur = Duration::from_secs(conn_sec.max(1));
    let init_dur = Duration::from_secs(vhost_ctx.proxy_ext.init_timeout_sec.max(1));
    let ka_dur = Duration::from_secs(vhost_ctx.proxy_ext.keep_alive_timeout_sec.max(1));

    if vhost_ctx.proxy_ext.max_conns > 0
        && !state
            .upstream_pool
            .try_acquire_conns_slot(&vhost_ctx.proxy_upstream, vhost_ctx.proxy_ext.max_conns)
    {
        return Ok(h2_text_reply(
            503,
            b"503 Service Unavailable - Upstream Connection Limit Reached\n",
        ));
    }
    let slot = OwnedConnSlot {
        state: Arc::clone(state),
        addr: vhost_ctx.proxy_upstream.clone(),
        active: vhost_ctx.proxy_ext.max_conns > 0,
    };

    let proxy = ReverseProxy::new(&vhost_ctx.proxy_upstream)
        .with_timeouts(conn_dur, init_dur)
        .with_init_timeout(init_dur)
        .with_keep_alive_timeout(ka_dur)
        .with_resp_buffer(vhost_ctx.proxy_ext.resp_buffer)
        .with_preserve_host(vhost_ctx.proxy_preserve_host)
        .with_max_conns(vhost_ctx.proxy_ext.max_conns)
        .with_https(true);

    let (mut upstream_stream, is_from_pool) = match state
        .upstream_pool
        .acquire_tagged_with_timeout(&vhost_ctx.proxy_upstream, conn_dur)
        .await
    {
        Ok(res) => res,
        Err(err) => {
            return Ok(if err.kind() == std::io::ErrorKind::TimedOut {
                h2_text_reply(504, b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
            } else {
                h2_text_reply(502, b"502 Bad Gateway - Proxy Upstream Unavailable\n")
            });
        }
    };

    let client_addr = SocketAddr::new(real_ip, 0);
    let first = proxy
        .begin_decoded_response(
            &mut upstream_stream,
            raw_head.as_bytes(),
            &req.body,
            client_addr,
        )
        .await;
    let (head, mut reader) = match first {
        Ok(ok) => ok,
        // Havuzdaki bayat (arka uç tarafından kapatılmış) bağlantı: bir kez taze bağlantıyla dene.
        Err(err)
            if is_from_pool
                && matches!(&err.error, ProxyError::Io(e) if e.kind() != std::io::ErrorKind::TimedOut) =>
        {
            let mut fresh = match state
                .upstream_pool
                .dial_fresh_with_timeout(&vhost_ctx.proxy_upstream, conn_dur)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "h2 vekil: taze upstream baglantisi acilamadi");
                    return Ok(h2_proxy_error_reply(&ProxyError::Connect(e.to_string())));
                }
            };
            match proxy
                .begin_decoded_response(&mut fresh, raw_head.as_bytes(), &req.body, client_addr)
                .await
            {
                Ok(ok) => {
                    upstream_stream = fresh;
                    ok
                }
                Err(e) => return Ok(h2_proxy_error_reply(&e.error)),
            }
        }
        Err(err) => return Ok(h2_proxy_error_reply(&err.error)),
    };

    if reader.is_finished() {
        if reader.upstream_reusable() {
            state.upstream_pool.release_with_ttl(
                &vhost_ctx.proxy_upstream,
                upstream_stream,
                ka_dur,
            );
        }
        return Ok((head.status, head.headers, bytes::Bytes::new(), None));
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(
        H2_PROXY_STREAM_QUEUE_CHUNKS,
    );
    let pool_state = Arc::clone(state);
    let upstream_addr = vhost_ctx.proxy_upstream.clone();
    tokio::spawn(async move {
        let _slot = slot;
        loop {
            let next = tokio::select! {
                r = reader.next_chunk(&mut upstream_stream) => r,
                _ = tx.closed() => return,
            };
            match next {
                Ok(Some(chunk)) => {
                    if tx.send(Ok(bytes::Bytes::from(chunk))).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let io_err = match err {
                        ProxyError::Io(e) => e,
                        other => std::io::Error::other(other.to_string()),
                    };
                    if tx.send(Err(io_err)).await.is_err() {
                        tracing::debug!("h2 vekil: istemci akisi hata bildirilmeden once kapandi");
                    }
                    return;
                }
            }
        }
        if reader.upstream_reusable() {
            pool_state
                .upstream_pool
                .release_with_ttl(&upstream_addr, upstream_stream, ka_dur);
        }
    });
    Ok((head.status, head.headers, bytes::Bytes::new(), Some(rx)))
}

// =========================================================================
// 3. GERİYE DÖNÜK UYUMLULUK ALT MODÜLLERİ
// =========================================================================

pub mod h1 {
    pub use super::{serve_proxy_request, PROXY_BUFFER_SIZE};
}

pub mod h2 {
    pub use super::{
        h2_proxy_error_reply, h2_text_reply, serve_h2_proxy_request, H2BodyReceiver,
        OwnedConnSlot, H2_PROXY_STREAM_QUEUE_CHUNKS,
    };
}
