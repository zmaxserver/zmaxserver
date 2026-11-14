use crate::web_engine::context::ResolvedVHostContext;
use crate::api::{ParsedHttpRequest, ServerState};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use zmax_proxy::{ProxyError, ReverseProxy};

/// HTTP/2 yanıt gövdesi için üst sınır: arka uç okuyucu ile h2 yazıcı arasındaki kanal en çok bu kadar
/// parça (her biri <= 8 KiB okuma) tutar; dolunca arka uçtan okuma durur (geri basınç). Yanıtın
/// tamamı hiçbir koşulda bellekte toplanmaz.
pub(crate) const H2_PROXY_STREAM_QUEUE_CHUNKS: usize = 8;

/// HTTP/2 vekil yanıtının çözülmüş gövde parçaları (hata = akış sıfırlanır).
pub type H2BodyReceiver = tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>;

/// Arka uç bağlantı yuvası (`max_conns` / `max_ws`); yanıt akışı görevine taşınabilsin diye sahiplidir.
pub(crate) struct OwnedConnSlot {
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

pub(crate) fn h2_text_reply(
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

pub(crate) fn h2_proxy_error_reply(
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

/// HTTP/2 üzerinden gelen vekil vhost isteklerini arka uç HTTP/1.1 sunucusuna iletir. Yanıt başı
/// hemen döner; gövde (Content-Length / chunked çözülmüş) `H2BodyReceiver` ile artımlı akar.
pub(crate) async fn serve_h2_proxy_request(
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
        // Zaman aşımı ve geçersiz istek yeniden denenmez.
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
    // Görevin sahibi `tx`'tir: istemci akışı bırakınca (`tx.closed()`) görev biter, arka uç soketi
    // ve bağlantı yuvası düşürülür; arka uç sessizse `init_timeout` okumayı keser.
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
