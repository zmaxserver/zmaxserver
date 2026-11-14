//! # L2 — HTTP/2 Protokol Yöneticisi (`pipeline/l2_protocol/h2.rs`)
//!
//! `h2` crate'i üzerinden HTTP/2 çerçeveleme, akış çoklama (multiplexing),
//! akış denetimi (flow control) ve 8 katmanlı boru hattı entegrasyonu.

use bytes::{Bytes, BytesMut};
use h2::server::{self, SendResponse};
use h2::RecvStream;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::core::state::ParsedHttpRequest;
use crate::core::state::ServerState;
use crate::pipeline::{Outcome, RequestContext, ResponseSink, Scheme};

const DEFAULT_H2_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_H2_BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP/2 bağlantısını karşılar ve gelen tüm akışları (streams) asenkron olarak boru hattına yönlendirir.
pub async fn handle_h2_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
    is_https: bool,
    listen_port: u16,
    tls_sni: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _conn_guard = match state.conn_limiter.try_acquire(peer_addr.ip(), None) {
        Ok(guard) => guard,
        Err(()) => return Ok(()),
    };

    let mut builder = server::Builder::new();
    builder
        .max_concurrent_streams(128)
        .initial_window_size(1024 * 1024)
        .max_frame_size(16384)
        .max_send_buffer_size(1024 * 1024);

    let mut connection = builder.handshake(stream).await?;

    let shutdown = Arc::clone(&state.shutdown);
    let mut shutdown_sub = shutdown.subscribe();
    let mut graceful_sent = false;

    loop {
        let accept_fut = connection.accept();
        tokio::select! {
            result = accept_fut => {
                let Some(res) = result else {
                    break;
                };
                let (request, respond) = match res {
                    Ok(pair) => pair,
                    Err(_) => break,
                };

                let state_clone = Arc::clone(&state);
                let sni_clone = tls_sni.clone();

                tokio::spawn(async move {
                    let _ = process_h2_stream(
                        request,
                        respond,
                        peer_addr,
                        state_clone,
                        is_https,
                        listen_port,
                        sni_clone,
                    )
                    .await;
                });
            }
            change_res = shutdown_sub.changed(), if !graceful_sent => {
                if change_res.is_ok() && *shutdown_sub.borrow() {
                    connection.graceful_shutdown();
                    graceful_sent = true;
                }
            }
        }
    }

    Ok(())
}

async fn process_h2_stream(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
    is_https: bool,
    listen_port: u16,
    tls_sni: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let started = Instant::now();
    let (parts, mut recv_stream) = request.into_parts();

    let method = parts.method.as_str().to_string();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| {
            let p = pq.path();
            let q = pq.query().unwrap_or("");
            (p.to_string(), q.to_string())
        })
        .unwrap_or_else(|| {
            let raw = parts.uri.to_string();
            if let Some((p, q)) = raw.split_once('?') {
                (if p.is_empty() { "/".to_string() } else { p.to_string() }, q.to_string())
            } else if raw.is_empty() {
                ("/".to_string(), String::new())
            } else {
                (raw, String::new())
            }
        });
    let path = path_and_query.0;
    let query = path_and_query.1;

    let authority_host = parts
        .uri
        .authority()
        .map(|a| a.host().to_string())
        .or_else(|| {
            parts
                .headers
                .get(http::header::HOST)
                .and_then(|h| h.to_str().ok())
                .map(|s| {
                    if let Some(stripped) = s.strip_prefix('[') {
                        if let Some(end) = stripped.find(']') {
                            return stripped[..end].to_string();
                        }
                    }
                    s.split(':').next().unwrap_or("").to_string()
                })
        })
        .unwrap_or_default();

    let mut headers_vec: Vec<(String, String)> = Vec::with_capacity(parts.headers.len() + 1);
    for (k, v) in parts.headers.iter() {
        let key = k.as_str().to_string();
        let val = v.to_str().unwrap_or("").to_string();
        headers_vec.push((key, val));
    }

    if !headers_vec.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) && !authority_host.is_empty() {
        headers_vec.push(("host".to_string(), authority_host.clone()));
    }

    let (max_body_bytes, body_timeout) = {
        let rt = state.runtime.read().await;
        let mb = rt.config.security.max_body_size_mb.max(1);
        let sec = rt.config.security.slowloris_body_timeout_sec.max(5);
        (
            (mb as usize) * 1024 * 1024,
            Duration::from_secs(sec),
        )
    };

    let body_limit = max_body_bytes.max(DEFAULT_H2_MAX_BODY_BYTES);
    let timeout_dur = if body_timeout.as_secs() > 0 {
        body_timeout
    } else {
        DEFAULT_H2_BODY_TIMEOUT
    };

    let mut body_bytes = BytesMut::new();
    let body_read_res = tokio::time::timeout(timeout_dur, async {
        while let Some(chunk_res) = recv_stream.data().await {
            let chunk = chunk_res.map_err(|e| format!("H2 stream read error: {}", e))?;
            if body_bytes.len() + chunk.len() > body_limit {
                return Err("H2 body size exceeds limit".to_string());
            }
            body_bytes.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }
        Ok::<(), String>(())
    })
    .await;

    let scheme = if is_https { Scheme::Https } else { Scheme::Http };

    match body_read_res {
        Ok(Ok(())) => {
            let req = ParsedHttpRequest {
                method,
                path,
                query,
                version: 2,
                host: authority_host,
                headers: headers_vec,
                body: body_bytes.freeze().to_vec(),
                keep_alive: false,
            };

            let ctx = RequestContext {
                peer: peer_addr,
                real_ip: peer_addr.ip(),
                scheme,
                req,
                vhost: None,
                route: None,
                cache_status: None,
                started,
                req_id: String::new(),
                server_port: listen_port,
                tls_sni,
            };

            let mut sink = ResponseSink::H2(&mut respond);
            execute_h2_pipeline(ctx, &state, &mut sink).await?;
        }
        Ok(Err(err_msg)) => {
            let mut sink = ResponseSink::H2(&mut respond);
            let resp = crate::pipeline::ResponseContext::simple(
                413,
                "Payload Too Large",
                Bytes::copy_from_slice(err_msg.as_bytes()),
                "text/plain; charset=utf-8",
            );
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(&mut sink, &state, resp).await?;
        }
        Err(_) => {
            let mut sink = ResponseSink::H2(&mut respond);
            let resp = crate::pipeline::ResponseContext::simple(
                408,
                "Request Timeout",
                Bytes::from_static(b"408 Request Timeout - Body Read Timed Out\n"),
                "text/plain; charset=utf-8",
            );
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(&mut sink, &state, resp).await?;
        }
    }

    Ok(())
}

/// HTTP/2 akışı için L3 -> L8 boru hattını işletir.
async fn execute_h2_pipeline(
    mut ctx: RequestContext,
    state: &Arc<ServerState>,
    sink: &mut ResponseSink<'_>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // L2 doğrulamaları
    let l2 = super::L2ProtocolLayer;
    let outcome = l2.run_validations(ctx, state).await;
    match outcome {
        Outcome::Respond(resp) => {
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(sink, state, resp).await?;
            return Ok(());
        }
        Outcome::Continue(next_ctx) => ctx = next_ctx,
    }

    // L3 Real IP
    let l3 = crate::pipeline::l3_realip::L3RealIpLayer;
    match l3.run_internal(ctx, state).await {
        Outcome::Respond(resp) => {
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(sink, state, resp).await?;
            return Ok(());
        }
        Outcome::Continue(next_ctx) => ctx = next_ctx,
    }

    // L4 Güvenlik
    let l4 = crate::pipeline::l4_security::L4SecurityLayer;
    match l4.run_internal(ctx, state).await {
        Outcome::Respond(resp) => {
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(sink, state, resp).await?;
            return Ok(());
        }
        Outcome::Continue(next_ctx) => ctx = next_ctx,
    }

    // L5 Yönlendirme
    let l5 = crate::pipeline::l5_router::L5RouterLayer;
    match l5.run_internal(ctx, state).await {
        Outcome::Respond(resp) => {
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(sink, state, resp).await?;
            return Ok(());
        }
        Outcome::Continue(next_ctx) => ctx = next_ctx,
    }

    // L6 Önbellek
    let l6 = crate::pipeline::l6_cache::L6CacheLayer;
    match l6.run_internal(ctx, state).await {
        Outcome::Respond(resp) => {
            crate::pipeline::l8_response::L8ResponseLayer::write_response_context(sink, state, resp).await?;
            return Ok(());
        }
        Outcome::Continue(next_ctx) => ctx = next_ctx,
    }

    // L7 İşleyiciler
    let resp = crate::pipeline::l7_handlers::dispatch_handler(ctx, state, sink).await?;
    crate::pipeline::l8_response::L8ResponseLayer::write_response_context(sink, state, resp).await?;

    Ok(())
}
