//! # ZMax HTTP/2 (`h2`) Çerçeve ve İstek İşleme Motoru
//! `h2` crate'i üzerinden TLS ALPN "h2" el sıkışmasını kabul eder,
//! her HTTP/2 akışını `web_engine` istek boru hattına yönlendirir.

use bytes::{Bytes, BytesMut};
use h2::server::{self, SendResponse};
use h2::{RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, error};

use crate::api::ServerState;
use crate::logger::AccessLogEntry;
use crate::web_engine::{self, H2BodyReceiver, ParsedHttpRequest};

const DEFAULT_H2_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_H2_BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP/2 bağlantısını karşılar ve gelen tüm akışları (streams) asenkron olarak yürütür.
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
    let mut builder = server::Builder::new();
    builder
        .max_concurrent_streams(128)
        .initial_window_size(1024 * 1024)
        .max_frame_size(16384)
        .max_send_buffer_size(1024 * 1024);

    let mut connection = builder.handshake(stream).await?;
    debug!(peer = %peer_addr, "HTTP/2 el sikismasi tamamlandi");

    while let Some(result) = connection.accept().await {
        let (request, respond) = match result {
            Ok(pair) => pair,
            Err(err) => {
                debug!(peer = %peer_addr, error = %err, "HTTP/2 stream kabul hatasi");
                break;
            }
        };

        let state_clone = Arc::clone(&state);
        let sni_clone = tls_sni.clone();

        tokio::spawn(async move {
            if let Err(e) = process_h2_stream(
                request,
                respond,
                peer_addr,
                state_clone,
                is_https,
                listen_port,
                sni_clone,
            )
            .await
            {
                debug!(peer = %peer_addr, error = %e, "HTTP/2 akisi sonlandi");
            }
        });
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
    let _uri_string = parts.uri.to_string();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| (pq.path().to_string(), pq.query().unwrap_or("").to_string()))
        .unwrap_or_else(|| ("/".to_string(), String::new()));
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
                .map(|s| s.split(':').next().unwrap_or("").to_string())
        })
        .unwrap_or_default();

    let mut headers_vec: Vec<(String, String)> = Vec::with_capacity(parts.headers.len());
    let mut referer = String::new();
    let mut user_agent = String::new();

    for (k, v) in parts.headers.iter() {
        let key = k.as_str().to_string();
        let val = v.to_str().unwrap_or("").to_string();
        if key.eq_ignore_ascii_case("referer") {
            referer = val.clone();
        } else if key.eq_ignore_ascii_case("user-agent") {
            user_agent = val.clone();
        }
        headers_vec.push((key, val));
    }

    if !headers_vec
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("host"))
        && !authority_host.is_empty()
    {
        headers_vec.push(("host".to_string(), authority_host.clone()));
    }

    let max_body = {
        let rt = state.runtime.read().await;
        rt.config.security.max_body_size_mb * 1024 * 1024
    };
    let max_body = if max_body == 0 {
        DEFAULT_H2_MAX_BODY_BYTES
    } else {
        max_body
    };

    let mut body_buf = BytesMut::new();

    let read_body_future = async {
        while let Some(chunk_res) = recv_stream.data().await {
            let chunk = match chunk_res {
                Ok(c) => c,
                Err(_) => return false,
            };
            if body_buf.len() + chunk.len() > max_body {
                return false;
            }
            body_buf.extend_from_slice(&chunk);
            let _ = recv_stream.flow_control().release_capacity(chunk.len());
        }
        true
    };

    let body_read_ok = tokio::time::timeout(DEFAULT_H2_BODY_TIMEOUT, read_body_future)
        .await
        .unwrap_or(false);

    let req_id = if state.runtime.read().await.config.logging.add_request_id {
        zmax_security::generate_request_id()
    } else {
        String::new()
    };

    if !body_read_ok {
        let is_head = method.eq_ignore_ascii_case("HEAD");
        let resp = http::Response::builder()
            .status(413)
            .header("content-type", "text/plain; charset=utf-8")
            .body(())?;
        let mut send_stream = respond.send_response(resp, is_head)?;
        let err_body = Bytes::from_static(b"413 Payload Too Large (HTTP/2)\n");
        let bytes_sent = if is_head {
            0
        } else {
            let len = err_body.len();
            send_stream.send_data(err_body, true)?;
            len
        };

        let client_ip_str = peer_addr.ip().to_string();
        let target_str = if query.is_empty() {
            path.clone()
        } else {
            format!("{}?{}", path, query)
        };

        state.record_access_log_detailed(
            &client_ip_str,
            &method,
            &path,
            413,
            started.elapsed(),
            bytes_sent,
            &referer,
            &user_agent,
        );

        state.log_manager.log_access(AccessLogEntry {
            timestamp: SystemTime::now(),
            client_ip: client_ip_str,
            method: method.clone(),
            target: target_str,
            protocol: "HTTP/2.0".to_string(),
            status: 413,
            bytes_sent,
            referer,
            user_agent,
            request_id: req_id,
            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
            domain: "default".to_string(),
            target_path: None,
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        });

        return Ok(());
    }

    let parsed_req = ParsedHttpRequest {
        method: method.clone(),
        path: path.clone(),
        query: query.clone(),
        version: 2,
        host: authority_host.clone(),
        headers: headers_vec,
        body: body_buf.to_vec(),
        keep_alive: true,
    };

    let mut proxy_stream: Option<H2BodyReceiver> = None;
    let dispatch_res = web_engine::handle_h2_dispatched_request(
        &parsed_req,
        peer_addr.ip(),
        &state,
        is_https,
        listen_port,
        tls_sni.as_deref(),
        &req_id,
        &mut proxy_stream,
    )
    .await;

    let (status_code, resp_headers, body_bytes, log_meta) = match dispatch_res {
        Ok(out) => out,
        Err(err) => {
            error!(error = %err, "HTTP/2 istek isleme hatasi");
            let err_body = Bytes::from_static(b"500 Internal Server Error\n");
            let mut builder = http::Response::builder().status(500);
            builder = builder.header("content-type", "text/plain; charset=utf-8");
            let is_head = method.eq_ignore_ascii_case("HEAD");
            let resp = builder.body(())?;
            let mut send_stream = respond.send_response(resp, is_head)?;
            let bytes_sent = if is_head {
                0
            } else {
                let len = err_body.len();
                send_stream.send_data(err_body, true)?;
                len
            };

            let client_ip_str = peer_addr.ip().to_string();
            let target_str = if query.is_empty() {
                path.clone()
            } else {
                format!("{}?{}", path, query)
            };

            state.record_access_log_detailed(
                &client_ip_str,
                &method,
                &path,
                500,
                started.elapsed(),
                bytes_sent,
                &referer,
                &user_agent,
            );

            state.log_manager.log_access(AccessLogEntry {
                timestamp: SystemTime::now(),
                client_ip: client_ip_str,
                method: method.clone(),
                target: target_str,
                protocol: "HTTP/2.0".to_string(),
                status: 500,
                bytes_sent,
                referer,
                user_agent,
                request_id: req_id,
                duration_ms: started.elapsed().as_secs_f64() * 1000.0,
                domain: "default".to_string(),
                target_path: None,
                json_format: false,
                also_write_global: true,
                max_size_bytes: 0,
            });

            return Ok(());
        }
    };

    let mut response_builder = http::Response::builder().status(status_code);
    for (hk, hv) in &resp_headers {
        if hk.starts_with(':')
            || hk.eq_ignore_ascii_case("connection")
            || hk.eq_ignore_ascii_case("keep-alive")
            || hk.eq_ignore_ascii_case("transfer-encoding")
            || hk.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        response_builder = response_builder.header(hk.as_str(), hv.as_str());
    }

    let is_head = method.eq_ignore_ascii_case("HEAD");
    // [kart-2] HTTP/2: HEAD, 204 veya 304 durumunda govde gonderilmez; gonderilen bayt 0
    let is_no_body = is_head || status_code == 204 || status_code == 304;
    let has_body = !is_no_body && !body_bytes.is_empty();

    let resp = response_builder.body(())?;
    let bytes_sent = if let Some(body_rx) = proxy_stream {
        // Ters vekil yanıtı: gövde arka uçtan geldikçe DATA çerçevesi olarak akıtılır.
        let mut send_stream = respond.send_response(resp, false)?;
        stream_body_to_h2(&mut send_stream, body_rx).await
    } else {
        let mut send_stream = respond.send_response(resp, !has_body)?;
        if has_body {
            let len = body_bytes.len();
            send_stream.send_data(body_bytes, true)?;
            len
        } else {
            0
        }
    };

    let domain_str = log_meta
        .domain
        .clone()
        .unwrap_or_else(|| "default".to_string());

    state.record_access_log_detailed(
        &peer_addr.ip().to_string(),
        &method,
        &path,
        status_code,
        started.elapsed(),
        bytes_sent,
        &referer,
        &user_agent,
    );

    let client_ip_str = peer_addr.ip().to_string();
    let target_str = if query.is_empty() {
        path.clone()
    } else {
        format!("{}?{}", path, query)
    };

    state.log_manager.log_access(AccessLogEntry {
        timestamp: SystemTime::now(),
        client_ip: client_ip_str,
        method: method.clone(),
        target: target_str,
        protocol: "HTTP/2.0".to_string(),
        status: status_code,
        bytes_sent,
        referer,
        user_agent,
        request_id: req_id,
        duration_ms: started.elapsed().as_secs_f64() * 1000.0,
        domain: domain_str,
        target_path: log_meta.custom_log_path,
        json_format: log_meta.json_format,
        also_write_global: log_meta.also_write_global,
        max_size_bytes: log_meta.max_log_size_bytes,
    });

    Ok(())
}

/// Kanal kapanana dek gelen gövde parçalarını h2 akış denetimine (flow control) uyarak yazar ve
/// akışı bitirir. Arka uç hatasında akış `INTERNAL_ERROR` ile sıfırlanır; istemci akışı sıfırlarsa
/// bırakılır (alıcı düşünce arka uç okuyucu görevi de biter). Yazılan bayt sayısını döner.
async fn stream_body_to_h2(send: &mut SendStream<Bytes>, mut rx: H2BodyReceiver) -> usize {
    enum Event {
        Item(Option<Result<Bytes, std::io::Error>>),
        ClientReset,
    }
    let mut sent = 0usize;
    loop {
        let event = tokio::select! {
            item = rx.recv() => Event::Item(item),
            _ = std::future::poll_fn(|cx| send.poll_reset(cx)) => Event::ClientReset,
        };
        match event {
            Event::ClientReset => {
                debug!("HTTP/2 istemcisi akisi sifirladi; vekil govdesi birakildi");
                return sent;
            }
            Event::Item(None) => {
                if let Err(e) = send.send_data(Bytes::new(), true) {
                    debug!(error = %e, "HTTP/2 akis sonu yazilamadi");
                }
                return sent;
            }
            Event::Item(Some(Err(e))) => {
                debug!(error = %e, "vekil govdesi yarida kesildi; akis sifirlaniyor");
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                return sent;
            }
            Event::Item(Some(Ok(mut data))) => {
                while !data.is_empty() {
                    send.reserve_capacity(data.len());
                    let cap = match std::future::poll_fn(|cx| send.poll_capacity(cx)).await {
                        Some(Ok(c)) if c > 0 => c,
                        _ => return sent,
                    };
                    let piece = data.split_to(cap.min(data.len()));
                    let piece_len = piece.len();
                    if let Err(e) = send.send_data(piece, false) {
                        debug!(error = %e, "HTTP/2 veri cercevesi yazilamadi");
                        return sent;
                    }
                    sent += piece_len;
                }
            }
        }
    }
}
