//! L1 — Bağlantı katmanı: HTTP/HTTPS kabul döngüleri ve HTTP/1.1 Keep-Alive bağlantı döngüsü.

use crate::api::{read_http_request_with_limits, send_http_read_error, ServerState};
use crate::web_engine::pipeline_h1::handle_single_web_request;
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::OwnedSemaphorePermit;
use zmax_httpparser::HttpReadLimits;
use zmax_timeout::with_idle_timeout;

/// Global aktif bağlantı semaforu (ZMX-001: Kaynak tükenmesi ve bellek DoS engeli)
static GLOBAL_CONN_SEMAPHORE: LazyLock<Arc<tokio::sync::Semaphore>> = LazyLock::new(|| {
    Arc::new(tokio::sync::Semaphore::new(10000))
});

/// IP başına aktif bağlantı tablosu (ZMX-001: Nginx limit_conn_zone eşdeğeri)
static IP_ACTIVE_CONNS: LazyLock<DashMap<IpAddr, Arc<AtomicUsize>>> = LazyLock::new(DashMap::new);

/// IP ve Global bağlantı sayısı için RAII koruyucusu
pub struct ConnectionGuard {
    ip: IpAddr,
    counter: Arc<AtomicUsize>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::SeqCst);
        if prev <= 1 {
            IP_ACTIVE_CONNS.remove_if(&self.ip, |_, val| Arc::strong_count(val) <= 2 && val.load(Ordering::SeqCst) == 0);
        }
    }
}

pub fn acquire_connection_guard(ip: IpAddr, max_per_ip: usize) -> Result<ConnectionGuard, &'static str> {
    let permit = Arc::clone(&*GLOBAL_CONN_SEMAPHORE).try_acquire_owned()
        .map_err(|_| "Global baglanti siniri (10.000) asildi")?;
    
    // [D-28] Loopback (127.0.0.1 / ::1) yerel ters vekil ve benchmarklar için 10.000 limite izin verir; dış IP'ler max_per_ip (50) ile korunur
    let effective_max = if ip.is_loopback() { 10000 } else { max_per_ip };

    let counter = IP_ACTIVE_CONNS
        .entry(ip)
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();
    
    let current = counter.fetch_add(1, Ordering::SeqCst);
    if current >= effective_max {
        counter.fetch_sub(1, Ordering::SeqCst);
        return Err("IP basina eszamanli baglanti siniri asildi");
    }

    Ok(ConnectionGuard {
        ip,
        counter,
        _permit: Some(permit),
    })
}

/// HTTP kabul döngüsünü arka planda başlatır.
pub(crate) fn spawn_http_accept_loop(
    listener: TcpListener,
    state: Arc<ServerState>,
    nodelay: bool,
    port: u16,
) {
    tokio::spawn(async move {
        loop {
            if let Ok((mut socket, peer_addr)) = listener.accept().await {
                if nodelay {
                    let _ = socket.set_nodelay(true);
                }
                let s = Arc::clone(&state);
                tokio::spawn(async move {
                    let guard = match acquire_connection_guard(peer_addr.ip(), 50) {
                        Ok(g) => g,
                        Err(_) => {
                            let resp = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nRetry-After: 5\r\nConnection: close\r\n\r\n429 Too Many Requests: Baglanti limiti asildi.\r\n";
                            let _ = socket.write_all(resp).await;
                            let _ = socket.shutdown().await;
                            return;
                        }
                    };
                    let _ = handle_web_connection(socket, peer_addr, s, false, port).await;
                    drop(guard);
                });
            }
        }
    });
}

/// HTTPS kabul döngüsünü (TLS el sıkışma + ALPN h2/http1.1 ayrımı) arka planda başlatır.
pub(crate) fn spawn_https_accept_loop(
    listener: TcpListener,
    acceptor: zmax_tls::TlsAcceptor,
    state: Arc<ServerState>,
    nodelay: bool,
    port: u16,
) {
    tokio::spawn(async move {
        loop {
            if let Ok((socket, peer_addr)) = listener.accept().await {
                if nodelay {
                    let _ = socket.set_nodelay(true);
                }
                let s = Arc::clone(&state);
                let acc = acceptor.clone();
                tokio::spawn(async move {
                    let guard = match acquire_connection_guard(peer_addr.ip(), 50) {
                        Ok(g) => g,
                        Err(_) => return, // TLS el sıkışma öncesi drop
                    };
                    let hs = tokio::time::timeout(Duration::from_secs(10), acc.accept(socket)).await;
                    if let Ok(Ok(tls_stream)) = hs {
                        let alpn = zmax_tls::negotiated_alpn(&tls_stream);
                        let sni = zmax_tls::client_sni(&tls_stream).map(|s| s.to_string());
                        if alpn.as_deref() == Some(b"h2") {
                            let _ = crate::pipeline::l2_protocol::h2::handle_h2_connection(
                                tls_stream, peer_addr, s, true, port, sni,
                            )
                            .await;
                        } else {
                            let _ = handle_web_connection(tls_stream, peer_addr, s, true, port).await;
                        }
                    }
                    drop(guard);
                });
            }
        }
    });
}

/// Ana Web Trafiği Yöneticisi (HTTP/1.1 Keep-Alive destekli).
pub async fn handle_web_connection<S>(
    mut socket: S,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
    is_https: bool,
    server_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let mut leftover = Vec::with_capacity(4096);
    let mut req_index = 0usize;

    loop {
        let (
            header_timeout_sec,
            body_timeout_sec,
            keep_alive_timeout_sec,
            max_header_bytes,
            max_body_bytes,
        ) = {
            let rt = state.runtime.read().await;
            let sec = &rt.config.security;
            let web_max_mb = sec.max_body_size_mb.max(1);
            (
                sec.slowloris_header_timeout_sec.max(1),
                sec.slowloris_body_timeout_sec.max(1),
                sec.keep_alive_timeout_sec.max(1),
                sec.max_header_size_kb.max(8) * 1024,
                web_max_mb * 1024 * 1024,
            )
        };

        // Keep-Alive bağlantı ikinci veya sonraki isteği boşta beklerken idle timeout uygular.
        if req_index > 0 && leftover.is_empty() {
            let mut pool_buf = state.buffer_pool.acquire();
            if pool_buf.capacity() < 4096 {
                pool_buf.reserve(4096);
            }
            let cap = pool_buf.capacity().min(8192);
            pool_buf.resize(cap, 0);
            let idle_res = with_idle_timeout(
                Duration::from_secs(keep_alive_timeout_sec),
                socket.read(&mut pool_buf[..]),
            )
            .await;

            match idle_res {
                Ok(Ok(n)) if n > 0 => {
                    leftover.extend_from_slice(&pool_buf[..n]);
                    state.buffer_pool.release(pool_buf);
                }
                _ => {
                    state.buffer_pool.release(pool_buf);
                    break;
                }
            }
        }

        let limits = HttpReadLimits {
            max_header_bytes,
            max_body_bytes,
            header_timeout: Duration::from_secs(header_timeout_sec),
            body_timeout: Duration::from_secs(body_timeout_sec),
        };

        let req = match read_http_request_with_limits(&mut socket, &mut leftover, limits).await {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(err) => {
                send_http_read_error(&mut socket, &err).await;
                break;
            }
        };

        req_index += 1;
        let should_keep_alive = handle_single_web_request(
            &mut socket,
            peer_addr,
            &state,
            is_https,
            server_port,
            keep_alive_timeout_sec,
            req,
        )
        .await?;

        if !should_keep_alive {
            break;
        }
    }

    Ok(())
}
