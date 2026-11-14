//! # L1 — Bağlantı Katmanı (`pipeline/l1_connection.rs`)
//!
//! TCP bağlantı kabulü, IP başına eşzamanlı bağlantı kısıtlaması,
//! idle/keep-alive zaman aşımları, slowloris (header/body timeout) koruması
//! ve bağlantı yaşam döngüsü yönetimi.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::state::ServerState;
use zmax_httpparser::HttpReadLimits;
use zmax_timeout::with_idle_timeout;

use super::{Outcome, PipelineLayer, RequestContext, Scheme};

/// L1 Bağlantı Katmanı Yöneticisi
pub struct L1ConnectionLayer;

impl L1ConnectionLayer {
    /// IP başına eşzamanlı bağlantı sınırını denetler ve bağlantı izni alır.
    pub fn try_acquire_connection(
        state: &ServerState,
        ip: IpAddr,
    ) -> Result<zmax_security::ConnGuard, ()> {
        state.conn_limiter.try_acquire(ip, None)
    }

    /// Aşırı eşzamanlı bağlantı durumunda 429 Too Many Requests yanıtı gönderir.
    pub async fn reject_too_many_connections<S>(socket: &mut S) -> tokio::io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let msg = b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain; charset=utf-8\r\nRetry-After: 5\r\nConnection: close\r\n\r\n429 Too Many Concurrent Connections\n";
        socket.write_all(msg).await?;
        socket.shutdown().await?;
        Ok(())
    }

    /// Çalışma zamanı yapılandırmasından L1 zaman aşımı ve boyut sınırlarını okur.
    pub async fn read_connection_limits(state: &ServerState) -> L1Limits {
        let rt = state.runtime.read().await;
        let sec = &rt.config.security;
        let web_max_mb = sec.max_body_size_mb.max(1);
        L1Limits {
            header_timeout_sec: sec.slowloris_header_timeout_sec.max(2),
            body_timeout_sec: sec.slowloris_body_timeout_sec.max(5),
            keep_alive_timeout_sec: sec.keep_alive_timeout_sec.max(1),
            max_header_bytes: sec.max_header_size_kb.max(8) * 1024,
            max_body_bytes: web_max_mb * 1024 * 1024,
        }
    }

    /// Keep-alive durumunda soketten bir sonraki istek için veri bekler (idle timeout ile).
    pub async fn wait_for_keep_alive_data<S>(
        socket: &mut S,
        state: &ServerState,
        leftover: &mut Vec<u8>,
        keep_alive_timeout_sec: u64,
    ) -> bool
    where
        S: AsyncRead + Unpin,
    {
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
                true
            }
            _ => {
                state.buffer_pool.release(pool_buf);
                false
            }
        }
    }
}

impl PipelineLayer for L1ConnectionLayer {
    fn run<'a>(
        &'a self,
        ctx: RequestContext,
        _st: &'a ServerState,
    ) -> Pin<Box<dyn Future<Output = Outcome> + Send + 'a>> {
        Box::pin(async move {
            Outcome::Continue(ctx)
        })
    }
}

/// L1 Katmanı Zaman Aşımı ve Boyut Sınırları
#[derive(Debug, Clone, Copy)]
pub struct L1Limits {
    pub header_timeout_sec: u64,
    pub body_timeout_sec: u64,
    pub keep_alive_timeout_sec: u64,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
}

impl L1Limits {
    pub fn to_http_read_limits(&self) -> HttpReadLimits {
        HttpReadLimits {
            max_header_bytes: self.max_header_bytes,
            max_body_bytes: self.max_body_bytes,
            header_timeout: Duration::from_secs(self.header_timeout_sec),
            body_timeout: Duration::from_secs(self.body_timeout_sec),
        }
    }
}
