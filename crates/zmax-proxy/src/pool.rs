//! # zmax-proxy :: pool
//!
//! Ters vekil (Reverse Proxy) için yüksek performanslı ve keep-alive uyumlu
//! TCP bağlantı havuzu (Connection Pool).
//!
//! Özellikler:
//! - Upstream ana bilgisayarlarına göre boşta bekleyen (idle) `TcpStream` bağlantılarını havuzlama.
//! - Bağlantı canlılık denetimi (liveness probe - soketin karşı tarafça kapatılıp kapatılmadığını algılama).
//! - Boşta kalma (idle timeout) süresi dolan bağlantıları otomatik temizleme.
//! - RAII guard (`PooledStream`) ile drop anında bağlantıyı otomatik havuza iade etme.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use crate::ProxyError;

const DEFAULT_POOL_SIZE: usize = 16;
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Boşta bekleyen tek bir bağlantı girişi.
struct IdleEntry {
    stream: TcpStream,
    idle_since: Instant,
}

/// Upstream başına bağlantı deposu.
struct HostPool {
    idle_streams: Vec<IdleEntry>,
}

impl HostPool {
    fn new() -> Self {
        Self {
            idle_streams: Vec::new(),
        }
    }
}

/// Ters vekil bağlantı havuzu.
#[derive(Clone)]
pub struct ProxyConnectionPool {
    inner: Arc<Mutex<HashMap<String, HostPool>>>,
    max_idle_per_host: usize,
    idle_timeout: Duration,
    connect_timeout: Duration,
}

impl Default for ProxyConnectionPool {
    fn default() -> Self {
        Self::new(DEFAULT_POOL_SIZE, DEFAULT_IDLE_TIMEOUT, DEFAULT_CONNECT_TIMEOUT)
    }
}

impl ProxyConnectionPool {
    /// Yeni bir bağlantı havuzu oluşturur.
    pub fn new(
        max_idle_per_host: usize,
        idle_timeout: Duration,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_idle_per_host: if max_idle_per_host == 0 {
                DEFAULT_POOL_SIZE
            } else {
                max_idle_per_host
            },
            idle_timeout,
            connect_timeout,
        }
    }

    pub fn max_idle_per_host(&self) -> usize {
        self.max_idle_per_host
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Verilen upstream adresi için canlı bir `TcpStream` temin eder.
    /// Havuzda boşta ve canlı bağlantı varsa onu yeniden kullanır; yoksa yeni bağlantı açar.
    pub async fn acquire(&self, upstream: &str) -> Result<PooledStream, ProxyError> {
        let normalized = normalize_upstream_addr(upstream);

        // 1. Havuzdan boşta ve canlı bağlantı ara
        {
            let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(host_pool) = map.get_mut(&normalized) {
                let now = Instant::now();
                while let Some(entry) = host_pool.idle_streams.pop() {
                    // Süresi dolmuş mu?
                    if now.duration_since(entry.idle_since) > self.idle_timeout {
                        continue;
                    }

                    // Soket hala canlı mı?
                    if is_stream_alive(&entry.stream) {
                        return Ok(PooledStream {
                            stream: Some(entry.stream),
                            upstream: normalized,
                            pool: Some(self.clone()),
                            reusable: true,
                        });
                    }
                }
            }
        }

        // 2. Havuzda canlı bağlantı yoksa yeni bağlantı kur
        let stream = tokio::time::timeout(self.connect_timeout, connect_upstream(&normalized))
            .await
            .map_err(|_| ProxyError::Connect("Baglanti zaman asimi".to_string()))?
            .map_err(|e| ProxyError::Connect(format!("Baglanti kurulamadi ({}): {}", normalized, e)))?;

        let _ = stream.set_nodelay(true);

        Ok(PooledStream {
            stream: Some(stream),
            upstream: normalized,
            pool: Some(self.clone()),
            reusable: true,
        })
    }

    /// Kullanımı biten bir bağlantıyı havuza iade eder.
    pub fn release(&self, upstream: &str, stream: TcpStream) {
        if !is_stream_alive(&stream) {
            return;
        }

        let normalized = normalize_upstream_addr(upstream);
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let host_pool = map.entry(normalized).or_insert_with(HostPool::new);

        // Kapasite dolmuşsa en eskiyi çıkar
        if host_pool.idle_streams.len() >= self.max_idle_per_host {
            host_pool.idle_streams.remove(0);
        }

        host_pool.idle_streams.push(IdleEntry {
            stream,
            idle_since: Instant::now(),
        });
    }

    /// Havuzdaki boşta bekleyen bağlantı sayısını döndürür.
    pub fn idle_count(&self, upstream: &str) -> usize {
        let normalized = normalize_upstream_addr(upstream);
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&normalized)
            .map(|hp| hp.idle_streams.len())
            .unwrap_or(0)
    }

    /// Süresi dolmuş tüm boşta bağlantıları temizler.
    pub fn cleanup_expired(&self) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        for host_pool in map.values_mut() {
            host_pool.idle_streams.retain(|entry| {
                now.duration_since(entry.idle_since) <= self.idle_timeout
                    && is_stream_alive(&entry.stream)
            });
        }
    }
}

/// RAII korumalı havuz bağlantısı.
/// Drop olduğunda, `reusable` bayrağı true ise bağlantıyı otomatik olarak havuza geri verir.
pub struct PooledStream {
    stream: Option<TcpStream>,
    upstream: String,
    pool: Option<ProxyConnectionPool>,
    reusable: bool,
}

impl PooledStream {
    /// Bağlantının yeniden kullanıma uygun olup olmadığını ayarlar.
    pub fn set_reusable(&mut self, reusable: bool) {
        self.reusable = reusable;
    }

    /// Bağlantının yeniden kullanılabilir olup olmadığını döndürür.
    pub fn is_reusable(&self) -> bool {
        self.reusable
    }

    /// Soketi havuz yönetiminden çıkarıp doğrudan tüketiciye devreder.
    pub fn into_inner(mut self) -> Option<TcpStream> {
        self.stream.take()
    }
}

impl Deref for PooledStream {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        self.stream.as_ref().expect("PooledStream soketi mevcut olmali")
    }
}

impl DerefMut for PooledStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.stream.as_mut().expect("PooledStream soketi mevcut olmali")
    }
}

impl Drop for PooledStream {
    fn drop(&mut self) {
        if self.reusable {
            if let (Some(stream), Some(pool)) = (self.stream.take(), self.pool.take()) {
                pool.release(&self.upstream, stream);
            }
        }
    }
}

impl fmt::Debug for PooledStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledStream")
            .field("upstream", &self.upstream)
            .field("reusable", &self.reusable)
            .finish()
    }
}

/// Soketin hala canlı (healthy) olup olmadığını kontrol eder.
/// Karşı taraf RST/FIN gönderdiyse 0 bayt okunur ve soket ölü kabul edilir.
fn is_stream_alive(stream: &TcpStream) -> bool {
    let mut buf = [0u8; 1];
    match stream.try_read(&mut buf) {
        Ok(0) => false, // Karşı uç bağlantıyı kapattı (EOF)
        Ok(_) => false, // Beklenmeyen veri var, sıfır durumda değil
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true, // Normal boşta soket
        Err(_) => false, // Bağlantı hatası (RST, vb.)
    }
}

/// Upstream URL veya adresi normalize eder (`http://127.0.0.1:3000/` -> `127.0.0.1:3000`).
pub fn normalize_upstream_addr(raw: &str) -> String {
    let s = raw.trim();
    let without_proto = if let Some(stripped) = s.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = s.strip_prefix("https://") {
        stripped
    } else {
        s
    };

    let without_path = without_proto.split(['/', '?', '#']).next().unwrap_or(without_proto);
    without_path.trim().to_string()
}

/// Arka uç adresine bağlanır.
async fn connect_upstream(addr_str: &str) -> std::io::Result<TcpStream> {
    if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        return TcpStream::connect(sa).await;
    }

    TcpStream::connect(addr_str).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_normalize_upstream_addr() {
        assert_eq!(normalize_upstream_addr("http://127.0.0.1:3000"), "127.0.0.1:3000");
        assert_eq!(normalize_upstream_addr("http://127.0.0.1:3000/api/v1"), "127.0.0.1:3000");
        assert_eq!(normalize_upstream_addr("https://backend.local:8443/"), "backend.local:8443");
        assert_eq!(normalize_upstream_addr("127.0.0.1:8080"), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn test_pool_acquire_and_reuse() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Arka uç sunucu simülasyonu
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 128];
                    // Basit yankı/açık tutma
                    while let Ok(n) = socket.try_read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                    }
                });
            }
        });

        let pool = ProxyConnectionPool::new(4, Duration::from_secs(10), Duration::from_secs(2));
        let addr_str = addr.to_string();

        // 1. İlk bağlantıyı al
        let conn1 = pool.acquire(&addr_str).await.expect("Ilk baglanti alinmali");
        assert!(conn1.is_reusable());
        drop(conn1); // Havuza iade edilmeli

        let idle_count = pool.idle_count(&addr_str);
        assert_eq!(idle_count, 1);

        // 2. İkinci kez al - havuzdaki bağlantı kullanılmalı
        let conn2 = pool.acquire(&addr_str).await.expect("Ikinci baglanti alinmali");
        drop(conn2);

        assert_eq!(pool.idle_count(&addr_str), 1);
    }

    #[tokio::test]
    async fn test_pool_discards_unreusable_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let pool = ProxyConnectionPool::new(4, Duration::from_secs(10), Duration::from_secs(2));
        let addr_str = addr.to_string();

        let mut conn = pool.acquire(&addr_str).await.expect("Baglanti acilmali");
        conn.set_reusable(false); // Yeniden kullanıma uygun değil
        drop(conn);

        assert_eq!(pool.idle_count(&addr_str), 0);
    }
}
