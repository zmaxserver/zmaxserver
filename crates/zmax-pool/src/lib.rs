//! # zmax-pool
//! Sıfır kopyalama bellek havuzu (Buffer Pool) ve arka uç Keep-Alive bağlantı havuzu.

use bytes::BytesMut;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_FAIL_COOLDOWN: Duration = Duration::from_secs(5);

/// Yeniden kullanılabilir bayt tamponu havuzu (malloc/free yükünü sıfırlar)
pub struct BufferPool {
    pool: Mutex<Vec<BytesMut>>,
    buffer_capacity: usize,
    max_pool_size: usize,
}

impl BufferPool {
    pub fn new(buffer_capacity: usize, max_pool_size: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(max_pool_size)),
            buffer_capacity,
            max_pool_size,
        }
    }

    /// Havuzdan bir tampon alır; havuz boşsa yeni bir tane ayırır
    pub fn acquire(&self) -> BytesMut {
        if let Ok(mut lock) = self.pool.lock() {
            if let Some(buf) = lock.pop() {
                return buf;
            }
        }
        BytesMut::with_capacity(self.buffer_capacity)
    }

    /// Kullanılan tamponu temizleyip (clear) tekrar kullanılmak üzere havuza iade eder
    pub fn release(&self, mut buf: BytesMut) {
        buf.clear();
        if let Ok(mut lock) = self.pool.lock() {
            if lock.len() < self.max_pool_size {
                lock.push(buf);
            }
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        // Varsayılan: 8 KB tampon boyutu, havuzda maksimum 1024 adet hazır tampon
        Self::new(8192, 1024)
    }
}

#[derive(Debug)]
struct PooledStream {
    stream: TcpStream,
    last_used: Instant,
    ttl: Duration,
}

/// Soket havuzunun anlık durum istatistikleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PoolStats {
    /// Havuzda boşta bekleyen (süresi dolmamış) toplam soket sayısı.
    pub active_idle: usize,
    /// Havuzda kayıtlı boşta soketi bulunan arka uç sayısı.
    pub total_upstreams: usize,
}

/// `mod_fastcgi` / `mod_proxy` arka uç bağlantıları için yeniden kullanılabilir `TcpStream` havuzu.
#[derive(Debug)]
pub struct UpstreamSocketPool {
    pools: Mutex<HashMap<String, VecDeque<PooledStream>>>,
    active_conns: Mutex<HashMap<String, usize>>,
    max_idle_per_upstream: usize,
    idle_ttl: Duration,
}

impl Default for UpstreamSocketPool {
    fn default() -> Self {
        Self::new(32)
    }
}

impl UpstreamSocketPool {
    pub fn new(max_idle_per_upstream: usize) -> Self {
        Self::with_idle_ttl(max_idle_per_upstream, DEFAULT_IDLE_TTL)
    }

    pub fn with_idle_ttl(max_idle_per_upstream: usize, idle_ttl: Duration) -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
            active_conns: Mutex::new(HashMap::new()),
            max_idle_per_upstream,
            idle_ttl,
        }
    }

    /// Belirtilen upstream için aktif bağlantı yuvası almaya çalışır.
    /// `max_conns > 0` ise ve mevcut aktif bağlantı sayısı >= `max_conns` ise `false` döner.
    pub fn try_acquire_conns_slot(&self, addr: &str, max_conns: usize) -> bool {
        if max_conns == 0 {
            return true;
        }
        let mut map = self.active_conns.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(addr.to_string()).or_insert(0);
        if *count >= max_conns {
            false
        } else {
            *count += 1;
            true
        }
    }

    /// Aktif bağlantı yuvasını serbest bırakır.
    pub fn release_conns_slot(&self, addr: &str) {
        let mut map = self.active_conns.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(addr) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(addr);
            }
        }
    }

    /// Belirli bir upstream için aktif bağlantı sayısını döndürür.
    pub fn active_count(&self, addr: &str) -> usize {
        let map = self.active_conns.lock().unwrap_or_else(|e| e.into_inner());
        map.get(addr).copied().unwrap_or(0)
    }

    /// Boşta bekleyen sağlıklı bir soket verir; yoksa `timeout` süresi içinde yeni TCP bağlantısı açar.
    pub async fn acquire(&self, addr: &str, timeout: Duration) -> io::Result<TcpStream> {
        self.acquire_with_timeout(addr, timeout).await
    }

    /// Boşta bekleyen sağlıklı bir soket verir; yoksa `dial_timeout` süresi içinde yeni TCP bağlantısı açar.
    pub async fn acquire_with_timeout(
        &self,
        addr: &str,
        dial_timeout: Duration,
    ) -> io::Result<TcpStream> {
        let (stream, _) = self.acquire_tagged_with_timeout(addr, dial_timeout).await?;
        Ok(stream)
    }

    /// Soketi havuzdan (`true`) veya yeni bağlantı açarak (`false`) verir.
    pub async fn acquire_tagged_with_timeout(
        &self,
        addr: &str,
        dial_timeout: Duration,
    ) -> io::Result<(TcpStream, bool)> {
        loop {
            let candidate = {
                let mut map = self.pools.lock().unwrap_or_else(|e| e.into_inner());
                let Some(queue) = map.get_mut(addr) else {
                    break;
                };
                let mut picked = None;
                while let Some(entry) = queue.pop_back() {
                    if entry.last_used.elapsed() < entry.ttl {
                        picked = Some(entry.stream);
                        break;
                    }
                }
                if queue.is_empty() {
                    map.remove(addr);
                }
                picked
            };

            let Some(stream) = candidate else {
                break;
            };

            if is_stream_healthy(&stream) {
                let _ = stream.set_nodelay(true);
                return Ok((stream, true));
            }
        }

        let stream = self.dial_fresh_with_timeout(addr, dial_timeout).await?;
        Ok((stream, false))
    }

    /// Havuza bakmadan `dial_timeout` süresi içinde doğrudan yeni TCP bağlantısı açar.
    pub async fn dial_fresh_with_timeout(
        &self,
        addr: &str,
        dial_timeout: Duration,
    ) -> io::Result<TcpStream> {
        let stream = tokio::time::timeout(dial_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Arka uc baglanti zaman asimi"))??;
        let _ = stream.set_nodelay(true);
        Ok(stream)
    }

    /// Kullanımı biten sağlıklı soketi belirtilen TTL ile tekrar kullanılmak üzere havuza geri alır.
    pub fn release_with_ttl(&self, addr: &str, stream: TcpStream, ttl: Duration) {
        if self.max_idle_per_upstream == 0 || !is_stream_healthy(&stream) {
            return;
        }

        let now = Instant::now();
        let mut map = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        let queue = map.entry(addr.to_string()).or_default();

        while let Some(front) = queue.front() {
            if now.duration_since(front.last_used) >= front.ttl {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() < self.max_idle_per_upstream {
            queue.push_back(PooledStream {
                stream,
                last_used: now,
                ttl,
            });
        }
    }

    /// Kullanımı biten sağlıklı soketi tekrar kullanılmak üzere havuza geri alır.
    pub fn release(&self, addr: &str, stream: TcpStream) {
        self.release_with_ttl(addr, stream, self.idle_ttl);
    }

    /// Hatalı veya yarıda kalan soketi havuza iade etmeden kapatır.
    pub fn discard(&self, stream: TcpStream) {
        drop(stream);
    }

    /// Belirli bir upstream için havuzdaki tüm boşta bekleyen soketleri temizler.
    pub fn discard_upstream(&self, addr: &str) -> usize {
        let mut map = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(addr).map(|q| q.len()).unwrap_or(0)
    }

    /// Belirli bir upstream için havuzda bekleyen soket sayısını döndürür.
    pub fn idle_count(&self, addr: &str) -> usize {
        let map = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        map.get(addr).map(|q| q.len()).unwrap_or(0)
    }

    /// Süresi dolmuş soketleri temizler ve güncel havuz istatistiklerini döner.
    pub fn stats(&self) -> PoolStats {
        let now = Instant::now();
        let mut map = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        let mut active_idle = 0usize;
        map.retain(|_, queue| {
            queue.retain(|e| now.duration_since(e.last_used) < e.ttl);
            active_idle += queue.len();
            !queue.is_empty()
        });
        PoolStats {
            active_idle,
            total_upstreams: map.len(),
        }
    }

    /// Süresi dolmuş boşta bekleyen tüm soketleri temizler ve çıkarılan sayıyı döner.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let mut map = self.pools.lock().unwrap_or_else(|e| e.into_inner());
        let mut removed = 0usize;
        map.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|e| now.duration_since(e.last_used) < e.ttl);
            removed += before.saturating_sub(queue.len());
            !queue.is_empty()
        });
        removed
    }
}

fn is_stream_healthy(stream: &TcpStream) -> bool {
    let mut probe = [0u8; 1];
    match stream.try_read(&mut probe) {
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
        Ok(0) => false,
        Ok(_) => false,
        Err(_) => false,
    }
}

/// Çoklu arka uç yük dengeleme politikası.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbPolicy {
    /// Arka uçlar arasında sırayla dairesel dağıtım.
    RoundRobin,
    /// En az aktif bağlantıya sahip arka ucu seçer.
    LeastConn,
}

#[derive(Debug)]
struct BackendState {
    index: usize,
    addr: String,
    active_conns: AtomicUsize,
    failed_until: Mutex<Option<Instant>>,
}

/// Seçilen arka uç için RAII bağlantı kiralaması; `Drop` anında aktif bağlantı sayacını düşürür.
#[derive(Debug)]
pub struct UpstreamLease {
    state: Arc<BackendState>,
}

impl UpstreamLease {
    /// Seçilen arka ucun ağ adresini döner.
    pub fn addr(&self) -> &str {
        &self.state.addr
    }

    /// Seçilen arka ucun dengeleyici içindeki indeksini döner.
    pub fn index(&self) -> usize {
        self.state.index
    }

    /// Bu arka uç üzerindeki anlık aktif kiralama sayısını döner.
    pub fn active_conns(&self) -> usize {
        self.state.active_conns.load(Ordering::Acquire)
    }
}

impl Drop for UpstreamLease {
    fn drop(&mut self) {
        self.state.active_conns.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Pasif sağlık kontrolü destekli çoklu arka uç yük dengeleyici.
#[derive(Debug)]
pub struct UpstreamBalancer {
    backends: Vec<Arc<BackendState>>,
    policy: LbPolicy,
    rr_cursor: AtomicUsize,
    cooldown: Duration,
}

impl UpstreamBalancer {
    /// Varsayılan 5 saniyelik pasif sağlık cooldown süresiyle yük dengeleyici oluşturur.
    pub fn new(upstreams: Vec<String>, policy: LbPolicy) -> Self {
        Self::with_cooldown(upstreams, policy, DEFAULT_FAIL_COOLDOWN)
    }

    /// Özel pasif sağlık cooldown süresiyle yük dengeleyici oluşturur.
    pub fn with_cooldown(upstreams: Vec<String>, policy: LbPolicy, cooldown: Duration) -> Self {
        let backends = upstreams
            .into_iter()
            .enumerate()
            .map(|(index, addr)| {
                Arc::new(BackendState {
                    index,
                    addr,
                    active_conns: AtomicUsize::new(0),
                    failed_until: Mutex::new(None),
                })
            })
            .collect();
        Self {
            backends,
            policy,
            rr_cursor: AtomicUsize::new(0),
            cooldown,
        }
    }

    /// Politikaya ve pasif sağlık durumuna göre uygun arka ucu seçip RAII kiralama döner.
    pub fn pick(&self) -> Option<UpstreamLease> {
        let n = self.backends.len();
        if n == 0 {
            return None;
        }

        let now = Instant::now();
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % n;

        let chosen_idx = match self.policy {
            LbPolicy::RoundRobin => {
                let mut healthy_pick = None;
                for offset in 0..n {
                    let idx = (start + offset) % n;
                    if check_backend_cooldown(&self.backends[idx], now).is_none() {
                        healthy_pick = Some(idx);
                        break;
                    }
                }
                healthy_pick
            }
            LbPolicy::LeastConn => {
                let mut best: Option<(usize, usize)> = None;
                for offset in 0..n {
                    let idx = (start + offset) % n;
                    if check_backend_cooldown(&self.backends[idx], now).is_none() {
                        let conns = self.backends[idx].active_conns.load(Ordering::Acquire);
                        if best.is_none_or(|(_, min)| conns < min) {
                            best = Some((idx, conns));
                        }
                    }
                }
                best.map(|(idx, _)| idx)
            }
        }
        .unwrap_or_else(|| self.pick_earliest_recovery(now));

        let backend = &self.backends[chosen_idx];
        backend.active_conns.fetch_add(1, Ordering::AcqRel);
        Some(UpstreamLease {
            state: Arc::clone(backend),
        })
    }

    /// Tüm arka uçlar cooldown içindeyken iyileşmesine en az süre kalan (eşitlikte ilk) arka ucu seçer.
    fn pick_earliest_recovery(&self, now: Instant) -> usize {
        let mut best_idx = 0usize;
        let mut best_until: Option<Instant> = None;

        for (idx, backend) in self.backends.iter().enumerate() {
            match check_backend_cooldown(backend, now) {
                None => return idx,
                Some(until) => {
                    if best_until.is_none_or(|cur| until < cur) {
                        best_until = Some(until);
                        best_idx = idx;
                    }
                }
            }
        }
        best_idx
    }

    /// İlgili arka ucu geçici olarak sağlıksız işaretler ve cooldown süresince pas geçer.
    pub fn mark_failed(&self, idx: usize) {
        if let Some(backend) = self.backends.get(idx) {
            let mut guard = backend.failed_until.lock().unwrap_or_else(|e| e.into_inner());
            *guard = Some(Instant::now() + self.cooldown);
        }
    }

    /// İlgili arka ucu tekrar sağlıklı duruma sıfırlar.
    pub fn mark_healthy(&self, idx: usize) {
        if let Some(backend) = self.backends.get(idx) {
            let mut guard = backend.failed_until.lock().unwrap_or_else(|e| e.into_inner());
            *guard = None;
        }
    }

    /// Arka ucun şu anda sağlıklı olup olmadığını döner.
    pub fn is_healthy(&self, idx: usize) -> bool {
        self.backends
            .get(idx)
            .is_some_and(|b| check_backend_cooldown(b, Instant::now()).is_none())
    }

    /// Arka uçtaki aktif kiralama sayısını döner.
    pub fn active_conns(&self, idx: usize) -> usize {
        self.backends
            .get(idx)
            .map_or(0, |b| b.active_conns.load(Ordering::Acquire))
    }

    /// Kayıtlı arka uç sayısını döner.
    pub fn len(&self) -> usize {
        self.backends.len()
    }

    /// Arka uç listesinin boş olup olmadığını döner.
    pub fn is_empty(&self) -> bool {
        self.backends.is_empty()
    }

    /// Verilen indeksteki arka uç adresini döner.
    pub fn addr(&self, idx: usize) -> Option<&str> {
        self.backends.get(idx).map(|b| b.addr.as_str())
    }
}

/// Cooldown dolmuşsa sıfırlar ve `None` döner; devam ediyorsa bitiş anını döner.
fn check_backend_cooldown(backend: &BackendState, now: Instant) -> Option<Instant> {
    let mut guard = backend.failed_until.lock().unwrap_or_else(|e| e.into_inner());
    match *guard {
        None => None,
        Some(until) if now >= until => {
            *guard = None;
            None
        }
        Some(until) => Some(until),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn test_buffer_pool_acquire_and_release() {
        let pool = BufferPool::new(1024, 2);
        let mut buf = pool.acquire();
        assert!(buf.capacity() >= 1024);
        buf.extend_from_slice(b"merhaba");
        pool.release(buf);

        let reused = pool.acquire();
        assert_eq!(reused.len(), 0);
        assert!(reused.capacity() >= 1024);
    }

    #[tokio::test]
    async fn test_upstream_socket_pool_reuses_healthy_socket_and_respects_limit() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let accept_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accept_count_srv = accept_count.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                accept_count_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });

        let pool = UpstreamSocketPool::new(2);
        let timeout = Duration::from_secs(2);

        // İlk bağlantı yeni açılır
        let mut s1 = pool.acquire(&addr, timeout).await.unwrap();
        s1.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        s1.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        pool.release(&addr, s1);
        assert_eq!(pool.idle_count(&addr), 1);

        // İkinci acquire havuzdaki aynı bağlantıyı yeniden kullanmalı (accept_count == 1)
        let mut s2 = pool.acquire(&addr, timeout).await.unwrap();
        assert_eq!(pool.idle_count(&addr), 0);
        s2.write_all(b"pong").await.unwrap();
        s2.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"pong");
        assert_eq!(accept_count.load(std::sync::atomic::Ordering::SeqCst), 1);

        // max_idle_per_upstream = 2 sınırını test et
        let s3 = pool.acquire(&addr, timeout).await.unwrap();
        let s4 = pool.acquire(&addr, timeout).await.unwrap();
        pool.release(&addr, s2);
        pool.release(&addr, s3);
        pool.release(&addr, s4);
        assert_eq!(pool.idle_count(&addr), 2);
    }

    #[tokio::test]
    async fn test_upstream_socket_pool_discards_closed_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            // İlk bağlantıyı hemen kapat
            if let Ok((s1, _)) = listener.accept().await {
                drop(s1);
            }
            // İkinci bağlantıyı açık tut ve yankıla
            if let Ok((mut s2, _)) = listener.accept().await {
                let mut buf = [0u8; 16];
                if let Ok(n) = s2.read(&mut buf).await {
                    let _ = s2.write_all(&buf[..n]).await;
                }
            }
        });

        let pool = UpstreamSocketPool::new(4);
        let s1 = pool.acquire(&addr, Duration::from_secs(2)).await.unwrap();
        // Sunucunun kapatma FIN paketinin iletilmesi için kısa bekleme
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Kapalı soket release edilse bile havuza alınmaz (veya alınsa bile acquire'da atılır)
        pool.release(&addr, s1);

        let mut s2 = pool.acquire(&addr, Duration::from_secs(2)).await.unwrap();
        s2.write_all(b"ok").await.unwrap();
        let mut out = [0u8; 2];
        s2.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ok");
    }

    #[tokio::test]
    async fn test_pool_acquire_with_timeout_discard_and_stats() {
        let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = l1.local_addr().unwrap().to_string();
        let addr2 = l2.local_addr().unwrap().to_string();

        tokio::spawn(async move {
            let mut keep = Vec::new();
            while let Ok((s, _)) = l1.accept().await {
                keep.push(s);
            }
        });
        tokio::spawn(async move {
            let mut keep = Vec::new();
            while let Ok((s, _)) = l2.accept().await {
                keep.push(s);
            }
        });

        let pool = UpstreamSocketPool::new(4);
        assert_eq!(
            pool.stats(),
            PoolStats {
                active_idle: 0,
                total_upstreams: 0
            }
        );

        let s1 = pool
            .acquire_with_timeout(&addr1, Duration::from_secs(2))
            .await
            .unwrap();
        let s2 = pool
            .acquire_with_timeout(&addr2, Duration::from_secs(2))
            .await
            .unwrap();
        let s3 = pool
            .acquire_with_timeout(&addr1, Duration::from_secs(2))
            .await
            .unwrap();

        pool.release(&addr1, s1);
        pool.release(&addr2, s2);
        // s3 discard edilirse havuza eklenmemeli
        pool.discard(s3);

        assert_eq!(
            pool.stats(),
            PoolStats {
                active_idle: 2,
                total_upstreams: 2
            }
        );

        assert_eq!(pool.discard_upstream(&addr1), 1);
        assert_eq!(
            pool.stats(),
            PoolStats {
                active_idle: 1,
                total_upstreams: 1
            }
        );
    }

    #[test]
    fn test_balancer_round_robin_distribution() {
        let empty = UpstreamBalancer::new(vec![], LbPolicy::RoundRobin);
        assert!(empty.is_empty());
        assert!(empty.pick().is_none());

        let balancer = UpstreamBalancer::new(
            vec![
                "127.0.0.1:9001".to_string(),
                "127.0.0.1:9002".to_string(),
                "127.0.0.1:9003".to_string(),
            ],
            LbPolicy::RoundRobin,
        );

        let mut picked_indices = Vec::new();
        for _ in 0..6 {
            let lease = balancer.pick().unwrap();
            picked_indices.push(lease.index());
            assert_eq!(lease.active_conns(), 1);
        }
        assert_eq!(picked_indices, vec![0, 1, 2, 0, 1, 2]);
        assert_eq!(balancer.active_conns(0), 0);
        assert_eq!(balancer.active_conns(1), 0);
        assert_eq!(balancer.active_conns(2), 0);
    }

    #[test]
    fn test_balancer_least_conn_and_raii_drop() {
        let balancer = UpstreamBalancer::new(
            vec![
                "127.0.0.1:9001".to_string(),
                "127.0.0.1:9002".to_string(),
                "127.0.0.1:9003".to_string(),
            ],
            LbPolicy::LeastConn,
        );

        let l0 = balancer.pick().unwrap();
        assert_eq!(l0.index(), 0);
        assert_eq!(balancer.active_conns(0), 1);

        let l1 = balancer.pick().unwrap();
        assert_eq!(l1.index(), 1);
        assert_eq!(balancer.active_conns(1), 1);

        let l2 = balancer.pick().unwrap();
        assert_eq!(l2.index(), 2);
        assert_eq!(balancer.active_conns(2), 1);

        // Eşitlikte (1,1,1) sıradaki (0) seçilir -> [2, 1, 1]
        let l0_extra = balancer.pick().unwrap();
        assert_eq!(l0_extra.index(), 0);
        assert_eq!(balancer.active_conns(0), 2);

        // 1 bırakılınca aktifler [2, 0, 1] olur; sonraki pick kesinlikle 1'i seçmeli
        drop(l1);
        assert_eq!(balancer.active_conns(1), 0);

        let picked_least = balancer.pick().unwrap();
        assert_eq!(picked_least.index(), 1);
        assert_eq!(picked_least.addr(), "127.0.0.1:9002");
        assert_eq!(balancer.active_conns(1), 1);

        // Aktifler [2, 1, 1] iken 0 (2 aktif) seçilmemeli
        let picked_not_busiest = balancer.pick().unwrap();
        assert_ne!(picked_not_busiest.index(), 0);

        drop(l0);
        drop(l2);
        drop(l0_extra);
        drop(picked_least);
        drop(picked_not_busiest);

        for idx in 0..balancer.len() {
            assert_eq!(balancer.active_conns(idx), 0);
        }
    }

    #[test]
    fn test_balancer_passive_failover_and_all_failed_fallback() {
        let balancer = UpstreamBalancer::with_cooldown(
            vec![
                "127.0.0.1:9001".to_string(),
                "127.0.0.1:9002".to_string(),
                "127.0.0.1:9003".to_string(),
            ],
            LbPolicy::RoundRobin,
            Duration::from_millis(50),
        );

        balancer.mark_failed(0);
        assert!(!balancer.is_healthy(0));
        assert!(balancer.is_healthy(1));
        assert!(balancer.is_healthy(2));

        // 0 pas geçilmeli
        for _ in 0..6 {
            let lease = balancer.pick().unwrap();
            assert_ne!(lease.index(), 0);
        }

        // Tüm arka uçlar başarısız olursa en erken iyileşecek olana (0) düşmeli
        std::thread::sleep(Duration::from_millis(10));
        balancer.mark_failed(1);
        balancer.mark_failed(2);
        let fallback = balancer.pick().unwrap();
        assert_eq!(fallback.index(), 0);
        drop(fallback);

        // Manuel sağlıklıya çekme hemen sıfırlar
        balancer.mark_healthy(2);
        assert!(balancer.is_healthy(2));
        let recovered = balancer.pick().unwrap();
        assert_eq!(recovered.index(), 2);
        drop(recovered);

        // Cooldown dolunca kalanlar da otomatik iyileşmeli
        std::thread::sleep(Duration::from_millis(60));
        assert!(balancer.is_healthy(0));
        assert!(balancer.is_healthy(1));
        assert!(balancer.is_healthy(2));
    }
}
