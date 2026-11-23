//! # zmax-tls :: session
//! TLS Session Cache ve Bilet (Session Ticket) yönetimi.
//!
//! TLS 1.2 Session ID ve TLS 1.3 PSK / Session Ticket tabanlı oturum sürdürme
//! (Session Resumption) işlemlerini izler, sınırlar ve yüksek hızda sunar.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use rustls::server::{ProducesTickets, StoresServerSessions};
use rustls::Error;

/// TLS Oturum önbellek metrikleri (telemetri ve canlı istatistikler).
#[derive(Debug, Default)]
pub struct SessionCacheMetrics {
    puts: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    takes: AtomicU64,
}

impl SessionCacheMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_put(&self) {
        self.puts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_take(&self) {
        self.takes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn puts(&self) -> u64 {
        self.puts.load(Ordering::Relaxed)
    }

    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    pub fn takes(&self) -> u64 {
        self.takes.load(Ordering::Relaxed)
    }

    pub fn total_lookups(&self) -> u64 {
        self.hits() + self.misses()
    }

    pub fn hit_ratio(&self) -> f64 {
        let total = self.total_lookups();
        if total == 0 {
            0.0
        } else {
            (self.hits() as f64) / (total as f64)
        }
    }

    pub fn reset(&self) {
        self.puts.store(0, Ordering::Relaxed);
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.takes.store(0, Ordering::Relaxed);
    }
}

/// Metrik toplayan, bellek sınırlı TLS oturum önbellek sarmalayıcısı.
pub struct InstrumentedSessionCache {
    inner: Arc<dyn StoresServerSessions>,
    metrics: Arc<SessionCacheMetrics>,
}

impl std::fmt::Debug for InstrumentedSessionCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstrumentedSessionCache")
            .field("hits", &self.metrics.hits())
            .field("misses", &self.metrics.misses())
            .field("puts", &self.metrics.puts())
            .finish()
    }
}

impl InstrumentedSessionCache {
    pub fn new(capacity: usize) -> (Arc<Self>, Arc<SessionCacheMetrics>) {
        let inner = rustls::server::ServerSessionMemoryCache::new(capacity);
        let metrics = Arc::new(SessionCacheMetrics::new());
        let cache = Arc::new(Self {
            inner,
            metrics: Arc::clone(&metrics),
        });
        (cache, metrics)
    }

    pub fn metrics(&self) -> &Arc<SessionCacheMetrics> {
        &self.metrics
    }
}

impl StoresServerSessions for InstrumentedSessionCache {
    fn put(&self, key: Vec<u8>, val: Vec<u8>) -> bool {
        let res = self.inner.put(key, val);
        if res {
            self.metrics.record_put();
        }
        res
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let res = self.inner.get(key);
        if res.is_some() {
            self.metrics.record_hit();
        } else {
            self.metrics.record_miss();
        }
        res
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        let res = self.inner.take(key);
        if res.is_some() {
            self.metrics.record_take();
        }
        res
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

/// Dinleyici düzeyinde TLS Session ve Bilet ayarları.
#[derive(Debug, Clone)]
pub struct TlsSessionConfig {
    /// Oturum önbellek kapasitesi (maksimum saklanacak oturum adedi).
    pub cache_capacity: usize,
    /// Oturum sürdürme (resumption) etkin mi?
    pub resumption_enabled: bool,
    /// TLS 1.2 / 1.3 bilet üretimi etkin mi?
    pub tickets_enabled: bool,
    /// Bilet geçerlilik süresi (saniye).
    pub ticket_lifetime_secs: u32,
}

impl Default for TlsSessionConfig {
    fn default() -> Self {
        Self {
            cache_capacity: 2048,
            resumption_enabled: true,
            tickets_enabled: true,
            ticket_lifetime_secs: 43200, // 12 saat (RFC 5077 / OLS standardı)
        }
    }
}

impl TlsSessionConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = capacity;
        self
    }

    pub fn with_resumption(mut self, enabled: bool) -> Self {
        self.resumption_enabled = enabled;
        self
    }

    pub fn with_tickets(mut self, enabled: bool) -> Self {
        self.tickets_enabled = enabled;
        self
    }

    pub fn with_ticket_lifetime_secs(mut self, secs: u32) -> Self {
        self.ticket_lifetime_secs = secs;
        self
    }

    /// Oturum deposunu ve metrik nesnesini oluşturur.
    pub fn build_storage(&self) -> (Arc<dyn StoresServerSessions>, Arc<SessionCacheMetrics>) {
        if !self.resumption_enabled || self.cache_capacity == 0 {
            let metrics = Arc::new(SessionCacheMetrics::new());
            (Arc::new(NoSessionStorage), metrics)
        } else {
            let (cache, metrics) = InstrumentedSessionCache::new(self.cache_capacity);
            (cache, metrics)
        }
    }

    /// Session Ticket üreticisini oluşturur.
    pub fn build_ticketer(&self) -> Result<Arc<dyn ProducesTickets>, Error> {
        if !self.tickets_enabled {
            Ok(Arc::new(NoTickets))
        } else {
            Ok(Arc::new(InMemoryTicketer::new(self.ticket_lifetime_secs)))
        }
    }
}

/// Oturum kaydetmeyen pasif depolama.
#[derive(Debug)]
struct NoSessionStorage;

impl StoresServerSessions for NoSessionStorage {
    fn put(&self, _key: Vec<u8>, _val: Vec<u8>) -> bool {
        false
    }
    fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn take(&self, _key: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn can_cache(&self) -> bool {
        false
    }
}

/// Bilet üretmeyen pasif üretici.
#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }
    fn lifetime(&self) -> u32 {
        0
    }
    fn encrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn decrypt(&self, _bytes: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Bellek içi güvenli Session Ticket üreticisi.
#[derive(Debug)]
pub struct InMemoryTicketer {
    lifetime: u32,
    tickets: RwLock<HashMap<Vec<u8>, (Vec<u8>, Instant)>>,
}

impl InMemoryTicketer {
    pub fn new(lifetime_secs: u32) -> Self {
        Self {
            lifetime: lifetime_secs,
            tickets: RwLock::new(HashMap::new()),
        }
    }
}

impl ProducesTickets for InMemoryTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut ticket_id = vec![0u8; 32];
        ticket_id[0..16].copy_from_slice(&nanos.to_le_bytes());
        ticket_id[16..24].copy_from_slice(&count.to_le_bytes());
        ticket_id[24..32].copy_from_slice(&(plain.len() as u64).to_le_bytes());

        let expires = Instant::now() + Duration::from_secs(self.lifetime as u64);
        if let Ok(mut lock) = self.tickets.write() {
            if lock.len() > 2000 {
                let now = Instant::now();
                lock.retain(|_, (_, exp)| *exp > now);
            }
            lock.insert(ticket_id.clone(), (plain.to_vec(), expires));
        }
        Some(ticket_id)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        let lock = self.tickets.read().ok()?;
        if let Some((plain, expires)) = lock.get(cipher) {
            if Instant::now() <= *expires {
                return Some(plain.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instrumented_session_cache_records_metrics() {
        let (cache, metrics) = InstrumentedSessionCache::new(10);
        assert_eq!(metrics.hits(), 0);
        assert_eq!(metrics.misses(), 0);
        assert_eq!(metrics.puts(), 0);

        // Put session
        let key = vec![1, 2, 3];
        let val = vec![4, 5, 6];
        assert!(cache.put(key.clone(), val.clone()));
        assert_eq!(metrics.puts(), 1);

        // Cache hit
        let retrieved = cache.get(&key);
        assert_eq!(retrieved, Some(val.clone()));
        assert_eq!(metrics.hits(), 1);
        assert_eq!(metrics.misses(), 0);
        assert!((metrics.hit_ratio() - 1.0).abs() < 1e-6);

        // Cache miss
        let missing = cache.get(&[9, 9, 9]);
        assert_eq!(missing, None);
        assert_eq!(metrics.hits(), 1);
        assert_eq!(metrics.misses(), 1);
        assert_eq!(metrics.total_lookups(), 2);
        assert!((metrics.hit_ratio() - 0.5).abs() < 1e-6);

        // Take session
        let taken = cache.take(&key);
        assert_eq!(taken, Some(val));
        assert_eq!(metrics.takes(), 1);

        // Now key is gone
        assert_eq!(cache.get(&key), None);
        assert_eq!(metrics.misses(), 2);
    }

    #[test]
    fn test_tls_session_config_disabled() {
        let cfg = TlsSessionConfig::new().with_resumption(false);
        let (storage, _metrics) = cfg.build_storage();
        assert!(!storage.can_cache());
        assert!(!storage.put(vec![1], vec![2]));
        assert_eq!(storage.get(&[1]), None);

        let ticketer_res = TlsSessionConfig::new().with_tickets(false).build_ticketer();
        assert!(ticketer_res.is_ok());
        let ticketer = ticketer_res.unwrap();
        assert!(!ticketer.enabled());
    }

    #[test]
    fn test_in_memory_ticketer_encrypt_and_decrypt() {
        let ticketer = InMemoryTicketer::new(3600);
        assert!(ticketer.enabled());
        assert_eq!(ticketer.lifetime(), 3600);

        let plain = b"session_state_data_payload_123";
        let ticket = ticketer.encrypt(plain).expect("Bilet şifrelenemedi");
        assert_eq!(ticket.len(), 32);

        let recovered = ticketer.decrypt(&ticket).expect("Bilet çözülemedi");
        assert_eq!(recovered, plain);

        // Bilinmeyen bilet None dönmeli
        assert_eq!(ticketer.decrypt(&[0u8; 32]), None);
    }
}
