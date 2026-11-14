//! L7 — Upstream Katmanı
//! Arka uç havuzu, yük dengeleme (`UpstreamBalancer`), PHP backend haritası ve bağlantı semaforları.

pub use zmax_pool::{LbPolicy, UpstreamBalancer, UpstreamHealth};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

/// Arka uç adreslerine göre eşzamanlı istek sınırını denetleyen semafor haritası.
#[derive(Clone, Default)]
pub struct BackendSemaphores {
    semaphores: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
}

impl BackendSemaphores {
    pub fn new() -> Self {
        Self {
            semaphores: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Belirtilen arka uç adresi için semafor döner veya sınır değeriyle oluşturur.
    pub fn get_or_create(&self, addr: &str, max_conns: usize) -> Arc<Semaphore> {
        let mut map = self.semaphores.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(addr.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(max_conns.max(1))))
            .clone()
    }
}
