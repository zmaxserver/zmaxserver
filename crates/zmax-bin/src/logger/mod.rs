//! # ZMax Asenkron Toplu Günlük Motoru (`AsyncLogManager`)
//! İstek yolunu (hot-path) disk G/Ç ile bloklamadan `tokio::sync::mpsc` kanalı üzerinden
//! NCSA Combined ve JSON erişim/hata günlüklerini toplu tamponlayarak yazar, döndürür (`.1`)
//! ve `reopen_all` / `read_tail_lines` işlemlerini yönetir.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot};

const LIVE_CHANNEL_CAPACITY: usize = 1024;
const LOG_CHANNEL_CAPACITY: usize = 16_384;
const MIN_FLUSH_MS: u64 = 50;
const TAIL_CHUNK_SIZE: usize = 64 * 1024;
const MAX_TAIL_SCAN_BYTES: u64 = 32 * 1024 * 1024;
pub const DEFAULT_WAF_EVENTS_LOG: &str = "logs/waf_events.log";

/// Canlı akış (SSE) için yayınlanan tek günlük satırı.
#[derive(Debug, Clone)]
pub struct LiveLogLine {
    /// "access" veya "error"
    pub kind: &'static str,
    pub domain: String,
    pub line: String,
}

/// Tek bir HTTP/HTTPS isteği için erişim günlüğü kaydı.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub timestamp: SystemTime,
    pub client_ip: String,
    pub method: String,
    pub target: String,
    pub protocol: String,
    pub status: u16,
    pub bytes_sent: usize,
    pub referer: String,
    pub user_agent: String,
    pub request_id: String,
    pub duration_ms: f64,
    pub domain: String,
    pub target_path: Option<PathBuf>,
    pub json_format: bool,
    pub also_write_global: bool,
    pub max_size_bytes: u64,
}

impl Default for AccessLogEntry {
    fn default() -> Self {
        Self {
            timestamp: SystemTime::now(),
            client_ip: "-".to_string(),
            method: "GET".to_string(),
            target: "/".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes_sent: 0,
            referer: String::new(),
            user_agent: String::new(),
            request_id: String::new(),
            duration_ms: 0.0,
            domain: String::new(),
            target_path: None,
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        }
    }
}

mod format;
pub(crate) mod rotate;
mod tail;
mod worker;
#[cfg(test)]
mod tests;

use format::*;
use worker::*;
use rotate::rotate_log_file;

/// Arka plan görevinde açık dosya tanıtıcılarıyla toplu ve kilitlenmesiz günlük yazımı yönetir.
#[derive(Debug)]
pub struct AsyncLogManager {
    base_dir: PathBuf,
    tx: mpsc::Sender<LogCommand>,
    dropped: Arc<AtomicU64>,
    dropped_events: Arc<AtomicU64>,
    live_tx: tokio::sync::broadcast::Sender<LiveLogLine>,
    live_dropped: Arc<AtomicU64>,
}

impl AsyncLogManager {
    /// Yeni bir asenkron günlük yöneticisi başlatır ve arka plan yazıcı görevini doğurur.
    pub fn new(
        base_dir: PathBuf,
        global_access_log: PathBuf,
        global_error_log: PathBuf,
        batch_flush_ms: u64,
        batch_buffer_kb: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(LOG_CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));
        let dropped_events = Arc::new(AtomicU64::new(0));
        let (live_tx, _) = tokio::sync::broadcast::channel(LIVE_CHANNEL_CAPACITY);
        let live_dropped = Arc::new(AtomicU64::new(0));

        let resolved_access = resolve_log_path(&base_dir, &global_access_log);
        let resolved_error = resolve_log_path(&base_dir, &global_error_log);
        let resolved_waf = resolve_log_path(&base_dir, Path::new(DEFAULT_WAF_EVENTS_LOG));
        let batch_threshold_bytes = batch_buffer_kb.saturating_mul(1024);
        let writer_capacity = batch_threshold_bytes.clamp(8 * 1024, 256 * 1024);

        let worker_state = LogWorkerState {
            base_dir: base_dir.clone(),
            global_access_log: resolved_access,
            global_error_log: resolved_error,
            global_waf_log: resolved_waf,
            writers: HashMap::new(),
            total_pending_bytes: 0,
            batch_threshold_bytes,
            writer_capacity,
            live_tx: live_tx.clone(),
            live_dropped: live_dropped.clone(),
        };
        let flush_ms = batch_flush_ms.max(MIN_FLUSH_MS);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(run_log_worker(rx, worker_state, flush_ms));
        } else {
            let _ = std::thread::Builder::new()
                .name("zmax-async-logger".to_string())
                .spawn(move || {
                    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        rt.block_on(run_log_worker(rx, worker_state, flush_ms));
                    }
                });
        }

        Self {
            base_dir,
            tx,
            dropped,
            dropped_events,
            live_tx,
            live_dropped,
        }
    }

    /// Canlı log akışına abone olur (sınırlı kanal; yavaş abone satır kaçırır, yazımı bloklamaz).
    pub fn subscribe_live(&self) -> tokio::sync::broadcast::Receiver<LiveLogLine> {
        self.live_tx.subscribe()
    }

    /// Canlı akışta düşen satır sayısı (abone yok veya abone geride kaldı).
    pub fn live_dropped_count(&self) -> u64 {
        self.live_dropped.load(Ordering::Relaxed)
    }

    /// Yavaş abonenin kaçırdığı satırları `dropped` sayacına ekler.
    pub fn add_live_dropped(&self, n: u64) {
        self.live_dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Erişim günlüğü kaydını beklemesiz (`try_send`) olarak kuyruğa ekler; kanal doluysa sayacı artırır.
    pub fn log_access(&self, entry: AccessLogEntry) {
        if self.tx.try_send(LogCommand::Access(entry)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Hata günlüğü satırını beklemesiz (`try_send`) olarak kuyruğa ekler; kanal doluysa sayacı artırır.
    pub fn log_error(
        &self,
        path_override: Option<PathBuf>,
        message: String,
        max_size_bytes: u64,
        also_global: bool,
    ) {
        if self
            .tx
            .try_send(LogCommand::Error {
                path_override,
                message,
                max_size_bytes,
                also_global,
            })
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Kuyruk taşması nedeniyle düşürülen WAF olay sayısını döndürür.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// WAF olay kaydını beklemesiz (`try_send`) olarak olay günlüğüne (`logs/waf_events.log`) kuyruklar.
    pub fn log_waf_event(
        &self,
        record: zmax_security::waf_events::WafEventRecord,
        path_override: Option<PathBuf>,
        max_size_bytes: u64,
        also_global: bool,
    ) -> bool {
        if self
            .tx
            .try_send(LogCommand::Waf {
                path_override,
                record,
                max_size_bytes,
                also_global,
            })
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
            static WARNED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                tracing::warn!("WAF olay gunlugu kuyrugu dolu, olaylar dusuruluyor (dropped_events)");
            }
            false
        } else {
            true
        }
    }

    /// Açık tüm `BufWriter`ları diske boşaltır ve kapatır (`SIGUSR1`/logrotate sonrası yeniden açılış için).
    pub async fn reopen_all(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(LogCommand::ReopenAll(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    /// Kuyrukta bekleyen tüm günlükleri diske topluca boşaltır.
    pub async fn flush(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(LogCommand::Flush(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    /// Küresel erişim ve hata günlüğü dosya yollarını sıcak yenilemede günceller.
    pub async fn update_global_paths(&self, access_log: PathBuf, error_log: PathBuf) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .tx
            .send(LogCommand::UpdateGlobalPaths {
                access_log,
                error_log,
                ack: ack_tx,
            })
            .await
            .is_ok()
        {
            let _ = ack_rx.await;
        }
    }

    /// Kanal doluluğu nedeniyle güvenli şekilde düşürülen günlük kaydı sayısını döndürür.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}
