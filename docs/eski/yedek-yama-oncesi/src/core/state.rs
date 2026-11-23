//! K2 — Sunucu durumu: `ServerState`, `RuntimeState`, `ServerStats`, bellek içi erişim günlüğü.

use crate::api::EffectiveAuthTokens;
use crate::modules_runtime::CompiledPolicies;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use zmax_config::{LoadedModules, LoadedVHost, ZMaxConfig};


pub(crate) const MAX_IN_MEMORY_LOGS: usize = 200;

#[derive(Debug, Clone)]
pub struct AccessLogRecord {
    pub time: String,
    pub ip: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    pub latency: String,
    pub bytes_sent: usize,
    pub request_id: String,
    pub domain: String,
}

pub struct ServerStats {
    pub start_time: Instant,
    pub total_requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

pub struct RuntimeState {
    pub config: ZMaxConfig,
    pub vhosts: Vec<LoadedVHost>,
    pub modules: LoadedModules,
    pub policies: CompiledPolicies,
    pub redis_client: Option<zmax_redis::ZMaxRedisClient>,
    pub auth: EffectiveAuthTokens,
    pub conf_path: PathBuf,
    pub vhosts_dir: PathBuf,
    pub modules_dir: PathBuf,
}

/// Her başarılı yapılandırma uygulamasında artan nesil sayacı (köprü: reload/health `generation`).
pub static CONFIG_GENERATION: AtomicU64 = AtomicU64::new(0);

pub struct ServerState {
    pub base_dir: PathBuf,
    pub cache: zmax_cache::ZMaxCache,
    pub limiter: RwLock<zmax_security::RateLimiter>,
    pub ban_manager: Arc<zmax_security::IpBanManager>,
    pub wp_guard: Arc<zmax_security::WpBruteForceGuard>,
    pub basic_auth: Arc<zmax_security::BasicAuthManager>, // [kart-9]
    pub buffer_pool: Arc<zmax_pool::BufferPool>,
    pub upstream_pool: Arc<zmax_pool::UpstreamSocketPool>,
    pub runtime: RwLock<RuntimeState>,
    pub admin_static_handler: RwLock<zmax_static::StaticFileHandler>,
    pub tls: Arc<zmax_tls::SniResolver>,
    pub admin_tls: Arc<zmax_tls::SniResolver>,
    pub api_tls: Arc<zmax_tls::SniResolver>,
    pub log_manager: Arc<crate::logger::AsyncLogManager>,
    pub waf_events: Arc<zmax_security::waf_events::WafEventStore>,
    pub htaccess_resolver: Arc<zmax_rewrite::HtAccessResolver>,
    pub shutdown: Arc<zmax_runtime::ShutdownCoordinator>,
    pub access_logs: Mutex<VecDeque<AccessLogRecord>>,
    pub stats: ServerStats,
}

impl ServerState {
    /// Bellekte tutulan son erişim günlüklerine yeni bir kayıt ekler (en fazla 200 kayıt).
    pub fn record_access_log(
        &self,
        ip: &str,
        method: &str,
        path: &str,
        status: u16,
        elapsed: Duration,
    ) {
        self.record_access_log_detailed(ip, method, path, status, elapsed, 0, "", "");
    }

    /// Bellekte tutulan son erişim günlüklerine ayrıntılı (bayt, istek kimliği, alan adı) kayıt ekler.
    #[allow(clippy::too_many_arguments)]
    pub fn record_access_log_detailed(
        &self,
        ip: &str,
        method: &str,
        path: &str,
        status: u16,
        elapsed: Duration,
        bytes_sent: usize,
        request_id: &str,
        domain: &str,
    ) {
        let time = current_hms_utc();
        let latency_ms = elapsed.as_secs_f64() * 1000.0;
        let record = AccessLogRecord {
            time,
            ip: ip.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            status,
            latency: format!("{:.2}ms", latency_ms),
            bytes_sent,
            request_id: request_id.to_string(),
            domain: domain.to_string(),
        };
        if let Ok(mut guard) = self.access_logs.lock() {
            if guard.len() >= MAX_IN_MEMORY_LOGS {
                guard.pop_back();
            }
            guard.push_front(record);
        }
    }
}

pub fn current_hms_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        % 86_400;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}
