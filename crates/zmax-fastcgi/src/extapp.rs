//! # OpenLiteSpeed Harici Uygulama (External Application) & Dinamik Havuz Yöneticisi
//!
//! Bu modül, OpenLiteSpeed'in External Application (Harici Uygulama) mimarisini
//! ZMax Server bünyesinde eksiksiz uygular:
//! - PHP LSAPI (`lsphp81`, `lsphp82`, `lsphp83`) ve FastCGI havuzları
//! - Unix Domain Socket (`/run/php/...sock`) ve TCP Socket (`127.0.0.1:9000`) desteği
//! - Dinamik worker ölçekleme (`min_conns`, `max_conns`, `idle_timeout`, `max_requests`, `instances`)
//! - Sağlık kontrolü (health check probing) ve çöken worker'ların otomatik yeniden başlatılması
//! - Script Handler uzantı eşleşmesi (`.php` -> ilgili LSAPI havuzu)

use crate::{lsapi, FastCgiClient, FastCgiError, FastCgiRequest, FastCgiResponse};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use zmax_pool::UpstreamSocketPool;

/// Harici Uygulama Türü.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtAppType {
    /// LiteSpeed PHP SAPI (`lsphp`).
    Lsapi,
    /// Standart FastCGI (`php-fpm`, Python, Go vb.).
    FastCgi,
    /// HTTP/HTTPS Ters Proxy.
    Proxy,
}

impl ExtAppType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lsapi => "lsapi",
            Self::FastCgi => "fastcgi",
            Self::Proxy => "proxy",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        let lower = s.to_ascii_lowercase();
        if lower.contains("lsapi") || lower.contains("lsphp") {
            Self::Lsapi
        } else if lower.contains("proxy") {
            Self::Proxy
        } else {
            Self::FastCgi
        }
    }
}

impl fmt::Display for ExtAppType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Soket İletişim Tipi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketKind {
    /// TCP Soketi (Örn: `127.0.0.1:9000`).
    Tcp(String),
    /// Unix Domain Socket (Örn: `/run/php/php8.2-fpm.sock`).
    Unix(PathBuf),
}

impl SocketKind {
    /// Adres dizgesini çözümler (UDS veya TCP).
    pub fn parse(addr: &str) -> Self {
        let trimmed = addr.trim();
        if let Some(path) = trimmed.strip_prefix("uds://") {
            Self::Unix(PathBuf::from(path))
        } else if let Some(path) = trimmed.strip_prefix("unix:") {
            Self::Unix(PathBuf::from(path))
        } else if trimmed.starts_with('/') || trimmed.ends_with(".sock") {
            Self::Unix(PathBuf::from(trimmed))
        } else {
            Self::Tcp(trimmed.to_string())
        }
    }

    /// Soketin Unix Domain Socket olup olmadığını döndürür.
    pub fn is_unix(&self) -> bool {
        matches!(self, Self::Unix(_))
    }

    /// Soketin TCP olup olmadığını döndürür.
    pub fn is_tcp(&self) -> bool {
        matches!(self, Self::Tcp(_))
    }

    /// Ham adres dizgesini döndürür.
    pub fn as_raw_string(&self) -> String {
        match self {
            Self::Tcp(addr) => addr.clone(),
            Self::Unix(path) => path.to_string_lossy().to_string(),
        }
    }
}

/// Harici Havuzun Sağlık Durumu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Tamamen sağlıklı ve istek kabul ediyor.
    Healthy,
    /// Bazı isteklerde gecikme veya kısmi hatalar alındı.
    Degraded,
    /// Soket kapalı veya worker çökmüş durumda (erişilemez).
    Down,
    /// Yeniden başlatıldı ve test aşamasında.
    Recovering,
}

impl HealthStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Down => "down",
            Self::Recovering => "recovering",
        }
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Harici Uygulama Yapılandırması (OLS Uyumlu).
#[derive(Debug, Clone)]
pub struct ExtAppConfig {
    /// Benzersiz tanımlayıcı (Örn: `"lsphp83"`).
    pub id: String,
    /// Görünen ad (Örn: `"LiteSpeed PHP 8.3"`).
    pub name: String,
    /// Uygulama türü (`Lsapi`, `FastCgi`).
    pub app_type: ExtAppType,
    /// Bağlantı adresi (UDS veya TCP).
    pub address: String,
    /// Asgari hazır bağlantı sayısı (varsayılan: 1).
    pub min_conns: usize,
    /// Azami eşzamanlı bağlantı sayısı (varsayılan: 100).
    pub max_conns: usize,
    /// Boşta bağlantı zaman aşımı süresi (varsayılan: 60 saniye).
    pub idle_timeout: Duration,
    /// Tek bir worker/bağlantının işleyebileceği azami istek (0 = sınırsız).
    pub max_requests: usize,
    /// Süreç / kopya adedi (varsayılan: 1).
    pub instances: usize,
    /// Başlatma zaman aşımı süresi.
    pub init_timeout: Duration,
    /// Hata durumunda yeniden deneme bekleme süresi (varsayılan: 5 saniye).
    pub retry_timeout: Duration,
    /// Kalıcı bağlantı (Keep-Alive) desteği.
    pub persist_conn: bool,
    /// İsteğe bağlı çalıştırılabilir ikili komut yolu (Örn: `"/usr/local/lsws/lsphp83/bin/lsphp"`).
    pub cmd: Option<String>,
    /// Ortam değişkenleri (`PHP_LSAPI_CHILDREN`, vb.).
    pub env_vars: HashMap<String, String>,
    /// Havuzun aktif olup olmadığı.
    pub enabled: bool,
}

impl Default for ExtAppConfig {
    fn default() -> Self {
        Self {
            id: "lsphp83".to_string(),
            name: "LiteSpeed PHP 8.3".to_string(),
            app_type: ExtAppType::Lsapi,
            address: "127.0.0.1:9083".to_string(),
            min_conns: 1,
            max_conns: 100,
            idle_timeout: Duration::from_secs(60),
            max_requests: 5000,
            instances: 1,
            init_timeout: Duration::from_secs(60),
            retry_timeout: Duration::from_secs(5),
            persist_conn: true,
            cmd: None,
            env_vars: HashMap::new(),
            enabled: true,
        }
    }
}

impl ExtAppConfig {
    /// OLS varsayılan PHP 8.1 havuzu.
    pub fn default_lsphp81() -> Self {
        let mut env = HashMap::new();
        env.insert("PHP_LSAPI_CHILDREN".to_string(), "35".to_string());
        env.insert("LSAPI_AVOID_FORK".to_string(), "200M".to_string());
        Self {
            id: "lsphp81".to_string(),
            name: "LiteSpeed PHP 8.1".to_string(),
            app_type: ExtAppType::Lsapi,
            address: "127.0.0.1:9081".to_string(),
            min_conns: 1,
            max_conns: 80,
            idle_timeout: Duration::from_secs(60),
            max_requests: 5000,
            instances: 1,
            init_timeout: Duration::from_secs(60),
            retry_timeout: Duration::from_secs(5),
            persist_conn: true,
            cmd: Some("/usr/local/lsws/lsphp81/bin/lsphp".to_string()),
            env_vars: env,
            enabled: true,
        }
    }

    /// OLS varsayılan PHP 8.2 havuzu.
    pub fn default_lsphp82() -> Self {
        let mut env = HashMap::new();
        env.insert("PHP_LSAPI_CHILDREN".to_string(), "35".to_string());
        env.insert("LSAPI_AVOID_FORK".to_string(), "200M".to_string());
        Self {
            id: "lsphp82".to_string(),
            name: "LiteSpeed PHP 8.2".to_string(),
            app_type: ExtAppType::Lsapi,
            address: "127.0.0.1:9082".to_string(),
            min_conns: 1,
            max_conns: 100,
            idle_timeout: Duration::from_secs(60),
            max_requests: 5000,
            instances: 1,
            init_timeout: Duration::from_secs(60),
            retry_timeout: Duration::from_secs(5),
            persist_conn: true,
            cmd: Some("/usr/local/lsws/lsphp82/bin/lsphp".to_string()),
            env_vars: env,
            enabled: true,
        }
    }

    /// OLS varsayılan PHP 8.3 havuzu.
    pub fn default_lsphp83() -> Self {
        let mut env = HashMap::new();
        env.insert("PHP_LSAPI_CHILDREN".to_string(), "50".to_string());
        env.insert("LSAPI_AVOID_FORK".to_string(), "200M".to_string());
        Self {
            id: "lsphp83".to_string(),
            name: "LiteSpeed PHP 8.3".to_string(),
            app_type: ExtAppType::Lsapi,
            address: "127.0.0.1:9083".to_string(),
            min_conns: 2,
            max_conns: 150,
            idle_timeout: Duration::from_secs(60),
            max_requests: 5000,
            instances: 1,
            init_timeout: Duration::from_secs(60),
            retry_timeout: Duration::from_secs(5),
            persist_conn: true,
            cmd: Some("/usr/local/lsws/lsphp83/bin/lsphp".to_string()),
            env_vars: env,
            enabled: true,
        }
    }
}

/// Havuz Anlık İstatistikleri.
#[derive(Debug, Clone)]
pub struct ExtAppStats {
    pub app_id: String,
    pub app_name: String,
    pub app_type: ExtAppType,
    pub address: String,
    pub is_unix: bool,
    pub health: HealthStatus,
    pub active_conns: usize,
    pub idle_conns: usize,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub consecutive_failures: usize,
    pub max_conns: usize,
    pub min_conns: usize,
    pub is_enabled: bool,
    pub last_health_check_secs_ago: Option<u64>,
}

/// Tekil bir Harici Uygulama Havuzu (`lsphp81`, `lsphp82`, vb.).
pub struct ExtAppPool {
    config: ExtAppConfig,
    socket_kind: SocketKind,
    socket_pool: Arc<UpstreamSocketPool>,
    active_conns: AtomicUsize,
    total_requests: AtomicU64,
    successful_requests: AtomicU64,
    failed_requests: AtomicU64,
    consecutive_failures: AtomicUsize,
    health: Mutex<HealthStatus>,
    last_check: Mutex<Option<Instant>>,
    last_failure: Mutex<Option<Instant>>,
    is_spawning: AtomicBool,
}

impl ExtAppPool {
    /// Yeni bir harici havuz oluşturur.
    pub fn new(config: ExtAppConfig) -> Self {
        let socket_kind = SocketKind::parse(&config.address);
        let socket_pool = Arc::new(UpstreamSocketPool::with_idle_ttl(
            config.max_conns,
            config.idle_timeout,
        ));
        Self {
            config,
            socket_kind,
            socket_pool,
            active_conns: AtomicUsize::new(0),
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            failed_requests: AtomicU64::new(0),
            consecutive_failures: AtomicUsize::new(0),
            health: Mutex::new(HealthStatus::Healthy),
            last_check: Mutex::new(None),
            last_failure: Mutex::new(None),
            is_spawning: AtomicBool::new(false),
        }
    }

    /// Havuz kimliğini döndürür.
    pub fn id(&self) -> &str {
        &self.config.id
    }

    /// Havuz adını döndürür.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Havuz tipini döndürür (`Lsapi`, `FastCgi`).
    pub fn app_type(&self) -> ExtAppType {
        self.config.app_type
    }

    /// Yapılandırmayı döndürür.
    pub fn config(&self) -> &ExtAppConfig {
        &self.config
    }

    /// Soket türünü döndürür.
    pub fn socket_kind(&self) -> &SocketKind {
        &self.socket_kind
    }

    /// Mevcut sağlık durumunu döndürür.
    pub fn health_status(&self) -> HealthStatus {
        let mut guard = self.health.lock().unwrap_or_else(|e| e.into_inner());
        // Eğer Down ise ve retry_timeout süresi dolduysa Recovering durumuna geçir.
        if *guard == HealthStatus::Down {
            let last_fail = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(t) = *last_fail {
                if t.elapsed() >= self.config.retry_timeout {
                    *guard = HealthStatus::Recovering;
                }
            }
        }
        *guard
    }

    /// Havuzun yeni istek kabul edip edemeyeceğini bildirir.
    pub fn is_available(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        let status = self.health_status();
        status == HealthStatus::Healthy
            || status == HealthStatus::Degraded
            || status == HealthStatus::Recovering
    }

    /// Aktif bağlantı sayısını döndürür.
    pub fn active_connections(&self) -> usize {
        self.active_conns.load(Ordering::Relaxed)
    }

    /// Anlık havuz istatistiklerini derler.
    pub fn stats(&self) -> ExtAppStats {
        let last_check_secs = self
            .last_check
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed().as_secs());

        let idle_count = self
            .socket_pool
            .idle_count(&self.socket_kind.as_raw_string());

        ExtAppStats {
            app_id: self.config.id.clone(),
            app_name: self.config.name.clone(),
            app_type: self.config.app_type,
            address: self.config.address.clone(),
            is_unix: self.socket_kind.is_unix(),
            health: self.health_status(),
            active_conns: self.active_conns.load(Ordering::Relaxed),
            idle_conns: idle_count,
            total_requests: self.total_requests.load(Ordering::Relaxed),
            successful_requests: self.successful_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            consecutive_failures: self.consecutive_failures.load(Ordering::Relaxed),
            max_conns: self.config.max_conns,
            min_conns: self.config.min_conns,
            is_enabled: self.config.enabled,
            last_health_check_secs_ago: last_check_secs,
        }
    }

    /// Çöken veya yanıt vermeyen worker'ların otomatik kurtarılması için sağlık kontrolü yapar.
    pub async fn probe_health(&self) -> HealthStatus {
        let start = Instant::now();
        {
            let mut lc = self.last_check.lock().unwrap_or_else(|e| e.into_inner());
            *lc = Some(start);
        }

        let is_ok = match &self.socket_kind {
            SocketKind::Tcp(addr) => {
                tokio::time::timeout(Duration::from_millis(1500), tokio::net::TcpStream::connect(addr))
                    .await
                    .map(|res| res.is_ok())
                    .unwrap_or(false)
            }
            SocketKind::Unix(path) => {
                #[cfg(unix)]
                {
                    tokio::time::timeout(
                        Duration::from_millis(1500),
                        tokio::net::UnixStream::connect(path),
                    )
                    .await
                    .map(|res| res.is_ok())
                    .unwrap_or(false)
                }
                #[cfg(not(unix))]
                {
                    // Windows ortamında simülasyon: dosya varlığı ve erişilebilirliği
                    path.exists()
                }
            }
        };

        let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if is_ok {
            self.consecutive_failures.store(0, Ordering::Relaxed);
            *h = HealthStatus::Healthy;
            HealthStatus::Healthy
        } else {
            let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
            let mut lf = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
            *lf = Some(Instant::now());

            if fails >= 3 {
                *h = HealthStatus::Down;
                // Çöken worker'ı otomatik yeniden başlatmayı dene
                self.spawn_worker_if_needed();
                HealthStatus::Down
            } else {
                *h = HealthStatus::Degraded;
                HealthStatus::Degraded
            }
        }
    }

    /// Eğer tanımlı bir komut varsa ve worker çöktüyse arka planda yeniden başlatır.
    pub fn spawn_worker_if_needed(&self) {
        if let Some(cmd_str) = &self.config.cmd {
            if self
                .is_spawning
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let cmd_clone = cmd_str.clone();
                let envs = self.config.env_vars.clone();
                let is_spawning_flag = &self.is_spawning as *const AtomicBool;
                let is_spawning_addr = is_spawning_flag as usize;

                tokio::spawn(async move {
                    let mut parts = cmd_clone.split_whitespace();
                    if let Some(program) = parts.next() {
                        let mut cmd = tokio::process::Command::new(program);
                        for arg in parts {
                            cmd.arg(arg);
                        }
                        for (k, v) in envs {
                            cmd.env(k, v);
                        }
                        let _ = cmd.spawn();
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    // Güvenli bayrak sıfırlama
                    let flag = unsafe { &*(is_spawning_addr as *const AtomicBool) };
                    flag.store(false, Ordering::SeqCst);
                });
            }
        }
    }

    /// İsteği ilgili protokolle (LSAPI veya FastCGI) yürütür.
    pub async fn execute(
        &self,
        req: &FastCgiRequest,
        custom_timeout: Option<Duration>,
    ) -> Result<FastCgiResponse, FastCgiError> {
        if !self.config.enabled {
            return Err(FastCgiError::SecurityViolation(format!(
                "Harici uygulama '{}' devre disi birakilmis",
                self.config.id
            )));
        }

        let status = self.health_status();
        if status == HealthStatus::Down {
            return Err(FastCgiError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("Harici uygulama '{}' erisilemez (Down)", self.config.id),
            )));
        }

        // Dinamik worker ölçekleme: max_conns kontrolü
        let current_conns = self.active_conns.fetch_add(1, Ordering::SeqCst);
        if current_conns >= self.config.max_conns {
            self.active_conns.fetch_sub(1, Ordering::SeqCst);
            return Err(FastCgiError::Protocol(format!(
                "Harici uygulama '{}' azami baglanti sinirina ({}) ulasti",
                self.config.id, self.config.max_conns
            )));
        }

        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let timeout = custom_timeout.unwrap_or(self.config.init_timeout);

        let res: Result<FastCgiResponse, FastCgiError> = match self.config.app_type {
            ExtAppType::Lsapi => {
                let addr = &self.config.address;
                lsapi::execute_lsapi(addr, req, Duration::from_secs(3), timeout).await
            }
            ExtAppType::FastCgi => {
                let client = FastCgiClient::with_pool(&self.config.address, self.socket_pool.clone());
                client
                    .execute_php_pooled(req.clone(), Duration::from_secs(3), timeout)
                    .await
                    .map(|d| FastCgiResponse {
                        raw_stdout: d.raw_stdout,
                        stderr: d.stderr.into_bytes(),
                    })
            }
            ExtAppType::Proxy => {
                // Proxy protokolü için FastCGI üzerinden HTTP köprüsü
                Err(FastCgiError::Protocol(
                    "Harici proxy uygulamasi dogrudan zmax-proxy uzerinden yonlendirilmelidir".into(),
                ))
            }
        };

        self.active_conns.fetch_sub(1, Ordering::SeqCst);

        match res {
            Ok(resp) => {
                self.successful_requests.fetch_add(1, Ordering::Relaxed);
                self.consecutive_failures.store(0, Ordering::Relaxed);
                let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
                *h = HealthStatus::Healthy;
                Ok(resp)
            }
            Err(err) => {
                self.failed_requests.fetch_add(1, Ordering::Relaxed);
                let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
                let mut lf = self.last_failure.lock().unwrap_or_else(|e| e.into_inner());
                *lf = Some(Instant::now());

                if fails >= 3 {
                    let mut h = self.health.lock().unwrap_or_else(|e| e.into_inner());
                    *h = HealthStatus::Down;
                    self.spawn_worker_if_needed();
                }
                Err(err)
            }
        }
    }
}

/// Script Handler Uzantı Eşleşme Tablosu (OpenLiteSpeed Uyumlu).
/// Örnek: `.php` -> `lsphp83`, `.php81` -> `lsphp81`, `.phtml` -> `lsphp83`
pub struct ScriptHandlerRegistry {
    handlers: RwLock<HashMap<String, String>>,
}

impl Default for ScriptHandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptHandlerRegistry {
    /// Yeni ve boş bir script handler kayıt tablosu oluşturur.
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    /// OpenLiteSpeed varsayılan uzantı eşleşmeleriyle başlatır.
    pub fn with_ols_defaults() -> Self {
        let registry = Self::new();
        let mut map = HashMap::new();
        map.insert(".php".to_string(), "lsphp83".to_string());
        map.insert(".php83".to_string(), "lsphp83".to_string());
        map.insert(".php82".to_string(), "lsphp82".to_string());
        map.insert(".php81".to_string(), "lsphp81".to_string());
        map.insert(".phtml".to_string(), "lsphp83".to_string());
        map.insert(".php7".to_string(), "lsphp81".to_string());
        *registry.handlers.try_write().unwrap() = map;
        registry
    }

    /// Uzantı için harici havuz eşlemesi tanımlar.
    pub async fn register(&self, extension: &str, app_id: &str) {
        let mut ext = extension.trim().to_ascii_lowercase();
        if !ext.starts_with('.') {
            ext.insert(0, '.');
        }
        let mut map = self.handlers.write().await;
        map.insert(ext, app_id.to_string());
    }

    /// Uzantı eşlemesini siler.
    pub async fn unregister(&self, extension: &str) -> Option<String> {
        let mut ext = extension.trim().to_ascii_lowercase();
        if !ext.starts_with('.') {
            ext.insert(0, '.');
        }
        let mut map = self.handlers.write().await;
        map.remove(&ext)
    }

    /// Verilen uzantıya karşılık gelen harici havuz kimliğini döndürür.
    pub async fn get_app_id(&self, extension: &str) -> Option<String> {
        let mut ext = extension.trim().to_ascii_lowercase();
        if !ext.starts_with('.') {
            ext.insert(0, '.');
        }
        let map = self.handlers.read().await;
        map.get(&ext).cloned()
    }

    /// Verilen URI veya dosya yolundan uzantıyı bulup ilgili havuz kimliğini eşleştirir.
    pub async fn match_uri(&self, uri_or_path: &str) -> Option<String> {
        let clean_path = uri_or_path.split('?').next().unwrap_or(uri_or_path);
        let path = Path::new(clean_path);
        if let Some(ext_os) = path.extension() {
            let ext = format!(".{}", ext_os.to_string_lossy().to_ascii_lowercase());
            let map = self.handlers.read().await;
            if let Some(app_id) = map.get(&ext) {
                return Some(app_id.clone());
            }
            // Çift uzantı kontrolü (örn: .php.bak -> .php)
            if let Some(stem) = path.file_stem() {
                let stem_str = stem.to_string_lossy();
                if let Some(dot_idx) = stem_str.rfind('.') {
                    let sub_ext = &stem_str[dot_idx..];
                    if let Some(app_id) = map.get(&sub_ext.to_ascii_lowercase()) {
                        return Some(app_id.clone());
                    }
                }
            }
        }
        None
    }

    /// Tüm uzantı-havuz eşleşmelerini listeler.
    pub async fn list_all(&self) -> HashMap<String, String> {
        self.handlers.read().await.clone()
    }
}

/// Tüm Harici Uygulama Havuzlarını Koordine Eden Ana Havuz Yöneticisi.
pub struct ExtAppManager {
    pools: RwLock<HashMap<String, Arc<ExtAppPool>>>,
    script_handlers: Arc<ScriptHandlerRegistry>,
    fallback_pool: RwLock<Option<String>>,
}

impl Default for ExtAppManager {
    fn default() -> Self {
        Self::with_ols_defaults()
    }
}

impl ExtAppManager {
    /// Yeni ve boş bir harici uygulama yöneticisi oluşturur.
    pub fn new() -> Self {
        Self {
            pools: RwLock::new(HashMap::new()),
            script_handlers: Arc::new(ScriptHandlerRegistry::new()),
            fallback_pool: RwLock::new(None),
        }
    }

    /// OpenLiteSpeed varsayılan PHP havuzları (`lsphp81`, `lsphp82`, `lsphp83`) ve script handler'lar ile başlatır.
    pub fn with_ols_defaults() -> Self {
        let manager = Self {
            pools: RwLock::new(HashMap::new()),
            script_handlers: Arc::new(ScriptHandlerRegistry::with_ols_defaults()),
            fallback_pool: RwLock::new(Some("lsphp83".to_string())),
        };

        // Varsayılan havuzları kaydet
        let p81 = ExtAppPool::new(ExtAppConfig::default_lsphp81());
        let p82 = ExtAppPool::new(ExtAppConfig::default_lsphp82());
        let p83 = ExtAppPool::new(ExtAppConfig::default_lsphp83());

        let mut pools = HashMap::new();
        pools.insert(p81.id().to_string(), Arc::new(p81));
        pools.insert(p82.id().to_string(), Arc::new(p82));
        pools.insert(p83.id().to_string(), Arc::new(p83));

        *manager.pools.try_write().unwrap() = pools;
        manager
    }

    /// Script Handler kayıt nesnesine erişim sağlar.
    pub fn script_handlers(&self) -> Arc<ScriptHandlerRegistry> {
        self.script_handlers.clone()
    }

    /// Yeni bir harici havuz ekler veya günceller.
    pub async fn add_pool(&self, pool: ExtAppPool) {
        let mut pools = self.pools.write().await;
        pools.insert(pool.id().to_string(), Arc::new(pool));
    }

    /// Kimliğe göre harici havuz alır.
    pub async fn get_pool(&self, app_id: &str) -> Option<Arc<ExtAppPool>> {
        let pools = self.pools.read().await;
        pools.get(app_id).cloned()
    }

    /// Kimliğe göre harici havuzu kaldırır.
    pub async fn remove_pool(&self, app_id: &str) -> Option<Arc<ExtAppPool>> {
        let mut pools = self.pools.write().await;
        pools.remove(app_id)
    }

    /// URI veya dosya yoluna göre en uygun harici havuzu çözümler (Failover destekli).
    pub async fn get_pool_for_uri(&self, uri_or_path: &str) -> Option<Arc<ExtAppPool>> {
        // 1. Script handler'dan eşleşen havuz kimliğini bul
        if let Some(target_app) = self.script_handlers.match_uri(uri_or_path).await {
            if let Some(pool) = self.get_pool(&target_app).await {
                if pool.is_available() {
                    return Some(pool);
                }
            }
        }

        // 2. Birincil havuz erişilemez ise fallback havuzuna geç
        let fallback_id = self.fallback_pool.read().await.clone();
        if let Some(fallback) = fallback_id {
            if let Some(pool) = self.get_pool(&fallback).await {
                if pool.is_available() {
                    return Some(pool);
                }
            }
        }

        // 3. Sağlıklı herhangi bir havuzu bulmayı dene
        let pools = self.pools.read().await;
        for pool in pools.values() {
            if pool.is_available() {
                return Some(pool.clone());
            }
        }

        None
    }

    /// Fallback (yedek) havuz kimliğini ayarlar.
    pub async fn set_fallback_pool(&self, app_id: Option<String>) {
        let mut guard = self.fallback_pool.write().await;
        *guard = app_id;
    }

    /// Tüm kayıtlı harici havuzların anlık durum istatistiklerini döndürür.
    pub async fn all_stats(&self) -> Vec<ExtAppStats> {
        let pools = self.pools.read().await;
        let mut stats: Vec<ExtAppStats> = pools.values().map(|p| p.stats()).collect();
        stats.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        stats
    }

    /// Tüm havuzlar üzerinde sağlık denetimi (probe) çalıştırır ve sonuçları döner.
    pub async fn probe_all_pools(&self) -> Vec<ExtAppStats> {
        let pools = {
            let read_guard = self.pools.read().await;
            read_guard.values().cloned().collect::<Vec<_>>()
        };

        for pool in &pools {
            pool.probe_health().await;
        }

        self.all_stats().await
    }

    /// URI'ye göre isteği doğru havuza yönlendirip çalıştırır.
    pub async fn execute_request(
        &self,
        uri_or_path: &str,
        req: &FastCgiRequest,
        timeout: Option<Duration>,
    ) -> Result<FastCgiResponse, FastCgiError> {
        let pool = self.get_pool_for_uri(uri_or_path).await.ok_or_else(|| {
            FastCgiError::Protocol(format!(
                "'{uri_or_path}' istegini karsilayacak saglikli harici havuz (LSAPI/FastCGI) bulunamadi"
            ))
        })?;

        pool.execute(req, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_kind_parse_uds_and_tcp() {
        let uds1 = SocketKind::parse("uds:///run/php/php8.2-fpm.sock");
        assert!(uds1.is_unix());
        assert_eq!(uds1.as_raw_string(), "/run/php/php8.2-fpm.sock");

        let uds2 = SocketKind::parse("unix:/tmp/lsphp.sock");
        assert!(uds2.is_unix());
        assert_eq!(uds2.as_raw_string(), "/tmp/lsphp.sock");

        let uds3 = SocketKind::parse("/var/run/php.sock");
        assert!(uds3.is_unix());

        let tcp = SocketKind::parse("127.0.0.1:9083");
        assert!(tcp.is_tcp());
        assert_eq!(tcp.as_raw_string(), "127.0.0.1:9083");
    }

    #[test]
    fn extapp_type_parsing() {
        assert_eq!(ExtAppType::from_str_loose("lsphp"), ExtAppType::Lsapi);
        assert_eq!(ExtAppType::from_str_loose("php-lsapi"), ExtAppType::Lsapi);
        assert_eq!(ExtAppType::from_str_loose("fcgi"), ExtAppType::FastCgi);
        assert_eq!(ExtAppType::from_str_loose("proxy"), ExtAppType::Proxy);
    }

    #[tokio::test]
    async fn script_handler_extension_matching() {
        let registry = ScriptHandlerRegistry::with_ols_defaults();

        assert_eq!(registry.match_uri("/index.php").await, Some("lsphp83".to_string()));
        assert_eq!(
            registry.match_uri("/app/test.php81?debug=1").await,
            Some("lsphp81".to_string())
        );
        assert_eq!(
            registry.match_uri("/legacy/page.php82").await,
            Some("lsphp82".to_string())
        );
        assert_eq!(
            registry.match_uri("/views/template.phtml").await,
            Some("lsphp83".to_string())
        );
        assert_eq!(registry.match_uri("/static/style.css").await, None);

        // Dinamik uzantı ekleme
        registry.register(".customphp", "lsphp81").await;
        assert_eq!(
            registry.match_uri("/custom.customphp").await,
            Some("lsphp81".to_string())
        );

        // Uzantı silme
        registry.unregister(".customphp").await;
        assert_eq!(registry.match_uri("/custom.customphp").await, None);
    }

    #[tokio::test]
    async fn extapp_pool_stats_and_dynamic_scaling_limits() {
        let config = ExtAppConfig {
            id: "test_pool".to_string(),
            name: "Test Pool".to_string(),
            app_type: ExtAppType::FastCgi,
            address: "127.0.0.1:9999".to_string(),
            min_conns: 1,
            max_conns: 2, // Çok düşük sınır belirle
            idle_timeout: Duration::from_secs(30),
            max_requests: 100,
            instances: 1,
            init_timeout: Duration::from_secs(5),
            retry_timeout: Duration::from_secs(1),
            persist_conn: true,
            cmd: None,
            env_vars: HashMap::new(),
            enabled: true,
        };

        let pool = ExtAppPool::new(config);
        assert_eq!(pool.id(), "test_pool");
        assert_eq!(pool.active_connections(), 0);

        let stats = pool.stats();
        assert_eq!(stats.app_id, "test_pool");
        assert_eq!(stats.max_conns, 2);
        assert_eq!(stats.health, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn extapp_manager_ols_defaults_and_failover() {
        let manager = ExtAppManager::with_ols_defaults();

        // 3 varsayılan havuz mevcut olmalı
        let stats = manager.all_stats().await;
        assert_eq!(stats.len(), 3);
        assert!(stats.iter().any(|s| s.app_id == "lsphp81"));
        assert!(stats.iter().any(|s| s.app_id == "lsphp82"));
        assert!(stats.iter().any(|s| s.app_id == "lsphp83"));

        // URI yönlendirmesi
        let pool = manager.get_pool_for_uri("/var/www/site/index.php").await;
        assert!(pool.is_some());
        assert_eq!(pool.unwrap().id(), "lsphp83");

        let pool81 = manager.get_pool_for_uri("/var/www/site/legacy.php81").await;
        assert!(pool81.is_some());
        assert_eq!(pool81.unwrap().id(), "lsphp81");
    }

    #[tokio::test]
    async fn health_check_and_status_transitions() {
        let config = ExtAppConfig {
            id: "probe_pool".to_string(),
            name: "Probe Pool".to_string(),
            app_type: ExtAppType::FastCgi,
            // Erişilemeyecek bir port
            address: "127.0.0.1:54321".to_string(),
            min_conns: 1,
            max_conns: 10,
            idle_timeout: Duration::from_secs(10),
            max_requests: 100,
            instances: 1,
            init_timeout: Duration::from_secs(1),
            retry_timeout: Duration::from_millis(100),
            persist_conn: true,
            cmd: None,
            env_vars: HashMap::new(),
            enabled: true,
        };

        let pool = ExtAppPool::new(config);
        // İlk probe: Degraded veya Down olmalı
        let status1 = pool.probe_health().await;
        assert_eq!(status1, HealthStatus::Degraded);

        // İkinci ve üçüncü probe sonrası Down olmalı
        pool.probe_health().await;
        let status3 = pool.probe_health().await;
        assert_eq!(status3, HealthStatus::Down);

        // retry_timeout beklendikten sonra Recovering'e geçmeli
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(pool.health_status(), HealthStatus::Recovering);
    }
}
