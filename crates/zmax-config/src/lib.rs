//! # zmax-config
//! ZMax Server evrensel TOML yapılandırma, çakışmasız port yönetimi ve Sanal Konak (vHost) yöneticisi.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// [kart-3] vHost REST API tam alan JSON ayrıştırma ve TOML turu
pub mod vhost_json;
pub use vhost_json::*;

// [kart-5] Sanal konak hotlink koruması ve IP ACL şeması
pub mod security_ext;
pub use security_ext::{default_hotlink_extensions, HotlinkConfig, VhostAclConfig};

pub mod acme;
pub use acme::AcmeConfig;

// [kart-10] Sanal konak ters vekil zaman aşımı, keep-alive ve tamponsuz akış şeması
pub mod proxy_ext;
pub use proxy_ext::ProxyExtConfig;
// [ek-dinleyici] [[listeners.extra]] sabit arka uçlu TLS ters vekil dinleyicileri
pub mod extra_listener;
pub use extra_listener::{ExtraListenerConfig, ExtraRouteConfig, ExtraSslConfig};
// [kart-9] vHost HTTP Basic Authentication (Parola Korumalı Dizinler)
pub mod auth;
pub use auth::*;

/// Popüler paneller (cPanel, Plesk, DirectAdmin, CyberPanel, HestiaCP, aaPanel, zPanel vb.)
/// ve OS ephemeral aralıkları (Linux 32768-60999, Windows 49152-65535) ile çakışmayan
/// ZMax Server standart port bloğu (IANA Unassigned).
pub const DEFAULT_HTTP_PORT: u16 = 19480;
pub const DEFAULT_HTTPS_PORT: u16 = 19483;
pub const DEFAULT_ADMIN_PORT: u16 = 19485;
pub const DEFAULT_API_PORT: u16 = 19486;

/// Tüm popüler panellerin ve ortak altyapı servislerinin rezerve port listesi (çakışma kontrolü için).
pub const KNOWN_PANEL_PORTS: &[u16] = &[
    81, 888, 1500, 2002, 2003, 2004, 2005, 2019, 2030, 2031, 2082, 2083, 2086, 2087, 2095, 2096,
    2222, 2304, 3000, 3306, 5273, 5274, 5432, 6379, 7080, 7800, 8000, 8025, 8026, 8035, 8036,
    8045, 8046, 8047, 8055, 8056, 8080, 8081, 8083, 8084, 8088, 8090, 8091, 8404, 8443, 8766,
    8787, 8788, 8789, 8880, 8888, 9000, 9090, 9443, 10000, 18055, 19443, 20000, 55433,
];

fn default_true() -> bool {
    true
}

fn default_graceful_shutdown_secs() -> u64 {
    15
}

fn default_https_alpn() -> Vec<String> {
    vec!["h2".to_string(), "http/1.1".to_string()]
}

fn default_batch_flush_ms() -> u64 {
    250
}

fn default_batch_buffer_kb() -> usize {
    64
}

fn default_vhost_log_format() -> String {
    "combined".to_string()
}

fn default_tls_min_version() -> String {
    "1.2".to_string()
}

fn default_php_lb_policy() -> String {
    "round_robin".to_string()
}

fn default_php_io_timeout_secs() -> u64 {
    60
}

fn default_php_max_idle_conns() -> usize {
    16
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ServerGlobalConfig {
    pub server_name: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub group: String,
    /// Geçici dosya dizini. Boşsa `<kök>/tmp`; göreli yol kök dizine göre çözülür. Yetki düşürmeden önce
    /// 0700 ve doğrulanmış sahiple hazırlanır (`/tmp/zmax` gibi tahmin edilebilir ortak yol KULLANILMAZ).
    #[serde(default)]
    pub tmp_dir: String,
    pub priority: i32,
    #[serde(default = "default_true")]
    pub cpu_affinity: bool,
    pub workers: usize,
    #[serde(default = "default_true")]
    pub reuseport_workers: bool,
    #[serde(default = "default_graceful_shutdown_secs")]
    pub graceful_shutdown_secs: u64,
    #[serde(default)]
    pub acme: AcmeConfig,
    // [ols-parity] Sunucu düzeyi Tuning, Dinleyiciler ve Harici Uygulama Havuzları
    #[serde(default)]
    pub tuning: TuningConfig,
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,
    #[serde(default, alias = "extapps", alias = "external_apps")]
    pub ext_apps: Vec<ExternalAppConfig>,
    #[serde(default)]
    pub script_handlers: Vec<ScriptHandlerConfig>,
}

pub type ServerConfig = ServerGlobalConfig;

impl Default for ServerGlobalConfig {
    fn default() -> Self {
        Self {
            server_name: concat!("ZMax/", env!("ZMAX_VERSION")).to_string(),
            user: "nobody".to_string(),
            group: "nobody".to_string(),
            tmp_dir: String::new(),
            priority: 0,
            cpu_affinity: true,
            workers: 0,
            reuseport_workers: true,
            graceful_shutdown_secs: default_graceful_shutdown_secs(),
            acme: AcmeConfig::default(),
            tuning: TuningConfig::default(),
            listeners: Vec::new(),
            ext_apps: Vec::new(),
            script_handlers: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct HttpListenerConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub backlog: u32,
    pub tcp_nodelay: bool,
    pub reuse_port: bool,
    #[serde(default)]
    pub proxy_protocol: bool,
}

impl Default for HttpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "0.0.0.0".to_string(),
            port: DEFAULT_HTTP_PORT,
            backlog: 4096,
            tcp_nodelay: true,
            reuse_port: false,
            proxy_protocol: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct HttpsListenerConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub ssl: bool,
    #[serde(default = "default_https_alpn")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub proxy_protocol: bool,
    // Güvenli varsayılan: TOML'da alan yazılmasa bile strict SNI açık kalır.
    #[serde(default = "default_true")]
    pub strict_sni: bool,
}

impl Default for HttpsListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: "0.0.0.0".to_string(),
            port: DEFAULT_HTTPS_PORT,
            ssl: true,
            alpn: default_https_alpn(),
            proxy_protocol: false,
            strict_sni: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct AdminListenerConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub document_root: String,
    pub require_token: bool,
    pub token: String,
    /// Yalniz okuma rolu icin istege bagli token (bos = okuma rolu kapali).
    pub read_token: String,
    pub ssl: bool,
    pub tls_cert: String,
    pub tls_key: String,
    pub proxy_prefix: String,
    pub trusted_proxies: Vec<String>,
}

impl Default for AdminListenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: DEFAULT_ADMIN_PORT,
            document_root: "admin".to_string(),
            require_token: false,
            token: String::new(),
            read_token: String::new(),
            ssl: false,
            tls_cert: String::new(),
            tls_key: String::new(),
            proxy_prefix: String::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct ApiListenerConfig {
    pub enabled: bool,
    pub address: String,
    pub port: u16,
    pub unix_socket: String,
    pub token: String,
    /// Yalniz okuma rolu icin istege bagli token (bos = okuma rolu kapali).
    pub read_token: String,
    pub require_token: bool,
    pub cors_allow_origin: String,
    pub ssl: bool,
    pub tls_cert: String,
    pub tls_key: String,
    pub proxy_prefix: String,
    pub trusted_proxies: Vec<String>,
}

impl Default for ApiListenerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: DEFAULT_API_PORT,
            unix_socket: String::new(),
            token: String::new(),
            read_token: String::new(),
            require_token: false,
            // Boş = CORS kapalı. Wildcard varsayılanı kaldırıldı (W-05/W-06).
            cors_allow_origin: String::new(),
            ssl: false,
            tls_cert: String::new(),
            tls_key: String::new(),
            proxy_prefix: String::new(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ListenerConfig {
    pub id: String,
    pub name: String,
    #[serde(alias = "ip")]
    pub address: String,
    pub port: u16,
    #[serde(alias = "tls")]
    pub secure: bool,
    pub protocol: String,
    #[serde(default, alias = "vhosts_mapping", alias = "vhost_mapping")]
    pub vhost_mappings: Vec<String>,
    #[serde(default)]
    pub tls_versions: Vec<String>,
    #[serde(default, alias = "cert_path")]
    pub cert_file: String,
    #[serde(default, alias = "key_path")]
    pub key_file: String,
    #[serde(default = "default_https_alpn")]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub ca_file: String,
    #[serde(default = "default_client_verify")]
    pub client_verify: String,
    #[serde(default)]
    pub ciphers: String,
    #[serde(default)]
    pub reuse_port: bool,
    #[serde(default = "default_listener_backlog")]
    pub backlog: u32,
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_listener_backlog() -> u32 {
    4096
}

fn default_client_verify() -> String {
    "none".to_string()
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            address: "0.0.0.0".to_string(),
            port: 80,
            secure: false,
            protocol: "HTTP/1.1, HTTP/2".to_string(),
            vhost_mappings: vec!["*".to_string()],
            tls_versions: vec!["1.2".to_string(), "1.3".to_string()],
            cert_file: String::new(),
            key_file: String::new(),
            alpn: default_https_alpn(),
            ca_file: String::new(),
            client_verify: default_client_verify(),
            ciphers: String::new(),
            reuse_port: false,
            backlog: 4096,
            proxy_protocol: false,
            enabled: true,
        }
    }
}

impl ListenerConfig {
    /// Dinleyicinin IP / bind adresini döndürür (OLS denklik takma adı: `ip`).
    pub fn ip(&self) -> &str {
        &self.address
    }

    /// Dinleyicinin IP / bind adresini günceller.
    pub fn set_ip(&mut self, ip: impl Into<String>) {
        self.address = ip.into();
    }

    /// TLS sertifika dosya yolunu döndürür (OLS denklik takma adı: `cert_path`).
    pub fn cert_path(&self) -> &str {
        &self.cert_file
    }

    /// TLS sertifika dosya yolunu günceller.
    pub fn set_cert_path(&mut self, path: impl Into<String>) {
        self.cert_file = path.into();
    }

    /// TLS özel anahtar dosya yolunu döndürür (OLS denklik takma adı: `key_path`).
    pub fn key_path(&self) -> &str {
        &self.key_file
    }

    /// TLS özel anahtar dosya yolunu günceller.
    pub fn set_key_path(&mut self, path: impl Into<String>) {
        self.key_file = path.into();
    }

    /// Eşlenen sanal konak listesini döndürür (OLS denklik takma adı: `vhosts_mapping`).
    pub fn vhosts_mapping(&self) -> &[String] {
        &self.vhost_mappings
    }

    /// Dinleyici yapılandırmasını doğrular.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.port == 0 {
            return Err(format!("Dinleyici '{}' etkin ancak portu 0 olamaz", self.id));
        }
        if !self.address.trim().is_empty() {
            parse_listener_ip(&self.address)
                .map_err(|e| format!("Dinleyici '{}' adresi geçersiz: {}", self.id, e))?;
        }
        Ok(())
    }
}

fn default_compress_mime_types() -> Vec<String> {
    vec![
        "text/html".to_string(),
        "text/plain".to_string(),
        "text/css".to_string(),
        "application/javascript".to_string(),
        "application/json".to_string(),
        "application/xml".to_string(),
        "image/svg+xml".to_string(),
    ]
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct TuningConfig {
    #[serde(alias = "max_conns")]
    pub max_connections: u32,
    #[serde(default = "default_max_ssl_connections")]
    pub max_ssl_connections: u32,
    #[serde(alias = "conn_timeout")]
    pub connection_timeout: u64,
    pub keep_alive_timeout: u64,
    #[serde(alias = "max_keep_alive_reqs")]
    pub max_keep_alive_req: u32,
    #[serde(default = "default_true")]
    pub smart_keep_alive: bool,
    #[serde(default)]
    pub snd_buf_size: usize,
    #[serde(default)]
    pub rcv_buf_size: usize,
    #[serde(alias = "gzip")]
    pub gzip_enabled: bool,
    #[serde(default = "default_compress_level")]
    pub gzip_level: u32,
    #[serde(alias = "brotli")]
    pub brotli_enabled: bool,
    #[serde(default = "default_compress_level")]
    pub brotli_level: u32,
    pub min_compress_size: usize,
    #[serde(default = "default_compress_mime_types")]
    pub compress_mime_types: Vec<String>,
    #[serde(default = "default_true", alias = "ssl_session_cache")]
    pub ssl_session_cache: bool,
    pub ssl_cache_size: usize,
    pub ssl_cache_timeout: u64,
    #[serde(default = "default_true")]
    pub ssl_session_tickets: bool,
    #[serde(alias = "quic")]
    pub http3_enabled: bool,
    #[serde(alias = "quic_port")]
    pub http3_port: u16,
    #[serde(default = "default_true")]
    pub cache_static: bool,
    #[serde(default = "default_max_cached_file_size_kb")]
    pub max_cached_file_size_kb: usize,
    #[serde(default = "default_total_in_mem_cache_mb")]
    pub total_in_mem_cache_mb: usize,
    #[serde(default = "default_io_model")]
    pub io_model: String,
}

fn default_max_ssl_connections() -> u32 {
    5000
}

fn default_compress_level() -> u32 {
    6
}

fn default_max_cached_file_size_kb() -> usize {
    1024
}

fn default_total_in_mem_cache_mb() -> usize {
    256
}

fn default_io_model() -> String {
    "auto".to_string()
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self {
            max_connections: 10000,
            max_ssl_connections: 5000,
            connection_timeout: 60,
            keep_alive_timeout: 15,
            max_keep_alive_req: 1000,
            smart_keep_alive: true,
            snd_buf_size: 0,
            rcv_buf_size: 0,
            gzip_enabled: true,
            gzip_level: 6,
            brotli_enabled: true,
            brotli_level: 6,
            min_compress_size: 256,
            compress_mime_types: default_compress_mime_types(),
            ssl_session_cache: true,
            ssl_cache_size: 1_000_000,
            ssl_cache_timeout: 3600,
            ssl_session_tickets: true,
            http3_enabled: true,
            http3_port: 443,
            cache_static: true,
            max_cached_file_size_kb: 1024,
            total_in_mem_cache_mb: 256,
            io_model: "auto".to_string(),
        }
    }
}

impl TuningConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0 {
            return Err("tuning.max_connections değeri 0 olamaz.".to_string());
        }
        if self.connection_timeout == 0 {
            return Err("tuning.connection_timeout değeri 0 olamaz.".to_string());
        }
        if self.keep_alive_timeout == 0 {
            return Err("tuning.keep_alive_timeout değeri 0 olamaz.".to_string());
        }
        if self.gzip_level > 9 {
            return Err("tuning.gzip_level en fazla 9 olabilir.".to_string());
        }
        if self.brotli_level > 11 {
            return Err("tuning.brotli_level en fazla 11 olabilir.".to_string());
        }
        Ok(())
    }
}

/// OLS (OpenLiteSpeed) WebAdmin standart ayar denkliği sağlayan Sunucu İnce Ayar modeli.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ServerTuningConfig {
    #[serde(alias = "conn_timeout")]
    pub connection_timeout: u64,
    pub keep_alive_timeout: u64,
    #[serde(alias = "max_keep_alive_req")]
    pub max_keep_alive_reqs: u32,
    #[serde(alias = "gzip_enabled")]
    pub gzip: bool,
    #[serde(alias = "brotli_enabled")]
    pub brotli: bool,
    pub ssl_session_cache: bool,
    pub ssl_cache_size: usize,
    pub ssl_cache_timeout: u64,
    #[serde(alias = "http3_enabled")]
    pub quic: bool,
    #[serde(alias = "http3_port")]
    pub quic_port: u16,
    #[serde(alias = "max_conns")]
    pub max_connections: u32,
    pub min_compress_size: usize,
}

impl Default for ServerTuningConfig {
    fn default() -> Self {
        Self {
            connection_timeout: 60,
            keep_alive_timeout: 15,
            max_keep_alive_reqs: 1000,
            gzip: true,
            brotli: true,
            ssl_session_cache: true,
            ssl_cache_size: 1_000_000,
            ssl_cache_timeout: 3600,
            quic: true,
            quic_port: 443,
            max_connections: 10000,
            min_compress_size: 256,
        }
    }
}

impl From<TuningConfig> for ServerTuningConfig {
    fn from(t: TuningConfig) -> Self {
        Self {
            connection_timeout: t.connection_timeout,
            keep_alive_timeout: t.keep_alive_timeout,
            max_keep_alive_reqs: t.max_keep_alive_req,
            gzip: t.gzip_enabled,
            brotli: t.brotli_enabled,
            ssl_session_cache: t.ssl_session_cache,
            ssl_cache_size: t.ssl_cache_size,
            ssl_cache_timeout: t.ssl_cache_timeout,
            quic: t.http3_enabled,
            quic_port: t.http3_port,
            max_connections: t.max_connections,
            min_compress_size: t.min_compress_size,
        }
    }
}

impl From<ServerTuningConfig> for TuningConfig {
    fn from(s: ServerTuningConfig) -> Self {
        Self {
            max_connections: s.max_connections,
            connection_timeout: s.connection_timeout,
            keep_alive_timeout: s.keep_alive_timeout,
            max_keep_alive_req: s.max_keep_alive_reqs,
            gzip_enabled: s.gzip,
            brotli_enabled: s.brotli,
            min_compress_size: s.min_compress_size,
            ssl_session_cache: s.ssl_session_cache,
            ssl_cache_size: s.ssl_cache_size,
            ssl_cache_timeout: s.ssl_cache_timeout,
            http3_enabled: s.quic,
            http3_port: s.quic_port,
            ..Self::default()
        }
    }
}

fn default_extapp_init_timeout() -> u64 {
    60
}

fn default_extapp_instances() -> u32 {
    1
}

fn default_extapp_backlog() -> u32 {
    100
}

fn default_extapp_mem_limit() -> u64 {
    2047
}

fn default_extapp_proc_limit() -> u32 {
    400
}

/// OLS (OpenLiteSpeed) Harici Uygulama (PHP LSAPI, FastCGI, Reverse Proxy) yapılandırma modeli.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ExternalAppConfig {
    pub id: String,
    pub name: String,
    #[serde(alias = "type")]
    pub app_type: String,
    #[serde(alias = "socket", alias = "addr")]
    pub address: String,
    #[serde(alias = "max_connections")]
    pub max_conns: u32,
    #[serde(default)]
    pub env_vars: HashMap<String, String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default = "default_extapp_init_timeout")]
    pub init_timeout: u64,
    #[serde(default)]
    pub retry_timeout: u64,
    #[serde(default = "default_true")]
    pub persist_conn: bool,
    #[serde(default = "default_true")]
    pub resp_buffer: bool,
    #[serde(default = "default_extapp_instances")]
    pub instances: u32,
    #[serde(default)]
    pub ext_path: String,
    #[serde(default = "default_extapp_backlog")]
    pub backlog: u32,
    #[serde(default = "default_true")]
    pub run_on_startup: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "default_extapp_mem_limit")]
    pub mem_soft_limit_mb: u64,
    #[serde(default = "default_extapp_mem_limit")]
    pub mem_hard_limit_mb: u64,
    #[serde(default = "default_extapp_proc_limit")]
    pub proc_soft_limit: u32,
    #[serde(default = "default_extapp_proc_limit")]
    pub proc_hard_limit: u32,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

pub type ExtAppConfig = ExternalAppConfig;

impl Default for ExternalAppConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            app_type: "lsphp".to_string(),
            address: "127.0.0.1:9000".to_string(),
            max_conns: 100,
            env_vars: HashMap::new(),
            env: Vec::new(),
            init_timeout: 60,
            retry_timeout: 0,
            persist_conn: true,
            resp_buffer: true,
            instances: 1,
            ext_path: String::new(),
            backlog: 100,
            run_on_startup: true,
            priority: 0,
            mem_soft_limit_mb: 2047,
            mem_hard_limit_mb: 2047,
            proc_soft_limit: 400,
            proc_hard_limit: 400,
            enabled: true,
        }
    }
}

impl ExternalAppConfig {
    /// Adresin Unix Domain Socket (UDS) olup olmadığını kontrol eder.
    pub fn is_uds(&self) -> bool {
        self.address.starts_with("uds://")
            || self.address.starts_with("unix:")
            || self.address.ends_with(".sock")
    }

    /// Adresin TCP bağlantısı olup olmadığını kontrol eder.
    pub fn is_tcp(&self) -> bool {
        !self.is_uds()
    }

    pub fn is_lsapi(&self) -> bool {
        self.app_type.eq_ignore_ascii_case("lsapi") || self.app_type.eq_ignore_ascii_case("lsphp")
    }

    pub fn is_fastcgi(&self) -> bool {
        self.app_type.eq_ignore_ascii_case("fastcgi") || self.app_type.eq_ignore_ascii_case("fcgi")
    }

    pub fn is_proxy(&self) -> bool {
        self.app_type.eq_ignore_ascii_case("proxy") || self.app_type.eq_ignore_ascii_case("http")
    }

    pub fn effective_address(&self) -> &str {
        &self.address
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("ExternalAppConfig 'id' boş olamaz".to_string());
        }
        if self.address.trim().is_empty() {
            return Err(format!("ExternalAppConfig '{}' adresi (address) boş olamaz", self.id));
        }
        if self.max_conns == 0 {
            return Err(format!("ExternalAppConfig '{}' max_conns 0 olamaz", self.id));
        }
        Ok(())
    }
}

/// OLS Script Handler kuralı (uzantı -> harici havuz eşlemesi)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ScriptHandlerConfig {
    pub suffix: String,
    #[serde(default = "default_handler_type", alias = "type")]
    pub handler_type: String,
    pub handler: String,
    #[serde(default)]
    pub note: String,
}

fn default_handler_type() -> String {
    "LSAPI".to_string()
}

impl Default for ScriptHandlerConfig {
    fn default() -> Self {
        Self {
            suffix: "php".to_string(),
            handler_type: default_handler_type(),
            handler: "lsphp83".to_string(),
            note: String::new(),
        }
    }
}

impl ScriptHandlerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.suffix.trim().is_empty() {
            return Err("ScriptHandlerConfig 'suffix' boş olamaz".to_string());
        }
        if self.handler.trim().is_empty() {
            return Err("ScriptHandlerConfig 'handler' boş olamaz".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct ContextConfig {
    pub uri: String,
    pub context_type: String,
    pub target: String,
    pub location: String,
    pub handler: String,
    pub headers: HashMap<String, String>,
    pub access_allowed: Vec<String>,
    pub access_denied: Vec<String>,
    pub rewrite_rules: Vec<String>,
    pub redirect_status: u16,
    pub enabled: bool,
}

#[derive(Deserialize)]
struct ContextConfigHelper {
    #[serde(default = "default_context_uri")]
    uri: String,
    #[serde(default = "default_context_type", alias = "type")]
    context_type: String,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    handler: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    access_allowed: Vec<String>,
    #[serde(default)]
    access_denied: Vec<String>,
    #[serde(default)]
    rewrite_rules: Vec<String>,
    #[serde(default = "default_redirect_status")]
    redirect_status: u16,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_context_uri() -> String {
    "/".to_string()
}

fn default_context_type() -> String {
    "static".to_string()
}

fn default_redirect_status() -> u16 {
    301
}

impl<'de> serde::Deserialize<'de> for ContextConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let h = ContextConfigHelper::deserialize(deserializer)?;
        let resolved_target = h.target
            .clone()
            .or_else(|| h.location.clone())
            .unwrap_or_default();
        let resolved_location = h.location
            .clone()
            .or_else(|| if !resolved_target.is_empty() { Some(resolved_target.clone()) } else { None })
            .unwrap_or_default();
        Ok(Self {
            uri: h.uri,
            context_type: h.context_type,
            target: resolved_target,
            location: resolved_location,
            handler: h.handler,
            headers: h.headers,
            access_allowed: h.access_allowed,
            access_denied: h.access_denied,
            rewrite_rules: h.rewrite_rules,
            redirect_status: h.redirect_status,
            enabled: h.enabled,
        })
    }
}

/// OLS denklik takma adı: VHost Context yapılandırması
pub type VHostContextConfig = ContextConfig;

impl ContextConfig {
    /// Hedef adresi veya dosya yolunu döndürür (OLS denklik takma adı: `target`).
    pub fn target(&self) -> &str {
        if !self.target.is_empty() {
            &self.target
        } else {
            &self.location
        }
    }

    /// Konum yolunu döndürür.
    pub fn location(&self) -> &str {
        if !self.location.is_empty() {
            &self.location
        } else {
            &self.target
        }
    }

    /// Context'in Reverse Proxy türünde olup olmadığını denetler.
    pub fn is_proxy(&self) -> bool {
        self.context_type.eq_ignore_ascii_case("proxy")
    }

    /// Context'in Statik Dosya (static) türünde olup olmadığını denetler.
    pub fn is_static(&self) -> bool {
        self.context_type.eq_ignore_ascii_case("static")
    }

    /// Context'in Yeniden Yönlendirme (redirect) türünde olup olmadığını denetler.
    pub fn is_redirect(&self) -> bool {
        self.context_type.eq_ignore_ascii_case("redirect")
    }

    /// Yanıt veya istek başlığı ekler.
    pub fn add_header(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(key.into(), value.into());
    }

    /// Context yapılandırmasını doğrular.
    pub fn validate(&self) -> Result<(), String> {
        if self.uri.trim().is_empty() || !self.uri.starts_with('/') {
            return Err(format!("ContextConfig 'uri' '/' ile başlamalıdır ('{}')", self.uri));
        }
        let ctype = self.context_type.trim().to_ascii_lowercase();
        if !matches!(ctype.as_str(), "static" | "proxy" | "redirect" | "cgi" | "fcgi" | "lsapi") {
            return Err(format!("Geçersiz ContextConfig context_type: '{}'", self.context_type));
        }
        Ok(())
    }
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            uri: "/".to_string(),
            context_type: "static".to_string(),
            target: String::new(),
            location: String::new(),
            handler: String::new(),
            headers: HashMap::new(),
            access_allowed: Vec::new(),
            access_denied: Vec::new(),
            rewrite_rules: Vec::new(),
            redirect_status: 301,
            enabled: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ListenersConfig {
    pub http: HttpListenerConfig,
    pub https: HttpsListenerConfig,
    pub admin: AdminListenerConfig,
    pub api: ApiListenerConfig,
    /// `[[listeners.extra]]`: sabit arka uçlu ek TLS ters vekil dinleyicileri (boş = eski davranış).
    pub extra: Vec<ExtraListenerConfig>,
    /// `[[listeners.custom]]` veya `[[listeners.list]]`: Dinamik dinleyici tanımları
    #[serde(default)]
    pub custom: Vec<ListenerConfig>,
}

fn default_stale_while_revalidate_sec() -> u64 {
    30
}

fn default_max_log_size_mb() -> u64 {
    100
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct CacheConfig {
    pub enabled: bool,
    pub memory_cache_mb: u64,
    pub disk_cache_dir: String,
    pub default_ttl_seconds: u64,
    pub purge_key_header: String,
    #[serde(default = "default_stale_while_revalidate_sec")]
    pub stale_while_revalidate_sec: u64,
    /// HTTP `PURGE` metodu ve `X-LiteSpeed-Purge` istek başlığı ile önbellek temizleme (varsayılan KAPALI).
    pub purge_enabled: bool,
    /// `purge_key_header` başlığında beklenen gizli anahtar (boş = anahtar yetkisi yok).
    pub purge_key: String,
    /// Anahtarsız PURGE'e izinli IP / CIDR listesi (boş = IP yetkisi yok).
    pub purge_allow_ips: Vec<String>,
    /// İstek `Cache-Control` / `Pragma` / `X-LiteSpeed-Cache-Control` başlıklarının önbelleği atlamasına izin verir
    /// (varsayılan KAPALI: OpenLiteSpeed gibi istek başlıkları yok sayılır; açıkken her istemci PHP'yi tetikleyebilir).
    pub respect_request_cache_control: bool,
}

/// Gizli değeri `Debug` çıktısında göstermeden "ayarlı mı" bilgisini verir.
fn redacted_secret(secret: &str) -> &'static str {
    if secret.is_empty() {
        ""
    } else {
        "<gizli>"
    }
}

impl std::fmt::Debug for CacheConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheConfig")
            .field("enabled", &self.enabled)
            .field("memory_cache_mb", &self.memory_cache_mb)
            .field("disk_cache_dir", &self.disk_cache_dir)
            .field("default_ttl_seconds", &self.default_ttl_seconds)
            .field("purge_key_header", &self.purge_key_header)
            .field(
                "stale_while_revalidate_sec",
                &self.stale_while_revalidate_sec,
            )
            .field("purge_enabled", &self.purge_enabled)
            .field("purge_key", &redacted_secret(&self.purge_key))
            .field("purge_allow_ips", &self.purge_allow_ips)
            .field(
                "respect_request_cache_control",
                &self.respect_request_cache_control,
            )
            .finish()
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            memory_cache_mb: 256,
            disk_cache_dir: "cachedata".to_string(),
            default_ttl_seconds: 300,
            purge_key_header: "X-ZMax-Purge-Key".to_string(),
            stale_while_revalidate_sec: default_stale_while_revalidate_sec(),
            purge_enabled: false,
            purge_key: String::new(),
            purge_allow_ips: Vec::new(),
            respect_request_cache_control: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct SecurityConfig {
    pub slowloris_header_timeout_sec: u64,
    pub slowloris_body_timeout_sec: u64,
    pub keep_alive_timeout_sec: u64,
    pub rate_limit_enabled: bool,
    pub rate_limit_per_minute: u32,
    pub block_path_traversal: bool,
    pub max_body_size_mb: usize,
    pub max_header_size_kb: usize,
    #[serde(default)]
    pub allow_ips: Vec<String>,
    #[serde(default)]
    pub deny_ips: Vec<String>,
    /// Otomatik ban'dan (ardışık 401, WAF, hız sınırı) muaf IP/CIDR listesi. Boş varsayılan; loopback koddan her zaman muaf.
    /// Not: `allow_ips` sıkı beyaz listedir (listede olmayanı engeller), ban muafiyeti DEĞİLDİR.
    #[serde(default)]
    pub ban_exempt_ips: Vec<String>,
    /// Basic Auth için eşzamanlı Argon2/apr1 doğrulama üst sınırı (semafor; yeniden başlatmada geçerli).
    pub auth_max_concurrent_hashes: usize,
    /// API/admin ardışık 401 eşiği (aşılınca IP banlanır).
    #[serde(default = "d_auth_fail_limit")]
    pub auth_fail_limit: u32,
    #[serde(default = "d_auth_fail_window")]
    pub auth_fail_window_sec: u64,
    #[serde(default = "d_auth_ban")]
    pub auth_ban_sec: u64,
    /// API/admin IP başına dakikadaki istek sınırı.
    #[serde(default = "d_api_rate")]
    pub api_rate_limit_per_minute: u32,
}

fn d_auth_fail_limit() -> u32 { 5 }
fn d_auth_fail_window() -> u64 { 300 }
fn d_auth_ban() -> u64 { 900 }
/// WebAdmin tek sayfa 5 uç noktayı yoklar; birden çok sekme/panel için 120/dk yetersizdi (429).
fn d_api_rate() -> u32 { 600 }

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            slowloris_header_timeout_sec: 10,
            slowloris_body_timeout_sec: 30,
            keep_alive_timeout_sec: 65,
            rate_limit_enabled: true,
            rate_limit_per_minute: 2000,
            block_path_traversal: true,
            max_body_size_mb: 64,
            max_header_size_kb: 64,
            allow_ips: Vec::new(),
            deny_ips: Vec::new(),
            ban_exempt_ips: Vec::new(),
            auth_max_concurrent_hashes: 4,
            auth_fail_limit: 5,
            auth_fail_window_sec: 300,
            auth_ban_sec: 900,
            api_rate_limit_per_minute: 600,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct LoggingConfig {
    pub access_log: String,
    pub error_log: String,
    pub log_level: String,
    pub log_format: String,
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,
    #[serde(default = "default_batch_flush_ms")]
    pub batch_flush_ms: u64,
    #[serde(default = "default_batch_buffer_kb")]
    pub batch_buffer_kb: usize,
    #[serde(default = "default_true")]
    pub add_request_id: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            access_log: "logs/access.log".to_string(),
            error_log: "logs/error.log".to_string(),
            log_level: "info".to_string(),
            log_format: "%h %l %u %t \"%r\" %>s %b".to_string(),
            max_log_size_mb: default_max_log_size_mb(),
            batch_flush_ms: default_batch_flush_ms(),
            batch_buffer_kb: default_batch_buffer_kb(),
            add_request_id: true,
        }
    }
}

impl LoggingConfig {
    /// Günlük yapılandırmasındaki seviye ve biçim alanlarını doğrular.
    pub fn validate(&self) -> Result<(), String> {
        let lvl = self.log_level.trim().to_ascii_lowercase();
        if !matches!(lvl.as_str(), "error" | "warn" | "warning" | "info" | "debug" | "trace") {
            return Err(format!("Geçersiz logging.log_level değeri: '{}'", self.log_level));
        }
        if !is_valid_log_format(&self.log_format) {
            return Err(format!("Geçersiz logging.log_format değeri: '{}'", self.log_format));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostsDirConfig {
    pub path: String,
}

impl Default for VHostsDirConfig {
    fn default() -> Self {
        Self {
            path: "conf/vhosts".to_string(),
        }
    }
}

fn default_sandbox_engine() -> String {
    "nsjail".to_string()
}
fn default_sandbox_profile() -> String {
    "conf/jail/default.cfg".to_string()
}
fn default_seccomp_policy() -> String {
    "conf/seccomp/zmax_seccomp.cfg".to_string()
}
fn default_cgroup_mem_limit() -> u64 {
    256
}
fn default_cgroup_pids_limit() -> u32 {
    64
}
fn default_cgroup_cpu_percent() -> u32 {
    50
}

/// Linux izolasyon ve sandbox modeli (nsjail / cgroups / seccomp) (I-01 .. I-10 / izalasyon.md)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SandboxConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_sandbox_engine")]
    pub engine: String,
    #[serde(default = "default_sandbox_profile")]
    pub profile: String,
    #[serde(default = "default_seccomp_policy")]
    pub seccomp_policy: String,
    #[serde(default = "default_cgroup_mem_limit")]
    pub cgroup_mem_limit_mb: u64,
    #[serde(default = "default_cgroup_pids_limit")]
    pub cgroup_pids_limit: u32,
    #[serde(default = "default_cgroup_cpu_percent")]
    pub cgroup_cpu_percent: u32,
    #[serde(default = "default_true")]
    pub read_only_root: bool,
    #[serde(default = "default_true")]
    pub network_isolated: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            engine: default_sandbox_engine(),
            profile: default_sandbox_profile(),
            seccomp_policy: default_seccomp_policy(),
            cgroup_mem_limit_mb: default_cgroup_mem_limit(),
            cgroup_pids_limit: default_cgroup_pids_limit(),
            cgroup_cpu_percent: default_cgroup_cpu_percent(),
            read_only_root: true,
            network_isolated: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ZMaxConfig {
    pub server: ServerGlobalConfig,
    pub listeners: ListenersConfig,
    pub cache: CacheConfig,
    pub security: SecurityConfig,
    pub logging: LoggingConfig,
    pub vhosts_dir: VHostsDirConfig,
    #[serde(default)]
    pub acme: AcmeConfig,
    #[serde(default)]
    pub tuning: TuningConfig,
    #[serde(default, alias = "ext_apps", alias = "external_apps")]
    pub extapps: Vec<ExternalAppConfig>,
    #[serde(default)]
    pub script_handlers: Vec<ScriptHandlerConfig>,
    #[serde(default)]
    pub vhosts: HashMap<String, VHostEntry>,
    #[serde(default)]
    pub sandbox: SandboxConfig,
}

impl ZMaxConfig {
    /// OLS denklik standartlarında sunucu ince ayar modelini (`ServerTuningConfig`) döndürür.
    pub fn effective_tuning(&self) -> ServerTuningConfig {
        if self.server.tuning != TuningConfig::default() {
            self.server.tuning.clone().into()
        } else {
            self.tuning.clone().into()
        }
    }

    /// Etkin harici uygulama listesini döndürür (server.ext_apps veya top-level extapps).
    pub fn effective_ext_apps(&self) -> Vec<ExternalAppConfig> {
        if !self.server.ext_apps.is_empty() {
            self.server.ext_apps.clone()
        } else {
            self.extapps.clone()
        }
    }

    /// Etkin dinamik dinleyicileri döndürür (server.listeners veya listeners.custom).
    pub fn effective_custom_listeners(&self) -> Vec<ListenerConfig> {
        if !self.server.listeners.is_empty() {
            self.server.listeners.clone()
        } else {
            self.listeners.custom.clone()
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct VHostFileDocument {
    pub vhost: VHostEntry,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostEntry {
    pub name: String,
    pub aliases: Vec<String>,
    pub document_root: String,
    pub index_files: Vec<String>,
    pub cache: VHostCacheSection,
    pub php: VHostPhpSection,
    pub ssl: VHostSslSection,
    pub security: VHostSecuritySection,
    pub rewrite: VHostRewriteSection,
    pub proxy: VHostProxySection,
    pub headers: VHostHeadersSection,
    #[serde(default)]
    pub logging: VHostLoggingSection,
    #[serde(default)]
    pub error_docs: VHostErrorDocsSection,
    // [ols-parity] HTTP durum koduna göre özel hata sayfaları eşlemesi
    #[serde(default, with = "serde_status_hashmap", skip_serializing_if = "HashMap::is_empty")]
    pub error_pages: HashMap<u16, String>,
    #[serde(default)]
    pub tls: VHostTlsSection,
    #[serde(default, rename = "static")]
    pub static_files: VHostStaticSection,
    #[serde(default)]
    pub hotlink: HotlinkConfig,
    #[serde(default)]
    pub acl: VhostAclConfig,
    #[serde(default)]
    pub acme: AcmeConfig,
    // [kart-10] Ters vekil genişletilmiş ayarları (initTimeout, keep-alive, respBuffer)
    #[serde(default)]
    pub proxy_ext: ProxyExtConfig,
    #[serde(default)]
    pub auth: VHostAuthSection,
    // [ols-parity] URI tabanlı Context yönlendiricisi
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contexts: Vec<ContextConfig>,
    // [ols-parity] vHost düzeyinde harici uygulama havuzları
    #[serde(default, alias = "extapps", skip_serializing_if = "Vec::is_empty")]
    pub ext_apps: Vec<ExtAppConfig>,
    // [ols-parity] vHost düzeyinde betik işleyicileri
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub script_handlers: Vec<ScriptHandlerConfig>,
}

pub type VHostConfig = VHostEntry;

impl Default for VHostEntry {
    fn default() -> Self {
        Self {
            name: "localhost".to_string(),
            aliases: Vec::new(),
            document_root: "www/html".to_string(),
            index_files: vec![
                "index.html".to_string(),
                "index.htm".to_string(),
                "index.php".to_string(),
            ],
            cache: VHostCacheSection::default(),
            php: VHostPhpSection::default(),
            ssl: VHostSslSection::default(),
            security: VHostSecuritySection::default(),
            rewrite: VHostRewriteSection::default(),
            proxy: VHostProxySection::default(),
            headers: VHostHeadersSection::default(),
            logging: VHostLoggingSection::default(),
            error_docs: VHostErrorDocsSection::default(),
            error_pages: HashMap::new(),
            tls: VHostTlsSection::default(),
            static_files: VHostStaticSection::default(),
            hotlink: HotlinkConfig::default(),
            acl: VhostAclConfig::default(),
            acme: AcmeConfig::default(),
            proxy_ext: ProxyExtConfig::default(),
            auth: VHostAuthSection::default(),
            contexts: Vec::new(),
            ext_apps: Vec::new(),
            script_handlers: Vec::new(),
        }
    }
}

impl VHostEntry {
    /// Etkin PHP FastCGI yukarı akış (upstream) adreslerini döndürür.
    /// `php.upstreams` doluysa onu kullanır; aksi durumda tekil `php.upstream` değerine düşer.
    pub fn effective_php_upstreams(&self) -> Vec<String> {
        let multi: Vec<String> = self
            .php
            .upstreams
            .iter()
            .map(|u| u.trim())
            .filter(|u| !u.is_empty())
            .map(|u| u.to_string())
            .collect();
        if !multi.is_empty() {
            return multi;
        }
        let single = self.php.upstream.trim();
        if single.is_empty() {
            Vec::new()
        } else {
            vec![single.to_string()]
        }
    }

    /// Verilen HTTP durum kodu için özel hata sayfası yolunu yol enjeksiyonu (`..`) korumalı biçimde çözer.
    pub fn resolve_error_doc_page(&self, status: u16) -> Option<PathBuf> {
        let raw_page = self.error_pages.get(&status).cloned().or_else(|| {
            if self.error_docs.enabled {
                self.error_docs.pages.get(&status).cloned().or_else(|| {
                    if status == 404 {
                        self.error_docs.not_found.clone()
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        })?;
        if !is_safe_relative_subpath(&raw_page) {
            return None;
        }
        let page_rel = Path::new(raw_page.trim());
        let base = self.error_docs.dir.trim();
        if base.is_empty() {
            Some(page_rel.to_path_buf())
        } else if is_safe_error_docs_dir(base) {
            Some(Path::new(base).join(page_rel))
        } else {
            None
        }
    }

    /// JSON metninden `VHostEntry` ayrıştırır (eksik alanlar varsayılanlarla tamamlanır).
    pub fn parse_json(content: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(content)
    }

    /// `VHostEntry` yapısını biçimlendirilmiş JSON metnine serileştirir.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Sanal konak kaydının tüm alan ve alt bölümlerini doğrular.
    pub fn validate(&self) -> Result<(), String> {
        validate_domain(&self.name)
            .map_err(|e| format!("vHost '{}' alan adı geçersiz: {}", self.name, e))?;
        let scope = format!("vHost '{}'", self.name);
        validate_ip_acl_list(&scope, "security.allow_ips", &self.security.allow_ips)?;
        validate_ip_acl_list(&scope, "security.deny_ips", &self.security.deny_ips)?;
        self.acl.validate(&scope)?;
        self.hotlink.validate(&scope)?;
        self.validate_sections()
    }

    /// Etkin hotlink koruma yapılandırmasını döndürür.
    /// Doğrudan `[vhost.hotlink]` tanımlıysa onu; aksi halde geriye uyumluluk için `[vhost.security.hotlink_protection]` değerini temel alır.
    pub fn effective_hotlink(&self) -> HotlinkConfig {
        if self.hotlink.enabled || !self.hotlink.allowed_referers.is_empty() {
            self.hotlink.clone()
        } else if self.security.hotlink_protection {
            HotlinkConfig {
                enabled: true,
                allowed_referers: Vec::new(),
                extensions: default_hotlink_extensions(),
            }
        } else {
            self.hotlink.clone()
        }
    }

    /// Etkin IP ACL yapılandırmasını döndürür.
    /// `[vhost.acl]` tanımlıysa onu; boşsa geriye uyumluluk için `[vhost.security.allow_ips]` ve `deny_ips` değerlerini temel alır.
    pub fn effective_acl(&self) -> VhostAclConfig {
        if !self.acl.allow_ips.is_empty() || !self.acl.deny_ips.is_empty() {
            self.acl.clone()
        } else {
            VhostAclConfig {
                allow_ips: self.security.allow_ips.clone(),
                deny_ips: self.security.deny_ips.clone(),
            }
        }
    }

    /// Alan adı ve IP ACL dışında kalan bölüm düzeyindeki ayarları doğrular.
    pub fn validate_sections(&self) -> Result<(), String> {
        self.logging.validate()?;
        self.tls.validate()?;
        self.php.validate()?;
        self.proxy_ext.validate("vhost.proxy_ext")?;
        // [kart-9] Basic Authentication bölüm doğrulaması
        self.auth.validate(&format!("vHost '{}'", self.name))?;
        for ctx in &self.contexts {
            ctx.validate()?;
        }
        for app in &self.ext_apps {
            app.validate()?;
        }
        for sh in &self.script_handlers {
            sh.validate()?;
        }
        for (code, path) in &self.error_pages {
            if *code < 100 || *code > 599 {
                return Err(format!("vHost '{}' geçersiz HTTP durum kodu: {}", self.name, code));
            }
            if !is_safe_relative_subpath(path) {
                return Err(format!("vHost '{}' geçersiz hata sayfası yolu: '{}'", self.name, path));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostCacheSection {
    pub enabled: bool,
    pub expire: u64,
}

impl Default for VHostCacheSection {
    fn default() -> Self {
        Self {
            enabled: true,
            expire: 300,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostPhpSection {
    pub enabled: bool,
    pub sapi: String,
    pub upstream: String,
    pub timeout: u64,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default = "default_php_lb_policy")]
    pub lb_policy: String,
    /// FastCGI bağlantı zaman aşımı (ms). `None` = vhost bir değer vermedi; `mod_fastcgi` politika
    /// değeri (`settings.dial_timeout_ms`) kullanılır. `Some(0)` da politikaya düşer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dial_timeout_ms: Option<u64>,
    #[serde(default = "default_php_io_timeout_secs")]
    pub io_timeout_secs: u64,
    #[serde(default = "default_true")]
    pub keep_conn: bool,
    #[serde(default = "default_php_max_idle_conns")]
    pub max_idle_conns: usize,
    #[serde(default = "default_true")]
    pub resolve_root_symlink: bool,
    #[serde(default = "default_true")]
    pub allow_x_accel_redirect: bool,
    #[serde(default)]
    pub x_accel_prefix: String,
}

impl Default for VHostPhpSection {
    fn default() -> Self {
        Self {
            enabled: true,
            sapi: "fastcgi".to_string(),
            upstream: "127.0.0.1:9000".to_string(),
            timeout: 60,
            upstreams: Vec::new(),
            lb_policy: default_php_lb_policy(),
            dial_timeout_ms: None,
            io_timeout_secs: default_php_io_timeout_secs(),
            keep_conn: true,
            max_idle_conns: default_php_max_idle_conns(),
            resolve_root_symlink: true,
            allow_x_accel_redirect: true,
            x_accel_prefix: String::new(),
        }
    }
}

impl VHostPhpSection {
    /// PHP yük dengeleme politikası ve zaman aşımı yapılandırmasını doğrular.
    pub fn validate(&self) -> Result<(), String> {
        let policy = self.lb_policy.trim().to_ascii_lowercase();
        if !matches!(
            policy.as_str(),
            "round_robin" | "least_conn" | "random" | "ip_hash" | "first"
        ) {
            return Err(format!(
                "Geçersiz vhost.php.lb_policy değeri: '{}' (beklenen: round_robin, least_conn, random, ip_hash, first)",
                self.lb_policy
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct VHostSslSection {
    #[serde(alias = "cert", alias = "cert_file")]
    pub certificate: String,
    #[serde(alias = "key_file")]
    pub key: String,
    #[serde(default)]
    pub acme: bool,
    #[serde(default)]
    pub acme_config: Option<AcmeConfig>,
}

pub type SslConfig = VHostSslSection;

impl VHostSslSection {
    pub fn cert(&self) -> &str {
        &self.certificate
    }

    pub fn cert_path(&self) -> &str {
        &self.certificate
    }

    pub fn key_path(&self) -> &str {
        &self.key
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostSecuritySection {
    pub hotlink_protection: bool,
    pub force_https: bool,
    #[serde(default)]
    pub allow_ips: Vec<String>,
    #[serde(default)]
    pub deny_ips: Vec<String>,
    #[serde(default)]
    pub waf_enabled: Option<bool>,
    #[serde(default = "default_true")]
    pub wp_brute_force: bool,
    #[serde(default)]
    pub waf_exclude_paths: Vec<String>,
    /// [kart-12-hazirlik-b] OLS B5 denkliği: .env, .git, wp-config, tehlikeli uzantılar koruması (varsayılan kapalı)
    #[serde(default)]
    pub block_dangerous_files: bool,
}

impl Default for VHostSecuritySection {
    fn default() -> Self {
        Self {
            hotlink_protection: false,
            force_https: false,
            allow_ips: Vec::new(),
            deny_ips: Vec::new(),
            waf_enabled: None,
            wp_brute_force: true,
            waf_exclude_paths: Vec::new(),
            block_dangerous_files: false,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(default)]
pub struct VHostRewriteRule {
    pub pattern: String,
    pub target: String,
    pub status: u16,
    #[serde(default)]
    pub flags: Vec<String>,
    pub last: bool,
}

pub type RewriteRule = VHostRewriteRule;

/// OLS (OpenLiteSpeed) Sanal Konak Yeniden Yazma (Rewrite) modeli.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct VHostRewriteConfig {
    #[serde(alias = "enabled")]
    pub enable: bool,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default = "default_true")]
    pub inherit: bool,
}

pub type RewriteConfig = VHostRewriteConfig;

impl Default for VHostRewriteConfig {
    fn default() -> Self {
        Self {
            enable: true,
            rules: Vec::new(),
            inherit: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct VHostRewriteSection {
    #[serde(alias = "enable")]
    pub enabled: bool,
    pub try_files: bool,
    pub htaccess: bool,
    #[serde(default = "default_true")]
    pub inherit: bool,
    #[serde(default)]
    pub raw_rules: Vec<String>,
    #[serde(default)]
    pub rules: Vec<VHostRewriteRule>,
}

impl Default for VHostRewriteSection {
    fn default() -> Self {
        Self {
            enabled: true,
            try_files: true,
            htaccess: true,
            inherit: true,
            raw_rules: Vec::new(),
            rules: Vec::new(),
        }
    }
}

impl From<VHostRewriteSection> for VHostRewriteConfig {
    fn from(s: VHostRewriteSection) -> Self {
        let mut r = s.raw_rules;
        if r.is_empty() && !s.rules.is_empty() {
            r = s
                .rules
                .iter()
                .map(|rule| {
                    if rule.status > 0 {
                        format!("RewriteRule {} {} [R={}]", rule.pattern, rule.target, rule.status)
                    } else {
                        format!("RewriteRule {} {}", rule.pattern, rule.target)
                    }
                })
                .collect();
        }
        Self {
            enable: s.enabled,
            rules: r,
            inherit: s.inherit,
        }
    }
}

impl From<VHostRewriteConfig> for VHostRewriteSection {
    fn from(c: VHostRewriteConfig) -> Self {
        Self {
            enabled: c.enable,
            try_files: true,
            htaccess: true,
            inherit: c.inherit,
            raw_rules: c.rules.clone(),
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostLoggingSection {
    pub enabled: bool,
    pub access_log: String,
    pub error_log: String,
    #[serde(default = "default_vhost_log_format")]
    pub format: String,
    #[serde(default = "default_max_log_size_mb")]
    pub max_log_size_mb: u64,
    #[serde(default = "default_true")]
    pub also_write_global: bool,
}

impl Default for VHostLoggingSection {
    fn default() -> Self {
        Self {
            enabled: false,
            access_log: String::new(),
            error_log: String::new(),
            format: default_vhost_log_format(),
            max_log_size_mb: default_max_log_size_mb(),
            also_write_global: true,
        }
    }
}

impl VHostLoggingSection {
    /// Sanal konak günlük biçimini doğrular.
    pub fn validate(&self) -> Result<(), String> {
        if !is_valid_log_format(&self.format) {
            return Err(format!("Geçersiz vhost.logging.format değeri: '{}'", self.format));
        }
        Ok(())
    }
}

mod serde_status_pages {
    use serde::de::{MapAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;
    use std::fmt;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StatusKey {
        Num(u16),
        Str(String),
    }

    pub fn serialize<S>(map: &BTreeMap<u16, String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str_map: BTreeMap<String, &String> =
            map.iter().map(|(k, v)| (k.to_string(), v)).collect();
        str_map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<u16, String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusMapVisitor;

        impl<'de> Visitor<'de> for StatusMapVisitor {
            type Value = BTreeMap<u16, String>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("HTTP durum kodu -> dosya yolu eşlemesi")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut out = BTreeMap::new();
                while let Some((key, val)) = access.next_entry::<StatusKey, String>()? {
                    let code = match key {
                        StatusKey::Num(n) => n,
                        StatusKey::Str(s) => s.trim().parse::<u16>().map_err(|_| {
                            serde::de::Error::custom(format!(
                                "Geçersiz HTTP durum kodu anahtarı: '{}'",
                                s
                            ))
                        })?,
                    };
                    out.insert(code, val);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_map(StatusMapVisitor)
    }
}

mod serde_status_hashmap {
    use serde::de::{MapAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;
    use std::fmt;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StatusKey {
        Num(u16),
        Str(String),
    }

    pub fn serialize<S>(map: &HashMap<u16, String>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let str_map: HashMap<String, &String> =
            map.iter().map(|(k, v)| (k.to_string(), v)).collect();
        str_map.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<u16, String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StatusMapVisitor;

        impl<'de> Visitor<'de> for StatusMapVisitor {
            type Value = HashMap<u16, String>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("HTTP durum kodu -> dosya yolu eşlemesi")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut out = HashMap::new();
                while let Some((key, val)) = access.next_entry::<StatusKey, String>()? {
                    let code = match key {
                        StatusKey::Num(n) => n,
                        StatusKey::Str(s) => s.trim().parse::<u16>().map_err(|_| {
                            serde::de::Error::custom(format!(
                                "Geçersiz HTTP durum kodu anahtarı: '{}'",
                                s
                            ))
                        })?,
                    };
                    out.insert(code, val);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_map(StatusMapVisitor)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct VHostErrorDocsSection {
    pub enabled: bool,
    pub dir: String,
    #[serde(default, with = "serde_status_pages")]
    pub pages: std::collections::BTreeMap<u16, String>,
    #[serde(default)]
    pub not_found: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostTlsSection {
    #[serde(default = "default_true")]
    pub http2: bool,
    pub strict_sni: bool,
    #[serde(default = "default_tls_min_version")]
    pub min_version: String,
}

impl Default for VHostTlsSection {
    fn default() -> Self {
        Self {
            http2: true,
            strict_sni: true,
            min_version: default_tls_min_version(),
        }
    }
}

impl VHostTlsSection {
    /// Minimum TLS sürümünü doğrular (`"1.2"` veya `"1.3"`).
    pub fn validate(&self) -> Result<(), String> {
        match self.min_version.trim() {
            "1.2" | "1.3" => Ok(()),
            other => Err(format!(
                "Geçersiz vhost.tls.min_version değeri: '{}' (beklenen: \"1.2\" veya \"1.3\")",
                other
            )),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostStaticSection {
    #[serde(default = "default_true")]
    pub precompressed: bool,
    #[serde(default = "default_true")]
    pub brotli: bool,
    #[serde(default = "default_true")]
    pub gzip: bool,
    pub autoindex: bool,
    #[serde(default = "default_true")]
    pub sendfile: bool,
}

impl Default for VHostStaticSection {
    fn default() -> Self {
        Self {
            precompressed: true,
            brotli: true,
            gzip: true,
            autoindex: false,
            sendfile: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostProxySection {
    pub enabled: bool,
    pub upstream: String,
    pub path_prefix: String,
    pub preserve_host: bool,
    pub websocket: bool,
}

impl Default for VHostProxySection {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream: String::new(),
            path_prefix: "/".to_string(),
            preserve_host: true,
            websocket: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct VHostHeadersSection {
    pub security_headers: bool,
    pub hsts: bool,
}

impl Default for VHostHeadersSection {
    fn default() -> Self {
        Self {
            security_headers: true,
            hsts: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoadedVHost {
    pub entry: VHostEntry,
    pub file_name: String,
    pub resolved_doc_root: PathBuf,
}

impl ZMaxConfig {
    pub fn parse_toml(content: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(content)
    }

    /// JSON metninden `ZMaxConfig` ayrıştırır (eksik alanlar varsayılanlarla tamamlanır).
    pub fn parse_json(content: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(content)
    }

    /// `ZMaxConfig` yapısını biçimlendirilmiş JSON metnine serileştirir.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Yapılandırmayı dosyadan yükler; dosya yoksa güvenli varsayılanları döner.
    pub fn load_or_default(path: &Path) -> Result<Self, String> {
        let mut cfg = if path.exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("Yapılandırma dosyası okunamadı ({}): {}", path.display(), e))?;
            Self::parse_toml(&content)
                .map_err(|e| format!("TOML sözdizimi hatası ({}): {}", path.display(), e))?
        } else {
            Self::default()
        };
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    /// Ortam değişkenleriyle port/adres/token değerlerini esnek olarak geçersiz kılar.
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("ZMAX_HTTP_ADDR") {
            if !v.trim().is_empty() {
                self.listeners.http.address = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("ZMAX_HTTP_PORT") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    self.listeners.http.port = p;
                }
            }
        }
        if let Ok(v) = std::env::var("ZMAX_HTTPS_ADDR") {
            if !v.trim().is_empty() {
                self.listeners.https.address = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("ZMAX_HTTPS_PORT") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    self.listeners.https.port = p;
                }
            }
        }
        if let Ok(v) = std::env::var("ZMAX_ADMIN_ADDR") {
            if !v.trim().is_empty() {
                self.listeners.admin.address = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("ZMAX_ADMIN_PORT") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    self.listeners.admin.port = p;
                }
            }
        }
        if let Ok(v) = std::env::var("ZMAX_API_ADDR") {
            if !v.trim().is_empty() {
                self.listeners.api.address = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("ZMAX_API_PORT") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    self.listeners.api.port = p;
                }
            }
        }
        if let Ok(v) = std::env::var("ZMAX_API_TOKEN") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                self.listeners.api.token = trimmed.to_string();
                self.listeners.api.require_token = true;
            }
        }
        if let Ok(v) = std::env::var("ZMAX_ADMIN_TOKEN") {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                self.listeners.admin.token = trimmed.to_string();
                self.listeners.admin.require_token = true;
            }
        }
        if let Ok(v) = std::env::var("ZMAX_ADMIN_REQUIRE_TOKEN") {
            if let Some(flag) = parse_env_bool(&v) {
                self.listeners.admin.require_token = flag;
            }
        }
        if let Ok(v) = std::env::var("ZMAX_MAX_BODY_MB") {
            if let Ok(mb) = v.trim().parse::<usize>() {
                if mb > 0 {
                    self.security.max_body_size_mb = mb;
                }
            }
        }
        if let Ok(v) = std::env::var("ZMAX_VHOSTS_DIR") {
            if !v.trim().is_empty() {
                self.vhosts_dir.path = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("ZMAX_WORKERS") {
            if let Ok(w) = v.trim().parse::<usize>() {
                self.server.workers = w;
            }
        }
    }

    /// Tüm çekirdek yapılandırma alanlarını (dinleyiciler, port çakışması, güvenlik limitleri, önbellek ve günlük seviyesi) doğrular.
    pub fn validate(&self) -> Result<(), String> {
        let mut active_tcp: Vec<(&'static str, std::net::IpAddr, u16)> = Vec::new();
        let tcp_specs = [
            ("http", self.listeners.http.enabled, self.listeners.http.address.as_str(), self.listeners.http.port),
            ("https", self.listeners.https.enabled, self.listeners.https.address.as_str(), self.listeners.https.port),
            ("admin", self.listeners.admin.enabled, self.listeners.admin.address.as_str(), self.listeners.admin.port),
            ("api", self.listeners.api.enabled, self.listeners.api.address.as_str(), self.listeners.api.port),
        ];

        for (name, enabled, raw_addr, port) in tcp_specs {
            if !enabled {
                continue;
            }
            if port == 0 {
                return Err(format!("Etkin '{}' dinleyicisinin portu 0 olamaz.", name));
            }
            let ip = parse_listener_ip(raw_addr).map_err(|e| {
                format!("Etkin '{}' dinleyicisinin adresi geçersiz ('{}'): {}", name, raw_addr, e)
            })?;
            for &(prev_name, prev_ip, prev_port) in &active_tcp {
                // Admin ve API dinleyicileri bilinçli olarak aynı soket üzerinden sunulabilir.
                let admin_api_pair = (prev_name == "admin" && name == "api") || (prev_name == "api" && name == "admin");
                if !admin_api_pair && prev_port == port && ips_overlap(prev_ip, ip) {
                    return Err(format!(
                        "Dinleyici port çakışması: '{}' ({}:{}) ile '{}' ({}:{}) aynı soketi kullanıyor.",
                        prev_name, prev_ip, prev_port, name, ip, port
                    ));
                }
            }
            active_tcp.push((name, ip, port));
        }
        extra_listener::validate_extra_listeners(
            &self.listeners.extra,
            &active_tcp
                .iter()
                .map(|(n, ip, p)| (n.to_string(), *ip, *p))
                .collect::<Vec<_>>(),
        )?;

        if self.listeners.http.enabled && self.listeners.http.backlog == 0 {
            return Err("listeners.http.backlog değeri 0 olamaz.".to_string());
        }
        if self.security.slowloris_header_timeout_sec == 0 {
            return Err("security.slowloris_header_timeout_sec değeri 0 olamaz.".to_string());
        }
        if self.security.slowloris_body_timeout_sec == 0 {
            return Err("security.slowloris_body_timeout_sec değeri 0 olamaz.".to_string());
        }
        if self.security.keep_alive_timeout_sec == 0 {
            return Err("security.keep_alive_timeout_sec değeri 0 olamaz.".to_string());
        }
        if self.security.rate_limit_enabled && self.security.rate_limit_per_minute == 0 {
            return Err("Hız sınırlama etkinken security.rate_limit_per_minute değeri 0 olamaz.".to_string());
        }
        if self.security.max_body_size_mb == 0 {
            return Err("security.max_body_size_mb değeri 0 olamaz.".to_string());
        }
        if self.security.max_header_size_kb == 0 {
            return Err("security.max_header_size_kb değeri 0 olamaz.".to_string());
        }
        if self.cache.enabled && (self.cache.memory_cache_mb == 0 || self.cache.default_ttl_seconds == 0) {
            return Err("Önbellek etkinken memory_cache_mb ve default_ttl_seconds 0 olamaz.".to_string());
        }
        validate_ip_acl_list("cache", "purge_allow_ips", &self.cache.purge_allow_ips)?;
        self.logging.validate()?;
        validate_ip_acl_list("security", "allow_ips", &self.security.allow_ips)?;
        validate_ip_acl_list("security", "deny_ips", &self.security.deny_ips)?;
        for (domain, vh) in &self.vhosts {
            validate_domain(domain).map_err(|e| format!("Geçersiz satır içi vHost alanı '{}': {}", domain, e))?;
            let scope = format!("vhosts.{}", domain);
            validate_ip_acl_list(&scope, "security.allow_ips", &vh.security.allow_ips)?;
            validate_ip_acl_list(&scope, "security.deny_ips", &vh.security.deny_ips)?;
            vh.validate_sections()
                .map_err(|e| format!("vhosts.{} doğrulama hatası: {}", domain, e))?;
        }
        for (name, enabled, ssl, tls_cert, tls_key, proxy_prefix) in [
            (
                "admin",
                self.listeners.admin.enabled,
                self.listeners.admin.ssl,
                self.listeners.admin.tls_cert.as_str(),
                self.listeners.admin.tls_key.as_str(),
                self.listeners.admin.proxy_prefix.as_str(),
            ),
            (
                "api",
                self.listeners.api.enabled,
                self.listeners.api.ssl,
                self.listeners.api.tls_cert.as_str(),
                self.listeners.api.tls_key.as_str(),
                self.listeners.api.proxy_prefix.as_str(),
            ),
        ] {
            validate_panel_listener_tls_and_proxy(
                name,
                enabled,
                ssl,
                tls_cert,
                tls_key,
                proxy_prefix,
            )?;
        }

        // [Güvenlik] Wildcard CORS, kötü niyetli bir sitenin kullanıcı token'ıyla
        // çapraz-origin yönetim çağrısı yapmasına olanak tanır. Boş değer CORS'u
        // kapatır; aksi halde yalnızca http(s) origin'i kabul edilir.
        let cors = self.listeners.api.cors_allow_origin.trim();
        if !cors.is_empty()
            && (cors == "*"
                || (!cors.starts_with("http://") && !cors.starts_with("https://")))
        {
            return Err(format!(
                "listeners.api.cors_allow_origin güvensiz: '{}'. Boş bırakılabilir (CORS kapalı) veya https://... biçiminde tek bir origin verilmelidir.",
                cors
            ));
        }

        // [Güvenlik] Etkin TLS dinleyicisinde strict SNI zorunludur; aksi halde
        // IP/literal Host başlıkları iç vhost'lara erişebilir.
        if self.listeners.https.enabled
            && self.listeners.https.ssl
            && !self.listeners.https.strict_sni
        {
            return Err(
                "listeners.https.strict_sni = false güvensizdir; etkin TLS dinleyicisinde true olmalıdır."
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Ana yapılandırma ile birlikte vHost ve modül dizinlerini doğrular; kritik olmayan eksikler için uyarı listesi döndürür.
    pub fn validate_workspace_layout(
        &self,
        base_dir: &Path,
        vhosts: &[LoadedVHost],
        modules: &LoadedModules,
    ) -> Result<Vec<String>, String> {
        self.validate()?;
        let mut warnings = Vec::new();

        for (name, enabled, ssl, tls_cert, tls_key) in [
            (
                "admin",
                self.listeners.admin.enabled,
                self.listeners.admin.ssl,
                self.listeners.admin.tls_cert.as_str(),
                self.listeners.admin.tls_key.as_str(),
            ),
            (
                "api",
                self.listeners.api.enabled,
                self.listeners.api.ssl,
                self.listeners.api.tls_cert.as_str(),
                self.listeners.api.tls_key.as_str(),
            ),
        ] {
            if enabled && ssl {
                let cert_path = resolve_path(base_dir, tls_cert.trim());
                if !cert_path.is_file() {
                    return Err(format!(
                        "Etkin '{}' dinleyicisinin TLS sertifika dosyası bulunamadı: {}",
                        name,
                        cert_path.display()
                    ));
                }
                let key_path = resolve_path(base_dir, tls_key.trim());
                if !key_path.is_file() {
                    return Err(format!(
                        "Etkin '{}' dinleyicisinin TLS özel anahtar dosyası bulunamadı: {}",
                        name,
                        key_path.display()
                    ));
                }
                if let Some(warning) = sensitive_file_permission_warning(&key_path, true) {
                    warnings.push(format!("'{}' dinleyicisi: {}", name, warning));
                }
            }
        }

        extra_listener::validate_extra_listener_files(&self.listeners.extra, base_dir)?;

        for vh in vhosts {
            validate_domain(&vh.entry.name)
                .map_err(|e| format!("vHost '{}' alan adı geçersiz: {}", vh.file_name, e))?;
            let scope = format!("vHost '{}'", vh.entry.name);
            validate_ip_acl_list(&scope, "security.allow_ips", &vh.entry.security.allow_ips)?;
            validate_ip_acl_list(&scope, "security.deny_ips", &vh.entry.security.deny_ips)?;
            vh.entry
                .validate_sections()
                .map_err(|e| format!("vHost '{}' yapılandırma hatası: {}", vh.entry.name, e))?;
            if vh.entry.php.enabled && vh.entry.effective_php_upstreams().is_empty() {
                return Err(format!("vHost '{}' PHP etkin ancak upstream boş.", vh.entry.name));
            }
            if vh.entry.proxy.enabled && vh.entry.proxy.upstream.trim().is_empty() {
                return Err(format!("vHost '{}' proxy etkin ancak upstream boş.", vh.entry.name));
            }
            if !vh.resolved_doc_root.exists() {
                warnings.push(format!(
                    "vHost '{}' document_root dizini henüz mevcut değil: {}",
                    vh.entry.name,
                    vh.resolved_doc_root.display()
                ));
            }
            if self.listeners.https.enabled && !vh.entry.ssl.certificate.trim().is_empty() {
                let cert_path = resolve_path(base_dir, &vh.entry.ssl.certificate);
                if !cert_path.exists() {
                    warnings.push(format!(
                        "vHost '{}' SSL sertifika dosyası bulunamadı: {}",
                        vh.entry.name,
                        cert_path.display()
                    ));
                }
            }
            if !vh.entry.ssl.key.trim().is_empty() {
                let key_path = resolve_path(base_dir, vh.entry.ssl.key.trim());
                if let Some(warning) = sensitive_file_permission_warning(&key_path, true) {
                    warnings.push(format!("vHost '{}': {}", vh.entry.name, warning));
                }
            }
        }

        for (name, enabled, address, require_token, token) in [
            (
                "admin",
                self.listeners.admin.enabled,
                self.listeners.admin.address.as_str(),
                self.listeners.admin.require_token,
                self.listeners.admin.token.as_str(),
            ),
            (
                "api",
                self.listeners.api.enabled,
                self.listeners.api.address.as_str(),
                self.listeners.api.require_token,
                self.listeners.api.token.as_str(),
            ),
        ] {
            if enabled && !is_loopback_bind(address) && (!require_token || token.trim().is_empty()) {
                warnings.push(format!(
                    "Güvenlik: '{}' dinleyicisi {} adresine bağlanıyor ancak require_token={} ve token {}. Çalışma anında otomatik token üretilse de yapılandırmada açıkça token tanımlanmalıdır.",
                    name,
                    address,
                    require_token,
                    if token.trim().is_empty() { "boş" } else { "dolu" }
                ));
            }
        }

        if modules.len() < 18 {
            warnings.push(format!(
                "Yüklü modül sayısı beklenen 18'den az (bulunan: {}).",
                modules.len()
            ));
        }

        Ok(warnings)
    }
}

/// Duyarlı bir dosyanın dünya tarafından okunabilir/yazılabilir olup olmadığını denetler.
/// Özel anahtarlar için `private = true` kullanılır; bu durumda group/other bitleri
/// uyarı üretir. Diğer dosyalarda yalnızca world-write biti denetlenir.
/// Unix dışı platformlarda anlamlı olmadığından `None` döner.
pub fn sensitive_file_permission_warning(path: &Path, private: bool) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        let (bad, expected, reason) = if private {
            (mode & 0o077 != 0, "0640 root:nobody", "group/other izni açık")
        } else {
            (mode & 0o002 != 0, "0644 veya daha kısıtlı", "world-write izni açık")
        };
        if bad {
            return Some(format!(
                "'{}' izni {:04o}; {} olmalı ({}).",
                path.display(),
                mode,
                expected,
                reason
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, private);
    }
    None
}

fn parse_listener_ip(raw: &str) -> Result<std::net::IpAddr, String> {
    let trimmed = raw.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    if let Ok(sock) = raw.trim().parse::<std::net::SocketAddr>() {
        return Ok(sock.ip());
    }
    Err("IPv4 veya IPv6 adresi bekleniyordu".to_string())
}

/// Tek bir IPv4/IPv6 adresi veya CIDR ağ maskesini doğrular (`IPv4 <= /32`, `IPv6 <= /128`).
pub fn validate_ip_or_cidr(raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Boş IP veya CIDR girişi geçersizdir".to_string());
    }
    if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
        if prefix_part.is_empty() || !prefix_part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!("Geçersiz CIDR öneki: '/{}'", prefix_part));
        }
        let prefix = prefix_part
            .parse::<u8>()
            .map_err(|_| format!("CIDR öneki sayısal sınır dışında: '/{}'", prefix_part))?;
        let ip = ip_part
            .parse::<std::net::IpAddr>()
            .map_err(|_| format!("Geçersiz IP adresi: '{}'", ip_part))?;
        let (family, max_prefix) = match ip {
            std::net::IpAddr::V4(_) => ("IPv4", 32),
            std::net::IpAddr::V6(_) => ("IPv6", 128),
        };
        if prefix > max_prefix {
            return Err(format!(
                "{} adresi için CIDR öneki /{} sınırını aşamaz (verilen: /{})",
                family, max_prefix, prefix
            ));
        }
        Ok(())
    } else {
        trimmed
            .parse::<std::net::IpAddr>()
            .map(|_| ())
            .map_err(|_| format!("Geçersiz IPv4/IPv6 adresi: '{}'", trimmed))
    }
}

fn validate_ip_acl_list(scope: &str, field: &str, items: &[String]) -> Result<(), String> {
    for item in items {
        validate_ip_or_cidr(item)
            .map_err(|e| format!("{} için geçersiz {} öğesi ('{}'): {}", scope, field, item, e))?;
    }
    Ok(())
}

fn ips_overlap(a: std::net::IpAddr, b: std::net::IpAddr) -> bool {
    a == b || a.is_unspecified() || b.is_unspecified()
}

/// Panel dinleyicisinin (`admin` / `api`) TLS sertifika alanlarını ve ters vekil yol önekini doğrular.
fn validate_panel_listener_tls_and_proxy(
    name: &str,
    enabled: bool,
    ssl: bool,
    tls_cert: &str,
    tls_key: &str,
    proxy_prefix: &str,
) -> Result<(), String> {
    if enabled && ssl {
        if tls_cert.trim().is_empty() {
            return Err(format!(
                "Etkin '{}' dinleyicisinde ssl=true iken tls_cert boş olamaz.",
                name
            ));
        }
        if tls_key.trim().is_empty() {
            return Err(format!(
                "Etkin '{}' dinleyicisinde ssl=true iken tls_key boş olamaz.",
                name
            ));
        }
    }
    if !proxy_prefix.is_empty() {
        if !proxy_prefix.starts_with('/') {
            return Err(format!(
                "Dinleyici '{}' için proxy_prefix '/' ile başlamalıdır ('{}').",
                name, proxy_prefix
            ));
        }
        if proxy_prefix.contains("..")
            || proxy_prefix.contains('\\')
            || proxy_prefix.contains('\0')
            || proxy_prefix
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!(
                "Dinleyici '{}' için proxy_prefix geçersiz veya güvensiz karakterler içeriyor ('{}').",
                name, proxy_prefix
            ));
        }
    }
    Ok(())
}

fn parse_env_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Verilen dinleme adresinin yerel loopback arayüzüne (`127.0.0.1`, `::1`, `localhost`) ait olup olmadığını denetler.
pub fn is_loopback_bind(addr: &str) -> bool {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return false;
    }
    if let Ok(sock) = trimmed.parse::<std::net::SocketAddr>() {
        return sock.ip().is_loopback();
    }
    let unbracketed = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let host = match trimmed.split_once(':') {
        Some((h, _)) if !trimmed.starts_with('[') && !trimmed.contains("::") => h,
        _ => unbracketed,
    };
    let lower = host.trim().to_ascii_lowercase();
    lower == "localhost" || lower.ends_with(".localhost")
}

/// Göreceli yolları sunucu kök dizinine çözer.
pub fn resolve_path(base_dir: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Alan adını yol enjeksiyonu (path traversal) ve geçersiz karakterlere karşı doğrular.
pub fn validate_domain(raw: &str) -> Result<String, &'static str> {
    let domain = raw.trim().to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return Err("Alan adı uzunluğu 1 ile 253 karakter arasında olmalıdır");
    }
    if domain.contains("..")
        || domain.contains('/')
        || domain.contains('\\')
        || domain.contains('\0')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err("Geçersiz veya güvensiz alan adı");
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("Geçersiz alan adı etiketi");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("Alan adı etiketi '-' ile başlayamaz veya bitemez");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("Alan adı yalnızca ASCII harf, rakam, nokta ve tire içerebilir");
        }
    }
    Ok(domain)
}

fn is_valid_log_format(raw: &str) -> bool {
    if raw.contains('\0') || raw.contains('\r') || raw.contains('\n') {
        return false;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "combined" | "common" | "json" | "clf" | "main" | "vhost_combined" | "extended"
    ) {
        return true;
    }
    trimmed.contains('%') || trimmed.contains('$')
}

fn is_safe_relative_subpath(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.starts_with('/')
        || trimmed.starts_with('\\')
        || trimmed.contains("..")
    {
        return false;
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return false;
    }
    let path = Path::new(trimmed);
    !path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
}

fn is_safe_error_docs_dir(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('\0') || trimmed.contains("..") {
        return false;
    }
    !Path::new(trimmed)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Sanal konak kaydını temiz TOML belge metnine dönüştürür.
pub fn serialize_vhost_toml(entry: &VHostEntry) -> Result<String, toml::ser::Error> {
    let doc = VHostFileDocument {
        vhost: entry.clone(),
    };
    toml::to_string_pretty(&doc)
}

/// Sanal konak kaydını biçimlendirilmiş JSON metnine serileştirir.
pub fn serialize_vhost_json(entry: &VHostEntry) -> Result<String, serde_json::Error> {
    entry.to_json_pretty()
}

/// JSON metninden sanal konak kaydını ayrıştırır (eksik alanlar varsayılanlarla tamamlanır).
pub fn deserialize_vhost_json(content: &str) -> Result<VHostEntry, serde_json::Error> {
    VHostEntry::parse_json(content)
}

/// `conf/vhosts/*.toml` altındaki tüm sanal konakları deterministik sırada yükler.
pub fn load_vhosts_dir(vhosts_dir: &Path, base_dir: &Path) -> Result<Vec<LoadedVHost>, String> {
    let mut result = Vec::new();
    if !vhosts_dir.exists() {
        return Ok(result);
    }

    let mut entries: Vec<PathBuf> = std::fs::read_dir(vhosts_dir)
        .map_err(|e| format!("vhosts dizini okunamadı ({}): {}", vhosts_dir.display(), e))?
        .filter_map(|res| res.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    entries.sort();

    for path in entries {
        let content = std::fs::read_to_string(&path)
            .map_err(|e| format!("vHost dosyası okunamadı ({}): {}", path.display(), e))?;
        let doc: VHostFileDocument = toml::from_str(&content)
            .map_err(|e| format!("vHost TOML hatası ({}): {}", path.display(), e))?;
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown.toml")
            .to_string();
        let resolved_doc_root = resolve_path(base_dir, &doc.vhost.document_root);
        result.push(LoadedVHost {
            entry: doc.vhost,
            file_name,
            resolved_doc_root,
        });
    }

    Ok(result)
}

/// İstenen Host başlığına en uygun sanal konağı eşleştirir (yoksa None).
pub fn match_vhost<'a>(vhosts: &'a [LoadedVHost], host_header: &str) -> Option<&'a LoadedVHost> {
    let clean_host = host_header
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    if !clean_host.is_empty() {
        // 1. Önce doğrudan alan adı veya alias tam eşleşmesi ara
        if let Some(found) = vhosts.iter().find(|v| {
            v.entry.name.eq_ignore_ascii_case(&clean_host)
                || v.entry
                    .aliases
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&clean_host))
        }) {
            return Some(found);
        }

        // 2. Tam eşleşme yoksa catch-all (_ veya *) vHost ara
        if let Some(catch_all) = vhosts.iter().find(|v| {
            v.entry.name == "_"
                || v.entry.name == "*"
                || v.entry.aliases.iter().any(|a| a == "_" || a == "*")
        }) {
            return Some(catch_all);
        }

        // [kart-12-a] Tanımlı host başlığı hiçbir vHost veya catch-all kaydı ile eşleşmiyorsa,
        // başka sitelerin içeriğini sızdırmamak için güvenli olarak None döner.
        return None;
    }

    vhosts
        .iter()
        .find(|v| v.entry.name.eq_ignore_ascii_case("localhost"))
        .or_else(|| vhosts.first())
}

/// `modules/mod_*.toml` dosyalarının `[module]` meta başlığı.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ModuleMeta {
    pub name: String,
    pub version: String,
    pub category: String,
    pub enabled: bool,
}

/// Bir modül TOML dosyasının tam serileştirme/ayrıştırma şeması.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ModuleFileDocument {
    pub module: ModuleMeta,
    #[serde(default, skip_serializing_if = "toml::map::Map::is_empty")]
    pub settings: toml::map::Map<String, toml::Value>,
    #[serde(default, skip_serializing_if = "toml::map::Map::is_empty")]
    pub connection: toml::map::Map<String, toml::Value>,
    #[serde(default, skip_serializing_if = "toml::map::Map::is_empty")]
    pub features: toml::map::Map<String, toml::Value>,
    #[serde(flatten)]
    pub extra: toml::map::Map<String, toml::Value>,
}

/// Bellekte tutulan tek bir modül kaydı (`mod_proxy`, `mod_redis`, `mod_headers` vb.).
#[derive(Debug, Clone)]
pub struct ModuleConfigEntry {
    pub meta: ModuleMeta,
    pub settings: toml::map::Map<String, toml::Value>,
    pub connection: toml::map::Map<String, toml::Value>,
    pub features: toml::map::Map<String, toml::Value>,
    pub extra: toml::map::Map<String, toml::Value>,
    pub file_name: String,
    pub file_path: PathBuf,
}

impl ModuleConfigEntry {
    pub fn name(&self) -> &str {
        &self.meta.name
    }

    pub fn is_enabled(&self) -> bool {
        self.meta.enabled
    }

    /// Belirtilen anahtarı `[settings]`, `[connection]` veya `[features]` içinde arar.
    pub fn get(&self, key: &str) -> Option<&toml::Value> {
        self.settings
            .get(key)
            .or_else(|| self.connection.get(key))
            .or_else(|| self.features.get(key))
    }

    /// Belirli bir bölüm (`settings`, `connection`, `features` veya ek tablo) içinden değer okur.
    pub fn get_section_value(&self, section: &str, key: &str) -> Option<&toml::Value> {
        match section {
            "settings" => self.settings.get(key),
            "connection" => self.connection.get(key),
            "features" => self.features.get(key),
            other => self.extra.get(other).and_then(|v| v.as_table()).and_then(|t| t.get(key)),
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_integer())
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        self.get_i64(key).and_then(|n| u64::try_from(n).ok())
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_string_list(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect()
        })
    }

    pub fn get_i64_list(&self, key: &str) -> Option<Vec<i64>> {
        self.get(key).and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_integer())
                .collect()
        })
    }

    /// Tüm yapılandırma anahtarlarını birleşik bir tablo olarak döner.
    pub fn all_settings(&self) -> toml::map::Map<String, toml::Value> {
        let mut merged = toml::map::Map::new();
        for (k, v) in &self.connection {
            merged.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.features {
            merged.insert(k.clone(), v.clone());
        }
        for (k, v) in &self.settings {
            merged.insert(k.clone(), v.clone());
        }
        merged
    }

    fn to_document(&self) -> ModuleFileDocument {
        ModuleFileDocument {
            module: self.meta.clone(),
            settings: self.settings.clone(),
            connection: self.connection.clone(),
            features: self.features.clone(),
            extra: self.extra.clone(),
        }
    }
}

/// `modules/mod_*.toml` altındaki tüm modülleri tutan ve WebAdmin için disk güncellemesi sunan yönetici.
#[derive(Debug, Clone, Default)]
pub struct LoadedModules {
    pub modules_dir: PathBuf,
    pub entries: Vec<ModuleConfigEntry>,
}

impl LoadedModules {
    /// Belirtilen dizindeki tüm `.toml` modül dosyalarını deterministik sırada yükler.
    pub fn load_from_dir(modules_dir: &Path) -> Result<Self, String> {
        let mut entries = Vec::new();
        if !modules_dir.exists() {
            return Ok(Self {
                modules_dir: modules_dir.to_path_buf(),
                entries,
            });
        }

        let mut paths: Vec<PathBuf> = std::fs::read_dir(modules_dir)
            .map_err(|e| format!("Modül dizini okunamadı ({}): {}", modules_dir.display(), e))?
            .filter_map(|res| res.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
            .collect();
        paths.sort();

        for path in paths {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| format!("Modül dosyası okunamadı ({}): {}", path.display(), e))?;
            let mut doc: ModuleFileDocument = toml::from_str(&content)
                .map_err(|e| format!("Modül TOML hatası ({}): {}", path.display(), e))?;
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown.toml")
                .to_string();
            if doc.module.name.trim().is_empty() {
                doc.module.name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
            }
            entries.push(ModuleConfigEntry {
                meta: doc.module,
                settings: doc.settings,
                connection: doc.connection,
                features: doc.features,
                extra: doc.extra,
                file_name,
                file_path: path,
            });
        }

        Ok(Self {
            modules_dir: modules_dir.to_path_buf(),
            entries,
        })
    }

    /// Diskten tüm modülleri yeniden yükler ve yüklenen modül sayısını döner.
    pub fn reload(&mut self) -> Result<usize, String> {
        let reloaded = Self::load_from_dir(&self.modules_dir)?;
        let count = reloaded.entries.len();
        self.entries = reloaded.entries;
        Ok(count)
    }

    pub fn list(&self) -> &[ModuleConfigEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn matches_name(entry: &ModuleConfigEntry, query: &str) -> bool {
        let q = query.trim();
        if entry.meta.name.eq_ignore_ascii_case(q) {
            return true;
        }
        let stem = entry
            .file_name
            .strip_suffix(".toml")
            .unwrap_or(&entry.file_name);
        stem.eq_ignore_ascii_case(q)
    }

    pub fn get(&self, name: &str) -> Option<&ModuleConfigEntry> {
        self.entries.iter().find(|e| Self::matches_name(e, name))
    }

    pub fn get_mut(&mut self, name: &str) -> Option<&mut ModuleConfigEntry> {
        self.entries.iter_mut().find(|e| Self::matches_name(e, name))
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        self.get(name).map(|e| e.meta.enabled).unwrap_or(false)
    }

    /// Belirtilen modülün `enabled` durumunu atomik olarak diskte ve bellekte günceller.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> Result<(), String> {
        let idx = self
            .entries
            .iter()
            .position(|e| Self::matches_name(e, name))
            .ok_or_else(|| format!("Modül bulunamadı: {}", name))?;

        let entry = &self.entries[idx];
        let path = &entry.file_path;

        let updated_toml = match std::fs::read_to_string(path) {
            Ok(existing) => patch_module_enabled_toml(&existing, enabled)
                .filter(|patched| {
                    toml::from_str::<ModuleFileDocument>(patched)
                        .map(|d| d.module.enabled == enabled)
                        .unwrap_or(false)
                })
                .unwrap_or_else(|| {
                    let mut doc = entry.to_document();
                    doc.module.enabled = enabled;
                    toml::to_string_pretty(&doc).unwrap_or_default()
                }),
            Err(_) => {
                let mut doc = entry.to_document();
                doc.module.enabled = enabled;
                toml::to_string_pretty(&doc)
                    .map_err(|e| format!("Modül TOML serileştirme hatası: {}", e))?
            }
        };

        write_file_atomic(path, updated_toml.as_bytes())?;
        self.entries[idx].meta.enabled = enabled;
        Ok(())
    }

    /// Belirtilen modülün `enabled` durumunu tersine çevirir ve yeni durumu döner.
    pub fn toggle_enabled(&mut self, name: &str) -> Result<bool, String> {
        let current = self
            .get(name)
            .map(|e| e.meta.enabled)
            .ok_or_else(|| format!("Modül bulunamadı: {}", name))?;
        let next = !current;
        self.set_enabled(name, next)?;
        Ok(next)
    }
}

/// `modules/` dizinindeki tüm modül yapılandırmalarını yükler.
pub fn load_modules_dir(modules_dir: &Path) -> Result<LoadedModules, String> {
    LoadedModules::load_from_dir(modules_dir)
}

fn patch_module_enabled_toml(content: &str, enabled: bool) -> Option<String> {
    let line_ending = if content.contains("\r\n") { "\r\n" } else { "\n" };
    let mut lines: Vec<String> = content.split('\n').map(|l| l.trim_end_matches('\r').to_string()).collect();
    let had_trailing_newline = content.ends_with('\n');
    if had_trailing_newline && lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }

    let mut in_module = false;
    let mut module_header_idx: Option<usize> = None;
    let mut replaced = false;

    for (i, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim().trim_start_matches('\u{feff}');
        let clean_header = trimmed.split('#').next().unwrap_or("").trim();
        if clean_header.starts_with('[') && clean_header.ends_with(']') {
            in_module = clean_header == "[module]";
            if in_module && module_header_idx.is_none() {
                module_header_idx = Some(i);
            }
            continue;
        }
        if in_module {
            let no_comment = trimmed.split('#').next().unwrap_or("").trim();
            if let Some(rest) = no_comment.strip_prefix("enabled") {
                if rest.trim_start().starts_with('=') {
                    let comment_suffix = line
                        .find('#')
                        .map(|idx| format!(" {}", &line[idx..]))
                        .unwrap_or_default();
                    *line = format!("enabled = {}{}", enabled, comment_suffix);
                    replaced = true;
                    break;
                }
            }
        }
    }

    if !replaced {
        let header_idx = module_header_idx?;
        lines.insert(header_idx + 1, format!("enabled = {}", enabled));
    }

    let mut out = lines.join(line_ending);
    if had_trailing_newline {
        out.push_str(line_ending);
    }
    Some(out)
}

static ATOMIC_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn write_file_atomic(target: &Path, data: &[u8]) -> Result<(), String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("Geçersiz hedef dosya yolu: {}", target.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("Dizin oluşturulamadı ({}): {}", parent.display(), e))?;
    let fname = target
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("module.toml");
    let seq = ATOMIC_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = parent.join(format!(".{}.{}.{}.tmp", fname, std::process::id(), seq));
    std::fs::write(&tmp, data)
        .map_err(|e| format!("Geçici modül dosyası yazılamadı ({}): {}", tmp.display(), e))?;
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Modül dosyası güncellenemedi ({}): {}", target.display(), e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ports_never_collide_with_known_panels() {
        let zmax_ports = [
            DEFAULT_HTTP_PORT,
            DEFAULT_HTTPS_PORT,
            DEFAULT_ADMIN_PORT,
            DEFAULT_API_PORT,
        ];
        for p in zmax_ports {
            assert!(
                !KNOWN_PANEL_PORTS.contains(&p),
                "ZMax portu ({}) bilinen bir panel portu ile çakışıyor!",
                p
            );
            assert!(p < 32768, "ZMax portu ({}) Linux ephemeral aralığa girmemeli!", p);
        }
    }

    #[test]
    fn test_parse_real_zmax_toml_schema() {
        let sample = r#"
[server]
server_name = "ZMax"
workers = 4

[listeners.http]
address = "0.0.0.0"
port = 19480

[listeners.https]
address = "0.0.0.0"
port = 19483
ssl = true

[listeners.admin]
address = "127.0.0.1"
port = 19485
document_root = "admin"

[listeners.api]
enabled = true
address = "127.0.0.1"
port = 19486

[cache]
memory_cache_mb = 512
default_ttl_seconds = 600

[vhosts_dir]
path = "conf/vhosts"
"#;
        let cfg = ZMaxConfig::parse_toml(sample).expect("Gerçek zmax.toml ayrıştırılmalı");
        assert_eq!(cfg.server.workers, 4);
        assert_eq!(cfg.listeners.http.port, 19480);
        assert_eq!(cfg.listeners.https.port, 19483);
        assert_eq!(cfg.listeners.admin.port, 19485);
        assert_eq!(cfg.listeners.api.port, 19486);
        assert_eq!(cfg.cache.memory_cache_mb, 512);
        assert_eq!(cfg.vhosts_dir.path, "conf/vhosts");
    }

    #[test]
    fn test_validate_domain_security() {
        assert_eq!(validate_domain("Example.COM").unwrap(), "example.com");
        assert_eq!(validate_domain("sub.site-1.org").unwrap(), "sub.site-1.org");
        assert!(validate_domain("../etc/passwd").is_err());
        assert!(validate_domain("foo/bar.com").is_err());
        assert!(validate_domain("").is_err());
        assert!(validate_domain("-bad.com").is_err());
    }

    #[test]
    fn test_security_and_listener_defaults_backward_compat() {
        let cfg = ZMaxConfig::default();
        assert_eq!(cfg.security.max_body_size_mb, 64);
        assert_eq!(cfg.security.max_header_size_kb, 64);
        assert!(!cfg.listeners.http.reuse_port);
        assert!(!cfg.listeners.admin.require_token);
        assert!(cfg.listeners.admin.token.is_empty());

        let legacy_toml = r#"
[listeners.http]
address = "0.0.0.0"
port = 19480
reuse_port = true

[security]
rate_limit_enabled = true
"#;
        let parsed = ZMaxConfig::parse_toml(legacy_toml).unwrap();
        assert!(parsed.listeners.http.reuse_port);
        assert_eq!(parsed.security.max_body_size_mb, 64);
        assert_eq!(parsed.security.max_header_size_kb, 64);
        assert!(!parsed.listeners.admin.require_token);
        assert!(parsed.listeners.admin.token.is_empty());
    }

    #[test]
    fn test_vhost_backward_compat_and_new_sections() {
        let legacy_localhost = r#"
[vhost]
name = "localhost"
aliases = ["127.0.0.1", "::1"]
document_root = "www/html"
index_files = ["index.html", "index.htm", "index.php"]

[vhost.cache]
enabled = true
expire = 300

[vhost.php]
enabled = true
sapi = "fastcgi"
upstream = "127.0.0.1:9000"
timeout = 60

[vhost.security]
hotlink_protection = false
force_https = false
"#;
        let doc: VHostFileDocument = toml::from_str(legacy_localhost).unwrap();
        assert!(doc.vhost.rewrite.enabled);
        assert!(doc.vhost.rewrite.try_files);
        assert!(doc.vhost.rewrite.htaccess);
        assert!(!doc.vhost.proxy.enabled);
        assert_eq!(doc.vhost.proxy.path_prefix, "/");
        assert!(doc.vhost.proxy.preserve_host);
        assert!(doc.vhost.proxy.websocket);
        assert!(doc.vhost.headers.security_headers);
        assert!(!doc.vhost.headers.hsts);

        let extended = r#"
[vhost]
name = "app.example.com"
document_root = "www/app"

[vhost.rewrite]
enabled = true
try_files = false
htaccess = false

[vhost.proxy]
enabled = true
upstream = "127.0.0.1:3000"
path_prefix = "/api"
preserve_host = false
websocket = true

[vhost.headers]
security_headers = true
hsts = true
"#;
        let ext_doc: VHostFileDocument = toml::from_str(extended).unwrap();
        assert!(ext_doc.vhost.rewrite.enabled);
        assert!(!ext_doc.vhost.rewrite.try_files);
        assert!(!ext_doc.vhost.rewrite.htaccess);
        assert!(ext_doc.vhost.proxy.enabled);
        assert_eq!(ext_doc.vhost.proxy.upstream, "127.0.0.1:3000");
        assert_eq!(ext_doc.vhost.proxy.path_prefix, "/api");
        assert!(!ext_doc.vhost.proxy.preserve_host);
        assert!(ext_doc.vhost.proxy.websocket);
        assert!(ext_doc.vhost.headers.security_headers);
        assert!(ext_doc.vhost.headers.hsts);

        let serialized = serialize_vhost_toml(&ext_doc.vhost).unwrap();
        let roundtrip: VHostFileDocument = toml::from_str(&serialized).unwrap();
        assert_eq!(roundtrip.vhost.proxy.upstream, "127.0.0.1:3000");
        assert!(roundtrip.vhost.headers.hsts);
    }

    #[test]
    fn test_is_loopback_bind() {
        assert!(is_loopback_bind("127.0.0.1"));
        assert!(is_loopback_bind("127.0.0.1:19485"));
        assert!(is_loopback_bind("127.0.1.1"));
        assert!(is_loopback_bind("::1"));
        assert!(is_loopback_bind("[::1]"));
        assert!(is_loopback_bind("[::1]:19485"));
        assert!(is_loopback_bind("localhost"));
        assert!(is_loopback_bind("LOCALHOST:8080"));
        assert!(is_loopback_bind("admin.localhost"));

        assert!(!is_loopback_bind("0.0.0.0"));
        assert!(!is_loopback_bind("0.0.0.0:19480"));
        assert!(!is_loopback_bind("::"));
        assert!(!is_loopback_bind("[::]:19480"));
        assert!(!is_loopback_bind("192.168.1.10"));
        assert!(!is_loopback_bind("example.com"));
        assert!(!is_loopback_bind(""));
    }

    static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_env_overrides_admin_token_and_body_limit() {
        let _guard = ENV_TEST_LOCK.lock().unwrap();
        std::env::set_var("ZMAX_ADMIN_TOKEN", "adm-secret-99");
        std::env::set_var("ZMAX_ADMIN_REQUIRE_TOKEN", "true");
        std::env::set_var("ZMAX_MAX_BODY_MB", "256");

        let mut cfg = ZMaxConfig::default();
        cfg.apply_env_overrides();
        assert_eq!(cfg.listeners.admin.token, "adm-secret-99");
        assert!(cfg.listeners.admin.require_token);
        assert_eq!(cfg.security.max_body_size_mb, 256);

        std::env::set_var("ZMAX_ADMIN_REQUIRE_TOKEN", "false");
        cfg.apply_env_overrides();
        assert!(!cfg.listeners.admin.require_token);

        std::env::remove_var("ZMAX_ADMIN_TOKEN");
        std::env::remove_var("ZMAX_ADMIN_REQUIRE_TOKEN");
        std::env::remove_var("ZMAX_MAX_BODY_MB");
    }

    #[test]
    fn test_modules_loader_and_disk_toggle() {
        let dir = std::env::temp_dir().join(format!("zmax_cfg_mods_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(
            dir.join("mod_proxy.toml"),
            r#"# Ters Proxy
[module]
name = "mod_proxy"
version = "1.0.0"
category = "Ağ & Yönlendirme"
enabled = true

[settings]
preserve_host = true
websocket_upgrade = true
max_body_size_mb = 128
"#,
        )
        .unwrap();

        std::fs::write(
            dir.join("mod_redis.toml"),
            r#"# Redis
[module]
name = "mod_redis"
version = "1.0.0"
category = "Performans"
enabled = true

[connection]
host = "127.0.0.1"
port = 6379

[features]
banned_ip_sync = true
pubsub_channel = "zmax:cache:purge"
"#,
        )
        .unwrap();

        std::fs::write(
            dir.join("mod_rewrite.toml"),
            r#"[module]
name = "mod_rewrite"
version = "1.0.0"
enabled = false

[settings]
enable_htaccess = true
"#,
        )
        .unwrap();

        let mut mods = load_modules_dir(&dir).unwrap();
        assert_eq!(mods.len(), 3);
        assert!(mods.is_enabled("mod_proxy"));
        assert!(!mods.is_enabled("mod_rewrite"));

        let proxy = mods.get("mod_proxy").unwrap();
        assert_eq!(proxy.get_bool("preserve_host"), Some(true));
        assert_eq!(proxy.get_u64("max_body_size_mb"), Some(128));

        let redis = mods.get("mod_redis").unwrap();
        assert_eq!(redis.get_str("host"), Some("127.0.0.1"));
        assert_eq!(redis.get_u64("port"), Some(6379));
        assert_eq!(redis.get_bool("banned_ip_sync"), Some(true));
        assert_eq!(redis.get_str("pubsub_channel"), Some("zmax:cache:purge"));

        // Disk üzerinde toggle ve yorum koruma doğrulaması
        let new_state = mods.toggle_enabled("mod_proxy").unwrap();
        assert!(!new_state);
        assert!(!mods.is_enabled("mod_proxy"));

        let disk_text = std::fs::read_to_string(dir.join("mod_proxy.toml")).unwrap();
        assert!(disk_text.contains("# Ters Proxy"));
        assert!(disk_text.contains("enabled = false"));

        let reloaded = load_modules_dir(&dir).unwrap();
        assert!(!reloaded.is_enabled("mod_proxy"));
        assert!(reloaded.get("mod_proxy").unwrap().get_bool("websocket_upgrade") == Some(true));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_real_workspace_modules_dir() {
        let workspace_modules = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("modules");
        assert!(workspace_modules.is_dir(), "modules dizini bulunamadı");
        let mods = load_modules_dir(&workspace_modules).unwrap();
        assert_eq!(mods.len(), 18, "Tüm 18 yerleşik modül yüklenmeli, bulunan: {}", mods.len());
        for expected in [
            "mod_acme",
            "mod_autoindex",
            "mod_brotli",
            "mod_cache",
            "mod_coreruleset",
            "mod_fastcgi",
            "mod_geoip",
            "mod_gzip",
            "mod_headers",
            "mod_pagespeed",
            "mod_proxy",
            "mod_quic",
            "mod_realip",
            "mod_redis",
            "mod_rewrite",
            "mod_security",
            "mod_ssl",
            "mod_static",
        ] {
            let entry = mods.get(expected).unwrap_or_else(|| panic!("Eksik modül: {}", expected));
            assert_eq!(entry.meta.name, expected);
        }
        let realip = mods.get("mod_realip").unwrap();
        assert!(realip
            .get_string_list("trusted_proxies")
            .is_some_and(|v| !v.is_empty()));
        let brotli = mods.get("mod_brotli").unwrap();
        assert_eq!(brotli.get_u64("compression_level"), Some(6));
    }

    #[test]
    fn test_real_workspace_conf_vhosts_and_validation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let conf_path = root.join("conf").join("zmax.toml");
        assert!(conf_path.is_file(), "conf/zmax.toml bulunamadı");

        let cfg = ZMaxConfig::load_or_default(&conf_path).unwrap();
        assert!(!cfg.listeners.http.reuse_port);
        assert_eq!(cfg.security.max_body_size_mb, 64);
        assert_eq!(cfg.security.max_header_size_kb, 64);

        let vhosts = load_vhosts_dir(&resolve_path(root, &cfg.vhosts_dir.path), root).unwrap();
        assert!(vhosts.iter().any(|v| v.entry.name == "localhost"));
        assert!(vhosts.iter().any(|v| v.entry.name == "example.com"));

        let mods = load_modules_dir(&root.join("modules")).unwrap();
        let warnings = cfg
            .validate_workspace_layout(root, &vhosts, &mods)
            .expect("Gerçek çalışma alanı yapılandırması geçerli olmalı");
        assert!(warnings.iter().all(|w| !w.contains("modül sayısı")));

        let mut dup_port = cfg.clone();
        dup_port.listeners.admin.port = dup_port.listeners.http.port;
        assert!(dup_port.validate().is_err(), "Aynı soketteki port çakışması reddedilmeli");

        let mut zero_body = cfg.clone();
        zero_body.security.max_body_size_mb = 0;
        assert!(zero_body.validate().is_err(), "max_body_size_mb=0 reddedilmeli");

        let mut bad_level = cfg;
        bad_level.logging.log_level = "verbose_invalid".to_string();
        assert!(bad_level.validate().is_err(), "Geçersiz log_level reddedilmeli");
    }

    #[test]
    fn test_panel_listener_tls_and_proxy_backward_compat() {
        let legacy_toml = r#"
[listeners.admin]
enabled = true
address = "127.0.0.1"
port = 19485
document_root = "admin"

[listeners.api]
enabled = true
address = "127.0.0.1"
port = 19486
cors_allow_origin = "https://panel.example.com"
"#;
        let cfg = ZMaxConfig::parse_toml(legacy_toml)
            .expect("Panel TLS ve proxy alanları olmadan eski zmax.toml ayrıştırılmalı");
        assert!(!cfg.listeners.admin.ssl);
        assert!(cfg.listeners.admin.tls_cert.is_empty());
        assert!(cfg.listeners.admin.tls_key.is_empty());
        assert!(cfg.listeners.admin.proxy_prefix.is_empty());
        assert!(cfg.listeners.admin.trusted_proxies.is_empty());

        assert!(!cfg.listeners.api.ssl);
        assert!(cfg.listeners.api.tls_cert.is_empty());
        assert!(cfg.listeners.api.tls_key.is_empty());
        assert!(cfg.listeners.api.proxy_prefix.is_empty());
        assert!(cfg.listeners.api.trusted_proxies.is_empty());

        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_secure_listener_defaults_and_cors_validation() {
        let def = ZMaxConfig::default();
        assert!(def.listeners.https.strict_sni);
        assert!(def.listeners.api.cors_allow_origin.is_empty());

        // TOML'da alan yazılmasa bile strict_sni güvenli varsayılana düşmeli.
        let omitted = ZMaxConfig::parse_toml(
            "[listeners.https]\nenabled = true\naddress = \"127.0.0.1\"\nport = 8443\n",
        )
        .expect("TOML ayrıştırılmalı");
        assert!(
            omitted.listeners.https.strict_sni,
            "eksik strict_sni alanı güvenli varsayılana düşmeli"
        );

        // Wildcard CORS reddedilmeli.
        let wildcard = ZMaxConfig::parse_toml(
            "[listeners.api]\nenabled = true\naddress = \"127.0.0.1\"\nport = 19486\ncors_allow_origin = \"*\"\n",
        )
        .expect("TOML ayrıştırılmalı");
        let err = wildcard.validate().expect_err("wildcard CORS reddedilmeli");
        assert!(err.contains("cors_allow_origin"), "{err}");

        // Boş origin güvenli: CORS kapalı.
        let off = ZMaxConfig::parse_toml(
            "[listeners.api]\nenabled = true\naddress = \"127.0.0.1\"\nport = 19486\n",
        )
        .expect("TOML ayrıştırılmalı");
        assert!(off.listeners.api.cors_allow_origin.is_empty());
        assert!(off.validate().is_ok());

        // Açıkça kapatılan strict SNI reddedilmeli.
        let insecure_tls = ZMaxConfig::parse_toml(
            "[listeners.https]\nenabled = true\naddress = \"127.0.0.1\"\nport = 8443\nssl = true\nstrict_sni = false\n",
        )
        .expect("TOML ayrıştırılmalı");
        let err = insecure_tls
            .validate()
            .expect_err("strict_sni=false reddedilmeli");
        assert!(err.contains("strict_sni"), "{err}");
    }

    #[test]
    fn test_panel_listener_tls_and_proxy_parse_and_validation() {
        let toml = r#"
[listeners.admin]
enabled = true
address = "127.0.0.1"
port = 19485
ssl = true
tls_cert = "certs/admin.pem"
tls_key = "certs/admin.key"
proxy_prefix = "/panel"
trusted_proxies = ["127.0.0.1", "::1"]

[listeners.api]
enabled = true
address = "127.0.0.1"
port = 19486
proxy_prefix = "/v1/zmax"
trusted_proxies = ["127.0.0.1"]
"#;
        let cfg = ZMaxConfig::parse_toml(toml)
            .expect("Panel TLS ve proxy alanları içeren yapılandırma ayrıştırılmalı");
        assert!(cfg.listeners.admin.ssl);
        assert_eq!(cfg.listeners.admin.tls_cert, "certs/admin.pem");
        assert_eq!(cfg.listeners.admin.tls_key, "certs/admin.key");
        assert_eq!(cfg.listeners.admin.proxy_prefix, "/panel");
        assert_eq!(
            cfg.listeners.admin.trusted_proxies,
            vec!["127.0.0.1".to_string(), "::1".to_string()]
        );

        assert!(!cfg.listeners.api.ssl);
        assert_eq!(cfg.listeners.api.proxy_prefix, "/v1/zmax");
        assert_eq!(
            cfg.listeners.api.trusted_proxies,
            vec!["127.0.0.1".to_string()]
        );
        assert!(cfg.validate().is_ok());

        let mut empty_cert = cfg.clone();
        empty_cert.listeners.admin.tls_cert = "   ".to_string();
        assert!(
            empty_cert.validate().is_err(),
            "admin.ssl=true iken boş tls_cert reddedilmeli"
        );

        let mut empty_key = cfg.clone();
        empty_key.listeners.admin.tls_key.clear();
        assert!(
            empty_key.validate().is_err(),
            "admin.ssl=true iken boş tls_key reddedilmeli"
        );

        for invalid_prefix in ["no-slash", "/v1/../secret", "/v1\\bad", "/v1 bad"] {
            let mut bad_prefix = cfg.clone();
            bad_prefix.listeners.api.proxy_prefix = invalid_prefix.to_string();
            assert!(
                bad_prefix.validate().is_err(),
                "Geçersiz proxy_prefix '{}' reddedilmeli",
                invalid_prefix
            );
        }

        let mut disabled_admin = cfg;
        disabled_admin.listeners.admin.enabled = false;
        disabled_admin.listeners.admin.tls_cert.clear();
        disabled_admin.listeners.admin.tls_key.clear();
        assert!(
            disabled_admin.validate().is_ok(),
            "Devre dışı dinleyicide boş TLS yolları engel oluşturmamalı"
        );
    }

    #[test]
    fn test_panel_listener_tls_workspace_layout_requires_existing_files() {
        let dir = std::env::temp_dir().join(format!("zmax_cfg_panel_tls_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let cert_rel = "admin.pem";
        let key_rel = "admin.key";

        let mut cfg = ZMaxConfig::default();
        cfg.listeners.admin.ssl = true;
        cfg.listeners.admin.tls_cert = cert_rel.to_string();
        cfg.listeners.admin.tls_key = key_rel.to_string();

        let mods = LoadedModules::default();
        assert!(
            cfg.validate_workspace_layout(&dir, &[], &mods).is_err(),
            "Eksik sertifika dosyası ile validate_workspace_layout hata dönmeli"
        );

        std::fs::write(dir.join(cert_rel), "dummy-cert").unwrap();
        assert!(
            cfg.validate_workspace_layout(&dir, &[], &mods).is_err(),
            "Eksik özel anahtar dosyası ile validate_workspace_layout hata dönmeli"
        );

        std::fs::write(dir.join(key_rel), "dummy-key").unwrap();
        assert!(
            cfg.validate_workspace_layout(&dir, &[], &mods).is_ok(),
            "Sertifika ve anahtar dosyaları mevcutken validate_workspace_layout geçmeli"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_ip_acl_log_size_and_stale_ttl_backward_compat() {
        let def = ZMaxConfig::default();
        assert!(def.security.allow_ips.is_empty());
        assert!(def.security.deny_ips.is_empty());
        assert_eq!(def.logging.max_log_size_mb, 100);
        assert_eq!(def.cache.stale_while_revalidate_sec, 30);

        let legacy = r#"
[cache]
enabled = true

[security]
rate_limit_enabled = true

[logging]
log_level = "info"
"#;
        let parsed = ZMaxConfig::parse_toml(legacy).unwrap();
        assert!(parsed.security.allow_ips.is_empty());
        assert!(parsed.security.deny_ips.is_empty());
        assert_eq!(parsed.logging.max_log_size_mb, 100);
        assert_eq!(parsed.cache.stale_while_revalidate_sec, 30);
        assert!(parsed.validate().is_ok());

        let extended = r#"
[cache]
stale_while_revalidate_sec = 45

[security]
allow_ips = ["10.0.0.0/8", "2001:db8::/32"]
deny_ips = ["192.168.1.50", "::1"]

[logging]
max_log_size_mb = 250
"#;
        let ext = ZMaxConfig::parse_toml(extended).unwrap();
        assert_eq!(ext.cache.stale_while_revalidate_sec, 45);
        assert_eq!(ext.logging.max_log_size_mb, 250);
        assert_eq!(ext.security.allow_ips, vec!["10.0.0.0/8", "2001:db8::/32"]);
        assert_eq!(ext.security.deny_ips, vec!["192.168.1.50", "::1"]);
        assert!(ext.validate().is_ok());

        let vhost_legacy = r#"
[vhost]
name = "legacy.example.com"
document_root = "www/legacy"

[vhost.security]
force_https = true
"#;
        let v_legacy: VHostFileDocument = toml::from_str(vhost_legacy).unwrap();
        assert!(v_legacy.vhost.security.allow_ips.is_empty());
        assert!(v_legacy.vhost.security.deny_ips.is_empty());

        let vhost_ext = r#"
[vhost]
name = "acl.example.com"
document_root = "www/acl"

[vhost.security]
hotlink_protection = true
allow_ips = ["192.168.10.0/24", "::1"]
deny_ips = ["203.0.113.5"]
"#;
        let v_ext: VHostFileDocument = toml::from_str(vhost_ext).unwrap();
        assert_eq!(
            v_ext.vhost.security.allow_ips,
            vec!["192.168.10.0/24", "::1"]
        );
        assert_eq!(v_ext.vhost.security.deny_ips, vec!["203.0.113.5"]);

        let serialized = serialize_vhost_toml(&v_ext.vhost).unwrap();
        let roundtrip: VHostFileDocument = toml::from_str(&serialized).unwrap();
        assert_eq!(roundtrip.vhost.security.allow_ips, v_ext.vhost.security.allow_ips);
        assert_eq!(roundtrip.vhost.security.deny_ips, v_ext.vhost.security.deny_ips);
    }

    #[test]
    fn test_ip_acl_cidr_validation_global_and_vhost() {
        let mut cfg = ZMaxConfig::default();
        cfg.security.allow_ips = vec![
            "127.0.0.1".to_string(),
            "10.0.0.0/8".to_string(),
            "192.168.1.1/32".to_string(),
            "0.0.0.0/0".to_string(),
            "::1".to_string(),
            "2001:db8::/32".to_string(),
            "::1/128".to_string(),
            "::/0".to_string(),
        ];
        cfg.security.deny_ips = vec!["198.51.100.0/24".to_string()];
        assert!(cfg.validate().is_ok());

        for bad in [
            "not-an-ip",
            "",
            "192.168.1.0/33",
            "::1/129",
            "10.0.0.1/+24",
            "10.0.0.1/-1",
            "10.0.0.1/abc",
            "10.0.0.1/8/16",
            "10.0.0.1 /24",
        ] {
            let mut bad_allow = ZMaxConfig::default();
            bad_allow.security.allow_ips = vec![bad.to_string()];
            assert!(
                bad_allow.validate().is_err(),
                "Geçersiz allow_ips girişi reddedilmeli: '{}'",
                bad
            );

            let mut bad_deny = ZMaxConfig::default();
            bad_deny.security.deny_ips = vec![bad.to_string()];
            assert!(
                bad_deny.validate().is_err(),
                "Geçersiz deny_ips girişi reddedilmeli: '{}'",
                bad
            );
        }

        let dir = std::env::temp_dir().join(format!("zmax_cfg_ip_acl_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mods = LoadedModules::default();

        let vh_entry = VHostEntry {
            name: "acl.test".to_string(),
            security: VHostSecuritySection {
                allow_ips: vec!["10.20.0.0/16".to_string()],
                deny_ips: vec!["192.0.2.99".to_string()],
                ..VHostSecuritySection::default()
            },
            ..VHostEntry::default()
        };
        let vh_valid = LoadedVHost {
            entry: vh_entry,
            file_name: "acl.test.toml".to_string(),
            resolved_doc_root: dir.join("www"),
        };
        assert!(
            ZMaxConfig::default()
                .validate_workspace_layout(&dir, std::slice::from_ref(&vh_valid), &mods)
                .is_ok()
        );

        let mut vh_bad_allow = vh_valid.clone();
        vh_bad_allow.entry.security.allow_ips = vec!["10.0.0.0/33".to_string()];
        assert!(
            ZMaxConfig::default()
                .validate_workspace_layout(&dir, &[vh_bad_allow], &mods)
                .is_err(),
            "Geçersiz vHost allow_ips reddedilmeli"
        );

        let mut vh_bad_deny = vh_valid;
        vh_bad_deny.entry.security.deny_ips = vec!["::1/129".to_string()];
        assert!(
            ZMaxConfig::default()
                .validate_workspace_layout(&dir, &[vh_bad_deny], &mods)
                .is_err(),
            "Geçersiz vHost deny_ips reddedilmeli"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_new_global_listener_and_logging_defaults_and_roundtrip() {
        let def = ZMaxConfig::default();
        assert_eq!(def.server.user, "nobody");
        assert_eq!(def.server.group, "nobody");
        assert!(def.server.cpu_affinity);
        assert!(def.server.reuseport_workers);
        assert_eq!(def.server.graceful_shutdown_secs, 15);
        assert!(!def.listeners.http.proxy_protocol);
        assert_eq!(def.listeners.https.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert!(!def.listeners.https.proxy_protocol);
        assert!(def.listeners.https.strict_sni);
        assert_eq!(def.logging.batch_flush_ms, 250);
        assert_eq!(def.logging.batch_buffer_kb, 64);
        assert!(def.logging.add_request_id);

        let toml_input = r#"
[server]
user = "www-data"
group = "www-data"
cpu_affinity = false
reuseport_workers = false
graceful_shutdown_secs = 30

[listeners.http]
proxy_protocol = true

[listeners.https]
enabled = true
alpn = ["h2"]
proxy_protocol = true
strict_sni = true

[logging]
log_format = "json"
batch_flush_ms = 500
batch_buffer_kb = 128
add_request_id = false
"#;
        let parsed = ZMaxConfig::parse_toml(toml_input).expect("TOML ayrıştırılmalı");
        assert!(parsed.validate().is_ok());
        assert_eq!(parsed.server.user, "www-data");
        assert_eq!(parsed.server.group, "www-data");
        assert!(!parsed.server.cpu_affinity);
        assert!(!parsed.server.reuseport_workers);
        assert_eq!(parsed.server.graceful_shutdown_secs, 30);
        assert!(parsed.listeners.http.proxy_protocol);
        assert_eq!(parsed.listeners.https.alpn, vec!["h2".to_string()]);
        assert!(parsed.listeners.https.proxy_protocol);
        assert!(parsed.listeners.https.strict_sni);
        assert_eq!(parsed.logging.batch_flush_ms, 500);
        assert_eq!(parsed.logging.batch_buffer_kb, 128);
        assert!(!parsed.logging.add_request_id);

        let json = parsed.to_json_pretty().expect("JSON serileştirilmeli");
        let roundtrip = ZMaxConfig::parse_json(&json).expect("JSON ayrıştırılmalı");
        assert_eq!(roundtrip.server.graceful_shutdown_secs, 30);
        assert!(!roundtrip.server.reuseport_workers);
        assert!(roundtrip.listeners.https.strict_sni);
        assert_eq!(roundtrip.logging.batch_buffer_kb, 128);
        assert!(!roundtrip.logging.add_request_id);

        let minimal_json = ZMaxConfig::parse_json("{}").expect("Boş JSON varsayılanlarla açılmalı");
        assert!(minimal_json.server.reuseport_workers);
        assert_eq!(minimal_json.server.graceful_shutdown_secs, 15);
        assert_eq!(minimal_json.logging.batch_flush_ms, 250);
    }

    #[test]
    fn test_new_vhost_sections_toml_and_json_roundtrip() {
        let minimal_vhost = VHostEntry::parse_json(r#"{"name":"min.example.com"}"#).unwrap();
        assert!(!minimal_vhost.logging.enabled);
        assert_eq!(minimal_vhost.logging.format, "combined");
        assert_eq!(minimal_vhost.logging.max_log_size_mb, 100);
        assert!(minimal_vhost.logging.also_write_global);
        assert!(!minimal_vhost.error_docs.enabled);
        assert!(minimal_vhost.tls.http2);
        assert!(minimal_vhost.tls.strict_sni);
        assert_eq!(minimal_vhost.tls.min_version, "1.2");
        assert!(minimal_vhost.static_files.precompressed);
        assert!(minimal_vhost.static_files.brotli);
        assert!(minimal_vhost.static_files.gzip);
        assert!(!minimal_vhost.static_files.autoindex);
        assert!(minimal_vhost.static_files.sendfile);
        assert_eq!(minimal_vhost.security.waf_enabled, None);
        assert!(minimal_vhost.security.wp_brute_force);
        assert!(minimal_vhost.security.waf_exclude_paths.is_empty());
        assert!(minimal_vhost.rewrite.rules.is_empty());
        assert_eq!(minimal_vhost.php.lb_policy, "round_robin");
        assert_eq!(minimal_vhost.php.dial_timeout_ms, None);
        assert_eq!(minimal_vhost.php.io_timeout_secs, 60);
        assert!(minimal_vhost.php.keep_conn);
        assert_eq!(minimal_vhost.php.max_idle_conns, 16);
        assert!(minimal_vhost.php.resolve_root_symlink);
        assert!(minimal_vhost.php.allow_x_accel_redirect);
        assert!(minimal_vhost.php.x_accel_prefix.is_empty());

        let toml_doc = r#"
[vhost]
name = "shop.example.com"
document_root = "www/shop"

[vhost.logging]
enabled = true
access_log = "logs/shop_access.log"
error_log = "logs/shop_error.log"
format = "json"
max_log_size_mb = 250
also_write_global = false

[vhost.error_docs]
enabled = true
dir = "errors"
[vhost.error_docs.pages]
404 = "404.html"
500 = "50x.html"

[vhost.tls]
http2 = false
strict_sni = true
min_version = "1.3"

[vhost.static]
precompressed = false
brotli = false
gzip = true
autoindex = true
sendfile = false

[vhost.security]
waf_enabled = true
wp_brute_force = false
waf_exclude_paths = ["/wp-json/webhook", "/healthz"]

[[vhost.rewrite.rules]]
pattern = "^/old/(.*)$"
target = "/new/$1"
status = 301
flags = ["L", "NC"]
last = true

[vhost.php]
enabled = true
upstreams = ["127.0.0.1:9001", "127.0.0.1:9002"]
lb_policy = "least_conn"
dial_timeout_ms = 1500
io_timeout_secs = 90
keep_conn = false
max_idle_conns = 32
resolve_root_symlink = false
allow_x_accel_redirect = false
x_accel_prefix = "/protected/"
"#;
        let parsed: VHostFileDocument = toml::from_str(toml_doc).expect("Genişletilmiş vHost TOML ayrıştırılmalı");
        assert!(parsed.vhost.validate().is_ok());

        let toml_roundtrip: VHostFileDocument =
            toml::from_str(&serialize_vhost_toml(&parsed.vhost).unwrap()).unwrap();
        let json_str = serialize_vhost_json(&toml_roundtrip.vhost).unwrap();
        let json_roundtrip = deserialize_vhost_json(&json_str).unwrap();

        assert!(json_roundtrip.logging.enabled);
        assert_eq!(json_roundtrip.logging.format, "json");
        assert_eq!(json_roundtrip.logging.max_log_size_mb, 250);
        assert!(!json_roundtrip.logging.also_write_global);
        assert_eq!(json_roundtrip.error_docs.pages.get(&404).map(String::as_str), Some("404.html"));
        assert!(!json_roundtrip.tls.http2);
        assert!(json_roundtrip.tls.strict_sni);
        assert_eq!(json_roundtrip.tls.min_version, "1.3");
        assert!(!json_roundtrip.static_files.precompressed);
        assert!(json_roundtrip.static_files.autoindex);
        assert!(!json_roundtrip.static_files.sendfile);
        assert_eq!(json_roundtrip.security.waf_enabled, Some(true));
        assert!(!json_roundtrip.security.wp_brute_force);
        assert_eq!(json_roundtrip.security.waf_exclude_paths.len(), 2);
        assert_eq!(json_roundtrip.rewrite.rules.len(), 1);
        assert_eq!(json_roundtrip.rewrite.rules[0].status, 301);
        assert!(json_roundtrip.rewrite.rules[0].last);
        assert_eq!(json_roundtrip.php.upstreams, vec!["127.0.0.1:9001", "127.0.0.1:9002"]);
        assert_eq!(json_roundtrip.php.lb_policy, "least_conn");
        assert_eq!(parsed.vhost.php.dial_timeout_ms, Some(1500));
        assert_eq!(toml_roundtrip.vhost.php.dial_timeout_ms, Some(1500));
        assert_eq!(json_roundtrip.php.dial_timeout_ms, Some(1500));
        assert_eq!(json_roundtrip.php.max_idle_conns, 32);
        assert_eq!(json_roundtrip.php.x_accel_prefix, "/protected/");
    }

    #[test]
    fn test_effective_php_upstreams_and_error_doc_page_traversal() {
        let mut vh = VHostEntry::default();
        assert_eq!(vh.effective_php_upstreams(), vec!["127.0.0.1:9000".to_string()]);

        vh.php.upstreams = vec![
            "  ".to_string(),
            "127.0.0.1:9001".to_string(),
            "unix:/run/php.sock".to_string(),
        ];
        assert_eq!(
            vh.effective_php_upstreams(),
            vec!["127.0.0.1:9001".to_string(), "unix:/run/php.sock".to_string()]
        );

        vh.php.upstreams.clear();
        vh.php.upstream.clear();
        assert!(vh.effective_php_upstreams().is_empty());

        // Error docs devre dışı iken None döner
        vh.error_docs.pages.insert(404, "404.html".to_string());
        assert!(vh.resolve_error_doc_page(404).is_none());

        vh.error_docs.enabled = true;
        vh.error_docs.dir = "errors".to_string();
        assert_eq!(
            vh.resolve_error_doc_page(404),
            Some(Path::new("errors").join("404.html"))
        );
        assert!(vh.resolve_error_doc_page(500).is_none());

        vh.error_docs.pages.insert(403, "custom/403.html".to_string());
        assert_eq!(
            vh.resolve_error_doc_page(403),
            Some(Path::new("errors").join("custom/403.html"))
        );

        // Path traversal / absolute path saldırıları engellenmeli
        for unsafe_page in [
            "../etc/passwd",
            "sub/../../secret.html",
            "/etc/passwd",
            "\\Windows\\win.ini",
            "C:\\secret.html",
            "bad\0.html",
            "   ",
        ] {
            vh.error_docs.pages.insert(502, unsafe_page.to_string());
            assert!(
                vh.resolve_error_doc_page(502).is_none(),
                "Güvensiz hata sayfası yolu reddedilmeli: '{}'",
                unsafe_page
            );
        }

        vh.error_docs.dir = "../outside".to_string();
        assert!(vh.resolve_error_doc_page(404).is_none());

        vh.error_docs.dir.clear();
        assert_eq!(vh.resolve_error_doc_page(404), Some(PathBuf::from("404.html")));
    }

    #[test]
    fn test_validation_log_format_tls_min_version_and_php_lb_policy() {
        let mut cfg = ZMaxConfig::default();
        assert!(cfg.validate().is_ok());

        for bad_fmt in ["", "   ", "xml", "invalid_format", "combined\n"] {
            cfg.logging.log_format = bad_fmt.to_string();
            assert!(
                cfg.validate().is_err(),
                "Geçersiz global log_format reddedilmeli: '{}'",
                bad_fmt
            );
        }
        for good_fmt in ["combined", "common", "json", "%h %l %u %t \"%r\" %>s %b"] {
            cfg.logging.log_format = good_fmt.to_string();
            assert!(cfg.validate().is_ok(), "Geçerli log_format kabul edilmeli: '{}'", good_fmt);
        }

        let mut vh = VHostEntry {
            name: "valid.example.com".to_string(),
            ..VHostEntry::default()
        };
        assert!(vh.validate().is_ok());

        vh.logging.format = "invalid_vhost_fmt".to_string();
        assert!(vh.validate().is_err());
        vh.logging.format = "combined".to_string();

        for bad_tls in ["1.0", "1.1", "1.4", "ssl3", ""] {
            vh.tls.min_version = bad_tls.to_string();
            assert!(
                vh.validate().is_err(),
                "Geçersiz TLS min_version reddedilmeli: '{}'",
                bad_tls
            );
        }
        for good_tls in ["1.2", "1.3"] {
            vh.tls.min_version = good_tls.to_string();
            assert!(vh.validate().is_ok());
        }

        for bad_lb in ["", "sticky", "hash"] {
            vh.php.lb_policy = bad_lb.to_string();
            assert!(
                vh.validate().is_err(),
                "Geçersiz php.lb_policy reddedilmeli: '{}'",
                bad_lb
            );
        }
        for good_lb in ["round_robin", "least_conn", "random", "ip_hash", "first"] {
            vh.php.lb_policy = good_lb.to_string();
            assert!(vh.validate().is_ok());
        }

        // Inline ZMaxConfig.vhosts üzerinden de doğrulanmalı
        let mut bad_inline = ZMaxConfig::default();
        let mut bad_vh = VHostEntry::default();
        bad_vh.tls.min_version = "1.0".to_string();
        bad_inline.vhosts.insert("inline.example.com".to_string(), bad_vh);
        assert!(bad_inline.validate().is_err());
    }

    #[test]
    fn test_acme_config_vhost_and_server_roundtrip() {
        let toml_str = r#"
            [server]
            server_name = "ZMax-ACME-Test"

            [server.acme]
            acme_root = "/var/www/acme"
            force_https_exempt = true

            [vhost]
            name = "acme.example.com"
            document_root = "/var/www/acme.example.com"

            [vhost.acme]
            acme_root = "/var/www/custom-acme"
            force_https_exempt = true
        "#;
        let vh_doc: VHostFileDocument = toml::from_str(toml_str).unwrap();
        assert_eq!(
            vh_doc.vhost.acme.acme_root,
            Some(PathBuf::from("/var/www/custom-acme"))
        );
        assert!(vh_doc.vhost.acme.force_https_exempt);

        let cfg: ZMaxConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.server.server_name, "ZMax-ACME-Test");
        assert_eq!(
            cfg.server.acme.acme_root,
            Some(PathBuf::from("/var/www/acme"))
        );
        assert!(cfg.server.acme.force_https_exempt);
    }

    #[test]
    fn test_cache_purge_defaults_off_validation_and_redacted_debug() {
        let def = ZMaxConfig::default();
        assert!(!def.cache.purge_enabled, "PURGE varsayılan KAPALI olmalı");
        assert!(def.cache.purge_key.is_empty());
        assert!(def.cache.purge_allow_ips.is_empty());
        assert!(!def.cache.respect_request_cache_control);

        let legacy = ZMaxConfig::parse_toml("[cache]\nenabled = true\n").unwrap();
        assert!(!legacy.cache.purge_enabled);

        let on = ZMaxConfig::parse_toml(
            "[cache]\npurge_enabled = true\npurge_key = \"cok-gizli-anahtar\"\npurge_allow_ips = [\"10.0.0.0/8\"]\n",
        )
        .unwrap();
        assert!(on.cache.purge_enabled);
        assert!(on.validate().is_ok());
        let dbg = format!("{:?}", on.cache);
        assert!(!dbg.contains("cok-gizli-anahtar"), "anahtar Debug'a sızmamalı: {dbg}");
        assert!(dbg.contains("<gizli>"));

        let bad = ZMaxConfig::parse_toml("[cache]\npurge_enabled = true\npurge_allow_ips = [\"gecersiz\"]\n")
            .unwrap();
        assert!(bad.validate().is_err(), "geçersiz CIDR reddedilmeli");
    }

    #[test]
    fn k8_vhost_php_dial_timeout_default_none_and_json_null_roundtrip() {
        let doc: VHostFileDocument =
            toml::from_str("[vhost]\nname = \"a.test\"\ndocument_root = \"www/a\"\n")
                .expect("asgari vHost ayrıştırılmalı");
        assert_eq!(doc.vhost.php.dial_timeout_ms, None);
        // None değeri TOML'a yazılmaz (vhost değer vermiyor)
        let toml_out = serialize_vhost_toml(&doc.vhost).unwrap();
        assert!(!toml_out.contains("dial_timeout_ms"), "{toml_out}");
        // JSON: None -> null -> None
        let json_str = serialize_vhost_json(&doc.vhost).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(
            v["dial_timeout_ms"].is_null()
                || v.get("php")
                    .map(|p| p["dial_timeout_ms"].is_null())
                    .unwrap_or(false),
            "{json_str}"
        );
        let back = deserialize_vhost_json(&json_str).unwrap();
        assert_eq!(back.php.dial_timeout_ms, None);
        // Açık değer korunur
        let mut with = doc.vhost.clone();
        with.php.dial_timeout_ms = Some(2500);
        let back2 = deserialize_vhost_json(&serialize_vhost_json(&with).unwrap()).unwrap();
        assert_eq!(back2.php.dial_timeout_ms, Some(2500));
    }

    #[test]
    fn k8_server_user_group_tmp_dir_default_to_empty_when_absent() {
        let cfg = ZMaxConfig::parse_toml("[server]\nserver_name = \"x\"\n").unwrap();
        assert_eq!(cfg.server.user, "");
        assert_eq!(cfg.server.group, "");
        assert_eq!(cfg.server.tmp_dir, "");
        let cfg2 = ZMaxConfig::parse_toml("[server]\ntmp_dir = \"run/tmp\"\n").unwrap();
        assert_eq!(cfg2.server.tmp_dir, "run/tmp");
    }

    #[test]
    fn test_ols_parity_models_roundtrip() {
        // 1. TuningConfig varsayılanları ve TOML ayrıştırma
        let tuning_default = TuningConfig::default();
        assert_eq!(tuning_default.max_connections, 10000);
        assert_eq!(tuning_default.connection_timeout, 60);
        assert!(tuning_default.gzip_enabled);
        assert!(tuning_default.http3_enabled);

        let toml_tuning = r#"
[server]
server_name = "ols_test"
[tuning]
max_connections = 50000
connection_timeout = 120
gzip_enabled = false
http3_port = 8443
"#;
        let cfg = ZMaxConfig::parse_toml(toml_tuning).expect("tuning TOML ayrıştırılmalı");
        assert_eq!(cfg.tuning.max_connections, 50000);
        assert_eq!(cfg.tuning.connection_timeout, 120);
        assert!(!cfg.tuning.gzip_enabled);
        assert_eq!(cfg.tuning.http3_port, 8443);
        // Atanmayan alanlar varsayılan kalır
        assert_eq!(cfg.tuning.keep_alive_timeout, 15);

        // 2. ListenerConfig varsayılanları ve dinamik dinleyici
        let listener_def = ListenerConfig::default();
        assert_eq!(listener_def.port, 80);
        assert!(listener_def.enabled);
        assert_eq!(listener_def.vhost_mappings, vec!["*".to_string()]);

        let toml_listeners = r#"
[server]
server_name = "test_l"
[[listeners.custom]]
id = "listener_7080"
name = "Admin Port"
address = "127.0.0.1"
port = 7080
secure = true
protocol = "HTTP/2"
vhost_mappings = ["admin.local"]
tls_versions = ["1.3"]
"#;
        let cfg_l = ZMaxConfig::parse_toml(toml_listeners).expect("dinleyici TOML ayrıştırılmalı");
        assert_eq!(cfg_l.listeners.custom.len(), 1);
        let l = &cfg_l.listeners.custom[0];
        assert_eq!(l.id, "listener_7080");
        assert_eq!(l.port, 7080);
        assert!(l.secure);
        assert_eq!(l.vhost_mappings, vec!["admin.local".to_string()]);

        // 3. ContextConfig varsayılanları ve vHost contexts listesi
        let ctx_def = ContextConfig::default();
        assert_eq!(ctx_def.uri, "/");
        assert_eq!(ctx_def.context_type, "static");
        assert!(ctx_def.enabled);

        let toml_vhost = r#"
[vhost]
name = "context.test"
document_root = "www/test"

[[vhost.contexts]]
uri = "/api"
context_type = "proxy"
location = "http://127.0.0.1:3000"
rewrite_rules = ["RewriteRule ^/api/(.*)$ /$1 [P]"]

[[vhost.contexts]]
uri = "/static"
context_type = "static"
location = "/var/www/static"
"#;
        let doc: VHostFileDocument = toml::from_str(toml_vhost).expect("vhost contexts ayrıştırılmalı");
        assert_eq!(doc.vhost.contexts.len(), 2);
        assert_eq!(doc.vhost.contexts[0].uri, "/api");
        assert_eq!(doc.vhost.contexts[0].context_type, "proxy");
        assert_eq!(doc.vhost.contexts[0].location, "http://127.0.0.1:3000");
        assert_eq!(doc.vhost.contexts[1].uri, "/static");
        assert_eq!(doc.vhost.contexts[1].context_type, "static");
    }

    #[test]
    fn test_ols_server_tuning_config_serde_and_default() {
        let def = ServerTuningConfig::default();
        assert_eq!(def.connection_timeout, 60);
        assert_eq!(def.keep_alive_timeout, 15);
        assert_eq!(def.max_keep_alive_reqs, 1000);
        assert!(def.gzip);
        assert!(def.brotli);
        assert!(def.ssl_session_cache);
        assert_eq!(def.ssl_cache_size, 1_000_000);
        assert_eq!(def.ssl_cache_timeout, 3600);
        assert!(def.quic);
        assert_eq!(def.quic_port, 443);
        assert_eq!(def.max_connections, 10000);
        assert_eq!(def.min_compress_size, 256);

        let toml_str = r#"
connection_timeout = 90
keep_alive_timeout = 25
max_keep_alive_reqs = 500
gzip = false
brotli = true
ssl_session_cache = true
ssl_cache_size = 500000
ssl_cache_timeout = 1800
quic = false
quic_port = 8443
max_connections = 25000
min_compress_size = 512
"#;
        let parsed: ServerTuningConfig = toml::from_str(toml_str).expect("ServerTuningConfig toml parsed");
        assert_eq!(parsed.connection_timeout, 90);
        assert_eq!(parsed.keep_alive_timeout, 25);
        assert_eq!(parsed.max_keep_alive_reqs, 500);
        assert!(!parsed.gzip);
        assert!(parsed.brotli);
        assert!(parsed.ssl_session_cache);
        assert_eq!(parsed.ssl_cache_size, 500000);
        assert_eq!(parsed.ssl_cache_timeout, 1800);
        assert!(!parsed.quic);
        assert_eq!(parsed.quic_port, 8443);
        assert_eq!(parsed.max_connections, 25000);
        assert_eq!(parsed.min_compress_size, 512);

        // From<TuningConfig> ve From<ServerTuningConfig> çift yönlü dönüşüm
        let tuning_from_server: TuningConfig = parsed.clone().into();
        assert_eq!(tuning_from_server.connection_timeout, 90);
        assert_eq!(tuning_from_server.max_keep_alive_req, 500);
        assert!(!tuning_from_server.gzip_enabled);
        assert!(!tuning_from_server.http3_enabled);

        let server_from_tuning: ServerTuningConfig = tuning_from_server.into();
        assert_eq!(server_from_tuning, parsed);

        // ZMaxConfig::effective_tuning() testi
        let mut zmax = ZMaxConfig::default();
        zmax.tuning.connection_timeout = 75;
        let eff = zmax.effective_tuning();
        assert_eq!(eff.connection_timeout, 75);
    }

    #[test]
    fn test_ols_listener_config_aliases_and_methods() {
        let mut l = ListenerConfig::default();
        assert_eq!(l.ip(), "0.0.0.0");
        assert_eq!(l.port, 80);
        assert!(!l.secure);
        assert_eq!(l.cert_path(), "");
        assert_eq!(l.key_path(), "");
        assert_eq!(l.vhosts_mapping(), &["*".to_string()]);

        l.set_ip("192.168.1.50");
        l.set_cert_path("/etc/ssl/cert.pem");
        l.set_key_path("/etc/ssl/key.pem");
        assert_eq!(l.ip(), "192.168.1.50");
        assert_eq!(l.address, "192.168.1.50");
        assert_eq!(l.cert_path(), "/etc/ssl/cert.pem");
        assert_eq!(l.key_path(), "/etc/ssl/key.pem");

        // Serde takma adları (ip, cert_path, key_path, vhosts_mapping, tls) ile TOML ayrıştırma
        let toml_listener = r#"
id = "ls_ols_https"
name = "OLS Secure Listener"
ip = "10.0.0.1"
port = 443
tls = true
protocol = "HTTP/2, HTTP/3 (QUIC)"
vhosts_mapping = ["site1.com", "site2.com"]
tls_versions = ["1.3"]
cert_path = "/certs/bundle.crt"
key_path = "/certs/server.key"
enabled = true
"#;
        let parsed: ListenerConfig = toml::from_str(toml_listener).expect("ListenerConfig with aliases parsed");
        assert_eq!(parsed.id, "ls_ols_https");
        assert_eq!(parsed.name, "OLS Secure Listener");
        assert_eq!(parsed.ip(), "10.0.0.1");
        assert_eq!(parsed.address, "10.0.0.1");
        assert_eq!(parsed.port, 443);
        assert!(parsed.secure);
        assert_eq!(parsed.vhosts_mapping(), &["site1.com".to_string(), "site2.com".to_string()]);
        assert_eq!(parsed.cert_path(), "/certs/bundle.crt");
        assert_eq!(parsed.key_path(), "/certs/server.key");
    }

    #[test]
    fn test_ols_external_app_config_serde_and_uds() {
        let def = ExternalAppConfig::default();
        assert_eq!(def.app_type, "lsphp");
        assert_eq!(def.address, "127.0.0.1:9000");
        assert_eq!(def.max_conns, 100);
        assert!(def.is_tcp());
        assert!(!def.is_uds());
        assert!(def.persist_conn);
        assert_eq!(def.instances, 1);
        assert!(def.enabled);

        let uds_app = ExternalAppConfig {
            id: "lsphp83".to_string(),
            name: "PHP 8.3 LiteSpeed".to_string(),
            app_type: "lsphp".to_string(),
            address: "uds:///tmp/lsphp83.sock".to_string(),
            max_conns: 200,
            env_vars: {
                let mut map = HashMap::new();
                map.insert("PHP_LSAPI_CHILDREN".to_string(), "50".to_string());
                map.insert("MEMORY_LIMIT".to_string(), "512M".to_string());
                map
            },
            init_timeout: 45,
            retry_timeout: 5,
            persist_conn: true,
            instances: 4,
            enabled: true,
            ..Default::default()
        };
        assert!(uds_app.is_uds());
        assert!(!uds_app.is_tcp());

        // Serde roundtrip testi
        let toml_str = toml::to_string(&uds_app).expect("ExternalAppConfig serialize to toml");
        let parsed: ExternalAppConfig = toml::from_str(&toml_str).expect("ExternalAppConfig deserialize from toml");
        assert_eq!(parsed.id, "lsphp83");
        assert_eq!(parsed.max_conns, 200);
        assert_eq!(parsed.env_vars.get("PHP_LSAPI_CHILDREN").map(String::as_str), Some("50"));
        assert!(parsed.is_uds());

        // ZMaxConfig içine [[extapps]] listesi ekleme ve ayrıştırma
        let zmax_toml = r#"
[server]
server_name = "ols_server"

[[extapps]]
id = "lsphp81"
name = "PHP 8.1"
app_type = "lsphp"
address = "uds:///tmp/lsphp81.sock"
max_conns = 80

[[extapps]]
id = "node_proxy"
name = "Node Backend"
app_type = "proxy"
address = "127.0.0.1:3000"
max_conns = 150
"#;
        let cfg: ZMaxConfig = ZMaxConfig::parse_toml(zmax_toml).expect("ZMaxConfig with extapps parsed");
        assert_eq!(cfg.extapps.len(), 2);
        assert_eq!(cfg.extapps[0].id, "lsphp81");
        assert!(cfg.extapps[0].is_uds());
        assert_eq!(cfg.extapps[1].id, "node_proxy");
        assert!(cfg.extapps[1].is_tcp());
    }

    #[test]
    fn test_ols_vhost_context_config_headers_and_types() {
        let mut ctx = VHostContextConfig::default();
        assert_eq!(ctx.uri, "/");
        assert!(ctx.is_static());
        assert!(!ctx.is_proxy());
        assert!(!ctx.is_redirect());

        ctx.context_type = "proxy".to_string();
        ctx.location = "http://127.0.0.1:8080".to_string();
        ctx.add_header("X-Forwarded-Proto", "https");
        ctx.add_header("X-Real-IP", "$remote_addr");
        assert!(ctx.is_proxy());
        assert_eq!(ctx.headers.get("X-Forwarded-Proto").map(String::as_str), Some("https"));

        let toml_ctx = r#"
uri = "/app"
context_type = "redirect"
location = "https://example.com/login"
handler = "redirect_handler"

[headers]
X-Redirect-Reason = "Authentication Required"
"#;
        let parsed: VHostContextConfig = toml::from_str(toml_ctx).expect("VHostContextConfig parsed");
        assert_eq!(parsed.uri, "/app");
        assert!(parsed.is_redirect());
        assert_eq!(parsed.location, "https://example.com/login");
        assert_eq!(parsed.headers.get("X-Redirect-Reason").map(String::as_str), Some("Authentication Required"));
    }

    #[test]
    fn test_ols_vhost_rewrite_config_roundtrip_and_inherit() {
        let def = VHostRewriteConfig::default();
        assert!(def.enable);
        assert!(def.inherit);
        assert!(def.rules.is_empty());

        let toml_str = r#"
enable = true
inherit = false
rules = [
    "RewriteEngine On",
    "RewriteCond %{REQUEST_FILENAME} !-f",
    "RewriteCond %{REQUEST_FILENAME} !-d",
    "RewriteRule ^(.*)$ index.php [L]"
]
"#;
        let parsed: VHostRewriteConfig = toml::from_str(toml_str).expect("VHostRewriteConfig parsed");
        assert!(parsed.enable);
        assert!(!parsed.inherit);
        assert_eq!(parsed.rules.len(), 4);
        assert_eq!(parsed.rules[3], "RewriteRule ^(.*)$ index.php [L]");

        // From<VHostRewriteConfig> for VHostRewriteSection dönüşümü
        let section: VHostRewriteSection = parsed.clone().into();
        assert!(section.enabled);
        assert!(!section.inherit);
        assert_eq!(section.raw_rules.len(), 4);

        // From<VHostRewriteSection> for VHostRewriteConfig dönüşümü
        let back_cfg: VHostRewriteConfig = section.into();
        assert_eq!(back_cfg.rules, parsed.rules);
        assert_eq!(back_cfg.inherit, parsed.inherit);
    }
}
