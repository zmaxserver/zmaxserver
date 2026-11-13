use std::path::PathBuf;
use zmax_header::SecurityHeadersPolicy;
use zmax_security::IpAccessList;

#[derive(Debug, Clone, Default)]
pub struct LogMeta {
    pub domain: Option<String>,
    pub custom_log_path: Option<PathBuf>,
    pub json_format: bool,
    pub also_write_global: bool,
    pub max_log_size_bytes: u64,
}

#[derive(Clone)]
pub struct ResolvedVHostContext {
    pub doc_root: PathBuf,
    pub index_files: Vec<String>,
    pub php_enabled: bool,
    pub php_upstream: String,
    pub php_upstreams: Vec<String>,
    pub php_lb_policy: String,
    pub php_timeout: u64,
    pub cache_enabled: bool,
    pub cache_expire: u64,
    pub cache_stale_sec: u64,
    pub vhost_name: String,
    pub vhost_aliases: Vec<String>,
    pub force_https: bool,
    pub hotlink_protection: bool,
    pub hotlink_config: zmax_config::HotlinkConfig,
    pub global_acl: IpAccessList,
    pub vhost_acl: IpAccessList,
    pub vhost_acl_engine: zmax_security::VhostAcl,
    pub rewrite_enabled: bool,
    pub rewrite_try_files: bool,
    pub rewrite_htaccess: bool,
    pub rewrite_rules: Vec<zmax_config::VHostRewriteRule>,
    pub proxy_enabled: bool,
    pub proxy_upstream: String,
    pub proxy_path_prefix: String,
    pub proxy_preserve_host: bool,
    pub proxy_websocket: bool,
    // [kart-10] Ters vekil genisletilmis ayarları (initTimeout, keep-alive, respBuffer)
    pub proxy_ext: zmax_config::ProxyExtConfig,
    pub(super) auto_webp: bool,
    pub(super) auto_avif: bool,
    pub(super) etag_enabled: bool,
    pub(super) last_modified_header: bool,
    pub max_log_size_bytes: u64,
    pub(super) headers_policy: Option<SecurityHeadersPolicy>,
    // 8-Madde Alanlari
    pub waf_enabled: Option<bool>,
    pub waf_exclude_paths: Vec<String>,
    pub error_docs: zmax_config::VHostErrorDocsSection,
    pub logging: zmax_config::VHostLoggingSection,
    pub tls_http2: bool,
    pub acme_root: Option<PathBuf>,
    pub auth: zmax_config::VHostAuthSection, // [kart-9]
    // [kart-8] FastCGI bağlantı zaman aşımı (milisaniye)
    pub php_dial_timeout_ms: u64,
    pub autoindex: bool,
    pub block_dangerous_files: bool,
}

/// FastCGI bağlantı zaman aşımı (ms): vhost değeri verilmişse (ve 0 değilse) o; yoksa `mod_fastcgi`
/// politika değeri (en az 1 ms). vhost varsayılanı `None` olduğundan politika gerçekten kullanılır.
#[inline]
pub(super) fn resolve_php_dial_timeout_ms(vhost_dial_ms: Option<u64>, policy_dial_ms: u64) -> u64 {
    match vhost_dial_ms {
        Some(ms) if ms > 0 => ms,
        _ => policy_dial_ms.max(1),
    }
}
