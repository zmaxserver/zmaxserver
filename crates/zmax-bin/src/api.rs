//! # ZMax Evrensel Kontrol API Yönlendiricisi
//! Hosting kontrol panelleri (zPanel, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia, aaPanel vb.)
//! ve dahili WebAdmin UI için ortak REST JSON API katmanı (`/api/v1/*` + `/api/*`).

use crate::modules_runtime::{
    append_error_log, build_redis_client, compile_policies, compute_effective_auth,
    module_category_key, CompiledPolicies, EffectiveAuthTokens,
};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use zmax_config::{
    load_vhosts_dir, resolve_path, serialize_vhost_toml, validate_domain, LoadedModules,
    LoadedVHost, VHostEntry, ZMaxConfig, KNOWN_PANEL_PORTS,
};
use zmax_httpparser::{read_http1_request_buffered, HttpReadError, HttpReadLimits, HttpRequestData};
use zmax_obfuscate::zpoly;

const MAX_IN_MEMORY_LOGS: usize = 200;

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

pub struct ServerState {
    pub base_dir: PathBuf,
    pub cache: zmax_cache::ZMaxCache,
    pub limiter: RwLock<zmax_security::RateLimiter>,
    pub ban_manager: Arc<zmax_security::IpBanManager>,
    pub wp_guard: Arc<zmax_security::WpBruteForceGuard>,
    pub buffer_pool: Arc<zmax_pool::BufferPool>,
    pub upstream_pool: Arc<zmax_pool::UpstreamSocketPool>,
    pub runtime: RwLock<RuntimeState>,
    pub admin_static_handler: RwLock<zmax_static::StaticFileHandler>,
    pub tls: Arc<zmax_tls::SniResolver>,
    pub admin_tls: Arc<zmax_tls::SniResolver>,
    pub api_tls: Arc<zmax_tls::SniResolver>,
    pub log_manager: Arc<crate::logger::AsyncLogManager>,
    pub htaccess_resolver: Arc<zmax_rewrite::HtAccessResolver>,
    pub shutdown: Arc<zmax_runtime::ShutdownCoordinator>,
    pub access_logs: Mutex<VecDeque<AccessLogRecord>>,
    pub stats: ServerStats,
}

impl ServerState {
    /// Bellekte tutulan son erişim günlüklerine yeni bir kayıt ekler (en fazla 200 kayıt).
    pub fn record_access_log(&self, ip: &str, method: &str, path: &str, status: u16, elapsed: Duration) {
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

/// vhost tablosundaki sertifikaları SNI çözümleyicisine yükler; atlananları logs/error.log'a yazar.
pub async fn refresh_tls_certs(
    resolver: &zmax_tls::SniResolver,
    vhosts: &[LoadedVHost],
    base_dir: &Path,
) -> usize {
    let sources = zmax_tls::sources_from_vhosts(vhosts, base_dir);
    let report = resolver.replace(&sources);
    for sk in &report.skipped {
        let line = format!("[TLS] vhost atlandi ({}): {}", sk.label, sk.reason);
        eprintln!("{}", line);
        append_error_log(base_dir, &line).await;
    }
    report.loaded
}

#[derive(Debug, Clone)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub version: u8,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl From<HttpRequestData> for ParsedHttpRequest {
    fn from(d: HttpRequestData) -> Self {
        Self {
            method: d.method,
            path: d.path,
            query: d.query,
            version: d.version,
            host: d.host,
            headers: d.headers,
            body: d.body,
            keep_alive: d.keep_alive,
        }
    }
}

/// JSON dizgesi için RFC 8259 uyumlu kaçış uygular.
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Düz JSON gövdesinden basit `"key":"value"` metin alanı çıkarır (dış bağımlılık gerektirmez).
pub fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let mut chars = after_colon[1..].chars();
    let mut val = String::new();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(esc) = chars.next() {
                match esc {
                    'n' => val.push('\n'),
                    'r' => val.push('\r'),
                    't' => val.push('\t'),
                    '"' => val.push('"'),
                    '\\' => val.push('\\'),
                    '/' => val.push('/'),
                    other => val.push(other),
                }
            }
        } else if c == '"' {
            return Some(val);
        } else {
            val.push(c);
        }
    }
    None
}

/// Düz JSON gövdesinden basit `"key": true/false` mantıksal alanı çıkarır.
pub fn extract_json_bool(body: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Düz JSON gövdesinden basit `"key": 123` tam sayı alanı çıkarır.
pub fn extract_json_u64(body: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    let num_str: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if num_str.is_empty() {
        None
    } else {
        num_str.parse::<u64>().ok()
    }
}

/// Düz JSON gövdesinden basit `["a","b"]` dizge dizisini çıkarır.
pub fn extract_json_string_array(body: &str, key: &str) -> Option<Vec<String>> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }
    let end = after_colon.find(']')?;
    let inner = &after_colon[1..end];
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if in_str {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                items.push(cur.clone());
                cur.clear();
                in_str = false;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' {
            in_str = true;
        }
    }
    Some(items)
}

/// Akıştan yapılandırılmış sınırlarla HTTP/1.1 isteği okur (`Content-Length` + `chunked` + `413/431/408`).
pub async fn read_http_request_with_limits<S>(
    stream: &mut S,
    leftover: &mut Vec<u8>,
    limits: HttpReadLimits,
) -> Result<Option<ParsedHttpRequest>, HttpReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let opt = read_http1_request_buffered(stream, leftover, limits).await?;
    Ok(opt.map(ParsedHttpRequest::from))
}

/// HTTP okuma hatasını uygun HTTP durum koduyla (413, 431, 408, 400) istemciye yazar.
pub async fn send_http_read_error<S>(socket: &mut S, err: &HttpReadError)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let (code, reason, body) = match err {
        HttpReadError::PayloadTooLarge => (413u16, "Payload Too Large", "413 Payload Too Large"),
        HttpReadError::HeadersTooLarge => {
            (431u16, "Request Header Fields Too Large", "431 Request Header Fields Too Large")
        }
        HttpReadError::Timeout => (408u16, "Request Timeout", "408 Request Timeout"),
        HttpReadError::BadRequest(_) => (400u16, "Bad Request", "400 Bad Request"),
        HttpReadError::Io(_) => return,
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nServer: zmaxserver\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    );
    let _ = socket.write_all(resp.as_bytes()).await;
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `[listeners.api]` veya `[listeners.admin]` token doğrulaması (`Authorization: Bearer <token>` veya `X-ZMax-Token`).
pub fn is_authorized(req: &ParsedHttpRequest, expected_token: &str, require_token: bool) -> bool {
    if expected_token.is_empty() && !require_token {
        return true;
    }
    if expected_token.is_empty() && require_token {
        return false;
    }
    for (name, val) in &req.headers {
        if name.eq_ignore_ascii_case("authorization") {
            if let Some(bearer) = val
                .strip_prefix("Bearer ")
                .or_else(|| val.strip_prefix("bearer "))
            {
                if constant_time_eq(bearer.trim(), expected_token) {
                    return true;
                }
            }
        } else if name.eq_ignore_ascii_case("x-zmax-token")
            && constant_time_eq(val.trim(), expected_token)
        {
            return true;
        }
    }
    false
}

async fn send_response_with_content_type<S>(
    socket: &mut S,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    cors_origin: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let origin = if cors_origin.is_empty() { "*" } else { cors_origin };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nServer: {}\r\nContent-Type: {}\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-ZMax-Token, X-ZMax-Purge-Key\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        zpoly!("zmaxserver-api").as_str(),
        content_type,
        origin,
        body.len(),
        body
    );
    socket.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Standart CORS ve Server başlıklarıyla JSON yanıtı gönderir.
pub async fn send_json_response<S>(
    socket: &mut S,
    status_code: u16,
    status_text: &str,
    cors_origin: &str,
    json_body: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    send_response_with_content_type(
        socket,
        status_code,
        status_text,
        "application/json; charset=utf-8",
        cors_origin,
        json_body,
    )
    .await
}

/// HTTPS dinleyicisinin etkin ALPN protokol bayt dizilerini (`["h2", "http/1.1"]` vb.) döndürür.
pub fn current_https_alpn_protocols(config: &ZMaxConfig) -> Vec<Vec<u8>> {
    zmax_tls::parse_alpn_list(&config.listeners.https.alpn)
}

/// Tekil bir dinleyicinin (panel veya API) TLS sertifikasını `SniResolver` üzerine yükler/günceller.
pub async fn refresh_listener_tls_cert(
    resolver: &zmax_tls::SniResolver,
    label: &str,
    ssl_enabled: bool,
    tls_cert: &str,
    tls_key: &str,
    base_dir: &Path,
) -> usize {
    let cert_trimmed = tls_cert.trim();
    let key_trimmed = tls_key.trim();
    if !ssl_enabled || cert_trimmed.is_empty() || key_trimmed.is_empty() {
        let _ = resolver.replace(&[]);
        return 0;
    }
    let sources = [zmax_tls::CertSource {
        label: label.to_string(),
        names: Vec::new(),
        cert_path: resolve_path(base_dir, cert_trimmed),
        key_path: resolve_path(base_dir, key_trimmed),
    }];
    let report = resolver.replace(&sources);
    for sk in &report.skipped {
        let line = format!(
            "[TLS] {} dinleyici sertifikasi atlandi ({}): {}",
            label, sk.label, sk.reason
        );
        eprintln!("{}", line);
        append_error_log(base_dir, &line).await;
    }
    report.loaded
}

/// Diskten `conf/zmax.toml`, `conf/vhosts/*.toml` ve `modules/mod_*.toml` dosyalarını atomik olarak yeniler
/// ve güncel HTTPS ALPN protokol listesini de döndürür.
pub async fn reload_runtime_state_with_alpn(
    state: &Arc<ServerState>,
) -> Result<(usize, Vec<Vec<u8>>), String> {
    let (conf_path, old_vhosts_dir, modules_dir) = {
        let rt = state.runtime.read().await;
        (rt.conf_path.clone(), rt.vhosts_dir.clone(), rt.modules_dir.clone())
    };

    let new_cfg = ZMaxConfig::load_or_default(&conf_path)?;
    let resolved_vhosts_dir = if new_cfg.vhosts_dir.path.trim().is_empty() {
        old_vhosts_dir
    } else {
        resolve_path(&state.base_dir, &new_cfg.vhosts_dir.path)
    };
    let loaded_vhosts = load_vhosts_dir(&resolved_vhosts_dir, &state.base_dir)?;
    let loaded_modules = LoadedModules::load_from_dir(&modules_dir)?;
    let _ = new_cfg.validate_workspace_layout(&state.base_dir, &loaded_vhosts, &loaded_modules)?;
    let policies = compile_policies(&new_cfg, &loaded_modules);
    let redis_client = build_redis_client(&loaded_modules);
    let auth = compute_effective_auth(&new_cfg);
    for notice in &auth.auto_generated_notices {
        eprintln!("{}", notice);
        append_error_log(&state.base_dir, notice).await;
    }

    let vhost_count = loaded_vhosts.len();
    let new_admin_dir = resolve_path(&state.base_dir, &new_cfg.listeners.admin.document_root);
    let access_log_rel = if new_cfg.logging.access_log.trim().is_empty() {
        "logs/access.log"
    } else {
        new_cfg.logging.access_log.trim()
    };
    let error_log_rel = if new_cfg.logging.error_log.trim().is_empty() {
        "logs/error.log"
    } else {
        new_cfg.logging.error_log.trim()
    };
    let global_access_log = resolve_path(&state.base_dir, access_log_rel);
    let global_error_log = resolve_path(&state.base_dir, error_log_rel);
    let alpn_protocols = current_https_alpn_protocols(&new_cfg);

    {
        let mut limiter = state.limiter.write().await;
        *limiter = zmax_security::RateLimiter::new(policies.effective_rate_limit);
    }
    {
        let mut admin_handler = state.admin_static_handler.write().await;
        *admin_handler = zmax_static::StaticFileHandler::new(new_admin_dir);
    }

    state
        .log_manager
        .update_global_paths(global_access_log, global_error_log)
        .await;
    state.htaccess_resolver.clear_cache();

    refresh_tls_certs(&state.tls, &loaded_vhosts, &state.base_dir).await;
    refresh_listener_tls_cert(
        &state.admin_tls,
        "admin",
        new_cfg.listeners.admin.ssl,
        &new_cfg.listeners.admin.tls_cert,
        &new_cfg.listeners.admin.tls_key,
        &state.base_dir,
    )
    .await;
    refresh_listener_tls_cert(
        &state.api_tls,
        "api",
        new_cfg.listeners.api.ssl,
        &new_cfg.listeners.api.tls_cert,
        &new_cfg.listeners.api.tls_key,
        &state.base_dir,
    )
    .await;

    {
        let mut rt = state.runtime.write().await;
        rt.config = new_cfg;
        rt.vhosts = loaded_vhosts;
        rt.modules = loaded_modules;
        rt.policies = policies;
        rt.redis_client = redis_client;
        rt.auth = auth;
        rt.vhosts_dir = resolved_vhosts_dir;
    }

    Ok((vhost_count, alpn_protocols))
}

/// Diskten `conf/zmax.toml`, `conf/vhosts/*.toml` ve `modules/mod_*.toml` dosyalarını atomik olarak yeniler.
pub async fn reload_runtime_state(state: &Arc<ServerState>) -> Result<usize, String> {
    reload_runtime_state_with_alpn(state)
        .await
        .map(|(count, _)| count)
}

fn format_vhost_json(v: &LoadedVHost) -> String {
    let mut root = match serde_json::to_value(&v.entry) {
        Ok(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    let has_ssl = !v.entry.ssl.certificate.trim().is_empty();
    let effective_upstreams = v.entry.effective_php_upstreams();

    root.insert(
        "domain".to_string(),
        serde_json::Value::String(v.entry.name.clone()),
    );
    root.insert(
        "resolved_root".to_string(),
        serde_json::Value::String(v.resolved_doc_root.to_string_lossy().into_owned()),
    );
    root.insert(
        "file".to_string(),
        serde_json::Value::String(v.file_name.clone()),
    );

    // Geriye dönük uyumlu üst-düzey kısayol alanları
    root.insert(
        "php_enabled".to_string(),
        serde_json::Value::Bool(v.entry.php.enabled),
    );
    root.insert(
        "php_sapi".to_string(),
        serde_json::Value::String(v.entry.php.sapi.clone()),
    );
    root.insert(
        "php_upstream".to_string(),
        serde_json::Value::String(v.entry.php.upstream.clone()),
    );
    root.insert(
        "php_timeout".to_string(),
        serde_json::Value::from(v.entry.php.timeout),
    );
    root.insert(
        "php_upstreams".to_string(),
        serde_json::json!(effective_upstreams),
    );
    root.insert(
        "upstreams".to_string(),
        serde_json::json!(v.entry.php.upstreams),
    );
    root.insert(
        "lb_policy".to_string(),
        serde_json::Value::String(v.entry.php.lb_policy.clone()),
    );
    root.insert(
        "dial_timeout_ms".to_string(),
        serde_json::Value::from(v.entry.php.dial_timeout_ms),
    );
    root.insert(
        "io_timeout_secs".to_string(),
        serde_json::Value::from(v.entry.php.io_timeout_secs),
    );
    root.insert(
        "keep_conn".to_string(),
        serde_json::Value::Bool(v.entry.php.keep_conn),
    );
    root.insert(
        "max_idle_conns".to_string(),
        serde_json::Value::from(v.entry.php.max_idle_conns as u64),
    );
    root.insert(
        "resolve_root_symlink".to_string(),
        serde_json::Value::Bool(v.entry.php.resolve_root_symlink),
    );
    root.insert(
        "allow_x_accel_redirect".to_string(),
        serde_json::Value::Bool(v.entry.php.allow_x_accel_redirect),
    );
    root.insert(
        "x_accel_prefix".to_string(),
        serde_json::Value::String(v.entry.php.x_accel_prefix.clone()),
    );

    root.insert(
        "cache_enabled".to_string(),
        serde_json::Value::Bool(v.entry.cache.enabled),
    );
    root.insert(
        "cache_expire".to_string(),
        serde_json::Value::from(v.entry.cache.expire),
    );

    root.insert("ssl_enabled".to_string(), serde_json::Value::Bool(has_ssl));
    root.insert(
        "ssl_cert".to_string(),
        serde_json::Value::String(v.entry.ssl.certificate.clone()),
    );
    root.insert(
        "ssl_key".to_string(),
        serde_json::Value::String(v.entry.ssl.key.clone()),
    );

    root.insert(
        "force_https".to_string(),
        serde_json::Value::Bool(v.entry.security.force_https),
    );
    root.insert(
        "hotlink_protection".to_string(),
        serde_json::Value::Bool(v.entry.security.hotlink_protection),
    );
    root.insert(
        "allow_ips".to_string(),
        serde_json::json!(v.entry.security.allow_ips),
    );
    root.insert(
        "deny_ips".to_string(),
        serde_json::json!(v.entry.security.deny_ips),
    );
    root.insert(
        "waf_enabled".to_string(),
        serde_json::json!(v.entry.security.waf_enabled),
    );
    root.insert(
        "wp_brute_force".to_string(),
        serde_json::Value::Bool(v.entry.security.wp_brute_force),
    );
    root.insert(
        "waf_exclude_paths".to_string(),
        serde_json::json!(v.entry.security.waf_exclude_paths),
    );

    root.insert(
        "proxy_enabled".to_string(),
        serde_json::Value::Bool(v.entry.proxy.enabled),
    );
    root.insert(
        "proxy_upstream".to_string(),
        serde_json::Value::String(v.entry.proxy.upstream.clone()),
    );
    root.insert(
        "proxy_path_prefix".to_string(),
        serde_json::Value::String(v.entry.proxy.path_prefix.clone()),
    );
    root.insert(
        "preserve_host".to_string(),
        serde_json::Value::Bool(v.entry.proxy.preserve_host),
    );
    root.insert(
        "websocket".to_string(),
        serde_json::Value::Bool(v.entry.proxy.websocket),
    );

    root.insert(
        "rewrite_enabled".to_string(),
        serde_json::Value::Bool(v.entry.rewrite.enabled),
    );
    root.insert(
        "try_files".to_string(),
        serde_json::Value::Bool(v.entry.rewrite.try_files),
    );
    root.insert(
        "htaccess".to_string(),
        serde_json::Value::Bool(v.entry.rewrite.htaccess),
    );

    root.insert(
        "logging_enabled".to_string(),
        serde_json::Value::Bool(v.entry.logging.enabled),
    );
    root.insert(
        "access_log".to_string(),
        serde_json::Value::String(v.entry.logging.access_log.clone()),
    );
    root.insert(
        "error_log".to_string(),
        serde_json::Value::String(v.entry.logging.error_log.clone()),
    );
    root.insert(
        "log_format".to_string(),
        serde_json::Value::String(v.entry.logging.format.clone()),
    );
    root.insert(
        "max_log_size_mb".to_string(),
        serde_json::Value::from(v.entry.logging.max_log_size_mb),
    );
    root.insert(
        "also_write_global".to_string(),
        serde_json::Value::Bool(v.entry.logging.also_write_global),
    );

    root.insert(
        "http2".to_string(),
        serde_json::Value::Bool(v.entry.tls.http2),
    );
    root.insert(
        "strict_sni".to_string(),
        serde_json::Value::Bool(v.entry.tls.strict_sni),
    );
    root.insert(
        "tls_min_version".to_string(),
        serde_json::Value::String(v.entry.tls.min_version.clone()),
    );

    root.insert(
        "precompressed".to_string(),
        serde_json::Value::Bool(v.entry.static_files.precompressed),
    );
    root.insert(
        "brotli".to_string(),
        serde_json::Value::Bool(v.entry.static_files.brotli),
    );
    root.insert(
        "gzip".to_string(),
        serde_json::Value::Bool(v.entry.static_files.gzip),
    );
    root.insert(
        "autoindex".to_string(),
        serde_json::Value::Bool(v.entry.static_files.autoindex),
    );
    root.insert(
        "sendfile".to_string(),
        serde_json::Value::Bool(v.entry.static_files.sendfile),
    );

    root.insert(
        "security_headers".to_string(),
        serde_json::Value::Bool(v.entry.headers.security_headers),
    );
    root.insert(
        "hsts".to_string(),
        serde_json::Value::Bool(v.entry.headers.hsts),
    );

    root.insert(
        "error_docs_enabled".to_string(),
        serde_json::Value::Bool(v.entry.error_docs.enabled),
    );
    root.insert(
        "error_docs_dir".to_string(),
        serde_json::Value::String(v.entry.error_docs.dir.clone()),
    );

    serde_json::to_string(&serde_json::Value::Object(root)).unwrap_or_else(|_| "{}".to_string())
}

fn classify_ban_reason_key(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("slowloris") {
        "reason_slowloris"
    } else if lower.contains("rate") || lower.contains("limit") {
        "reason_ratelimit"
    } else if lower.contains("brute") || lower.contains("wp-login") || lower.contains("xmlrpc") {
        "reason_bruteforce"
    } else {
        "reason_waf"
    }
}

async fn write_vhost_atomic(vhosts_dir: &Path, domain: &str, entry: &VHostEntry) -> Result<(), String> {
    write_vhost_atomic_to_file(vhosts_dir, &format!("{}.toml", domain), domain, entry).await
}

async fn write_vhost_atomic_to_file(
    vhosts_dir: &Path,
    file_name: &str,
    domain: &str,
    entry: &VHostEntry,
) -> Result<(), String> {
    tokio::fs::create_dir_all(vhosts_dir)
        .await
        .map_err(|e| format!("vhosts dizini oluşturulamadı: {}", e))?;

    let toml_text = serialize_vhost_toml(entry)
        .map_err(|e| format!("TOML serileştirme hatası: {}", e))?;
    let content = format!(
        "# ZMax Server API tarafından otomatik yönetilen Sanal Konak ({})\n{}",
        domain, toml_text
    );

    let safe_file = if file_name.trim().is_empty()
        || file_name.contains('/')
        || file_name.contains('\\')
        || file_name.contains("..")
    {
        format!("{}.toml", domain)
    } else {
        file_name.to_string()
    };
    let target = vhosts_dir.join(&safe_file);
    let tmp_path = vhosts_dir.join(format!(".{}.tmp", safe_file));
    tokio::fs::write(&tmp_path, content.as_bytes())
        .await
        .map_err(|e| format!("Geçici vHost dosyası yazılamadı: {}", e))?;
    if let Err(e) = tokio::fs::rename(&tmp_path, &target).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(format!("vHost dosyası taşınamadı: {}", e));
    }
    Ok(())
}

fn percent_decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query_param(query: &str, key: &str) -> Option<String> {
    let trimmed = query.strip_prefix('?').unwrap_or(query);
    if trimmed.is_empty() {
        return None;
    }
    for pair in trimmed.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if percent_decode_component(raw_k) == key {
            return Some(percent_decode_component(raw_v));
        }
    }
    None
}

fn has_parent_dir_traversal(path: &str) -> bool {
    path.contains('\0') || path.split(['/', '\\']).any(|seg| seg == "..")
}

fn merge_section_object(
    root: &mut serde_json::Map<String, serde_json::Value>,
    section_key: &str,
    patch: &serde_json::Value,
) -> Result<(), String> {
    let patch_obj = patch.as_object().ok_or_else(|| {
        format!("'{}' alani bir JSON nesnesi ({{...}}) olmalidir", section_key)
    })?;
    let target_entry = root
        .entry(section_key.to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !target_entry.is_object() {
        *target_entry = serde_json::Value::Object(serde_json::Map::new());
    }
    if let Some(target_map) = target_entry.as_object_mut() {
        for (k, v) in patch_obj {
            target_map.insert(k.clone(), v.clone());
        }
    }
    Ok(())
}

fn val_as_str(v: &serde_json::Value, field: &str) -> Result<String, String> {
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("'{}' alani metin (string) olmalidir", field))
}

fn val_as_bool(v: &serde_json::Value, field: &str) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("'{}' alani mantiksal (bool) olmalidir", field))
}

fn val_as_u64(v: &serde_json::Value, field: &str) -> Result<u64, String> {
    v.as_u64()
        .ok_or_else(|| format!("'{}' alani negatif olmayan tamsayi olmalidir", field))
}

fn val_as_usize(v: &serde_json::Value, field: &str) -> Result<usize, String> {
    let n = val_as_u64(v, field)?;
    usize::try_from(n).map_err(|_| format!("'{}' degeri tasma sinirini asiyor", field))
}

fn val_as_string_list(v: &serde_json::Value, field: &str) -> Result<Vec<String>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| format!("'{}' alani dizi ([...]) olmalidir", field))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| format!("'{}' dizisi yalnizca metin icermelidir", field))?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn merge_vhost_json_patch(
    base: &VHostEntry,
    domain: &str,
    body: &[u8],
) -> Result<VHostEntry, String> {
    let parsed: serde_json::Value = if body.iter().all(|b| b.is_ascii_whitespace()) {
        serde_json::json!({})
    } else {
        serde_json::from_slice(body)
            .map_err(|e| format!("Gecersiz JSON govdesi: {}", e))?
    };
    let obj = parsed
        .as_object()
        .ok_or_else(|| "JSON govdesi nesne ({...}) olmalidir".to_string())?;

    let mut base_map = match serde_json::to_value(base) {
        Ok(serde_json::Value::Object(m)) => m,
        Ok(_) => return Err("Temel vHost serilestirme bicimi hatali".to_string()),
        Err(e) => return Err(format!("Temel vHost serilestirilemedi: {}", e)),
    };

    if let Some(v) = obj.get("aliases") {
        base_map.insert("aliases".to_string(), v.clone());
    }
    if let Some(v) = obj.get("document_root") {
        base_map.insert("document_root".to_string(), v.clone());
    }
    if let Some(v) = obj.get("index_files") {
        base_map.insert("index_files".to_string(), v.clone());
    }

    for section in [
        "cache",
        "php",
        "ssl",
        "security",
        "rewrite",
        "proxy",
        "headers",
        "logging",
        "error_docs",
        "tls",
        "static",
    ] {
        if let Some(patch) = obj.get(section) {
            merge_section_object(&mut base_map, section, patch)?;
        }
    }
    if let Some(patch) = obj.get("static_files") {
        merge_section_object(&mut base_map, "static", patch)?;
    }

    let mut entry: VHostEntry = serde_json::from_value(serde_json::Value::Object(base_map))
        .map_err(|e| format!("vHost alanlari ayristirilamadi: {}", e))?;
    entry.name = domain.to_string();

    // Geriye dönük düz kısayol alanlarını uygula
    if let Some(v) = obj.get("cache_enabled") {
        entry.cache.enabled = val_as_bool(v, "cache_enabled")?;
    }
    if let Some(v) = obj.get("cache_expire") {
        entry.cache.expire = val_as_u64(v, "cache_expire")?;
    }

    if let Some(v) = obj.get("php_enabled") {
        entry.php.enabled = val_as_bool(v, "php_enabled")?;
    }
    if let Some(v) = obj.get("php_sapi") {
        entry.php.sapi = val_as_str(v, "php_sapi")?;
    }
    if let Some(v) = obj.get("php_upstream") {
        entry.php.upstream = val_as_str(v, "php_upstream")?;
    }
    if let Some(v) = obj.get("php_timeout") {
        entry.php.timeout = val_as_u64(v, "php_timeout")?;
    }
    if let Some(v) = obj.get("php_upstreams").or_else(|| obj.get("upstreams")) {
        entry.php.upstreams = val_as_string_list(v, "upstreams")?;
    }
    if let Some(v) = obj.get("lb_policy") {
        entry.php.lb_policy = val_as_str(v, "lb_policy")?;
    }
    if let Some(v) = obj.get("dial_timeout_ms") {
        entry.php.dial_timeout_ms = val_as_u64(v, "dial_timeout_ms")?;
    }
    if let Some(v) = obj.get("io_timeout_secs") {
        entry.php.io_timeout_secs = val_as_u64(v, "io_timeout_secs")?;
    }
    if let Some(v) = obj.get("keep_conn") {
        entry.php.keep_conn = val_as_bool(v, "keep_conn")?;
    }
    if let Some(v) = obj.get("max_idle_conns") {
        entry.php.max_idle_conns = val_as_usize(v, "max_idle_conns")?;
    }
    if let Some(v) = obj.get("resolve_root_symlink") {
        entry.php.resolve_root_symlink = val_as_bool(v, "resolve_root_symlink")?;
    }
    if let Some(v) = obj.get("allow_x_accel_redirect") {
        entry.php.allow_x_accel_redirect = val_as_bool(v, "allow_x_accel_redirect")?;
    }
    if let Some(v) = obj.get("x_accel_prefix") {
        entry.php.x_accel_prefix = val_as_str(v, "x_accel_prefix")?;
    }

    if let Some(v) = obj.get("ssl_cert") {
        entry.ssl.certificate = val_as_str(v, "ssl_cert")?;
    }
    if let Some(v) = obj.get("ssl_key") {
        entry.ssl.key = val_as_str(v, "ssl_key")?;
    }

    if let Some(v) = obj.get("hotlink_protection") {
        entry.security.hotlink_protection = val_as_bool(v, "hotlink_protection")?;
    }
    if let Some(v) = obj.get("force_https") {
        entry.security.force_https = val_as_bool(v, "force_https")?;
    }
    if let Some(v) = obj.get("allow_ips") {
        entry.security.allow_ips = val_as_string_list(v, "allow_ips")?;
    }
    if let Some(v) = obj.get("deny_ips") {
        entry.security.deny_ips = val_as_string_list(v, "deny_ips")?;
    }
    if let Some(v) = obj.get("waf_enabled") {
        entry.security.waf_enabled = match v {
            serde_json::Value::Null => None,
            serde_json::Value::Bool(b) => Some(*b),
            _ => {
                return Err("'waf_enabled' alani bool veya null olmalidir".to_string());
            }
        };
    }
    if let Some(v) = obj.get("wp_brute_force") {
        entry.security.wp_brute_force = val_as_bool(v, "wp_brute_force")?;
    }
    if let Some(v) = obj.get("waf_exclude_paths") {
        entry.security.waf_exclude_paths = val_as_string_list(v, "waf_exclude_paths")?;
    }

    if let Some(v) = obj.get("logging_enabled") {
        entry.logging.enabled = val_as_bool(v, "logging_enabled")?;
    }
    if let Some(v) = obj.get("access_log") {
        entry.logging.access_log = val_as_str(v, "access_log")?;
    }
    if let Some(v) = obj.get("error_log") {
        entry.logging.error_log = val_as_str(v, "error_log")?;
    }
    if let Some(v) = obj.get("log_format") {
        entry.logging.format = val_as_str(v, "log_format")?;
    }
    if let Some(v) = obj.get("max_log_size_mb") {
        entry.logging.max_log_size_mb = val_as_u64(v, "max_log_size_mb")?;
    }
    if let Some(v) = obj.get("also_write_global") {
        entry.logging.also_write_global = val_as_bool(v, "also_write_global")?;
    }

    if let Some(v) = obj.get("http2") {
        entry.tls.http2 = val_as_bool(v, "http2")?;
    }
    if let Some(v) = obj.get("strict_sni") {
        entry.tls.strict_sni = val_as_bool(v, "strict_sni")?;
    }
    if let Some(v) = obj.get("tls_min_version") {
        entry.tls.min_version = val_as_str(v, "tls_min_version")?;
    }

    if let Some(v) = obj.get("precompressed") {
        entry.static_files.precompressed = val_as_bool(v, "precompressed")?;
    }
    if let Some(v) = obj.get("brotli") {
        entry.static_files.brotli = val_as_bool(v, "brotli")?;
    }
    if let Some(v) = obj.get("gzip") {
        entry.static_files.gzip = val_as_bool(v, "gzip")?;
    }
    if let Some(v) = obj.get("autoindex") {
        entry.static_files.autoindex = val_as_bool(v, "autoindex")?;
    }
    if let Some(v) = obj.get("sendfile") {
        entry.static_files.sendfile = val_as_bool(v, "sendfile")?;
    }

    if let Some(v) = obj.get("rewrite_enabled") {
        entry.rewrite.enabled = val_as_bool(v, "rewrite_enabled")?;
    }
    if let Some(v) = obj.get("try_files") {
        entry.rewrite.try_files = val_as_bool(v, "try_files")?;
    }
    if let Some(v) = obj.get("htaccess") {
        entry.rewrite.htaccess = val_as_bool(v, "htaccess")?;
    }

    if let Some(v) = obj.get("proxy_enabled") {
        entry.proxy.enabled = val_as_bool(v, "proxy_enabled")?;
    }
    if let Some(v) = obj.get("proxy_upstream") {
        entry.proxy.upstream = val_as_str(v, "proxy_upstream")?;
    }
    if let Some(v) = obj.get("proxy_path_prefix") {
        entry.proxy.path_prefix = val_as_str(v, "proxy_path_prefix")?;
    }
    if let Some(v) = obj.get("preserve_host") {
        entry.proxy.preserve_host = val_as_bool(v, "preserve_host")?;
    }
    if let Some(v) = obj.get("websocket") {
        entry.proxy.websocket = val_as_bool(v, "websocket")?;
    }

    if let Some(v) = obj.get("security_headers") {
        entry.headers.security_headers = val_as_bool(v, "security_headers")?;
    }
    if let Some(v) = obj.get("hsts") {
        entry.headers.hsts = val_as_bool(v, "hsts")?;
    }

    if let Some(v) = obj.get("error_docs_enabled") {
        entry.error_docs.enabled = val_as_bool(v, "error_docs_enabled")?;
    }
    if let Some(v) = obj.get("error_docs_dir") {
        entry.error_docs.dir = val_as_str(v, "error_docs_dir")?;
    }

    if entry.document_root.contains("..")
        || entry.document_root.contains('\0')
        || entry.document_root.trim().is_empty()
    {
        return Err("Gecersiz document_root yolu".to_string());
    }
    for (label, path_val) in [
        ("logging.access_log", entry.logging.access_log.as_str()),
        ("logging.error_log", entry.logging.error_log.as_str()),
        ("error_docs.dir", entry.error_docs.dir.as_str()),
        ("ssl.certificate", entry.ssl.certificate.as_str()),
        ("ssl.key", entry.ssl.key.as_str()),
    ] {
        if has_parent_dir_traversal(path_val) {
            return Err(format!("Gecersiz {} dosya yolu: '{}'", label, path_val));
        }
    }

    entry.validate()?;
    if entry.php.enabled && entry.effective_php_upstreams().is_empty() {
        return Err("PHP etkin ancak upstream bos olamaz".to_string());
    }
    if entry.proxy.enabled && entry.proxy.upstream.trim().is_empty() {
        return Err("Proxy etkin ancak upstream bos olamaz".to_string());
    }

    Ok(entry)
}

/// Ters vekil arkasındaki panel/API isteklerinden yapılandırılmış `proxy_prefix` önekini soyar.
pub fn normalize_panel_request_path(raw_path: &str, proxy_prefix: &str) -> String {
    let prefix = proxy_prefix.trim().trim_end_matches('/');
    if prefix.is_empty() || prefix == "/" {
        return raw_path.to_string();
    }
    if raw_path == prefix {
        return "/".to_string();
    }
    if let Some(rest) = raw_path.strip_prefix(prefix) {
        if rest.is_empty() || rest == "/" {
            return "/".to_string();
        }
        if rest.starts_with('/') {
            return rest.to_string();
        }
    }
    raw_path.to_string()
}

/// Hem WebAdmin (`/api/*`) hem Kontrol API (`/api/v1/*`) isteklerini tek noktadan işler.
/// Eşleşen bir API yolu varsa `Ok(true)` döner; WebAdmin statik dosyası sunulacaksa `Ok(false)` döner.
pub async fn handle_api_route<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    strict_api_only: bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let (cors_origin, expected_token, require_token, proxy_prefix) = {
        let rt = state.runtime.read().await;
        let (tok, req_tok, prefix) = if strict_api_only {
            (
                rt.auth.api_token.clone(),
                rt.auth.api_require_token,
                rt.config.listeners.api.proxy_prefix.clone(),
            )
        } else {
            (
                rt.auth.admin_token.clone(),
                rt.auth.admin_require_token,
                rt.config.listeners.admin.proxy_prefix.clone(),
            )
        };
        (
            rt.config.listeners.api.cors_allow_origin.clone(),
            tok,
            req_tok,
            prefix,
        )
    };

    let req_path = normalize_panel_request_path(&req.path, &proxy_prefix);
    let is_api_or_metrics_path = req_path.starts_with("/api/") || req_path == "/metrics";
    if !is_api_or_metrics_path && !strict_api_only {
        return Ok(false);
    }

    // CORS Preflight
    if req.method == "OPTIONS" {
        let origin = if cors_origin.is_empty() { "*" } else { &cors_origin };
        let resp = format!(
            "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-ZMax-Token, X-ZMax-Purge-Key\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            origin
        );
        socket.write_all(resp.as_bytes()).await?;
        return Ok(true);
    }

    // 1. Public Health Check (Panel / Systemd / Load Balancer probe)
    if req_path == "/api/v1/health" || (strict_api_only && req_path == "/") {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let (vhosts_len, mods_len) = {
            let rt = state.runtime.read().await;
            (rt.vhosts.len(), rt.modules.len())
        };
        let json = format!(
            r#"{{"ok":true,"status":"ok","engine":"zmax","version":"1.0.01","pid":{},"uptime_seconds":{},"vhosts":{},"modules":{}}}"#,
            std::process::id(),
            uptime_secs,
            vhosts_len,
            mods_len
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // Token kontrolü (yapılandırılmışsa veya dinleyici loopback dışındaysa zorunlu)
    if !is_authorized(req, &expected_token, require_token) {
        let err = r#"{"ok":false,"error":"Yetkisiz erisim: Gecerli Bearer veya X-ZMax-Token gerekli."}"#;
        send_json_response(socket, 401, "Unauthorized", &cors_origin, err).await?;
        return Ok(true);
    }

    // 1b. Prometheus Metrik Ucu (/metrics ve /api/v1/metrics)
    if (req_path == "/metrics" || req_path == "/api/v1/metrics") && req.method == "GET" {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let total = state.stats.total_requests.load(Ordering::Relaxed);
        let hits = state.stats.cache_hits.load(Ordering::Relaxed);
        let misses = state.stats.cache_misses.load(Ordering::Relaxed);
        let banned_count = state.ban_manager.list_banned().len();
        let (vhosts_len, mods_len) = {
            let rt = state.runtime.read().await;
            (rt.vhosts.len(), rt.modules.len())
        };
        let body = format!(
            "# HELP zmax_uptime_seconds ZMax sunucusunun calisma suresi (saniye).\n\
             # TYPE zmax_uptime_seconds gauge\n\
             zmax_uptime_seconds {}\n\
             # HELP zmax_requests_total Toplam islenen HTTP istek sayisi.\n\
             # TYPE zmax_requests_total counter\n\
             zmax_requests_total {}\n\
             # HELP zmax_cache_hits_total L1/L2 onbellek isabet sayisi.\n\
             # TYPE zmax_cache_hits_total counter\n\
             zmax_cache_hits_total {}\n\
             # HELP zmax_cache_misses_total L1/L2 onbellek iska sayisi.\n\
             # TYPE zmax_cache_misses_total counter\n\
             zmax_cache_misses_total {}\n\
             # HELP zmax_vhosts_loaded Yuklu sanal konak (vHost) sayisi.\n\
             # TYPE zmax_vhosts_loaded gauge\n\
             zmax_vhosts_loaded {}\n\
             # HELP zmax_modules_loaded Yuklu modul sayisi.\n\
             # TYPE zmax_modules_loaded gauge\n\
             zmax_modules_loaded {}\n\
             # HELP zmax_banned_ips Aktif yasakli IP sayisi.\n\
             # TYPE zmax_banned_ips gauge\n\
             zmax_banned_ips {}\n",
            uptime_secs, total, hits, misses, vhosts_len, mods_len, banned_count
        );
        send_response_with_content_type(
            socket,
            200,
            "OK",
            "text/plain; version=0.0.4; charset=utf-8",
            &cors_origin,
            &body,
        )
        .await?;
        return Ok(true);
    }

    // 2. Durum ve Telemetri (/api/status ve /api/v1/status)
    if (req_path == "/api/status" || req_path == "/api/v1/status") && req.method == "GET" {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let total = state.stats.total_requests.load(Ordering::Relaxed);
        let hits = state.stats.cache_hits.load(Ordering::Relaxed);
        let misses = state.stats.cache_misses.load(Ordering::Relaxed);
        let banned_count = state.ban_manager.list_banned().len();

        let rt = state.runtime.read().await;
        let workers = if rt.config.server.workers == 0 {
            zmax_runtime::detect_worker_threads()
        } else {
            rt.config.server.workers
        };
        let cfg = &rt.config;
        let json = format!(
            r#"{{"ok":true,"running":true,"engine":"zmax","version":"1.0.01","pid":{},"uptime_seconds":{},"total_requests":{},"cache_hits":{},"cache_misses":{},"workers":{},"ram_mb":12,"vhosts_loaded":{},"active_sites":{},"modules_loaded":{},"banned_count":{},"ports":{{"http":{},"https":{},"admin":{},"api":{}}},"listeners":{{"http":"{}:{}","https":"{}:{}","admin":"{}:{}","api":"{}:{}"}},"cache":{{"enabled":{},"memory_cache_mb":{},"default_ttl_seconds":{},"disk_enabled":{}}},"security":{{"rate_limit_enabled":{},"rate_limit_per_minute":{},"keep_alive_timeout_sec":{},"slowloris_header_timeout_sec":{},"max_body_size_mb":{}}},"vhosts_dir":"{}","config_path":"{}"}}"#,
            std::process::id(),
            uptime_secs,
            total,
            hits,
            misses,
            workers,
            rt.vhosts.len(),
            rt.vhosts.len(),
            rt.modules.len(),
            banned_count,
            cfg.listeners.http.port,
            cfg.listeners.https.port,
            cfg.listeners.admin.port,
            cfg.listeners.api.port,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            cfg.cache.enabled,
            cfg.cache.memory_cache_mb,
            cfg.cache.default_ttl_seconds,
            state.cache.disk_dir().is_some(),
            cfg.security.rate_limit_enabled,
            cfg.security.rate_limit_per_minute,
            cfg.security.keep_alive_timeout_sec,
            cfg.security.slowloris_header_timeout_sec,
            cfg.security.max_body_size_mb,
            json_escape(&rt.vhosts_dir.to_string_lossy()),
            json_escape(&rt.conf_path.to_string_lossy()),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 3. Modüller Listesi (GET /api/v1/modules ve /api/modules)
    if (req_path == "/api/v1/modules" || req_path == "/api/modules") && req.method == "GET" {
        let rt = state.runtime.read().await;
        let items: Vec<String> = rt
            .modules
            .list()
            .iter()
            .map(|m| {
                let cat_key = module_category_key(&m.meta.name, &m.meta.category);
                let rel_file = format!("modules/{}", m.file_name);
                format!(
                    r#"{{"name":"{}","version":"{}","category":"{}","categoryKey":"{}","file":"{}","enabled":{}}}"#,
                    json_escape(&m.meta.name),
                    json_escape(&m.meta.version),
                    json_escape(&m.meta.category),
                    cat_key,
                    json_escape(&rel_file),
                    m.meta.enabled
                )
            })
            .collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"modules":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 3b. Modül Aç/Kapat (POST /api/v1/modules/toggle)
    if (req_path == "/api/v1/modules/toggle" || req_path == "/api/modules/toggle")
        && req.method == "POST"
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let Some(name) = extract_json_string(&body_str, "name") else {
            let err = r#"{"ok":false,"error":"Modul adi (name) zorunludur."}"#;
            send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
            return Ok(true);
        };
        let desired = extract_json_bool(&body_str, "enabled");

        let mut rt = state.runtime.write().await;
        let res = match desired {
            Some(en) => rt.modules.set_enabled(&name, en).map(|()| en),
            None => rt.modules.toggle_enabled(&name),
        };
        match res {
            Ok(new_state) => {
                let cfg_clone = rt.config.clone();
                let policies = compile_policies(&cfg_clone, &rt.modules);
                let new_rate = policies.effective_rate_limit;
                let redis_client = build_redis_client(&rt.modules);
                rt.policies = policies;
                rt.redis_client = redis_client;
                drop(rt);

                let mut limiter = state.limiter.write().await;
                *limiter = zmax_security::RateLimiter::new(new_rate);

                let json = format!(
                    r#"{{"ok":true,"name":"{}","enabled":{}}}"#,
                    json_escape(&name),
                    new_state
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(msg) => {
                drop(rt);
                let json = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&msg));
                send_json_response(socket, 404, "Not Found", &cors_origin, &json).await?;
            }
        }
        return Ok(true);
    }

    // 4. Yasaklı IP Listesi ve Yasak Kaldırma (/api/v1/security/bans, /api/v1/security/unban)
    if (req_path == "/api/v1/security/bans" || req_path == "/api/security/bans")
        && req.method == "GET"
    {
        let now_hms = current_hms_utc();
        let bans = state.ban_manager.list_banned();
        let items: Vec<String> = bans
            .iter()
            .map(|b| {
                let reason_key = classify_ban_reason_key(&b.reason);
                let rem_json = match b.remaining_secs {
                    Some(s) => s.to_string(),
                    None => "null".to_string(),
                };
                format!(
                    r#"{{"ip":"{}","reasonKey":"{}","reason":"{}","permanent":{},"remaining_secs":{},"time":"{}"}}"#,
                    json_escape(&b.ip.to_string()),
                    reason_key,
                    json_escape(&b.reason),
                    b.permanent,
                    rem_json,
                    now_hms
                )
            })
            .collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"bans":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    if (req_path == "/api/v1/security/unban" || req_path == "/api/security/unban")
        && req.method == "POST"
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_ip = extract_json_string(&body_str, "ip").unwrap_or_default();
        let Ok(ip) = raw_ip.trim().parse::<IpAddr>() else {
            let err = r#"{"ok":false,"error":"Gecersiz IP adresi."}"#;
            send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
            return Ok(true);
        };
        let existed = state.ban_manager.unban(ip);
        state.wp_guard.reset(ip);
        let json = format!(
            r#"{{"ok":true,"ip":"{}","unbanned":{}}}"#,
            json_escape(&ip.to_string()),
            existed
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 5. Canlı ve Dosya Tabanlı Erişim/Hata Logları (GET /api/v1/logs ve /api/logs)
    if (req_path == "/api/v1/logs" || req_path == "/api/logs") && req.method == "GET" {
        let domain_q = parse_query_param(&req.query, "domain")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let kind_q = parse_query_param(&req.query, "kind")
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let lines_q = parse_query_param(&req.query, "lines")
            .and_then(|s| s.trim().parse::<usize>().ok());

        if domain_q.is_some() || kind_q.as_deref() == Some("error") {
            let kind = kind_q.unwrap_or_else(|| "access".to_string());
            if kind != "access" && kind != "error" {
                let err = r#"{"ok":false,"error":"Gecersiz kind parametresi (access veya error olmali)"}"#;
                send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
                return Ok(true);
            }
            let limit = lines_q.unwrap_or(100).min(5000);

            let (resolved_domain, target_path) = if let Some(raw_domain) = domain_q {
                let domain = match validate_domain(&raw_domain) {
                    Ok(d) => d,
                    Err(msg) => {
                        let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                        send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                        return Ok(true);
                    }
                };

                let rt = state.runtime.read().await;
                let found = rt.vhosts.iter().find(|v| {
                    v.entry.name.eq_ignore_ascii_case(&domain)
                        || v.entry
                            .aliases
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(&domain))
                });
                let vhost = match found {
                    Some(v) => v,
                    None => {
                        let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
                        send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
                        return Ok(true);
                    }
                };

                let raw_rel = if kind == "error" {
                    vhost.entry.logging.error_log.trim()
                } else {
                    vhost.entry.logging.access_log.trim()
                };
                let path = if !raw_rel.is_empty() {
                    resolve_path(&state.base_dir, raw_rel)
                } else {
                    let per_vhost = resolve_path(
                        &state.base_dir,
                        &format!("logs/{}.{}.log", vhost.entry.name, kind),
                    );
                    if per_vhost.exists() {
                        per_vhost
                    } else {
                        let global_rel = if kind == "error" {
                            if rt.config.logging.error_log.trim().is_empty() {
                                "logs/error.log"
                            } else {
                                rt.config.logging.error_log.trim()
                            }
                        } else if rt.config.logging.access_log.trim().is_empty() {
                            "logs/access.log"
                        } else {
                            rt.config.logging.access_log.trim()
                        };
                        resolve_path(&state.base_dir, global_rel)
                    }
                };
                (Some(vhost.entry.name.clone()), path)
            } else {
                let rt = state.runtime.read().await;
                let global_rel = if rt.config.logging.error_log.trim().is_empty() {
                    "logs/error.log"
                } else {
                    rt.config.logging.error_log.trim()
                };
                (None, resolve_path(&state.base_dir, global_rel))
            };

            state.log_manager.flush().await;
            let tail_lines = match state.log_manager.read_tail_lines(&target_path, limit).await {
                Ok(lines) => lines,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("Log dosyasi okunamadi: {}", e)
                    })
                    .to_string();
                    send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err)
                        .await?;
                    return Ok(true);
                }
            };

            let json = serde_json::json!({
                "ok": true,
                "domain": resolved_domain,
                "kind": kind,
                "path": target_path.to_string_lossy(),
                "count": tail_lines.len(),
                "lines": tail_lines,
                "logs": tail_lines
            })
            .to_string();
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        }

        let snapshot: Vec<AccessLogRecord> = state
            .access_logs
            .lock()
            .map(|q| {
                let take_n = lines_q.unwrap_or(MAX_IN_MEMORY_LOGS).min(MAX_IN_MEMORY_LOGS);
                q.iter().take(take_n).cloned().collect()
            })
            .unwrap_or_default();
        let items: Vec<serde_json::Value> = snapshot
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "time": entry.time,
                    "ip": entry.ip,
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                    "latency": entry.latency,
                    "bytes_sent": entry.bytes_sent,
                    "request_id": entry.request_id,
                    "domain": entry.domain
                })
            })
            .collect();
        let json = serde_json::json!({
            "ok": true,
            "kind": "access",
            "count": items.len(),
            "logs": items
        })
        .to_string();
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 5b. Log Dosyalarını Yeniden Açma / Logrotate (POST /api/v1/logs/reopen ve /api/logs/reopen)
    if (req_path == "/api/v1/logs/reopen" || req_path == "/api/logs/reopen") && req.method == "POST" {
        state.log_manager.reopen_all().await;
        let dropped = state.log_manager.dropped_count();
        let json = serde_json::json!({
            "ok": true,
            "status": "reopened",
            "dropped": dropped,
            "message": "Tum log dosyalari flush edildi ve yeniden acilmak uzere serbest birakildi."
        })
        .to_string();
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 6. Port Keşif ve Çakışma Matrisi (/api/v1/ports)
    if req_path == "/api/v1/ports" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let panel_ports: Vec<String> = KNOWN_PANEL_PORTS.iter().map(|p| p.to_string()).collect();
        let active_ports = [
            cfg.listeners.http.port,
            cfg.listeners.https.port,
            cfg.listeners.admin.port,
            cfg.listeners.api.port,
        ];
        let collision = active_ports
            .iter()
            .any(|p| KNOWN_PANEL_PORTS.contains(p));
        let json = format!(
            r#"{{"ok":true,"collision_detected":{},"ports":{{"http":{},"https":{},"admin":{},"api":{}}},"listeners":{{"http":"{}:{}","https":"{}:{}","admin":"{}:{}","api":"{}:{}"}},"tls":{{"https":{},"admin":{},"api":{}}},"unix_socket":"{}","known_panel_ports":[{}]}}"#,
            collision,
            cfg.listeners.http.port,
            cfg.listeners.https.port,
            cfg.listeners.admin.port,
            cfg.listeners.api.port,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            cfg.listeners.https.ssl,
            cfg.listeners.admin.ssl,
            cfg.listeners.api.ssl,
            json_escape(&cfg.listeners.api.unix_socket),
            panel_ports.join(","),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 7. Önbellek Temizleme (/api/purge veya /api/v1/cache/purge — domain+tag, domain, tag, uri/key veya tümü)
    if (req_path == "/api/purge" || req_path == "/api/v1/cache/purge") && req.method == "POST" {
        let payload: serde_json::Value = if req.body.iter().all(|b| b.is_ascii_whitespace()) {
            serde_json::json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("Gecersiz JSON govdesi: {}", e)
                    })
                    .to_string();
                    send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                    return Ok(true);
                }
            }
        };

        let domain_opt = payload
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let tag_opt = payload
            .get("tag")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let tags_opt = payload
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            })
            .filter(|v| !v.is_empty());
        let uri_opt = payload
            .get("uri")
            .or_else(|| payload.get("key"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let redis_opt = state.runtime.read().await.redis_client.clone();

        match (domain_opt, tag_opt, tags_opt, uri_opt) {
            (Some(domain), Some(tag), _, _) => {
                let purged = state.cache.purge_by_domain_tag(&domain, &tag).await;
                if let Some(redis) = redis_opt {
                    let ev = zmax_redis::ClusterSyncEvent::PurgeTag {
                        domain: domain.clone(),
                        tag: tag.clone(),
                    };
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_event(&ev),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_tag",
                    "domain": domain,
                    "tag": tag,
                    "purged": purged,
                    "message": "Secili alan adi ve etiket onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, Some(tags), _) => {
                let purged = state.cache.purge_by_tags(&domain, &tags).await;
                if let Some(redis) = redis_opt {
                    let d = domain.clone();
                    let t_list = tags.clone();
                    tokio::spawn(async move {
                        for t in t_list {
                            let ev = zmax_redis::ClusterSyncEvent::PurgeTag {
                                domain: d.clone(),
                                tag: t,
                            };
                            let _ = tokio::time::timeout(
                                Duration::from_millis(250),
                                redis.publish_event(&ev),
                            )
                            .await;
                        }
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_tags",
                    "domain": domain,
                    "tags": tags,
                    "purged": purged,
                    "message": "Secili alan adi etiketleri temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, Some(tag), _, _) => {
                let purged = state.cache.purge_by_tag(&tag).await;
                if let Some(redis) = redis_opt {
                    let msg = format!("tag:{}", tag);
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_purge(&msg),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "tag",
                    "tag": tag,
                    "purged": purged,
                    "message": "Secili etiket onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, None, Some(tags), None) => {
                let mut purged = 0;
                for t in &tags {
                    purged += state.cache.purge_by_tag(t).await;
                }
                if let Some(redis) = redis_opt {
                    let t_list = tags.clone();
                    tokio::spawn(async move {
                        for t in t_list {
                            let msg = format!("tag:{}", t);
                            let _ = tokio::time::timeout(
                                Duration::from_millis(250),
                                redis.publish_purge(&msg),
                            )
                            .await;
                        }
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "tags",
                    "tags": tags,
                    "purged": purged,
                    "message": "Secili etiketler onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, None, None) => {
                let purged = state.cache.purge_by_domain_tag(&domain, "*").await;
                if let Some(redis) = redis_opt {
                    let ev = zmax_redis::ClusterSyncEvent::PurgeDomain {
                        domain: domain.clone(),
                    };
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_event(&ev),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain",
                    "domain": domain,
                    "purged": purged,
                    "message": "Secili alan adi onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (_, _, _, Some(target_uri)) => {
                state.cache.purge(&target_uri).await;
                if let Some(redis) = redis_opt {
                    let msg = target_uri.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_purge(&msg),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "key",
                    "key": target_uri,
                    "message": "Secili onbellek anahtari temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, None, None, None) => {
                state.cache.purge_all().await;
                if let Some(redis) = redis_opt {
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_event(&zmax_redis::ClusterSyncEvent::PurgeAll),
                        )
                        .await;
                    });
                }
                let json = r#"{"ok":true,"status":"success","scope":"all","message":"L1 & L2 Onbellegi tamamen temizlendi!"}"#;
                send_json_response(socket, 200, "OK", &cors_origin, json).await?;
                return Ok(true);
            }
        }
    }

    // 8. Yapılandırma, Modüller ve vHost Sıcak Yenileme (/api/reload veya /api/v1/reload)
    if (req_path == "/api/reload" || req_path == "/api/v1/reload") && req.method == "POST" {
        match reload_runtime_state(state).await {
            Ok(vhosts_count) => {
                state.cache.purge_all().await;
                let json = format!(
                    r#"{{"ok":true,"status":"reloaded","vhosts_loaded":{},"message":"Yapilandirma, moduller ve vHost tablosu sifir kesintiyle yenilendi."}}"#,
                    vhosts_count
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(e) => {
                let json = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &json).await?;
            }
        }
        return Ok(true);
    }

    // 9. Aktif Konfigürasyon Okuma (/api/v1/config)
    if req_path == "/api/v1/config" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let token_configured = !rt.auth.api_token.is_empty();
        let json = format!(
            r#"{{"ok":true,"server":{{"server_name":"{}","workers":{},"cpu_affinity":{}}},"listeners":{{"http":{{"enabled":{},"address":"{}","port":{},"reuse_port":{}}},"https":{{"enabled":{},"address":"{}","port":{},"ssl":{}}},"admin":{{"enabled":{},"address":"{}","port":{},"document_root":"{}","require_token":{},"ssl":{},"proxy_prefix":"{}"}},"api":{{"enabled":{},"address":"{}","port":{},"require_token":{},"token_configured":{},"unix_socket":"{}","ssl":{},"proxy_prefix":"{}"}}}},"cache":{{"enabled":{},"memory_cache_mb":{},"default_ttl_seconds":{}}},"security":{{"rate_limit_enabled":{},"rate_limit_per_minute":{},"keep_alive_timeout_sec":{},"block_path_traversal":{},"max_body_size_mb":{}}},"vhosts_dir":"{}"}}"#,
            json_escape(&cfg.server.server_name),
            cfg.server.workers,
            cfg.server.cpu_affinity,
            cfg.listeners.http.enabled,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            cfg.listeners.http.reuse_port,
            cfg.listeners.https.enabled,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            cfg.listeners.https.ssl,
            cfg.listeners.admin.enabled,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.admin.document_root),
            rt.auth.admin_require_token,
            cfg.listeners.admin.ssl,
            json_escape(&cfg.listeners.admin.proxy_prefix),
            cfg.listeners.api.enabled,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            rt.auth.api_require_token,
            token_configured,
            json_escape(&cfg.listeners.api.unix_socket),
            cfg.listeners.api.ssl,
            json_escape(&cfg.listeners.api.proxy_prefix),
            cfg.cache.enabled,
            cfg.cache.memory_cache_mb,
            cfg.cache.default_ttl_seconds,
            cfg.security.rate_limit_enabled,
            cfg.security.rate_limit_per_minute,
            cfg.security.keep_alive_timeout_sec,
            cfg.security.block_path_traversal,
            cfg.security.max_body_size_mb,
            json_escape(&cfg.vhosts_dir.path),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 10. Sanal Konak Listesi (GET /api/v1/vhosts)
    if req_path == "/api/v1/vhosts" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let items: Vec<String> = rt.vhosts.iter().map(format_vhost_json).collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"vhosts":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 11. Yeni Sanal Konak Oluşturma / Güncelleme (POST /api/v1/vhosts veya PUT /api/v1/vhosts/<domain>)
    if (req_path == "/api/v1/vhosts" && req.method == "POST")
        || (req_path.starts_with("/api/v1/vhosts/") && (req.method == "PUT" || req.method == "POST"))
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_domain = req_path
            .strip_prefix("/api/v1/vhosts/")
            .map(|s| s.to_string())
            .or_else(|| extract_json_string(&body_str, "domain"))
            .or_else(|| extract_json_string(&body_str, "name"))
            .unwrap_or_default();

        let domain = match validate_domain(&raw_domain) {
            Ok(d) => d,
            Err(msg) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        let document_root = if let Some(doc_root) = extract_json_string(&body_str, "document_root") {
            if doc_root.contains("..") || doc_root.contains('\0') || doc_root.trim().is_empty() {
                let err = r#"{"ok":false,"error":"Gecersiz document_root yolu"}"#;
                send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
                return Ok(true);
            }
            doc_root
        } else {
            format!("www/{}", domain)
        };

        let base_entry = VHostEntry {
            name: domain.clone(),
            document_root,
            ..VHostEntry::default()
        };

        let entry = match merge_vhost_json_patch(&base_entry, &domain, &req.body) {
            Ok(e) => e,
            Err(e) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        let vhosts_dir = state.runtime.read().await.vhosts_dir.clone();
        if let Err(e) = write_vhost_atomic(&vhosts_dir, &domain, &entry).await {
            let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
            send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err).await?;
            return Ok(true);
        }

        let count = reload_runtime_state(state).await.unwrap_or(0);
        let json = format!(
            r#"{{"ok":true,"status":"saved","domain":"{}","vhosts_loaded":{}}}"#,
            json_escape(&domain),
            count
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 12. Tekil Sanal Konak Okuma veya Silme (GET / DELETE /api/v1/vhosts/<domain>)
    if let Some(raw_domain) = req_path.strip_prefix("/api/v1/vhosts/") {
        let domain = match validate_domain(raw_domain) {
            Ok(d) => d,
            Err(msg) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        if req.method == "GET" {
            let rt = state.runtime.read().await;
            if let Some(found) = rt
                .vhosts
                .iter()
                .find(|v| v.entry.name.eq_ignore_ascii_case(&domain))
            {
                let json = format!(r#"{{"ok":true,"vhost":{}}}"#, format_vhost_json(found));
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            } else {
                let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
                send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
            }
            return Ok(true);
        }

        if req.method == "DELETE" {
            let vhosts_dir = state.runtime.read().await.vhosts_dir.clone();
            let target = vhosts_dir.join(format!("{}.toml", domain));
            if !target.exists() {
                let err = r#"{"ok":false,"error":"Silinecek sanal konak dosyasi bulunamadi"}"#;
                send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
                return Ok(true);
            }
            if let Err(e) = tokio::fs::remove_file(&target).await {
                let err = format!(
                    r#"{{"ok":false,"error":"Dosya silinemedi: {}"}}"#,
                    json_escape(&e.to_string())
                );
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err).await?;
                return Ok(true);
            }
            let count = reload_runtime_state(state).await.unwrap_or(0);
            let json = format!(
                r#"{{"ok":true,"status":"deleted","domain":"{}","vhosts_loaded":{}}}"#,
                json_escape(&domain),
                count
            );
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        }
    }

    // Eşleşmeyen /api/* ucu
    let err = r#"{"ok":false,"error":"Bilinmeyen veya desteklenmeyen API uc noktasi"}"#;
    send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_extractors() {
        let body = r#"{"domain":"site.com","document_root":"www/site","php_enabled":true,"cache_expire":600,"aliases":["www.site.com","m.site.com"]}"#;
        assert_eq!(extract_json_string(body, "domain").as_deref(), Some("site.com"));
        assert_eq!(extract_json_string(body, "document_root").as_deref(), Some("www/site"));
        assert_eq!(extract_json_bool(body, "php_enabled"), Some(true));
        assert_eq!(extract_json_u64(body, "cache_expire"), Some(600));
        assert_eq!(
            extract_json_string_array(body, "aliases"),
            Some(vec!["www.site.com".to_string(), "m.site.com".to_string()])
        );
    }

    #[test]
    fn test_authorization_check() {
        let req = ParsedHttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/status".to_string(),
            query: String::new(),
            version: 1,
            host: "127.0.0.1".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer secret-key".to_string())],
            body: Vec::new(),
            keep_alive: false,
        };
        assert!(is_authorized(&req, "secret-key", true));
        assert!(!is_authorized(&req, "wrong-key", true));
        assert!(is_authorized(&req, "", false));
    }

    #[test]
    fn test_normalize_panel_request_path() {
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console/api/status", "/v1/zmax/console"),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console/api/status", "/v1/zmax/console/"),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console", "/v1/zmax/console"),
            "/"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console/", "/v1/zmax/console"),
            "/"
        );
        assert_eq!(
            normalize_panel_request_path("/api/status", "/v1/zmax/console"),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console2/api/status", "/v1/zmax/console"),
            "/v1/zmax/console2/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/api/status", ""),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/api/status", "/"),
            "/api/status"
        );
    }

    #[tokio::test]
    async fn test_prometheus_metrics_config_ports_and_proxy_prefix_routing() {
        use tokio::io::AsyncReadExt;

        let cfg = ZMaxConfig::parse_toml(
            r#"
[listeners.admin]
enabled = true
address = "127.0.0.1"
port = 19485
ssl = true
tls_cert = "certs/admin.pem"
tls_key = "certs/admin.key"
proxy_prefix = "/v1/zmax/console"
require_token = true
token = "adm-secret-token"

[listeners.api]
enabled = true
address = "127.0.0.1"
port = 19486
ssl = false
proxy_prefix = "/v1/zmax/api"
require_token = true
token = "api-secret-token"
"#,
        )
        .unwrap();

        let modules = LoadedModules::default();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);
        let state = Arc::new(ServerState {
            base_dir: PathBuf::from("."),
            cache: zmax_cache::ZMaxCache::new(1024 * 1024, 60),
            limiter: RwLock::new(zmax_security::RateLimiter::new(1000)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::default()),
            buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
            upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::default()),
            runtime: RwLock::new(RuntimeState {
                config: cfg,
                vhosts: Vec::new(),
                modules,
                policies,
                redis_client: None,
                auth,
                conf_path: PathBuf::from("conf/zmax.toml"),
                vhosts_dir: PathBuf::from("conf/vhosts"),
                modules_dir: PathBuf::from("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(PathBuf::from("."))),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(crate::logger::AsyncLogManager::new(
                PathBuf::from("."),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                250,
                64,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            access_logs: Mutex::new(VecDeque::new()),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: AtomicU64::new(17),
                cache_hits: AtomicU64::new(11),
                cache_misses: AtomicU64::new(6),
            },
        });
        state
            .ban_manager
            .ban("203.0.113.10".parse().unwrap(), "rate limit", 60);

        async fn call_route(
            state: &Arc<ServerState>,
            strict_api_only: bool,
            method: &str,
            path: &str,
            headers: Vec<(String, String)>,
        ) -> (bool, String) {
            let (mut client, mut server) = tokio::io::duplex(64 * 1024);
            let req = ParsedHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                query: String::new(),
                version: 1,
                host: "127.0.0.1".to_string(),
                headers,
                body: Vec::new(),
                keep_alive: false,
            };
            let st = Arc::clone(state);
            let task = tokio::spawn(async move {
                let handled = handle_api_route(&mut server, &req, &st, strict_api_only)
                    .await
                    .unwrap();
                let _ = server.shutdown().await;
                handled
            });
            let mut out = Vec::new();
            client.read_to_end(&mut out).await.unwrap();
            let handled = task.await.unwrap();
            (handled, String::from_utf8_lossy(&out).into_owned())
        }

        // Yetkisiz /metrics talebi 401 dönmeli
        let (handled_unauth, resp_unauth) =
            call_route(&state, true, "GET", "/metrics", Vec::new()).await;
        assert!(handled_unauth);
        assert!(resp_unauth.starts_with("HTTP/1.1 401 Unauthorized"), "{resp_unauth}");

        // Ön ek soyulmuş Prometheus /metrics (API dinleyici)
        let api_auth = vec![("Authorization".to_string(), "Bearer api-secret-token".to_string())];
        let (handled_metrics, resp_metrics) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/metrics",
            api_auth.clone(),
        )
        .await;
        assert!(handled_metrics);
        assert!(resp_metrics.starts_with("HTTP/1.1 200 OK"), "{resp_metrics}");
        assert!(
            resp_metrics.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
            "{resp_metrics}"
        );
        assert!(resp_metrics.contains("zmax_uptime_seconds "), "{resp_metrics}");
        assert!(resp_metrics.contains("zmax_requests_total 17\n"), "{resp_metrics}");
        assert!(resp_metrics.contains("zmax_cache_hits_total 11\n"), "{resp_metrics}");
        assert!(resp_metrics.contains("zmax_cache_misses_total 6\n"), "{resp_metrics}");
        assert!(resp_metrics.contains("zmax_vhosts_loaded 0\n"), "{resp_metrics}");
        assert!(resp_metrics.contains("zmax_modules_loaded 0\n"), "{resp_metrics}");
        assert!(resp_metrics.contains("zmax_banned_ips 1\n"), "{resp_metrics}");

        // Panel taraması için /api/v1/metrics (Admin dinleyici + ön ek soyma)
        let adm_auth = vec![("X-ZMax-Token".to_string(), "adm-secret-token".to_string())];
        let (handled_panel_metrics, resp_panel_metrics) = call_route(
            &state,
            false,
            "GET",
            "/v1/zmax/console/api/v1/metrics",
            adm_auth.clone(),
        )
        .await;
        assert!(handled_panel_metrics);
        assert!(
            resp_panel_metrics.contains("zmax_requests_total 17\n"),
            "{resp_panel_metrics}"
        );

        // /api/v1/config ssl ve proxy_prefix alanlarını token/key sızdırmadan dönmeli
        let (handled_cfg, resp_cfg) = call_route(
            &state,
            false,
            "GET",
            "/v1/zmax/console/api/v1/config",
            adm_auth,
        )
        .await;
        assert!(handled_cfg);
        assert!(
            resp_cfg.contains(r#""ssl":true,"proxy_prefix":"/v1/zmax/console""#),
            "{resp_cfg}"
        );
        assert!(
            resp_cfg.contains(r#""ssl":false,"proxy_prefix":"/v1/zmax/api""#),
            "{resp_cfg}"
        );
        assert!(!resp_cfg.contains("adm-secret-token"));
        assert!(!resp_cfg.contains("api-secret-token"));
        assert!(!resp_cfg.contains("admin.key"));

        // /api/v1/ports tls nesnesini dönmeli
        let (handled_ports, resp_ports) =
            call_route(&state, true, "GET", "/v1/zmax/api/api/v1/ports", api_auth).await;
        assert!(handled_ports);
        assert!(
            resp_ports.contains(r#""tls":{"https":true,"admin":true,"api":false}"#),
            "{resp_ports}"
        );

        // Admin kök yolu API olarak yakalanmamalı (statik UI düşmeli), API kökü health dönmeli
        let (handled_admin_root, _) =
            call_route(&state, false, "GET", "/v1/zmax/console", Vec::new()).await;
        assert!(!handled_admin_root);

        let (handled_api_root, resp_api_root) =
            call_route(&state, true, "GET", "/v1/zmax/api", Vec::new()).await;
        assert!(handled_api_root);
        assert!(resp_api_root.contains(r#""status":"ok""#), "{resp_api_root}");
    }
}
