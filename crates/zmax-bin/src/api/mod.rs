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
use zmax_httpparser::{
    read_http1_request_buffered, HttpReadError, HttpReadLimits, HttpRequestData,
};
use zmax_obfuscate::zpoly;

pub mod admin_static;
pub mod routes;
pub mod services;
use services::vhost_service::{format_vhost_json, merge_vhost_json_patch, write_vhost_atomic_with_rollback};

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
        HttpReadError::HeadersTooLarge => (
            431u16,
            "Request Header Fields Too Large",
            "431 Request Header Fields Too Large",
        ),
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

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
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
    let origin = if cors_origin.is_empty() {
        "*"
    } else {
        cors_origin
    };
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
        (
            rt.conf_path.clone(),
            rt.vhosts_dir.clone(),
            rt.modules_dir.clone(),
        )
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
    crate::acme_runtime::apply_global_acme_root(&new_cfg, &state.base_dir);

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

    // [ek-dinleyici] ek dinleyicileri yeni yapılandırmayla uzlaştır (hata reload'u bozmaz; günlüğe yazılır)
    let _ = crate::web_engine::reconcile_extra_listeners(state).await;

    Ok((vhost_count, alpn_protocols))
}

/// Diskten `conf/zmax.toml`, `conf/vhosts/*.toml` ve `modules/mod_*.toml` dosyalarını atomik olarak yeniler.
pub async fn reload_runtime_state(state: &Arc<ServerState>) -> Result<usize, String> {
    reload_runtime_state_with_alpn(state)
        .await
        .map(|(count, _)| count)
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
        let origin = if cors_origin.is_empty() {
            "*"
        } else {
            &cors_origin
        };
        let resp = format!(
            "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-ZMax-Token, X-ZMax-Purge-Key\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            origin
        );
        socket.write_all(resp.as_bytes()).await?;
        return Ok(true);
    }

    if routes::system::health_version(socket, req, state, &req_path, &cors_origin, strict_api_only).await? {
        return Ok(true);
    }


    // Token kontrolü (yapılandırılmışsa veya dinleyici loopback dışındaysa zorunlu)
    if !is_authorized(req, &expected_token, require_token) {
        let err =
            r#"{"ok":false,"error":"Yetkisiz erisim: Gecerli Bearer veya X-ZMax-Token gerekli."}"#;
        send_json_response(socket, 401, "Unauthorized", &cors_origin, err).await?;
        return Ok(true);
    }

    if routes::system::handle(socket, req, state, &req_path, &cors_origin).await? {
        return Ok(true);
    }
    if routes::security_cache::handle(socket, req, state, &req_path, &cors_origin).await? {
        return Ok(true);
    }
    if routes::logs::handle(socket, req, state, &req_path, &cors_origin).await? {
        return Ok(true);
    }
    if routes::vhosts::handle(socket, req, state, &req_path, &cors_origin).await? {
        return Ok(true);
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
        assert_eq!(
            extract_json_string(body, "domain").as_deref(),
            Some("site.com")
        );
        assert_eq!(
            extract_json_string(body, "document_root").as_deref(),
            Some("www/site")
        );
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
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
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
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(PathBuf::from(
                ".",
            ))),
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
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
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
                let handled = handle_api_route(&mut server, &req, &st)
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
        assert!(
            resp_unauth.starts_with("HTTP/1.1 401 Unauthorized"),
            "{resp_unauth}"
        );

        // Ön ek soyulmuş Prometheus /metrics (API dinleyici)
        let api_auth = vec![(
            "Authorization".to_string(),
            "Bearer api-secret-token".to_string(),
        )];
        let (handled_metrics, resp_metrics) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/metrics",
            api_auth.clone(),
        )
        .await;
        assert!(handled_metrics);
        assert!(
            resp_metrics.starts_with("HTTP/1.1 200 OK"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_uptime_seconds "),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_requests_total 17\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_cache_hits_total 11\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_cache_misses_total 6\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_vhosts_loaded 0\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_modules_loaded 0\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_banned_ips 1\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_waf_events_total 0\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_waf_blocked_24h 0\n"),
            "{resp_metrics}"
        );

        // WAF olayı kaydedildiğinde /metrics ve /api/v1/status sayaçları yansımalı
        state.waf_events.record_violation(
            &zmax_security::WafViolation::SqlInjection("union select".to_string()),
            "site.test",
            "127.0.0.1",
            "GET",
            "/arama?password=Secret&id=1",
        );
        let (handled_waf_metrics, resp_waf_metrics) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/metrics",
            api_auth.clone(),
        )
        .await;
        assert!(handled_waf_metrics);
        assert!(
            resp_waf_metrics.contains("zmax_waf_events_total 1\n"),
            "{resp_waf_metrics}"
        );
        assert!(
            resp_waf_metrics.contains("zmax_waf_blocked_24h 1\n"),
            "{resp_waf_metrics}"
        );

        let (handled_waf_status, resp_waf_status) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/api/v1/status",
            api_auth.clone(),
        )
        .await;
        assert!(handled_waf_status);
        assert!(
            resp_waf_status.contains(r#""waf_events_total":1,"waf_blocked_24h":1"#),
            "{resp_waf_status}"
        );
        assert!(!resp_waf_status.contains("Secret"), "{resp_waf_status}");

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
        assert!(
            resp_api_root.contains(r#""status":"ok""#),
            "{resp_api_root}"
        );
    }

    #[tokio::test]
    async fn test_vhost_api_crud_full_fields_put_get_equality_and_atomic_rollback() {
        use tokio::io::AsyncReadExt;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("zmax_test_crud_{}_{}", std::process::id(), nanos));
        let conf_dir = test_dir.join("conf");
        let vhosts_dir = conf_dir.join("vhosts");
        let modules_dir = test_dir.join("modules");
        let www_dir = test_dir.join("www");
        std::fs::create_dir_all(&vhosts_dir).unwrap();
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::create_dir_all(&www_dir).unwrap();

        let conf_path = conf_dir.join("zmax.toml");
        std::fs::write(
            &conf_path,
            r#"
[server]
server_name = "ZMax/Test"

[vhosts_dir]
path = "conf/vhosts"
"#,
        )
        .unwrap();

        let cfg = ZMaxConfig::load_or_default(&conf_path).unwrap();
        let modules = LoadedModules::default();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);

        let state = Arc::new(ServerState {
            base_dir: test_dir.clone(),
            cache: zmax_cache::ZMaxCache::new(1024 * 1024, 60),
            limiter: RwLock::new(zmax_security::RateLimiter::new(1000)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::default()),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
            buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
            upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::default()),
            runtime: RwLock::new(RuntimeState {
                config: cfg,
                vhosts: Vec::new(),
                modules,
                policies,
                redis_client: None,
                auth,
                conf_path: conf_path.clone(),
                vhosts_dir: vhosts_dir.clone(),
                modules_dir: modules_dir.clone(),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                test_dir.clone(),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(crate::logger::AsyncLogManager::new(
                test_dir.clone(),
                test_dir.join("logs/access.log"),
                test_dir.join("logs/error.log"),
                250,
                64,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::new()),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
            },
        });

        async fn run_api_req(
            state: &Arc<ServerState>,
            method: &str,
            path: &str,
            body: &[u8],
        ) -> (bool, String) {
            let (mut client, mut server) = tokio::io::duplex(64 * 1024);
            let req = ParsedHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                query: String::new(),
                version: 1,
                host: "127.0.0.1".to_string(),
                headers: Vec::new(),
                body: body.to_vec(),
                keep_alive: false,
            };
            let st = Arc::clone(state);
            let task = tokio::spawn(async move {
                let handled = handle_api_route(&mut server, &req, &st, true)
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

        let toml_file = vhosts_dir.join("crud.test.toml");

        // 1. PUT /api/v1/vhosts/crud.test - Tüm alanların yazılması
        let put_body = r#"{
            "document_root": "www/crud.test",
            "aliases": ["www.crud.test"],
            "hotlink_protection": true,
            "allow_ips": ["10.0.0.1/32"],
            "deny_ips": ["192.168.1.100"],
            "waf_enabled": true,
            "wp_brute_force": false,
            "waf_exclude_paths": ["/muaf/yol"],
            "security_headers": true,
            "hsts": true,
            "logging_enabled": true,
            "access_log": "logs/crud_access.log",
            "error_log": "logs/crud_error.log",
            "log_format": "%h %l %u %t \"%r\" %>s %b",
            "max_log_size_mb": 42,
            "also_write_global": false,
            "error_docs_enabled": true,
            "error_docs_dir": "errors",
            "error_docs_pages": {
                "404": "404.html",
                "500": "500.html"
            },
            "rewrite_enabled": true,
            "try_files": true,
            "htaccess": false,
            "rewrite_rules": [
                {
                    "pattern": "^/eski$",
                    "target": "/yeni",
                    "status": 301,
                    "flags": ["L"],
                    "last": true
                }
            ],
            "http2": true,
            "strict_sni": true,
            "tls_min_version": "1.3"
        }"#;

        let (handled, resp) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            put_body.as_bytes(),
        )
        .await;
        assert!(handled);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains(r#""status":"saved""#), "{resp}");
        assert!(
            toml_file.exists(),
            "vHost TOML dosyası diske yazılmış olmalıdır"
        );

        let original_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert!(!original_toml.is_empty());

        // 2. GET /api/v1/vhosts/crud.test - Geri okuma ve birebir eşitlik
        let (handled_get, resp_get) =
            run_api_req(&state, "GET", "/api/v1/vhosts/crud.test", &[]).await;
        assert!(handled_get);
        assert!(resp_get.starts_with("HTTP/1.1 200 OK"), "{resp_get}");

        let body_json = resp_get.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body_json).unwrap();
        assert_eq!(v["ok"], true);
        let vhost = &v["vhost"];

        assert_eq!(vhost["domain"], "crud.test");
        assert_eq!(vhost["document_root"], "www/crud.test");
        assert_eq!(vhost["hotlink_protection"], true);
        assert_eq!(vhost["security"]["hotlink_protection"], true);
        assert_eq!(vhost["allow_ips"], serde_json::json!(["10.0.0.1/32"]));
        assert_eq!(
            vhost["security"]["allow_ips"],
            serde_json::json!(["10.0.0.1/32"])
        );
        assert_eq!(vhost["deny_ips"], serde_json::json!(["192.168.1.100"]));
        assert_eq!(vhost["waf_enabled"], true);
        assert_eq!(vhost["security"]["waf_enabled"], true);
        assert_eq!(vhost["wp_brute_force"], false);
        assert_eq!(vhost["waf_exclude_paths"], serde_json::json!(["/muaf/yol"]));
        assert_eq!(vhost["security_headers"], true);
        assert_eq!(vhost["headers"]["security_headers"], true);
        assert_eq!(vhost["hsts"], true);
        assert_eq!(vhost["logging_enabled"], true);
        assert_eq!(vhost["access_log"], "logs/crud_access.log");
        assert_eq!(vhost["error_log"], "logs/crud_error.log");
        assert_eq!(vhost["log_format"], "%h %l %u %t \"%r\" %>s %b");
        assert_eq!(vhost["max_log_size_mb"], 42);
        assert_eq!(vhost["also_write_global"], false);
        assert_eq!(vhost["error_docs_enabled"], true);
        assert_eq!(vhost["error_docs_dir"], "errors");
        assert_eq!(vhost["error_docs_pages"]["404"], "404.html");
        assert_eq!(vhost["error_docs_pages"]["500"], "500.html");
        assert_eq!(vhost["rewrite_enabled"], true);
        assert_eq!(vhost["rewrite_rules"][0]["pattern"], "^/eski$");
        assert_eq!(vhost["rewrite_rules"][0]["status"], 301);
        assert_eq!(vhost["http2"], true);
        assert_eq!(vhost["tls_min_version"], "1.3");

        // Aktif çalışma zamanındaki nesne eşitliği
        {
            let rt = state.runtime.read().await;
            let loaded = rt
                .vhosts
                .iter()
                .find(|x| x.entry.name == "crud.test")
                .expect("vHost runtime'da bulunmalıdır");
            assert!(loaded.entry.security.hotlink_protection);
            assert_eq!(loaded.entry.security.allow_ips, vec!["10.0.0.1/32"]);
            assert_eq!(loaded.entry.security.waf_exclude_paths, vec!["/muaf/yol"]);
            assert_eq!(loaded.entry.rewrite.rules.len(), 1);
            assert_eq!(
                loaded.entry.error_docs.pages.get(&404).map(String::as_str),
                Some("404.html")
            );
        }

        // 3. Bozuk JSON durumunda 400 Bad Request ve dosyanın DEĞİŞMEMESİ
        let (handled_bad, resp_bad) =
            run_api_req(&state, "PUT", "/api/v1/vhosts/crud.test", b"{bozuk_json:").await;
        assert!(handled_bad);
        assert!(
            resp_bad.starts_with("HTTP/1.1 400 Bad Request"),
            "{resp_bad}"
        );
        let after_bad_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert_eq!(
            after_bad_toml, original_toml,
            "Bozuk JSON sonrası TOML dosyası asla değişmemelidir"
        );

        // 4. Geçersiz alan (geçersiz IP ACL) durumunda 400 Bad Request ve dosyanın DEĞİŞMEMESİ
        let (handled_inv, resp_inv) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            br#"{"allow_ips":["gecersiz_ip_degeri"]}"#,
        )
        .await;
        assert!(handled_inv);
        assert!(
            resp_inv.starts_with("HTTP/1.1 400 Bad Request"),
            "{resp_inv}"
        );
        let after_inv_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert_eq!(
            after_inv_toml, original_toml,
            "Geçersiz alan sonrası TOML dosyası asla değişmemelidir"
        );

        // 5. Path traversal durumunda 400 Bad Request ve dosyanın DEĞİŞMEMESİ
        let (handled_trav, resp_trav) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            br#"{"document_root":"../../../etc/passwd"}"#,
        )
        .await;
        assert!(handled_trav);
        assert!(
            resp_trav.starts_with("HTTP/1.1 400 Bad Request"),
            "{resp_trav}"
        );
        let after_trav_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert_eq!(
            after_trav_toml, original_toml,
            "Traversal saldırısı sonrası TOML dosyası asla değişmemelidir"
        );

        // 6. Kısmi Alan Güncellemesi (Patch)
        let patch_body = r#"{"hotlink_protection": false, "security": {"waf_enabled": false}}"#;
        let (handled_patch, resp_patch) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            patch_body.as_bytes(),
        )
        .await;
        assert!(handled_patch);
        assert!(resp_patch.starts_with("HTTP/1.1 200 OK"), "{resp_patch}");

        let (handled_patch_get, resp_patch_get) =
            run_api_req(&state, "GET", "/api/v1/vhosts/crud.test", &[]).await;
        assert!(handled_patch_get);
        let patch_json: serde_json::Value =
            serde_json::from_str(resp_patch_get.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let patch_vhost = &patch_json["vhost"];
        assert_eq!(patch_vhost["hotlink_protection"], false);
        assert_eq!(patch_vhost["security"]["waf_enabled"], false);
        // Önceki alanlar korunmuş olmalıdır
        assert_eq!(patch_vhost["allow_ips"], serde_json::json!(["10.0.0.1/32"]));
        assert_eq!(patch_vhost["error_docs_pages"]["404"], "404.html");
        assert_eq!(patch_vhost["rewrite_rules"][0]["pattern"], "^/eski$");

        // Temizlik
        let _ = std::fs::remove_dir_all(&test_dir);
    }
}
