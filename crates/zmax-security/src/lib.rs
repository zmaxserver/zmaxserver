//! # zmax-security
//! WAF, bellek-sınırlı Rate Limiting, IP yasak yöneticisi ve WordPress brute-force kalkanı.

use dashmap::DashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod acl;
pub mod hotlink;

pub use acl::*;
pub use hotlink::*;

const DEFAULT_PURGE_THRESHOLD: usize = 4096;
const RATE_WINDOW_SECS: u64 = 60;
static REQUEST_ID_SEQ: AtomicU64 = AtomicU64::new(1);

/// Kilit gerektirmeyen (`AtomicU64` + `SystemTime`) hızlı ve benzersiz `X-Request-Id` üretir.
pub fn generate_request_id() -> String {
    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let seq = REQUEST_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("zmx-{ts_ms}-{seq}")
}

struct PurgeGuard<'a> {
    flag: &'a AtomicBool,
}

impl Drop for PurgeGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

pub struct RateLimiter {
    // IP bazlı istek sayaçları
    ip_records: DashMap<IpAddr, (u32, Instant)>,
    max_requests_per_minute: u32,
    purge_threshold: usize,
    hard_cap: usize,
    purging: AtomicBool,
    checks_counter: AtomicU64,
}

impl RateLimiter {
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self::with_purge_threshold(max_requests_per_minute, DEFAULT_PURGE_THRESHOLD)
    }

    /// Belirli bir temizleme eşiğiyle `RateLimiter` oluşturur (DDoS bellek patlamasını önler).
    pub fn with_purge_threshold(max_requests_per_minute: u32, purge_threshold: usize) -> Self {
        let threshold = purge_threshold.max(16);
        let hard_cap = threshold.saturating_mul(16).max(4096);
        Self {
            ip_records: DashMap::new(),
            max_requests_per_minute,
            purge_threshold: threshold,
            hard_cap,
            purging: AtomicBool::new(false),
            checks_counter: AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.ip_records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ip_records.is_empty()
    }

    /// 60 saniyelik penceresi dolmuş kayıtları bellekten temizler; temizlenen kayıt sayısını döner.
    pub fn purge_expired(&self) -> usize {
        let now = Instant::now();
        let before = self.ip_records.len();
        self.ip_records
            .retain(|_, (_, start_time)| now.duration_since(*start_time).as_secs() < RATE_WINDOW_SECS);
        before.saturating_sub(self.ip_records.len())
    }

    fn maybe_purge(&self, now: Instant) {
        let seq = self.checks_counter.fetch_add(1, Ordering::Relaxed);
        let len = self.ip_records.len();
        if len < self.purge_threshold && (seq & 1023) != 1023 {
            return;
        }
        if self
            .purging
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _guard = PurgeGuard {
            flag: &self.purging,
        };

        self.ip_records
            .retain(|_, (_, start_time)| now.duration_since(*start_time).as_secs() < RATE_WINDOW_SECS);

        // Aynı saniyede milyonlarca sahte IP saldırısı gelirse üst bellek sınırını koru
        if self.ip_records.len() >= self.hard_cap {
            let mut keep_budget = self.hard_cap / 2;
            self.ip_records.retain(|_, _| {
                if keep_budget > 0 {
                    keep_budget -= 1;
                    true
                } else {
                    false
                }
            });
        }
    }

    /// İstek gönderen IP'nin sınırları aşıp aşmadığını denetler
    pub fn check_allowed(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        // Kilitlenme (deadlock) olmaması için DashMap entry almadan önce temizleme çalışır.
        self.maybe_purge(now);

        let mut entry = self.ip_records.entry(ip).or_insert((0, now));
        let (count, start_time) = entry.value_mut();

        if now.duration_since(*start_time).as_secs() >= RATE_WINDOW_SECS {
            // Süre doldu, sayacı sıfırla
            *count = 1;
            *start_time = now;
            true
        } else if *count < self.max_requests_per_minute {
            *count += 1;
            true
        } else {
            // Hız limiti aşıldı!
            false
        }
    }
}

/// Yasaklanmış bir IP kaydının özeti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BannedIpInfo {
    pub ip: IpAddr,
    pub reason: String,
    pub remaining_secs: Option<u64>,
    pub permanent: bool,
}

#[derive(Debug, Clone)]
struct IpBanEntry {
    reason: String,
    expires_at: Option<Instant>,
}

/// Kalıcı ve süreli (TTL tabanlı) IP yasak listesi yöneticisi.
pub struct IpBanManager {
    bans: DashMap<IpAddr, IpBanEntry>,
}

impl Default for IpBanManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IpBanManager {
    pub fn new() -> Self {
        Self {
            bans: DashMap::new(),
        }
    }

    /// IP'yi yasaklar. `ttl_secs == 0` ise kalıcı yasak uygulanır; `> 0` ise belirtilen saniye kadar sürer.
    pub fn ban(&self, ip: IpAddr, reason: impl Into<String>, ttl_secs: u64) {
        let expires_at = if ttl_secs == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_secs))
        };
        self.bans.insert(
            ip,
            IpBanEntry {
                reason: reason.into(),
                expires_at,
            },
        );
    }

    /// IP üzerindeki yasağı kaldırır. Kayıt varsa `true` döner.
    pub fn unban(&self, ip: IpAddr) -> bool {
        self.bans.remove(&ip).is_some()
    }

    /// IP'nin aktif olarak yasaklı olup olmadığını kontrol eder; süresi dolmuşsa kaydı temizler.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let expired = match self.bans.get(&ip) {
            Some(entry) => match entry.expires_at {
                None => return true,
                Some(exp) if now < exp => return true,
                Some(_) => true,
            },
            None => return false,
        };
        if expired {
            self.bans.remove_if(&ip, |_, entry| {
                entry.expires_at.map(|exp| Instant::now() >= exp).unwrap_or(false)
            });
        }
        false
    }

    /// Süresi dolmuş yasakları temizler ve aktif yasaklı IP listesini döndürür.
    pub fn list_banned(&self) -> Vec<BannedIpInfo> {
        let now = Instant::now();
        self.bans
            .retain(|_, entry| entry.expires_at.map(|exp| now < exp).unwrap_or(true));

        let mut list: Vec<BannedIpInfo> = self
            .bans
            .iter()
            .map(|r| {
                let (permanent, remaining_secs) = match r.value().expires_at {
                    None => (true, None),
                    Some(exp) => (false, Some(exp.saturating_duration_since(now).as_secs())),
                };
                BannedIpInfo {
                    ip: *r.key(),
                    reason: r.value().reason.clone(),
                    remaining_secs,
                    permanent,
                }
            })
            .collect();
        list.sort_by_key(|item| item.ip.to_string());
        list
    }
}

fn parse_cidr_spec(spec: &str) -> Option<(IpAddr, u8)> {
    let s = spec.trim();
    if s.is_empty() {
        return None;
    }
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        if prefix_str.is_empty() || !prefix_str.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let prefix: u8 = prefix_str.parse().ok()?;
        let net_ip: IpAddr = ip_str.parse().ok()?;
        match net_ip {
            IpAddr::V4(_) if prefix <= 32 => Some((net_ip, prefix)),
            IpAddr::V6(_) if prefix <= 128 => Some((net_ip, prefix)),
            _ => None,
        }
    } else {
        let ip: IpAddr = s.parse().ok()?;
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((ip, prefix))
    }
}

/// Tekil IP adresini (`192.168.1.10`, `::1`) veya CIDR ağ tanımını (`10.0.0.0/8`, `2001:db8::/32`) doğrular.
pub fn is_valid_ip_or_cidr(spec: &str) -> bool {
    parse_cidr_spec(spec).is_some()
}

/// Verilen IP adresinin tekil IP veya CIDR tanımıyla eşleşip eşleşmediğini bit maskesiyle denetler.
pub fn ip_matches_cidr_spec(ip: IpAddr, spec: &str) -> bool {
    let Some((net_ip, prefix)) = parse_cidr_spec(spec) else {
        return false;
    };
    match (ip, net_ip) {
        (IpAddr::V4(addr), IpAddr::V4(net)) => {
            let mask: u32 = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(addr) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(addr), IpAddr::V6(net)) => {
            let mask: u128 = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(addr) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

/// CIDR ve tekil IP tabanlı izin/engelleme (`allow`/`deny`) erişim kontrol listesi.
#[derive(Debug, Clone, Default)]
pub struct IpAccessList {
    allow: Vec<String>,
    deny: Vec<String>,
}

impl IpAccessList {
    /// Verilen `allow` ve `deny` IP/CIDR kurallarıyla yeni bir erişim kontrol listesi oluşturur.
    pub fn new(allow: Vec<String>, deny: Vec<String>) -> Self {
        Self { allow, deny }
    }

    /// Hem `allow` hem `deny` kural listelerinin boş olup olmadığını döndürür.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }

    /// Verilen IP adresine izin verilip verilmediğini değerlendirir (`allow` öncelikli, ardından `deny`, varsa sıkı beyaz liste modu).
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.allow.iter().any(|spec| ip_matches_cidr_spec(ip, spec)) {
            return true;
        }
        if self.deny.iter().any(|spec| ip_matches_cidr_spec(ip, spec)) {
            return false;
        }
        if self.allow.iter().any(|spec| is_valid_ip_or_cidr(spec)) {
            return false;
        }
        true
    }
}

/// WordPress brute-force kalkanının değerlendirme sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WpGuardVerdict {
    Allowed,
    SuggestBan {
        attempts: u32,
        ban_duration_secs: u64,
    },
}

/// WordPress `/wp-login.php` ve `/xmlrpc.php` POST denemelerini IP bazında sayan kalkan.
pub struct WpBruteForceGuard {
    attempts: DashMap<IpAddr, (u32, Instant)>,
    max_attempts: u32,
    window_secs: u64,
    ban_duration_secs: u64,
    purge_threshold: usize,
    purging: AtomicBool,
}

impl Default for WpBruteForceGuard {
    fn default() -> Self {
        Self::new(10, 300, 900)
    }
}

impl WpBruteForceGuard {
    pub fn new(max_attempts: u32, window_secs: u64, ban_duration_secs: u64) -> Self {
        Self {
            attempts: DashMap::new(),
            max_attempts: max_attempts.max(1),
            window_secs: window_secs.max(1),
            ban_duration_secs: ban_duration_secs.max(1),
            purge_threshold: DEFAULT_PURGE_THRESHOLD,
            purging: AtomicBool::new(false),
        }
    }

    /// İsteğin korunan bir WordPress kimlik doğrulama / XML-RPC uç noktasına yönelik POST olup olmadığını belirler.
    pub fn is_protected_endpoint(method: &str, path: &str) -> bool {
        if !method.eq_ignore_ascii_case("POST") {
            return false;
        }
        let path_only = path.split('?').next().unwrap_or(path);
        let normalized = path_only.trim_end_matches('/').to_ascii_lowercase();
        normalized == "/wp-login.php"
            || normalized.ends_with("/wp-login.php")
            || normalized == "/xmlrpc.php"
            || normalized.ends_with("/xmlrpc.php")
    }

    fn maybe_purge(&self, now: Instant) {
        if self.attempts.len() < self.purge_threshold {
            return;
        }
        if self
            .purging
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _guard = PurgeGuard {
            flag: &self.purging,
        };
        let window = self.window_secs;
        self.attempts
            .retain(|_, (_, start)| now.duration_since(*start).as_secs() < window);
    }

    /// WordPress POST denemesini değerlendirir; eşik aşılırsa geçici yasak önerisi döndürür.
    pub fn check_attempt(&self, ip: IpAddr, method: &str, path: &str) -> WpGuardVerdict {
        if !Self::is_protected_endpoint(method, path) {
            return WpGuardVerdict::Allowed;
        }

        let now = Instant::now();
        self.maybe_purge(now);

        let mut entry = self.attempts.entry(ip).or_insert((0, now));
        let (count, start_time) = entry.value_mut();

        if now.duration_since(*start_time).as_secs() >= self.window_secs {
            *count = 1;
            *start_time = now;
            return WpGuardVerdict::Allowed;
        }

        *count += 1;
        if *count > self.max_attempts {
            WpGuardVerdict::SuggestBan {
                attempts: *count,
                ban_duration_secs: self.ban_duration_secs,
            }
        } else {
            WpGuardVerdict::Allowed
        }
    }

    /// Kalkan eşiği aşıldığında IP'yi otomatik olarak `IpBanManager` listesine ekler; izinliyse `true` döner.
    pub fn check_and_ban(
        &self,
        ip: IpAddr,
        method: &str,
        path: &str,
        ban_manager: &IpBanManager,
    ) -> bool {
        match self.check_attempt(ip, method, path) {
            WpGuardVerdict::Allowed => true,
            WpGuardVerdict::SuggestBan {
                attempts,
                ban_duration_secs,
            } => {
                ban_manager.ban(
                    ip,
                    format!("WordPress brute-force ({} deneme)", attempts),
                    ban_duration_secs,
                );
                false
            }
        }
    }

    pub fn reset(&self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }
}

/// Temel WAF ve Path Traversal denetim ihlalleri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WafViolation {
    NullByte,
    PathTraversal(String),
    SensitiveFileAccess(String),
    SqlInjection(String),
    CrossSiteScripting(String),
    CommandInjection(String),
}

impl fmt::Display for WafViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WafViolation::NullByte => write!(f, "Null byte enjeksiyonu tespit edildi"),
            WafViolation::PathTraversal(p) => write!(f, "Path traversal girisimi: {}", p),
            WafViolation::SensitiveFileAccess(p) => write!(f, "Hassas dosya erisimi: {}", p),
            WafViolation::SqlInjection(p) => write!(f, "SQL enjeksiyon imzasi: {}", p),
            WafViolation::CrossSiteScripting(p) => write!(f, "XSS imzasi: {}", p),
            WafViolation::CommandInjection(p) => write!(f, "Komut enjeksiyon imzasi: {}", p),
        }
    }
}

impl std::error::Error for WafViolation {}

/// WAF inceleme sonucu (`inspect` ve `inspect_with_policy` için ortak dönüş tipi).
pub type WafVerdict = Result<(), WafViolation>;

/// VHost bazlı WAF yapılandırma politikası.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VHostWafPolicy<'a> {
    pub waf_enabled: Option<bool>,
    pub exclude_paths: &'a [String],
}

fn path_matches_exclude_prefix(decoded_path: &str, exclude_paths: &[String]) -> bool {
    for raw_prefix in exclude_paths {
        let p = raw_prefix.trim();
        if p.is_empty() {
            continue;
        }
        if p.ends_with('/') {
            if decoded_path.starts_with(p) {
                return true;
            }
        } else if decoded_path == p
            || (decoded_path.starts_with(p) && decoded_path[p.len()..].starts_with('/'))
        {
            return true;
        }
    }
    false
}

/// Temel HTTP istek WAF / Path Traversal denetçisi.
#[derive(Debug, Clone)]
pub struct WafInspector {
    pub block_traversal: bool,
    pub block_sensitive_files: bool,
    pub block_sqli: bool,
    pub block_xss: bool,
    pub block_cmdi: bool,
}

impl Default for WafInspector {
    fn default() -> Self {
        Self {
            block_traversal: true,
            block_sensitive_files: true,
            block_sqli: true,
            block_xss: true,
            block_cmdi: true,
        }
    }
}

impl WafInspector {
    pub fn new() -> Self {
        Self::default()
    }

    fn inspect_core<'a, I>(
        &self,
        path: &str,
        query: &str,
        headers: I,
        body: Option<&[u8]>,
        exclude_paths: &[String],
    ) -> WafVerdict
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let decoded_path = decode_url_rounds(path, 2, false);
        let decoded_query = decode_url_rounds(query, 2, true);

        if path.contains('\0')
            || query.contains('\0')
            || decoded_path.contains('\0')
            || decoded_query.contains('\0')
        {
            return Err(WafViolation::NullByte);
        }

        if self.block_traversal
            && (has_path_traversal(&decoded_path)
                || has_path_traversal(&decoded_query)
                || path.contains("..")
                || query.contains(".."))
        {
            return Err(WafViolation::PathTraversal(path.to_string()));
        }

        if self.block_sensitive_files {
            if let Some(hit) = detect_sensitive_file(&decoded_path) {
                return Err(WafViolation::SensitiveFileAccess(hit.to_string()));
            }
        }

        if !exclude_paths.is_empty() && path_matches_exclude_prefix(&decoded_path, exclude_paths) {
            return Ok(());
        }

        let path_lower = normalize_whitespace(&decoded_path);
        let query_lower = normalize_whitespace(&decoded_query);

        if self.block_sqli {
            if let Some(sig) = detect_sqli(&path_lower).or_else(|| detect_sqli(&query_lower)) {
                return Err(WafViolation::SqlInjection(sig.to_string()));
            }
        }

        if self.block_xss {
            if let Some(sig) = detect_xss(&path_lower).or_else(|| detect_xss(&query_lower)) {
                return Err(WafViolation::CrossSiteScripting(sig.to_string()));
            }
            for (name, val) in headers {
                if name.eq_ignore_ascii_case("user-agent") || name.eq_ignore_ascii_case("referer") {
                    let h_norm = normalize_whitespace(&decode_url_rounds(val, 1, false));
                    if let Some(sig) = detect_xss(&h_norm) {
                        return Err(WafViolation::CrossSiteScripting(sig.to_string()));
                    }
                }
            }
        }

        if self.block_cmdi {
            if let Some(sig) = detect_cmdi(&path_lower).or_else(|| detect_cmdi(&query_lower)) {
                return Err(WafViolation::CommandInjection(sig.to_string()));
            }
        }

        if let Some(raw_body) = body.filter(|b| !b.is_empty()) {
            let body_lossy = String::from_utf8_lossy(raw_body);
            let body_norm = normalize_whitespace(&decode_url_rounds(&body_lossy, 1, true));
            if self.block_sqli {
                if let Some(sig) = detect_sqli(&body_norm) {
                    return Err(WafViolation::SqlInjection(sig.to_string()));
                }
            }
            if self.block_xss {
                if let Some(sig) = detect_xss(&body_norm) {
                    return Err(WafViolation::CrossSiteScripting(sig.to_string()));
                }
            }
            if self.block_cmdi {
                if let Some(sig) = detect_cmdi(&body_norm) {
                    return Err(WafViolation::CommandInjection(sig.to_string()));
                }
            }
        }

        Ok(())
    }

    /// HTTP istek yolu, sorgu dizesi ve temel başlıkları tehdit imzalarına karşı denetler.
    pub fn inspect(
        &self,
        _method: &str,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
    ) -> WafVerdict {
        self.inspect_core(path, query, headers.iter().copied(), None, &[])
    }

    /// VHost bazlı WAF politikası (`waf_enabled`, `exclude_paths`) ve gövde (`body`) ile istek denetimi yapar.
    pub fn inspect_with_policy(
        &self,
        _method: &str,
        path: &str,
        query: &str,
        headers: &[(String, String)],
        body: &[u8],
        policy: &VHostWafPolicy<'_>,
    ) -> WafVerdict {
        if policy.waf_enabled == Some(false) {
            return Ok(());
        }
        self.inspect_core(
            path,
            query,
            headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            Some(body),
            policy.exclude_paths,
        )
    }
}

fn decode_url_once(input: &str, plus_as_space: bool) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        if plus_as_space && bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_url_rounds(input: &str, rounds: usize, plus_as_space: bool) -> String {
    let mut current = input.to_string();
    for _ in 0..rounds {
        let next = decode_url_once(&current, plus_as_space);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn normalize_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_ascii_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_space = false;
        }
    }
    out
}

fn has_path_traversal(decoded: &str) -> bool {
    if decoded.contains("..\\") || decoded.contains("../") || decoded.contains("\\..") {
        return true;
    }
    decoded
        .split(['/', '\\'])
        .any(|seg| seg == ".." || seg.eq_ignore_ascii_case("%2e%2e"))
}

fn detect_sensitive_file(decoded_path: &str) -> Option<&'static str> {
    let lower = decoded_path.to_ascii_lowercase();
    if lower.starts_with("/.well-known/") {
        return None;
    }
    for seg in lower.split(['/', '\\']) {
        if seg.is_empty() {
            continue;
        }
        if matches!(
            seg,
            ".env"
                | ".git"
                | ".svn"
                | ".hg"
                | ".htaccess"
                | ".htpasswd"
                | "wp-config.php"
                | "wp-config.bak"
                | "wp-config.php.bak"
        ) || seg.starts_with(".env.")
        {
            return Some(match seg {
                ".git" => ".git",
                ".htaccess" => ".htaccess",
                ".htpasswd" => ".htpasswd",
                "wp-config.php" | "wp-config.bak" | "wp-config.php.bak" => "wp-config",
                _ => ".env",
            });
        }
    }
    None
}

fn detect_sqli(norm: &str) -> Option<&'static str> {
    const SIGNATURES: &[&str] = &[
        "union select",
        "union all select",
        "' or '1'='1",
        "' or 1=1",
        "\" or 1=1",
        "or 1=1--",
        "; drop table",
        "; delete from",
        "waitfor delay",
        "benchmark(",
        "sleep(",
        "information_schema",
        "load_file(",
    ];
    SIGNATURES.iter().copied().find(|sig| norm.contains(sig))
}

fn detect_xss(norm: &str) -> Option<&'static str> {
    const SIGNATURES: &[&str] = &[
        "<script",
        "</script>",
        "javascript:",
        "onerror=",
        "onload=",
        "<iframe",
    ];
    SIGNATURES.iter().copied().find(|sig| norm.contains(sig))
}

fn detect_cmdi(norm: &str) -> Option<&'static str> {
    const SIGNATURES: &[&str] = &[
        "/etc/passwd",
        "/etc/shadow",
        "cmd.exe",
        "powershell.exe",
        "; cat /etc/",
        "$(whoami)",
    ];
    SIGNATURES.iter().copied().find(|sig| norm.contains(sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_blocks_abuse() {
        let limiter = RateLimiter::new(5); // Maks 5 istek
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // İlk 5 istek kabul edilmeli
        for _ in 0..5 {
            assert!(limiter.check_allowed(ip));
        }

        // 6. ve sonraki istekler bloke edilmeli (Brute-force kalkanı)
        assert!(!limiter.check_allowed(ip));
        assert!(!limiter.check_allowed(ip));
    }

    #[test]
    fn test_rate_limiter_purges_expired_and_caps_memory() {
        let limiter = RateLimiter::with_purge_threshold(10, 32);
        let expired_time = Instant::now() - Duration::from_secs(120);
        for i in 0..40u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i));
            limiter.ip_records.insert(ip, (3, expired_time));
        }
        assert_eq!(limiter.len(), 40);

        // Yeni bir istek geldiğinde eşik aşıldığı için süresi dolanlar temizlenmeli
        let active_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
        assert!(limiter.check_allowed(active_ip));
        assert_eq!(limiter.len(), 1);

        // Hard cap koruması (aynı anda binlerce sahte IP saldırısı)
        for i in 0..700u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0xAC10_0000 + i));
            assert!(limiter.check_allowed(ip));
        }
        assert!(limiter.len() <= limiter.hard_cap);
    }

    #[test]
    fn test_ip_ban_manager_ttl_unban_and_list() {
        let mgr = IpBanManager::new();
        let ip1: IpAddr = "203.0.113.10".parse().unwrap();
        let ip2: IpAddr = "203.0.113.20".parse().unwrap();
        let ip_expired: IpAddr = "203.0.113.30".parse().unwrap();

        mgr.ban(ip1, "Saldiri", 0); // kalıcı
        mgr.ban(ip2, "Brute force", 600);
        mgr.bans.insert(
            ip_expired,
            IpBanEntry {
                reason: "Eski".to_string(),
                expires_at: Some(Instant::now() - Duration::from_secs(5)),
            },
        );

        assert!(mgr.is_banned(ip1));
        assert!(mgr.is_banned(ip2));
        assert!(!mgr.is_banned(ip_expired));

        let listed = mgr.list_banned();
        assert_eq!(listed.len(), 2);
        assert!(listed.iter().any(|b| b.ip == ip1 && b.permanent));
        assert!(listed
            .iter()
            .any(|b| b.ip == ip2 && !b.permanent && b.remaining_secs.is_some()));

        assert!(mgr.unban(ip1));
        assert!(!mgr.is_banned(ip1));
        assert!(!mgr.unban(ip1));
    }

    #[test]
    fn test_wp_brute_force_guard_and_auto_ban() {
        let guard = WpBruteForceGuard::new(3, 300, 600);
        let bans = IpBanManager::new();
        let attacker: IpAddr = "198.51.100.55".parse().unwrap();

        // GET veya normal URL'ler etkilenmez
        for _ in 0..10 {
            assert_eq!(
                guard.check_attempt(attacker, "GET", "/wp-login.php"),
                WpGuardVerdict::Allowed
            );
            assert_eq!(
                guard.check_attempt(attacker, "POST", "/wp-admin/admin-ajax.php"),
                WpGuardVerdict::Allowed
            );
        }

        // İlk 3 POST denemesi izinli, 4. deneme ban önerir
        for _ in 0..3 {
            assert!(guard.check_and_ban(attacker, "POST", "/wp-login.php?action=login", &bans));
        }
        assert!(!bans.is_banned(attacker));

        assert!(!guard.check_and_ban(attacker, "POST", "/xmlrpc.php", &bans));
        assert!(bans.is_banned(attacker));
    }

    #[test]
    fn test_waf_inspector_blocks_attacks_and_allows_normal_requests() {
        let waf = WafInspector::new();

        // Normal istekler + ACME
        assert!(waf
            .inspect("GET", "/.well-known/acme-challenge/abc123", "", &[])
            .is_ok());
        assert!(waf
            .inspect(
                "GET",
                "/wp-json/wp/v2/posts",
                "page=1&search=merhaba+dunya",
                &[("User-Agent", "Mozilla/5.0")]
            )
            .is_ok());

        // Traversal & double encoding
        assert!(matches!(
            waf.inspect("GET", "/wp-content/%2e%2e/%2e%2e/etc/passwd", "", &[]),
            Err(WafViolation::PathTraversal(_))
        ));
        assert!(matches!(
            waf.inspect("GET", "/%252e%252e/secret", "", &[]),
            Err(WafViolation::PathTraversal(_))
        ));

        // Hassas dosya
        assert!(matches!(
            waf.inspect("GET", "/.env", "", &[]),
            Err(WafViolation::SensitiveFileAccess(_))
        ));
        assert!(matches!(
            waf.inspect("GET", "/.git/config", "", &[]),
            Err(WafViolation::SensitiveFileAccess(_))
        ));

        // Null byte
        assert!(matches!(
            waf.inspect("GET", "/index.php%00.jpg", "", &[]),
            Err(WafViolation::NullByte)
        ));

        // SQLi & XSS & CMDi
        assert!(matches!(
            waf.inspect("GET", "/search", "id=1%20UNION%20SELECT%201,2", &[]),
            Err(WafViolation::SqlInjection(_))
        ));
        assert!(matches!(
            waf.inspect("GET", "/", "q=%3Cscript%3Ealert(1)%3C/script%3E", &[]),
            Err(WafViolation::CrossSiteScripting(_))
        ));
        assert!(matches!(
            waf.inspect("GET", "/", "f=/etc/passwd", &[]),
            Err(WafViolation::CommandInjection(_))
        ));
    }

    #[test]
    fn test_is_valid_ip_or_cidr_and_boundary_prefixes() {
        assert!(is_valid_ip_or_cidr("192.168.1.10"));
        assert!(is_valid_ip_or_cidr(" 10.0.0.0/8 "));
        assert!(is_valid_ip_or_cidr("0.0.0.0/0"));
        assert!(is_valid_ip_or_cidr("192.168.1.10/32"));
        assert!(is_valid_ip_or_cidr("::1"));
        assert!(is_valid_ip_or_cidr("::/0"));
        assert!(is_valid_ip_or_cidr("2001:db8::/32"));
        assert!(is_valid_ip_or_cidr("2001:db8::1/128"));

        assert!(!is_valid_ip_or_cidr(""));
        assert!(!is_valid_ip_or_cidr("   "));
        assert!(!is_valid_ip_or_cidr("999.0.0.1"));
        assert!(!is_valid_ip_or_cidr("10.0.0.0/33"));
        assert!(!is_valid_ip_or_cidr("::1/129"));
        assert!(!is_valid_ip_or_cidr("10.0.0.0/"));
        assert!(!is_valid_ip_or_cidr("/24"));
        assert!(!is_valid_ip_or_cidr("10.0.0.0/+8"));
        assert!(!is_valid_ip_or_cidr("10.0.0.0/8/16"));
    }

    #[test]
    fn test_ip_matches_cidr_spec_v4_v6_and_boundaries() {
        let v4: IpAddr = "192.168.1.42".parse().unwrap();
        let v6: IpAddr = "2001:db8:abcd::1".parse().unwrap();

        assert!(ip_matches_cidr_spec(v4, "192.168.1.42"));
        assert!(ip_matches_cidr_spec(v4, "192.168.1.42/32"));
        assert!(!ip_matches_cidr_spec(v4, "192.168.1.43/32"));
        assert!(ip_matches_cidr_spec(v4, "192.168.1.99/24"));
        assert!(ip_matches_cidr_spec(v4, "0.0.0.0/0"));
        assert!(!ip_matches_cidr_spec(v4, "::/0"));

        assert!(ip_matches_cidr_spec(v6, "2001:db8:abcd::1"));
        assert!(ip_matches_cidr_spec(v6, "2001:db8:abcd::1/128"));
        assert!(ip_matches_cidr_spec(v6, "2001:db8::/32"));
        assert!(!ip_matches_cidr_spec(v6, "2001:db9::/32"));
        assert!(ip_matches_cidr_spec(v6, "::/0"));
        assert!(!ip_matches_cidr_spec(v6, "0.0.0.0/0"));
    }

    #[test]
    fn test_ip_access_list_empty_and_invalid_rules() {
        let empty = IpAccessList::default();
        assert!(empty.is_empty());
        assert!(empty.is_allowed("192.0.2.1".parse().unwrap()));
        assert!(empty.is_allowed("::1".parse().unwrap()));

        let only_invalid = IpAccessList::new(vec!["invalid-cidr".to_string()], vec![]);
        assert!(!only_invalid.is_empty());
        assert!(only_invalid.is_allowed("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_access_list_deny_cidr_and_allow_overrides_deny() {
        let deny_only = IpAccessList::new(
            vec![],
            vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
        );
        assert!(!deny_only.is_allowed("10.20.30.40".parse().unwrap()));
        assert!(deny_only.is_allowed("8.8.8.8".parse().unwrap()));
        assert!(!deny_only.is_allowed("2001:db8::9".parse().unwrap()));
        assert!(deny_only.is_allowed("2001:db9::9".parse().unwrap()));

        // İzin öncelikli: allow eşleşirse deny içinde olsa bile izin verilir,
        // ancak geçerli allow kuralı olduğundan strict whitelist uygulanır.
        let override_list = IpAccessList::new(
            vec!["10.0.1.5/32".to_string()],
            vec!["10.0.0.0/8".to_string()],
        );
        assert!(override_list.is_allowed("10.0.1.5".parse().unwrap()));
        assert!(!override_list.is_allowed("10.0.1.6".parse().unwrap()));
        assert!(!override_list.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ip_access_list_whitelist_only_ipv4_ipv6_and_zero_prefix() {
        let whitelist = IpAccessList::new(
            vec!["192.168.10.0/24".to_string(), "2001:db8:1::/48".to_string()],
            vec![],
        );
        assert!(whitelist.is_allowed("192.168.10.77".parse().unwrap()));
        assert!(!whitelist.is_allowed("192.168.11.77".parse().unwrap()));
        assert!(whitelist.is_allowed("2001:db8:1::42".parse().unwrap()));
        assert!(!whitelist.is_allowed("2001:db8:2::42".parse().unwrap()));

        let all_v4_only = IpAccessList::new(
            vec!["0.0.0.0/0".to_string()],
            vec!["10.0.0.0/8".to_string()],
        );
        assert!(all_v4_only.is_allowed("10.1.2.3".parse().unwrap()));
        assert!(all_v4_only.is_allowed("1.1.1.1".parse().unwrap()));
        assert!(!all_v4_only.is_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn test_waf_policy_disabled_bypasses_all_checks() {
        let waf = WafInspector::new();
        let policy = VHostWafPolicy {
            waf_enabled: Some(false),
            exclude_paths: &[],
        };

        assert!(waf
            .inspect_with_policy(
                "POST",
                "/../../.env",
                "id=1 UNION SELECT 1,2",
                &[("User-Agent".into(), "<script>alert(1)</script>".into())],
                b"<script>evil()</script>",
                &policy,
            )
            .is_ok());
    }

    #[test]
    fn test_waf_policy_exclude_paths_and_traversal_protection() {
        let waf = WafInspector::new();
        let excludes = vec!["/wp-json/elementor/".to_string(), "/wp-admin/post.php".to_string()];
        let policy = VHostWafPolicy {
            waf_enabled: Some(true),
            exclude_paths: &excludes,
        };

        // Hariç tutulan yoldaki Elementor HTML/JS içeriği false positive olmadan geçmeli
        assert!(waf
            .inspect_with_policy(
                "POST",
                "/wp-json/elementor/v1/documents/12",
                "action=save",
                &[],
                br#"{"html":"<script>console.log('widget')</script><iframe src='/x'></iframe>"}"#,
                &policy,
            )
            .is_ok());

        // Tam yol eşleşmesi de izinli olmalı
        assert!(waf
            .inspect_with_policy(
                "POST",
                "/wp-admin/post.php",
                "",
                &[],
                b"content=<script>demo</script>",
                &policy,
            )
            .is_ok());

        // Hariç tutulan yolda olsa bile traversal (..) ve hassas dosya erişimi engellenmeli!
        assert!(matches!(
            waf.inspect_with_policy(
                "GET",
                "/wp-json/elementor/../../.env",
                "",
                &[],
                b"",
                &policy,
            ),
            Err(WafViolation::PathTraversal(_))
        ));
        assert!(matches!(
            waf.inspect_with_policy(
                "GET",
                "/wp-json/elementor/%2e%2e/wp-config.php",
                "",
                &[],
                b"",
                &policy,
            ),
            Err(WafViolation::PathTraversal(_))
        ));
        assert!(matches!(
            waf.inspect_with_policy(
                "GET",
                "/wp-json/elementor/.env",
                "",
                &[],
                b"",
                &policy,
            ),
            Err(WafViolation::SensitiveFileAccess(_))
        ));
        assert!(matches!(
            waf.inspect_with_policy(
                "GET",
                "/wp-json/elementor/doc%00.php",
                "",
                &[],
                b"",
                &policy,
            ),
            Err(WafViolation::NullByte)
        ));
    }

    #[test]
    fn test_waf_policy_inspects_body_on_non_excluded_paths() {
        let waf = WafInspector::new();
        let excludes = vec!["/wp-json/elementor/".to_string()];
        let policy = VHostWafPolicy {
            waf_enabled: None,
            exclude_paths: &excludes,
        };

        // Hariç tutulmayan yolda gövdedeki SQLi / XSS engellenmeli
        assert!(matches!(
            waf.inspect_with_policy(
                "POST",
                "/wp-json/elementor-sahte/v1",
                "",
                &[],
                b"q=1%20UNION%20SELECT%20password%20FROM%20users",
                &policy,
            ),
            Err(WafViolation::SqlInjection(_))
        ));
        assert!(matches!(
            waf.inspect_with_policy(
                "POST",
                "/iletisim",
                "",
                &[],
                b"yorum=<script>alert(1)</script>",
                &policy,
            ),
            Err(WafViolation::CrossSiteScripting(_))
        ));
        assert!(waf
            .inspect_with_policy(
                "POST",
                "/iletisim",
                "",
                &[],
                b"yorum=Merhaba+dunya&konu=Destek",
                &policy,
            )
            .is_ok());
    }

    #[tokio::test]
    async fn test_generate_request_id_format_and_concurrent_uniqueness() {
        use std::collections::HashSet;

        let sample = generate_request_id();
        let parts: Vec<&str> = sample.split('-').collect();
        assert_eq!(parts.len(), 3, "Beklenmeyen request id bicimi: {sample}");
        assert_eq!(parts[0], "zmx");
        assert!(parts[1].parse::<u64>().is_ok());
        assert!(parts[2].parse::<u64>().is_ok());

        let mut handles = Vec::with_capacity(16);
        for _ in 0..16 {
            handles.push(tokio::spawn(async {
                (0..200).map(|_| generate_request_id()).collect::<Vec<_>>()
            }));
        }

        let mut seen = HashSet::with_capacity(3200);
        for h in handles {
            for id in h.await.unwrap() {
                assert!(id.starts_with("zmx-"));
                assert!(seen.insert(id), "Cakisan request id uretildi!");
            }
        }
        assert_eq!(seen.len(), 3200);
    }
}
