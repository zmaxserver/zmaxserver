//! WAF olay günlüğü kaydı, 24 saatlik pencere sayacı ve gizlilik (parola/çerez/belirteç) maskeleme.

use crate::WafViolation;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// 24 saatlik kayan pencere süresi (saniye).
pub const WAF_EVENT_WINDOW_SECS: u64 = 86_400;
/// Bellekte saklanacak son WAF olay kayıtlarının varsayılan üst sınırı.
pub const DEFAULT_MAX_RECENT_WAF_EVENTS: usize = 500;
/// Maksimum alan uzunluğu (günlük şişmesini ve log enjeksiyonunu önler).
const MAX_WAF_FIELD_LEN: usize = 512;
/// VHost başına pencere haritası üst sınırı (sınırsız bellek büyümesine karşı koruma).
const MAX_TRACKED_VHOSTS: usize = 10_000;

/// Sınıflandırılmış WAF kural meta verisi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WafRuleMeta {
    pub rule_id: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
}

/// Bir `WafViolation` değerini deterministik kural kimliği, kategori ve önem derecesine eşler.
pub fn classify_waf_violation(violation: &WafViolation) -> WafRuleMeta {
    match violation {
        WafViolation::SqlInjection(_) => WafRuleMeta {
            rule_id: "942100",
            category: "sqli",
            severity: "critical",
        },
        WafViolation::CrossSiteScripting(_) => WafRuleMeta {
            rule_id: "941100",
            category: "xss",
            severity: "high",
        },
        WafViolation::PathTraversal(_) => WafRuleMeta {
            rule_id: "930100",
            category: "lfi",
            severity: "critical",
        },
        WafViolation::SensitiveFileAccess(_) => WafRuleMeta {
            rule_id: "930130",
            category: "lfi",
            severity: "high",
        },
        WafViolation::CommandInjection(_) => WafRuleMeta {
            rule_id: "932100",
            category: "rce",
            severity: "critical",
        },
        WafViolation::NullByte => WafRuleMeta {
            rule_id: "920100",
            category: "other",
            severity: "high",
        },
    }
}

/// Kural ihlalinden gizli veri içermeyen standart kural etiketi üretir.
pub fn format_waf_rule_label(violation: &WafViolation) -> String {
    let meta = classify_waf_violation(violation);
    match violation {
        WafViolation::SqlInjection(sig) => {
            format!(
                "{} SQLi ({})",
                meta.rule_id,
                sanitize_waf_field(sig, "sqli", 64)
            )
        }
        WafViolation::CrossSiteScripting(sig) => {
            format!(
                "{} XSS ({})",
                meta.rule_id,
                sanitize_waf_field(sig, "xss", 64)
            )
        }
        WafViolation::PathTraversal(_) => format!("{} Path Traversal", meta.rule_id),
        WafViolation::SensitiveFileAccess(hit) => format!(
            "{} Sensitive File ({})",
            meta.rule_id,
            sanitize_waf_field(hit, "file", 64)
        ),
        WafViolation::CommandInjection(sig) => format!(
            "{} Command Injection ({})",
            meta.rule_id,
            sanitize_waf_field(sig, "cmdi", 64)
        ),
        WafViolation::NullByte => format!("{} Null Byte Injection", meta.rule_id),
    }
}

/// Geçerli UNIX epoch saniyesini döndürür.
pub fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[inline]
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

/// UNIX saniyesini ISO-8601 UTC zaman damgasına (`YYYY-MM-DDTHH:MM:SSZ`) dönüştürür.
pub fn format_utc_iso8601(unix_secs: u64) -> String {
    let epoch = i64::try_from(unix_secs).unwrap_or(i64::MAX);
    let days = epoch.div_euclid(86_400);
    let rem = epoch.rem_euclid(86_400) as u32;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    let clamped_year = year.clamp(0, 9999) as u16;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        clamped_year, month, day, hour, minute, second
    )
}

fn truncate_chars(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    let mut end = 0usize;
    for (idx, ch) in s.char_indices() {
        let next = idx + ch.len_utf8();
        if next > max_len {
            break;
        }
        end = next;
    }
    s[..end].to_string()
}

fn strip_control_chars(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch == '\0' {
            continue;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

/// Bir yol segmentinin UUID, Hex veya Base64 biçiminde bir belirteç (token) olup olmadığını belirler.
/// Kural: >=20 karakter hex / base64 / uuid ise true döndürür.
pub fn is_token_like_segment(segment: &str) -> bool {
    let s = segment.trim();
    if s.len() < 20 {
        return false;
    }

    // 1. UUID kalıbı (8-4-4-4-12 hex basamakları ve tireler, toplam 36 karakter)
    if s.len() == 36 {
        let bytes = s.as_bytes();
        if bytes[8] == b'-' && bytes[13] == b'-' && bytes[18] == b'-' && bytes[23] == b'-' {
            let is_uuid = bytes.iter().enumerate().all(|(idx, &b)| {
                if idx == 8 || idx == 13 || idx == 18 || idx == 23 {
                    true
                } else {
                    b.is_ascii_hexdigit()
                }
            });
            if is_uuid {
                return true;
            }
        }
    }

    // 2. Hex kalıbı (uzunluk >= 20 ve tüm karakterler 0-9, a-f, A-F)
    if s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // 3. Base64 / Base64URL kalıbı (uzunluk >= 20, geçerli base64 karakterleri)
    let is_b64_chars = s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '-'
            || c == '_'
            || c == '+'
            || c == '/'
            || c == '='
    });
    if is_b64_chars {
        let has_digit = s.chars().any(|c| c.is_ascii_digit());
        let has_symbol = s.chars().any(|c| c == '=' || c == '-' || c == '_' || c == '+' || c == '/');
        let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
        let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
        if has_digit || has_symbol || (has_lower && has_upper) {
            return true;
        }
    }

    false
}

fn redact_inline_headers_and_userinfo(raw: &str) -> String {
    let mut s = raw.to_string();

    // URL içi gömülü kimlik bilgisi: http(s)://user:pass@host -> http(s)://[REDACTED]@host
    for scheme in ["https://", "http://"] {
        let lower = s.to_ascii_lowercase();
        if let Some(pos) = lower.find(scheme) {
            let after_scheme = pos + scheme.len();
            let rest = &s[after_scheme..];
            let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            if let Some(at_rel) = rest[..auth_end].rfind('@') {
                let mut replaced = String::with_capacity(s.len());
                replaced.push_str(&s[..after_scheme]);
                replaced.push_str("[REDACTED]@");
                replaced.push_str(&rest[at_rel + 1..]);
                s = replaced;
            }
        }
    }

    // Metin içinde Cookie:, Set-Cookie:, Authorization: kalıpları geçerse kalan kısmı maskele
    let lower = s.to_ascii_lowercase();
    for needle in ["cookie:", "set-cookie:", "authorization:"] {
        if let Some(pos) = lower.find(needle) {
            let keep_end = pos + needle.len();
            s.truncate(keep_end);
            s.push_str("[REDACTED]");
            break;
        }
    }

    s
}

/// Erişim ve yönlendirme günlüklerinde URL içindeki parola ve kimlik bilgilerini gizler.
pub fn redact_sensitive_url_target(raw_target: &str) -> String {
    redact_inline_headers_and_userinfo(&strip_control_chars(raw_target))
}

/// WAF olay günlüğüne yazılacak istek yolunu temizler:
/// - Sorgu DEĞERLERİNİ hiçbir şekilde yazmaz (yalnız `anahtar=` biçiminde bırakır).
/// - Yoldaki token-benzeri segmentleri (>=20 karakter hex/base64/uuid) `{token}` yapar.
/// - Parola, çerez, belirteç ve kontrol karakterlerini gizler.
pub fn sanitize_waf_path(raw_path: &str) -> String {
    let cleaned = strip_control_chars(raw_path);
    if cleaned.is_empty() {
        return "/".to_string();
    }

    // Şema ve sunucu öneki varsa (örn. https://vhost.test/...) temizle
    let path_to_process = if let Some(idx) = cleaned.find("://") {
        let after_scheme = &cleaned[idx + 3..];
        if let Some(slash_idx) = after_scheme.find('/') {
            &after_scheme[slash_idx..]
        } else {
            "/"
        }
    } else {
        &cleaned
    };

    let (path_part, query_part) = match path_to_process.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (path_to_process, None),
    };

    // Yol segmentlerini tek tek incele ve token maskelemesi uygula
    let mut sanitized_path_segments = Vec::new();
    for seg in path_part.split('/') {
        if seg.is_empty() {
            sanitized_path_segments.push(String::new());
            continue;
        }

        let (seg_base, matrix_opt) = match seg.split_once(';') {
            Some((b, m)) => (b, Some(m)),
            None => (seg, None),
        };

        let masked_base = if is_token_like_segment(seg_base) {
            "{token}".to_string()
        } else if let Some((file_stem, ext)) = seg_base.rsplit_once('.') {
            if is_token_like_segment(file_stem) {
                format!("{{token}}.{}", ext)
            } else {
                seg_base.to_string()
            }
        } else {
            seg_base.to_string()
        };

        let final_seg = if let Some(matrix) = matrix_opt {
            let mut matrix_out = String::new();
            for item in matrix.split(';') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let key = if let Some((k, _)) = item.split_once('=') {
                    k
                } else if let Some(idx) = item.to_ascii_lowercase().find("%3d") {
                    &item[..idx]
                } else {
                    item
                };
                matrix_out.push(';');
                matrix_out.push_str(key.trim());
                matrix_out.push('=');
            }
            format!("{}{}", masked_base, matrix_out)
        } else {
            masked_base
        };

        sanitized_path_segments.push(final_seg);
    }

    let mut sanitized_path = sanitized_path_segments.join("/");
    if sanitized_path.is_empty() {
        sanitized_path = "/".to_string();
    }

    // Sorgu dizesi işleme: DEĞERLERİ HİÇBİR ŞEKİLDE YAZMA, yalnızca anahtar adları
    if let Some(query) = query_part {
        let mut query_params = Vec::new();
        for item in query.split('&') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let key = if let Some((k, _)) = item.split_once('=') {
                k
            } else if let Some(idx) = item.to_ascii_lowercase().find("%3d") {
                &item[..idx]
            } else {
                item
            };
            query_params.push(format!("{}=", key.trim()));
        }
        if !query_params.is_empty() {
            sanitized_path.push('?');
            sanitized_path.push_str(&query_params.join("&"));
        } else {
            sanitized_path.push('?');
        }
    }

    truncate_chars(&sanitized_path, MAX_WAF_FIELD_LEN)
}

/// Genel WAF olay alanlarını (IP, vhost, kural vb.) temizler ve kontrol karakterlerini kaldırır.
pub fn sanitize_waf_field(raw: &str, fallback: &str, max_len: usize) -> String {
    let cleaned = strip_control_chars(raw);
    if cleaned.is_empty() {
        return fallback.to_string();
    }
    let truncated = truncate_chars(&cleaned, max_len);
    if truncated.is_empty() {
        fallback.to_string()
    } else {
        truncated
    }
}

fn json_escape_str(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
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

/// Tekil WAF engelleme/denetim olay kaydı (parola, çerez ve sorgu değeri içermez).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafEventRecord {
    pub timestamp_unix: u64,
    pub timestamp: String,
    pub vhost: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub rule_id: String,
    pub rule: String,
    pub category: String,
    pub severity: String,
    pub action: String,
}

impl WafEventRecord {
    /// Verilen `WafViolation` ve istek bağlamından parola/çerez/değerden arındırılmış kayıt üretir.
    pub fn from_violation(
        violation: &WafViolation,
        vhost: &str,
        client_ip: &str,
        method: &str,
        path: &str,
        timestamp_unix: u64,
    ) -> Self {
        let meta = classify_waf_violation(violation);
        let rule = format_waf_rule_label(violation);
        Self {
            timestamp_unix,
            timestamp: format_utc_iso8601(timestamp_unix),
            vhost: sanitize_waf_field(vhost, "default", 255),
            client_ip: sanitize_waf_field(client_ip, "-", 64),
            method: sanitize_waf_field(method, "GET", 16),
            path: sanitize_waf_path(path),
            rule_id: meta.rule_id.to_string(),
            rule: sanitize_waf_field(&rule, meta.rule_id, 128),
            category: meta.category.to_string(),
            severity: meta.severity.to_string(),
            action: "block".to_string(),
        }
    }

    /// WAF olayını tek satırlık geçerli JSON olarak biçimlendirir (sonuna `\n` ekler).
    pub fn to_json_line(&self) -> String {
        format!(
            "{{\"ts\":\"{}\",\"ts_unix\":{},\"vhost\":\"{}\",\"ip\":\"{}\",\"method\":\"{}\",\"path\":\"{}\",\"rule_id\":\"{}\",\"rule\":\"{}\",\"category\":\"{}\",\"severity\":\"{}\",\"action\":\"{}\"}}\n",
            json_escape_str(&self.timestamp),
            self.timestamp_unix,
            json_escape_str(&self.vhost),
            json_escape_str(&self.client_ip),
            json_escape_str(&self.method),
            json_escape_str(&self.path),
            json_escape_str(&self.rule_id),
            json_escape_str(&self.rule),
            json_escape_str(&self.category),
            json_escape_str(&self.severity),
            json_escape_str(&self.action),
        )
    }
}

#[derive(Debug, Default)]
struct WindowBuckets {
    buckets: VecDeque<(u64, u64)>,
    total_in_window: u64,
}

impl WindowBuckets {
    fn prune(&mut self, now_unix: u64, window_secs: u64) {
        let cutoff = now_unix.saturating_sub(window_secs);
        while let Some(&(ts, cnt)) = self.buckets.front() {
            if ts < cutoff {
                self.buckets.pop_front();
                self.total_in_window = self.total_in_window.saturating_sub(cnt);
            } else {
                break;
            }
        }
    }

    fn push(&mut self, now_unix: u64, window_secs: u64) {
        self.prune(now_unix, window_secs);
        if let Some((last_ts, last_cnt)) = self.buckets.back_mut() {
            if *last_ts == now_unix {
                *last_cnt = last_cnt.saturating_add(1);
                self.total_in_window = self.total_in_window.saturating_add(1);
                return;
            }
        }
        self.buckets.push_back((now_unix, 1));
        self.total_in_window = self.total_in_window.saturating_add(1);
    }
}

#[derive(Debug)]
struct WafStoreInner {
    global_window: WindowBuckets,
    vhost_windows: HashMap<String, WindowBuckets>,
    recent_events: VecDeque<WafEventRecord>,
}

/// 24 saatlik WAF olay sayacını, kuyruk düşürme sayacını ve son olayları bellekte kilitlenmeye dayanıklı biçimde tutar.
#[derive(Debug)]
pub struct WafEventStore {
    total_events: AtomicU64,
    dropped_events: AtomicU64,
    max_recent_events: usize,
    window_secs: u64,
    inner: Mutex<WafStoreInner>,
}

impl Default for WafEventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WafEventStore {
    /// Varsayılan 24 saatlik pencere ve 500 son olay kapasitesiyle yeni depo oluşturur.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_RECENT_WAF_EVENTS, WAF_EVENT_WINDOW_SECS)
    }

    /// Özel son olay kapasitesi ve zaman penceresiyle yeni depo oluşturur.
    pub fn with_limits(max_recent_events: usize, window_secs: u64) -> Self {
        let cap = max_recent_events.max(1);
        Self {
            total_events: AtomicU64::new(0),
            dropped_events: AtomicU64::new(0),
            max_recent_events: cap,
            window_secs: window_secs.max(1),
            inner: Mutex::new(WafStoreInner {
                global_window: WindowBuckets::default(),
                vhost_windows: HashMap::new(),
                recent_events: VecDeque::with_capacity(cap.min(512)),
            }),
        }
    }

    /// WAF ihlalini geçerli sistem saatiyle kaydeder, sayaçları artırır ve temizlenmiş kaydı döndürür.
    pub fn record_violation(
        &self,
        violation: &WafViolation,
        vhost: &str,
        client_ip: &str,
        method: &str,
        path: &str,
    ) -> WafEventRecord {
        self.record_violation_at(
            violation,
            vhost,
            client_ip,
            method,
            path,
            current_unix_secs(),
        )
    }

    /// WAF ihlalini belirtilen UNIX zaman damgasıyla kaydeder (belirlenimci testler için uygundur).
    pub fn record_violation_at(
        &self,
        violation: &WafViolation,
        vhost: &str,
        client_ip: &str,
        method: &str,
        path: &str,
        now_unix: u64,
    ) -> WafEventRecord {
        let record =
            WafEventRecord::from_violation(violation, vhost, client_ip, method, path, now_unix);
        self.record_entry(record.clone());
        record
    }

    /// Hazır bir `WafEventRecord` kaydını depoya işler ve sayaçları günceller.
    pub fn record_entry(&self, record: WafEventRecord) {
        self.total_events.fetch_add(1, Ordering::Relaxed);
        let now_unix = record.timestamp_unix;
        let window_secs = self.window_secs;
        let vhost_key = record.vhost.to_ascii_lowercase();

        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.global_window.push(now_unix, window_secs);

        if guard.vhost_windows.len() >= MAX_TRACKED_VHOSTS {
            guard.vhost_windows.retain(|_, wb| {
                wb.prune(now_unix, window_secs);
                wb.total_in_window > 0
            });
        }
        if guard.vhost_windows.contains_key(&vhost_key)
            || guard.vhost_windows.len() < MAX_TRACKED_VHOSTS
        {
            guard
                .vhost_windows
                .entry(vhost_key)
                .or_default()
                .push(now_unix, window_secs);
        }

        if guard.recent_events.len() >= self.max_recent_events {
            guard.recent_events.pop_back();
        }
        guard.recent_events.push_front(record);
    }

    /// Süreç başlangıcından bu yana kaydedilen toplam WAF olay sayısını döndürür.
    pub fn total_count(&self) -> u64 {
        self.total_events.load(Ordering::Relaxed)
    }

    /// Kuyruk taşması nedeniyle günlüğe yazılamayan olay sayısını artırır.
    pub fn record_dropped(&self) {
        self.dropped_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Kuyruk taşması nedeniyle düşürülen WAF olay sayısını döndürür.
    pub fn dropped_events(&self) -> u64 {
        self.dropped_events.load(Ordering::Relaxed)
    }

    /// Son 24 saatteki toplam WAF olay sayısını döndürür.
    pub fn last_24h_count(&self) -> u64 {
        self.last_24h_count_at(current_unix_secs())
    }

    /// Belirtilen referans zamanına göre son penceredeki WAF olay sayısını döndürür.
    pub fn last_24h_count_at(&self, now_unix: u64) -> u64 {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.global_window.prune(now_unix, self.window_secs);
        guard.global_window.total_in_window
    }

    /// Belirli bir vHost için son 24 saatteki WAF olay sayısını döndürür.
    pub fn last_24h_count_for_vhost(&self, vhost: &str) -> u64 {
        self.last_24h_count_for_vhost_at(vhost, current_unix_secs())
    }

    /// Belirli bir vHost ve referans zamanına göre son penceredeki WAF olay sayısını döndürür.
    pub fn last_24h_count_for_vhost_at(&self, vhost: &str, now_unix: u64) -> u64 {
        let key = sanitize_waf_field(vhost, "default", 255).to_ascii_lowercase();
        let window_secs = self.window_secs;
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(wb) = guard.vhost_windows.get_mut(&key) else {
            return 0;
        };
        wb.prune(now_unix, window_secs);
        let count = wb.total_in_window;
        if count == 0 {
            guard.vhost_windows.remove(&key);
        }
        count
    }

    /// Halka tamponda tutulan son olay sayısını döndürür.
    pub fn recent_count(&self) -> usize {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.recent_events.len()
    }

    /// En yeniden eskiye doğru en fazla `limit` son WAF olayını döndürür.
    pub fn recent_events(&self, limit: usize) -> Vec<WafEventRecord> {
        if limit == 0 {
            return Vec::new();
        }
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.recent_events.iter().take(limit).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_iso8601_formats_epoch_and_reference_date() {
        assert_eq!(format_utc_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc_iso8601(1_794_430_800), "2026-11-11T21:00:00Z");
    }

    #[test]
    fn is_token_like_segment_detects_uuid_hex_and_base64() {
        // UUID
        assert!(is_token_like_segment("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_token_like_segment("c9bf9e57-1685-4c89-bafb-ff5af830be8a"));

        // Hex token (>=20 karakter)
        assert!(is_token_like_segment("4f5a6b7c8d9e0f1a2b3c4d5e"));
        assert!(is_token_like_segment("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

        // Base64 token (>=20 karakter)
        assert!(is_token_like_segment("dGVzdC10b2tlbi1leGFtcGxlLTEyMzQ1Ng=="));
        assert!(is_token_like_segment("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));

        // Normal kısa yollar token DEĞİLDİR
        assert!(!is_token_like_segment("index.html"));
        assert!(!is_token_like_segment("login"));
        assert!(!is_token_like_segment("webhook"));
        assert!(!is_token_like_segment("short-token"));
    }

    #[test]
    fn sanitize_waf_path_masks_tokens_and_suppresses_query_values() {
        // 1. UUID segment maskelemesi
        let p_uuid = sanitize_waf_path("/reset/550e8400-e29b-41d4-a716-446655440000/confirm");
        assert_eq!(p_uuid, "/reset/{token}/confirm");

        // 2. Hex token segment maskelemesi
        let p_hex = sanitize_waf_path("/reset/4f5a6b7c8d9e0f1a2b3c4d5e/confirm");
        assert_eq!(p_hex, "/reset/{token}/confirm");

        // 3. Base64 token segment maskelemesi
        let p_b64 = sanitize_waf_path("/verify/dGVzdC10b2tlbi1leGFtcGxlLTEyMzQ1Ng==/ok");
        assert_eq!(p_b64, "/verify/{token}/ok");

        // 4. Sorgu DEĞERLERİ asla yazılmaz, yalnızca anahtarlar kalır
        let p_query = sanitize_waf_path(
            "/giris?password=CokGizliParola123&%70assword=GizliP&user_pass=admin1&pw=1234&api-key=abcxyz&sessionid=sess99&code=oauth_code_here&q=union+select",
        );
        assert!(!p_query.contains("CokGizliParola123"), "{p_query}");
        assert!(!p_query.contains("GizliP"), "{p_query}");
        assert!(!p_query.contains("admin1"), "{p_query}");
        assert!(!p_query.contains("1234"), "{p_query}");
        assert!(!p_query.contains("abcxyz"), "{p_query}");
        assert!(!p_query.contains("sess99"), "{p_query}");
        assert!(!p_query.contains("oauth_code_here"), "{p_query}");
        assert!(!p_query.contains("union+select"), "{p_query}");

        assert!(p_query.contains("password="), "{p_query}");
        assert!(p_query.contains("%70assword="), "{p_query}");
        assert!(p_query.contains("user_pass="), "{p_query}");
        assert!(p_query.contains("pw="), "{p_query}");
        assert!(p_query.contains("api-key="), "{p_query}");
        assert!(p_query.contains("sessionid="), "{p_query}");
        assert!(p_query.contains("code="), "{p_query}");
        assert!(p_query.contains("q="), "{p_query}");

        // 5. Matris parametrelerinde de değerler maskelenir
        let p_matrix = sanitize_waf_path("/sayfa;token=SecretTok;jsessionid=Sess123?id=100");
        assert_eq!(p_matrix, "/sayfa;token=;jsessionid=?id=");
        assert!(!p_matrix.contains("SecretTok"), "{p_matrix}");
        assert!(!p_matrix.contains("Sess123"), "{p_matrix}");
        assert!(!p_matrix.contains("100"), "{p_matrix}");
    }

    #[test]
    fn violation_classification_and_json_serialization_contain_required_fields() {
        let store = WafEventStore::new();
        let rec = store.record_violation_at(
            &WafViolation::SqlInjection("union select".to_string()),
            "site.test",
            "203.0.113.9",
            "GET",
            "/arama?password=SuperSecret&id=1",
            1_794_430_800,
        );

        assert_eq!(rec.timestamp, "2026-11-11T21:00:00Z");
        assert_eq!(rec.rule_id, "942100");
        assert_eq!(rec.category, "sqli");
        assert_eq!(rec.severity, "critical");
        assert_eq!(rec.vhost, "site.test");
        assert_eq!(rec.client_ip, "203.0.113.9");
        assert_eq!(rec.path, "/arama?password=&id=");

        let line = rec.to_json_line();
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"ts\":\"2026-11-11T21:00:00Z\""));
        assert!(line.contains("\"rule_id\":\"942100\""));
        assert!(line.contains("\"vhost\":\"site.test\""));
        assert!(line.contains("\"ip\":\"203.0.113.9\""));
        assert!(line.contains("\"path\":\"/arama?password=&id=\""));
        assert!(line.contains("\"action\":\"block\""));
        assert!(!line.contains("SuperSecret"), "{line}");
    }

    #[test]
    fn store_tracks_total_24h_window_dropped_and_recent_ring_buffer() {
        let store = WafEventStore::with_limits(3, 86_400);
        let t0 = 1_794_430_800u64;

        store.record_violation_at(
            &WafViolation::SqlInjection("union select".to_string()),
            "a.test",
            "1.1.1.1",
            "GET",
            "/a1",
            t0,
        );
        store.record_violation_at(
            &WafViolation::CrossSiteScripting("<script".to_string()),
            "a.test",
            "1.1.1.2",
            "GET",
            "/a2",
            t0 + 100,
        );
        store.record_violation_at(
            &WafViolation::CommandInjection("cmd.exe".to_string()),
            "b.test",
            "2.2.2.2",
            "POST",
            "/b1",
            t0 + 200,
        );
        store.record_violation_at(
            &WafViolation::NullByte,
            "a.test",
            "1.1.1.3",
            "GET",
            "/a3",
            t0 + 86_450,
        );

        assert_eq!(store.total_count(), 4);
        assert_eq!(store.recent_count(), 3);
        let recent = store.recent_events(10);
        assert_eq!(recent[0].path, "/a3");
        assert_eq!(recent[1].path, "/b1");
        assert_eq!(recent[2].path, "/a2");

        // t0+86_450 anında t0 (86_450 sn önce) pencereden düşmüş olmalı; kalan 3 olay
        assert_eq!(store.last_24h_count_at(t0 + 86_450), 3);
        assert_eq!(store.last_24h_count_for_vhost_at("a.test", t0 + 86_450), 2);
        assert_eq!(store.last_24h_count_for_vhost_at("b.test", t0 + 86_450), 1);

        // Pencere tamamen geçince 24 saatlik sayaç 0 olmalı ama toplam sayaç 4 kalmalı
        assert_eq!(store.last_24h_count_at(t0 + 200_000), 0);
        assert_eq!(store.last_24h_count_for_vhost_at("a.test", t0 + 200_000), 0);
        assert_eq!(store.total_count(), 4);

        // dropped_events sayacı testi
        assert_eq!(store.dropped_events(), 0);
        store.record_dropped();
        store.record_dropped();
        assert_eq!(store.dropped_events(), 2);
    }
}
