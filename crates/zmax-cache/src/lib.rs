//! # zmax-cache
//! ZMax Server LSCache dengi yüksek hızlı L1 bellek + L2 disk sayfa önbellek motoru.

use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use moka::future::Cache;
use moka::Expiry;
use std::borrow::Borrow;
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

const DISK_CACHE_MAGIC: &[u8; 4] = b"ZMXC";
const DISK_CACHE_VERSION_V1: u16 = 1;
const DISK_CACHE_VERSION: u16 = 2;
static DISK_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedResponse {
    pub status: u16,
    pub content_type: String,
    pub body: Bytes,
    pub tags: Vec<String>,
}

/// Önbellek okuma sonucunu (taze, bayat veya ıskalama) temsil eder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    /// Yaşam süresi dolmamış taze önbellek yanıtı.
    Fresh(CachedResponse),
    /// Taze süresi dolmuş ancak bayat sunum penceresi (`stale_until_ms`) içindeki yanıt.
    Stale(CachedResponse),
    /// Kayıt bulunamadı veya bayat sunum penceresi de doldu.
    Miss,
}

/// Cache Stampede (Singleflight) liderliğini tutan ve bırakıldığında bekleyenleri uyandıran koruyucu.
pub struct StampedeGuard {
    inflight: Arc<DashMap<String, Arc<Notify>>>,
    key: String,
    notify: Arc<Notify>,
}

impl fmt::Debug for StampedeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StampedeGuard")
            .field("key", &self.key)
            .finish()
    }
}

impl Drop for StampedeGuard {
    fn drop(&mut self) {
        self.inflight
            .remove_if(&self.key, |_, existing| Arc::ptr_eq(existing, &self.notify));
        self.notify.notify_waiters();
    }
}

/// Eşzamanlı önbellek doldurma yarışı (Singleflight) için lider veya takipçi yuvası.
#[derive(Debug)]
pub enum StampedeSlot {
    /// Kaynağı doldurmaktan sorumlu tek lider istek; koruyucu bırakıldığında takipçiler uyanır.
    Leader(StampedeGuard),
    /// Liderin işlemi tamamlamasını `notified()` üzerinden bekleyen takipçi istek.
    Follower(Arc<Notify>),
}

#[derive(Clone, Debug)]
struct CacheEntry {
    response: CachedResponse,
    cached_at_ms: u64,
    expires_at_ms: u64,
    pub stale_until_ms: u64,
}

struct PerEntryExpiry;

impl Expiry<String, CacheEntry> for PerEntryExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &CacheEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        let remaining_ms = value.stale_until_ms.saturating_sub(now_epoch_ms());
        Some(Duration::from_millis(remaining_ms))
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &CacheEntry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        let remaining_ms = value.stale_until_ms.saturating_sub(now_epoch_ms());
        Some(Duration::from_millis(remaining_ms))
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Sanal konak, protokol, metot, yol, sorgu dizgesi ve Accept-Encoding bilgilerini
/// birleştirerek çakışmasız benzersiz bir önbellek anahtarı üretir.
pub fn build_cache_key(
    vhost: &str,
    is_https: bool,
    method: &str,
    path: &str,
    query: &str,
    accept_encoding: Option<&str>,
) -> String {
    let scheme = if is_https { "https" } else { "http" };
    let clean_vhost = {
        let v = vhost.trim().to_ascii_lowercase().replace('|', "_");
        if v.is_empty() {
            "default".to_string()
        } else {
            v
        }
    };
    let clean_method = {
        let m = method.trim().to_ascii_uppercase().replace('|', "_");
        if m.is_empty() {
            "GET".to_string()
        } else {
            m
        }
    };
    let clean_path = if path.is_empty() { "/" } else { path };
    let clean_enc = accept_encoding
        .map(|s| s.trim().to_ascii_lowercase().replace('|', ","))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "identity".to_string());

    format!("{scheme}://{clean_vhost}|{clean_method}|{clean_enc}|{clean_path}?{query}")
}

/// Ham URI girdisinden temiz yol (`path`) bilgisini ayıklar.
///
/// Örnekler:
/// - `"/index.html?v=1"` -> `"/index.html"`
/// - `"http://site.test|GET|identity|/api/v1?page=1"` -> `"/api/v1"`
/// - `"https://site.test/foo/bar?baz"` -> `"/foo/bar"`
/// - `"index.html"` -> `"/index.html"`
pub fn extract_path_from_uri(uri: &str) -> String {
    let u = uri.trim();
    if u.is_empty() {
        return "/".to_string();
    }
    // Bileşik anahtar formatı (içinde '|' olan)
    if let Some(pipe_idx) = u.rfind('|') {
        let after_pipe = &u[pipe_idx + 1..];
        let path_part = after_pipe.split('?').next().unwrap_or("/");
        return if path_part.starts_with('/') {
            path_part.to_string()
        } else {
            format!("/{path_part}")
        };
    }
    // HTTP/HTTPS tam URL
    if let Some(scheme_end) = u.find("://") {
        let rest = &u[scheme_end + 3..];
        if let Some(slash_idx) = rest.find('/') {
            let path_query = &rest[slash_idx..];
            let path_part = path_query.split('?').next().unwrap_or("/");
            return path_part.to_string();
        }
        return "/".to_string();
    }
    // Normal yol (query içerebilir)
    let path_part = u.split('?').next().unwrap_or("/");
    if path_part.starts_with('/') {
        path_part.to_string()
    } else {
        format!("/{path_part}")
    }
}

/// Verilen önbellek anahtarının belirtilen yol veya URI ile eşleşip eşleşmediğini doğrular.
pub fn key_matches_uri(key: &str, target_path: &str) -> bool {
    let clean_target = if target_path.starts_with('/') {
        target_path
    } else {
        target_path
    };
    if key == target_path || key == clean_target {
        return true;
    }
    // Bileşik anahtar ayrıştırması
    if let Some(last_pipe) = key.rfind('|') {
        let path_query = &key[last_pipe + 1..];
        let key_path = path_query.split('?').next().unwrap_or("");
        if key_path == clean_target {
            return true;
        }
        if clean_target.starts_with('/') && key_path == &clean_target[1..] {
            return true;
        }
        if !clean_target.starts_with('/') && key_path.starts_with('/') && &key_path[1..] == clean_target {
            return true;
        }
    }
    false
}

/// LiteSpeed (`X-LiteSpeed-Cache-Control`, `X-LiteSpeed-Tag`, `X-LiteSpeed-Purge`, `X-LiteSpeed-Vary`)
/// HTTP yanıt başlıklarından ayrıştırılan önbellek yönergeleri.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LsCacheDirective {
    pub cacheable: Option<bool>,
    pub max_age_secs: Option<u64>,
    pub is_private: bool,
    pub no_vary: bool,
    pub tags: Vec<String>,
    pub purge_tags: Vec<String>,
    pub purge_all: bool,
    pub vary_cookies: Vec<String>,
    pub vary_headers: Vec<String>,
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !item.is_empty() && !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

fn escape_vary_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '|' => out.push_str("%7C"),
            ';' => out.push_str("%3B"),
            '=' => out.push_str("%3D"),
            _ => out.push(ch),
        }
    }
    out
}

/// HTTP başlıklarından LSCache (`X-LiteSpeed-*`) yönergelerini ayrıştırır.
pub fn parse_lscache_headers<'a, I>(headers: I) -> LsCacheDirective
where
    I: IntoIterator,
    I::Item: Borrow<(&'a str, &'a str)>,
{
    let mut dir = LsCacheDirective::default();
    let mut saw_public = false;
    let mut saw_no_cache = false;
    let mut saw_private = false;

    for item in headers {
        let &(name, value) = item.borrow();
        let name = name.trim();
        if name.eq_ignore_ascii_case("x-litespeed-cache-control") {
            for part in value.split(',') {
                let tok = part.trim();
                if tok.is_empty() {
                    continue;
                }
                let lower = tok.to_ascii_lowercase();
                if lower == "no-cache" || lower == "no-store" {
                    saw_no_cache = true;
                } else if lower == "public" {
                    saw_public = true;
                } else if lower == "private" {
                    saw_private = true;
                    dir.is_private = true;
                } else if lower == "no-vary" {
                    dir.no_vary = true;
                } else if let Some(secs_str) = lower.strip_prefix("max-age=") {
                    if let Ok(secs) = secs_str.trim().parse::<u64>() {
                        dir.max_age_secs = Some(secs);
                    }
                }
            }
        } else if name.eq_ignore_ascii_case("x-litespeed-tag") {
            for part in value.split(',') {
                let tag = part.trim();
                if !tag.is_empty() {
                    push_unique(&mut dir.tags, tag.to_string());
                }
            }
        } else if name.eq_ignore_ascii_case("x-litespeed-purge") {
            let tokens: Vec<&str> = value
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            for (idx, tok) in tokens.iter().enumerate() {
                if *tok == "*" {
                    dir.purge_all = true;
                } else if idx == 0
                    && tokens.len() > 1
                    && (tok.eq_ignore_ascii_case("public")
                        || tok.eq_ignore_ascii_case("private")
                        || tok.eq_ignore_ascii_case("stale"))
                {
                    continue;
                } else {
                    push_unique(&mut dir.purge_tags, (*tok).to_string());
                }
            }
        } else if name.eq_ignore_ascii_case("x-litespeed-vary") {
            for part in value.split(',') {
                let tok = part.trim();
                if tok.is_empty() {
                    continue;
                }
                if let Some(cookie_name) = strip_prefix_ignore_ascii_case(tok, "cookie=") {
                    let cookie_name = cookie_name.trim();
                    if !cookie_name.is_empty() {
                        push_unique(&mut dir.vary_cookies, cookie_name.to_string());
                    }
                } else if let Some(hdr_name) = strip_prefix_ignore_ascii_case(tok, "header=") {
                    let hdr_name = hdr_name.trim().to_ascii_lowercase();
                    if !hdr_name.is_empty() {
                        push_unique(&mut dir.vary_headers, hdr_name);
                    }
                } else if strip_prefix_ignore_ascii_case(tok, "value=").is_some() {
                    continue;
                } else if !tok.contains('=') {
                    push_unique(&mut dir.vary_headers, tok.to_ascii_lowercase());
                }
            }
        }
    }

    dir.cacheable = if saw_no_cache || dir.max_age_secs == Some(0) {
        Some(false)
    } else if saw_public || (!saw_private && dir.max_age_secs.is_some()) {
        Some(true)
    } else {
        None
    };

    dir
}

/// `X-LiteSpeed-Vary` yönergelerine göre çerez ve başlık değerlerini temel önbellek anahtarına ekler.
pub fn build_lscache_vary_key(
    base_key: &str,
    directive: &LsCacheDirective,
    req_headers: &[(String, String)],
    cookie_header: Option<&str>,
) -> String {
    if directive.no_vary
        || (directive.vary_cookies.is_empty() && directive.vary_headers.is_empty())
    {
        return base_key.to_string();
    }

    let mut parsed_cookies: Vec<(&str, &str)> = Vec::new();
    if let Some(raw_cookies) = cookie_header {
        for pair in raw_cookies.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some((k, v)) = pair.split_once('=') {
                parsed_cookies.push((k.trim(), v.trim()));
            }
        }
    }

    let mut cookie_names: Vec<&str> = directive
        .vary_cookies
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    cookie_names.sort_unstable();
    cookie_names.dedup();

    let mut cookie_parts = Vec::with_capacity(cookie_names.len());
    for cname in cookie_names {
        let val = parsed_cookies
            .iter()
            .rev()
            .find(|(k, _)| *k == cname)
            .map(|(_, v)| *v)
            .unwrap_or("");
        cookie_parts.push(format!(
            "{}={}",
            escape_vary_component(cname),
            escape_vary_component(val)
        ));
    }

    let mut header_names: Vec<String> = directive
        .vary_headers
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    header_names.sort();
    header_names.dedup();

    let mut header_parts = Vec::with_capacity(header_names.len());
    for hname in header_names {
        let joined: String = req_headers
            .iter()
            .filter(|(k, _)| k.trim().eq_ignore_ascii_case(&hname))
            .map(|(_, v)| v.trim())
            .collect::<Vec<_>>()
            .join(",");
        header_parts.push(format!(
            "{}={}",
            escape_vary_component(&hname),
            escape_vary_component(&joined)
        ));
    }

    format!(
        "{base_key}|lsc_c=[{}]|lsc_h=[{}]",
        cookie_parts.join(";"),
        header_parts.join(";")
    )
}

/// L2 kalıcı disk önbellek deposu (`cachedata` dizini altında güvenli SHA-256 dosya adlarıyla).
#[derive(Clone, Debug)]
pub struct DiskCache {
    dir: PathBuf,
}

impl DiskCache {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Önbellek anahtarından yol enjeksiyonuna karşı tamamen güvenli `.zcache` dosya yolu üretir.
    pub fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{}.zcache", sha256_hex(key.as_bytes())))
    }

    async fn get_entry(&self, key: &str) -> Option<CacheEntry> {
        let path = self.entry_path(key);
        let raw = tokio::fs::read(&path).await.ok()?;
        let (stored_key, entry) = match decode_disk_entry(&raw) {
            Some(decoded) => decoded,
            None => {
                let _ = tokio::fs::remove_file(&path).await;
                return None;
            }
        };
        if stored_key != key {
            return None;
        }
        if now_epoch_ms() >= entry.stale_until_ms {
            let _ = tokio::fs::remove_file(&path).await;
            return None;
        }
        Some(entry)
    }

    async fn set_entry(&self, key: &str, entry: &CacheEntry) -> std::io::Result<()> {
        tokio::fs::create_dir_all(&self.dir).await?;
        let encoded = encode_disk_entry(key, entry);
        let target = self.entry_path(key);
        let seq = DISK_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!(".cache.{}.{}.tmp", std::process::id(), seq));
        tokio::fs::write(&tmp, &encoded).await?;
        if let Err(e) = tokio::fs::rename(&tmp, &target).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        Ok(())
    }

    pub async fn purge(&self, key: &str) {
        let path = self.entry_path(key);
        let _ = tokio::fs::remove_file(path).await;
    }

    pub async fn purge_all(&self) {
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else {
            return;
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str());
            if ext == Some("zcache") || ext == Some("tmp") {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
    }

    /// Diskteki kayıtları tarayarak verilen etikete sahip tüm önbellek dosyalarını siler ve anahtarlarını döner.
    pub async fn purge_by_tag(&self, tag: &str) -> Vec<String> {
        let mut purged_keys = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else {
            return purged_keys;
        };
        let now = now_epoch_ms();
        while let Ok(Some(dir_entry)) = rd.next_entry().await {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("zcache") {
                continue;
            }
            let Ok(raw) = tokio::fs::read(&path).await else {
                continue;
            };
            if let Some((key, entry)) = decode_disk_entry(&raw) {
                if now >= entry.stale_until_ms {
                    let _ = tokio::fs::remove_file(&path).await;
                } else if entry.response.tags.iter().any(|t| t == tag)
                    && tokio::fs::remove_file(&path).await.is_ok()
                {
                    purged_keys.push(key);
                }
            } else {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        purged_keys
    }

    /// Verilen alan adına ait tüm önbellek dosyalarını temizler ve anahtarlarını döner.
    pub async fn purge_by_domain_match(&self, domain: &str) -> Vec<String> {
        let mut purged_keys = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else {
            return purged_keys;
        };
        let d = domain.trim().to_ascii_lowercase();
        let needle_http = format!("http://{d}|");
        let needle_https = format!("https://{d}|");
        let tag_domain_scoped = format!("domain::{d}");
        let tag_domain_colon = format!("domain:{d}");
        let tag_wildcard = format!("{d}::*");

        while let Ok(Some(dir_entry)) = rd.next_entry().await {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("zcache") {
                continue;
            }
            let Ok(raw) = tokio::fs::read(&path).await else {
                continue;
            };
            if let Some((key, entry)) = decode_disk_entry(&raw) {
                let matches_domain = key.starts_with(&needle_http)
                    || key.starts_with(&needle_https)
                    || entry.response.tags.iter().any(|t| {
                        t == &d
                            || t == &tag_domain_scoped
                            || t == &tag_domain_colon
                            || t == &tag_wildcard
                    });
                if matches_domain && tokio::fs::remove_file(&path).await.is_ok() {
                    purged_keys.push(key);
                }
            } else {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        purged_keys
    }

    /// Verilen URI / yol ile eşleşen tüm önbellek dosyalarını temizler ve anahtarlarını döner.
    pub async fn purge_by_uri_match(&self, target_path: &str) -> Vec<String> {
        let mut purged_keys = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else {
            return purged_keys;
        };
        let uri_tag = format!("__uri:{target_path}");
        let path_tag = format!("__path:{target_path}");

        while let Ok(Some(dir_entry)) = rd.next_entry().await {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("zcache") {
                continue;
            }
            let Ok(raw) = tokio::fs::read(&path).await else {
                continue;
            };
            if let Some((key, entry)) = decode_disk_entry(&raw) {
                let matches_uri = key_matches_uri(&key, target_path)
                    || entry
                        .response
                        .tags
                        .iter()
                        .any(|t| t == &uri_tag || t == &path_tag);
                if matches_uri && tokio::fs::remove_file(&path).await.is_ok() {
                    purged_keys.push(key);
                }
            } else {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        purged_keys
    }

    /// Hem alan adı hem URI yolu eşleşen önbellek dosyalarını temizler.
    pub async fn purge_by_domain_and_uri_match(
        &self,
        domain: &str,
        target_path: &str,
    ) -> Vec<String> {
        let mut purged_keys = Vec::new();
        let Ok(mut rd) = tokio::fs::read_dir(&self.dir).await else {
            return purged_keys;
        };
        let d = domain.trim().to_ascii_lowercase();
        let needle_http = format!("http://{d}|");
        let needle_https = format!("https://{d}|");
        let tag_domain_scoped = format!("domain::{d}");
        let tag_wildcard = format!("{d}::*");
        let uri_tag = format!("__uri:{target_path}");

        while let Ok(Some(dir_entry)) = rd.next_entry().await {
            let path = dir_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("zcache") {
                continue;
            }
            let Ok(raw) = tokio::fs::read(&path).await else {
                continue;
            };
            if let Some((key, entry)) = decode_disk_entry(&raw) {
                let matches_domain = key.starts_with(&needle_http)
                    || key.starts_with(&needle_https)
                    || entry.response.tags.iter().any(|t| {
                        t == &d || t == &tag_domain_scoped || t == &tag_wildcard
                    });
                let matches_uri = key_matches_uri(&key, target_path)
                    || entry.response.tags.iter().any(|t| t == &uri_tag);

                if matches_domain && matches_uri && tokio::fs::remove_file(&path).await.is_ok() {
                    purged_keys.push(key);
                }
            } else {
                let _ = tokio::fs::remove_file(&path).await;
            }
        }
        purged_keys
    }
}

pub struct ZMaxCache {
    cache: Cache<String, CacheEntry>,
    default_ttl_seconds: u64,
    tag_index: DashMap<String, HashSet<String>>,
    key_tags: DashMap<String, Vec<String>>,
    disk: Option<DiskCache>,
    inflight: Arc<DashMap<String, Arc<Notify>>>,
}

impl ZMaxCache {
    pub fn new(max_capacity_bytes: u64, ttl_seconds: u64) -> Self {
        Self::build(max_capacity_bytes, ttl_seconds, None)
    }

    /// L1 bellek + L2 kalıcı disk önbelleği (`cachedata` dizini) ile yeni bir motor oluşturur.
    pub fn with_disk_dir(
        max_capacity_bytes: u64,
        ttl_seconds: u64,
        disk_dir: impl AsRef<Path>,
    ) -> Self {
        let dir = disk_dir.as_ref();
        let _ = std::fs::create_dir_all(dir);
        Self::build(max_capacity_bytes, ttl_seconds, Some(DiskCache::new(dir)))
    }

    /// L2 disk önbellek dizinini doğrulayıp oluşturarak motoru başlatır.
    pub fn try_with_disk_dir(
        max_capacity_bytes: u64,
        ttl_seconds: u64,
        disk_dir: impl AsRef<Path>,
    ) -> std::io::Result<Self> {
        let dir = disk_dir.as_ref();
        std::fs::create_dir_all(dir)?;
        Ok(Self::build(
            max_capacity_bytes,
            ttl_seconds,
            Some(DiskCache::new(dir)),
        ))
    }

    fn build(max_capacity_bytes: u64, ttl_seconds: u64, disk: Option<DiskCache>) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity_bytes)
            .weigher(|key: &String, entry: &CacheEntry| -> u32 {
                let weight = key.len().saturating_add(entry.response.body.len());
                weight.clamp(1, u32::MAX as usize) as u32
            })
            .expire_after(PerEntryExpiry)
            .build();

        Self {
            cache,
            default_ttl_seconds: ttl_seconds,
            tag_index: DashMap::new(),
            key_tags: DashMap::new(),
            disk,
            inflight: Arc::new(DashMap::new()),
        }
    }

    pub fn default_ttl_seconds(&self) -> u64 {
        self.default_ttl_seconds
    }

    pub fn disk_dir(&self) -> Option<&Path> {
        self.disk.as_ref().map(|d| d.dir())
    }

    fn unregister_key_tags(&self, key: &str) {
        if let Some((_, old_tags)) = self.key_tags.remove(key) {
            for tag in old_tags {
                let mut remove_bucket = false;
                if let Some(mut bucket) = self.tag_index.get_mut(&tag) {
                    bucket.remove(key);
                    if bucket.is_empty() {
                        remove_bucket = true;
                    }
                }
                if remove_bucket {
                    self.tag_index.remove(&tag);
                }
            }
        }
    }

    fn register_key_tags(&self, key: &str, tags: &[String]) {
        self.unregister_key_tags(key);
        if tags.is_empty() {
            return;
        }
        let mut unique_tags = Vec::with_capacity(tags.len());
        for tag in tags {
            if tag.is_empty() {
                continue;
            }
            if !unique_tags.iter().any(|t| t == tag) {
                unique_tags.push(tag.clone());
            }
            self.tag_index
                .entry(tag.clone())
                .or_default()
                .insert(key.to_string());
        }
        if !unique_tags.is_empty() {
            self.key_tags.insert(key.to_string(), unique_tags);
        }
    }

    /// Önbellekten girdiyi taze/bayat durumunu ayırt ederek okur (`Fresh`, `Stale`, `Miss`).
    pub async fn get_with_stale(&self, uri: &str) -> CacheLookup {
        let now = now_epoch_ms();
        if let Some(entry) = self.cache.get(uri).await {
            if now < entry.expires_at_ms {
                return CacheLookup::Fresh(entry.response);
            }
            if now < entry.stale_until_ms {
                return CacheLookup::Stale(entry.response);
            }
            self.purge(uri).await;
            return CacheLookup::Miss;
        }

        if let Some(disk) = &self.disk {
            if let Some(entry) = disk.get_entry(uri).await {
                if now < entry.expires_at_ms {
                    self.register_key_tags(uri, &entry.response.tags);
                    self.cache.insert(uri.to_string(), entry.clone()).await;
                    return CacheLookup::Fresh(entry.response);
                }
                if now < entry.stale_until_ms {
                    self.register_key_tags(uri, &entry.response.tags);
                    self.cache.insert(uri.to_string(), entry.clone()).await;
                    return CacheLookup::Stale(entry.response);
                }
                disk.purge(uri).await;
                self.unregister_key_tags(uri);
            }
        }

        CacheLookup::Miss
    }

    pub async fn get(&self, uri: &str) -> Option<CachedResponse> {
        match self.get_with_stale(uri).await {
            CacheLookup::Fresh(resp) => Some(resp),
            CacheLookup::Stale(_) | CacheLookup::Miss => None,
        }
    }

    pub async fn set(&self, uri: String, response: CachedResponse) {
        self.set_with_ttl(uri, response, self.default_ttl_seconds)
            .await;
    }

    /// `set` için uyumlu yardımcı yöntem.
    pub async fn insert(&self, key: String, response: CachedResponse) {
        self.set(key, response).await;
    }

    /// Alan adı (`domain::tag` biçimi) ve isteğe özel TTL ile etiketli önbellek kaydı ekler.
    pub async fn insert_with_tags(
        &self,
        key: String,
        mut response: CachedResponse,
        ttl_seconds: u64,
        domain: &str,
        tags: &[String],
    ) {
        let clean_domain = domain.trim().to_ascii_lowercase();
        let mut combined: Vec<String> = Vec::with_capacity(response.tags.len() + tags.len() + 1);
        for raw_tag in response.tags.iter().chain(tags.iter()) {
            let t = raw_tag.trim();
            if t.is_empty() {
                continue;
            }
            let scoped = if clean_domain.is_empty()
                || t.starts_with(&format!("{clean_domain}::"))
            {
                t.to_string()
            } else {
                Self::format_domain_tag(&clean_domain, t)
            };
            push_unique(&mut combined, scoped);
        }
        if !clean_domain.is_empty() {
            push_unique(&mut combined, Self::format_domain_tag(&clean_domain, "*"));
        }
        response.tags = combined;
        self.set_with_ttl(key, response, ttl_seconds).await;
    }

    /// Alan adı ve etiketi `domain::tag` indeks anahtarına dönüştürür.
    pub fn format_domain_tag(domain: &str, tag: &str) -> String {
        let d = domain.trim().to_ascii_lowercase();
        let t = tag.trim();
        if d.is_empty() {
            t.to_string()
        } else {
            format!("{d}::{t}")
        }
    }

    /// Girdiyi özel yaşam süresiyle (`ttl_seconds`, örn. vHost `expire`) L1 + varsa L2 önbelleğe yazar.
    pub async fn set_with_ttl(&self, key: String, response: CachedResponse, ttl_seconds: u64) {
        self.set_with_ttl_and_stale(key, response, ttl_seconds, 0)
            .await;
    }

    /// Girdiyi taze yaşam süresi (`ttl_seconds`) ve bayat sunum penceresi (`stale_seconds`) ile
    /// L1 + varsa L2 önbelleğe yazar.
    pub async fn set_with_ttl_and_stale(
        &self,
        key: String,
        response: CachedResponse,
        ttl_seconds: u64,
        stale_seconds: u64,
    ) {
        if ttl_seconds == 0 && stale_seconds == 0 {
            self.purge(&key).await;
            return;
        }

        let now = now_epoch_ms();
        let expires_at_ms = now.saturating_add(ttl_seconds.saturating_mul(1000));
        let stale_until_ms = expires_at_ms.saturating_add(stale_seconds.saturating_mul(1000));
        self.register_key_tags(&key, &response.tags);

        let entry = CacheEntry {
            response,
            cached_at_ms: now,
            expires_at_ms,
            stale_until_ms,
        };

        if let Some(disk) = &self.disk {
            let _ = disk.set_entry(&key, &entry).await;
        }
        self.cache.insert(key, entry).await;
    }

    /// Eşzamanlı önbellek ıskalamalarında (Cache Stampede) tek bir lider seçer;
    /// diğer istekler liderin `StampedeGuard` bırakmasını bekleyecek bir `Follower(Notify)` alır.
    pub fn try_acquire_fill(&self, key: &str) -> StampedeSlot {
        match self.inflight.entry(key.to_string()) {
            Entry::Occupied(existing) => StampedeSlot::Follower(Arc::clone(existing.get())),
            Entry::Vacant(slot) => {
                let notify = Arc::new(Notify::new());
                slot.insert(Arc::clone(&notify));
                StampedeSlot::Leader(StampedeGuard {
                    inflight: Arc::clone(&self.inflight),
                    key: key.to_string(),
                    notify,
                })
            }
        }
    }

    pub async fn purge(&self, uri: &str) {
        self.cache.invalidate(uri).await;
        self.unregister_key_tags(uri);
        if let Some(disk) = &self.disk {
            disk.purge(uri).await;
        }
    }

    async fn purge_by_tag_keys(&self, tag: &str) -> HashSet<String> {
        let mut purged_keys: HashSet<String> = HashSet::new();
        if tag.is_empty() {
            return purged_keys;
        }
        if let Some((_, keys)) = self.tag_index.remove(tag) {
            for key in keys {
                self.cache.invalidate(&key).await;
                self.unregister_key_tags(&key);
                if let Some(disk) = &self.disk {
                    disk.purge(&key).await;
                }
                purged_keys.insert(key);
            }
        }

        if let Some(disk) = &self.disk {
            for key in disk.purge_by_tag(tag).await {
                self.cache.invalidate(&key).await;
                self.unregister_key_tags(&key);
                purged_keys.insert(key);
            }
        }

        purged_keys
    }

    /// Verilen etikete (`tag`, örn. vHost adı veya sayfa grubu) bağlı tüm L1 ve L2 girdilerini temizler.
    pub async fn purge_by_tag(&self, tag: &str) -> usize {
        self.purge_by_tag_keys(tag).await.len()
    }

    /// Belirli bir alan adına ait tüm önbellek girdilerini temizler (L1 ve L2).
    /// Hem `domain::<alan>`, `<alan>`, `<alan>::*` etiketlerini hem de bileşik anahtarlardaki alan adını eşleştirir.
    pub async fn purge_by_domain(&self, domain: &str) -> usize {
        let d = domain.trim().to_ascii_lowercase();
        if d.is_empty() {
            return 0;
        }
        let mut purged_keys: HashSet<String> = HashSet::new();

        // 1. Olası tüm etiket formatlarını temizle
        let candidate_tags = [
            Self::format_domain_tag(&d, "*"),
            format!("domain::{d}"),
            format!("domain:{d}"),
            d.clone(),
        ];
        for tag in &candidate_tags {
            purged_keys.extend(self.purge_by_tag_keys(tag).await);
        }

        // 2. L1 anahtar listesinde (key_tags) domain bileşeni içerenleri temizle
        let domain_needle_http = format!("http://{d}|");
        let domain_needle_https = format!("https://{d}|");
        let matching_l1_keys: Vec<String> = self
            .key_tags
            .iter()
            .filter(|entry| {
                let k = entry.key();
                k.starts_with(&domain_needle_http) || k.starts_with(&domain_needle_https)
            })
            .map(|entry| entry.key().clone())
            .collect();

        for key in matching_l1_keys {
            self.cache.invalidate(&key).await;
            self.unregister_key_tags(&key);
            if let Some(disk) = &self.disk {
                disk.purge(&key).await;
            }
            purged_keys.insert(key);
        }

        // 3. L2 disk önbelleğinde domaine ait dosyaları temizle
        if let Some(disk) = &self.disk {
            for key in disk.purge_by_domain_match(&d).await {
                self.cache.invalidate(&key).await;
                self.unregister_key_tags(&key);
                purged_keys.insert(key);
            }
        }

        purged_keys.len()
    }

    /// Ham URI yolu veya anahtar ile önbellek girdilerini temizler (L1 ve L2).
    /// Tam anahtar eşleşmesini, `__uri:<path>` etiketini ve anahtar içindeki path ayrıştırmasını destekler.
    pub async fn purge_by_uri(&self, target_uri: &str) -> usize {
        let uri = target_uri.trim();
        if uri.is_empty() {
            return 0;
        }
        let mut purged_keys: HashSet<String> = HashSet::new();

        // 1. Doğrudan tam anahtar olarak dene
        if self.key_tags.contains_key(uri) {
            self.cache.invalidate(uri).await;
            self.unregister_key_tags(uri);
            if let Some(disk) = &self.disk {
                disk.purge(uri).await;
            }
            purged_keys.insert(uri.to_string());
        }

        // 2. URI'yi temiz path biçimine dönüştür
        let normalized_path = extract_path_from_uri(uri);

        // 3. Etiket eşleşmesi: __uri:<path> ve __path:<path>
        let uri_tag = format!("__uri:{normalized_path}");
        let path_tag = format!("__path:{normalized_path}");
        purged_keys.extend(self.purge_by_tag_keys(&uri_tag).await);
        purged_keys.extend(self.purge_by_tag_keys(&path_tag).await);

        // 4. L1 anahtarlarını tara
        let matching_l1_keys: Vec<String> = self
            .key_tags
            .iter()
            .filter(|entry| key_matches_uri(entry.key(), &normalized_path))
            .map(|entry| entry.key().clone())
            .collect();

        for key in matching_l1_keys {
            self.cache.invalidate(&key).await;
            self.unregister_key_tags(&key);
            if let Some(disk) = &self.disk {
                disk.purge(&key).await;
            }
            purged_keys.insert(key);
        }

        // 5. L2 disk önbelleğinde eşleşenleri temizle
        if let Some(disk) = &self.disk {
            for key in disk.purge_by_uri_match(&normalized_path).await {
                self.cache.invalidate(&key).await;
                self.unregister_key_tags(&key);
                purged_keys.insert(key);
            }
        }

        purged_keys.len()
    }

    /// Belirli bir alan adı ve URI yolu ile eşleşen önbellek girdilerini temizler (L1 ve L2).
    pub async fn purge_by_domain_uri(&self, domain: &str, target_uri: &str) -> usize {
        let d = domain.trim().to_ascii_lowercase();
        let uri = target_uri.trim();
        if d.is_empty() {
            return self.purge_by_uri(uri).await;
        }
        if uri.is_empty() {
            return self.purge_by_domain(&d).await;
        }
        let normalized_path = extract_path_from_uri(uri);
        let mut purged_keys: HashSet<String> = HashSet::new();

        let domain_needle_http = format!("http://{d}|");
        let domain_needle_https = format!("https://{d}|");

        // L1 eşleşmeleri
        let matching_l1: Vec<String> = self
            .key_tags
            .iter()
            .filter(|entry| {
                let k = entry.key();
                (k.starts_with(&domain_needle_http) || k.starts_with(&domain_needle_https))
                    && key_matches_uri(k, &normalized_path)
            })
            .map(|entry| entry.key().clone())
            .collect();

        for key in matching_l1 {
            self.cache.invalidate(&key).await;
            self.unregister_key_tags(&key);
            if let Some(disk) = &self.disk {
                disk.purge(&key).await;
            }
            purged_keys.insert(key);
        }

        // L2 disk eşleşmeleri
        if let Some(disk) = &self.disk {
            for key in disk.purge_by_domain_and_uri_match(&d, &normalized_path).await {
                self.cache.invalidate(&key).await;
                self.unregister_key_tags(&key);
                purged_keys.insert(key);
            }
        }

        purged_keys.len()
    }

    /// Belirli bir alan adına (`domain::tag`) ait önbellek girdilerini temizler.
    pub async fn purge_by_domain_tag(&self, domain: &str, tag: &str) -> usize {
        let t = tag.trim();
        if t.is_empty() {
            return 0;
        }
        if t == "*" {
            if domain.trim().is_empty() {
                let count = self.key_tags.len().max(self.cache.entry_count() as usize);
                self.purge_all().await;
                return count;
            }
            return self.purge_by_domain(domain).await;
        }
        let mut purged_keys: HashSet<String> = HashSet::new();
        let scoped = Self::format_domain_tag(domain, t);
        // Yalnız `alan::etiket` kayıtları: ham etiket birden çok vhost'un girdisini indekslediğinden
        // burada silinirse başka vhost'un önbelleği de boşalırdı (vhost izolasyonu).
        purged_keys.extend(self.purge_by_tag_keys(&scoped).await);
        purged_keys.len()
    }

    /// Verilen alan adı için birden çok etiketi tek seferde temizler ve benzersiz silinen kayıt sayısını döner.
    pub async fn purge_by_tags(&self, domain: &str, tags: &[String]) -> usize {
        let mut purged_keys: HashSet<String> = HashSet::new();
        for raw_tag in tags {
            let t = raw_tag.trim();
            if t.is_empty() {
                continue;
            }
            if t == "*" && domain.trim().is_empty() {
                let count = self.key_tags.len().max(self.cache.entry_count() as usize);
                self.purge_all().await;
                return count.max(purged_keys.len());
            }
            let scoped = Self::format_domain_tag(domain, t);
            purged_keys.extend(self.purge_by_tag_keys(&scoped).await);
        }
        purged_keys.len()
    }

    /// `X-LiteSpeed-Purge` yönergesini (`purge_all` veya `purge_tags`) alan adı kapsamında uygular.
    pub async fn apply_lscache_purge(&self, domain: &str, directive: &LsCacheDirective) -> usize {
        if directive.purge_all {
            let mut tags = Vec::with_capacity(directive.purge_tags.len() + 1);
            tags.push("*".to_string());
            tags.extend(directive.purge_tags.iter().cloned());
            self.purge_by_tags(domain, &tags).await
        } else {
            self.purge_by_tags(domain, &directive.purge_tags).await
        }
    }

    pub async fn purge_all(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
        self.tag_index.clear();
        self.key_tags.clear();
        if let Some(disk) = &self.disk {
            disk.purge_all().await;
        }
    }
}

fn encode_disk_entry(key: &str, entry: &CacheEntry) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let ct_bytes = entry.response.content_type.as_bytes();
    let body_bytes = entry.response.body.as_ref();

    let mut out = Vec::with_capacity(72 + key_bytes.len() + ct_bytes.len() + body_bytes.len());
    out.extend_from_slice(DISK_CACHE_MAGIC);
    out.extend_from_slice(&DISK_CACHE_VERSION.to_le_bytes());
    out.extend_from_slice(&entry.response.status.to_le_bytes());
    out.extend_from_slice(&entry.cached_at_ms.to_le_bytes());
    out.extend_from_slice(&entry.expires_at_ms.to_le_bytes());
    out.extend_from_slice(&entry.stale_until_ms.to_le_bytes());

    out.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(key_bytes);

    out.extend_from_slice(&(ct_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(ct_bytes);

    out.extend_from_slice(&(entry.response.tags.len() as u32).to_le_bytes());
    for tag in &entry.response.tags {
        let tb = tag.as_bytes();
        out.extend_from_slice(&(tb.len() as u32).to_le_bytes());
        out.extend_from_slice(tb);
    }

    out.extend_from_slice(&(body_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(body_bytes);
    out
}

fn decode_disk_entry(raw: &[u8]) -> Option<(String, CacheEntry)> {
    if raw.len() < 4 + 2 + 2 + 8 + 8 {
        return None;
    }
    if &raw[..4] != DISK_CACHE_MAGIC {
        return None;
    }
    let version = u16::from_le_bytes([raw[4], raw[5]]);
    if version != DISK_CACHE_VERSION && version != DISK_CACHE_VERSION_V1 {
        return None;
    }
    let status = u16::from_le_bytes([raw[6], raw[7]]);
    let cached_at_ms = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    let expires_at_ms = u64::from_le_bytes(raw[16..24].try_into().ok()?);

    let mut pos = 24usize;
    let stale_until_ms = if version == DISK_CACHE_VERSION {
        read_u64(raw, &mut pos)?
    } else {
        expires_at_ms
    };
    let key_bytes = read_len_prefixed_u32(raw, &mut pos)?;
    let key = String::from_utf8(key_bytes.to_vec()).ok()?;

    let ct_bytes = read_len_prefixed_u32(raw, &mut pos)?;
    let content_type = String::from_utf8(ct_bytes.to_vec()).ok()?;

    let tag_count = read_u32(raw, &mut pos)? as usize;
    if tag_count > 4096 {
        return None;
    }
    let mut tags = Vec::with_capacity(tag_count);
    for _ in 0..tag_count {
        let tb = read_len_prefixed_u32(raw, &mut pos)?;
        tags.push(String::from_utf8(tb.to_vec()).ok()?);
    }

    let body_len = read_u64(raw, &mut pos)? as usize;
    let end = pos.checked_add(body_len)?;
    if end > raw.len() {
        return None;
    }
    let body = Bytes::copy_from_slice(&raw[pos..end]);

    Some((
        key,
        CacheEntry {
            response: CachedResponse {
                status,
                content_type,
                body,
                tags,
            },
            cached_at_ms,
            expires_at_ms,
            stale_until_ms,
        },
    ))
}

fn read_u32(raw: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    if end > raw.len() {
        return None;
    }
    let v = u32::from_le_bytes(raw[*pos..end].try_into().ok()?);
    *pos = end;
    Some(v)
}

fn read_u64(raw: &[u8], pos: &mut usize) -> Option<u64> {
    let end = pos.checked_add(8)?;
    if end > raw.len() {
        return None;
    }
    let v = u64::from_le_bytes(raw[*pos..end].try_into().ok()?);
    *pos = end;
    Some(v)
}

fn read_len_prefixed_u32<'a>(raw: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32(raw, pos)? as usize;
    let end = pos.checked_add(len)?;
    if end > raw.len() {
        return None;
    }
    let slice = &raw[*pos..end];
    *pos = end;
    Some(slice)
}

/// Bağımlılıksız, deterministik SHA-256 hex özeti (L2 disk dosya adları için).
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(data.len() + 72);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let (blocks, _) = padded.as_chunks::<64>();
    for block in blocks {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut hex = String::with_capacity(64);
    for word in h {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{:08x}", word);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_resp(body: &'static str, tags: Vec<&str>) -> CachedResponse {
        CachedResponse {
            status: 200,
            content_type: "text/html".to_string(),
            body: Bytes::from_static(body.as_bytes()),
            tags: tags.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn test_build_cache_key_uniqueness() {
        let k_p1 = build_cache_key("example.com", false, "GET", "/list", "p=1", None);
        let k_p2 = build_cache_key("example.com", false, "GET", "/list", "p=2", None);
        assert_ne!(k_p1, k_p2);

        let k_http = build_cache_key("example.com", false, "GET", "/index.html", "", None);
        let k_https = build_cache_key("example.com", true, "GET", "/index.html", "", None);
        assert_ne!(k_http, k_https);

        let k_plain = build_cache_key("example.com", true, "GET", "/app.js", "", None);
        let k_br = build_cache_key("example.com", true, "GET", "/app.js", "", Some("br"));
        let k_gzip = build_cache_key("example.com", true, "GET", "/app.js", "", Some("gzip"));
        assert_ne!(k_plain, k_br);
        assert_ne!(k_br, k_gzip);

        let k_norm1 = build_cache_key("Example.COM ", true, "get", "/", "", Some(" GZIP "));
        let k_norm2 = build_cache_key("example.com", true, "GET", "/", "", Some("gzip"));
        assert_eq!(k_norm1, k_norm2);
    }

    #[tokio::test]
    async fn test_per_entry_ttl_expiration() {
        // Global default TTL kısa (1s), ancak uzun ömürlü girdi 30s saklanabilmeli;
        // tersine global TTL uzun (60s) iken 1s'lik girdi süresi dolunca düşmeli.
        let cache = ZMaxCache::new(1024 * 1024, 60);
        let short_key = build_cache_key("site.test", false, "GET", "/short", "", None);
        let long_key = build_cache_key("site.test", false, "GET", "/long", "", None);

        cache
            .set_with_ttl(short_key.clone(), sample_resp("kisa", vec!["site.test"]), 1)
            .await;
        cache
            .set_with_ttl(long_key.clone(), sample_resp("uzun", vec!["site.test"]), 60)
            .await;

        assert!(cache.get(&short_key).await.is_some());
        assert!(cache.get(&long_key).await.is_some());

        tokio::time::sleep(Duration::from_millis(1150)).await;

        assert!(cache.get(&short_key).await.is_none());
        assert_eq!(
            cache.get(&long_key).await.unwrap().body,
            Bytes::from_static(b"uzun")
        );
    }

    #[tokio::test]
    async fn test_purge_by_tag_and_overwrite() {
        let cache = ZMaxCache::new(1024 * 1024, 60);
        let k1 = build_cache_key("a.com", true, "GET", "/p1", "", None);
        let k2 = build_cache_key("a.com", true, "GET", "/p2", "", None);
        let k3 = build_cache_key("b.com", true, "GET", "/p1", "", None);

        cache
            .set(k1.clone(), sample_resp("a1", vec!["a.com", "home"]))
            .await;
        cache
            .set(k2.clone(), sample_resp("a2", vec!["a.com", "post:5"]))
            .await;
        cache
            .set(k3.clone(), sample_resp("b1", vec!["b.com", "home"]))
            .await;

        // a.com etiketli 2 kayıt tek seferde silinmeli, b.com korunmalı
        let purged = cache.purge_by_tag("a.com").await;
        assert_eq!(purged, 2);
        assert!(cache.get(&k1).await.is_none());
        assert!(cache.get(&k2).await.is_none());
        assert!(cache.get(&k3).await.is_some());

        // home etiketiyle kalan b.com da silinmeli
        assert_eq!(cache.purge_by_tag("home").await, 1);
        assert!(cache.get(&k3).await.is_none());
    }

    #[tokio::test]
    async fn test_l2_disk_cache_persistence_l1_eviction_and_purge_all() {
        let dir = std::env::temp_dir().join(format!("zmax_l2_cache_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Çok küçük L1 (40 bayt) -> büyük gövdeler L1'den düşse veya hiç girmese bile L2 diskten okunmalı!
        let cache = ZMaxCache::with_disk_dir(40, 60, &dir);
        let k1 = build_cache_key("disk.test", true, "GET", "/big1", "", None);
        let k2 = build_cache_key("disk.test", true, "GET", "/big2", "", None);

        let body1 = "X".repeat(128);
        let body2 = "Y".repeat(128);

        cache
            .set_with_ttl(
                k1.clone(),
                CachedResponse {
                    status: 200,
                    content_type: "text/plain".to_string(),
                    body: Bytes::from(body1.clone()),
                    tags: vec!["disk.test".to_string()],
                },
                60,
            )
            .await;
        cache
            .set_with_ttl(
                k2.clone(),
                CachedResponse {
                    status: 200,
                    content_type: "text/plain".to_string(),
                    body: Bytes::from(body2.clone()),
                    tags: vec!["disk.test".to_string(), "other".to_string()],
                },
                60,
            )
            .await;

        // L1 bellek dolmuş olsa bile L2 diskten okunabilmeli
        let got1 = cache.get(&k1).await.expect("L2 diskten k1 okunabilmeli");
        assert_eq!(got1.body.as_ref(), body1.as_bytes());
        let got2 = cache.get(&k2).await.expect("L2 diskten k2 okunabilmeli");
        assert_eq!(got2.body.as_ref(), body2.as_bytes());

        // Sunucu yeniden başlatılsa (yeni ZMaxCache nesnesi, aynı disk dizini) L2 diskten okunabilmeli
        drop(cache);
        let restarted = ZMaxCache::with_disk_dir(1024 * 1024, 60, &dir);
        let from_disk = restarted
            .get(&k1)
            .await
            .expect("Yeniden başlatma sonrası L2 diskten okunabilmeli");
        assert_eq!(from_disk.body.as_ref(), body1.as_bytes());

        // Yeniden başlatma sonrasında bile tag bazlı purge L2 diskteki girdiyi bulup silebilmeli
        let purged_cnt = restarted.purge_by_tag("other").await;
        assert_eq!(purged_cnt, 1);
        assert!(restarted.get(&k2).await.is_none());
        assert!(restarted.get(&k1).await.is_some());

        // purge_all L1 ve L2'deki her şeyi temizlemeli
        restarted.purge_all().await;
        assert!(restarted.get(&k1).await.is_none());

        let remaining_files = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("zcache"))
            .count();
        assert_eq!(remaining_files, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn stale_while_revalidate_returns_fresh_then_stale_then_miss() {
        let cache = ZMaxCache::new(1024 * 1024, 60);
        let key = build_cache_key("swr.test", true, "GET", "/article", "", None);

        cache
            .set_with_ttl_and_stale(key.clone(), sample_resp("v1", vec!["swr"]), 1, 2)
            .await;

        assert!(matches!(
            cache.get_with_stale(&key).await,
            CacheLookup::Fresh(ref resp) if resp.body == Bytes::from_static(b"v1")
        ));
        assert!(cache.get(&key).await.is_some());

        // Taze süre (1s) dolup bayat pencere (1s..3s) içine girildiğinde
        tokio::time::sleep(Duration::from_millis(1150)).await;

        // Geriye dönük uyumlu `get()` bayatı `None` saymalı ancak kaydı silmemeli
        assert!(cache.get(&key).await.is_none());
        assert!(matches!(
            cache.get_with_stale(&key).await,
            CacheLookup::Stale(ref resp) if resp.body == Bytes::from_static(b"v1")
        ));

        // Bayat pencere de (toplam 3s) dolduğunda Miss dönüp temizlemeli
        tokio::time::sleep(Duration::from_millis(2000)).await;
        assert!(matches!(cache.get_with_stale(&key).await, CacheLookup::Miss));
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn stampede_shield_elects_single_leader_and_wakes_followers_on_drop() {
        use std::sync::atomic::AtomicUsize;

        let cache = Arc::new(ZMaxCache::new(1024 * 1024, 60));
        let key = build_cache_key("stampede.test", true, "GET", "/heavy", "", None);
        let other_key = build_cache_key("stampede.test", true, "GET", "/other", "", None);

        let leader_guard = match cache.try_acquire_fill(&key) {
            StampedeSlot::Leader(guard) => guard,
            StampedeSlot::Follower(_) => panic!("ilk istek Leader olmaliydi"),
        };

        // Farklı anahtarlar birbirini engellememeli
        assert!(matches!(
            cache.try_acquire_fill(&other_key),
            StampedeSlot::Leader(_)
        ));

        let waiting = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(3);
        for _ in 0..3 {
            let c = Arc::clone(&cache);
            let k = key.clone();
            let w = Arc::clone(&waiting);
            handles.push(tokio::spawn(async move {
                let notify = match c.try_acquire_fill(&k) {
                    StampedeSlot::Follower(n) => n,
                    StampedeSlot::Leader(_) => panic!("es zamanli istek Follower olmaliydi"),
                };
                w.fetch_add(1, Ordering::SeqCst);
                tokio::time::timeout(Duration::from_millis(1000), notify.notified())
                    .await
                    .expect("lider birakildiginda takipci uyanmaliydi");
            }));
        }

        while waiting.load(Ordering::SeqCst) < 3 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;

        drop(leader_guard);
        for h in handles {
            h.await.expect("takipci gorev basarili olmali");
        }

        // Lider bırakıldıktan sonra yeni bir istek tekrar Leader olabilmeli
        assert!(matches!(
            cache.try_acquire_fill(&key),
            StampedeSlot::Leader(_)
        ));

        // Panic güvenliği: Lider görev panic olsa dahi Drop ile inflight temizlenmeli
        let c_panic = Arc::clone(&cache);
        let panic_key = build_cache_key("stampede.test", true, "GET", "/panic", "", None);
        let pk_clone = panic_key.clone();
        let panic_handle = tokio::spawn(async move {
            let _guard = match c_panic.try_acquire_fill(&pk_clone) {
                StampedeSlot::Leader(g) => g,
                StampedeSlot::Follower(_) => panic!("panic testi Leader olmaliydi"),
            };
            panic!("ornek upstream panigi");
        });
        assert!(panic_handle.await.is_err());
        assert!(matches!(
            cache.try_acquire_fill(&panic_key),
            StampedeSlot::Leader(_)
        ));
    }

    #[test]
    fn disk_cache_v1_compat_and_v2_stale_roundtrip() {
        let entry = CacheEntry {
            response: sample_resp("disk-body", vec!["t1"]),
            cached_at_ms: 1_000,
            expires_at_ms: 2_000,
            stale_until_ms: 5_000,
        };
        let encoded_v2 = encode_disk_entry("k-v2", &entry);
        let (k2, decoded_v2) = decode_disk_entry(&encoded_v2).expect("v2 decode basarili olmali");
        assert_eq!(k2, "k-v2");
        assert_eq!(decoded_v2.expires_at_ms, 2_000);
        assert_eq!(decoded_v2.stale_until_ms, 5_000);
        assert_eq!(decoded_v2.response, entry.response);

        // Eski v1 formatını elle oluşturup geriye dönük uyumluluğu doğrula
        let mut v1 = Vec::new();
        v1.extend_from_slice(DISK_CACHE_MAGIC);
        v1.extend_from_slice(&DISK_CACHE_VERSION_V1.to_le_bytes());
        v1.extend_from_slice(&200u16.to_le_bytes());
        v1.extend_from_slice(&1_000u64.to_le_bytes());
        v1.extend_from_slice(&2_000u64.to_le_bytes());
        let key_bytes = b"k-v1";
        v1.extend_from_slice(&(key_bytes.len() as u32).to_le_bytes());
        v1.extend_from_slice(key_bytes);
        let ct_bytes = b"text/html";
        v1.extend_from_slice(&(ct_bytes.len() as u32).to_le_bytes());
        v1.extend_from_slice(ct_bytes);
        v1.extend_from_slice(&0u32.to_le_bytes());
        let body_bytes = b"legacy";
        v1.extend_from_slice(&(body_bytes.len() as u64).to_le_bytes());
        v1.extend_from_slice(body_bytes);

        let (k1, decoded_v1) = decode_disk_entry(&v1).expect("v1 decode basarili olmali");
        assert_eq!(k1, "k-v1");
        assert_eq!(decoded_v1.expires_at_ms, 2_000);
        assert_eq!(decoded_v1.stale_until_ms, 2_000);
        assert_eq!(decoded_v1.response.body, Bytes::from_static(b"legacy"));
    }

    #[tokio::test]
    async fn lscache_tag_insert_and_domain_scoped_purge() {
        let cache = ZMaxCache::new(1024 * 1024, 60);
        let dir_a = parse_lscache_headers([
            ("X-LiteSpeed-Cache-Control", "public, max-age=300"),
            ("X-LiteSpeed-Tag", "post:42, cat:haber, home"),
        ]);
        assert_eq!(dir_a.cacheable, Some(true));
        assert_eq!(dir_a.max_age_secs, Some(300));
        assert_eq!(dir_a.tags, vec!["post:42", "cat:haber", "home"]);

        let k_a1 = build_cache_key("a.example", true, "GET", "/yazi-42", "", None);
        let k_a2 = build_cache_key("a.example", true, "GET", "/", "", None);
        let k_b1 = build_cache_key("b.example", true, "GET", "/yazi-42", "", None);

        cache
            .insert_with_tags(k_a1.clone(), sample_resp("a1", vec![]), 300, "a.example", &dir_a.tags)
            .await;
        cache
            .insert_with_tags(
                k_a2.clone(),
                sample_resp("a2", vec![]),
                300,
                "a.example",
                &["home".to_string()],
            )
            .await;
        cache
            .insert_with_tags(
                k_b1.clone(),
                sample_resp("b1", vec![]),
                300,
                "b.example",
                &["post:42".to_string(), "home".to_string()],
            )
            .await;

        // Sadece a.example altındaki post:42 temizlenmeli, b.example korunmalı
        assert_eq!(cache.purge_by_domain_tag("a.example", "post:42").await, 1);
        assert!(cache.get(&k_a1).await.is_none());
        assert!(cache.get(&k_a2).await.is_some());
        assert!(cache.get(&k_b1).await.is_some());

        // Kalan a.example/home temizlenirken b.example/home dokunulmamalı
        assert_eq!(
            cache
                .purge_by_tags("a.example", &["home".to_string()])
                .await,
            1
        );
        assert!(cache.get(&k_a2).await.is_none());
        assert!(cache.get(&k_b1).await.is_some());
    }

    #[tokio::test]
    async fn lscache_purge_wildcard_clears_only_target_domain() {
        let dir = std::env::temp_dir().join(format!("zmax_lsc_purge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ZMaxCache::with_disk_dir(1024 * 1024, 60, &dir);

        let k_a1 = build_cache_key("site1.test", true, "GET", "/1", "", None);
        let k_a2 = build_cache_key("site1.test", true, "GET", "/2", "", None);
        let k_b1 = build_cache_key("site2.test", true, "GET", "/1", "", None);

        cache
            .insert_with_tags(
                k_a1.clone(),
                sample_resp("s1-1", vec![]),
                120,
                "site1.test",
                &["p:1".to_string()],
            )
            .await;
        cache
            .insert_with_tags(
                k_a2.clone(),
                sample_resp("s1-2", vec![]),
                120,
                "site1.test",
                &["p:2".to_string()],
            )
            .await;
        cache
            .insert_with_tags(
                k_b1.clone(),
                sample_resp("s2-1", vec![]),
                120,
                "site2.test",
                &["p:1".to_string()],
            )
            .await;

        let d_star = parse_lscache_headers([("X-LiteSpeed-Purge", "*")]);
        assert!(d_star.purge_all);
        assert!(d_star.purge_tags.is_empty());

        let d_pub_star = parse_lscache_headers([("x-litespeed-purge", "public, *")]);
        assert!(d_pub_star.purge_all);

        let purged = cache.apply_lscache_purge("site1.test", &d_star).await;
        assert_eq!(purged, 2);
        assert!(cache.get(&k_a1).await.is_none());
        assert!(cache.get(&k_a2).await.is_none());
        assert!(cache.get(&k_b1).await.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lscache_cache_control_no_cache_private_and_public() {
        let d_nocache = parse_lscache_headers([("X-LiteSpeed-Cache-Control", "no-cache")]);
        assert_eq!(d_nocache.cacheable, Some(false));
        assert!(!d_nocache.is_private);

        let d_private =
            parse_lscache_headers([("X-LiteSpeed-Cache-Control", "private, max-age=1800")]);
        assert!(d_private.is_private);
        assert_eq!(d_private.max_age_secs, Some(1800));
        assert_ne!(d_private.cacheable, Some(true));

        let d_rev_private =
            parse_lscache_headers([("X-LiteSpeed-Cache-Control", "max-age=1800, private")]);
        assert_eq!(d_private, d_rev_private);

        let d_public_novary = parse_lscache_headers([(
            "X-LiteSpeed-Cache-Control",
            "public, max-age=604800, no-vary",
        )]);
        assert_eq!(d_public_novary.cacheable, Some(true));
        assert_eq!(d_public_novary.max_age_secs, Some(604800));
        assert!(d_public_novary.no_vary);
        assert!(!d_public_novary.is_private);

        let d_zero = parse_lscache_headers([("X-LiteSpeed-Cache-Control", "public, max-age=0")]);
        assert_eq!(d_zero.cacheable, Some(false));
    }

    #[test]
    fn lscache_vary_header_and_cookie_key_generation() {
        let d = parse_lscache_headers([(
            "X-LiteSpeed-Vary",
            "cookie=wp_lang, cookie=wc_cart, header=Accept-Language",
        )]);
        assert_eq!(d.vary_cookies, vec!["wp_lang", "wc_cart"]);
        assert_eq!(d.vary_headers, vec!["accept-language"]);

        let base = build_cache_key("shop.test", true, "GET", "/urunler", "", Some("br"));
        let h_tr = vec![("Accept-Language".to_string(), "tr-TR".to_string())];
        let h_en = vec![("accept-language".to_string(), "en-US".to_string())];

        let k_tr_empty = build_lscache_vary_key(&base, &d, &h_tr, Some("wp_lang=tr; session=xyz"));
        let k_tr_other_session =
            build_lscache_vary_key(&base, &d, &h_tr, Some("wp_lang=tr; session=different"));
        // Vary listesinde olmayan çerez anahtarı değiştirmemeli
        assert_eq!(k_tr_empty, k_tr_other_session);

        let k_tr_cart = build_lscache_vary_key(&base, &d, &h_tr, Some("wp_lang=tr; wc_cart=1"));
        let k_en = build_lscache_vary_key(&base, &d, &h_en, Some("wp_lang=tr; session=xyz"));
        let k_no_cookie = build_lscache_vary_key(&base, &d, &h_tr, None);

        assert_ne!(k_tr_empty, k_tr_cart);
        assert_ne!(k_tr_empty, k_en);
        assert_ne!(k_tr_empty, k_no_cookie);

        // no-vary açıkken temel anahtar aynen dönmeli
        let mut d_novary = d.clone();
        d_novary.no_vary = true;
        assert_eq!(
            build_lscache_vary_key(&base, &d_novary, &h_tr, Some("wp_lang=tr")),
            base
        );
    }

    #[tokio::test]
    async fn lscache_purge_by_tags_deduplicates_multi_tag_hit() {
        let cache = ZMaxCache::new(1024 * 1024, 60);
        let k1 = build_cache_key("blog.test", true, "GET", "/yazi", "", None);
        let k2 = build_cache_key("blog.test", true, "GET", "/arsiv", "", None);

        cache
            .insert_with_tags(
                k1.clone(),
                sample_resp("yazi", vec![]),
                60,
                "blog.test",
                &["post:10".to_string(), "cat:5".to_string()],
            )
            .await;
        cache
            .insert_with_tags(
                k2.clone(),
                sample_resp("arsiv", vec![]),
                60,
                "blog.test",
                &["cat:5".to_string()],
            )
            .await;

        let purge_dir = parse_lscache_headers([("X-LiteSpeed-Purge", "public, post:10, cat:5")]);
        assert!(!purge_dir.purge_all);
        assert_eq!(purge_dir.purge_tags, vec!["post:10", "cat:5"]);

        // k1 hem post:10 hem cat:5 içeriyor; toplam silinen benzersiz kayıt sayısı 2 olmalı
        let purged = cache.apply_lscache_purge("blog.test", &purge_dir).await;
        assert_eq!(purged, 2);
        assert!(cache.get(&k1).await.is_none());
        assert!(cache.get(&k2).await.is_none());
    }

    #[tokio::test]
    async fn test_purge_by_domain_with_multiple_tag_formats_and_composite_key() {
        let dir = std::env::temp_dir().join(format!("zmax_domain_purge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ZMaxCache::with_disk_dir(1024 * 1024, 60, &dir);

        let k1 = build_cache_key("site.test", false, "GET", "/page1", "", None);
        let k2 = build_cache_key("site.test", true, "GET", "/page2", "", None);
        let k_other = build_cache_key("other.test", false, "GET", "/page1", "", None);

        // k1: web_engine'in eski tarz tekil domain etiketi
        cache
            .set_with_ttl_and_stale(
                k1.clone(),
                sample_resp("body1", vec!["site.test"]),
                120,
                30,
            )
            .await;

        // k2: domain::site.test etiketi
        cache
            .set_with_ttl_and_stale(
                k2.clone(),
                sample_resp("body2", vec!["domain::site.test"]),
                120,
                30,
            )
            .await;

        // k_other: başka alan adı
        cache
            .set_with_ttl_and_stale(
                k_other.clone(),
                sample_resp("other", vec!["other.test"]),
                120,
                30,
            )
            .await;

        // site.test temizlenmeli, other.test korunmalı
        let purged = cache.purge_by_domain("site.test").await;
        assert_eq!(purged, 2);
        assert!(cache.get(&k1).await.is_none());
        assert!(cache.get(&k2).await.is_none());
        assert!(cache.get(&k_other).await.is_some());

        // purge_by_domain_tag("other.test", "*") ile wildcard temizliği de doğrula
        let purged_other = cache.purge_by_domain_tag("other.test", "*").await;
        assert_eq!(purged_other, 1);
        assert!(cache.get(&k_other).await.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_purge_by_raw_uri_matches_composite_cache_key() {
        let dir = std::env::temp_dir().join(format!("zmax_uri_purge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ZMaxCache::with_disk_dir(1024 * 1024, 60, &dir);

        let k_index = build_cache_key("shop.test", false, "GET", "/index.html", "", None);
        let k_about = build_cache_key("shop.test", false, "GET", "/about", "", None);

        cache
            .set_with_ttl_and_stale(
                k_index.clone(),
                sample_resp("index", vec!["shop.test", "__uri:/index.html"]),
                120,
                30,
            )
            .await;

        cache
            .set_with_ttl_and_stale(
                k_about.clone(),
                sample_resp("about", vec!["shop.test", "__uri:/about"]),
                120,
                30,
            )
            .await;

        // Ham URI "/index.html" temizlenmeli
        let purged = cache.purge_by_uri("/index.html").await;
        assert_eq!(purged, 1);
        assert!(cache.get(&k_index).await.is_none());
        assert!(cache.get(&k_about).await.is_some());

        // Ham URI "about" (başında slash olmadan) da temizlenebilmeli
        let purged_about = cache.purge_by_uri("about").await;
        assert_eq!(purged_about, 1);
        assert!(cache.get(&k_about).await.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_purge_by_domain_and_uri() {
        let dir = std::env::temp_dir().join(format!("zmax_dom_uri_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ZMaxCache::with_disk_dir(1024 * 1024, 60, &dir);

        let k_d1_p = build_cache_key("dom1.test", false, "GET", "/page", "", None);
        let k_d1_o = build_cache_key("dom1.test", false, "GET", "/other", "", None);
        let k_d2_p = build_cache_key("dom2.test", false, "GET", "/page", "", None);

        cache
            .set_with_ttl_and_stale(k_d1_p.clone(), sample_resp("d1_p", vec!["dom1.test"]), 120, 30)
            .await;
        cache
            .set_with_ttl_and_stale(k_d1_o.clone(), sample_resp("d1_o", vec!["dom1.test"]), 120, 30)
            .await;
        cache
            .set_with_ttl_and_stale(k_d2_p.clone(), sample_resp("d2_p", vec!["dom2.test"]), 120, 30)
            .await;

        let purged = cache.purge_by_domain_uri("dom1.test", "/page").await;
        assert_eq!(purged, 1);
        assert!(cache.get(&k_d1_p).await.is_none());
        assert!(cache.get(&k_d1_o).await.is_some());
        assert!(cache.get(&k_d2_p).await.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
