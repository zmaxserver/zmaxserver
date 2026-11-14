//! Modül politikaları ve dinamik güvenlik/otomatik token denetimi.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use zmax_config::{is_loopback_bind, LoadedModules, VHostEntry, ZMaxConfig};
use zmax_header::SecurityHeadersPolicy;

pub use crate::modules::policy::*;
pub use crate::modules::registry::module_category_key;


/// Sanal konak ve küresel `mod_headers` kurallarını birleştirerek yanıt başlığı politikası üretir.
pub fn resolve_vhost_security_headers(
    global_enabled: bool,
    global_policy: &SecurityHeadersPolicy,
    vhost: Option<&VHostEntry>,
) -> Option<SecurityHeadersPolicy> {
    let vh_sec = vhost.map(|v| v.headers.security_headers).unwrap_or(true);
    let vh_hsts = vhost.map(|v| v.headers.hsts).unwrap_or(false);
    if !global_enabled || !vh_sec {
        if vh_hsts {
            return Some(SecurityHeadersPolicy {
                hsts_enabled: true,
                x_frame_options: None,
                x_content_type_options: false,
                referrer_policy: None,
                content_security_policy: None,
                permissions_policy: None,
                ..SecurityHeadersPolicy::default()
            });
        }
        return None;
    }
    let mut p = global_policy.clone();
    p.hsts_enabled = global_policy.hsts_enabled || vh_hsts;
    Some(p)
}

/// OS CSPRNG (`RandomState` / `BCryptGenRandom` / `getrandom`) tabanlı 256-bit rastgele API/Admin token üretir.
pub fn generate_secure_token() -> String {
    let mut hex = String::with_capacity(53);
    hex.push_str("zmax_");
    for round in 0..3u64 {
        let state = RandomState::new();
        let mut hasher = state.build_hasher();
        hasher.write_u64(round);
        hasher.write_u32(std::process::id());
        let val = hasher.finish();
        hex.push_str(&format!("{:016x}", val));
    }
    hex
}

#[derive(Debug, Clone)]
pub struct EffectiveAuthTokens {
    pub api_token: String,
    pub api_require_token: bool,
    pub admin_token: String,
    pub admin_require_token: bool,
    pub auto_generated_notices: Vec<String>,
}

/// `Admin` veya `API` loopback dışına (`0.0.0.0` vb.) bağlanıyorsa ve token tanımlı değilse
/// otomatik güçlü token üreterek yetkisiz erişimi engeller.
pub fn compute_effective_auth(config: &ZMaxConfig) -> EffectiveAuthTokens {
    let mut notices = Vec::new();

    let api_non_loopback = config.listeners.api.enabled && !is_loopback_bind(&config.listeners.api.address);
    let admin_non_loopback =
        config.listeners.admin.enabled && !is_loopback_bind(&config.listeners.admin.address);

    let configured_api_token = config.listeners.api.token.trim().to_string();
    let configured_admin_token = config.listeners.admin.token.trim().to_string();

    let mut api_token = configured_api_token.clone();
    let mut api_require_token = config.listeners.api.require_token || !api_token.is_empty();

    if api_non_loopback && (api_token.is_empty() || !api_require_token) {
        if api_token.is_empty() {
            api_token = generate_secure_token();
            notices.push(format!(
                "[GUVENLIK] API dinleyicisi loopback disi ({}) acildigi icin otomatik API token uretildi: {}",
                config.listeners.api.address, api_token
            ));
        } else {
            notices.push(format!(
                "[GUVENLIK] API dinleyicisi loopback disi ({}) acildigi icin token dogrulamasi zorunlu kilindi.",
                config.listeners.api.address
            ));
        }
        api_require_token = true;
    }

    let mut admin_token = if !configured_admin_token.is_empty() {
        configured_admin_token
    } else if !api_token.is_empty() {
        api_token.clone()
    } else {
        String::new()
    };
    let mut admin_require_token = config.listeners.admin.require_token || !admin_token.is_empty();

    if admin_non_loopback && (admin_token.is_empty() || !admin_require_token) {
        if admin_token.is_empty() {
            admin_token = generate_secure_token();
            notices.push(format!(
                "[GUVENLIK] WebAdmin dinleyicisi loopback disi ({}) acildigi icin otomatik Admin token uretildi: {}",
                config.listeners.admin.address, admin_token
            ));
        } else {
            notices.push(format!(
                "[GUVENLIK] WebAdmin dinleyicisi loopback disi ({}) acildigi icin token dogrulamasi zorunlu kilindi.",
                config.listeners.admin.address
            ));
        }
        admin_require_token = true;
    }

    EffectiveAuthTokens {
        api_token,
        api_require_token,
        admin_token,
        admin_require_token,
        auto_generated_notices: notices,
    }
}


/// İstek bazlı `mod_redis` istemcisi oluşturur (`mod_redis` etkinse).
pub fn build_redis_client(modules: &LoadedModules) -> Option<zmax_redis::ZMaxRedisClient> {
    let m = modules.get("mod_redis")?;
    if !m.is_enabled() {
        return None;
    }
    let host = m.get_str("host").unwrap_or("127.0.0.1").to_string();
    let port = m.get_u64("port").unwrap_or(6379) as u16;
    let addr = m
        .get_str("addr")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{host}:{port}"));
    let database = m.get_u64("database").unwrap_or(0) as u8;
    let db = m.get_u64("db").unwrap_or(u64::from(database)) as u8;
    let cfg = zmax_redis::RedisConfig {
        host,
        port,
        addr,
        username: m
            .get_str("username")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        password: m
            .get_str("password")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        database,
        db,
        timeout_ms: m.get_u64("timeout_ms").unwrap_or(100),
        pubsub_channel: m
            .get_str("pubsub_channel")
            .unwrap_or("zmax:cache:purge")
            .to_string(),
        channel_prefix: m
            .get_str("channel_prefix")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("zmax")
            .to_string(),
        reconnect_backoff_ms: m.get_u64("reconnect_backoff_ms").unwrap_or(500),
    };
    Some(zmax_redis::ZMaxRedisClient::new(cfg))
}

fn accept_supports_media_type(accept_lower: &str, media_type: &str) -> bool {
    accept_lower.split(',').any(|item| {
        let mut parts = item.split(';');
        let mime = parts.next().unwrap_or("").trim();
        if mime != media_type {
            return false;
        }
        for param in parts {
            let Some((key, val)) = param.split_once('=') else {
                continue;
            };
            if key.trim() != "q" {
                continue;
            }
            if let Ok(q) = val.trim().parse::<f32>() {
                if q.is_finite() && q <= 0.0 {
                    return false;
                }
            }
        }
        true
    })
}

fn find_safe_negotiated_variant(
    orig_path: &Path,
    orig_parent: &Path,
    canon_parent: &Path,
    target_ext: &str,
) -> Option<PathBuf> {
    let file_name = orig_path.file_name()?;
    let stem = orig_path.file_stem()?;

    let mut append_name = file_name.to_os_string();
    append_name.push(".");
    append_name.push(target_ext);

    let mut replace_name = stem.to_os_string();
    replace_name.push(".");
    replace_name.push(target_ext);

    let candidates = [
        orig_parent.join(append_name),
        orig_parent.join(replace_name),
    ];

    for cand in candidates {
        let Ok(canon_cand) = std::fs::canonicalize(&cand) else {
            continue;
        };
        let is_regular_file = std::fs::metadata(&canon_cand).is_ok_and(|m| m.is_file());
        if is_regular_file && canon_cand.parent() == Some(canon_parent) {
            return Some(canon_cand);
        }
    }
    None
}

/// Tarayıcının `Accept` başlığına göre `.jpg`, `.jpeg` ve `.png` dosyaları için güvenli biçimde `.avif` veya `.webp` varyantını seçer.
pub fn select_negotiated_image_path(
    orig_path: &Path,
    accept_header: Option<&str>,
    allow_avif: bool,
    allow_webp: bool,
) -> Option<(PathBuf, &'static str)> {
    if !allow_avif && !allow_webp {
        return None;
    }
    let ext = orig_path.extension().and_then(|e| e.to_str())?;
    if !(ext.eq_ignore_ascii_case("jpg")
        || ext.eq_ignore_ascii_case("jpeg")
        || ext.eq_ignore_ascii_case("png"))
    {
        return None;
    }

    let accept = accept_header?.trim();
    if accept.is_empty() {
        return None;
    }
    let accept_lower = accept.to_ascii_lowercase();

    let orig_parent = orig_path.parent()?;
    let parent_for_canon = if orig_parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        orig_parent
    };
    let canon_parent = std::fs::canonicalize(parent_for_canon).ok()?;

    if allow_avif && accept_supports_media_type(&accept_lower, "image/avif") {
        if let Some(canon_avif) =
            find_safe_negotiated_variant(orig_path, orig_parent, &canon_parent, "avif")
        {
            return Some((canon_avif, "image/avif"));
        }
    }

    if allow_webp && accept_supports_media_type(&accept_lower, "image/webp") {
        if let Some(canon_webp) =
            find_safe_negotiated_variant(orig_path, orig_parent, &canon_parent, "webp")
        {
            return Some((canon_webp, "image/webp"));
        }
    }

    None
}

const DEFAULT_LOG_ROTATION_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// Belirtilen günlük dosyasına satır ekler; boyut `max_bytes` eşiğine ulaştığında `.1` yedeğine döndürür.
pub async fn append_line_with_rotation(log_file: &Path, line: &str, max_bytes: u64) {
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = log_file.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
    }

    if max_bytes > 0 {
        if let Ok(meta) = tokio::fs::metadata(log_file).await {
            if meta.is_file() && meta.len() >= max_bytes {
                let mut backup_os = log_file.as_os_str().to_os_string();
                backup_os.push(".1");
                let backup_file = PathBuf::from(backup_os);
                if tokio::fs::rename(log_file, &backup_file).await.is_err() {
                    let _ = tokio::fs::remove_file(&backup_file).await;
                    let _ = tokio::fs::rename(log_file, &backup_file).await;
                }
            }
        }
    }

    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .await
    {
        if line.ends_with('\n') {
            let _ = f.write_all(line.as_bytes()).await;
        } else {
            let _ = f.write_all(format!("{line}\n").as_bytes()).await;
        }
        let _ = f.flush().await;
    }
}

/// Hata/uyarı günlüklerini `logs/error.log` dosyasına boyut sınırı ile güvenli şekilde yazar.
pub async fn append_error_log_limit(base_dir: &Path, line: &str, max_bytes: u64) {
    let log_file = base_dir.join("logs").join("error.log");
    append_line_with_rotation(&log_file, line, max_bytes).await;
}

/// Erişim günlüklerini `logs/access.log` dosyasına boyut sınırı ile güvenli şekilde yazar.
pub async fn append_access_log_limit(base_dir: &Path, line: &str, max_bytes: u64) {
    let log_file = base_dir.join("logs").join("access.log");
    append_line_with_rotation(&log_file, line, max_bytes).await;
}

/// Hata/uyarı günlüklerini `logs/error.log` dosyasına güvenli şekilde yazar.
pub async fn append_error_log(base_dir: &Path, line: &str) {
    append_error_log_limit(base_dir, line, DEFAULT_LOG_ROTATION_MAX_BYTES).await;
}

const HOTLINK_PROTECTED_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp", "mp4", "webm", "ogg", "mp3",
    "wav", "woff", "woff2", "ttf", "eot", "pdf", "zip",
];

/// Dosya adı veya yolunun hotlink koruması kapsamındaki statik medya/varlık uzantısına sahip olup olmadığını kontrol eder.
#[allow(dead_code)]
pub fn is_hotlink_protected_extension(file_name_or_path: &str) -> bool {
    let path_only = file_name_or_path
        .split(['?', '#'])
        .next()
        .unwrap_or(file_name_or_path)
        .trim();
    let Some(ext) = Path::new(path_only).extension().and_then(|e| e.to_str()) else {
        return false;
    };
    HOTLINK_PROTECTED_EXTENSIONS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

fn is_valid_port(port_str: &str) -> bool {
    !port_str.is_empty()
        && port_str.bytes().all(|b| b.is_ascii_digit())
        && port_str.parse::<u16>().is_ok()
}

fn normalize_host_without_port(raw: &str, allow_bare_ipv6: bool) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(after_open) = s.strip_prefix('[') {
        let end = after_open.find(']')?;
        let inner = &after_open[..end];
        let after = &after_open[end + 1..];
        if !after.is_empty() {
            let port_str = after.strip_prefix(':')?;
            if !is_valid_port(port_str) {
                return None;
            }
        }
        let ip = inner.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(format!("[{ip}]"));
    }

    if allow_bare_ipv6 {
        if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
            return Some(format!("[{ip}]"));
        }
    }

    let host = if let Some((h, port_str)) = s.split_once(':') {
        if !is_valid_port(port_str) {
            return None;
        }
        h
    } else {
        s
    };

    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

fn is_subdomain_match_eligible(domain: &str) -> bool {
    let is_ip = domain
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok();
    domain != "default" && domain.contains('.') && !is_ip
}

fn host_matches_allowed_domain(ref_host: &str, candidate: &str) -> bool {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return false;
    }

    if let Some(wild_base) = trimmed.strip_prefix("*.") {
        let Some(domain) = normalize_host_without_port(wild_base, false) else {
            return false;
        };
        if is_subdomain_match_eligible(&domain) {
            let suffix = format!(".{domain}");
            return ref_host.ends_with(&suffix);
        }
        return false;
    }

    let Some(domain) = normalize_host_without_port(trimmed, true) else {
        return false;
    };
    if ref_host == domain {
        return true;
    }
    if is_subdomain_match_eligible(&domain) {
        let suffix = format!(".{domain}");
        return ref_host.ends_with(&suffix);
    }
    false
}

/// HTTP `Referer` başlığından şemayı, yolu, kimlik bilgisini ve portu soyarak küçük harfli ana makine adını çıkarır.
#[allow(dead_code)]
pub fn extract_referer_host(referer: &str) -> Option<String> {
    let raw = referer.trim();
    let rest = if raw
        .as_bytes()
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"http://"))
    {
        &raw[7..]
    } else if raw
        .as_bytes()
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
    {
        &raw[8..]
    } else {
        return None;
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("").trim();
    if authority.is_empty() || authority.contains('\\') {
        return None;
    }

    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .trim();

    normalize_host_without_port(host_port, false)
}

/// Statik medya/varlık isteğinin dış kaynaklı (hotlink) olup olmadığını değerlendirir; engellenmeliyse `true` döner.
pub fn is_hotlink_blocked(
    referer_header: Option<&str>,
    request_host: &str,
    vhost_name: &str,
    vhost_aliases: &[String],
    file_path: &str,
) -> bool {
    if !is_hotlink_protected_extension(file_path) {
        return false;
    }

    let Some(raw_referer) = referer_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };

    let Some(ref_host) = extract_referer_host(raw_referer) else {
        return false;
    };

    let allowed = host_matches_allowed_domain(&ref_host, request_host)
        || host_matches_allowed_domain(&ref_host, vhost_name)
        || vhost_aliases
            .iter()
            .any(|alias| host_matches_allowed_domain(&ref_host, alias));

    !allowed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotlink_protection_blocks_external_media_but_allows_direct_and_self() {
        let protected = [
            "jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp", "mp4", "webm", "ogg",
            "mp3", "wav", "woff", "woff2", "ttf", "eot", "pdf", "zip",
        ];
        for ext in protected {
            assert!(
                is_hotlink_protected_extension(&format!("/assets/file.{ext}")),
                "{ext} korunmalı"
            );
            assert!(
                is_hotlink_protected_extension(&format!(
                    "C:\\www\\media\\ITEM.{}?v=2#top",
                    ext.to_ascii_uppercase()
                )),
                "{ext} büyük harf ve sorguyla da korunmalı"
            );
        }
        for open in [
            "/index.html",
            "/css/app.css",
            "/js/main.js",
            "/api/data.json",
            "/robots.txt",
            "/noext",
            "/.env",
        ] {
            assert!(!is_hotlink_protected_extension(open), "{open} korunmamalı");
        }

        assert_eq!(
            extract_referer_host("https://Alan.COM:8080/galeri/1?x=2#h").as_deref(),
            Some("alan.com")
        );
        assert_eq!(
            extract_referer_host("HTTP://user:pass@Sub.Site.Test:8443/sayfa").as_deref(),
            Some("sub.site.test")
        );
        assert_eq!(
            extract_referer_host("https://[::1]:8443/media").as_deref(),
            Some("[::1]")
        );
        assert_eq!(
            extract_referer_host("http://good.com@evil.com/steal").as_deref(),
            Some("evil.com")
        );
        assert_eq!(extract_referer_host(""), None);
        assert_eq!(extract_referer_host("/relative/page.html"), None);
        assert_eq!(extract_referer_host("about:blank"), None);
        assert_eq!(extract_referer_host("http:///no-host"), None);
        assert_eq!(extract_referer_host("https://alan.com:abc/bad"), None);
        assert_eq!(extract_referer_host("https://alan.com:+80/bad"), None);

        let aliases = vec![
            "partner.example".to_string(),
            "*.cdn-mirror.test".to_string(),
            "::1".to_string(),
        ];

        // Doğrudan istek veya boş/kırık referer engellenmemeli
        assert!(!is_hotlink_blocked(
            None,
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(!is_hotlink_blocked(
            Some("   "),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(!is_hotlink_blocked(
            Some("/local/page.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));

        // Korumasız uzantılar dış referer ile bile engellenmemeli
        assert!(!is_hotlink_blocked(
            Some("https://evil.com/ref"),
            "site.test",
            "site.test",
            &aliases,
            "/css/main.css"
        ));

        // Kendi domaini, portu soyulmuş host, alt alan adı ve alias izinli
        assert!(!is_hotlink_blocked(
            Some("HTTPS://SITE.TEST/post"),
            "site.test:8080",
            "site.test",
            &aliases,
            "/img/hero.png"
        ));
        assert!(!is_hotlink_blocked(
            Some("https://blog.site.test/yazi"),
            "site.test",
            "site.test",
            &aliases,
            "/video/clip.mp4"
        ));
        assert!(!is_hotlink_blocked(
            Some("https://sub.partner.example/embed"),
            "site.test",
            "site.test",
            &aliases,
            "/docs/manual.pdf"
        ));
        assert!(!is_hotlink_blocked(
            Some("https://edge1.cdn-mirror.test/page"),
            "site.test",
            "site.test",
            &aliases,
            "/fonts/ui.woff2"
        ));
        assert!(!is_hotlink_blocked(
            Some("http://[::1]:8443/index.html"),
            "[::1]:8080",
            "localhost",
            &aliases,
            "/img/logo.webp"
        ));

        // Harici domain ve sahte sonek/önek denemeleri engellenmeli
        assert!(is_hotlink_blocked(
            Some("https://evil.com/steal.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(is_hotlink_blocked(
            Some("https://evilsite.test/steal.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(is_hotlink_blocked(
            Some("https://site.test.evil.com/steal.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));

        // www. normalizasyonu yapılmamalı
        assert!(is_hotlink_blocked(
            Some("https://site.test/page"),
            "www.site.test",
            "www.site.test",
            &[],
            "/img/hero.jpg"
        ));

        // IP adreslerinde ve "default" / "localhost" üzerinde subdomain eşleşmesi kapalı olmalı
        assert!(!is_hotlink_blocked(
            Some("http://127.0.0.1:3000/page"),
            "127.0.0.1:8080",
            "default",
            &[],
            "/img/hero.png"
        ));
        assert!(is_hotlink_blocked(
            Some("http://evil.127.0.0.1/page"),
            "127.0.0.1:8080",
            "default",
            &[],
            "/img/hero.png"
        ));
        assert!(is_hotlink_blocked(
            Some("http://evil.default/page"),
            "site.test",
            "default",
            &[],
            "/img/hero.png"
        ));
        assert!(is_hotlink_blocked(
            Some("http://evil.localhost/page"),
            "localhost:8080",
            "localhost",
            &[],
            "/img/hero.png"
        ));
    }

    fn make_temp_test_dir(label: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "zmax_modules_runtime_{}_{}_{}",
            label,
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("geçici test dizini oluşturulmalı");
        dir
    }

    #[test]
    fn static_module_policy_compiles_with_expected_defaults_and_overrides() {
        let def = StaticModulePolicy::default();
        assert!(def.etag_enabled);
        assert!(def.last_modified_header);
        assert!(def.auto_webp);
        assert!(def.auto_avif);
        assert!(!def.directory_browsing);

        let cfg = ZMaxConfig::default();
        let empty_mods = LoadedModules::default();
        let compiled_missing = compile_policies(&cfg, &empty_mods);
        assert!(compiled_missing.static_policy.etag_enabled);
        assert!(compiled_missing.static_policy.last_modified_header);
        assert!(!compiled_missing.static_policy.auto_webp);
        assert!(!compiled_missing.static_policy.auto_avif);
        assert!(!compiled_missing.static_policy.directory_browsing);

        let dir = make_temp_test_dir("static_policy");
        let disabled_toml = r#"
[module]
name = "mod_static"
enabled = false

[settings]
etag_enabled = false
last_modified_header = false
auto_webp = true
auto_avif = true
directory_browsing = true
"#;
        std::fs::write(dir.join("mod_static.toml"), disabled_toml).unwrap();
        let disabled_mods = LoadedModules::load_from_dir(&dir).unwrap();
        let compiled_disabled = compile_policies(&cfg, &disabled_mods);
        assert!(compiled_disabled.static_policy.etag_enabled);
        assert!(compiled_disabled.static_policy.last_modified_header);
        assert!(!compiled_disabled.static_policy.auto_webp);
        assert!(!compiled_disabled.static_policy.auto_avif);
        assert!(!compiled_disabled.static_policy.directory_browsing);

        let enabled_toml = r#"
[module]
name = "mod_static"
enabled = true

[settings]
etag_enabled = false
last_modified_header = true
auto_webp = true
auto_avif = false
directory_browsing = true
"#;
        std::fs::write(dir.join("mod_static.toml"), enabled_toml).unwrap();
        let enabled_mods = LoadedModules::load_from_dir(&dir).unwrap();
        let compiled_enabled = compile_policies(&cfg, &enabled_mods);
        assert!(!compiled_enabled.static_policy.etag_enabled);
        assert!(compiled_enabled.static_policy.last_modified_header);
        assert!(compiled_enabled.static_policy.auto_webp);
        assert!(!compiled_enabled.static_policy.auto_avif);
        assert!(compiled_enabled.static_policy.directory_browsing);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_negotiated_image_prefers_avif_then_webp_safely() {
        let dir = make_temp_test_dir("negotiate");
        let outside = make_temp_test_dir("negotiate_outside");

        let jpg_path = dir.join("foto.jpg");
        let stem_avif = dir.join("foto.avif");
        let stem_webp = dir.join("foto.webp");
        std::fs::write(&jpg_path, b"jpg").unwrap();
        std::fs::write(&stem_avif, b"avif").unwrap();
        std::fs::write(&stem_webp, b"webp").unwrap();

        let canon_stem_avif = std::fs::canonicalize(&stem_avif).unwrap();
        let canon_stem_webp = std::fs::canonicalize(&stem_webp).unwrap();

        // AVIF + WebP destekleniyorsa AVIF öncelikli olmalı
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/avif,image/webp"), true, true),
            Some((canon_stem_avif, "image/avif"))
        );

        // Yalnız WebP destekleniyorsa WebP seçilmeli
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/webp,*/*;q=0.8"), true, true),
            Some((canon_stem_webp.clone(), "image/webp"))
        );

        // AVIF politikası kapalıysa WebP'ye düşmeli
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/avif,image/webp"), false, true),
            Some((canon_stem_webp.clone(), "image/webp"))
        );

        // q=0 ile reddedilen AVIF yerine WebP seçilmeli
        assert_eq!(
            select_negotiated_image_path(
                &jpg_path,
                Some("image/avif;q=0, image/webp;q=0.9"),
                true,
                true
            ),
            Some((canon_stem_webp, "image/webp"))
        );

        // <orig>.avif dosyası <stem>.avif dosyasından önce tercih edilmeli
        let orig_avif = dir.join("foto.jpg.avif");
        std::fs::write(&orig_avif, b"orig-avif").unwrap();
        let canon_orig_avif = std::fs::canonicalize(&orig_avif).unwrap();
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/avif,image/webp"), true, true),
            Some((canon_orig_avif, "image/avif"))
        );

        // .txt dosyasında devreye girmemeli
        let txt_path = dir.join("notlar.txt");
        std::fs::write(&txt_path, b"text").unwrap();
        std::fs::write(dir.join("notlar.avif"), b"fake").unwrap();
        assert_eq!(
            select_negotiated_image_path(&txt_path, Some("image/avif,image/webp"), true, true),
            None
        );

        // .PNG ve .jpeg uzantıları büyük/küçük harf duyarsız çalışmalı
        let png_path = dir.join("logo.PNG");
        let png_webp = dir.join("logo.webp");
        std::fs::write(&png_path, b"png").unwrap();
        std::fs::write(&png_webp, b"webp").unwrap();
        assert_eq!(
            select_negotiated_image_path(&png_path, Some("IMAGE/WEBP"), true, true),
            Some((std::fs::canonicalize(&png_webp).unwrap(), "image/webp"))
        );

        // Varyant adında klasör varsa dosya olarak kabul edilmemeli
        let dir_fake_jpg = dir.join("klasor.jpeg");
        std::fs::write(&dir_fake_jpg, b"jpeg").unwrap();
        std::fs::create_dir_all(dir.join("klasor.avif")).unwrap();
        assert_eq!(
            select_negotiated_image_path(&dir_fake_jpg, Some("image/avif"), true, true),
            None
        );

        // Symlink ile parent dizin dışına kaçış engellenmeli
        let secret_avif = outside.join("gizli.avif");
        std::fs::write(&secret_avif, b"secret").unwrap();
        let symlink_jpg = dir.join("disari.jpg");
        std::fs::write(&symlink_jpg, b"jpg").unwrap();
        let symlink_avif = dir.join("disari.avif");
        #[cfg(unix)]
        let symlink_created = std::os::unix::fs::symlink(&secret_avif, &symlink_avif).is_ok();
        #[cfg(windows)]
        let symlink_created =
            std::os::windows::fs::symlink_file(&secret_avif, &symlink_avif).is_ok();
        if symlink_created {
            assert_eq!(
                select_negotiated_image_path(&symlink_jpg, Some("image/avif"), true, true),
                None
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn append_line_with_rotation_rotates_to_dot_one_backup() {
        let dir = make_temp_test_dir("log_rotate");
        let log_file = dir.join("logs").join("custom.log");
        let backup_file = dir.join("logs").join("custom.log.1");

        append_line_with_rotation(&log_file, "birinci-log-satiri-0123456789abcdef", 64).await;
        assert!(!backup_file.exists(), "ilk satırda yedek oluşmamalı");

        append_line_with_rotation(&log_file, "ikinci-log-satiri-0123456789abcdef", 64).await;
        assert!(!backup_file.exists(), "eşik yazım öncesi aşılmadığı için henüz dönmemeli");

        append_line_with_rotation(&log_file, "ucuncu-temiz-satir", 64).await;
        assert!(backup_file.is_file(), "eşik aşıldığında .1 yedeği oluşmalı");
        let backup_body = tokio::fs::read_to_string(&backup_file).await.unwrap();
        assert!(backup_body.contains("birinci-log-satiri"));
        assert!(backup_body.contains("ikinci-log-satiri"));
        let active_body = tokio::fs::read_to_string(&log_file).await.unwrap();
        assert_eq!(active_body, "ucuncu-temiz-satir\n");

        // İkinci döndürmede önceki .1 üzerine taşınıp yeni içerik sıfırdan başlamalı
        append_line_with_rotation(
            &log_file,
            "dorduncu-uzun-satir-0123456789abcdef0123456789abcdef0123456789abcdef",
            64,
        )
        .await;
        append_line_with_rotation(&log_file, "besinci-satir", 64).await;
        let second_backup = tokio::fs::read_to_string(&backup_file).await.unwrap();
        assert!(second_backup.contains("dorduncu-uzun-satir"));
        assert!(!second_backup.contains("birinci-log-satiri"));
        assert_eq!(
            tokio::fs::read_to_string(&log_file).await.unwrap(),
            "besinci-satir\n"
        );

        // append_error_log_limit ve append_access_log_limit yardımcıları da aynı döndürmeyi kullanmalı
        append_error_log_limit(&dir, "err-uzun-satir-0123456789", 10).await;
        append_error_log_limit(&dir, "err-yeni", 10).await;
        assert!(dir.join("logs").join("error.log.1").is_file());
        assert_eq!(
            tokio::fs::read_to_string(dir.join("logs").join("error.log"))
                .await
                .unwrap(),
            "err-yeni\n"
        );

        append_access_log_limit(&dir, "acc-uzun-satir-0123456789\r\n", 10).await;
        append_access_log_limit(&dir, "acc-yeni\n", 10).await;
        assert!(dir.join("logs").join("access.log.1").is_file());
        assert_eq!(
            tokio::fs::read_to_string(dir.join("logs").join("access.log"))
                .await
                .unwrap(),
            "acc-yeni\n"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn gzip_brotli_and_fastcgi_policies_compile_from_toml() {
        let dir = make_temp_test_dir("brotli_fcgi");
        std::fs::write(
            dir.join("mod_gzip.toml"),
            "[module]\nname = \"mod_gzip\"\nenabled = true\n\n[settings]\nmin_length = 1024\nvary_header = false\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("mod_brotli.toml"),
            "[module]\nname = \"mod_brotli\"\nenabled = false\n\n[settings]\nmin_length = 256\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("mod_fastcgi.toml"),
            "[module]\nname = \"mod_fastcgi\"\nenabled = true\n\n[settings]\ndefault_upstream = \"127.0.0.1:9001\"\nconnection_timeout_sec = 45\nkeep_alive_pool_size = 32\ndial_timeout_ms = 1500\nkeep_conn = false\n",
        )
        .unwrap();

        let cfg = ZMaxConfig::default();
        let mods = LoadedModules::load_from_dir(&dir).unwrap();
        let policies = compile_policies(&cfg, &mods);

        assert!(policies.gzip.enabled);
        assert!(!policies.gzip.brotli_enabled);
        assert_eq!(policies.gzip.min_length, 1024);
        assert!(!policies.gzip.vary_header);

        assert!(policies.fastcgi.enabled);
        assert_eq!(policies.fastcgi.default_upstream, "127.0.0.1:9001");
        assert_eq!(policies.fastcgi.timeout_sec, 45);
        assert_eq!(policies.fastcgi.pool_size, 32);
        assert_eq!(policies.fastcgi.dial_timeout_ms, 1500);
        assert!(!policies.fastcgi.keep_conn);

        std::fs::write(
            dir.join("mod_brotli.toml"),
            "[module]\nname = \"mod_brotli\"\nenabled = true\n",
        )
        .unwrap();
        let mods_on = LoadedModules::load_from_dir(&dir).unwrap();
        let policies_on = compile_policies(&cfg, &mods_on);
        assert!(policies_on.gzip.brotli_enabled);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
