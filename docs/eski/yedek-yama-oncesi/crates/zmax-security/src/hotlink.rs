//! # zmax-security :: hotlink
//! Dış kaynaklı doğrudan medya/varlık bağlama (Hotlinking) koruması.

/// Referer başlığından alan adını (host) temiz bir şekilde ayıklar.
/// Şema (`http://`, `https://`, `//`), port (`:8080`), yol ve sorgu parametrelerini eler.
pub fn extract_referer_host(raw_referer: &str) -> Option<String> {
    let trimmed = raw_referer.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Şema temizleme
    let without_scheme = if let Some(stripped) = trimmed.strip_prefix("https://") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("http://") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("//") {
        stripped
    } else {
        trimmed
    };

    // Yol veya sorgu öncesi host kısmını al
    let host_and_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim();

    if host_and_port.is_empty() {
        return None;
    }

    // IPv6 köşeli parantez kontrolü [::1]:8080
    if let Some(stripped) = host_and_port.strip_prefix('[') {
        if let Some((ipv6, _rest)) = stripped.split_once(']') {
            return Some(ipv6.to_ascii_lowercase());
        }
    }

    // Normal IPv4 veya alan adı: Port varsa temizle
    let host = host_and_port
        .split(':')
        .next()
        .unwrap_or("")
        .trim();

    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// İstek ana bilgisayarından (Host header) portu ve olası IPv6 köşeli parantezlerini temizler.
pub fn normalize_request_host(raw_host: &str) -> String {
    let trimmed = raw_host.trim();
    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some((ipv6, _)) = stripped.split_once(']') {
            return ipv6.to_ascii_lowercase();
        }
    }
    trimmed
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Bir alan adı kalıbının IP adresi veya yerel test alan adı olup olmadığını belirler.
fn is_ip_or_localhost(domain: &str) -> bool {
    let clean = domain.trim().trim_start_matches("*.").to_ascii_lowercase();
    clean == "localhost"
        || clean == "default"
        || clean.parse::<std::net::IpAddr>().is_ok()
}

/// Referer host'unun izin verilen bir alan adı kalıbıyla eşleşip eşleşmediğini denetler.
/// `*.ornek.com` ve `ornek.com` biçimleri alt alan adlarını kapsar.
pub fn host_matches_pattern(ref_host: &str, pattern: &str) -> bool {
    let ref_clean = ref_host.trim().to_ascii_lowercase();
    let pat_clean = pattern.trim().to_ascii_lowercase();

    if ref_clean.is_empty() || pat_clean.is_empty() {
        return false;
    }

    // Tam birebir eşleşme
    if ref_clean == pat_clean {
        return true;
    }

    // IP veya localhost için alt alan adı eşleşmesi güvenlik gerekçesiyle yapılmaz (örn. evil.127.0.0.1 engellenmelidir)
    if is_ip_or_localhost(&pat_clean) {
        return false;
    }

    // Wildcard öneki: *.ornek.com
    if let Some(base) = pat_clean.strip_prefix("*.") {
        if ref_clean == base || ref_clean.ends_with(&format!(".{base}")) {
            return true;
        }
    }

    // Standart alan adı: ornek.com girilmişse alt alan adları (sub.ornek.com) da izinlidir
    if ref_clean.ends_with(&format!(".{pat_clean}")) {
        return true;
    }

    false
}

pub fn default_extensions() -> Vec<String> {
    vec![
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
        "webp".to_string(),
        "svg".to_string(),
        "mp4".to_string(),
        "mp3".to_string(),
        "pdf".to_string(),
        "zip".to_string(),
    ]
}

/// İstek yapılan yolun korunan dosya uzantılarından birine sahip olup olmadığını kontrol eder.
pub fn is_extension_protected(path: &str, extensions: &[String]) -> bool {
    let clean_path = path.split(['?', '#']).next().unwrap_or("").trim();
    let Some(dot_idx) = clean_path.rfind('.') else {
        return false;
    };
    let ext = &clean_path[dot_idx + 1..].to_ascii_lowercase();
    if ext.is_empty() {
        return false;
    }

    let default_exts;
    let eff_exts = if extensions.is_empty() {
        default_exts = default_extensions();
        default_exts.as_slice()
    } else {
        extensions
    };

    eff_exts.iter().any(|e| {
        let normalized = e.trim().trim_start_matches('.').to_ascii_lowercase();
        normalized == *ext
    })
}

/// Hotlink koruma denetimi:
/// Korunan bir dosya uzantısı istendiğinde Referer başlığını denetler.
/// Boş Referer veya izinli alan adlarıyla eşleşen istekler geçer; aksi takdirde `true` (engellendi / 403 Forbidden) döner.
pub fn is_hotlink_blocked(
    enabled: bool,
    allowed_referers: &[String],
    extensions: &[String],
    referer: Option<&str>,
    request_host: &str,
    vhost_name: &str,
    vhost_aliases: &[String],
    request_path: &str,
) -> bool {
    // 1. Hotlink koruması etkin değilse izin ver
    if !enabled {
        return false;
    }

    // 2. İstenen dosya uzantısı koruma listesinde değilse izin ver (html, php vb. hotlink'e tabi değildir)
    if !is_extension_protected(request_path, extensions) {
        return false;
    }

    // 3. Referer başlığı yok veya boş ise İZİN VERİLİR (RewriteCond %{HTTP_REFERER} !^$)
    let Some(raw_ref) = referer.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };

    // Referer host'unu çözümle; çözümlenemiyorsa (bozuk/kırık referer) engelleme
    let Some(ref_host) = extract_referer_host(raw_ref) else {
        return false;
    };

    let req_host_clean = normalize_request_host(request_host);

    // 4. Referer izin kontrolleri
    // 4a. İstek yapılan alan adı ile eşleşiyor mu?
    if !req_host_clean.is_empty() && host_matches_pattern(&ref_host, &req_host_clean) {
        return false;
    }

    // 4b. vHost birincil alan adı ile eşleşiyor mu?
    if !vhost_name.trim().is_empty() && host_matches_pattern(&ref_host, vhost_name) {
        return false;
    }

    // 4c. vHost alias alan adlarından biriyle eşleşiyor mu?
    if vhost_aliases.iter().any(|alias| host_matches_pattern(&ref_host, alias)) {
        return false;
    }

    // 4d. Yapılandırmada tanımlı izinli referer listesiyle eşleşiyor mu?
    if allowed_referers.iter().any(|allowed| host_matches_pattern(&ref_host, allowed)) {
        return false;
    }

    // Hiçbiriyle eşleşmediyse harici hotlink tespit edildi: 403 Forbidden
    true
}

/// Nesne yönelimli Hotlink koruma yapılandırıcısı ve denetleyicisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotlinkGuard {
    pub enabled: bool,
    pub allowed_referers: Vec<String>,
    pub extensions: Vec<String>,
}

impl Default for HotlinkGuard {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_referers: Vec::new(),
            extensions: vec![
                "jpg".to_string(),
                "jpeg".to_string(),
                "png".to_string(),
                "gif".to_string(),
                "webp".to_string(),
                "svg".to_string(),
                "mp4".to_string(),
                "mp3".to_string(),
                "pdf".to_string(),
                "zip".to_string(),
            ],
        }
    }
}

impl HotlinkGuard {
    pub fn new(enabled: bool, allowed_referers: Vec<String>, extensions: Vec<String>) -> Self {
        Self {
            enabled,
            allowed_referers,
            extensions,
        }
    }

    pub fn check(
        &self,
        referer: Option<&str>,
        request_host: &str,
        vhost_name: &str,
        vhost_aliases: &[String],
        request_path: &str,
    ) -> bool {
        is_hotlink_blocked(
            self.enabled,
            &self.allowed_referers,
            &self.extensions,
            referer,
            request_host,
            vhost_name,
            vhost_aliases,
            request_path,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_referer_host() {
        assert_eq!(extract_referer_host("http://example.com/image.jpg"), Some("example.com".to_string()));
        assert_eq!(extract_referer_host("https://sub.domain.org:8443/page?x=1"), Some("sub.domain.org".to_string()));
        assert_eq!(extract_referer_host("//cdn.test/assets/logo.png"), Some("cdn.test".to_string()));
        assert_eq!(extract_referer_host("http://[2001:db8::1]:8080/path"), Some("2001:db8::1".to_string()));
        assert_eq!(extract_referer_host(""), None);
        assert_eq!(extract_referer_host("   "), None);
    }

    #[test]
    fn test_is_extension_protected() {
        let exts = vec!["jpg".to_string(), "png".to_string(), "webp".to_string()];
        assert!(is_extension_protected("/images/photo.jpg", &exts));
        assert!(is_extension_protected("/assets/pic.PNG", &exts));
        assert!(is_extension_protected("/test.webp?version=2", &exts));
        assert!(!is_extension_protected("/index.html", &exts));
        assert!(!is_extension_protected("/api/data", &exts));
        assert!(!is_extension_protected("/style.css", &exts));
    }

    #[test]
    fn test_host_matches_pattern() {
        assert!(host_matches_pattern("example.com", "example.com"));
        assert!(host_matches_pattern("sub.example.com", "example.com"));
        assert!(host_matches_pattern("deep.sub.example.com", "example.com"));
        assert!(host_matches_pattern("cdn.test", "*.test"));
        assert!(!host_matches_pattern("example.org", "example.com"));
        assert!(!host_matches_pattern("evil-example.com", "example.com"));
        // IP güvenlik kontrolü
        assert!(!host_matches_pattern("evil.127.0.0.1", "127.0.0.1"));
        assert!(!host_matches_pattern("evil.localhost", "localhost"));
    }

    #[test]
    fn test_hotlink_empty_referer_allowed() {
        let guard = HotlinkGuard {
            enabled: true,
            allowed_referers: vec!["friendly.com".to_string()],
            ..HotlinkGuard::default()
        };

        // Boş veya olmayan referer engellenmemeli
        assert!(!guard.check(None, "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
        assert!(!guard.check(Some(""), "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
        assert!(!guard.check(Some("   "), "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
    }

    #[test]
    fn test_hotlink_unprotected_extension_allowed() {
        let guard = HotlinkGuard {
            enabled: true,
            allowed_referers: vec![],
            ..HotlinkGuard::default()
        };

        // Kötü referer gelse bile korunan uzantı değilse izin verilir
        assert!(!guard.check(Some("http://evil.com"), "myvhost.test", "myvhost.test", &[], "/index.html"));
        assert!(!guard.check(Some("http://evil.com"), "myvhost.test", "myvhost.test", &[], "/app.js"));
    }

    #[test]
    fn test_hotlink_friendly_referer_allowed() {
        let guard = HotlinkGuard {
            enabled: true,
            allowed_referers: vec!["partner.com".to_string(), "*.cdn-network.test".to_string()],
            ..HotlinkGuard::default()
        };

        // Kendi domaini
        assert!(!guard.check(Some("http://myvhost.test/page"), "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
        // Kendi alt domaini
        assert!(!guard.check(Some("http://blog.myvhost.test/page"), "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
        // İzinli referer listesindeki partner
        assert!(!guard.check(Some("https://partner.com/article"), "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
        // İzinli wildcard
        assert!(!guard.check(Some("https://images.cdn-network.test/"), "myvhost.test", "myvhost.test", &[], "/photo.jpg"));
    }

    #[test]
    fn test_hotlink_foreign_referer_blocked() {
        let guard = HotlinkGuard {
            enabled: true,
            allowed_referers: vec!["partner.com".to_string()],
            ..HotlinkGuard::default()
        };

        // Yabancı siteden gelen istek engellenmeli (403 Forbidden)
        assert!(guard.check(Some("http://baska.test/"), "myvhost.test", "myvhost.test", &[], "/resim.jpg"));
        assert!(guard.check(Some("https://evil.org/stolen.html"), "myvhost.test", "myvhost.test", &[], "/media/video.mp4"));
    }
}
