//! # zmax-bin :: security_pipeline
//! HTTP/1.1 ve HTTP/2 istek boru hatları için birleştirilmiş ve ortak güvenlik denetimleri.
//! Hotlink koruması, IP/CIDR ACL, vHost WAF, WordPress kaba kuvvet ve HTTPS zorlama kuralları.

use crate::web_engine::{is_acme_challenge, ResolvedVHostContext};
use std::net::IpAddr;
use zmax_config::{VHostSecuritySection, VhostAclConfig};
use zmax_security::{
    is_hotlink_blocked, IpBanManager, VHostWafPolicy, VhostAcl, WafInspector, WpBruteForceGuard,
};

/// `[vhost.security]` ve `[vhost.acl]` bölümlerindeki allow/deny kurallarını
/// sırayı koruyup yinelenenleri ayıklayarak tek `VhostAcl` motorunda birleştirir.
pub fn build_merged_vhost_acl(security: &VHostSecuritySection, acl: &VhostAclConfig) -> VhostAcl {
    let mut allow_ips = Vec::with_capacity(security.allow_ips.len() + acl.allow_ips.len());
    for ip in security.allow_ips.iter().chain(acl.allow_ips.iter()) {
        let trimmed = ip.trim();
        if !trimmed.is_empty()
            && !allow_ips
                .iter()
                .any(|existing: &String| existing == trimmed)
        {
            allow_ips.push(trimmed.to_string());
        }
    }

    let mut deny_ips = Vec::with_capacity(security.deny_ips.len() + acl.deny_ips.len());
    for ip in security.deny_ips.iter().chain(acl.deny_ips.iter()) {
        let trimmed = ip.trim();
        if !trimmed.is_empty() && !deny_ips.iter().any(|existing: &String| existing == trimmed) {
            deny_ips.push(trimmed.to_string());
        }
    }

    VhostAcl::new(allow_ips, deny_ips)
}

/// Güvenlik denetimi sonuç kararı.
#[derive(Debug, PartialEq, Eq)]
pub enum SecurityVerdict {
    /// İstek tüm güvenlik denetimlerinden geçti, boru hattına devam edebilir.
    Allowed,
    /// İstek HTTP üzerinden geldi ve HTTPS'e yönlendirilmeli (301 Moved Permanently).
    RedirectHttps { location: String },
    /// İstek IP engeli, ACL veya kaba kuvvet nedeniyle reddedildi (403 Forbidden).
    Blocked { reason: &'static str },
    /// İstek WAF kural ihlali nedeniyle engellendi (403 Forbidden).
    WafBlocked { violation: String },
}

/// HTTP/1.1 ve HTTP/2 boru hatlarında istek gövdesi işlenmeden ÖNCE çalıştırılan ortak güvenlik kapısı.
pub fn evaluate_request_security(
    vhost_ctx: &ResolvedVHostContext,
    real_ip: IpAddr,
    peer_ip: IpAddr,
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    headers: &[(String, String)],
    body: &[u8],
    is_https: bool,
    https_port: u16,
    ban_manager: &IpBanManager,
    waf_inspector: &WafInspector,
    wp_guard: &WpBruteForceGuard,
    wp_brute_force_enabled: bool,
) -> SecurityVerdict {
    // 0. OLS B5 Denkliği: Korunan hassas kaynaklar, gizli dizinler (.git, .env) ve vhost yapılandırmasına göre tehlikeli dosyalar
    if zmax_rewrite::is_protected_or_dangerous_path(path, vhost_ctx.block_dangerous_files) {
        return SecurityVerdict::Blocked {
            reason: "403 Forbidden - Protected Resource",
        };
    }
    // 1. Yasaklı IP Denetimi (IpBanManager)
    if ban_manager.is_banned(peer_ip) || ban_manager.is_banned(real_ip) {
        return SecurityVerdict::Blocked {
            reason: "403 Forbidden - IP Blocked",
        };
    }

    // 2. IP ve CIDR Erişim Denetim Listesi (Global ACL ve vHost ACL)
    if !vhost_ctx.global_acl.is_empty() && !vhost_ctx.global_acl.is_allowed(real_ip) {
        return SecurityVerdict::Blocked {
            reason: "403 Forbidden - IP Access Denied",
        };
    }

    if !vhost_ctx.vhost_acl_engine.is_empty() {
        if !vhost_ctx.vhost_acl_engine.is_allowed(real_ip) {
            return SecurityVerdict::Blocked {
                reason: "403 Forbidden - IP Access Denied",
            };
        }
    } else if !vhost_ctx.vhost_acl.is_empty() && !vhost_ctx.vhost_acl.is_allowed(real_ip) {
        return SecurityVerdict::Blocked {
            reason: "403 Forbidden - IP Access Denied",
        };
    }

    // 3. WAF / Alan Adına Özel WAF Politikası
    let vhost_waf_policy = VHostWafPolicy {
        waf_enabled: vhost_ctx.waf_enabled,
        exclude_paths: &vhost_ctx.waf_exclude_paths,
    };
    if let Err(violation) =
        waf_inspector.inspect_with_policy(method, path, query, headers, body, &vhost_waf_policy)
    {
        return SecurityVerdict::WafBlocked {
            violation: violation.to_string(),
        };
    }

    // 4. WordPress Kaba Kuvvet Koruması (/wp-login.php, /xmlrpc.php)
    if wp_brute_force_enabled && !wp_guard.check_and_ban(real_ip, method, path, ban_manager) {
        return SecurityVerdict::Blocked {
            reason: "403 Forbidden - Brute Force Protection",
        };
    }

    // 5. force_https: HTTP isteğini HTTPS'e yönlendir (ACME HTTP-01 muaf)
    if !is_https && vhost_ctx.force_https && !is_acme_challenge(path) {
        if let Some(location) =
            crate::web_engine::https_redirect_location(host, path, query, https_port)
        {
            return SecurityVerdict::RedirectHttps { location };
        }
    }

    SecurityVerdict::Allowed
}

/// Hem HTTP/1.1 hem HTTP/2 boru hattında statik dosya sunumundan önce çağrılan birleştirilmiş Hotlink koruma denetimi.
pub fn is_request_hotlink_blocked(
    vhost_ctx: &ResolvedVHostContext,
    referer: Option<&str>,
    request_host: &str,
    request_path: &str,
) -> bool {
    let hl = &vhost_ctx.hotlink_config;
    let is_enabled = hl.enabled || vhost_ctx.hotlink_protection;
    if !is_enabled {
        return false;
    }

    is_hotlink_blocked(
        true,
        &hl.allowed_referers,
        &hl.extensions,
        referer,
        request_host,
        &vhost_ctx.vhost_name,
        &vhost_ctx.vhost_aliases,
        request_path,
    )
}

// [kart-9] Basic Authentication ortak asenkron denetim ve 401 yanit yardimcilari
/// Hem HTTP/1.1 hem HTTP/2 boru hattında çalıştırılan ortak Basic Auth kapısı (ACME HTTP-01 muaftır).
/// CPU-yoğun hash hesaplamaları `BasicAuthManager::check_request_async` aracılığıyla
/// `tokio::task::spawn_blocking` ve `Semaphore` koruması altında yürütülür.
/// Başarısız denemeler IP bazında sayılıp eşik aşımında IP otomatik banlanır.
pub async fn evaluate_basic_auth(
    vhost_ctx: &ResolvedVHostContext,
    client_ip: std::net::IpAddr,
    request_path: &str,
    headers: &[(String, String)],
    basic_auth: &std::sync::Arc<zmax_security::BasicAuthManager>,
    base_dir: &std::path::Path,
    ban_manager: &zmax_security::IpBanManager,
) -> zmax_security::AuthDecision {
    // ACME muafiyeti ham yola değil normalleştirilmiş yola bakar (`..` ile atlatma engellenir).
    if !vhost_ctx.auth.enabled || zmax_security::is_acme_challenge_exempt(request_path) {
        return zmax_security::AuthDecision::Allowed;
    }
    let auth_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str());
    basic_auth
        .check_request_async(
            client_ip,
            auth_header,
            request_path,
            &vhost_ctx.auth,
            Some(base_dir),
            ban_manager,
        )
        .await
}

/// 401 Unauthorized yanıtı için `WWW-Authenticate: Basic realm="..."` başlıklarını ve gövdeyi oluşturur.
pub fn build_unauthorized_response(
    vhost_ctx: &ResolvedVHostContext,
    realm: &str,
    req_id: Option<&str>,
) -> (Vec<(String, String)>, Vec<u8>) {
    let default_body = b"401 Unauthorized - Authentication Required\n";
    let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&401) {
        let custom_dir = if vhost_ctx.error_docs.dir.trim().is_empty() {
            None
        } else {
            Some(std::path::Path::new(vhost_ctx.error_docs.dir.trim()))
        };
        let handler = zmax_static::StaticFileHandler::new(&vhost_ctx.doc_root);
        handler
            .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
            .unwrap_or_else(|_| default_body.to_vec())
    } else {
        default_body.to_vec()
    };

    let content_type = if body.starts_with(b"<!DOCTYPE") || body.starts_with(b"<html") {
        "text/html; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };

    let mut headers = vec![
        (
            "WWW-Authenticate".to_string(),
            zmax_security::format_www_authenticate_header(realm),
        ),
        ("Cache-Control".to_string(), "no-store".to_string()),
        ("Content-Type".to_string(), content_type.to_string()),
    ];
    if let Some(id) = req_id {
        if !id.is_empty() {
            headers.push(("x-request-id".to_string(), id.to_string()));
        }
    }

    (headers, body)
}

/// Kimlik doğrulama reddinin HTTP karşılığı (HTTP/1.1 ve HTTP/2 ortak).
pub struct AuthDenial {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// `AuthDecision` -> yanıt: 401 (+WWW-Authenticate), 403 (ban), 429 / 503 (+Retry-After).
/// `Allowed` için `None` döner.
pub fn build_auth_denial(
    vhost_ctx: &ResolvedVHostContext,
    decision: &zmax_security::AuthDecision,
    req_id: Option<&str>,
) -> Option<AuthDenial> {
    use zmax_security::AuthDecision;
    let simple = |status: u16, reason: &'static str, body: &str, retry: Option<u64>| {
        let mut headers = vec![
            ("Cache-Control".to_string(), "no-store".to_string()),
            (
                "Content-Type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            ),
        ];
        if let Some(secs) = retry {
            headers.push(("Retry-After".to_string(), secs.to_string()));
        }
        if let Some(id) = req_id.filter(|id| !id.is_empty()) {
            headers.push(("x-request-id".to_string(), id.to_string()));
        }
        AuthDenial {
            status,
            reason,
            headers,
            body: body.as_bytes().to_vec(),
        }
    };
    match decision {
        AuthDecision::Allowed => None,
        AuthDecision::Unauthorized { realm } => {
            let (headers, body) = build_unauthorized_response(vhost_ctx, realm, req_id);
            Some(AuthDenial {
                status: 401,
                reason: "Unauthorized",
                headers,
                body,
            })
        }
        AuthDecision::Banned => Some(simple(
            403,
            "Forbidden",
            "403 Forbidden - Brute Force Protection\n",
            None,
        )),
        AuthDecision::TooManyRequests { retry_after_secs } => Some(simple(
            429,
            "Too Many Requests",
            "429 Too Many Requests - Too many concurrent authentication attempts\n",
            Some(*retry_after_secs),
        )),
        AuthDecision::Unavailable { retry_after_secs } => Some(simple(
            503,
            "Service Unavailable",
            "503 Service Unavailable - Authentication queue is busy\n",
            Some(*retry_after_secs),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::build_merged_vhost_acl;
    use std::net::IpAddr;
    use zmax_config::{VHostSecuritySection, VhostAclConfig};

    #[test]
    fn merged_vhost_acl_combines_security_and_acl_sections() {
        let security = VHostSecuritySection {
            allow_ips: vec!["10.0.0.1".into(), " 127.0.0.1 ".into()],
            deny_ips: vec!["192.168.1.0/24".into()],
            ..Default::default()
        };
        let acl = VhostAclConfig {
            allow_ips: vec!["127.0.0.1".into(), "192.168.1.50".into()],
            deny_ips: vec!["172.16.0.0/16".into(), "192.168.1.0/24".into()],
        };

        let merged = build_merged_vhost_acl(&security, &acl);
        assert_eq!(
            merged.allow_ips,
            vec!["10.0.0.1", "127.0.0.1", "192.168.1.50"]
        );
        assert_eq!(merged.deny_ips, vec!["192.168.1.0/24", "172.16.0.0/16"]);

        // Her iki bölümdeki allow kuralları (deny CIDR istisnası dahil) izinli
        assert!(merged.is_allowed("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(merged.is_allowed("127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(merged.is_allowed("192.168.1.50".parse::<IpAddr>().unwrap()));
        // Her iki bölümdeki deny kuralları engelli
        assert!(!merged.is_allowed("192.168.1.99".parse::<IpAddr>().unwrap()));
        assert!(!merged.is_allowed("172.16.5.10".parse::<IpAddr>().unwrap()));
        // Sıkı beyaz liste: listede olmayan dış IP engelli
        assert!(!merged.is_allowed("203.0.113.10".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn merged_vhost_acl_preserves_security_only_and_acl_only() {
        let mut sec_only = VHostSecuritySection::default();
        sec_only.deny_ips = vec!["198.51.100.10".into()];
        let empty_acl = VhostAclConfig::default();

        let acl1 = build_merged_vhost_acl(&sec_only, &empty_acl);
        assert!(!acl1.is_allowed("198.51.100.10".parse().unwrap()));
        assert!(acl1.is_allowed("127.0.0.1".parse().unwrap()));

        let empty_sec = VHostSecuritySection::default();
        let acl_only_cfg = VhostAclConfig {
            allow_ips: vec![],
            deny_ips: vec!["203.0.113.0/24".into()],
        };

        let acl2 = build_merged_vhost_acl(&empty_sec, &acl_only_cfg);
        assert!(!acl2.is_allowed("203.0.113.44".parse().unwrap()));
        assert!(acl2.is_allowed("127.0.0.1".parse().unwrap()));
    }
}
