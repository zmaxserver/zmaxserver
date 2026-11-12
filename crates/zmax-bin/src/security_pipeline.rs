//! # zmax-bin :: security_pipeline
//! HTTP/1.1 ve HTTP/2 istek boru hatları için birleştirilmiş ve ortak güvenlik denetimleri.
//! Hotlink koruması, IP/CIDR ACL, vHost WAF, WordPress kaba kuvvet ve HTTPS zorlama kuralları.

use crate::web_engine::{is_acme_challenge, ResolvedVHostContext};
use std::net::IpAddr;
use zmax_config::{VHostSecuritySection, VhostAclConfig};
use zmax_security::{
    is_hotlink_blocked, IpBanManager, VHostWafPolicy, VhostAcl, WafInspector, WafViolation,
    WpBruteForceGuard,
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
    WafBlocked { violation: WafViolation },
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
    if let Err(violation) = waf_inspector.inspect_with_policy(
        method,
        path,
        query,
        headers,
        body,
        &vhost_waf_policy,
    ) {
        return SecurityVerdict::WafBlocked { violation };
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

/// WAF engelleme olayını 24 saatlik sayaca ve asenkron WAF olay günlüğüne tek çağrıyla kaydeder.
pub fn record_waf_block(
    state: &crate::api::ServerState,
    vhost_ctx: &ResolvedVHostContext,
    client_ip: &str,
    method: &str,
    path: &str,
    violation: &WafViolation,
) {
    let record = state.waf_events.record_violation(
        violation,
        &vhost_ctx.vhost_name,
        client_ip,
        method,
        path,
    );
    let ok = state
        .log_manager
        .log_waf_event(record, None, vhost_ctx.max_log_size_bytes, true);
    if !ok {
        state.waf_events.record_dropped();
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
