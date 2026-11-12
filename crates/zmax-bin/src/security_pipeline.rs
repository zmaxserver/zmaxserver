//! # zmax-bin :: security_pipeline
//! HTTP/1.1 ve HTTP/2 istek boru hatları için birleştirilmiş ve ortak güvenlik denetimleri.
//! Hotlink koruması, IP/CIDR ACL, vHost WAF, WordPress kaba kuvvet ve HTTPS zorlama kuralları.

use std::net::IpAddr;
use zmax_security::{is_hotlink_blocked, IpBanManager, VHostWafPolicy, WafInspector, WpBruteForceGuard};
use crate::web_engine::{is_acme_challenge, ResolvedVHostContext};

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
        if let Some(location) = crate::web_engine::https_redirect_location(host, path, query, https_port) {
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
