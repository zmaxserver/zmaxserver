//! L4: ACL, WAF, kaba kuvvet ve HTTPS zorlama kararlari (H1/H2/ek dinleyici icin tek yol).

use crate::web_engine::{is_acme_challenge, ResolvedVHostContext};
use std::net::IpAddr;
use zmax_config::{VHostSecuritySection, VhostAclConfig};
use zmax_security::{IpBanManager, VHostWafPolicy, VhostAcl, WafInspector, WafViolation, WpBruteForceGuard};

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
