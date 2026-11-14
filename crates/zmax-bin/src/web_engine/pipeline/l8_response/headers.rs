//! L8 — vhost yanıt güvenlik başlığı politikası.

use zmax_config::VHostEntry;
use zmax_header::SecurityHeadersPolicy;

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
