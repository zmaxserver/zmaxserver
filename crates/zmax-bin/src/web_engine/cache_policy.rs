use crate::api::ServerState;
use std::sync::Arc;

/// [kart-cache-1] Önbellek etiketlerine alan adı varyantlarını ve ham URI etiketlerini ekler.
#[inline]
pub(super) fn append_domain_and_uri_cache_tags(tags: &mut Vec<String>, domain: &str, req_path: &str) {
    let clean_domain = domain.trim().to_ascii_lowercase();
    if !clean_domain.is_empty() {
        for tag in [
            clean_domain.clone(),
            format!("domain::{clean_domain}"),
            format!("domain:{clean_domain}"),
            format!("{clean_domain}::*"),
        ] {
            if !tags.iter().any(|t| t == &tag) {
                tags.push(tag);
            }
        }
    }
    let clean_path = zmax_cache::extract_path_from_uri(req_path);
    if !clean_path.is_empty() {
        for tag in [
            format!("__uri:{clean_path}"),
            format!("__path:{clean_path}"),
        ] {
            if !tags.iter().any(|t| t == &tag) {
                tags.push(tag);
            }
        }
    }
}

/// `[cache] respect_request_cache_control` (varsayılan KAPALI): istek `Cache-Control`/`Pragma` başlıkları önbelleği atlatır mı?
pub(super) async fn respect_request_cache_control(state: &Arc<ServerState>) -> bool {
    state
        .runtime
        .read()
        .await
        .config
        .cache
        .respect_request_cache_control
}

pub(super) fn request_has_bypass_cookie_or_auth(
    headers: &[(String, String)],
    respect_request_cache_control: bool,
) -> bool {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("authorization") {
            return true;
        }
        // Yapılandırma açık değilse bu başlıklar yok sayılır (istemci kaynaklı PHP amplifikasyonu).
        if respect_request_cache_control {
            if k.eq_ignore_ascii_case("cache-control")
                || k.eq_ignore_ascii_case("x-litespeed-cache-control")
            {
                let lower = v.to_ascii_lowercase();
                if lower.contains("no-cache")
                    || lower.contains("no-store")
                    || lower.contains("private")
                {
                    return true;
                }
            }
            if k.eq_ignore_ascii_case("pragma") && v.to_ascii_lowercase().contains("no-cache") {
                return true;
            }
        }
        if k.eq_ignore_ascii_case("cookie") {
            let lower = v.to_ascii_lowercase();
            if lower.contains("wordpress_logged_in")
                || lower.contains("wp-postpass")
                || lower.contains("comment_author")
                || lower.contains("phpsessid")
                || lower.contains("woocommerce_cart_hash")
                || lower.contains("woocommerce_items_in_cart")
            {
                return true;
            }
        }
    }
    false
}

pub(super) fn response_forbids_cache(headers: &[(String, String)]) -> bool {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            return true;
        }
        if k.eq_ignore_ascii_case("cache-control") {
            let lower = v.to_ascii_lowercase();
            if lower.contains("no-store")
                || lower.contains("no-cache")
                || lower.contains("private")
                || lower.contains("max-age=0")
            {
                return true;
            }
        }
        if k.eq_ignore_ascii_case("x-litespeed-cache-control") {
            let lower = v.to_ascii_lowercase();
            if lower.contains("no-store")
                || lower.contains("no-cache")
                || lower.contains("private")
                || lower.contains("max-age=0")
            {
                return true;
            }
        }
    }
    false
}
