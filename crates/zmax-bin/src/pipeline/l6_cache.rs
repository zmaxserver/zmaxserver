//! L6 Onbellek: onbellek etiket/politika kararlari, onbellekten yanit yazimi ve PURGE yetki/isleme.

use crate::api::{constant_time_eq, ParsedHttpRequest, ServerState};
use crate::web_engine::http_write::{default_status_reason, write_http_response};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use zmax_cache::{parse_lscache_headers, CachedResponse};
use zmax_header::SecurityHeadersPolicy;
use zmax_httpparser::extract_header;

/// [kart-cache-1] Önbellek etiketlerine alan adı varyantlarını ve ham URI etiketlerini ekler.
#[inline]
pub(crate) fn append_domain_and_uri_cache_tags(tags: &mut Vec<String>, domain: &str, req_path: &str) {
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
pub(crate) async fn respect_request_cache_control(state: &Arc<ServerState>) -> bool {
    state
        .runtime
        .read()
        .await
        .config
        .cache
        .respect_request_cache_control
}

pub(crate) fn request_has_bypass_cookie_or_auth(
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

pub(crate) fn response_forbids_cache(headers: &[(String, String)]) -> bool {
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

#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_cached_php_response<S>(
    socket: &mut S,
    cached: &CachedResponse,
    wants_gzip: bool,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_ref: Option<&SecurityHeadersPolicy>,
    cache_label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let mut hdrs = vec![("Content-Type".into(), cached.content_type.clone())];
    if wants_gzip && cached.tags.iter().any(|t| t == "__enc:gzip") {
        hdrs.push(("Content-Encoding".into(), "gzip".into()));
        hdrs.push(("Vary".into(), "Accept-Encoding".into()));
    }
    write_http_response(
        socket,
        cached.status,
        default_status_reason(cached.status),
        &hdrs,
        &cached.body,
        None,
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_ref,
        Some(cache_label),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn write_cached_static_response<S>(
    socket: &mut S,
    cached: &CachedResponse,
    wants_gzip: bool,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_ref: Option<&SecurityHeadersPolicy>,
    cache_label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let mut hdrs = vec![
        ("Content-Type".into(), cached.content_type.clone()),
        ("Accept-Ranges".into(), "bytes".into()),
    ];
    if let Some(etag) = cached.tags.iter().find_map(|t| t.strip_prefix("__etag:")) {
        hdrs.push(("ETag".into(), etag.to_string()));
    }
    if let Some(lm) = cached.tags.iter().find_map(|t| t.strip_prefix("__lm:")) {
        hdrs.push(("Last-Modified".into(), lm.to_string()));
    }
    let has_gz = wants_gzip && cached.tags.iter().any(|t| t == "__enc:gzip");
    if has_gz {
        hdrs.push(("Content-Encoding".into(), "gzip".into()));
    }
    let has_vary_accept = cached.tags.iter().any(|t| t == "__vary:accept");
    match (has_gz, has_vary_accept) {
        (true, true) => hdrs.push(("Vary".into(), "Accept-Encoding, Accept".into())),
        (true, false) => hdrs.push(("Vary".into(), "Accept-Encoding".into())),
        (false, true) => hdrs.push(("Vary".into(), "Accept".into())),
        (false, false) => {}
    }
    write_http_response(
        socket,
        cached.status,
        default_status_reason(cached.status),
        &hdrs,
        &cached.body,
        None,
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_ref,
        Some(cache_label),
    )
    .await
}

/// `PURGE` isteği / `X-LiteSpeed-Purge` istek başlığı için yetki denetimi (HTTP/1.1 ve HTTP/2 ortak).
///
/// Özellik `[cache] purge_enabled = true` değilse KAPALIDIR. Açıkken istek ya `purge_key_header`
/// başlığında `purge_key` değerini (sabit zamanlı karşılaştırma) taşımalı ya da istemci IP'si
/// `purge_allow_ips` (IP/CIDR) listesinde olmalıdır; ikisi de yapılandırılmamışsa hiçbir istek yetkili değildir.
pub(crate) fn authorize_purge(
    cfg: &zmax_config::CacheConfig,
    headers: &[(String, String)],
    client_ip: IpAddr,
) -> bool {
    if !cfg.purge_enabled {
        return false;
    }
    if !cfg.purge_key.is_empty() {
        if let Some(given) = extract_header(headers, &cfg.purge_key_header) {
            if !given.is_empty() && constant_time_eq(given, &cfg.purge_key) {
                return true;
            }
        }
    }
    cfg.purge_allow_ips
        .iter()
        .any(|spec| zmax_security::ip_matches_cidr_spec(client_ip, spec.trim()))
}

/// Ortak PURGE isteği sonucu (HTTP/1.1 ve HTTP/2 aynı karar yolunu kullanır).
pub(crate) enum PurgeRequestOutcome {
    /// İstek PURGE değil; normal akış sürer.
    NotPurge,
    /// PURGE isteği yetkisiz: 403, önbellek değişmez.
    Forbidden,
    /// Yetkili PURGE yapıldı; gerçekte silinen girdi sayısı.
    Done(usize),
}

/// `PURGE` metodu veya `X-LiteSpeed-Purge` istek başlığını yetki denetiminden geçirip uygular.
pub(crate) async fn process_cache_purge_request(
    state: &Arc<ServerState>,
    vhost_name: &str,
    req: &ParsedHttpRequest,
    client_ip: IpAddr,
) -> PurgeRequestOutcome {
    let purge_header = extract_header(&req.headers, "x-litespeed-purge");
    if !req.method.eq_ignore_ascii_case("PURGE") && purge_header.is_none() {
        return PurgeRequestOutcome::NotPurge;
    }
    let allowed = {
        let rt = state.runtime.read().await;
        authorize_purge(&rt.config.cache, &req.headers, client_ip)
    };
    if !allowed {
        return PurgeRequestOutcome::Forbidden;
    }
    PurgeRequestOutcome::Done(
        handle_lscache_request_purge(state, vhost_name, &req.path, purge_header).await,
    )
}

/// Yetkili isteği vhost kapsamında uygular ve gerçekte silinen benzersiz girdi sayısını döner.
///
/// `X-LiteSpeed-Purge` varsa (`*` veya etiket listesi) yalnız bu vhost'un `alan::etiket` kayıtları silinir;
/// yoksa `PURGE <yol>` o vhost'un ilgili yolundaki girdileri siler (başka vhost etkilenmez).
async fn handle_lscache_request_purge(
    state: &Arc<ServerState>,
    vhost_name: &str,
    path: &str,
    purge_header: Option<&str>,
) -> usize {
    match purge_header {
        Some(hdr) => {
            let hdrs = [("x-litespeed-purge", hdr)];
            let directive = parse_lscache_headers(hdrs.iter().copied());
            state
                .cache
                .apply_lscache_purge(vhost_name, &directive)
                .await
        }
        None => state.cache.purge_by_domain_uri(vhost_name, path).await,
    }
}

/// PURGE sonucunu (durum, neden, govde) uretir; H1 ve H2 ayni metinleri kullanir.
pub(crate) fn purge_response_parts(outcome: PurgeRequestOutcome) -> (u16, &'static str, String) {
    match outcome {
        PurgeRequestOutcome::Done(n) => (200, "OK", format!("Purged {n} entries\n")),
        _ => (403, "Forbidden", "403 Forbidden\n".to_string()),
    }
}
