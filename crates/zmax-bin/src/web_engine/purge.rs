use crate::api::{ParsedHttpRequest, ServerState};
use std::net::IpAddr;
use std::sync::Arc;
use zmax_cache::parse_lscache_headers;
use zmax_httpparser::extract_header;

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
            if !given.is_empty() && crate::api::constant_time_eq(given, &cfg.purge_key) {
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
