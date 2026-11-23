//! Panel yolu normalizasyonu, sorgu/yüzde-çözme yardımcıları ve API hız/ban koruması.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

tokio::task_local! {
    /// Gerçek ağ çağıranlarının kapsam içinde ayarladığı istemci IP'si (yoksa koruma atlanır).
    pub static ISTEMCI_IP: IpAddr;
}

fn istemci_ip() -> Option<IpAddr> {
    ISTEMCI_IP.try_with(|ip| *ip).ok().filter(|ip| !ip.is_loopback())
}

fn rate_limiter(limit: u32) -> &'static zmax_security::RateLimiter {
    static RL: OnceLock<zmax_security::RateLimiter> = OnceLock::new();
    RL.get_or_init(|| zmax_security::RateLimiter::new(limit))
}

fn basarisiz_sayac() -> &'static DashMap<IpAddr, (u32, Instant)> {
    static M: OnceLock<DashMap<IpAddr, (u32, Instant)>> = OnceLock::new();
    M.get_or_init(DashMap::new)
}

/// Rate limit + ban denetimi. Engellendiyse 429/403 yanıtı yazar ve `true` döner.
pub async fn api_koruma_engelle<S>(
    socket: &mut S,
    state: &Arc<crate::core::state::ServerState>,
    cors_origin: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let Some(ip) = istemci_ip() else { return Ok(false) };
    let (limit, ban_sec) = {
        let rt = state.runtime.read().await;
        (rt.config.security.api_rate_limit_per_minute, rt.config.security.auth_ban_sec)
    };
    if state.ban_manager.is_banned(ip) {
        let body = r#"{"ok":false,"error":"IP adresiniz gecici olarak engellendi."}"#;
        super::http::send_json_response_retry(socket, 403, "Forbidden", cors_origin, body, ban_sec).await?;
        return Ok(true);
    }
    if limit > 0 && !rate_limiter(limit).check_allowed(ip) {
        let body = r#"{"ok":false,"error":"Cok fazla istek: dakikadaki istek siniri asildi."}"#;
        super::http::send_json_response_retry(socket, 429, "Too Many Requests", cors_origin, body, 60).await?;
        return Ok(true);
    }
    Ok(false)
}

/// Başarısız kimlik doğrulamayı (401) sayar; eşik aşılırsa IP'yi banlar ve Redis'e yayınlar.
pub async fn kaydet_basarisiz(state: &Arc<crate::core::state::ServerState>) {
    let Some(ip) = istemci_ip() else { return };
    let (redis, limit, window, ban_sec) = {
        let rt = state.runtime.read().await;
        let s = &rt.config.security;
        (rt.redis_client.clone(), s.auth_fail_limit, s.auth_fail_window_sec, s.auth_ban_sec)
    };
    let now = Instant::now();
    let mut e = basarisiz_sayac().entry(ip).or_insert((0, now));
    if now.duration_since(e.1).as_secs() > window {
        *e = (0, now);
    }
    e.0 += 1;
    let asildi = limit > 0 && e.0 >= limit;
    drop(e);
    if asildi {
        basarisiz_sayac().remove(&ip);
        state.ban_manager.ban(ip, "API ardisik hatali kimlik dogrulama", ban_sec);
        crate::redis::publish_ban(redis.as_ref(), &ip.to_string(), ban_sec);
    }
}

pub(crate) fn percent_decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_query_param(query: &str, key: &str) -> Option<String> {
    let trimmed = query.strip_prefix('?').unwrap_or(query);
    if trimmed.is_empty() {
        return None;
    }
    for pair in trimmed.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if percent_decode_component(raw_k) == key {
            return Some(percent_decode_component(raw_v));
        }
    }
    None
}

/// Ters vekil arkasındaki panel/API isteklerinden yapılandırılmış `proxy_prefix` önekini soyar.
pub fn normalize_panel_request_path(raw_path: &str, proxy_prefix: &str) -> String {
    let prefix = proxy_prefix.trim().trim_end_matches('/');
    if prefix.is_empty() || prefix == "/" {
        return raw_path.to_string();
    }
    if raw_path == prefix {
        return "/".to_string();
    }
    if let Some(rest) = raw_path.strip_prefix(prefix) {
        if rest.is_empty() || rest == "/" {
            return "/".to_string();
        }
        if rest.starts_with('/') {
            return rest.to_string();
        }
    }
    raw_path.to_string()
}
