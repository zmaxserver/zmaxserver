//! Token doğrulama ve etkin auth token hesabı.

use super::*;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use zmax_config::{is_loopback_bind, ZMaxConfig};

pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `[listeners.api]` veya `[listeners.admin]` token doğrulaması (`Authorization: Bearer <token>` veya `X-ZMax-Token`).
pub fn is_authorized(req: &ParsedHttpRequest, expected_token: &str, require_token: bool) -> bool {
    if expected_token.is_empty() && !require_token {
        return true;
    }
    if expected_token.is_empty() && require_token {
        return false;
    }
    for (name, val) in &req.headers {
        if name.eq_ignore_ascii_case("authorization") {
            if let Some(bearer) = val
                .strip_prefix("Bearer ")
                .or_else(|| val.strip_prefix("bearer "))
            {
                if constant_time_eq(bearer.trim(), expected_token) {
                    return true;
                }
            }
        } else if name.eq_ignore_ascii_case("x-zmax-token")
            && constant_time_eq(val.trim(), expected_token)
        {
            return true;
        }
    }
    false
}

/// OS CSPRNG (`RandomState` / `BCryptGenRandom` / `getrandom`) tabanlı 256-bit rastgele API/Admin token üretir.
pub fn generate_secure_token() -> String {
    let mut hex = String::with_capacity(53);
    hex.push_str("zmax_");
    for round in 0..3u64 {
        let state = RandomState::new();
        let mut hasher = state.build_hasher();
        hasher.write_u64(round);
        hasher.write_u32(std::process::id());
        let val = hasher.finish();
        hex.push_str(&format!("{:016x}", val));
    }
    hex
}

#[derive(Debug, Clone)]
pub struct EffectiveAuthTokens {
    pub api_token: String,
    pub api_require_token: bool,
    pub admin_token: String,
    pub admin_require_token: bool,
    pub auto_generated_notices: Vec<String>,
}

/// `Admin` veya `API` loopback dışına (`0.0.0.0` vb.) bağlanıyorsa ve token tanımlı değilse
/// otomatik güçlü token üreterek yetkisiz erişimi engeller.
pub fn compute_effective_auth(config: &ZMaxConfig) -> EffectiveAuthTokens {
    let mut notices = Vec::new();

    let api_non_loopback = config.listeners.api.enabled && !is_loopback_bind(&config.listeners.api.address);
    let admin_non_loopback =
        config.listeners.admin.enabled && !is_loopback_bind(&config.listeners.admin.address);

    let configured_api_token = config.listeners.api.token.trim().to_string();
    let configured_admin_token = config.listeners.admin.token.trim().to_string();

    let mut api_token = configured_api_token.clone();
    let mut api_require_token = config.listeners.api.require_token || !api_token.is_empty();

    if api_non_loopback && (api_token.is_empty() || !api_require_token) {
        if api_token.is_empty() {
            api_token = generate_secure_token();
            notices.push(format!(
                "[GUVENLIK] API dinleyicisi loopback disi ({}) acildigi icin otomatik API token uretildi: {}",
                config.listeners.api.address, api_token
            ));
        } else {
            notices.push(format!(
                "[GUVENLIK] API dinleyicisi loopback disi ({}) acildigi icin token dogrulamasi zorunlu kilindi.",
                config.listeners.api.address
            ));
        }
        api_require_token = true;
    }

    let mut admin_token = if !configured_admin_token.is_empty() {
        configured_admin_token
    } else if !api_token.is_empty() {
        api_token.clone()
    } else {
        String::new()
    };
    let mut admin_require_token = config.listeners.admin.require_token || !admin_token.is_empty();

    if admin_non_loopback && (admin_token.is_empty() || !admin_require_token) {
        if admin_token.is_empty() {
            admin_token = generate_secure_token();
            notices.push(format!(
                "[GUVENLIK] WebAdmin dinleyicisi loopback disi ({}) acildigi icin otomatik Admin token uretildi: {}",
                config.listeners.admin.address, admin_token
            ));
        } else {
            notices.push(format!(
                "[GUVENLIK] WebAdmin dinleyicisi loopback disi ({}) acildigi icin token dogrulamasi zorunlu kilindi.",
                config.listeners.admin.address
            ));
        }
        admin_require_token = true;
    }

    EffectiveAuthTokens {
        api_token,
        api_require_token,
        admin_token,
        admin_require_token,
        auto_generated_notices: notices,
    }
}
