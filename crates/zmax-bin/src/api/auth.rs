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

/// Istek rolu: `Admin` = yonetim tokeni, `Read` = yalniz okuma tokeni.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRole {
    Admin,
    Read,
}

/// Token dogrulama sonucu rol; `None` = 401 (token yok/yanlis). 403 cagiran tarafta verilir.
pub fn authorize_role(
    req: &ParsedHttpRequest,
    expected_token: &str,
    read_token: &str,
    require_token: bool,
    local: bool,
) -> Option<AuthRole> {
    if expected_token.is_empty() {
        // Token yok: yalniz loopback kaynakli istek gecer; require_token aciksa hic gecmez.
        return if local && !require_token { Some(AuthRole::Admin) } else { None };
    }
    let mut role = None;
    let mut check = |cand: &str| {
        if constant_time_eq(cand, expected_token) {
            role = Some(AuthRole::Admin);
        } else if !read_token.is_empty() && constant_time_eq(cand, read_token) && role.is_none() {
            role = Some(AuthRole::Read);
        }
    };
    for (name, val) in &req.headers {
        if name.eq_ignore_ascii_case("authorization") {
            if let Some(bearer) = val
                .strip_prefix("Bearer ")
                .or_else(|| val.strip_prefix("bearer "))
            {
                check(bearer.trim());
            }
        } else if name.eq_ignore_ascii_case("x-zmax-token") {
            check(val.trim());
        }
    }
    role
}

/// `[listeners.api]` / `[listeners.admin]` yonetim rolu dogrulamasi; token bossa yalniz loopback gecer.
pub fn is_authorized(
    req: &ParsedHttpRequest,
    expected_token: &str,
    require_token: bool,
    local: bool,
) -> bool {
    authorize_role(req, expected_token, "", require_token, local) == Some(AuthRole::Admin)
}

/// Okuma rolunun erisebildigi uclar: yalniz GET/HEAD ve salt-okunur yollar.
pub fn read_role_allowed(method: &str, path: &str) -> bool {
    if !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) {
        return false;
    }
    let p = path.trim_end_matches('/');
    let p = p.strip_prefix("/api/v1").or_else(|| p.strip_prefix("/api")).unwrap_or(p);
    matches!(
        p,
        "/status" | "/metrics" | "/health" | "/logs" | "/vhosts" | "/ports" | "/config" | "/version"
    )
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
    pub api_read_token: String,
    pub admin_read_token: String,
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
                "[GUVENLIK] WebAdmin dinleyicisi loopback disi ({}) acildigi icin otomatik Admin token uretildi (degeri gunluge yazilmaz; kalici token icin zmax.toml [listeners.admin] token tanimlayin).",
                config.listeners.admin.address
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
        api_read_token: config.listeners.api.read_token.trim().to_string(),
        admin_read_token: {
            let r = config.listeners.admin.read_token.trim();
            if r.is_empty() { config.listeners.api.read_token.trim().to_string() } else { r.to_string() }
        },
        admin_token,
        admin_require_token,
        auto_generated_notices: notices,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("secret123", "secret123"));
        assert!(!constant_time_eq("secret123", "secret124"));
        assert!(!constant_time_eq("secret", "secret123"));
    }

    #[test]
    fn test_is_authorized() {
        let req = ParsedHttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/status".to_string(),
            query: String::new(),
            version: 1,
            host: "127.0.0.1".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer my-secret-token".to_string())],
            body: Vec::new(),
            keep_alive: false,
        };
        assert!(is_authorized(&req, "my-secret-token", true, false));
        assert!(!is_authorized(&req, "wrong-token", true, false));
        assert!(is_authorized(&req, "", false, true));
        assert!(!is_authorized(&req, "", false, false));
    }

    #[test]
    fn test_compute_effective_auth_preserves_tokens_and_auto_generates() {
        // 1. Yapılandırılmış token korunmalı
        let mut cfg = ZMaxConfig::default();
        cfg.listeners.api.token = "my-custom-api-token".to_string();
        cfg.listeners.admin.token = "my-custom-admin-token".to_string();
        let auth = compute_effective_auth(&cfg);
        assert_eq!(auth.api_token, "my-custom-api-token");
        assert_eq!(auth.admin_token, "my-custom-admin-token");
        assert!(auth.api_require_token);
        assert!(auth.admin_require_token);

        // 2. Loopback dışı bağlandığında token boşsa otomatik güvenli token üretilmeli
        let mut cfg_remote = ZMaxConfig::default();
        cfg_remote.listeners.api.enabled = true;
        cfg_remote.listeners.api.address = "0.0.0.0".to_string();
        cfg_remote.listeners.api.token = "".to_string();
        let auth_remote = compute_effective_auth(&cfg_remote);
        assert!(!auth_remote.api_token.is_empty());
        assert!(auth_remote.api_token.starts_with("zmax_"));
        assert!(auth_remote.api_require_token);
        assert!(!auth_remote.auto_generated_notices.is_empty());
    }
}
