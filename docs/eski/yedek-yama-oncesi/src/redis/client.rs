use zmax_config::LoadedModules;
use zmax_redis::{RedisConfig, ZMaxRedisClient};

/// İstek bazlı `mod_redis` istemcisi oluşturur (`mod_redis` etkinse).
pub fn build_redis_client(modules: &LoadedModules) -> Option<ZMaxRedisClient> {
    let m = modules.get("mod_redis")?;
    if !m.is_enabled() {
        return None;
    }
    let host = m.get_str("host").unwrap_or("127.0.0.1").to_string();
    let port = m.get_u64("port").unwrap_or(6379) as u16;
    let addr = m
        .get_str("addr")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{host}:{port}"));
    let database = m.get_u64("database").unwrap_or(0) as u8;
    let db = m.get_u64("db").unwrap_or(u64::from(database)) as u8;
    let cfg = RedisConfig {
        host,
        port,
        addr,
        username: m
            .get_str("username")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        password: m
            .get_str("password")
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string()),
        database,
        db,
        timeout_ms: m.get_u64("timeout_ms").unwrap_or(100),
        pubsub_channel: m
            .get_str("pubsub_channel")
            .unwrap_or("zmax:cache:purge")
            .to_string(),
        channel_prefix: m
            .get_str("channel_prefix")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("zmax")
            .to_string(),
        reconnect_backoff_ms: m.get_u64("reconnect_backoff_ms").unwrap_or(500),
    };
    Some(ZMaxRedisClient::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_redis_client_empty_modules() {
        let modules = LoadedModules::default();
        assert!(build_redis_client(&modules).is_none());
    }
}
