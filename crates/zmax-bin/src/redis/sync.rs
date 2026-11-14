use std::time::Duration;
use std::sync::OnceLock;
use zmax_config::LoadedModules;
use zmax_redis::{ClusterSyncEvent, ZMaxRedisClient};

/// Bu sürecin küme düğüm kimliği (kendi yayınını yok saymak için).
pub fn node_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{}-{:x}", std::process::id(), nanos)
    })
}

/// `mod_redis` içinden (ban eşitleme açık mı, ban süresi sn). Ayar yoksa (açık, 900).
pub fn ban_settings(modules: &LoadedModules) -> (bool, u64) {
    match modules.get("mod_redis") {
        Some(m) => (
            m.get_bool("banned_ip_sync").unwrap_or(true),
            m.get_u64("banned_ip_ttl_seconds").unwrap_or(900),
        ),
        None => (true, 900),
    }
}

fn spawn_event(redis: &ZMaxRedisClient, ev: ClusterSyncEvent) {
    let redis = redis.clone();
    tokio::spawn(async move {
        let _ = tokio::time::timeout(
            Duration::from_millis(250),
            redis.publish_event_from(node_id(), &ev),
        )
        .await;
    });
}

/// WP brute-force veya güvenlik ihlali nedeniyle bir IP adresini Redis kümesine yayınlar.
pub fn publish_ban(redis: Option<&ZMaxRedisClient>, ip: &str, ttl_secs: u64) {
    if let Some(redis) = redis {
        spawn_event(redis, ClusterSyncEvent::BanIp { ip: ip.to_string(), ttl_secs });
        let redis = redis.clone();
        let ip_s = ip.to_string();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(200),
                redis.ban_ip(&ip_s, ttl_secs),
            )
            .await;
        });
    }
}

/// Yasak kaldırma olayını kümeye yayınlar.
pub fn publish_unban(redis: Option<&ZMaxRedisClient>, ip: &str) {
    if let Some(redis) = redis {
        spawn_event(redis, ClusterSyncEvent::UnbanIp { ip: ip.to_string() });
    }
}

/// Yapılandırma yeniden yükleme olayını kümeye yayınlar.
pub fn publish_reload(redis: Option<&ZMaxRedisClient>) {
    if let Some(redis) = redis {
        spawn_event(redis, ClusterSyncEvent::ReloadConfig);
    }
}

/// Alan adı ve tekil etiket bazlı önbellek temizleme olayını Redis kümesine yayınlar.
pub fn publish_purge_tag(redis: Option<&ZMaxRedisClient>, domain: &str, tag: &str) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let ev = ClusterSyncEvent::PurgeTag {
            domain: domain.to_string(),
            tag: tag.to_string(),
        };
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                redis.publish_event_from(node_id(), &ev),
            )
            .await;
        });
    }
}

/// Alan adı ve çoklu etiket bazlı önbellek temizleme olayını Redis kümesine yayınlar.
pub fn publish_purge_tags(redis: Option<&ZMaxRedisClient>, domain: &str, tags: &[String]) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let d = domain.to_string();
        let t_list = tags.to_vec();
        tokio::spawn(async move {
            for t in t_list {
                let ev = ClusterSyncEvent::PurgeTag {
                    domain: d.clone(),
                    tag: t,
                };
                let _ = tokio::time::timeout(
                    Duration::from_millis(250),
                    redis.publish_event_from(node_id(), &ev),
                )
                .await;
            }
        });
    }
}

/// Ham etiket bazlı önbellek temizleme mesajını yayınlar.
pub fn publish_purge_raw_tag(redis: Option<&ZMaxRedisClient>, tag: &str) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let msg = format!("tag:{}", tag);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                redis.publish_purge(&msg),
            )
            .await;
        });
    }
}

/// Çoklu ham etiket önbellek temizleme mesajını yayınlar.
pub fn publish_purge_raw_tags(redis: Option<&ZMaxRedisClient>, tags: &[String]) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let t_list = tags.to_vec();
        tokio::spawn(async move {
            for t in t_list {
                let msg = format!("tag:{}", t);
                let _ = tokio::time::timeout(
                    Duration::from_millis(250),
                    redis.publish_purge(&msg),
                )
                .await;
            }
        });
    }
}

/// Belirli bir alan adına ait tüm önbellek temizleme olayını yayınlar.
pub fn publish_purge_domain(redis: Option<&ZMaxRedisClient>, domain: &str) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let ev = ClusterSyncEvent::PurgeDomain {
            domain: domain.to_string(),
        };
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                redis.publish_event_from(node_id(), &ev),
            )
            .await;
        });
    }
}

/// Alan adı ve URI bazlı önbellek temizleme mesajını yayınlar.
pub fn publish_purge_domain_uri(redis: Option<&ZMaxRedisClient>, domain: &str, uri: &str) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let msg = format!("{}:{}", domain, uri);
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                redis.publish_purge(&msg),
            )
            .await;
        });
    }
}

/// Belirli bir URI önbellek temizleme mesajını yayınlar.
pub fn publish_purge_uri(redis: Option<&ZMaxRedisClient>, uri: &str) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        let msg = uri.to_string();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                redis.publish_purge(&msg),
            )
            .await;
        });
    }
}

/// Tüm önbelleğin temizlendiğini bildiren olayı yayınlar.
pub fn publish_purge_all(redis: Option<&ZMaxRedisClient>) {
    if let Some(redis) = redis {
        let redis = redis.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_millis(250),
                redis.publish_event_from(node_id(), &ClusterSyncEvent::PurgeAll),
            )
            .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_none_safety() {
        // Redis kapalı/None iken fonksiyonlar hata fırlatmadan ve bloklamadan tamamlanmalıdır.
        publish_ban(None, "127.0.0.1", 900);
        publish_purge_tag(None, "example.com", "post-1");
        publish_purge_tags(None, "example.com", &["post-1".to_string()]);
        publish_purge_raw_tag(None, "post-1");
        publish_purge_raw_tags(None, &["post-1".to_string()]);
        publish_purge_domain(None, "example.com");
        publish_purge_domain_uri(None, "example.com", "/index.php");
        publish_purge_uri(None, "/index.php");
        publish_purge_all(None);
        publish_unban(None, "127.0.0.1");
        publish_reload(None);
    }
}
