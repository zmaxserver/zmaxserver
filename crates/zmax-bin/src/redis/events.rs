pub use zmax_redis::ClusterSyncEvent;

use crate::api::ServerState;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Kendi düğümünden gelen olay mı (döngü önleme)?
pub fn is_own_event(origin: &Option<String>) -> bool {
    origin.as_deref() == Some(super::sync::node_id())
}

async fn apply_event(state: &Arc<ServerState>, ev: ClusterSyncEvent, ban_sync: bool) {
    match ev {
        ClusterSyncEvent::BanIp { ip, ttl_secs } => {
            if ban_sync {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    state.ban_manager.ban(ip, "cluster-sync", ttl_secs);
                }
            }
        }
        ClusterSyncEvent::UnbanIp { ip } => {
            if ban_sync {
                if let Ok(ip) = ip.parse::<IpAddr>() {
                    state.ban_manager.unban(ip);
                    state.wp_guard.reset(ip);
                }
            }
        }
        ClusterSyncEvent::PurgeDomain { domain } => {
            state.cache.purge_by_domain(&domain).await;
        }
        ClusterSyncEvent::PurgeTag { domain, tag } => {
            state.cache.purge_by_domain_tag(&domain, &tag).await;
        }
        ClusterSyncEvent::PurgeAll => {
            state.cache.purge_all().await;
        }
        ClusterSyncEvent::ReloadConfig => {
            if crate::api::reload_runtime_state(state).await.is_ok() {
                state.cache.purge_all().await;
            }
        }
    }
}

fn config_key(c: &zmax_redis::RedisConfig) -> (String, String, Option<String>, Option<String>) {
    (c.effective_addr(), c.effective_events_channel(), c.username.clone(), c.password.clone())
}

/// Redis abone görevi: kapanma sinyaliyle sonlanır; Redis yoksa/erişilemezse sessizce yeniden dener.
pub fn spawn_subscriber(state: Arc<ServerState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutdown = state.shutdown.subscribe();
        loop {
            if *shutdown.borrow() {
                return;
            }
            let (client, ban_sync) = {
                let rt = state.runtime.read().await;
                (rt.redis_client.clone(), super::sync::ban_settings(&rt.modules).0)
            };
            let Some(client) = client else {
                tokio::select! {
                    _ = shutdown.changed() => {}
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                }
                continue;
            };
            let key = config_key(client.config());
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            let (tx, mut rx) = tokio::sync::mpsc::channel::<ClusterSyncEvent>(256);
            let sub_client = client.clone();
            let sub = tokio::spawn(async move {
                let _ = sub_client
                    .subscribe_events_origin(stop_rx, move |origin, ev| {
                        if !is_own_event(&origin) {
                            let _ = tx.try_send(ev);
                        }
                    })
                    .await;
            });
            let mut tick = tokio::time::interval(Duration::from_secs(30));
            tick.tick().await;
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() { break; }
                    }
                    Some(ev) = rx.recv() => apply_event(&state, ev, ban_sync).await,
                    _ = tick.tick() => {
                        let cur = state.runtime.read().await.redis_client.as_ref().map(|c| config_key(c.config()));
                        if cur.as_ref() != Some(&key) { break; }
                    }
                }
            }
            let _ = stop_tx.send(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), sub).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_events_reexport() {
        let ev = ClusterSyncEvent::PurgeAll;
        assert_eq!(ev.to_wire_string(), "purge:*");
    }

    #[test]
    fn test_own_event_ignored() {
        let id = super::super::sync::node_id().to_string();
        assert!(is_own_event(&Some(id)));
        assert!(!is_own_event(&None));
        assert!(!is_own_event(&Some("baska".into())));
    }
}
