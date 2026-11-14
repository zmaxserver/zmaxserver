use std::sync::Arc;
use std::time::Duration;
use crate::core::state::ServerState;

/// Arka plan bellek, havuz ve güvenlik bakım görevini başlatır.
pub fn spawn_background_tasks(state: Arc<ServerState>) {
    let maint_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let _ = maint_state.upstream_pool.purge_expired();
            let _ = maint_state.limiter.read().await.purge_expired();
            let _ = maint_state.ban_manager.list_banned();
        }
    });
}
