use std::sync::Arc;
use crate::core::state::ServerState;

/// SIGHUP ve SIGUSR1 sinyal dinleyicilerini başlatır.
#[allow(unused_variables)]
pub fn spawn_signal_handlers(state: Arc<ServerState>) {
    #[cfg(unix)]
    {
        use crate::modules_runtime::append_error_log;

        let state_sighup = Arc::clone(&state);
        tokio::spawn(async move {
            if let Ok(mut sighup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            {
                while sighup.recv().await.is_some() {
                    match crate::api::reload_runtime_state(&state_sighup).await {
                        Ok(vhost_count) => {
                            state_sighup.cache.purge_all().await;
                            println!(
                                "[Yeniden Yuklendi] SIGHUP alindi -> {} sanal konak ve yapilandirma yenilendi.",
                                vhost_count
                            );
                        }
                        Err(err) => {
                            eprintln!("[SIGHUP Hata] Yeniden yukleme basarisiz: {}", err);
                            append_error_log(
                                &state_sighup.base_dir,
                                &format!("[SIGHUP Hata] {}", err),
                            )
                            .await;
                        }
                    }
                }
            }
        });

        let state_sigusr1 = Arc::clone(&state);
        tokio::spawn(async move {
            if let Ok(mut sigusr1) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            {
                while sigusr1.recv().await.is_some() {
                    state_sigusr1.log_manager.reopen_all().await;
                    println!("[LOG] SIGUSR1 alindi -> Gunluk dosyalari yeniden acildi.");
                }
            }
        });
    }

    #[cfg(not(unix))]
    {
        let _ = state;
    }
}
