//! K3: doğrula→uygula yeniden yükleme (reload) ve TLS sertifika yenileme.

use crate::api::ServerState;
use crate::api::compute_effective_auth;
use crate::modules_runtime::{append_error_log, build_redis_client, compile_policies};
use std::path::Path;
use std::sync::Arc;
use zmax_config::{load_vhosts_dir, resolve_path, LoadedModules, LoadedVHost, ZMaxConfig};

/// vhost tablosundaki sertifikaları SNI çözümleyicisine yükler; atlananları logs/error.log'a yazar.
pub async fn refresh_tls_certs(
    resolver: &zmax_tls::SniResolver,
    vhosts: &[LoadedVHost],
    base_dir: &Path,
) -> usize {
    let sources = zmax_tls::sources_from_vhosts(vhosts, base_dir);
    let report = resolver.replace(&sources);
    for sk in &report.skipped {
        let line = format!("[TLS] vhost atlandi ({}): {}", sk.label, sk.reason);
        eprintln!("{}", line);
        append_error_log(base_dir, &line).await;
    }
    report.loaded
}

/// HTTPS dinleyicisinin etkin ALPN protokol bayt dizilerini (`["h2", "http/1.1"]` vb.) döndürür.
pub fn current_https_alpn_protocols(config: &ZMaxConfig) -> Vec<Vec<u8>> {
    zmax_tls::parse_alpn_list(&config.listeners.https.alpn)
}

/// Tekil bir dinleyicinin (panel veya API) TLS sertifikasını `SniResolver` üzerine yükler/günceller.
pub async fn refresh_listener_tls_cert(
    resolver: &zmax_tls::SniResolver,
    label: &str,
    ssl_enabled: bool,
    tls_cert: &str,
    tls_key: &str,
    base_dir: &Path,
) -> usize {
    let cert_trimmed = tls_cert.trim();
    let key_trimmed = tls_key.trim();
    if !ssl_enabled || cert_trimmed.is_empty() || key_trimmed.is_empty() {
        let _ = resolver.replace(&[]);
        return 0;
    }
    let sources = [zmax_tls::CertSource {
        label: label.to_string(),
        names: Vec::new(),
        cert_path: resolve_path(base_dir, cert_trimmed),
        key_path: resolve_path(base_dir, key_trimmed),
    }];
    let report = resolver.replace(&sources);
    for sk in &report.skipped {
        let line = format!(
            "[TLS] {} dinleyici sertifikasi atlandi ({}): {}",
            label, sk.label, sk.reason
        );
        eprintln!("{}", line);
        append_error_log(base_dir, &line).await;
    }
    report.loaded
}

/// Diskten `conf/zmax.toml`, `conf/vhosts/*.toml` ve `modules/mod_*.toml` dosyalarını atomik olarak yeniler
/// ve güncel HTTPS ALPN protokol listesini de döndürür.
pub async fn reload_runtime_state_with_alpn(
    state: &Arc<ServerState>,
) -> Result<(usize, Vec<Vec<u8>>), String> {
    let (conf_path, old_vhosts_dir, modules_dir) = {
        let rt = state.runtime.read().await;
        (
            rt.conf_path.clone(),
            rt.vhosts_dir.clone(),
            rt.modules_dir.clone(),
        )
    };

    let new_cfg = ZMaxConfig::load_or_default(&conf_path)?;
    let resolved_vhosts_dir = if new_cfg.vhosts_dir.path.trim().is_empty() {
        old_vhosts_dir
    } else {
        resolve_path(&state.base_dir, &new_cfg.vhosts_dir.path)
    };
    let loaded_vhosts = load_vhosts_dir(&resolved_vhosts_dir, &state.base_dir)?;
    let loaded_modules = LoadedModules::load_from_dir(&modules_dir)?;
    let _ = new_cfg.validate_workspace_layout(&state.base_dir, &loaded_vhosts, &loaded_modules)?;
    let policies = compile_policies(&new_cfg, &loaded_modules);
    let redis_client = build_redis_client(&loaded_modules);
    let auth = compute_effective_auth(&new_cfg);
    for notice in &auth.auto_generated_notices {
        eprintln!("{}", notice);
        append_error_log(&state.base_dir, notice).await;
    }

    let vhost_count = loaded_vhosts.len();
    let new_admin_dir = resolve_path(&state.base_dir, &new_cfg.listeners.admin.document_root);
    let access_log_rel = if new_cfg.logging.access_log.trim().is_empty() {
        "logs/access.log"
    } else {
        new_cfg.logging.access_log.trim()
    };
    let error_log_rel = if new_cfg.logging.error_log.trim().is_empty() {
        "logs/error.log"
    } else {
        new_cfg.logging.error_log.trim()
    };
    let global_access_log = resolve_path(&state.base_dir, access_log_rel);
    let global_error_log = resolve_path(&state.base_dir, error_log_rel);
    let alpn_protocols = current_https_alpn_protocols(&new_cfg);

    {
        let mut limiter = state.limiter.write().await;
        *limiter = zmax_security::RateLimiter::new(policies.effective_rate_limit);
    }
    {
        let mut admin_handler = state.admin_static_handler.write().await;
        *admin_handler = zmax_static::StaticFileHandler::new(new_admin_dir);
    }

    state
        .log_manager
        .update_global_paths(global_access_log, global_error_log)
        .await;
    state.htaccess_resolver.clear_cache();
    crate::config::acme::apply_global_acme_root(&new_cfg, &state.base_dir);

    refresh_tls_certs(&state.tls, &loaded_vhosts, &state.base_dir).await;
    refresh_listener_tls_cert(
        &state.admin_tls,
        "admin",
        new_cfg.listeners.admin.ssl,
        &new_cfg.listeners.admin.tls_cert,
        &new_cfg.listeners.admin.tls_key,
        &state.base_dir,
    )
    .await;
    refresh_listener_tls_cert(
        &state.api_tls,
        "api",
        new_cfg.listeners.api.ssl,
        &new_cfg.listeners.api.tls_cert,
        &new_cfg.listeners.api.tls_key,
        &state.base_dir,
    )
    .await;

    {
        let mut rt = state.runtime.write().await;
        rt.config = new_cfg;
        rt.vhosts = loaded_vhosts;
        rt.modules = loaded_modules;
        rt.policies = policies;
        rt.redis_client = redis_client;
        rt.auth = auth;
        rt.vhosts_dir = resolved_vhosts_dir;
    }

    // [ek-dinleyici] ek dinleyicileri yeni yapılandırmayla uzlaştır (hata reload'u bozmaz; günlüğe yazılır)
    let _ = crate::web_engine::reconcile_extra_listeners(state).await;

    Ok((vhost_count, alpn_protocols))
}

/// Diskten `conf/zmax.toml`, `conf/vhosts/*.toml` ve `modules/mod_*.toml` dosyalarını atomik olarak yeniler.
pub async fn reload_runtime_state(state: &Arc<ServerState>) -> Result<usize, String> {
    reload_runtime_state_with_alpn(state)
        .await
        .map(|(count, _)| count)
}
