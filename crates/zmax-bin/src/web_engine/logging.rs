use super::context::ResolvedVHostContext;
use super::DEFAULT_LOG_MAX_BYTES;
use crate::api::ServerState;
use crate::modules_runtime::append_access_log_limit;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_and_log(
    state: &Arc<ServerState>,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    started: Instant,
    vhost_ctx: Option<&ResolvedVHostContext>,
    bytes_sent: usize,
    referer: Option<&str>,
    user_agent: Option<&str>,
    http_version: &str,
    req_id: &str,
) {
    let max_log_size_bytes = vhost_ctx
        .map(|v| v.max_log_size_bytes)
        .unwrap_or(DEFAULT_LOG_MAX_BYTES);
    // [kart-2] NCSA standardi: HEAD, 304, 204 veya 0 bayt gonderilen yanitlarda '-' yazilir; aksi halde gercek bayt.
    let is_zero_body =
        bytes_sent == 0 || status == 304 || status == 204 || method.eq_ignore_ascii_case("HEAD");
    let bytes_str = if is_zero_body {
        "-".to_string()
    } else {
        bytes_sent.to_string()
    };
    let actual_bytes = if is_zero_body { 0 } else { bytes_sent };
    let safe_path_owned = zmax_security::waf_events::redact_sensitive_url_target(path);
    let safe_path = if safe_path_owned.is_empty() {
        "/"
    } else {
        safe_path_owned.as_str()
    };
    state.record_access_log_detailed(
        ip,
        method,
        safe_path,
        status,
        started.elapsed(),
        actual_bytes,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );
    let line = format!(
        "{} - - \"{} {} {}\" {} {}\r\n",
        ip, method, safe_path, http_version, status, bytes_str
    );
    append_access_log_limit(&state.base_dir, &line, max_log_size_bytes).await;

    record_and_log_vhost(
        state,
        ip,
        method,
        safe_path,
        status,
        started,
        actual_bytes,
        referer,
        user_agent,
        http_version,
        req_id,
        vhost_ctx,
    )
    .await;
}

/// Alan adina ozel erisim ve hata gunlugu yazici (NCSA Combined, asenkron ve tamponlu).
pub async fn record_and_log_vhost(
    state: &Arc<ServerState>,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    started: Instant,
    bytes_sent: usize,
    referer: Option<&str>,
    user_agent: Option<&str>,
    http_version: &str,
    req_id: &str,
    vhost_ctx: Option<&ResolvedVHostContext>,
) {
    let elapsed = started.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    state.record_access_log_detailed(
        ip,
        method,
        path,
        status,
        elapsed,
        bytes_sent,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );

    let (domain, target_path, json_format, also_write_global, max_size) = match vhost_ctx {
        Some(ctx) => {
            let p = if ctx.logging.enabled && !ctx.logging.access_log.trim().is_empty() {
                Some(PathBuf::from(&ctx.logging.access_log))
            } else {
                None
            };
            (
                ctx.vhost_name.clone(),
                p,
                ctx.logging.format.eq_ignore_ascii_case("json"),
                ctx.logging.also_write_global,
                ctx.max_log_size_bytes,
            )
        }
        None => (
            "default".to_string(),
            None,
            false,
            true,
            DEFAULT_LOG_MAX_BYTES,
        ),
    };

    state.log_manager.log_access(crate::logger::AccessLogEntry {
        timestamp: std::time::SystemTime::now(),
        client_ip: ip.to_string(),
        method: method.to_string(),
        target: path.to_string(),
        protocol: http_version.to_string(),
        status,
        bytes_sent,
        referer: referer.unwrap_or("").to_string(),
        user_agent: user_agent.unwrap_or("").to_string(),
        request_id: req_id.to_string(),
        duration_ms,
        domain: domain.clone(),
        target_path,
        json_format,
        also_write_global,
        max_size_bytes: max_size,
    });
}
