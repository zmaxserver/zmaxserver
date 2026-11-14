use super::super::*;

pub(crate) async fn reload<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/reload" && req.method == "POST" {
        match reload_runtime_state(state).await {
            Ok(vhosts_count) => {
                state.cache.purge_all().await;
                let json = format!(
                    r#"{{"ok":true,"status":"reloaded","vhosts_loaded":{},"message":"Yapilandirma, moduller ve vHost tablosu sifir kesintiyle yenilendi."}}"#,
                    vhosts_count
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(e) => {
                let json = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &json)
                    .await?;
            }
        }
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn config<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/config" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let token_configured = !rt.auth.api_token.is_empty();
        let json = format!(
            r#"{{"ok":true,"server":{{"server_name":"{}","workers":{},"cpu_affinity":{}}},"listeners":{{"http":{{"enabled":{},"address":"{}","port":{},"reuse_port":{}}},"https":{{"enabled":{},"address":"{}","port":{},"ssl":{}}},"admin":{{"enabled":{},"address":"{}","port":{},"document_root":"{}","require_token":{},"ssl":{},"proxy_prefix":"{}"}},"api":{{"enabled":{},"address":"{}","port":{},"require_token":{},"token_configured":{},"unix_socket":"{}","ssl":{},"proxy_prefix":"{}"}}}},"cache":{{"enabled":{},"memory_cache_mb":{},"default_ttl_seconds":{}}},"security":{{"rate_limit_enabled":{},"rate_limit_per_minute":{},"keep_alive_timeout_sec":{},"block_path_traversal":{},"max_body_size_mb":{}}},"vhosts_dir":"{}"}}"#,
            json_escape(&cfg.server.server_name),
            cfg.server.workers,
            cfg.server.cpu_affinity,
            cfg.listeners.http.enabled,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            cfg.listeners.http.reuse_port,
            cfg.listeners.https.enabled,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            cfg.listeners.https.ssl,
            cfg.listeners.admin.enabled,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.admin.document_root),
            rt.auth.admin_require_token,
            cfg.listeners.admin.ssl,
            json_escape(&cfg.listeners.admin.proxy_prefix),
            cfg.listeners.api.enabled,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            rt.auth.api_require_token,
            token_configured,
            json_escape(&cfg.listeners.api.unix_socket),
            cfg.listeners.api.ssl,
            json_escape(&cfg.listeners.api.proxy_prefix),
            cfg.cache.enabled,
            cfg.cache.memory_cache_mb,
            cfg.cache.default_ttl_seconds,
            cfg.security.rate_limit_enabled,
            cfg.security.rate_limit_per_minute,
            cfg.security.keep_alive_timeout_sec,
            cfg.security.block_path_traversal,
            cfg.security.max_body_size_mb,
            json_escape(&cfg.vhosts_dir.path),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

