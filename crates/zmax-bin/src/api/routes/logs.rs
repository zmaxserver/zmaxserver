use super::super::*;

pub(super) async fn logs_get<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/logs" && req.method == "GET" {
        let domain_q = parse_query_param(&req.query, "domain")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let kind_q = parse_query_param(&req.query, "kind")
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let lines_q =
            parse_query_param(&req.query, "lines").and_then(|s| s.trim().parse::<usize>().ok());

        if domain_q.is_some() || kind_q.as_deref() == Some("error") {
            let kind = kind_q.unwrap_or_else(|| "access".to_string());
            if kind != "access" && kind != "error" {
                let err = r#"{"ok":false,"error":"Gecersiz kind parametresi (access veya error olmali)"}"#;
                send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
                return Ok(true);
            }
            let limit = lines_q.unwrap_or(100).min(5000);

            let (resolved_domain, target_path) = if let Some(raw_domain) = domain_q {
                let domain = match validate_domain(&raw_domain) {
                    Ok(d) => d,
                    Err(msg) => {
                        let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                        send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                        return Ok(true);
                    }
                };

                let rt = state.runtime.read().await;
                let found = rt.vhosts.iter().find(|v| {
                    v.entry.name.eq_ignore_ascii_case(&domain)
                        || v.entry
                            .aliases
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(&domain))
                });
                let vhost = match found {
                    Some(v) => v,
                    None => {
                        let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
                        send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
                        return Ok(true);
                    }
                };

                let raw_rel = if kind == "error" {
                    vhost.entry.logging.error_log.trim()
                } else {
                    vhost.entry.logging.access_log.trim()
                };
                let path = if !raw_rel.is_empty() {
                    resolve_path(&state.base_dir, raw_rel)
                } else {
                    let per_vhost = resolve_path(
                        &state.base_dir,
                        &format!("logs/{}.{}.log", vhost.entry.name, kind),
                    );
                    if per_vhost.exists() {
                        per_vhost
                    } else {
                        let global_rel = if kind == "error" {
                            if rt.config.logging.error_log.trim().is_empty() {
                                "logs/error.log"
                            } else {
                                rt.config.logging.error_log.trim()
                            }
                        } else if rt.config.logging.access_log.trim().is_empty() {
                            "logs/access.log"
                        } else {
                            rt.config.logging.access_log.trim()
                        };
                        resolve_path(&state.base_dir, global_rel)
                    }
                };
                (Some(vhost.entry.name.clone()), path)
            } else {
                let rt = state.runtime.read().await;
                let global_rel = if rt.config.logging.error_log.trim().is_empty() {
                    "logs/error.log"
                } else {
                    rt.config.logging.error_log.trim()
                };
                (None, resolve_path(&state.base_dir, global_rel))
            };

            state.log_manager.flush().await;
            let tail_lines = match state.log_manager.read_tail_lines(&target_path, limit).await {
                Ok(lines) => lines,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("Log dosyasi okunamadi: {}", e)
                    })
                    .to_string();
                    send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err)
                        .await?;
                    return Ok(true);
                }
            };

            let json = serde_json::json!({
                "ok": true,
                "domain": resolved_domain,
                "kind": kind,
                "path": target_path.to_string_lossy(),
                "count": tail_lines.len(),
                "lines": tail_lines,
                "logs": tail_lines
            })
            .to_string();
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        }

        let snapshot: Vec<AccessLogRecord> = state
            .access_logs
            .lock()
            .map(|q| {
                let take_n = lines_q
                    .unwrap_or(MAX_IN_MEMORY_LOGS)
                    .min(MAX_IN_MEMORY_LOGS);
                q.iter().take(take_n).cloned().collect()
            })
            .unwrap_or_default();
        let items: Vec<serde_json::Value> = snapshot
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "time": entry.time,
                    "ip": entry.ip,
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                    "latency": entry.latency,
                    "bytes_sent": entry.bytes_sent,
                    "request_id": entry.request_id,
                    "domain": entry.domain
                })
            })
            .collect();
        let json = serde_json::json!({
            "ok": true,
            "kind": "access",
            "count": items.len(),
            "logs": items
        })
        .to_string();
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn logs_reopen<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/logs/reopen" && req.method == "POST"
    {
        state.log_manager.reopen_all().await;
        let dropped = state.log_manager.dropped_count();
        let json = serde_json::json!({
            "ok": true,
            "status": "reopened",
            "dropped": dropped,
            "message": "Tum log dosyalari flush edildi ve yeniden acilmak uzere serbest birakildi."
        })
        .to_string();
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn handle<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if logs_get(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if logs_reopen(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    Ok(false)
}

