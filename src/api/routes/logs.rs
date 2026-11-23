use super::super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::broadcast::error::RecvError;

/// Aynı anda izin verilen en fazla SSE log akışı.
const MAX_LOG_STREAMS: usize = 20;
const KEEPALIVE_SECS: u64 = 15;
static ACTIVE_LOG_STREAMS: AtomicUsize = AtomicUsize::new(0);

struct StreamSlot;
impl StreamSlot {
    fn acquire() -> Option<Self> {
        let prev = ACTIVE_LOG_STREAMS.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_LOG_STREAMS {
            ACTIVE_LOG_STREAMS.fetch_sub(1, Ordering::AcqRel);
            None
        } else {
            Some(StreamSlot)
        }
    }
}
impl Drop for StreamSlot {
    fn drop(&mut self) {
        ACTIVE_LOG_STREAMS.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `GET /api/v1/logs/stream`: canlı günlük satırlarını Server-Sent Events olarak akıtır.
pub(super) async fn logs_stream<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path != "/api/v1/logs/stream" || req.method != "GET" {
        return Ok(false);
    }
    let domain_q = parse_query_param(&req.query, "domain")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    let type_q = parse_query_param(&req.query, "type")
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());
    if let Some(t) = type_q.as_deref() {
        if t != "access" && t != "error" {
            let err = r#"{"ok":false,"error":"Gecersiz type parametresi (access veya error olmali)"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        }
    }
    let Some(_slot) = StreamSlot::acquire() else {
        let err = r#"{"ok":false,"error":"Cok fazla eszamanli log akisi (en fazla 20)"}"#;
        send_json_response(socket, 503, "Service Unavailable", cors_origin, err).await?;
        return Ok(true);
    };

    let origin = if cors_origin.is_empty() { "*" } else { cors_origin.as_str() };
    let head = format!(
        "HTTP/1.1 200 OK
Content-Type: text/event-stream; charset=utf-8
Cache-Control: no-cache
Connection: close
X-Accel-Buffering: no
Access-Control-Allow-Origin: {}

: connected

",
        origin
    );
    socket.write_all(head.as_bytes()).await?;
    socket.flush().await?;

    let mut rx = state.log_manager.subscribe_live();
    let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await;

    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(item) => {
                    if let Some(t) = type_q.as_deref() {
                        if item.kind != t { continue; }
                    }
                    if let Some(d) = domain_q.as_deref() {
                        if !item.domain.eq_ignore_ascii_case(d) { continue; }
                    }
                    let frame = format!("data: {}\n\n", item.line.replace(['\r', '\n'], " "));
                    if socket.write_all(frame.as_bytes()).await.is_err() || socket.flush().await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => state.log_manager.add_live_dropped(n),
                Err(RecvError::Closed) => break,
            },
            _ = keepalive.tick() => {
                if socket.write_all(b": keepalive\n\n").await.is_err() || socket.flush().await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(true)
}

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
    if logs_stream(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if logs_get(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if logs_reopen(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    Ok(false)
}

