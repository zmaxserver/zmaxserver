//! Rust ↔ Go köprüsü (B2): `/api/v1/version`, `/api/v1/config/validate`, `/api/v1/events` (SSE).
//! Sözleşme: `katmanlizmax/go/contract/openapi.yaml` (alan adları Go `models.go` ile birebir).
use super::*;
use std::sync::OnceLock;
use tokio::sync::broadcast;

pub const CONTRACT_VERSION: &str = "1.0";

const FEATURES: &[&str] = &["version", "health", "config_validate", "reload_generation", "events_sse"];

static BUS: OnceLock<broadcast::Sender<String>> = OnceLock::new();

fn bus() -> &'static broadcast::Sender<String> {
    BUS.get_or_init(|| broadcast::channel(256).0)
}

/// Köprü olayı yayınlar (dinleyen yoksa sessizce düşer). `data_json` geçerli JSON nesnesi olmalı.
pub fn emit(event: &str, data_json: &str) {
    let _ = bus().send(format!("event: {}\ndata: {}\n\n", event, data_json));
}

fn line_of(src: &str, offset: usize) -> usize {
    src.as_bytes()[..offset.min(src.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count()
        + 1
}

fn field_of(msg: &str) -> String {
    let mut parts = msg.split('`');
    parts.next();
    parts.next().unwrap_or("").to_string()
}

pub(crate) async fn handle<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    _state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/version" && req.method == "GET" {
        let feats: Vec<String> = FEATURES.iter().map(|f| format!("\"{}\"", f)).collect();
        let json = format!(
            r#"{{"server_version":"{}","contract_version":"{}","supported_features":[{}]}}"#,
            env!("ZMAX_VERSION"),
            CONTRACT_VERSION,
            feats.join(",")
        );
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if req_path == "/api/v1/config/validate" && req.method == "POST" {
        let body: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(_) => {
                let err = r#"{"valid":false,"message":"Gecersiz JSON govdesi"}"#;
                send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
                return Ok(true);
            }
        };
        let content = body.get("toml_content").and_then(|v| v.as_str()).unwrap_or("");
        if content.is_empty() {
            let err = r#"{"valid":false,"message":"toml_content gerekli"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        }
        let json = match toml::from_str::<zmax_config::VHostFileDocument>(content) {
            Ok(_) => r#"{"valid":true}"#.to_string(),
            Err(e) => {
                let line = e.span().map(|s| line_of(content, s.start)).unwrap_or(0);
                let msg = e.message().to_string();
                let mut obj = serde_json::json!({"valid": false, "message": msg, "error_field": field_of(&msg)});
                if line > 0 {
                    obj["error_line"] = serde_json::json!(line);
                }
                obj.to_string()
            }
        };
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if req_path == "/api/v1/events" && req.method == "GET" {
        let mut rx = bus().subscribe();
        let origin = if cors_origin.is_empty() { "*" } else { cors_origin.as_str() };
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: {}\r\nConnection: close\r\n\r\n: ok\n\n",
            origin
        );
        socket.write_all(head.as_bytes()).await?;
        socket.flush().await?;
        loop {
            let chunk = match tokio::time::timeout(Duration::from_secs(15), rx.recv()).await {
                Ok(Ok(m)) => m,
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(_)) => break,
                Err(_) => ": ping\n\n".to_string(),
            };
            if socket.write_all(chunk.as_bytes()).await.is_err() || socket.flush().await.is_err() {
                break;
            }
        }
        return Ok(true);
    }
    Ok(false)
}
