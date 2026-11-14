use super::super::*;

pub(crate) fn classify_ban_reason_key(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("slowloris") {
        "reason_slowloris"
    } else if lower.contains("rate") || lower.contains("limit") {
        "reason_ratelimit"
    } else if lower.contains("brute") || lower.contains("wp-login") || lower.contains("xmlrpc") {
        "reason_bruteforce"
    } else {
        "reason_waf"
    }
}

pub(crate) async fn bans<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if (req_path == "/api/v1/security/bans" || req_path == "/api/security/bans")
        && req.method == "GET"
    {
        let now_hms = current_hms_utc();
        let bans = state.ban_manager.list_banned();
        let items: Vec<String> = bans
            .iter()
            .map(|b| {
                let reason_key = classify_ban_reason_key(&b.reason);
                let rem_json = match b.remaining_secs {
                    Some(s) => s.to_string(),
                    None => "null".to_string(),
                };
                format!(
                    r#"{{"ip":"{}","reasonKey":"{}","reason":"{}","permanent":{},"remaining_secs":{},"time":"{}"}}"#,
                    json_escape(&b.ip.to_string()),
                    reason_key,
                    json_escape(&b.reason),
                    b.permanent,
                    rem_json,
                    now_hms
                )
            })
            .collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"bans":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn unban<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if (req_path == "/api/v1/security/unban" || req_path == "/api/security/unban")
        && req.method == "POST"
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_ip = extract_json_string(&body_str, "ip").unwrap_or_default();
        let Ok(ip) = raw_ip.trim().parse::<IpAddr>() else {
            let err = r#"{"ok":false,"error":"Gecersiz IP adresi."}"#;
            send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
            return Ok(true);
        };
        let existed = state.ban_manager.unban(ip);
        state.wp_guard.reset(ip);
        {
            let rt = state.runtime.read().await;
            if crate::redis::ban_settings(&rt.modules).0 {
                crate::redis::publish_unban(rt.redis_client.as_ref(), &ip.to_string());
            }
        }
        let json = format!(
            r#"{{"ok":true,"ip":"{}","unbanned":{}}}"#,
            json_escape(&ip.to_string()),
            existed
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

