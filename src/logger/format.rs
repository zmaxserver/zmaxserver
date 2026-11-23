//! NCSA Combined / JSON satır biçimleyicileri.

use super::*;

pub(super) fn sanitize_log_line(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == '\0' {
            continue;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

pub(super) fn sanitize_log_token(raw: &str, empty_fallback: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch == '\0' {
            continue;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        empty_fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

pub(super) fn escape_clf_quoted(raw: &str, empty_fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return empty_fallback.to_string();
    }
    let mut out = String::with_capacity(trimmed.len() + 4);
    for ch in trimmed.chars() {
        match ch {
            '\0' => {}
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    if out.trim().is_empty() {
        empty_fallback.to_string()
    } else {
        out
    }
}

pub(super) fn format_combined_line(entry: &AccessLogEntry) -> String {
    let ts = zmax_core::format_clf_timestamp(entry.timestamp);
    let ip = sanitize_log_token(&entry.client_ip, "-");
    let method = sanitize_log_token(&entry.method, "GET");
    let target = sanitize_log_token(&entry.target, "/");
    let proto = sanitize_log_token(&entry.protocol, "HTTP/1.1");
    let referer = escape_clf_quoted(&entry.referer, "-");
    let ua = escape_clf_quoted(&entry.user_agent, "-");
    // NCSA Combined standardı: HEAD, 304, 204 veya 0 bayt gönderilen yanıtlarda '-' yazılır; aksi halde sayı yazılır.
    let bytes_field = if entry.bytes_sent == 0
        || entry.status == 304
        || entry.status == 204
        || entry.method.eq_ignore_ascii_case("HEAD")
    {
        "-".to_string()
    } else {
        entry.bytes_sent.to_string()
    };
    format!(
        "{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"\n",
        ip, ts, method, target, proto, entry.status, bytes_field, referer, ua
    )
}

pub(super) fn format_json_line(entry: &AccessLogEntry) -> String {
    let ts = zmax_core::format_iso8601_utc(entry.timestamp);
    let latency_ms = if entry.duration_ms.is_finite() {
        entry.duration_ms
    } else {
        0.0
    };
    let val = serde_json::json!({
        "ts": ts,
        "request_id": sanitize_log_token(&entry.request_id, ""),
        "domain": sanitize_log_token(&entry.domain, ""),
        "ip": sanitize_log_token(&entry.client_ip, ""),
        "method": sanitize_log_token(&entry.method, "GET"),
        "target": sanitize_log_token(&entry.target, "/"),
        "proto": sanitize_log_token(&entry.protocol, "HTTP/1.1"),
        "status": entry.status,
        "bytes": entry.bytes_sent,
        "latency_ms": latency_ms,
        "referer": sanitize_log_token(&entry.referer, ""),
        "user_agent": sanitize_log_token(&entry.user_agent, ""),
    });
    let mut line = serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string());
    line.push('\n');
    line
}
