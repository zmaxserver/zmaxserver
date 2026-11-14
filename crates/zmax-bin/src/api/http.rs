//! HTTP istek/yanıt türleri, JSON çıkarıcılar, okuma ve yanıt yazıcıları.

use super::*;

#[derive(Debug, Clone)]
pub struct ParsedHttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub version: u8,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl From<HttpRequestData> for ParsedHttpRequest {
    fn from(d: HttpRequestData) -> Self {
        Self {
            method: d.method,
            path: d.path,
            query: d.query,
            version: d.version,
            host: d.host,
            headers: d.headers,
            body: d.body,
            keep_alive: d.keep_alive,
        }
    }
}

/// JSON dizgesi için RFC 8259 uyumlu kaçış uygular.
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Düz JSON gövdesinden basit `"key":"value"` metin alanı çıkarır (dış bağımlılık gerektirmez).
pub fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let mut chars = after_colon[1..].chars();
    let mut val = String::new();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(esc) = chars.next() {
                match esc {
                    'n' => val.push('\n'),
                    'r' => val.push('\r'),
                    't' => val.push('\t'),
                    '"' => val.push('"'),
                    '\\' => val.push('\\'),
                    '/' => val.push('/'),
                    other => val.push(other),
                }
            }
        } else if c == '"' {
            return Some(val);
        } else {
            val.push(c);
        }
    }
    None
}

/// Düz JSON gövdesinden basit `"key": true/false` mantıksal alanı çıkarır.
pub fn extract_json_bool(body: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if after_colon.starts_with("true") {
        Some(true)
    } else if after_colon.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// Düz JSON gövdesinden basit `"key": 123` tam sayı alanı çıkarır.
pub fn extract_json_u64(body: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    let num_str: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if num_str.is_empty() {
        None
    } else {
        num_str.parse::<u64>().ok()
    }
}

/// Düz JSON gövdesinden basit `["a","b"]` dizge dizisini çıkarır.
pub fn extract_json_string_array(body: &str, key: &str) -> Option<Vec<String>> {
    let pattern = format!("\"{}\"", key);
    let idx = body.find(&pattern)?;
    let rest = &body[idx + pattern.len()..];
    let colon_idx = rest.find(':')?;
    let after_colon = rest[colon_idx + 1..].trim_start();
    if !after_colon.starts_with('[') {
        return None;
    }
    let end = after_colon.find(']')?;
    let inner = &after_colon[1..end];
    let mut items = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if in_str {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                items.push(cur.clone());
                cur.clear();
                in_str = false;
            } else {
                cur.push(ch);
            }
        } else if ch == '"' {
            in_str = true;
        }
    }
    Some(items)
}

/// Akıştan yapılandırılmış sınırlarla HTTP/1.1 isteği okur (`Content-Length` + `chunked` + `413/431/408`).
pub async fn read_http_request_with_limits<S>(
    stream: &mut S,
    leftover: &mut Vec<u8>,
    limits: HttpReadLimits,
) -> Result<Option<ParsedHttpRequest>, HttpReadError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let opt = read_http1_request_buffered(stream, leftover, limits).await?;
    Ok(opt.map(ParsedHttpRequest::from))
}

/// HTTP okuma hatasını uygun HTTP durum koduyla (413, 431, 408, 400) istemciye yazar.
pub async fn send_http_read_error<S>(socket: &mut S, err: &HttpReadError)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let (code, reason, body) = match err {
        HttpReadError::PayloadTooLarge => (413u16, "Payload Too Large", "413 Payload Too Large"),
        HttpReadError::HeadersTooLarge => (
            431u16,
            "Request Header Fields Too Large",
            "431 Request Header Fields Too Large",
        ),
        HttpReadError::Timeout => (408u16, "Request Timeout", "408 Request Timeout"),
        HttpReadError::BadRequest(_) => (400u16, "Bad Request", "400 Bad Request"),
        HttpReadError::Io(_) => return,
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nServer: zmaxserver\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        reason,
        body.len(),
        body
    );
    let _ = socket.write_all(resp.as_bytes()).await;
}

pub(crate) async fn send_response_with_content_type<S>(
    socket: &mut S,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    cors_origin: &str,
    body: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let origin = if cors_origin.is_empty() {
        "*"
    } else {
        cors_origin
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nServer: {}\r\nContent-Type: {}\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-ZMax-Token, X-ZMax-Purge-Key\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        status_text,
        zpoly!("zmaxserver-api").as_str(),
        content_type,
        origin,
        body.len(),
        body
    );
    socket.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Standart CORS ve Server başlıklarıyla JSON yanıtı gönderir.
pub async fn send_json_response_retry<S>(
    socket: &mut S,
    status_code: u16,
    status_text: &str,
    cors_origin: &str,
    json_body: &str,
    retry_after: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let origin = if cors_origin.is_empty() { "*" } else { cors_origin };
    let resp = format!(
        "HTTP/1.1 {} {}
Content-Type: application/json; charset=utf-8
Access-Control-Allow-Origin: {}
Retry-After: {}
Content-Length: {}
Connection: close

{}",
        status_code, status_text, origin, retry_after, json_body.len(), json_body
    );
    tokio::io::AsyncWriteExt::write_all(socket, resp.as_bytes()).await?;
    Ok(())
}

pub async fn send_json_response<S>(
    socket: &mut S,
    status_code: u16,
    status_text: &str,
    cors_origin: &str,
    json_body: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    send_response_with_content_type(
        socket,
        status_code,
        status_text,
        "application/json; charset=utf-8",
        cors_origin,
        json_body,
    )
    .await
}
