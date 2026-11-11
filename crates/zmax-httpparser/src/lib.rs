//! # zmax-httpparser
//! SIMD destekli, sıfır kopyalama (zero-copy) HTTP/1.1 ayrıştırıcısı,
//! asenkron chunked/keep-alive gövde okuyucusu ve gerçek IP çözümleyicisi.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct ParsedHttpRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: u8,
    pub headers: Vec<(&'a str, &'a [u8])>,
}

#[derive(Debug, Clone, Copy, Default)]
struct ValidatedHttpMeta {
    content_length: Option<usize>,
    is_chunked: bool,
}

#[derive(Debug, Clone, Copy)]
enum HeaderErrorKind {
    Name,
    Value,
}

#[derive(Debug)]
struct HeaderValidationError {
    kind: HeaderErrorKind,
    message: String,
}

impl HeaderValidationError {
    fn name(msg: impl Into<String>) -> Self {
        Self {
            kind: HeaderErrorKind::Name,
            message: msg.into(),
        }
    }

    fn value(msg: impl Into<String>) -> Self {
        Self {
            kind: HeaderErrorKind::Value,
            message: msg.into(),
        }
    }

    fn into_httparse_error(self) -> httparse::Error {
        match self.kind {
            HeaderErrorKind::Name => httparse::Error::HeaderName,
            HeaderErrorKind::Value => httparse::Error::HeaderValue,
        }
    }
}

fn trim_ows_bytes(mut bytes: &[u8]) -> &[u8] {
    while let Some(&first) = bytes.first() {
        if first == b' ' || first == b'\t' {
            bytes = &bytes[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = bytes.last() {
        if last == b' ' || last == b'\t' {
            bytes = &bytes[..bytes.len() - 1];
        } else {
            break;
        }
    }
    bytes
}

fn trim_ows_str(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

fn validate_http_headers(
    version: u8,
    headers: &[httparse::Header<'_>],
) -> Result<ValidatedHttpMeta, HeaderValidationError> {
    let mut host_count = 0usize;
    let mut has_invalid_host = false;
    let mut content_length: Option<usize> = None;
    let mut te_count = 0usize;

    for h in headers {
        if h.name.is_empty() || h.name.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(HeaderValidationError::name(
                "Geçersiz veya kontrol karakteri içeren HTTP başlık adı",
            ));
        }
        if h.value
            .iter()
            .any(|&b| matches!(b, b'\r' | b'\n' | b'\0'))
        {
            return Err(HeaderValidationError::value(
                "HTTP başlık değerinde yasaklı kontrol karakteri (CR/LF/NUL)",
            ));
        }

        if h.name.eq_ignore_ascii_case("host") {
            host_count += 1;
            let trimmed = trim_ows_bytes(h.value);
            if trimmed.is_empty() || trimmed.iter().any(|&b| b <= 0x20 || b == 0x7f) {
                has_invalid_host = true;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            let val_str = std::str::from_utf8(h.value).map_err(|_| {
                HeaderValidationError::value("Content-Length başlığı geçerli UTF-8 değil")
            })?;
            let trimmed = trim_ows_str(val_str);
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(HeaderValidationError::value(
                    "Geçersiz Content-Length başlığı",
                ));
            }
            let parsed_len = trimmed.parse::<usize>().map_err(|_| {
                HeaderValidationError::value("Content-Length sayısal sınırı aştı")
            })?;
            if let Some(prev) = content_length {
                if prev != parsed_len {
                    return Err(HeaderValidationError::value(
                        "Çelişkili birden fazla Content-Length başlığı",
                    ));
                }
            } else {
                content_length = Some(parsed_len);
            }
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let val_str = std::str::from_utf8(h.value).map_err(|_| {
                HeaderValidationError::value("Transfer-Encoding başlığı geçerli UTF-8 değil")
            })?;
            let trimmed = trim_ows_str(val_str);
            if trimmed.is_empty() {
                return Err(HeaderValidationError::value(
                    "Boş Transfer-Encoding başlığı",
                ));
            }
            for part in trimmed.split(',') {
                let token = trim_ows_str(part);
                if token.is_empty() || !token.eq_ignore_ascii_case("chunked") {
                    return Err(HeaderValidationError::value(
                        "Geçersiz veya desteklenmeyen Transfer-Encoding değeri",
                    ));
                }
                te_count += 1;
            }
        }
    }

    if te_count > 1 {
        return Err(HeaderValidationError::value(
            "Yinelenen veya karma Transfer-Encoding başlığı",
        ));
    }
    if te_count > 0 && content_length.is_some() {
        return Err(HeaderValidationError::value(
            "Transfer-Encoding ve Content-Length birlikte gönderilemez",
        ));
    }
    if version == 1 && (host_count > 1 || has_invalid_host) {
        return Err(HeaderValidationError::value(
            "HTTP/1.1 isteğinde yinelenen veya boş Host başlığı",
        ));
    }

    Ok(ValidatedHttpMeta {
        content_length,
        is_chunked: te_count == 1,
    })
}

pub fn parse_request<'a>(
    buffer: &'a [u8],
    headers_buf: &'a mut [httparse::Header<'a>],
) -> Result<Option<(ParsedHttpRequest<'a>, usize)>, httparse::Error> {
    let mut req = httparse::Request::new(headers_buf);
    match req.parse(buffer)? {
        httparse::Status::Complete(body_offset) => {
            let method = req.method.unwrap_or("GET");
            let path = req.path.unwrap_or("/");
            let version = req.version.unwrap_or(1);

            validate_http_headers(version, req.headers)
                .map_err(HeaderValidationError::into_httparse_error)?;

            let mut parsed_headers = Vec::with_capacity(req.headers.len());
            for h in req.headers {
                parsed_headers.push((h.name, h.value));
            }

            Ok(Some((
                ParsedHttpRequest {
                    method,
                    path,
                    version,
                    headers: parsed_headers,
                },
                body_offset,
            )))
        }
        httparse::Status::Partial => Ok(None),
    }
}

/// HTTP/1.1 asenkron istek okuma limitleri ve zaman aşımları.
#[derive(Debug, Clone, Copy)]
pub struct HttpReadLimits {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
}

impl Default for HttpReadLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 64 * 1024 * 1024,
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
        }
    }
}

/// Tam ayrıştırılmış ve sahiplenilmiş HTTP/1.1 isteği.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestData {
    pub method: String,
    pub target: String,
    pub path: String,
    pub query: String,
    pub version: u8,
    pub host: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

/// HTTP/1.1 okuma ve ayrıştırma sırasında oluşabilecek açık durum kodlu hatalar.
#[derive(Debug)]
pub enum HttpReadError {
    /// Gövde `max_body_bytes` sınırını aştı (HTTP 413 Payload Too Large).
    PayloadTooLarge,
    /// Başlık bloğu `max_header_bytes` veya başlık sayısı sınırını aştı (HTTP 431).
    HeadersTooLarge,
    /// İstemci başlık veya gövdeyi zaman aşımı içinde tamamlamadı (HTTP 408).
    Timeout,
    /// Bozuk HTTP sözdizimi, geçersiz Content-Length veya hatalı chunk çerçevesi (HTTP 400).
    BadRequest(String),
    /// Alt katman soket G/Ç hatası.
    Io(std::io::Error),
}

impl HttpReadError {
    /// Hatanın karşılık geldiği standart HTTP durum kodunu döner.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::PayloadTooLarge => 413,
            Self::HeadersTooLarge => 431,
            Self::Timeout => 408,
            Self::BadRequest(_) => 400,
            Self::Io(_) => 500,
        }
    }
}

impl fmt::Display for HttpReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "İstek gövdesi izin verilen sınırı aşıyor (413)"),
            Self::HeadersTooLarge => write!(f, "HTTP başlık boyutu sınırı aşıldı (431)"),
            Self::Timeout => write!(f, "HTTP istek okuma zaman aşımı (408)"),
            Self::BadRequest(msg) => write!(f, "Geçersiz HTTP isteği (400): {}", msg),
            Self::Io(err) => write!(f, "Soket okuma hatası: {}", err),
        }
    }
}

impl std::error::Error for HttpReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HttpReadError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Akıştan tek bir HTTP/1.1 isteği okur (`Content-Length`, `Transfer-Encoding: chunked` ve `keep_alive` destekli).
/// Temiz bağlantı kapanışında `Ok(None)` döner.
pub async fn read_http1_request<S>(
    stream: &mut S,
    limits: HttpReadLimits,
) -> Result<Option<HttpRequestData>, HttpReadError>
where
    S: AsyncRead + Unpin,
{
    let mut leftover = Vec::with_capacity(4096);
    read_http1_request_buffered(stream, &mut leftover, limits).await
}

/// Keep-alive bağlantılarda ardışık/pipelined istekleri kaybetmeden tampon üzerinden HTTP/1.1 isteği okur.
pub async fn read_http1_request_buffered<S>(
    stream: &mut S,
    leftover: &mut Vec<u8>,
    limits: HttpReadLimits,
) -> Result<Option<HttpRequestData>, HttpReadError>
where
    S: AsyncRead + Unpin,
{
    let mut tmp = [0u8; 8192];

    let header_end = loop {
        if let Some(pos) = find_header_end(leftover) {
            let end = pos + 4;
            if end > limits.max_header_bytes {
                return Err(HttpReadError::HeadersTooLarge);
            }
            break end;
        }
        if leftover.len() >= limits.max_header_bytes {
            return Err(HttpReadError::HeadersTooLarge);
        }

        let read_res = tokio::time::timeout(limits.header_timeout, stream.read(&mut tmp))
            .await
            .map_err(|_| HttpReadError::Timeout)?
            .map_err(HttpReadError::Io)?;

        if read_res == 0 {
            if leftover.is_empty() {
                return Ok(None);
            }
            return Err(HttpReadError::BadRequest(
                "HTTP başlığı tamamlanmadan bağlantı kapandı".to_string(),
            ));
        }

        leftover.extend_from_slice(&tmp[..read_res]);
    };

    let mut headers_buf = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers_buf);
    let parsed_offset = match req.parse(&leftover[..header_end]) {
        Ok(httparse::Status::Complete(offset)) => offset,
        Ok(httparse::Status::Partial) => {
            return Err(HttpReadError::BadRequest(
                "Eksik veya tamamlanmamış HTTP başlığı".to_string(),
            ));
        }
        Err(httparse::Error::TooManyHeaders) => return Err(HttpReadError::HeadersTooLarge),
        Err(e) => {
            return Err(HttpReadError::BadRequest(format!(
                "Bozuk HTTP istek sözdizimi: {}",
                e
            )));
        }
    };

    let method = req
        .method
        .ok_or_else(|| HttpReadError::BadRequest("HTTP metodu eksik".to_string()))?
        .to_string();
    let target = req
        .path
        .ok_or_else(|| HttpReadError::BadRequest("HTTP hedef yolu eksik".to_string()))?
        .to_string();
    let version = req.version.unwrap_or(1);
    if version > 1 {
        return Err(HttpReadError::BadRequest(
            "Desteklenmeyen HTTP sürümü".to_string(),
        ));
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };

    let meta = validate_http_headers(version, req.headers)
        .map_err(|e| HttpReadError::BadRequest(e.message))?;

    let mut headers = Vec::with_capacity(req.headers.len());
    let mut host = String::new();
    let mut conn_close = false;
    let mut conn_keep_alive = false;

    for h in req.headers.iter() {
        let name = h.name.to_string();
        let val = String::from_utf8_lossy(trim_ows_bytes(h.value)).into_owned();

        if name.eq_ignore_ascii_case("host") {
            if host.is_empty() {
                host = val.clone();
            }
        } else if name.eq_ignore_ascii_case("connection") {
            for token in val.split(',') {
                let t = trim_ows_str(token).to_ascii_lowercase();
                if t == "close" {
                    conn_close = true;
                } else if t == "keep-alive" {
                    conn_keep_alive = true;
                }
            }
        }

        headers.push((name, val));
    }

    let keep_alive = if version == 1 {
        !conn_close
    } else {
        conn_keep_alive && !conn_close
    };

    // Başlık baytlarını tampondan düşür; geriye gövde veya sonraki pipelined istek kalır.
    leftover.drain(..parsed_offset.min(header_end));

    let body = if meta.is_chunked {
        decode_chunked_stream(stream, leftover, limits.max_body_bytes, limits.body_timeout).await?
    } else if let Some(len) = meta.content_length {
        if len > limits.max_body_bytes {
            return Err(HttpReadError::PayloadTooLarge);
        }
        if len == 0 {
            Vec::new()
        } else {
            while leftover.len() < len {
                let n = tokio::time::timeout(limits.body_timeout, stream.read(&mut tmp))
                    .await
                    .map_err(|_| HttpReadError::Timeout)?
                    .map_err(HttpReadError::Io)?;
                if n == 0 {
                    return Err(HttpReadError::BadRequest(
                        "Content-Length gövdesi tamamlanmadan bağlantı kapandı".to_string(),
                    ));
                }
                leftover.extend_from_slice(&tmp[..n]);
            }
            leftover.drain(..len).collect()
        }
    } else {
        Vec::new()
    };

    Ok(Some(HttpRequestData {
        method,
        target,
        path,
        query,
        version,
        host,
        headers,
        body,
        keep_alive,
    }))
}

/// Akış + tampon üzerinden `Transfer-Encoding: chunked` gövdesini tam çözer ve sınır denetimi yapar.
pub async fn decode_chunked_stream<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    max_body_bytes: usize,
    body_timeout: Duration,
) -> Result<Vec<u8>, HttpReadError>
where
    S: AsyncRead + Unpin,
{
    const MAX_CHUNK_LINE_BYTES: usize = 4096;
    const MAX_TRAILER_BYTES: usize = 16 * 1024;

    let mut decoded = Vec::new();
    let mut tmp = [0u8; 8192];

    loop {
        let line_end = loop {
            if let Some(pos) = find_crlf(buf) {
                if pos > MAX_CHUNK_LINE_BYTES {
                    return Err(HttpReadError::BadRequest(
                        "Chunk boyut satırı çok uzun".to_string(),
                    ));
                }
                break pos;
            }
            if buf.len() > MAX_CHUNK_LINE_BYTES {
                return Err(HttpReadError::BadRequest(
                    "Chunk boyut satırında CRLF eksik".to_string(),
                ));
            }
            let n = tokio::time::timeout(body_timeout, stream.read(&mut tmp))
                .await
                .map_err(|_| HttpReadError::Timeout)?
                .map_err(HttpReadError::Io)?;
            if n == 0 {
                return Err(HttpReadError::BadRequest(
                    "Chunked gövde tamamlanmadan bağlantı kapandı".to_string(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        };

        let chunk_size = parse_chunk_size_line(&buf[..line_end])?;
        buf.drain(..line_end + 2);

        if chunk_size == 0 {
            // Opsiyonel trailer başlıklarını son boş `\r\n` satırına kadar tüket.
            let mut trailer_bytes = 0usize;
            loop {
                let trailer_line_end = loop {
                    if let Some(pos) = find_crlf(buf) {
                        break pos;
                    }
                    if buf.len() + trailer_bytes > MAX_TRAILER_BYTES {
                        return Err(HttpReadError::HeadersTooLarge);
                    }
                    let n = tokio::time::timeout(body_timeout, stream.read(&mut tmp))
                        .await
                        .map_err(|_| HttpReadError::Timeout)?
                        .map_err(HttpReadError::Io)?;
                    if n == 0 {
                        return Err(HttpReadError::BadRequest(
                            "Chunked bitiş satırı eksik (EOF)".to_string(),
                        ));
                    }
                    buf.extend_from_slice(&tmp[..n]);
                };

                trailer_bytes = trailer_bytes.saturating_add(trailer_line_end + 2);
                if trailer_bytes > MAX_TRAILER_BYTES {
                    return Err(HttpReadError::HeadersTooLarge);
                }
                let is_empty_line = trailer_line_end == 0;
                buf.drain(..trailer_line_end + 2);
                if is_empty_line {
                    break;
                }
            }
            return Ok(decoded);
        }

        if decoded.len().saturating_add(chunk_size) > max_body_bytes {
            return Err(HttpReadError::PayloadTooLarge);
        }

        let needed = chunk_size
            .checked_add(2)
            .ok_or(HttpReadError::PayloadTooLarge)?;
        while buf.len() < needed {
            let n = tokio::time::timeout(body_timeout, stream.read(&mut tmp))
                .await
                .map_err(|_| HttpReadError::Timeout)?
                .map_err(HttpReadError::Io)?;
            if n == 0 {
                return Err(HttpReadError::BadRequest(
                    "Chunk verisi tamamlanmadan bağlantı kapandı".to_string(),
                ));
            }
            buf.extend_from_slice(&tmp[..n]);
        }

        if &buf[chunk_size..chunk_size + 2] != b"\r\n" {
            return Err(HttpReadError::BadRequest(
                "Chunk veri bloğunun sonunda CRLF bulunamadı".to_string(),
            ));
        }

        decoded.extend_from_slice(&buf[..chunk_size]);
        buf.drain(..needed);
    }
}

/// Senkron bellek diliminden `Transfer-Encoding: chunked` gövdesini ayrıştırır.
/// Tamamlanmışsa `Ok(Some((gövde, tüketilen_bayt)))`, eksikse `Ok(None)` döner.
pub fn parse_chunked_body(
    raw: &[u8],
    max_body_bytes: usize,
) -> Result<Option<(Vec<u8>, usize)>, HttpReadError> {
    let mut pos = 0usize;
    let mut decoded = Vec::new();

    loop {
        let Some(rel_end) = find_crlf(&raw[pos..]) else {
            return Ok(None);
        };
        let chunk_size = parse_chunk_size_line(&raw[pos..pos + rel_end])?;
        pos += rel_end + 2;

        if chunk_size == 0 {
            loop {
                let Some(trailer_rel) = find_crlf(&raw[pos..]) else {
                    return Ok(None);
                };
                pos += trailer_rel + 2;
                if trailer_rel == 0 {
                    return Ok(Some((decoded, pos)));
                }
            }
        }

        if decoded.len().saturating_add(chunk_size) > max_body_bytes {
            return Err(HttpReadError::PayloadTooLarge);
        }

        let Some(data_end) = pos.checked_add(chunk_size) else {
            return Err(HttpReadError::PayloadTooLarge);
        };
        let Some(frame_end) = data_end.checked_add(2) else {
            return Err(HttpReadError::PayloadTooLarge);
        };
        if raw.len() < frame_end {
            return Ok(None);
        }
        if &raw[data_end..frame_end] != b"\r\n" {
            return Err(HttpReadError::BadRequest(
                "Chunk veri bloğunun sonunda CRLF bulunamadı".to_string(),
            ));
        }
        decoded.extend_from_slice(&raw[pos..data_end]);
        pos = frame_end;
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn parse_chunk_size_line(line: &[u8]) -> Result<usize, HttpReadError> {
    let s = std::str::from_utf8(line)
        .map_err(|_| HttpReadError::BadRequest("Chunk boyut satırı UTF-8 değil".to_string()))?;
    let hex_part = s.split(';').next().unwrap_or("").trim();
    if hex_part.is_empty() || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(HttpReadError::BadRequest(
            "Geçersiz chunk boyut ifadesi".to_string(),
        ));
    }
    usize::from_str_radix(hex_part, 16)
        .map_err(|_| HttpReadError::BadRequest("Chunk boyutu taşması".to_string()))
}

/// Başlık listesinden büyük/küçük harf duyarsız şekilde ilk eşleşen başlık değerini çıkarır.
pub fn extract_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

/// Zero-copy başlık diliminden büyük/küçük harf duyarsız şekilde başlık değerini çıkarır.
pub fn extract_header_bytes<'a>(
    headers: &'a [(&'a str, &'a [u8])],
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
        .map(|s| s.trim())
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Verilen IP adresinin tekil IP veya CIDR (`173.245.48.0/20`, `fc00::/7`) içinde olup olmadığını denetler.
pub fn is_ip_in_cidr(ip: IpAddr, cidr_or_ip: &str) -> bool {
    let spec = cidr_or_ip.trim();
    if spec.is_empty() {
        return false;
    }
    let ip = canonicalize_ip(ip);

    if let Some((net_str, prefix_str)) = spec.split_once('/') {
        let Ok(net_ip) = net_str.trim().parse::<IpAddr>() else {
            return false;
        };
        let Ok(prefix) = prefix_str.trim().parse::<u32>() else {
            return false;
        };
        let net_ip = canonicalize_ip(net_ip);
        match (ip, net_ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) if prefix <= 32 => {
                let mask = if prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) if prefix <= 128 => {
                let mask = if prefix == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            _ => false,
        }
    } else if let Ok(exact) = spec.parse::<IpAddr>() {
        ip == canonicalize_ip(exact)
    } else {
        false
    }
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxies: &[String]) -> bool {
    trusted_proxies
        .iter()
        .any(|cidr| is_ip_in_cidr(ip, cidr))
}

fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let token = raw.trim().trim_matches('"');
    if token.is_empty() {
        return None;
    }
    if let Ok(ip) = token.parse::<IpAddr>() {
        return Some(canonicalize_ip(ip));
    }
    if let Ok(sock) = token.parse::<SocketAddr>() {
        return Some(canonicalize_ip(sock.ip()));
    }
    let unbracketed = token
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'));
    unbracketed
        .and_then(|s| s.parse::<IpAddr>().ok())
        .map(canonicalize_ip)
}

/// `mod_realip` kurallarına göre sahteciliğe dayanıklı gerçek istemci IP çözümlemesi yapar.
/// Soket `peer_ip` adresi `trusted_proxies` içinde değilse başlıklar yok sayılır ve doğrudan `peer_ip` döner.
pub fn resolve_real_ip(
    peer_ip: IpAddr,
    headers: &[(String, String)],
    header_name: &str,
    trusted_proxies: &[String],
    recursive: bool,
) -> IpAddr {
    let peer = canonicalize_ip(peer_ip);
    if !is_trusted_proxy(peer, trusted_proxies) {
        return peer;
    }

    let target_header = if header_name.trim().is_empty() {
        "X-Forwarded-For"
    } else {
        header_name.trim()
    };

    let mut candidates = Vec::new();
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(target_header) {
            for part in v.split(',') {
                if let Some(ip) = parse_forwarded_ip(part) {
                    candidates.push(ip);
                }
            }
        }
    }

    if candidates.is_empty() {
        return peer;
    }

    if !recursive {
        return *candidates.last().unwrap_or(&peer);
    }

    for ip in candidates.iter().rev() {
        if !is_trusted_proxy(*ip, trusted_proxies) {
            return *ip;
        }
    }

    *candidates.first().unwrap_or(&peer)
}

const PROXY_V1_PREFIX: &[u8] = b"PROXY ";
const PROXY_V1_MAX_LEN: usize = 108;
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const PROXY_V2_HEADER_LEN: usize = 16;
const PROXY_V2_MAX_PAYLOAD_LEN: usize = 1024;

/// Ayrıştırılmış HAProxy PROXY Protocol v1 veya v2 başlığı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyProtocolHeader {
    pub version: u8,
    pub src_addr: Option<SocketAddr>,
    pub dst_addr: Option<SocketAddr>,
    pub consumed_bytes: usize,
}

/// PROXY Protocol önek ayrıştırma hataları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocolError {
    Incomplete,
    InvalidHeader(String),
    TooLong,
}

impl fmt::Display for ProxyProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "PROXY protocol başlığı tamamlanmadı"),
            Self::InvalidHeader(msg) => write!(f, "Geçersiz PROXY protocol başlığı: {}", msg),
            Self::TooLong => write!(f, "PROXY protocol başlığı izin verilen sınırı aşıyor"),
        }
    }
}

impl std::error::Error for ProxyProtocolError {}

fn parse_strict_port(raw: &str) -> Result<u16, ProxyProtocolError> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProxyProtocolError::InvalidHeader(format!(
            "Geçersiz port numarası: {}",
            raw
        )));
    }
    raw.parse::<u16>().map_err(|_| {
        ProxyProtocolError::InvalidHeader(format!("Port numarası aralık dışında: {}", raw))
    })
}

fn parse_proxy_v1(buf: &[u8]) -> Result<ProxyProtocolHeader, ProxyProtocolError> {
    let scan_len = buf.len().min(PROXY_V1_MAX_LEN);
    let Some(crlf_pos) = find_crlf(&buf[..scan_len]) else {
        if buf[..scan_len].contains(&b'\n')
            || buf[..scan_len.saturating_sub(1)].contains(&b'\r')
        {
            return Err(ProxyProtocolError::InvalidHeader(
                "PROXY v1 satırında CRLF zorunlu".to_string(),
            ));
        }
        if buf.len() >= PROXY_V1_MAX_LEN {
            return Err(ProxyProtocolError::TooLong);
        }
        return Err(ProxyProtocolError::Incomplete);
    };

    let line = &buf[..crlf_pos];
    if line
        .iter()
        .any(|&b| matches!(b, b'\r' | b'\n' | b'\0'))
    {
        return Err(ProxyProtocolError::InvalidHeader(
            "PROXY v1 satırında yasaklı kontrol karakteri".to_string(),
        ));
    }

    let line_str = std::str::from_utf8(line).map_err(|_| {
        ProxyProtocolError::InvalidHeader("PROXY v1 başlığı geçerli UTF-8/ASCII değil".to_string())
    })?;
    let rest = &line_str[PROXY_V1_PREFIX.len()..];
    let consumed_bytes = crlf_pos + 2;

    if rest == "UNKNOWN" || rest.starts_with("UNKNOWN ") {
        return Ok(ProxyProtocolHeader {
            version: 1,
            src_addr: None,
            dst_addr: None,
            consumed_bytes,
        });
    }

    let parts: Vec<&str> = rest.split(' ').collect();
    if parts.len() != 5 {
        return Err(ProxyProtocolError::InvalidHeader(
            "PROXY v1 alan sayısı geçersiz".to_string(),
        ));
    }

    let (src_ip, dst_ip) = match parts[0] {
        "TCP4" => {
            let src = parts[1].parse::<Ipv4Addr>().map_err(|_| {
                ProxyProtocolError::InvalidHeader("Geçersiz PROXY v1 TCP4 kaynak IP".to_string())
            })?;
            let dst = parts[2].parse::<Ipv4Addr>().map_err(|_| {
                ProxyProtocolError::InvalidHeader("Geçersiz PROXY v1 TCP4 hedef IP".to_string())
            })?;
            (IpAddr::V4(src), IpAddr::V4(dst))
        }
        "TCP6" => {
            let src = parts[1].parse::<Ipv6Addr>().map_err(|_| {
                ProxyProtocolError::InvalidHeader("Geçersiz PROXY v1 TCP6 kaynak IP".to_string())
            })?;
            let dst = parts[2].parse::<Ipv6Addr>().map_err(|_| {
                ProxyProtocolError::InvalidHeader("Geçersiz PROXY v1 TCP6 hedef IP".to_string())
            })?;
            (IpAddr::V6(src), IpAddr::V6(dst))
        }
        other => {
            return Err(ProxyProtocolError::InvalidHeader(format!(
                "Desteklenmeyen PROXY v1 protokolü: {}",
                other
            )));
        }
    };

    let src_port = parse_strict_port(parts[3])?;
    let dst_port = parse_strict_port(parts[4])?;

    Ok(ProxyProtocolHeader {
        version: 1,
        src_addr: Some(SocketAddr::new(src_ip, src_port)),
        dst_addr: Some(SocketAddr::new(dst_ip, dst_port)),
        consumed_bytes,
    })
}

fn parse_proxy_v2(buf: &[u8]) -> Result<ProxyProtocolHeader, ProxyProtocolError> {
    if buf.len() < PROXY_V2_HEADER_LEN {
        return Err(ProxyProtocolError::Incomplete);
    }

    let ver_cmd = buf[12];
    if (ver_cmd & 0xF0) != 0x20 {
        return Err(ProxyProtocolError::InvalidHeader(format!(
            "Geçersiz PROXY v2 sürüm alanı: {:#04x}",
            ver_cmd
        )));
    }
    let cmd = ver_cmd & 0x0F;
    if cmd > 0x01 {
        return Err(ProxyProtocolError::InvalidHeader(format!(
            "Geçersiz PROXY v2 komutu: {:#04x}",
            cmd
        )));
    }

    let fam_proto = buf[13];
    let family = fam_proto >> 4;
    let proto = fam_proto & 0x0F;
    if family > 0x03 || proto > 0x02 {
        return Err(ProxyProtocolError::InvalidHeader(format!(
            "Geçersiz PROXY v2 adres ailesi/protokolü: {:#04x}",
            fam_proto
        )));
    }

    let payload_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    if payload_len > PROXY_V2_MAX_PAYLOAD_LEN {
        return Err(ProxyProtocolError::TooLong);
    }

    let total_len = PROXY_V2_HEADER_LEN + payload_len;
    if buf.len() < total_len {
        return Err(ProxyProtocolError::Incomplete);
    }

    let payload = &buf[PROXY_V2_HEADER_LEN..total_len];
    if cmd == 0x00 {
        // LOCAL komutu: bağlantı proxy arkasından gelmiyor veya sağlık kontrolü; adresler kullanılmaz.
        return Ok(ProxyProtocolHeader {
            version: 2,
            src_addr: None,
            dst_addr: None,
            consumed_bytes: total_len,
        });
    }

    let (src_addr, dst_addr) = match family {
        0x00 => (None, None),
        0x01 => {
            if proto == 0x00 || payload.len() < 12 {
                return Err(ProxyProtocolError::InvalidHeader(
                    "PROXY v2 AF_INET adresi eksik veya protokol geçersiz".to_string(),
                ));
            }
            let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let dst_ip = Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            let dst_port = u16::from_be_bytes([payload[10], payload[11]]);
            (
                Some(SocketAddr::new(IpAddr::V4(src_ip), src_port)),
                Some(SocketAddr::new(IpAddr::V4(dst_ip), dst_port)),
            )
        }
        0x02 => {
            if proto == 0x00 || payload.len() < 36 {
                return Err(ProxyProtocolError::InvalidHeader(
                    "PROXY v2 AF_INET6 adresi eksik veya protokol geçersiz".to_string(),
                ));
            }
            let mut src_octets = [0u8; 16];
            let mut dst_octets = [0u8; 16];
            src_octets.copy_from_slice(&payload[0..16]);
            dst_octets.copy_from_slice(&payload[16..32]);
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);
            let dst_port = u16::from_be_bytes([payload[34], payload[35]]);
            (
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(src_octets)),
                    src_port,
                )),
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(dst_octets)),
                    dst_port,
                )),
            )
        }
        0x03 => {
            if proto == 0x00 || payload.len() < 216 {
                return Err(ProxyProtocolError::InvalidHeader(
                    "PROXY v2 AF_UNIX adresi eksik veya protokol geçersiz".to_string(),
                ));
            }
            (None, None)
        }
        _ => unreachable!(),
    };

    Ok(ProxyProtocolHeader {
        version: 2,
        src_addr,
        dst_addr,
        consumed_bytes: total_len,
    })
}

/// Tamponun başındaki PROXY Protocol v1/v2 önekini ayrıştırır.
/// Tampon PROXY imzası ile başlamıyorsa `Ok(None)` döner ve mevcut trafik verisine dokunmaz.
pub fn parse_proxy_protocol_prefix(
    buf: &[u8],
) -> Result<Option<ProxyProtocolHeader>, ProxyProtocolError> {
    if buf.is_empty() {
        return Err(ProxyProtocolError::Incomplete);
    }
    if buf.starts_with(PROXY_V1_PREFIX) {
        return parse_proxy_v1(buf).map(Some);
    }
    if buf.starts_with(&PROXY_V2_SIGNATURE) {
        return parse_proxy_v2(buf).map(Some);
    }
    if (buf.len() < PROXY_V1_PREFIX.len() && PROXY_V1_PREFIX.starts_with(buf))
        || (buf.len() < PROXY_V2_SIGNATURE.len() && PROXY_V2_SIGNATURE.starts_with(buf))
    {
        return Err(ProxyProtocolError::Incomplete);
    }
    Ok(None)
}

/// Akıştan opsiyonel PROXY Protocol v1/v2 başlığını okur; PROXY olmayan trafikte okunan baytları `prebuf` içinde korur.
pub async fn read_proxy_protocol_header<R: AsyncRead + Unpin>(
    stream: &mut R,
    prebuf: &mut bytes::BytesMut,
    timeout: Duration,
) -> Result<Option<ProxyProtocolHeader>, std::io::Error> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut tmp = [0u8; 1024];

    loop {
        if !prebuf.is_empty() {
            match parse_proxy_protocol_prefix(prebuf) {
                Ok(Some(hdr)) => {
                    let _ = prebuf.split_to(hdr.consumed_bytes);
                    return Ok(Some(hdr));
                }
                Ok(None) => return Ok(None),
                Err(ProxyProtocolError::Incomplete) => {}
                Err(ProxyProtocolError::InvalidHeader(msg)) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, msg));
                }
                Err(ProxyProtocolError::TooLong) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "PROXY protocol başlığı izin verilen sınırı aşıyor",
                    ));
                }
            }
        }

        let n = tokio::time::timeout_at(deadline, stream.read(&mut tmp))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "PROXY protocol başlığı okuma zaman aşımı",
                )
            })??;

        if n == 0 {
            if prebuf.is_empty() {
                return Ok(None);
            }
            if prebuf.starts_with(PROXY_V1_PREFIX)
                || prebuf.starts_with(&PROXY_V2_SIGNATURE)
                || (prebuf.len() >= 4 && PROXY_V2_SIGNATURE.starts_with(prebuf))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "PROXY protocol başlığı tamamlanmadan bağlantı kapandı",
                ));
            }
            return Ok(None);
        }

        prebuf.extend_from_slice(&tmp[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn test_valid_and_malformed_requests() {
        let mut headers = [httparse::EMPTY_HEADER; 16];

        // 1. Geçerli İstek
        let valid = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let res = parse_request(valid, &mut headers).unwrap();
        assert!(res.is_some());
        let (req, _) = res.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/index.html");

        // 2. Bozuk / Saldırı İsteği (Malformed Header)
        let mut headers2 = [httparse::EMPTY_HEADER; 16];
        let malformed = b"MALFORMED_GARBAGE_REQUEST\r\n\r\n";
        let res_err = parse_request(malformed, &mut headers2);
        assert!(res_err.is_err());
    }

    #[tokio::test]
    async fn test_read_http1_chunked_streaming() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            client
                .write_all(b"POST /upload?x=1 HTTP/1.1\r\nHost: api.test\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            client.write_all(b"5;ext=1\r\nhello\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client.write_all(b"6\r\n world\r\n0\r\nX-Checksum: abc\r\n\r\n").await.unwrap();
        });

        let req = read_http1_request(&mut server, HttpReadLimits::default())
            .await
            .unwrap()
            .expect("İstek okunmalı");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/upload");
        assert_eq!(req.query, "x=1");
        assert_eq!(req.host, "api.test");
        assert!(req.keep_alive);
        assert_eq!(req.body, b"hello world");
    }

    #[tokio::test]
    async fn test_payload_too_large_413_content_length_and_chunked() {
        // 1. Content-Length sınırı aşımı -> sessiz kesme değil, PayloadTooLarge (413)
        let (mut client1, mut server1) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            client1
                .write_all(b"POST /big HTTP/1.1\r\nHost: site.test\r\nContent-Length: 20\r\n\r\n12345678901234567890")
                .await
                .unwrap();
        });
        let limits = HttpReadLimits {
            max_body_bytes: 10,
            ..Default::default()
        };
        let err = read_http1_request(&mut server1, limits).await.unwrap_err();
        assert!(matches!(err, HttpReadError::PayloadTooLarge));
        assert_eq!(err.status_code(), 413);

        // 2. Chunked gövde sınırı aşımı -> PayloadTooLarge (413)
        let (mut client2, mut server2) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            client2
                .write_all(b"POST /chunk HTTP/1.1\r\nHost: site.test\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n123456\r\n5\r\n78901\r\n0\r\n\r\n")
                .await
                .unwrap();
        });
        let err2 = read_http1_request(&mut server2, limits).await.unwrap_err();
        assert!(matches!(err2, HttpReadError::PayloadTooLarge));
        assert_eq!(err2.status_code(), 413);
    }

    #[tokio::test]
    async fn test_headers_too_large_431_timeout_408_and_bad_request_400() {
        // 431 HeadersTooLarge
        let (mut c1, mut s1) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            c1.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n")
                .await
                .unwrap();
        });
        let err_hdr = read_http1_request(
            &mut s1,
            HttpReadLimits {
                max_header_bytes: 40,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_hdr, HttpReadError::HeadersTooLarge));
        assert_eq!(err_hdr.status_code(), 431);

        // 408 Timeout
        let (_c2, mut s2) = tokio::io::duplex(4096);
        let err_to = read_http1_request(
            &mut s2,
            HttpReadLimits {
                header_timeout: Duration::from_millis(30),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err_to, HttpReadError::Timeout));
        assert_eq!(err_to.status_code(), 408);

        // 400 BadRequest (çelişkili Content-Length)
        let (mut c3, mut s3) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            c3.write_all(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello")
                .await
                .unwrap();
        });
        let err_bad = read_http1_request(&mut s3, HttpReadLimits::default())
            .await
            .unwrap_err();
        assert!(matches!(err_bad, HttpReadError::BadRequest(_)));
        assert_eq!(err_bad.status_code(), 400);
    }

    #[tokio::test]
    async fn test_keep_alive_rules_and_pipelined_buffer() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            // 1: HTTP/1.1 varsayılan keep-alive = true
            // 2: HTTP/1.0 varsayılan keep-alive = false
            // 3: HTTP/1.0 + Connection: keep-alive = true
            // 4: HTTP/1.1 + Connection: close = false
            client
                .write_all(
                    b"GET /one HTTP/1.1\r\nHost: a\r\n\r\n\
                      GET /two HTTP/1.0\r\nHost: a\r\n\r\n\
                      GET /three HTTP/1.0\r\nConnection: keep-alive\r\n\r\n\
                      POST /four HTTP/1.1\r\nHost: a\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok",
                )
                .await
                .unwrap();
        });

        let mut buf = Vec::new();
        let r1 = read_http1_request_buffered(&mut server, &mut buf, HttpReadLimits::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r1.path, "/one");
        assert!(r1.keep_alive);

        let r2 = read_http1_request_buffered(&mut server, &mut buf, HttpReadLimits::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r2.path, "/two");
        assert!(!r2.keep_alive);

        let r3 = read_http1_request_buffered(&mut server, &mut buf, HttpReadLimits::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r3.path, "/three");
        assert!(r3.keep_alive);

        let r4 = read_http1_request_buffered(&mut server, &mut buf, HttpReadLimits::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r4.path, "/four");
        assert!(!r4.keep_alive);
        assert_eq!(r4.body, b"ok");

        // Temiz EOF
        let r5 = read_http1_request_buffered(&mut server, &mut buf, HttpReadLimits::default())
            .await
            .unwrap();
        assert!(r5.is_none());
    }

    #[test]
    fn test_parse_chunked_body_sync() {
        let raw = b"4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n";
        let (body, consumed) = parse_chunked_body(raw, 1024).unwrap().unwrap();
        assert_eq!(body, b"Wikipedia in\r\n\r\nchunks.");
        assert_eq!(consumed, raw.len());
    }

    #[test]
    fn test_extract_header_and_resolve_real_ip() {
        let trusted = vec![
            "173.245.48.0/20".to_string(),
            "10.0.0.0/8".to_string(),
            "127.0.0.1".to_string(),
        ];

        // 1. Güvensiz eş -> başlık sahteciliği yok sayılmalı
        let headers_spoof = vec![
            ("Host".to_string(), "site.com".to_string()),
            ("cf-connecting-ip".to_string(), "127.0.0.1".to_string()),
        ];
        assert_eq!(extract_header(&headers_spoof, "HOST"), Some("site.com"));
        let untrusted_peer: IpAddr = "203.0.113.45".parse().unwrap();
        assert_eq!(
            resolve_real_ip(untrusted_peer, &headers_spoof, "CF-Connecting-IP", &trusted, true),
            untrusted_peer
        );

        // 2. Güvenilir Cloudflare eş -> gerçek IP dönmeli
        let cf_peer: IpAddr = "173.245.48.10".parse().unwrap();
        let headers_cf = vec![("CF-Connecting-IP".to_string(), "198.51.100.7".to_string())];
        assert_eq!(
            resolve_real_ip(cf_peer, &headers_cf, "CF-Connecting-IP", &trusted, true),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );

        // 3. Zincirli X-Forwarded-For recursive çözümleme (sahte sol IP'yi atlar)
        let proxy_peer: IpAddr = "10.0.0.2".parse().unwrap();
        let headers_xff = vec![(
            "X-Forwarded-For".to_string(),
            "1.1.1.1, 198.51.100.88, 173.245.48.5".to_string(),
        )];
        assert_eq!(
            resolve_real_ip(proxy_peer, &headers_xff, "X-Forwarded-For", &trusted, true),
            "198.51.100.88".parse::<IpAddr>().unwrap()
        );
        // recursive = false iken en sağdaki atlama döner
        assert_eq!(
            resolve_real_ip(proxy_peer, &headers_xff, "X-Forwarded-For", &trusted, false),
            "173.245.48.5".parse::<IpAddr>().unwrap()
        );
    }

    fn build_proxy_v2_packet(ver_cmd: u8, fam_proto: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + payload.len());
        out.extend_from_slice(&PROXY_V2_SIGNATURE);
        out.push(ver_cmd);
        out.push(fam_proto);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn test_proxy_v1_tcp4_valid_and_preserves_trailing_http() {
        let raw = b"PROXY TCP4 192.168.1.10 10.0.0.1 54321 443\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
        let hdr = parse_proxy_protocol_prefix(raw).unwrap().unwrap();
        assert_eq!(hdr.version, 1);
        assert_eq!(
            hdr.src_addr,
            Some("192.168.1.10:54321".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            hdr.dst_addr,
            Some("10.0.0.1:443".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(&raw[hdr.consumed_bytes..], b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    }

    #[test]
    fn test_proxy_v1_tcp6_and_unknown() {
        let v6 = b"PROXY TCP6 2001:db8::1 2001:db8::2 12345 8443\r\n";
        let hdr_v6 = parse_proxy_protocol_prefix(v6).unwrap().unwrap();
        assert_eq!(hdr_v6.version, 1);
        assert_eq!(
            hdr_v6.src_addr,
            Some("[2001:db8::1]:12345".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            hdr_v6.dst_addr,
            Some("[2001:db8::2]:8443".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(hdr_v6.consumed_bytes, v6.len());

        let unk = b"PROXY UNKNOWN\r\n";
        let hdr_unk = parse_proxy_protocol_prefix(unk).unwrap().unwrap();
        assert_eq!(hdr_unk.version, 1);
        assert_eq!(hdr_unk.src_addr, None);
        assert_eq!(hdr_unk.dst_addr, None);
        assert_eq!(hdr_unk.consumed_bytes, unk.len());

        let unk_extra = b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\n";
        let hdr_unk2 = parse_proxy_protocol_prefix(unk_extra).unwrap().unwrap();
        assert_eq!(hdr_unk2.version, 1);
        assert_eq!(hdr_unk2.src_addr, None);
        assert_eq!(hdr_unk2.consumed_bytes, unk_extra.len());
    }

    #[test]
    fn test_proxy_v1_errors_crlf_too_long_and_invalid_fields() {
        // Eksik veri -> Incomplete
        assert_eq!(
            parse_proxy_protocol_prefix(b"PROXY TCP4 1.2.3.4"),
            Err(ProxyProtocolError::Incomplete)
        );
        assert_eq!(
            parse_proxy_protocol_prefix(b"PRO"),
            Err(ProxyProtocolError::Incomplete)
        );

        // Yalnız LF (CRLF yok) -> InvalidHeader
        assert!(matches!(
            parse_proxy_protocol_prefix(b"PROXY TCP4 1.2.3.4 5.6.7.8 80 443\n"),
            Err(ProxyProtocolError::InvalidHeader(_))
        ));

        // 108 baytı aşan satır -> TooLong
        let too_long = format!("PROXY UNKNOWN {}\r\n", "a".repeat(100));
        assert_eq!(
            parse_proxy_protocol_prefix(too_long.as_bytes()),
            Err(ProxyProtocolError::TooLong)
        );

        // Geçersiz port (+80) ve TCP4 içinde IPv6
        assert!(matches!(
            parse_proxy_protocol_prefix(b"PROXY TCP4 1.2.3.4 5.6.7.8 +80 443\r\n"),
            Err(ProxyProtocolError::InvalidHeader(_))
        ));
        assert!(matches!(
            parse_proxy_protocol_prefix(b"PROXY TCP4 ::1 ::2 80 443\r\n"),
            Err(ProxyProtocolError::InvalidHeader(_))
        ));
    }

    #[test]
    fn test_proxy_v2_ipv4_ipv6_with_tlvs_and_local() {
        // IPv4 + 4 bayt TLV
        let mut payload4 = vec![
            198, 51, 100, 7, // src 198.51.100.7
            10, 0, 0, 5,     // dst 10.0.0.5
        ];
        payload4.extend_from_slice(&50000u16.to_be_bytes());
        payload4.extend_from_slice(&443u16.to_be_bytes());
        payload4.extend_from_slice(&[0x01, 0x00, 0x01, 0xAA]); // TLV atlanmalı
        let mut pkt4 = build_proxy_v2_packet(0x21, 0x11, &payload4);
        pkt4.extend_from_slice(b"\x16\x03\x01"); // devamındaki TLS ClientHello başlangıcı

        let hdr4 = parse_proxy_protocol_prefix(&pkt4).unwrap().unwrap();
        assert_eq!(hdr4.version, 2);
        assert_eq!(
            hdr4.src_addr,
            Some("198.51.100.7:50000".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            hdr4.dst_addr,
            Some("10.0.0.5:443".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(hdr4.consumed_bytes, 16 + payload4.len());
        assert_eq!(&pkt4[hdr4.consumed_bytes..], b"\x16\x03\x01");

        // IPv6 + 3 bayt TLV
        let src6: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let dst6: Ipv6Addr = "2001:db8::20".parse().unwrap();
        let mut payload6 = Vec::new();
        payload6.extend_from_slice(&src6.octets());
        payload6.extend_from_slice(&dst6.octets());
        payload6.extend_from_slice(&44444u16.to_be_bytes());
        payload6.extend_from_slice(&8443u16.to_be_bytes());
        payload6.extend_from_slice(&[0x03, 0x00, 0x00]); // 3 bayt TLV
        let pkt6 = build_proxy_v2_packet(0x21, 0x21, &payload6);

        let hdr6 = parse_proxy_protocol_prefix(&pkt6).unwrap().unwrap();
        assert_eq!(hdr6.version, 2);
        assert_eq!(hdr6.src_addr, Some(SocketAddr::new(IpAddr::V6(src6), 44444)));
        assert_eq!(hdr6.dst_addr, Some(SocketAddr::new(IpAddr::V6(dst6), 8443)));
        assert_eq!(hdr6.consumed_bytes, pkt6.len());

        // LOCAL (0x20) + AF_UNSPEC (0x00)
        let pkt_local = build_proxy_v2_packet(0x20, 0x00, &[]);
        let hdr_local = parse_proxy_protocol_prefix(&pkt_local).unwrap().unwrap();
        assert_eq!(hdr_local.version, 2);
        assert_eq!(hdr_local.src_addr, None);
        assert_eq!(hdr_local.dst_addr, None);
        assert_eq!(hdr_local.consumed_bytes, 16);
    }

    #[test]
    fn test_proxy_v2_incomplete_corrupt_and_non_proxy() {
        // Kısmi v2 imzası -> Incomplete
        assert_eq!(
            parse_proxy_protocol_prefix(&PROXY_V2_SIGNATURE[..6]),
            Err(ProxyProtocolError::Incomplete)
        );
        // Tam imza ama 16 bayttan kısa -> Incomplete
        assert_eq!(
            parse_proxy_protocol_prefix(&PROXY_V2_SIGNATURE),
            Err(ProxyProtocolError::Incomplete)
        );
        // İmza + 16 bayt var ama payload eksik -> Incomplete
        let pkt_partial = build_proxy_v2_packet(0x21, 0x11, &[1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0, 2]);
        assert_eq!(
            parse_proxy_protocol_prefix(&pkt_partial[..20]),
            Err(ProxyProtocolError::Incomplete)
        );

        // Bozuk komut (0x22) -> InvalidHeader
        let bad_cmd = build_proxy_v2_packet(0x22, 0x11, &[0; 12]);
        assert!(matches!(
            parse_proxy_protocol_prefix(&bad_cmd),
            Err(ProxyProtocolError::InvalidHeader(_))
        ));

        // AF_INET ama payload 12 bayttan kısa -> InvalidHeader
        let short_v4 = build_proxy_v2_packet(0x21, 0x11, &[1, 2, 3, 4]);
        assert!(matches!(
            parse_proxy_protocol_prefix(&short_v4),
            Err(ProxyProtocolError::InvalidHeader(_))
        ));

        // Payload > 1024 bayt -> TooLong
        let mut too_big = Vec::from(PROXY_V2_SIGNATURE);
        too_big.push(0x21);
        too_big.push(0x00);
        too_big.extend_from_slice(&2048u16.to_be_bytes());
        assert_eq!(
            parse_proxy_protocol_prefix(&too_big),
            Err(ProxyProtocolError::TooLong)
        );

        // Normal HTTP ve TLS ClientHello -> Ok(None)
        assert_eq!(
            parse_proxy_protocol_prefix(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            Ok(None)
        );
        assert_eq!(
            parse_proxy_protocol_prefix(b"\x16\x03\x01\x02\x00\x01"),
            Ok(None)
        );
    }

    #[tokio::test]
    async fn test_read_proxy_protocol_header_async_stream_and_passthru() {
        // 1. Parçalı v2 başlığı + devamında HTTP isteği
        let (mut c1, mut s1) = tokio::io::duplex(4096);
        let payload = [192, 0, 2, 55, 198, 51, 100, 1, 0x10, 0x00, 0x01, 0xBB];
        let mut pkt = build_proxy_v2_packet(0x21, 0x11, &payload);
        pkt.extend_from_slice(b"GET /ok HTTP/1.1\r\nHost: a\r\n\r\n");

        tokio::spawn(async move {
            c1.write_all(&pkt[..8]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
            c1.write_all(&pkt[8..]).await.unwrap();
        });

        let mut prebuf = bytes::BytesMut::new();
        let hdr = read_proxy_protocol_header(&mut s1, &mut prebuf, Duration::from_secs(1))
            .await
            .unwrap()
            .expect("PROXY v2 okunmalı");
        assert_eq!(hdr.version, 2);
        assert_eq!(
            hdr.src_addr,
            Some("192.0.2.55:4096".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(&prebuf[..], b"GET /ok HTTP/1.1\r\nHost: a\r\n\r\n");

        // 2. PROXY olmayan normal HTTP akışı -> Ok(None) ve prebuf bozulmamalı
        let (mut c2, mut s2) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            c2.write_all(b"GET /plain HTTP/1.1\r\nHost: a\r\n\r\n")
                .await
                .unwrap();
        });
        let mut prebuf2 = bytes::BytesMut::new();
        let res2 = read_proxy_protocol_header(&mut s2, &mut prebuf2, Duration::from_secs(1))
            .await
            .unwrap();
        assert!(res2.is_none());
        assert_eq!(&prebuf2[..], b"GET /plain HTTP/1.1\r\nHost: a\r\n\r\n");
    }

    async fn assert_http1_bad_request(raw: &[u8]) {
        let mut hbuf = [httparse::EMPTY_HEADER; 32];
        assert!(
            parse_request(raw, &mut hbuf).is_err(),
            "parse_request reddetmeliydi: {:?}",
            String::from_utf8_lossy(raw)
        );

        let (mut client, mut server) = tokio::io::duplex(4096);
        let bytes = raw.to_vec();
        tokio::spawn(async move {
            let _ = client.write_all(&bytes).await;
        });
        let err = read_http1_request(&mut server, HttpReadLimits::default())
            .await
            .expect_err("read_http1_request reddetmeliydi");
        assert!(matches!(err, HttpReadError::BadRequest(_)));
        assert_eq!(err.status_code(), 400);
    }

    #[tokio::test]
    async fn test_smuggling_content_length_variants_rejected() {
        for bad in [
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nhello"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: -1\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1 0\r\n\r\n1234567890"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: \x0b5\r\n\r\nhello"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"[..],
        ] {
            assert_http1_bad_request(bad).await;
        }
    }

    #[tokio::test]
    async fn test_smuggling_cl_te_and_invalid_transfer_encoding_rejected() {
        for bad in [
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: identity\r\n\r\nhello"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked,\r\n\r\n0\r\n\r\n"[..],
        ] {
            assert_http1_bad_request(bad).await;
        }
    }

    #[tokio::test]
    async fn test_smuggling_duplicate_or_empty_host_and_control_chars_rejected() {
        for bad in [
            &b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: a.test\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost:   \r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Test: foo\0bar\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Bad Name: val\r\n\r\n"[..],
        ] {
            assert_http1_bad_request(bad).await;
        }

        // Doğrudan başlık doğrulamasında CR/LF/NUL kontrolü
        let cr_hdr = [
            httparse::Header {
                name: "Host",
                value: b"a.test",
            },
            httparse::Header {
                name: "X-Inject",
                value: b"v1\r\nX-Evil: 1",
            },
        ];
        assert!(validate_http_headers(1, &cr_hdr).is_err());

        let lf_name = [
            httparse::Header {
                name: "Host",
                value: b"a.test",
            },
            httparse::Header {
                name: "X-Bad\nName",
                value: b"v1",
            },
        ];
        assert!(validate_http_headers(1, &lf_name).is_err());
    }

    #[tokio::test]
    async fn test_proxy_protocol_timeout_eof_and_valid_edge_cases() {
        // 1. Timeout hatası
        let (_c_to, mut s_to) = tokio::io::duplex(4096);
        let mut pre_to = bytes::BytesMut::new();
        let err_to = read_proxy_protocol_header(&mut s_to, &mut pre_to, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert_eq!(err_to.kind(), std::io::ErrorKind::TimedOut);

        // 2. Yarım kalmış PROXY v1 başlığıyla EOF -> UnexpectedEof
        let (mut c_eof, mut s_eof) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            c_eof.write_all(b"PROXY TCP4 1.2.3.4").await.unwrap();
            c_eof.shutdown().await.unwrap();
        });
        let mut pre_eof = bytes::BytesMut::new();
        let err_eof = read_proxy_protocol_header(&mut s_eof, &mut pre_eof, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(err_eof.kind(), std::io::ErrorKind::UnexpectedEof);

        // 3. Aynı Content-Length (5 + 5) ve IPv6 Host kabul edilmeli
        let (mut c_ok, mut s_ok) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            c_ok.write_all(
                b"POST /ok HTTP/1.1\r\nHost: [::1]:8443\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            )
            .await
            .unwrap();
        });
        let req = read_http1_request(&mut s_ok, HttpReadLimits::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(req.host, "[::1]:8443");
        assert_eq!(req.body, b"hello");
    }
}
