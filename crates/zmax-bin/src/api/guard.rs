//! Panel yolu normalizasyonu ve sorgu/yüzde-çözme yardımcıları.

pub(crate) fn percent_decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(h), Some(l)) = (
                    (bytes[i + 1] as char).to_digit(16),
                    (bytes[i + 2] as char).to_digit(16),
                ) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_query_param(query: &str, key: &str) -> Option<String> {
    let trimmed = query.strip_prefix('?').unwrap_or(query);
    if trimmed.is_empty() {
        return None;
    }
    for pair in trimmed.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if percent_decode_component(raw_k) == key {
            return Some(percent_decode_component(raw_v));
        }
    }
    None
}

/// Ters vekil arkasındaki panel/API isteklerinden yapılandırılmış `proxy_prefix` önekini soyar.
pub fn normalize_panel_request_path(raw_path: &str, proxy_prefix: &str) -> String {
    let prefix = proxy_prefix.trim().trim_end_matches('/');
    if prefix.is_empty() || prefix == "/" {
        return raw_path.to_string();
    }
    if raw_path == prefix {
        return "/".to_string();
    }
    if let Some(rest) = raw_path.strip_prefix(prefix) {
        if rest.is_empty() || rest == "/" {
            return "/".to_string();
        }
        if rest.starts_with('/') {
            return rest.to_string();
        }
    }
    raw_path.to_string()
}
