use zmax_static::percent_decode_path;

/// ACME HTTP-01 dogrulama yolu (force_https yonlendirmesinden muaf).
pub fn is_acme_challenge(path: &str) -> bool {
    percent_decode_path(path)
        .map(|p| p.starts_with("/.well-known/acme-challenge/"))
        .unwrap_or_else(|| path.starts_with("/.well-known/acme-challenge/"))
}

/// `https://ayni-host/ayni-yol?sorgu` adresini uretir. HTTPS portu 443 degilse porta eklenir.
pub fn https_redirect_location(
    host_header: &str,
    path: &str,
    query: &str,
    https_port: u16,
) -> Option<String> {
    let host = host_header.trim();
    let hostname = if host.starts_with('[') {
        &host[..=host.find(']')?]
    } else {
        host.split(':').next().unwrap_or("")
    };
    if hostname.is_empty()
        || !hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':' | '_'))
    {
        return None;
    }
    let authority = if https_port == 443 {
        hostname.to_string()
    } else {
        format!("{}:{}", hostname, https_port)
    };
    let path = if path.is_empty() { "/" } else { path };
    Some(if query.is_empty() {
        format!("https://{}{}", authority, path)
    } else {
        format!("https://{}{}?{}", authority, path, query)
    })
}
