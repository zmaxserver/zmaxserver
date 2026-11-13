use super::http_write::{default_status_reason, write_http_response};
use tokio::io::AsyncWrite;
use zmax_cache::CachedResponse;
use zmax_header::SecurityHeadersPolicy;

#[allow(clippy::too_many_arguments)]
pub(super) async fn write_cached_php_response<S>(
    socket: &mut S,
    cached: &CachedResponse,
    wants_gzip: bool,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_ref: Option<&SecurityHeadersPolicy>,
    cache_label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let mut hdrs = vec![("Content-Type".into(), cached.content_type.clone())];
    if wants_gzip && cached.tags.iter().any(|t| t == "__enc:gzip") {
        hdrs.push(("Content-Encoding".into(), "gzip".into()));
        hdrs.push(("Vary".into(), "Accept-Encoding".into()));
    }
    write_http_response(
        socket,
        cached.status,
        default_status_reason(cached.status),
        &hdrs,
        &cached.body,
        None,
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_ref,
        Some(cache_label),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn write_cached_static_response<S>(
    socket: &mut S,
    cached: &CachedResponse,
    wants_gzip: bool,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_ref: Option<&SecurityHeadersPolicy>,
    cache_label: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let mut hdrs = vec![
        ("Content-Type".into(), cached.content_type.clone()),
        ("Accept-Ranges".into(), "bytes".into()),
    ];
    if let Some(etag) = cached.tags.iter().find_map(|t| t.strip_prefix("__etag:")) {
        hdrs.push(("ETag".into(), etag.to_string()));
    }
    if let Some(lm) = cached.tags.iter().find_map(|t| t.strip_prefix("__lm:")) {
        hdrs.push(("Last-Modified".into(), lm.to_string()));
    }
    let has_gz = wants_gzip && cached.tags.iter().any(|t| t == "__enc:gzip");
    if has_gz {
        hdrs.push(("Content-Encoding".into(), "gzip".into()));
    }
    let has_vary_accept = cached.tags.iter().any(|t| t == "__vary:accept");
    match (has_gz, has_vary_accept) {
        (true, true) => hdrs.push(("Vary".into(), "Accept-Encoding, Accept".into())),
        (true, false) => hdrs.push(("Vary".into(), "Accept-Encoding".into())),
        (false, true) => hdrs.push(("Vary".into(), "Accept".into())),
        (false, false) => {}
    }
    write_http_response(
        socket,
        cached.status,
        default_status_reason(cached.status),
        &hdrs,
        &cached.body,
        None,
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_ref,
        Some(cache_label),
    )
    .await
}
