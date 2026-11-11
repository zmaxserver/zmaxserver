//! # ZMax Web Trafik Motoru
//! HTTP/1.1 Keep-Alive döngüsü, WAF/Rate-Limit/WP Kalkanı, Rewrite/`.htaccess`,
//! Reverse Proxy + WebSocket, FastCGI (PHP), Range/ETag/Gzip Statik Sunum ve L1/L2 Önbellek.

pub use crate::api::ParsedHttpRequest;
use crate::api::{read_http_request_with_limits, send_http_read_error, ServerState};
use crate::modules_runtime::{
    append_access_log_limit, append_error_log_limit,
    resolve_vhost_security_headers, select_negotiated_image_path,
};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zmax_cache::{build_cache_key, CacheLookup, CachedResponse, StampedeSlot};
use zmax_compress::{gzip_compress, is_compressible_mime, negotiate_encoding, ContentEncoding};
use zmax_config::match_vhost;
use zmax_fastcgi::{FastCgiClient, FastCgiParamsBuilder};
use zmax_header::SecurityHeadersPolicy;
use zmax_httpparser::{extract_header, resolve_real_ip, HttpReadLimits};
use zmax_proxy::{rewrite_request_head_with_options, ProxyRewriteOptions, ReverseProxy};
use zmax_rewrite::{HtAccessResolver, RewriteEngine, RouteOutcome, RouteRequest};
use zmax_security::IpAccessList;
use zmax_static::{
    check_if_none_match, parse_byte_range, percent_decode_path, ByteRangeResult, StaticFileHandler,
};
use zmax_timeout::with_idle_timeout;

const MAX_STATIC_CACHE_BYTES: usize = 2 * 1024 * 1024;
const MAX_GZIP_IN_MEMORY_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_LOG_MAX_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct LogMeta {
    pub domain: Option<String>,
    pub custom_log_path: Option<PathBuf>,
    pub json_format: bool,
    pub also_write_global: bool,
    pub max_log_size_bytes: u64,
}

#[derive(Clone)]
pub struct ResolvedVHostContext {
    pub doc_root: PathBuf,
    pub index_files: Vec<String>,
    pub php_enabled: bool,
    pub php_upstream: String,
    pub php_upstreams: Vec<String>,
    pub php_lb_policy: String,
    pub php_timeout: u64,
    pub cache_enabled: bool,
    pub cache_expire: u64,
    pub cache_stale_sec: u64,
    pub vhost_name: String,
    pub vhost_aliases: Vec<String>,
    pub force_https: bool,
    pub hotlink_protection: bool,
    pub hotlink_config: zmax_config::HotlinkConfig,
    pub global_acl: IpAccessList,
    pub vhost_acl: IpAccessList,
    pub vhost_acl_engine: zmax_security::VhostAcl,
    pub rewrite_enabled: bool,
    pub rewrite_try_files: bool,
    pub rewrite_htaccess: bool,
    pub rewrite_rules: Vec<zmax_config::VHostRewriteRule>,
    pub proxy_enabled: bool,
    pub proxy_upstream: String,
    pub proxy_path_prefix: String,
    pub proxy_preserve_host: bool,
    pub proxy_websocket: bool,
    auto_webp: bool,
    auto_avif: bool,
    etag_enabled: bool,
    last_modified_header: bool,
    max_log_size_bytes: u64,
    headers_policy: Option<SecurityHeadersPolicy>,
    // 8-Madde Alanlari
    pub waf_enabled: Option<bool>,
    pub waf_exclude_paths: Vec<String>,
    pub error_docs: zmax_config::VHostErrorDocsSection,
    pub logging: zmax_config::VHostLoggingSection,
    pub tls_http2: bool,
}

/// Ana Web Trafiği Yöneticisi (HTTP/1.1 Keep-Alive destekli).
pub async fn handle_web_connection<S>(
    mut socket: S,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
    is_https: bool,
    server_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut leftover = Vec::with_capacity(4096);
    let mut req_index = 0usize;

    loop {
        let (
            header_timeout_sec,
            body_timeout_sec,
            keep_alive_timeout_sec,
            max_header_bytes,
            max_body_bytes,
        ) = {
            let rt = state.runtime.read().await;
            let sec = &rt.config.security;
            let web_max_mb = sec.max_body_size_mb.max(1);
            (
                sec.slowloris_header_timeout_sec.max(2),
                sec.slowloris_body_timeout_sec.max(5),
                sec.keep_alive_timeout_sec.max(1),
                sec.max_header_size_kb.max(8) * 1024,
                web_max_mb * 1024 * 1024,
            )
        };

        // Keep-Alive bağlantı ikinci veya sonraki isteği boşta beklerken idle timeout uygular.
        if req_index > 0 && leftover.is_empty() {
            let mut pool_buf = state.buffer_pool.acquire();
            if pool_buf.capacity() < 4096 {
                pool_buf.reserve(4096);
            }
            let cap = pool_buf.capacity().min(8192);
            pool_buf.resize(cap, 0);
            let idle_res = with_idle_timeout(
                Duration::from_secs(keep_alive_timeout_sec),
                socket.read(&mut pool_buf[..]),
            )
            .await;

            match idle_res {
                Ok(Ok(n)) if n > 0 => {
                    leftover.extend_from_slice(&pool_buf[..n]);
                    state.buffer_pool.release(pool_buf);
                }
                _ => {
                    state.buffer_pool.release(pool_buf);
                    break;
                }
            }
        }

        let limits = HttpReadLimits {
            max_header_bytes,
            max_body_bytes,
            header_timeout: Duration::from_secs(header_timeout_sec),
            body_timeout: Duration::from_secs(body_timeout_sec),
        };

        let req = match read_http_request_with_limits(&mut socket, &mut leftover, limits).await {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(err) => {
                send_http_read_error(&mut socket, &err).await;
                break;
            }
        };

        req_index += 1;
        let should_keep_alive = handle_single_web_request(
            &mut socket,
            peer_addr,
            &state,
            is_https,
            server_port,
            keep_alive_timeout_sec,
            req,
        )
        .await?;

        if !should_keep_alive {
            break;
        }
    }

    Ok(())
}

async fn handle_single_web_request<S>(
    socket: &mut S,
    peer_addr: SocketAddr,
    state: &Arc<ServerState>,
    is_https: bool,
    server_port: u16,
    keep_alive_timeout_sec: u64,
    req: ParsedHttpRequest,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let started = Instant::now();
    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);

    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let keep_alive = req.keep_alive;

    let (policies, redis_client, vhost_ctx) = {
        let rt = state.runtime.read().await;
        let policies = rt.policies.clone();
        let redis_client = rt.redis_client.clone();
        let vh_opt = match_vhost(&rt.vhosts, &req.host);
        let global_acl = IpAccessList::new(
            rt.config.security.allow_ips.clone(),
            rt.config.security.deny_ips.clone(),
        );
        let max_log_size_bytes = rt
            .config
            .logging
            .max_log_size_mb
            .saturating_mul(1024 * 1024);
        let max_log_size_bytes = if max_log_size_bytes == 0 {
            DEFAULT_LOG_MAX_BYTES
        } else {
            max_log_size_bytes
        };
        let cache_stale_sec = rt.config.cache.stale_while_revalidate_sec;
        let ctx = match vh_opt {
            Some(vh) => {
                let sec_headers = resolve_vhost_security_headers(
                    policies.headers_enabled,
                    &policies.security_headers,
                    Some(&vh.entry),
                );
                ResolvedVHostContext {
                    doc_root: vh.resolved_doc_root.clone(),
                    index_files: vh.entry.index_files.clone(),
                    php_enabled: vh.entry.php.enabled && policies.fastcgi.enabled,
                    php_upstream: if vh.entry.php.upstream.trim().is_empty() {
                        policies.fastcgi.default_upstream.clone()
                    } else {
                        vh.entry.php.upstream.clone()
                    },
                    php_timeout: vh
                        .entry
                        .php
                        .timeout
                        .max(policies.fastcgi.timeout_sec)
                        .max(5),
                    cache_enabled: vh.entry.cache.enabled && rt.config.cache.enabled,
                    cache_expire: vh.entry.cache.expire.max(1),
                    cache_stale_sec,
                    vhost_name: vh.entry.name.clone(),
                    vhost_aliases: vh.entry.aliases.clone(),
                    force_https: vh.entry.security.force_https,
                    hotlink_protection: vh.entry.effective_hotlink().enabled,
                    hotlink_config: vh.entry.effective_hotlink(),
                    global_acl: global_acl.clone(),
                    vhost_acl: IpAccessList::new(
                        vh.entry.security.allow_ips.clone(),
                        vh.entry.security.deny_ips.clone(),
                    ),
                    vhost_acl_engine: zmax_security::VhostAcl::new(
                        vh.entry.effective_acl().allow_ips,
                        vh.entry.effective_acl().deny_ips,
                    ),
                    rewrite_enabled: vh.entry.rewrite.enabled && policies.rewrite_enabled,
                    rewrite_try_files: vh.entry.rewrite.try_files,
                    rewrite_htaccess: vh.entry.rewrite.htaccess && policies.rewrite_htaccess,
                    proxy_enabled: vh.entry.proxy.enabled && policies.proxy.enabled,
                    proxy_upstream: vh.entry.proxy.upstream.clone(),
                    proxy_path_prefix: if vh.entry.proxy.path_prefix.trim().is_empty() {
                        "/".to_string()
                    } else {
                        vh.entry.proxy.path_prefix.clone()
                    },
                    proxy_preserve_host: vh.entry.proxy.preserve_host
                        && policies.proxy.preserve_host,
                    proxy_websocket: vh.entry.proxy.websocket && policies.proxy.websocket_upgrade,
                    auto_webp: policies.static_policy.auto_webp,
                    auto_avif: policies.static_policy.auto_avif,
                    etag_enabled: policies.static_policy.etag_enabled,
                    last_modified_header: policies.static_policy.last_modified_header,
                    max_log_size_bytes,
                    headers_policy: sec_headers,
                    php_upstreams: vh.entry.php.upstreams.clone(),
                    php_lb_policy: vh.entry.php.lb_policy.clone(),
                    rewrite_rules: vh.entry.rewrite.rules.clone(),
                    waf_enabled: vh.entry.security.waf_enabled,
                    waf_exclude_paths: vh.entry.security.waf_exclude_paths.clone(),
                    error_docs: vh.entry.error_docs.clone(),
                    logging: vh.entry.logging.clone(),
                    tls_http2: vh.entry.tls.http2,
                }
            }
            None => ResolvedVHostContext {
                doc_root: state.base_dir.join("www").join("html"),
                index_files: vec![
                    "index.html".to_string(),
                    "index.htm".to_string(),
                    "index.php".to_string(),
                ],
                php_enabled: false,
                php_upstream: policies.fastcgi.default_upstream.clone(),
                php_timeout: policies.fastcgi.timeout_sec.max(5),
                cache_enabled: rt.config.cache.enabled,
                cache_expire: rt.config.cache.default_ttl_seconds.max(1),
                cache_stale_sec,
                vhost_name: "default".to_string(),
                vhost_aliases: Vec::new(),
                force_https: false,
                hotlink_protection: false,
                hotlink_config: zmax_config::HotlinkConfig::default(),
                global_acl,
                vhost_acl: IpAccessList::default(),
                vhost_acl_engine: zmax_security::VhostAcl::default(),
                rewrite_enabled: policies.rewrite_enabled,
                rewrite_try_files: true,
                rewrite_htaccess: policies.rewrite_htaccess,
                proxy_enabled: false,
                proxy_upstream: String::new(),
                proxy_path_prefix: "/".to_string(),
                proxy_preserve_host: true,
                proxy_websocket: true,
                auto_webp: policies.static_policy.auto_webp,
                auto_avif: policies.static_policy.auto_avif,
                etag_enabled: policies.static_policy.etag_enabled,
                last_modified_header: policies.static_policy.last_modified_header,
                max_log_size_bytes,
                headers_policy: resolve_vhost_security_headers(
                    policies.headers_enabled,
                    &policies.security_headers,
                    None,
                ),
                php_upstreams: Vec::new(),
                php_lb_policy: "least_conn".to_string(),
                rewrite_rules: Vec::new(),
                waf_enabled: None,
                waf_exclude_paths: Vec::new(),
                error_docs: zmax_config::VHostErrorDocsSection::default(),
                logging: zmax_config::VHostLoggingSection::default(),
                tls_http2: true,
            },
        };
        (policies, redis_client, ctx)
    };

    let real_ip: IpAddr = if policies.realip.enabled {
        resolve_real_ip(
            peer_addr.ip(),
            &req.headers,
            &policies.realip.header_name,
            &policies.realip.trusted_proxies,
            policies.realip.recursive,
        )
    } else {
        peer_addr.ip()
    };
    let real_ip_str = real_ip.to_string();
    let https_port = {
        let rt = state.runtime.read().await;
        rt.config.listeners.https.port
    };
    let sec_ref = vhost_ctx.headers_policy.as_ref();
    let referer_hdr = extract_header(&req.headers, "referer");
    let ua_hdr = extract_header(&req.headers, "user-agent");
    let req_id = if state.runtime.read().await.config.logging.add_request_id {
        zmax_security::generate_request_id()
    } else {
        String::new()
    };

    // 1. Yasaklı IP, CIDR ACL (allow/deny) & Rate Limit Denetimi
    if state.ban_manager.is_banned(peer_addr.ip()) || state.ban_manager.is_banned(real_ip) {
        let err_body = b"403 Forbidden - IP Blocked";
        write_http_response(
            socket,
            403,
            "Forbidden",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            err_body,
            None,
            is_head,
            is_https,
            false,
            keep_alive_timeout_sec,
            sec_ref,
            None,
        )
        .await?;
        record_and_log(
            state,
            &real_ip_str,
            &req.method,
            &req.path,
            403,
            started,
            Some(&vhost_ctx),
            err_body.len(),
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(false);
    }

    if (!vhost_ctx.global_acl.is_empty() && !vhost_ctx.global_acl.is_allowed(real_ip))
        || (!vhost_ctx.vhost_acl.is_empty() && !vhost_ctx.vhost_acl.is_allowed(real_ip))
    {
        append_error_log_limit(
            &state.base_dir,
            &format!(
                "[ACL] {} {} {} -> IP Access Denied",
                real_ip_str, req.method, req.path
            ),
            vhost_ctx.max_log_size_bytes,
        )
        .await;
        let err_body = b"403 Forbidden - IP Access Denied";
        write_http_response(
            socket,
            403,
            "Forbidden",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            err_body,
            None,
            is_head,
            is_https,
            false,
            keep_alive_timeout_sec,
            sec_ref,
            None,
        )
        .await?;
        record_and_log(
            state,
            &real_ip_str,
            &req.method,
            &req.path,
            403,
            started,
            Some(&vhost_ctx),
            err_body.len(),
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(false);
    }

    {
        let limiter = state.limiter.read().await;
        if !limiter.check_allowed(real_ip) {
            let err_body = b"Too Many Requests!";
            write_http_response(
                socket,
                429,
                "Too Many Requests",
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                err_body,
                None,
                is_head,
                is_https,
                false,
                keep_alive_timeout_sec,
                sec_ref,
                None,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                429,
                started,
                Some(&vhost_ctx),
                err_body.len(),
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            return Ok(false);
        }
    }

    // 2. WAF / Alan Adina Ozel WAF Politikasi
    let vhost_waf_policy = zmax_security::VHostWafPolicy {
        waf_enabled: vhost_ctx.waf_enabled,
        exclude_paths: &vhost_ctx.waf_exclude_paths,
    };
    if let Err(violation) = policies.waf.inspector.inspect_with_policy(
        &req.method,
        &req.path,
        &req.query,
        &req.headers,
        &req.body,
        &vhost_waf_policy,
    ) {
        let err_line = format!(
            "[WAF] [{}] {} {} {} -> {}",
            vhost_ctx.vhost_name, real_ip_str, req.method, req.path, violation
        );
        append_error_log_limit(&state.base_dir, &err_line, vhost_ctx.max_log_size_bytes).await;
        let written_bytes = write_error_response(
            socket,
            403,
            "Forbidden",
            b"403 Forbidden - WAF Blocked",
            Some(&vhost_ctx),
            is_head,
            is_https,
            false,
            keep_alive_timeout_sec,
            sec_ref,
        )
        .await?;
        record_and_log(
            state,
            &real_ip_str,
            &req.method,
            &req.path,
            403,
            started,
            Some(&vhost_ctx),
            written_bytes,
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(false);
    }

    // 3. WordPress Brute-Force Koruması (/wp-login.php, /xmlrpc.php)
    if policies.waf.wp_brute_force_enabled
        && !state
            .wp_guard
            .check_and_ban(real_ip, &req.method, &req.path, &state.ban_manager)
    {
        if let Some(redis) = redis_client {
            let ip_s = real_ip_str.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(Duration::from_millis(200), redis.ban_ip(&ip_s, 900))
                    .await;
            });
        }
        let err_body = b"403 Forbidden - Brute Force Protection";
        write_http_response(
            socket,
            403,
            "Forbidden",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            err_body,
            None,
            is_head,
            is_https,
            false,
            keep_alive_timeout_sec,
            sec_ref,
            None,
        )
        .await?;
        record_and_log(
            state,
            &real_ip_str,
            &req.method,
            &req.path,
            403,
            started,
            Some(&vhost_ctx),
            err_body.len(),
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(false);
    }

    // 4. force_https: HTTP isteğini HTTPS'e yönlendir (ACME HTTP-01 muaf)
    if !is_https && vhost_ctx.force_https && !is_acme_challenge(&req.path) {
        if let Some(location) =
            https_redirect_location(&req.host, &req.path, &req.query, https_port)
        {
            write_http_response(
                socket,
                301,
                "Moved Permanently",
                &[("Location".into(), location)],
                b"",
                None,
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
                None,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                301,
                started,
                Some(&vhost_ctx),
                0,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            return Ok(keep_alive);
        }
    }

    // 5. Ters Proxy & WebSocket Yönlendirmesi (zmax-proxy + UpstreamSocketPool)
    if vhost_ctx.proxy_enabled
        && !vhost_ctx.proxy_upstream.trim().is_empty()
        && req.path.starts_with(&vhost_ctx.proxy_path_prefix)
    {
        let (status, still_alive, proxy_bytes) = serve_proxy_request(
            socket,
            state,
            &req,
            real_ip,
            is_https,
            &vhost_ctx,
            policies.proxy.connect_timeout_sec,
            keep_alive,
        )
        .await?;
        record_and_log(
            state,
            &real_ip_str,
            &req.method,
            &req.path,
            status,
            started,
            Some(&vhost_ctx),
            proxy_bytes,
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(still_alive);
    }

    // 6. Rewrite / .htaccess / try_files + PATH_INFO Yönlendirmesi
    let route_req = RouteRequest {
        doc_root: &vhost_ctx.doc_root,
        path: &req.path,
        query: &req.query,
        host: &req.host,
        https: is_https,
        method: &req.method,
        remote_addr: &real_ip_str,
        server_port,
        headers: &req.headers,
        index_files: &vhost_ctx.index_files,
        php_enabled: vhost_ctx.php_enabled,
        try_files_enabled: vhost_ctx.rewrite_enabled && vhost_ctx.rewrite_try_files,
    };

    let htaccess_resolver = if vhost_ctx.rewrite_enabled && vhost_ctx.rewrite_htaccess {
        HtAccessResolver::from_doc_root(&vhost_ctx.doc_root)
    } else {
        HtAccessResolver::from_htaccess(None)
    };
    let resolution =
        RewriteEngine::new().resolve_with_htaccess_info(&route_req, htaccess_resolver.htaccess());
    let path_info = resolution.path_info;
    let outcome = resolution.outcome;

    let wants_gzip = policies.gzip.enabled
        && negotiate_encoding(extract_header(&req.headers, "accept-encoding"))
            == ContentEncoding::Gzip;
    let has_range = extract_header(&req.headers, "range").is_some();
    let has_if_none_match = extract_header(&req.headers, "if-none-match").is_some();

    match outcome {
        RouteOutcome::Redirect { status, location } => {
            let reason = default_status_reason(status);
            write_http_response(
                socket,
                status,
                reason,
                &[("Location".into(), location)],
                b"",
                None,
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
                None,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                status,
                started,
                Some(&vhost_ctx),
                0,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            Ok(keep_alive)
        }
        RouteOutcome::Forbidden => {
            let written_bytes = write_error_response(
                socket,
                403,
                "Forbidden",
                b"403 Forbidden",
                Some(&vhost_ctx),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                403,
                started,
                Some(&vhost_ctx),
                written_bytes,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            Ok(keep_alive)
        }
        RouteOutcome::Gone => {
            let written_bytes = write_error_response(
                socket,
                410,
                "Gone",
                b"410 Gone",
                Some(&vhost_ctx),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                410,
                started,
                Some(&vhost_ctx),
                written_bytes,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            Ok(keep_alive)
        }
        RouteOutcome::PhpScript {
            path: script_path,
            query: effective_query,
        } => {
            let php_cacheable_req = vhost_ctx.cache_enabled
                && req.method.eq_ignore_ascii_case("GET")
                && !request_has_bypass_cookie_or_auth(&req.headers);

            let enc_label = if wants_gzip { "gzip" } else { "identity" };
            let cache_key = build_cache_key(
                &vhost_ctx.vhost_name,
                is_https,
                &req.method,
                &req.path,
                &effective_query,
                Some(enc_label),
            );

            let mut stampede_guard = None;
            if php_cacheable_req {
                match state.cache.get_with_stale(&cache_key).await {
                    CacheLookup::Fresh(cached) => {
                        state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                        // [kart-2] Cache HIT yanitinda HEAD/304/204 ise govde bayti 0; aksi halde onbellekteki govde boyutu
                        let cached_bytes =
                            if is_head || cached.status == 204 || cached.status == 304 {
                                0
                            } else {
                                cached.body.len()
                            };
                        write_cached_php_response(
                            socket,
                            &cached,
                            wants_gzip,
                            is_head,
                            is_https,
                            keep_alive,
                            keep_alive_timeout_sec,
                            sec_ref,
                            "HIT",
                        )
                        .await?;
                        record_and_log(
                            state,
                            &real_ip_str,
                            &req.method,
                            &req.path,
                            cached.status,
                            started,
                            Some(&vhost_ctx),
                            cached_bytes,
                            referer_hdr,
                            ua_hdr,
                            "HTTP/1.1",
                            &req_id,
                        )
                        .await;
                        return Ok(keep_alive);
                    }
                    CacheLookup::Stale(cached) => {
                        state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                        let cached_bytes =
                            if is_head || cached.status == 204 || cached.status == 304 {
                                0
                            } else {
                                cached.body.len()
                            };
                        if let StampedeSlot::Leader(guard) =
                            state.cache.try_acquire_fill(&cache_key)
                        {
                            let st_bg = Arc::clone(state);
                            let req_bg = req.clone();
                            let ctx_bg = vhost_ctx.clone();
                            let script_bg = script_path.clone();
                            let path_info_bg = path_info.clone();
                            let query_bg = effective_query.clone();
                            let gzip_bg = policies.gzip.clone();
                            let key_bg = cache_key.clone();
                            let max_obj = policies.cache_max_object_bytes;
                            let rport = peer_addr.port();
                            tokio::spawn(async move {
                                let _guard = guard;
                                let _ = fetch_and_cache_php(
                                    &st_bg,
                                    &req_bg,
                                    real_ip,
                                    rport,
                                    server_port,
                                    is_https,
                                    &ctx_bg,
                                    &script_bg,
                                    &path_info_bg,
                                    &query_bg,
                                    wants_gzip,
                                    &gzip_bg,
                                    true,
                                    &key_bg,
                                    max_obj,
                                )
                                .await;
                            });
                        }
                        write_cached_php_response(
                            socket,
                            &cached,
                            wants_gzip,
                            is_head,
                            is_https,
                            keep_alive,
                            keep_alive_timeout_sec,
                            sec_ref,
                            "STALE",
                        )
                        .await?;
                        record_and_log(
                            state,
                            &real_ip_str,
                            &req.method,
                            &req.path,
                            cached.status,
                            started,
                            Some(&vhost_ctx),
                            cached_bytes,
                            referer_hdr,
                            ua_hdr,
                            "HTTP/1.1",
                            &req_id,
                        )
                        .await;
                        return Ok(keep_alive);
                    }
                    CacheLookup::Miss => match state.cache.try_acquire_fill(&cache_key) {
                        StampedeSlot::Leader(guard) => {
                            stampede_guard = Some(guard);
                        }
                        StampedeSlot::Follower(notify) => {
                            let wait_dur = Duration::from_secs(vhost_ctx.php_timeout.min(10));
                            let _ = tokio::time::timeout(wait_dur, notify.notified()).await;
                            if let CacheLookup::Fresh(cached) | CacheLookup::Stale(cached) =
                                state.cache.get_with_stale(&cache_key).await
                            {
                                state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                                let cached_bytes =
                                    if is_head || cached.status == 204 || cached.status == 304 {
                                        0
                                    } else {
                                        cached.body.len()
                                    };
                                write_cached_php_response(
                                    socket,
                                    &cached,
                                    wants_gzip,
                                    is_head,
                                    is_https,
                                    keep_alive,
                                    keep_alive_timeout_sec,
                                    sec_ref,
                                    "HIT",
                                )
                                .await?;
                                record_and_log(
                                    state,
                                    &real_ip_str,
                                    &req.method,
                                    &req.path,
                                    cached.status,
                                    started,
                                    Some(&vhost_ctx),
                                    cached_bytes,
                                    referer_hdr,
                                    ua_hdr,
                                    "HTTP/1.1",
                                    &req_id,
                                )
                                .await;
                                return Ok(keep_alive);
                            }
                        }
                    },
                }
            }

            state.stats.cache_misses.fetch_add(1, Ordering::Relaxed);
            let (status, php_bytes) = serve_php_request(
                socket,
                state,
                &req,
                real_ip,
                peer_addr.port(),
                server_port,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                &vhost_ctx,
                &script_path,
                &path_info,
                &effective_query,
                wants_gzip,
                &policies.gzip,
                php_cacheable_req,
                &cache_key,
                policies.cache_max_object_bytes,
            )
            .await?;
            drop(stampede_guard);
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                status,
                started,
                Some(&vhost_ctx),
                php_bytes,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            Ok(keep_alive)
        }
        RouteOutcome::StaticFile {
            path: static_path,
            query: effective_query,
        } => {
            // [kart-5] hotlink kontrolü (vHost yapılandırmasından okunan listeler ve ortak boru hattı)
            if crate::security_pipeline::is_request_hotlink_blocked(
                &vhost_ctx,
                extract_header(&req.headers, "referer"),
                &req.host,
                &static_path,
            ) {
                let err_body = b"403 Forbidden - Hotlink Protection";
                write_http_response(
                    socket,
                    403,
                    "Forbidden",
                    &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                    err_body,
                    None,
                    is_head,
                    is_https,
                    false,
                    keep_alive_timeout_sec,
                    sec_ref,
                    None,
                )
                .await?;
                record_and_log(
                    state,
                    &real_ip_str,
                    &req.method,
                    &req.path,
                    403,
                    started,
                    Some(&vhost_ctx),
                    err_body.len(),
                    referer_hdr,
                    ua_hdr,
                    "HTTP/1.1",
                    &req_id,
                )
                .await;
                return Ok(keep_alive);
            }

            let accept_hdr = extract_header(&req.headers, "accept");
            let img_tag = negotiable_image_cache_tag(
                &static_path,
                accept_hdr,
                vhost_ctx.auto_avif,
                vhost_ctx.auto_webp,
            );
            let can_use_cache = vhost_ctx.cache_enabled
                && req.method.eq_ignore_ascii_case("GET")
                && !has_range
                && !has_if_none_match;
            let enc_label = format!(
                "{}{}",
                if wants_gzip { "gzip" } else { "identity" },
                img_tag
            );
            let cache_key = build_cache_key(
                &vhost_ctx.vhost_name,
                is_https,
                "GET",
                &static_path,
                &effective_query,
                Some(&enc_label),
            );

            let mut stampede_guard = None;
            if can_use_cache {
                match state.cache.get_with_stale(&cache_key).await {
                    CacheLookup::Fresh(cached) => {
                        state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                        // [kart-2] Cache HIT yanitinda HEAD/304/204 ise govde bayti 0; aksi halde onbellekteki govde boyutu
                        let cached_bytes =
                            if is_head || cached.status == 204 || cached.status == 304 {
                                0
                            } else {
                                cached.body.len()
                            };
                        write_cached_static_response(
                            socket,
                            &cached,
                            wants_gzip,
                            is_head,
                            is_https,
                            keep_alive,
                            keep_alive_timeout_sec,
                            sec_ref,
                            "HIT",
                        )
                        .await?;
                        record_and_log(
                            state,
                            &real_ip_str,
                            &req.method,
                            &req.path,
                            cached.status,
                            started,
                            Some(&vhost_ctx),
                            cached_bytes,
                            referer_hdr,
                            ua_hdr,
                            "HTTP/1.1",
                            &req_id,
                        )
                        .await;
                        return Ok(keep_alive);
                    }
                    CacheLookup::Stale(cached) => {
                        state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                        let cached_bytes =
                            if is_head || cached.status == 204 || cached.status == 304 {
                                0
                            } else {
                                cached.body.len()
                            };
                        if let StampedeSlot::Leader(guard) =
                            state.cache.try_acquire_fill(&cache_key)
                        {
                            let st_bg = Arc::clone(state);
                            let ctx_bg = vhost_ctx.clone();
                            let spath_bg = static_path.clone();
                            let accept_bg = accept_hdr.map(|s| s.to_string());
                            let gzip_bg = policies.gzip.clone();
                            let key_bg = cache_key.clone();
                            let max_obj = policies.cache_max_object_bytes;
                            tokio::spawn(async move {
                                let _guard = guard;
                                revalidate_static_cache(
                                    &st_bg,
                                    &ctx_bg,
                                    &spath_bg,
                                    accept_bg.as_deref(),
                                    wants_gzip,
                                    &gzip_bg,
                                    &key_bg,
                                    max_obj,
                                )
                                .await;
                            });
                        }
                        write_cached_static_response(
                            socket,
                            &cached,
                            wants_gzip,
                            is_head,
                            is_https,
                            keep_alive,
                            keep_alive_timeout_sec,
                            sec_ref,
                            "STALE",
                        )
                        .await?;
                        record_and_log(
                            state,
                            &real_ip_str,
                            &req.method,
                            &req.path,
                            cached.status,
                            started,
                            Some(&vhost_ctx),
                            cached_bytes,
                            referer_hdr,
                            ua_hdr,
                            "HTTP/1.1",
                            &req_id,
                        )
                        .await;
                        return Ok(keep_alive);
                    }
                    CacheLookup::Miss => match state.cache.try_acquire_fill(&cache_key) {
                        StampedeSlot::Leader(guard) => {
                            stampede_guard = Some(guard);
                        }
                        StampedeSlot::Follower(notify) => {
                            let _ = tokio::time::timeout(Duration::from_secs(5), notify.notified())
                                .await;
                            if let CacheLookup::Fresh(cached) | CacheLookup::Stale(cached) =
                                state.cache.get_with_stale(&cache_key).await
                            {
                                state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                                let cached_bytes =
                                    if is_head || cached.status == 204 || cached.status == 304 {
                                        0
                                    } else {
                                        cached.body.len()
                                    };
                                write_cached_static_response(
                                    socket,
                                    &cached,
                                    wants_gzip,
                                    is_head,
                                    is_https,
                                    keep_alive,
                                    keep_alive_timeout_sec,
                                    sec_ref,
                                    "HIT",
                                )
                                .await?;
                                record_and_log(
                                    state,
                                    &real_ip_str,
                                    &req.method,
                                    &req.path,
                                    cached.status,
                                    started,
                                    Some(&vhost_ctx),
                                    cached_bytes,
                                    referer_hdr,
                                    ua_hdr,
                                    "HTTP/1.1",
                                    &req_id,
                                )
                                .await;
                                return Ok(keep_alive);
                            }
                        }
                    },
                }
            }

            state.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

            let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
            let file_info = handler
                .resolve_with_index(&static_path, &vhost_ctx.index_files)
                // [kart-6] ACME challenge ve TLS reload
                .or_else(|| handler.resolve_acme_challenge(&static_path))
                .or_else(|| resolve_predecoded_static_file(&vhost_ctx.doc_root, &static_path));

            if let Some(info) = file_info {
                let (status, static_bytes) = serve_static_file(
                    socket,
                    state,
                    &req,
                    &info,
                    &vhost_ctx,
                    wants_gzip,
                    &policies.gzip,
                    can_use_cache,
                    &cache_key,
                    policies.cache_max_object_bytes,
                    is_head,
                    is_https,
                    keep_alive,
                    keep_alive_timeout_sec,
                )
                .await?;
                drop(stampede_guard);
                record_and_log(
                    state,
                    &real_ip_str,
                    &req.method,
                    &req.path,
                    status,
                    started,
                    Some(&vhost_ctx),
                    static_bytes,
                    referer_hdr,
                    ua_hdr,
                    "HTTP/1.1",
                    &req_id,
                )
                .await;
                return Ok(keep_alive);
            }

            drop(stampede_guard);
            let bytes_written = write_not_found(
                socket,
                Some(&vhost_ctx),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                404,
                started,
                Some(&vhost_ctx),
                bytes_written,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            Ok(keep_alive)
        }
        RouteOutcome::NotFound => {
            let bytes_written = write_not_found(
                socket,
                Some(&vhost_ctx),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                404,
                started,
                Some(&vhost_ctx),
                bytes_written,
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            Ok(keep_alive)
        }
    }
}

/// Önceden `zmax-rewrite` tarafından decode/doğrulanmış yolu (ör. dosya adında literal `%` varsa) çözer.
fn resolve_predecoded_static_file(
    doc_root: &Path,
    clean_path: &str,
) -> Option<zmax_static::StaticFileInfo> {
    let rel = clean_path.trim_matches('/');
    if rel.is_empty() || rel.contains('\0') || rel.contains('\\') || rel.contains("..") {
        return None;
    }
    let canon_root = std::fs::canonicalize(doc_root).ok()?;
    let canon_file = std::fs::canonicalize(doc_root.join(rel)).ok()?;
    if !canon_file.starts_with(&canon_root) || !canon_file.is_file() {
        return None;
    }
    let meta = std::fs::metadata(&canon_file).ok()?;
    let size = meta.len();
    let last_modified_secs = meta
        .modified()
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    Some(zmax_static::StaticFileInfo {
        path: canon_file,
        mime_type: StaticFileHandler::detect_mime(Path::new(rel)),
        size,
        etag: format!("\"{:x}-{:x}\"", size, last_modified_secs),
        last_modified_secs,
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve_static_file<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    orig_info: &zmax_static::StaticFileInfo,
    vhost_ctx: &ResolvedVHostContext,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    can_use_cache: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
) -> Result<(u16, usize), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let sec_ref = vhost_ctx.headers_policy.as_ref();
    let accept_hdr = extract_header(&req.headers, "accept");
    let mut info = orig_info.clone();
    let image_negotiation_candidate =
        (vhost_ctx.auto_avif || vhost_ctx.auto_webp) && is_negotiable_image_path(&orig_info.path);

    if image_negotiation_candidate {
        if let Some((alt_path, alt_mime)) = select_negotiated_image_path(
            &orig_info.path,
            accept_hdr,
            vhost_ctx.auto_avif,
            vhost_ctx.auto_webp,
        ) {
            if let Ok(meta) = std::fs::metadata(&alt_path) {
                let size = meta.len();
                let last_modified_secs = meta
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                info = zmax_static::StaticFileInfo {
                    path: alt_path,
                    mime_type: alt_mime,
                    size,
                    etag: format!("\"{:x}-{:x}\"", size, last_modified_secs),
                    last_modified_secs,
                };
            }
        }
    }

    let last_mod = info.last_modified_http();

    // 1. ETag / If-None-Match -> 304 Not Modified
    if vhost_ctx.etag_enabled && check_if_none_match(&req.headers, &info.etag) {
        let mut hdrs = vec![("Accept-Ranges".into(), "bytes".into())];
        hdrs.push(("ETag".into(), info.etag.clone()));
        if vhost_ctx.last_modified_header {
            hdrs.push(("Last-Modified".into(), last_mod));
        }
        if image_negotiation_candidate {
            hdrs.push(("Vary".into(), "Accept".into()));
        }
        write_http_response(
            socket,
            304,
            "Not Modified",
            &hdrs,
            b"",
            Some(0),
            true, // 304 gövdesizdir
            is_https,
            keep_alive,
            keep_alive_timeout_sec,
            sec_ref,
            None,
        )
        .await?;
        return Ok((304, 0));
    }

    // 2. Range başlığı -> 206 Partial Content veya 416 Range Not Satisfiable
    if let Some(range_val) = extract_header(&req.headers, "range") {
        match parse_byte_range(range_val, info.size) {
            ByteRangeResult::Single {
                start,
                end_inclusive,
            } => {
                let slice_len = (end_inclusive - start + 1) as usize;
                let mut hdrs = vec![
                    ("Content-Type".into(), info.mime_type.to_string()),
                    (
                        "Content-Range".into(),
                        format!("bytes {}-{}/{}", start, end_inclusive, info.size),
                    ),
                    ("Accept-Ranges".into(), "bytes".into()),
                ];
                if vhost_ctx.etag_enabled {
                    hdrs.push(("ETag".into(), info.etag.clone()));
                }
                if vhost_ctx.last_modified_header {
                    hdrs.push(("Last-Modified".into(), last_mod));
                }
                if image_negotiation_candidate {
                    hdrs.push(("Vary".into(), "Accept".into()));
                }
                if is_head {
                    write_http_response(
                        socket,
                        206,
                        "Partial Content",
                        &hdrs,
                        b"",
                        Some(slice_len),
                        true,
                        is_https,
                        keep_alive,
                        keep_alive_timeout_sec,
                        sec_ref,
                        None,
                    )
                    .await?;
                    // [kart-2] HEAD yanitlarinda govde gonderilmez; gercek bayt 0
                    return Ok((206, 0));
                }

                let mut file = tokio::fs::File::open(&info.path).await?;
                file.seek(std::io::SeekFrom::Start(start)).await?;
                if slice_len <= MAX_STATIC_CACHE_BYTES {
                    let mut part = Vec::with_capacity(slice_len);
                    let mut limited = file.take(slice_len as u64);
                    limited.read_to_end(&mut part).await?;
                    write_http_response(
                        socket,
                        206,
                        "Partial Content",
                        &hdrs,
                        &part,
                        Some(part.len()),
                        false,
                        is_https,
                        keep_alive,
                        keep_alive_timeout_sec,
                        sec_ref,
                        None,
                    )
                    .await?;
                } else {
                    write_http_head(
                        socket,
                        206,
                        "Partial Content",
                        &hdrs,
                        Some(slice_len),
                        is_https,
                        keep_alive,
                        keep_alive_timeout_sec,
                        sec_ref,
                        None,
                    )
                    .await?;
                    stream_file_range_pooled(socket, state, &mut file, slice_len as u64).await?;
                    let _ = socket.flush().await;
                    if !keep_alive {
                        let _ = socket.shutdown().await;
                    }
                }
                return Ok((206, slice_len));
            }
            ByteRangeResult::Unsatisfiable => {
                let hdrs = vec![
                    ("Content-Range".into(), format!("bytes */{}", info.size)),
                    ("Accept-Ranges".into(), "bytes".into()),
                ];
                write_http_response(
                    socket,
                    416,
                    "Range Not Satisfiable",
                    &hdrs,
                    b"",
                    Some(0),
                    is_head,
                    is_https,
                    keep_alive,
                    keep_alive_timeout_sec,
                    sec_ref,
                    None,
                )
                .await?;
                return Ok((416, 0));
            }
            ByteRangeResult::None => {}
        }
    }

    // 3. Tam dosya sunumu (HEAD isteğinde diskten gövdeyi okumaya gerek yok!)
    if is_head {
        let mut hdrs = vec![
            ("Content-Type".into(), info.mime_type.to_string()),
            ("Accept-Ranges".into(), "bytes".into()),
        ];
        if vhost_ctx.etag_enabled {
            hdrs.push(("ETag".into(), info.etag.clone()));
        }
        if vhost_ctx.last_modified_header {
            hdrs.push(("Last-Modified".into(), last_mod));
        }
        if image_negotiation_candidate {
            hdrs.push(("Vary".into(), "Accept".into()));
        }
        write_http_response(
            socket,
            200,
            "OK",
            &hdrs,
            b"",
            Some(info.size as usize),
            true,
            is_https,
            keep_alive,
            keep_alive_timeout_sec,
            sec_ref,
            Some("MISS"),
        )
        .await?;
        // [kart-2] HEAD yanitinda Content-Length gonderilir ancak gercek gonderilen govde bayti 0'dir
        return Ok((200, 0));
    }

    let can_try_gzip = wants_gzip
        && (info.size as usize) >= gzip_policy.min_length
        && (info.size as usize) <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(info.mime_type, &gzip_policy.mime_types);

    // Büyük ve sıkıştırılmayacak dosyaları RAM'e almadan 64 KiB havuzlu parçalarla akıt (OOM koruması).
    if (info.size as usize) > MAX_STATIC_CACHE_BYTES && !can_try_gzip {
        let mut hdrs = vec![
            ("Content-Type".into(), info.mime_type.to_string()),
            ("Accept-Ranges".into(), "bytes".into()),
        ];
        if vhost_ctx.etag_enabled {
            hdrs.push(("ETag".into(), info.etag.clone()));
        }
        if vhost_ctx.last_modified_header {
            hdrs.push(("Last-Modified".into(), last_mod));
        }
        if image_negotiation_candidate {
            hdrs.push(("Vary".into(), "Accept".into()));
        } else if gzip_policy.vary_header {
            hdrs.push(("Vary".into(), "Accept-Encoding".into()));
        }

        write_http_head(
            socket,
            200,
            "OK",
            &hdrs,
            Some(info.size as usize),
            is_https,
            keep_alive,
            keep_alive_timeout_sec,
            sec_ref,
            Some("BYPASS"),
        )
        .await?;
        let mut file = tokio::fs::File::open(&info.path).await?;
        stream_file_range_pooled(socket, state, &mut file, info.size).await?;
        let _ = socket.flush().await;
        if !keep_alive {
            let _ = socket.shutdown().await;
        }
        return Ok((200, info.size as usize));
    }

    let raw_bytes = tokio::fs::read(&info.path).await?;
    let can_gzip = can_try_gzip
        && raw_bytes.len() >= gzip_policy.min_length
        && raw_bytes.len() <= MAX_GZIP_IN_MEMORY_BYTES;

    let (final_bytes, encoded_gzip) = if can_gzip {
        let gz = gzip_compress(&raw_bytes);
        if gz.len() < raw_bytes.len() {
            (gz, true)
        } else {
            (raw_bytes, false)
        }
    } else {
        (raw_bytes, false)
    };

    if can_use_cache && final_bytes.len() <= cache_max_object_bytes.min(MAX_STATIC_CACHE_BYTES) {
        let mut tags = vec![vhost_ctx.vhost_name.clone()];
        if vhost_ctx.etag_enabled {
            tags.push(format!("__etag:{}", info.etag));
        }
        if vhost_ctx.last_modified_header {
            tags.push(format!("__lm:{}", last_mod));
        }
        if encoded_gzip {
            tags.push("__enc:gzip".to_string());
        }
        if image_negotiation_candidate {
            tags.push("__vary:accept".to_string());
        }
        state
            .cache
            .set_with_ttl_and_stale(
                cache_key.to_string(),
                CachedResponse {
                    status: 200,
                    content_type: info.mime_type.to_string(),
                    body: bytes::Bytes::from(final_bytes.clone()),
                    tags,
                },
                vhost_ctx.cache_expire,
                vhost_ctx.cache_stale_sec,
            )
            .await;
    }

    let mut hdrs = vec![
        ("Content-Type".into(), info.mime_type.to_string()),
        ("Accept-Ranges".into(), "bytes".into()),
    ];
    if vhost_ctx.etag_enabled {
        hdrs.push(("ETag".into(), info.etag.clone()));
    }
    if vhost_ctx.last_modified_header {
        hdrs.push(("Last-Modified".into(), last_mod));
    }
    if encoded_gzip {
        hdrs.push(("Content-Encoding".into(), "gzip".into()));
    }
    match (gzip_policy.vary_header, image_negotiation_candidate) {
        (true, true) => hdrs.push(("Vary".into(), "Accept-Encoding, Accept".into())),
        (true, false) => hdrs.push(("Vary".into(), "Accept-Encoding".into())),
        (false, _) => hdrs.push(("Vary".into(), "Accept".into())),
    }

    let sent_len = final_bytes.len();
    write_http_response(
        socket,
        200,
        "OK",
        &hdrs,
        &final_bytes,
        Some(sent_len),
        false,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_ref,
        Some("MISS"),
    )
    .await?;
    Ok((200, sent_len))
}

struct PreparedPhpResponse {
    status: u16,
    reason: String,
    content_type: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    applied_gzip: bool,
}

#[allow(clippy::too_many_arguments)]
async fn execute_and_prepare_php(
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    vhost_ctx: &ResolvedVHostContext,
    script_rel_path: &str,
    path_info: &str,
    effective_query: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    php_cacheable_req: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
    is_head: bool,
) -> Result<Option<PreparedPhpResponse>, Box<dyn std::error::Error + Send + Sync>> {
    let clean_rel = script_rel_path.trim_start_matches('/');
    let script_filename = vhost_ctx.doc_root.join(clean_rel);
    if !script_filename.is_file() {
        return Ok(None);
    }

    let script_str = script_filename.to_string_lossy().into_owned();
    let doc_root_str = vhost_ctx.doc_root.to_string_lossy().into_owned();
    let script_name = format!("/{}", clean_rel);
    let request_uri = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let remote_ip_str = real_ip.to_string();

    let mut builder = FastCgiParamsBuilder::new(
        &req.method,
        &request_uri,
        &script_name,
        &script_str,
        &doc_root_str,
    )
    .query_string(effective_query)
    .host(&req.host)
    .remote_addr(&remote_ip_str)
    .remote_port(remote_port)
    .server_port(server_port)
    .is_https(is_https)
    .body_len(req.body.len())
    .headers(&req.headers);

    if !path_info.trim().is_empty() {
        let translated = vhost_ctx
            .doc_root
            .join(path_info.trim_start_matches('/'))
            .to_string_lossy()
            .into_owned();
        builder = builder.path_info(path_info).path_translated(translated);
    }
    let params = builder.build();

    let fcgi_resp = FastCgiClient::execute_php_detailed(
        &vhost_ctx.php_upstream,
        &params,
        &req.body,
        vhost_ctx.php_timeout,
    )
    .await?;

    if !fcgi_resp.stderr.is_empty() {
        let err_txt = String::from_utf8_lossy(&fcgi_resp.stderr);
        if !err_txt.trim().is_empty() {
            append_error_log_limit(
                &state.base_dir,
                &format!("[PHP STDERR] ({}): {}", script_name, err_txt.trim()),
                vhost_ctx.max_log_size_bytes,
            )
            .await;
        }
    }

    let (status, reason, cgi_headers, php_body) =
        FastCgiClient::split_cgi_headers_with_reason(&fcgi_resp.raw_stdout);

    let content_type = cgi_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("text/html; charset=utf-8")
        .to_string();

    let upstream_encoded = cgi_headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-encoding"));

    let should_gzip = wants_gzip
        && !is_head
        && !upstream_encoded
        && php_body.len() >= gzip_policy.min_length
        && php_body.len() <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(&content_type, &gzip_policy.mime_types);

    let (final_body, applied_gzip) = if should_gzip {
        let gz = gzip_compress(php_body);
        if gz.len() < php_body.len() {
            (gz, true)
        } else {
            (php_body.to_vec(), false)
        }
    } else {
        (php_body.to_vec(), false)
    };

    let mut out_headers: Vec<(String, String)> = cgi_headers
        .into_iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("content-length"))
        .collect();

    if applied_gzip {
        out_headers.push(("Content-Encoding".into(), "gzip".into()));
        out_headers.push(("Vary".into(), "Accept-Encoding".into()));
    }

    let cache_eligible = php_cacheable_req
        && status == 200
        && !response_forbids_cache(&out_headers)
        && final_body.len() <= cache_max_object_bytes;

    if cache_eligible {
        let mut tags = vec![vhost_ctx.vhost_name.clone()];
        if applied_gzip {
            tags.push("__enc:gzip".to_string());
        }
        state
            .cache
            .set_with_ttl_and_stale(
                cache_key.to_string(),
                CachedResponse {
                    status,
                    content_type: content_type.clone(),
                    body: bytes::Bytes::from(final_body.clone()),
                    tags,
                },
                vhost_ctx.cache_expire,
                vhost_ctx.cache_stale_sec,
            )
            .await;
    }

    Ok(Some(PreparedPhpResponse {
        status,
        reason,
        content_type,
        headers: out_headers,
        body: final_body,
        applied_gzip,
    }))
}

#[allow(clippy::too_many_arguments)]
async fn fetch_and_cache_php(
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    vhost_ctx: &ResolvedVHostContext,
    script_rel_path: &str,
    path_info: &str,
    effective_query: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    php_cacheable_req: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let prepared = execute_and_prepare_php(
        state,
        req,
        real_ip,
        remote_port,
        server_port,
        is_https,
        vhost_ctx,
        script_rel_path,
        path_info,
        effective_query,
        wants_gzip,
        gzip_policy,
        php_cacheable_req,
        cache_key,
        cache_max_object_bytes,
        false,
    )
    .await?;
    let _ = prepared.as_ref().map(|p| (&p.content_type, p.applied_gzip));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn serve_php_request<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    vhost_ctx: &ResolvedVHostContext,
    script_rel_path: &str,
    path_info: &str,
    effective_query: &str,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    php_cacheable_req: bool,
    cache_key: &str,
    cache_max_object_bytes: usize,
) -> Result<(u16, usize), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let sec_ref = vhost_ctx.headers_policy.as_ref();

    match execute_and_prepare_php(
        state,
        req,
        real_ip,
        remote_port,
        server_port,
        is_https,
        vhost_ctx,
        script_rel_path,
        path_info,
        effective_query,
        wants_gzip,
        gzip_policy,
        php_cacheable_req,
        cache_key,
        cache_max_object_bytes,
        is_head,
    )
    .await
    {
        Ok(Some(prep)) => {
            let status = prep.status;
            // [kart-2] FastCGI yanitinda HEAD, 204 veya 304 durumunda govde bayti 0 iletilir
            let body_len = if is_head || status == 204 || status == 304 {
                0
            } else {
                prep.body.len()
            };
            write_http_response(
                socket,
                status,
                &prep.reason,
                &prep.headers,
                &prep.body,
                Some(prep.body.len()),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
                if php_cacheable_req {
                    Some("MISS")
                } else {
                    Some("BYPASS")
                },
            )
            .await?;
            Ok((status, body_len))
        }
        Ok(None) => {
            let bytes_written = write_not_found(
                socket,
                Some(vhost_ctx),
                is_head,
                is_https,
                keep_alive,
                keep_alive_timeout_sec,
                sec_ref,
            )
            .await?;
            Ok((404, bytes_written))
        }
        Err(err) => {
            append_error_log_limit(
                &state.base_dir,
                &format!(
                    "[FastCGI Hata] upstream={} err={}",
                    vhost_ctx.php_upstream, err
                ),
                vhost_ctx.max_log_size_bytes,
            )
            .await;
            let err_msg = b"<!DOCTYPE html><html><body style='font-family:sans-serif;background:#090d16;color:#f8fafc;padding:40px;'><h2>502 Bad Gateway - FastCGI Upstream Kapali</h2><p>PHP-FPM/LSPHP servisi baglanti kuramadi.</p></body></html>";
            write_http_response(
                socket,
                502,
                "Bad Gateway",
                &[("Content-Type".into(), "text/html; charset=utf-8".into())],
                err_msg,
                Some(err_msg.len()),
                is_head,
                is_https,
                false,
                keep_alive_timeout_sec,
                sec_ref,
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_msg.len() };
            Ok((502, sent_err_bytes))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_proxy_request<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    is_https: bool,
    vhost_ctx: &ResolvedVHostContext,
    connect_timeout_sec: u64,
    keep_alive: bool,
) -> Result<(u16, bool, usize), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let raw_target = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let mut raw_head = format!(
        "{} {} HTTP/1.{}\r\n",
        req.method,
        raw_target,
        req.version.min(1)
    );
    for (k, v) in &req.headers {
        raw_head.push_str(&format!("{}: {}\r\n", k, v));
    }
    raw_head.push_str("\r\n");

    let is_ws = vhost_ctx.proxy_websocket
        && extract_header(&req.headers, "upgrade")
            .map(|u| u.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

    let conn_dur = Duration::from_secs(connect_timeout_sec.max(2));

    if is_ws {
        let opts = ProxyRewriteOptions {
            preserve_host: vhost_ctx.proxy_preserve_host,
            upstream_host: if vhost_ctx.proxy_preserve_host {
                None
            } else {
                Some(vhost_ctx.proxy_upstream.as_str())
            },
        };
        let is_head = req.method.eq_ignore_ascii_case("HEAD");
        let Some(rewritten_head) =
            rewrite_request_head_with_options(raw_head.as_bytes(), real_ip, is_https, &opts)
        else {
            let err_body = b"400 Bad Request";
            write_http_response(
                socket,
                400,
                "Bad Request",
                &[("Content-Type".into(), "text/plain".into())],
                err_body,
                None,
                is_head,
                is_https,
                false,
                0,
                vhost_ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_body.len() };
            return Ok((400, false, sent_err_bytes));
        };

        let mut upstream =
            match tokio::time::timeout(conn_dur, TcpStream::connect(&vhost_ctx.proxy_upstream))
                .await
            {
                Ok(Ok(s)) => s,
                _ => {
                    let err_body = b"502 Bad Gateway - Upstream Unavailable";
                    write_http_response(
                        socket,
                        502,
                        "Bad Gateway",
                        &[("Content-Type".into(), "text/plain".into())],
                        err_body,
                        None,
                        is_head,
                        is_https,
                        false,
                        0,
                        vhost_ctx.headers_policy.as_ref(),
                        None,
                    )
                    .await?;
                    let sent_err_bytes = if is_head { 0 } else { err_body.len() };
                    return Ok((502, false, sent_err_bytes));
                }
            };
        let _ = upstream.set_nodelay(true);
        upstream.write_all(&rewritten_head).await?;
        if !req.body.is_empty() {
            upstream.write_all(&req.body).await?;
        }
        let _ = tokio::io::copy_bidirectional(socket, &mut upstream).await;
        return Ok((101, false, 0));
    }

    let mut raw_full = raw_head.into_bytes();
    raw_full.extend_from_slice(&req.body);

    let proxy = ReverseProxy::new(&vhost_ctx.proxy_upstream)
        .with_timeouts(conn_dur, Duration::from_secs(30))
        .with_preserve_host(vhost_ctx.proxy_preserve_host)
        .with_https(is_https);

    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let mut upstream_stream = match state
        .upstream_pool
        .acquire(&vhost_ctx.proxy_upstream, conn_dur)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            let err_body = b"502 Bad Gateway - Proxy Upstream Unavailable";
            write_http_response(
                socket,
                502,
                "Bad Gateway",
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                err_body,
                Some(err_body.len()),
                is_head,
                is_https,
                false,
                0,
                vhost_ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_body.len() };
            return Ok((502, false, sent_err_bytes));
        }
    };

    match proxy
        .forward_http_on_stream(&mut upstream_stream, &raw_full, SocketAddr::new(real_ip, 0))
        .await
    {
        Ok((resp_bytes, reusable)) => {
            if reusable {
                state
                    .upstream_pool
                    .release(&vhost_ctx.proxy_upstream, upstream_stream);
            }
            let status = parse_response_status(&resp_bytes).unwrap_or(200);
            // [kart-2] Ters vekil yanitinda HTTP basliklari haric gercek gonderilen govde bayti hesaplanir
            let body_len = if is_head || status == 204 || status == 304 {
                0
            } else if let Some(pos) = resp_bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                resp_bytes.len().saturating_sub(pos + 4)
            } else if let Some(pos) = resp_bytes.windows(2).position(|w| w == b"\n\n") {
                resp_bytes.len().saturating_sub(pos + 2)
            } else {
                0
            };
            socket.write_all(&resp_bytes).await?;
            let _ = socket.flush().await;
            let client_keep = keep_alive && reusable && !response_has_connection_close(&resp_bytes);
            if !client_keep {
                let _ = socket.shutdown().await;
            }
            Ok((status, client_keep, body_len))
        }
        Err(_) => {
            let err_body = b"502 Bad Gateway - Proxy Upstream Unavailable";
            write_http_response(
                socket,
                502,
                "Bad Gateway",
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                err_body,
                Some(err_body.len()),
                is_head,
                is_https,
                false,
                0,
                vhost_ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            let sent_err_bytes = if is_head { 0 } else { err_body.len() };
            Ok((502, false, sent_err_bytes))
        }
    }
}

fn response_has_connection_close(raw: &[u8]) -> bool {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..head_end]);
    head.lines().any(|line| {
        if let Some((k, v)) = line.split_once(':') {
            k.trim().eq_ignore_ascii_case("connection") && v.to_ascii_lowercase().contains("close")
        } else {
            false
        }
    })
}

fn is_negotiable_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            ext.eq_ignore_ascii_case("jpg")
                || ext.eq_ignore_ascii_case("jpeg")
                || ext.eq_ignore_ascii_case("png")
        })
        .unwrap_or(false)
}

fn negotiable_image_cache_tag(
    static_path: &str,
    accept_header: Option<&str>,
    auto_avif: bool,
    auto_webp: bool,
) -> &'static str {
    if !is_negotiable_image_path(Path::new(static_path)) || (!auto_avif && !auto_webp) {
        return "";
    }
    let lower = accept_header.unwrap_or("").to_ascii_lowercase();
    if auto_avif && lower.contains("image/avif") {
        return "+avif";
    }
    if auto_webp && lower.contains("image/webp") {
        return "+webp";
    }
    ""
}

#[allow(clippy::too_many_arguments)]
async fn write_cached_php_response<S>(
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
async fn write_cached_static_response<S>(
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

#[allow(clippy::too_many_arguments)]
async fn revalidate_static_cache(
    state: &Arc<ServerState>,
    vhost_ctx: &ResolvedVHostContext,
    static_path: &str,
    accept_header: Option<&str>,
    wants_gzip: bool,
    gzip_policy: &crate::modules_runtime::GzipPolicy,
    cache_key: &str,
    cache_max_object_bytes: usize,
) {
    let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
    let Some(orig_info) = handler
        .resolve_with_index(static_path, &vhost_ctx.index_files)
        .or_else(|| resolve_predecoded_static_file(&vhost_ctx.doc_root, static_path))
    else {
        return;
    };

    let image_negotiation_candidate =
        (vhost_ctx.auto_avif || vhost_ctx.auto_webp) && is_negotiable_image_path(&orig_info.path);
    let mut info = orig_info;
    if image_negotiation_candidate {
        if let Some((alt_path, alt_mime)) = select_negotiated_image_path(
            &info.path,
            accept_header,
            vhost_ctx.auto_avif,
            vhost_ctx.auto_webp,
        ) {
            if let Ok(meta) = std::fs::metadata(&alt_path) {
                let size = meta.len();
                let last_modified_secs = meta
                    .modified()
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                info = zmax_static::StaticFileInfo {
                    path: alt_path,
                    mime_type: alt_mime,
                    size,
                    etag: format!("\"{:x}-{:x}\"", size, last_modified_secs),
                    last_modified_secs,
                };
            }
        }
    }

    if (info.size as usize) > MAX_STATIC_CACHE_BYTES {
        return;
    }
    let Ok(raw_bytes) = tokio::fs::read(&info.path).await else {
        return;
    };
    let can_gzip = wants_gzip
        && raw_bytes.len() >= gzip_policy.min_length
        && raw_bytes.len() <= MAX_GZIP_IN_MEMORY_BYTES
        && is_compressible_mime(info.mime_type, &gzip_policy.mime_types);
    let (final_bytes, encoded_gzip) = if can_gzip {
        let gz = gzip_compress(&raw_bytes);
        if gz.len() < raw_bytes.len() {
            (gz, true)
        } else {
            (raw_bytes, false)
        }
    } else {
        (raw_bytes, false)
    };
    if final_bytes.len() > cache_max_object_bytes.min(MAX_STATIC_CACHE_BYTES) {
        return;
    }

    let mut tags = vec![vhost_ctx.vhost_name.clone()];
    if vhost_ctx.etag_enabled {
        tags.push(format!("__etag:{}", info.etag));
    }
    if vhost_ctx.last_modified_header {
        tags.push(format!("__lm:{}", info.last_modified_http()));
    }
    if encoded_gzip {
        tags.push("__enc:gzip".to_string());
    }
    if image_negotiation_candidate {
        tags.push("__vary:accept".to_string());
    }

    state
        .cache
        .set_with_ttl_and_stale(
            cache_key.to_string(),
            CachedResponse {
                status: 200,
                content_type: info.mime_type.to_string(),
                body: bytes::Bytes::from(final_bytes),
                tags,
            },
            vhost_ctx.cache_expire,
            vhost_ctx.cache_stale_sec,
        )
        .await;
}

async fn stream_file_range_pooled<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    file: &mut tokio::fs::File,
    mut remaining: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let mut buf = state.buffer_pool.acquire();
    let target_cap = 64 * 1024;
    if buf.capacity() < target_cap {
        buf.reserve(target_cap - buf.capacity());
    }
    buf.resize(target_cap, 0);

    let res = async {
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read]).await?;
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await?;
            remaining -= n as u64;
        }
        Ok(())
    }
    .await;

    state.buffer_pool.release(buf);
    res
}

fn parse_response_status(raw: &[u8]) -> Option<u16> {
    let end = raw.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&raw[..end]).ok()?;
    let mut parts = line.split_whitespace();
    let _http = parts.next()?;
    parts.next()?.parse::<u16>().ok()
}

fn request_has_bypass_cookie_or_auth(headers: &[(String, String)]) -> bool {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("authorization") {
            return true;
        }
        if k.eq_ignore_ascii_case("cookie") {
            let lower = v.to_ascii_lowercase();
            if lower.contains("wordpress_logged_in")
                || lower.contains("wp-postpass")
                || lower.contains("comment_author")
                || lower.contains("phpsessid")
                || lower.contains("woocommerce_cart_hash")
                || lower.contains("woocommerce_items_in_cart")
            {
                return true;
            }
        }
    }
    false
}

fn response_forbids_cache(headers: &[(String, String)]) -> bool {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("set-cookie") {
            return true;
        }
        if k.eq_ignore_ascii_case("cache-control") {
            let lower = v.to_ascii_lowercase();
            if lower.contains("no-store")
                || lower.contains("no-cache")
                || lower.contains("private")
                || lower.contains("max-age=0")
            {
                return true;
            }
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn format_http_response_head(
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    content_length: Option<usize>,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
    cache_status: Option<&str>,
) -> String {
    let mut head = format!("HTTP/1.1 {} {}\r\n", status, reason);
    if let Some(cs) = cache_status {
        head.push_str(&format!("X-Cache: {}\r\n", cs));
    }

    for (k, v) in headers {
        if k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("keep-alive")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let clean_val = v.replace(['\r', '\n'], "");
        head.push_str(&format!("{}: {}\r\n", k, clean_val));
    }

    if let Some(len) = content_length {
        head.push_str(&format!("Content-Length: {}\r\n", len));
    }

    if keep_alive {
        head.push_str(&format!(
            "Connection: keep-alive\r\nKeep-Alive: timeout={}\r\n",
            keep_alive_timeout_sec.max(1)
        ));
    } else {
        head.push_str("Connection: close\r\n");
    }

    head.push_str("\r\n");

    if let Some(policy) = sec_policy {
        policy.append_headers(&mut head, is_https);
    } else if !head.to_ascii_lowercase().contains("\r\nserver:") {
        head.truncate(head.len() - 2);
        head.push_str("Server: zmaxserver\r\n\r\n");
    }

    head
}

#[allow(clippy::too_many_arguments)]
async fn write_http_head<S>(
    socket: &mut S,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    explicit_content_length: Option<usize>,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
    cache_status: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let head = format_http_response_head(
        status,
        reason,
        headers,
        explicit_content_length,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
        cache_status,
    );
    socket.write_all(head.as_bytes()).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn write_http_response<S>(
    socket: &mut S,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    body: &[u8],
    explicit_content_length: Option<usize>,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
    cache_status: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let fallback_len = (status != 204 && status != 304).then_some(body.len());
    let head = format_http_response_head(
        status,
        reason,
        headers,
        explicit_content_length.or(fallback_len),
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
        cache_status,
    );

    socket.write_all(head.as_bytes()).await?;
    if !is_head && !body.is_empty() && status != 204 && status != 304 {
        socket.write_all(body).await?;
    }
    let _ = socket.flush().await;
    if !keep_alive {
        let _ = socket.shutdown().await;
    }
    Ok(())
}

async fn write_not_found<S>(
    socket: &mut S,
    vhost_ctx: Option<&ResolvedVHostContext>,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    write_error_response(
        socket,
        404,
        "Not Found",
        b"404 Not Found - ZMax Server",
        vhost_ctx,
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
    )
    .await
}

fn default_status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

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

#[allow(clippy::too_many_arguments)]
async fn record_and_log(
    state: &Arc<ServerState>,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    started: Instant,
    vhost_ctx: Option<&ResolvedVHostContext>,
    bytes_sent: usize,
    referer: Option<&str>,
    user_agent: Option<&str>,
    http_version: &str,
    req_id: &str,
) {
    let max_log_size_bytes = vhost_ctx
        .map(|v| v.max_log_size_bytes)
        .unwrap_or(DEFAULT_LOG_MAX_BYTES);
    // [kart-2] NCSA standardi: HEAD, 304, 204 veya 0 bayt gonderilen yanitlarda '-' yazilir; aksi halde gercek bayt.
    let is_zero_body =
        bytes_sent == 0 || status == 304 || status == 204 || method.eq_ignore_ascii_case("HEAD");
    let bytes_str = if is_zero_body {
        "-".to_string()
    } else {
        bytes_sent.to_string()
    };
    let actual_bytes = if is_zero_body { 0 } else { bytes_sent };
    state.record_access_log_detailed(
        ip,
        method,
        path,
        status,
        started.elapsed(),
        actual_bytes,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );
    let line = format!(
        "{} - - \"{} {} {}\" {} {}\r\n",
        ip, method, path, http_version, status, bytes_str
    );
    append_access_log_limit(&state.base_dir, &line, max_log_size_bytes).await;

    record_and_log_vhost(
        state,
        ip,
        method,
        path,
        status,
        started,
        actual_bytes,
        referer,
        user_agent,
        http_version,
        req_id,
        vhost_ctx,
    )
    .await;
}

// =========================================================================
// 8-MADDE KABUL STANDARDI: HATA SAYFALARI, ASENKRON LOG VE HTTP/2 MOTORU
// =========================================================================

/// VHost ozel hata dokumanini (error_docs) arar; yoksa varsayilan hata mesajini dondurur.
pub async fn write_error_response<S>(
    socket: &mut S,
    status: u16,
    reason: &str,
    default_msg: &[u8],
    vhost_ctx: Option<&ResolvedVHostContext>,
    is_head: bool,
    is_https: bool,
    keep_alive: bool,
    keep_alive_timeout_sec: u64,
    sec_policy: Option<&SecurityHeadersPolicy>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    let body_bytes: Vec<u8> = if let Some(ctx) = vhost_ctx {
        if let Some(rel_page) = ctx.error_docs.pages.get(&status) {
            let custom_dir = if ctx.error_docs.dir.trim().is_empty() {
                None
            } else {
                Some(Path::new(ctx.error_docs.dir.trim()))
            };
            let handler = StaticFileHandler::new(&ctx.doc_root);
            handler
                .resolve_error_doc_file(&ctx.doc_root, custom_dir, rel_page)
                .unwrap_or_else(|_| default_msg.to_vec())
        } else {
            default_msg.to_vec()
        }
    } else {
        default_msg.to_vec()
    };

    let content_type = if body_bytes.starts_with(b"<!DOCTYPE") || body_bytes.starts_with(b"<html") {
        "text/html; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };

    // [kart-2] HEAD, 204 veya 304 isteklerinde govde yazilmaz; gercek bayt 0 olarak raporlanir
    let written = if is_head || status == 204 || status == 304 {
        0
    } else {
        body_bytes.len()
    };
    write_http_response(
        socket,
        status,
        reason,
        &[("Content-Type".into(), content_type.into())],
        &body_bytes,
        Some(body_bytes.len()),
        is_head,
        is_https,
        keep_alive,
        keep_alive_timeout_sec,
        sec_policy,
        None,
    )
    .await?;

    Ok(written)
}

/// Alan adina ozel erisim ve hata gunlugu yazici (NCSA Combined, asenkron ve tamponlu).
pub async fn record_and_log_vhost(
    state: &Arc<ServerState>,
    ip: &str,
    method: &str,
    path: &str,
    status: u16,
    started: Instant,
    bytes_sent: usize,
    referer: Option<&str>,
    user_agent: Option<&str>,
    http_version: &str,
    req_id: &str,
    vhost_ctx: Option<&ResolvedVHostContext>,
) {
    let elapsed = started.elapsed();
    let duration_ms = elapsed.as_secs_f64() * 1000.0;
    state.record_access_log_detailed(
        ip,
        method,
        path,
        status,
        elapsed,
        bytes_sent,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );

    let (domain, target_path, json_format, also_write_global, max_size) = match vhost_ctx {
        Some(ctx) => {
            let p = if ctx.logging.enabled && !ctx.logging.access_log.trim().is_empty() {
                Some(PathBuf::from(&ctx.logging.access_log))
            } else {
                None
            };
            (
                ctx.vhost_name.clone(),
                p,
                ctx.logging.format.eq_ignore_ascii_case("json"),
                ctx.logging.also_write_global,
                ctx.max_log_size_bytes,
            )
        }
        None => (
            "default".to_string(),
            None,
            false,
            true,
            DEFAULT_LOG_MAX_BYTES,
        ),
    };

    state.log_manager.log_access(crate::logger::AccessLogEntry {
        timestamp: std::time::SystemTime::now(),
        client_ip: ip.to_string(),
        method: method.to_string(),
        target: path.to_string(),
        protocol: http_version.to_string(),
        status,
        bytes_sent,
        referer: referer.unwrap_or("").to_string(),
        user_agent: user_agent.unwrap_or("").to_string(),
        request_id: req_id.to_string(),
        duration_ms,
        domain: domain.clone(),
        target_path,
        json_format,
        also_write_global,
        max_size_bytes: max_size,
    });
}

/// HTTP/2 akislarini karsilayip unified web istek boru hattindan geciren yonlendirici.
pub async fn handle_h2_dispatched_request(
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    state: &Arc<ServerState>,
    is_https: bool,
    listen_port: u16,
    tls_sni: Option<&str>,
    req_id: &str,
) -> Result<
    (u16, Vec<(String, String)>, bytes::Bytes, LogMeta),
    Box<dyn std::error::Error + Send + Sync>,
> {
    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);

    // 1. VHost Cozumleme
    let host_header = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host") || k == ":authority")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let effective_host = if host_header.is_empty() {
        tls_sni.unwrap_or("")
    } else {
        host_header
    };

    let (policies, vhost_ctx) = {
        let rt = state.runtime.read().await;
        let policies = rt.policies.clone();
        let vh_opt = match_vhost(&rt.vhosts, effective_host);
        let global_acl = IpAccessList::new(
            rt.config.security.allow_ips.clone(),
            rt.config.security.deny_ips.clone(),
        );
        let ctx = match vh_opt {
            Some(vh) => ResolvedVHostContext {
                doc_root: vh.resolved_doc_root.clone(),
                index_files: vh.entry.index_files.clone(),
                php_enabled: vh.entry.php.enabled && policies.fastcgi.enabled,
                php_upstream: if vh.entry.php.upstream.trim().is_empty() {
                    policies.fastcgi.default_upstream.clone()
                } else {
                    vh.entry.php.upstream.clone()
                },
                php_upstreams: vh.entry.php.upstreams.clone(),
                php_lb_policy: vh.entry.php.lb_policy.clone(),
                php_timeout: vh
                    .entry
                    .php
                    .timeout
                    .max(policies.fastcgi.timeout_sec)
                    .max(5),
                cache_enabled: vh.entry.cache.enabled && rt.config.cache.enabled,
                cache_expire: vh.entry.cache.expire.max(1),
                cache_stale_sec: rt.config.cache.stale_while_revalidate_sec,
                vhost_name: vh.entry.name.clone(),
                vhost_aliases: vh.entry.aliases.clone(),
                force_https: vh.entry.security.force_https,
                hotlink_protection: vh.entry.effective_hotlink().enabled,
                hotlink_config: vh.entry.effective_hotlink(),
                global_acl: global_acl.clone(),
                vhost_acl: IpAccessList::new(
                    vh.entry.security.allow_ips.clone(),
                    vh.entry.security.deny_ips.clone(),
                ),
                vhost_acl_engine: zmax_security::VhostAcl::new(
                    vh.entry.effective_acl().allow_ips,
                    vh.entry.effective_acl().deny_ips,
                ),
                rewrite_enabled: vh.entry.rewrite.enabled && policies.rewrite_enabled,
                rewrite_try_files: vh.entry.rewrite.try_files,
                rewrite_htaccess: vh.entry.rewrite.htaccess && policies.rewrite_htaccess,
                rewrite_rules: vh.entry.rewrite.rules.clone(),
                proxy_enabled: vh.entry.proxy.enabled && policies.proxy.enabled,
                proxy_upstream: vh.entry.proxy.upstream.clone(),
                proxy_path_prefix: if vh.entry.proxy.path_prefix.trim().is_empty() {
                    "/".to_string()
                } else {
                    vh.entry.proxy.path_prefix.clone()
                },
                proxy_preserve_host: vh.entry.proxy.preserve_host && policies.proxy.preserve_host,
                proxy_websocket: vh.entry.proxy.websocket && policies.proxy.websocket_upgrade,
                auto_webp: policies.static_policy.auto_webp,
                auto_avif: policies.static_policy.auto_avif,
                etag_enabled: policies.static_policy.etag_enabled,
                last_modified_header: policies.static_policy.last_modified_header,
                max_log_size_bytes: DEFAULT_LOG_MAX_BYTES,
                headers_policy: None,
                waf_enabled: vh.entry.security.waf_enabled,
                waf_exclude_paths: vh.entry.security.waf_exclude_paths.clone(),
                error_docs: vh.entry.error_docs.clone(),
                logging: vh.entry.logging.clone(),
                tls_http2: vh.entry.tls.http2,
            },
            None => ResolvedVHostContext {
                doc_root: state.base_dir.join("www").join("html"),
                index_files: vec!["index.html".to_string(), "index.php".to_string()],
                php_enabled: false,
                php_upstream: policies.fastcgi.default_upstream.clone(),
                php_upstreams: Vec::new(),
                php_lb_policy: "least_conn".to_string(),
                php_timeout: policies.fastcgi.timeout_sec.max(5),
                cache_enabled: rt.config.cache.enabled,
                cache_expire: rt.config.cache.default_ttl_seconds.max(1),
                cache_stale_sec: rt.config.cache.stale_while_revalidate_sec,
                vhost_name: "default".to_string(),
                vhost_aliases: Vec::new(),
                force_https: false,
                hotlink_protection: false,
                hotlink_config: zmax_config::HotlinkConfig::default(),
                global_acl,
                vhost_acl: IpAccessList::default(),
                vhost_acl_engine: zmax_security::VhostAcl::default(),
                rewrite_enabled: policies.rewrite_enabled,
                rewrite_try_files: true,
                rewrite_htaccess: policies.rewrite_htaccess,
                rewrite_rules: Vec::new(),
                proxy_enabled: false,
                proxy_upstream: String::new(),
                proxy_path_prefix: "/".to_string(),
                proxy_preserve_host: true,
                proxy_websocket: true,
                auto_webp: policies.static_policy.auto_webp,
                auto_avif: policies.static_policy.auto_avif,
                etag_enabled: policies.static_policy.etag_enabled,
                last_modified_header: policies.static_policy.last_modified_header,
                max_log_size_bytes: DEFAULT_LOG_MAX_BYTES,
                headers_policy: None,
                waf_enabled: None,
                waf_exclude_paths: Vec::new(),
                error_docs: zmax_config::VHostErrorDocsSection::default(),
                logging: zmax_config::VHostLoggingSection::default(),
                tls_http2: true,
            },
        };
        (policies, ctx)
    };

    let log_meta = LogMeta {
        domain: Some(vhost_ctx.vhost_name.clone()),
        custom_log_path: if vhost_ctx.logging.enabled
            && !vhost_ctx.logging.access_log.trim().is_empty()
        {
            Some(PathBuf::from(&vhost_ctx.logging.access_log))
        } else {
            None
        },
        json_format: vhost_ctx.logging.format.eq_ignore_ascii_case("json"),
        also_write_global: vhost_ctx.logging.also_write_global,
        max_log_size_bytes: vhost_ctx.max_log_size_bytes,
    };

    // 2. HTTP/2 Kapali vHost Denetimi
    if is_https && !vhost_ctx.tls_http2 {
        let resp_body = bytes::Bytes::from_static(
            b"421 Misdirected Request - HTTP/2 is disabled for this domain\n",
        );
        let headers = vec![
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("x-request-id".into(), req_id.to_string()),
        ];
        return Ok((421, headers, resp_body, log_meta));
    }

    // 3. Ortak Guvenlik Boru Hatti (BanManager, IP ACL, vHost WAF, WP BruteForce, force_https)
    let custom_dir = if vhost_ctx.error_docs.dir.trim().is_empty() {
        None
    } else {
        Some(Path::new(vhost_ctx.error_docs.dir.trim()))
    };

    let https_port = {
        let rt = state.runtime.read().await;
        rt.config.listeners.https.port
    };

    let verdict = crate::security_pipeline::evaluate_request_security(
        &vhost_ctx,
        real_ip,
        real_ip,
        &req.method,
        &req.path,
        &req.query,
        effective_host,
        &req.headers,
        &req.body,
        is_https,
        https_port,
        &state.ban_manager,
        &policies.waf.inspector,
        &state.wp_guard,
        policies.waf.wp_brute_force_enabled,
    );

    match verdict {
        crate::security_pipeline::SecurityVerdict::Blocked { reason } => {
            let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
            let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&403) {
                handler
                    .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                    .unwrap_or_else(|_| format!("{}\n", reason).into_bytes())
            } else {
                format!("{}\n", reason).into_bytes()
            };
            let headers = vec![
                ("content-type".into(), "text/html; charset=utf-8".into()),
                ("x-request-id".into(), req_id.to_string()),
            ];
            return Ok((403, headers, bytes::Bytes::from(body), log_meta));
        }
        crate::security_pipeline::SecurityVerdict::WafBlocked { violation } => {
            let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
            let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&403) {
                handler
                    .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                    .unwrap_or_else(|_| b"403 Forbidden - WAF Blocked\n".to_vec())
            } else {
                b"403 Forbidden - WAF Blocked\n".to_vec()
            };
            let headers = vec![
                ("content-type".into(), "text/html; charset=utf-8".into()),
                ("x-waf-violation".into(), violation),
                ("x-request-id".into(), req_id.to_string()),
            ];
            return Ok((403, headers, bytes::Bytes::from(body), log_meta));
        }
        crate::security_pipeline::SecurityVerdict::RedirectHttps { location } => {
            let headers = vec![
                ("location".into(), location),
                ("x-request-id".into(), req_id.to_string()),
            ];
            return Ok((301, headers, bytes::Bytes::new(), log_meta));
        }
        crate::security_pipeline::SecurityVerdict::Allowed => {}
    }

    // 5. Rewrite & .htaccess Cozumleme
    let real_ip_str = real_ip.to_string();
    let route_req = zmax_rewrite::RouteRequest {
        doc_root: &vhost_ctx.doc_root,
        path: &req.path,
        query: &req.query,
        host: effective_host,
        https: is_https,
        method: &req.method,
        remote_addr: &real_ip_str,
        server_port: listen_port,
        headers: &req.headers,
        index_files: &vhost_ctx.index_files,
        php_enabled: vhost_ctx.php_enabled,
        try_files_enabled: vhost_ctx.rewrite_try_files,
    };
    let route_res = state.htaccess_resolver.resolve(&route_req);
    let (effective_path, is_php_route, eff_query) = match route_res {
        RouteOutcome::Redirect { status, location } => {
            let headers = vec![
                ("location".into(), location),
                ("x-request-id".into(), req_id.to_string()),
            ];
            return Ok((status, headers, bytes::Bytes::new(), log_meta));
        }
        RouteOutcome::PhpScript { path, query } => (path, true, query),
        RouteOutcome::StaticFile { path, query } => (path, false, query),
        RouteOutcome::Forbidden => {
            let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
            let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&403) {
                handler
                    .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                    .unwrap_or_else(|_| b"403 Forbidden\n".to_vec())
            } else {
                b"403 Forbidden\n".to_vec()
            };
            return Ok((
                403,
                vec![("content-type".into(), "text/html; charset=utf-8".into())],
                bytes::Bytes::from(body),
                log_meta,
            ));
        }
        RouteOutcome::Gone => {
            let body = b"410 Gone\n".to_vec();
            return Ok((
                410,
                vec![("content-type".into(), "text/plain".into())],
                bytes::Bytes::from(body),
                log_meta,
            ));
        }
        RouteOutcome::NotFound => {
            let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
            let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&404) {
                handler
                    .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                    .unwrap_or_else(|_| b"404 Not Found\n".to_vec())
            } else {
                b"404 Not Found\n".to_vec()
            };
            return Ok((
                404,
                vec![("content-type".into(), "text/html; charset=utf-8".into())],
                bytes::Bytes::from(body),
                log_meta,
            ));
        }
    };

    // 6. FastCGI (PHP) veya Statik Dosya Yonlendirme
    if is_php_route && vhost_ctx.php_enabled {
        let is_head = req.method.eq_ignore_ascii_case("HEAD");
        let prep_res = execute_and_prepare_php(
            state,
            req,
            real_ip,
            0,
            listen_port,
            is_https,
            &vhost_ctx,
            &effective_path,
            "",
            &eff_query,
            false,
            &policies.gzip,
            vhost_ctx.cache_enabled,
            &format!("{}:{}", effective_host, effective_path),
            MAX_STATIC_CACHE_BYTES,
            is_head,
        )
        .await;

        match prep_res {
            Ok(Some(prep)) => {
                let mut resp_headers = prep.headers;
                resp_headers.push(("x-request-id".into(), req_id.to_string()));
                return Ok((
                    prep.status,
                    resp_headers,
                    bytes::Bytes::from(prep.body),
                    log_meta,
                ));
            }
            _ => {
                let handler = StaticFileHandler::new(&vhost_ctx.doc_root);
                let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&502) {
                    handler
                        .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                        .unwrap_or_else(|_| b"502 Bad Gateway - PHP-FPM Error\n".to_vec())
                } else {
                    b"502 Bad Gateway - PHP-FPM Error\n".to_vec()
                };
                return Ok((
                    502,
                    vec![("content-type".into(), "text/html; charset=utf-8".into())],
                    bytes::Bytes::from(body),
                    log_meta,
                ));
            }
        }
    }

    // 7. Statik Dosya Sunumu
    let static_handler = StaticFileHandler::new(&vhost_ctx.doc_root);
    let resolved = static_handler.resolve_with_index(&effective_path, &vhost_ctx.index_files);
    match resolved {
        Some(info) => {
            // [kart-5] HTTP/2 Hotlink Korumasi Denetimi
            let referer_hdr = req
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
                .map(|(_, v)| v.as_str());
            if crate::security_pipeline::is_request_hotlink_blocked(
                &vhost_ctx,
                referer_hdr,
                effective_host,
                &effective_path,
            ) {
                let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&403) {
                    static_handler
                        .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                        .unwrap_or_else(|_| b"403 Forbidden - Hotlink Protection\n".to_vec())
                } else {
                    b"403 Forbidden - Hotlink Protection\n".to_vec()
                };
                let headers = vec![
                    ("content-type".into(), "text/html; charset=utf-8".into()),
                    ("x-request-id".into(), req_id.to_string()),
                ];
                return Ok((403, headers, bytes::Bytes::from(body), log_meta));
            }

            // [kart-2] HTTP/2 If-None-Match kontrolu -> 304 Not Modified
            if vhost_ctx.etag_enabled && check_if_none_match(&req.headers, &info.etag) {
                let mut headers = vec![
                    ("etag".into(), info.etag.clone()),
                    ("x-request-id".into(), req_id.to_string()),
                ];
                headers.push(("last-modified".into(), info.last_modified_secs.to_string()));
                return Ok((304, headers, bytes::Bytes::new(), log_meta));
            }
            match tokio::fs::read(&info.path).await {
                Ok(content) => {
                    let etag_val = format!("\"{}\"", info.etag);
                    let mut headers = vec![
                        ("content-type".into(), info.mime_type.to_string()),
                        ("etag".into(), etag_val),
                        ("x-request-id".into(), req_id.to_string()),
                    ];
                    headers.push(("last-modified".into(), info.last_modified_secs.to_string()));
                    Ok((200, headers, bytes::Bytes::from(content), log_meta))
                }
                Err(_) => {
                    let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&500) {
                        static_handler
                            .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                            .unwrap_or_else(|_| b"500 Internal Server Error\n".to_vec())
                    } else {
                        b"500 Internal Server Error\n".to_vec()
                    };
                    Ok((
                        500,
                        vec![("content-type".into(), "text/html; charset=utf-8".into())],
                        bytes::Bytes::from(body),
                        log_meta,
                    ))
                }
            }
        }
        None => {
            let body = if let Some(rel) = vhost_ctx.error_docs.pages.get(&404) {
                static_handler
                    .resolve_error_doc_file(&vhost_ctx.doc_root, custom_dir, rel)
                    .unwrap_or_else(|_| b"404 Not Found - ZMax Server\n".to_vec())
            } else {
                b"404 Not Found - ZMax Server\n".to_vec()
            };
            let headers = vec![
                ("content-type".into(), "text/html; charset=utf-8".into()),
                ("x-request-id".into(), req_id.to_string()),
            ];
            Ok((404, headers, bytes::Bytes::from(body), log_meta))
        }
    }
}
