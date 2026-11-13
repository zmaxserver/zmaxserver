//! # ZMax Web Trafik Motoru
//! HTTP/1.1 Keep-Alive döngüsü, WAF/Rate-Limit/WP Kalkanı, Rewrite/`.htaccess`,
//! Reverse Proxy + WebSocket, FastCGI (PHP), Range/ETag/Gzip Statik Sunum ve L1/L2 Önbellek.

pub use crate::api::ParsedHttpRequest;
use crate::api::{read_http_request_with_limits, send_http_read_error, ServerState};
use crate::modules_runtime::{
    append_access_log_limit, append_error_log_limit, resolve_vhost_security_headers,
    select_negotiated_image_path,
};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zmax_cache::{
    build_cache_key, parse_lscache_headers, CacheLookup, CachedResponse, StampedeSlot,
};
use zmax_compress::{gzip_compress, is_compressible_mime, negotiate_encoding, ContentEncoding};
use zmax_config::match_vhost;
use zmax_fastcgi::{FastCgiClient, FastCgiRequest};
use zmax_header::SecurityHeadersPolicy;
use zmax_httpparser::{extract_header, resolve_real_ip, HttpReadLimits};
use zmax_proxy::{ProxyError, ReverseProxy};
use zmax_rewrite::{HtAccessResolver, RewriteEngine, RouteOutcome, RouteRequest};
use zmax_security::IpAccessList;
use zmax_static::{
    check_if_none_match, is_sendfile_supported, parse_byte_range, percent_decode_path,
    ByteRangeResult, StaticFileHandler,
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
    // [kart-10] Ters vekil genisletilmis ayarları (initTimeout, keep-alive, respBuffer)
    pub proxy_ext: zmax_config::ProxyExtConfig,
    auto_webp: bool,
    auto_avif: bool,
    etag_enabled: bool,
    last_modified_header: bool,
    pub max_log_size_bytes: u64,
    headers_policy: Option<SecurityHeadersPolicy>,
    // 8-Madde Alanlari
    pub waf_enabled: Option<bool>,
    pub waf_exclude_paths: Vec<String>,
    pub error_docs: zmax_config::VHostErrorDocsSection,
    pub logging: zmax_config::VHostLoggingSection,
    pub tls_http2: bool,
    pub acme_root: Option<PathBuf>,
    pub auth: zmax_config::VHostAuthSection, // [kart-9]
    // [kart-8] FastCGI bağlantı zaman aşımı (milisaniye)
    pub php_dial_timeout_ms: u64,
    pub autoindex: bool,
    pub block_dangerous_files: bool,
}

/// [kart-cache-1] Önbellek etiketlerine alan adı varyantlarını ve ham URI etiketlerini ekler.
#[inline]
fn append_domain_and_uri_cache_tags(tags: &mut Vec<String>, domain: &str, req_path: &str) {
    let clean_domain = domain.trim().to_ascii_lowercase();
    if !clean_domain.is_empty() {
        for tag in [
            clean_domain.clone(),
            format!("domain::{clean_domain}"),
            format!("domain:{clean_domain}"),
            format!("{clean_domain}::*"),
        ] {
            if !tags.iter().any(|t| t == &tag) {
                tags.push(tag);
            }
        }
    }
    let clean_path = zmax_cache::extract_path_from_uri(req_path);
    if !clean_path.is_empty() {
        for tag in [
            format!("__uri:{clean_path}"),
            format!("__path:{clean_path}"),
        ] {
            if !tags.iter().any(|t| t == &tag) {
                tags.push(tag);
            }
        }
    }
}

/// FastCGI bağlantı zaman aşımı (ms): vhost değeri verilmişse (ve 0 değilse) o; yoksa `mod_fastcgi`
/// politika değeri (en az 1 ms). vhost varsayılanı `None` olduğundan politika gerçekten kullanılır.
#[inline]
fn resolve_php_dial_timeout_ms(vhost_dial_ms: Option<u64>, policy_dial_ms: u64) -> u64 {
    match vhost_dial_ms {
        Some(ms) if ms > 0 => ms,
        _ => policy_dial_ms.max(1),
    }
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
    S: AsyncRead + AsyncWrite + Unpin + 'static,
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
                sec.slowloris_header_timeout_sec.max(1),
                sec.slowloris_body_timeout_sec.max(1),
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
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let started = Instant::now();
    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);

    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let keep_alive = req.keep_alive;

    let (policies, redis_client, vhost_ctx, is_unknown_host) = {
        let rt = state.runtime.read().await;
        let policies = rt.policies.clone();
        let redis_client = rt.redis_client.clone();
        let vh_opt = match_vhost(&rt.vhosts, &req.host);
        let is_unknown_host =
            !rt.vhosts.is_empty() && !req.host.trim().is_empty() && vh_opt.is_none();
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
                    // [v1-1b] [vhost.security] ve [vhost.acl] kurallari tutarli birlestirilir
                    vhost_acl_engine: crate::security_pipeline::build_merged_vhost_acl(
                        &vh.entry.security,
                        &vh.entry.acl,
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
                    // [kart-10]
                    proxy_ext: vh.entry.proxy_ext.clone(),
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
                    acme_root: crate::acme_runtime::resolve_vhost_acme_root(
                        Some(&vh.entry),
                        &state.base_dir,
                    ),
                    auth: vh.entry.auth.clone(),
                    php_dial_timeout_ms: resolve_php_dial_timeout_ms(
                        vh.entry.php.dial_timeout_ms,
                        policies.fastcgi.dial_timeout_ms,
                    ),
                    autoindex: vh.entry.static_files.autoindex,
                    block_dangerous_files: vh.entry.security.block_dangerous_files,
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
                // [kart-10]
                proxy_ext: zmax_config::ProxyExtConfig::default(),
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
                acme_root: None,
                auth: zmax_config::VHostAuthSection::default(),
                php_dial_timeout_ms: resolve_php_dial_timeout_ms(
                    None,
                    policies.fastcgi.dial_timeout_ms,
                ),
                autoindex: policies.static_policy.directory_browsing,
                block_dangerous_files: false,
            },
        };
        (policies, redis_client, ctx, is_unknown_host)
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

    // [kart-12-a] Bilinmeyen Host: server_name eşleşmeyen istek için güvenli varsayılan 403 Forbidden
    if is_unknown_host {
        let err_body = b"403 Forbidden - Unknown Host\n";
        write_http_response(
            socket,
            403,
            "Forbidden",
            &[
                ("Content-Type".into(), "text/plain; charset=utf-8".into()),
                ("Connection".into(), "close".into()),
            ],
            err_body,
            Some(err_body.len()),
            is_head,
            is_https,
            false,
            0,
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
            None,
            if is_head { 0 } else { err_body.len() },
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(false);
    }

    // [v1-1b] Ortak Guvenlik Boru Hatti (BanManager, Global/vHost ACL, vHost WAF, WP BruteForce, force_https)
    let verdict = crate::security_pipeline::evaluate_request_security(
        &vhost_ctx,
        real_ip,
        peer_addr.ip(),
        &req.method,
        &req.path,
        &req.query,
        &req.host,
        &req.headers,
        &req.body,
        is_https,
        https_port,
        &state.ban_manager,
        &policies.waf.inspector,
        &state.wp_guard,
        policies.waf.wp_brute_force_enabled,
    );

    if !matches!(
        verdict,
        crate::security_pipeline::SecurityVerdict::Blocked { .. }
            | crate::security_pipeline::SecurityVerdict::WafBlocked { .. }
    ) {
        let rate_allowed = {
            let limiter = state.limiter.read().await;
            limiter.check_allowed(real_ip)
        };
        if !rate_allowed {
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
                if is_head { 0 } else { err_body.len() },
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            return Ok(false);
        }
    }

    match verdict {
        crate::security_pipeline::SecurityVerdict::Blocked { reason } => {
            if reason.contains("IP Access Denied") {
                append_error_log_limit(
                    &state.base_dir,
                    &format!(
                        "[ACL] {} {} {} -> IP Access Denied",
                        real_ip_str, req.method, req.path
                    ),
                    vhost_ctx.max_log_size_bytes,
                )
                .await;
            } else if reason.contains("Brute Force") {
                if let Some(redis) = redis_client {
                    let ip_s = real_ip_str.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(200),
                            redis.ban_ip(&ip_s, 900),
                        )
                        .await;
                    });
                }
            }
            let written_bytes = write_error_response(
                socket,
                403,
                "Forbidden",
                reason.as_bytes(),
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
        crate::security_pipeline::SecurityVerdict::WafBlocked { violation } => {
            let target_uri = if req.query.is_empty() {
                req.path.clone()
            } else {
                format!("{}?{}", req.path, req.query)
            };
            crate::security_pipeline::record_waf_block(
                state,
                &vhost_ctx,
                &real_ip_str,
                &req.method,
                &target_uri,
                &violation,
            );
            let safe_waf_path = zmax_security::waf_events::sanitize_waf_path(&target_uri);
            let safe_waf_rule = zmax_security::waf_events::format_waf_rule_label(&violation);
            let err_line = format!(
                "[WAF] [{}] {} {} {} -> {}",
                vhost_ctx.vhost_name, real_ip_str, req.method, safe_waf_path, safe_waf_rule
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
        crate::security_pipeline::SecurityVerdict::RedirectHttps { location } => {
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
        crate::security_pipeline::SecurityVerdict::Allowed => {}
    }

    // 4.5. [kart-9] Basic Authentication ($apr1$ & Argon2id)
    let auth_decision =
        crate::security_pipeline::evaluate_basic_auth(
            &vhost_ctx,
            real_ip,
            &req.path,
            &req.headers,
            &state.basic_auth,
            &state.base_dir,
            &state.ban_manager,
        )
        .await;
    if let Some(denial) =
        crate::security_pipeline::build_auth_denial(&vhost_ctx, &auth_decision, None)
    {
        let (auth_headers, auth_body) = (denial.headers, denial.body);
        let written_bytes = if is_head { 0 } else { auth_body.len() };
        write_http_response(
            socket,
            denial.status,
            denial.reason,
            &auth_headers,
            &auth_body,
            Some(auth_body.len()),
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
            denial.status,
            started,
            Some(&vhost_ctx),
            written_bytes,
            referer_hdr,
            ua_hdr,
            "HTTP/1.1",
            &req_id,
        )
        .await;
        return Ok(keep_alive);
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

    // 5b. [matris-cache-tags] PURGE metodu / X-LiteSpeed-Purge istek başlığı (ortak yetki denetimi, h2 ile aynı)
    match process_cache_purge_request(state, &vhost_ctx.vhost_name, &req, real_ip).await {
        PurgeRequestOutcome::NotPurge => {}
        outcome => {
            let (status, reason, purge_body) = match outcome {
                PurgeRequestOutcome::Done(n) => {
                    (200, "OK", format!("Purged {n} entries\n").into_bytes())
                }
                _ => (403, "Forbidden", b"403 Forbidden\n".to_vec()),
            };
            let resp_hdrs = vec![("Content-Type".into(), "text/plain; charset=utf-8".into())];
            write_http_response(
                socket,
                status,
                reason,
                &resp_hdrs,
                &purge_body,
                Some(purge_body.len()),
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
                purge_body.len(),
                referer_hdr,
                ua_hdr,
                "HTTP/1.1",
                &req_id,
            )
            .await;
            return Ok(keep_alive);
        }
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
        autoindex: vhost_ctx.autoindex,
        block_dangerous_files: vhost_ctx.block_dangerous_files,
    };

    let (outcome, path_info, error_documents) = if is_acme_challenge(&req.path) {
        (
            RouteOutcome::StaticFile {
                path: req.path.clone(),
                query: req.query.clone(),
            },
            String::new(),
            std::collections::BTreeMap::new(),
        )
    } else {
        let htaccess_resolver = if vhost_ctx.rewrite_enabled && vhost_ctx.rewrite_htaccess {
            HtAccessResolver::from_doc_root(&vhost_ctx.doc_root)
        } else {
            HtAccessResolver::from_htaccess(None)
        };
        let resolution = RewriteEngine::new()
            .resolve_with_htaccess_info(&route_req, htaccess_resolver.htaccess());
        (resolution.outcome, resolution.path_info, resolution.error_documents)
    };

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
            let custom_err_body = if let Some(custom_err) = error_documents.get(&403) {
                let clean = custom_err.trim_start_matches('/');
                std::fs::read(vhost_ctx.doc_root.join(clean)).ok()
            } else {
                None
            };
            let written_bytes = if let Some(body_bytes) = custom_err_body {
                write_http_response(
                    socket,
                    403,
                    "Forbidden",
                    &[("Content-Type".into(), "text/html; charset=utf-8".into())],
                    &body_bytes,
                    Some(body_bytes.len()),
                    is_head,
                    is_https,
                    keep_alive,
                    keep_alive_timeout_sec,
                    sec_ref,
                    None,
                )
                .await?;
                body_bytes.len()
            } else {
                write_error_response(
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
                .await?
            };
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
            let respect_req_cc = respect_request_cache_control(state).await;
            let php_cacheable_req = vhost_ctx.cache_enabled
                && req.method.eq_ignore_ascii_case("GET")
                && !request_has_bypass_cookie_or_auth(&req.headers, respect_req_cc);

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
            let has_req_bypass = request_has_bypass_cookie_or_auth(
                &req.headers,
                respect_request_cache_control(state).await,
            );
            let can_use_cache = vhost_ctx.cache_enabled
                && req.method.eq_ignore_ascii_case("GET")
                && !has_req_bypass
                && !has_range
                && !has_if_none_match
                && !is_acme_challenge(&static_path);
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
            let file_info = if is_acme_challenge(&static_path) {
                match vhost_ctx.acme_root.as_deref() {
                    Some(vhost_root) => {
                        handler.resolve_acme_challenge_with_root(&static_path, Some(vhost_root))
                    }
                    None => handler.resolve_acme_challenge(&static_path),
                }
            } else {
                handler
                    .resolve_with_index(&static_path, &vhost_ctx.index_files)
                    .or_else(|| resolve_predecoded_static_file(&vhost_ctx.doc_root, &static_path))
            };

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
    S: AsyncWrite + Unpin + 'static,
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
            if let Ok(meta) = tokio::fs::metadata(&alt_path).await {
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
                    // [kart-8] Büyük byte-range aktarımı: düz TCP üzerinde gerçek sendfile(2), TLS'te tamponlu yedek
                    stream_file_range_pooled(
                        socket,
                        state,
                        &mut file,
                        start,
                        slice_len as u64,
                        is_https,
                    )
                    .await?;
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
        // [kart-8] Büyük tam dosya aktarımı: düz TCP üzerinde gerçek sendfile(2), TLS'te tamponlu yedek
        stream_file_range_pooled(socket, state, &mut file, 0, info.size, is_https).await?;
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
        let mut tags = Vec::new();
        append_domain_and_uri_cache_tags(&mut tags, &vhost_ctx.vhost_name, &req.path);
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
    let cache_status = if can_use_cache {
        Some("MISS")
    } else {
        Some("BYPASS")
    };
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
        cache_status,
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
    /// Yanıt (Set-Cookie, Cache-Control, X-LiteSpeed-Cache-Control) önbelleğe alınmayı yasaklıyor.
    cache_forbidden: bool,
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

    // [kart-8] FastCGI havuzlu bağlantı yürütme (PooledClient / execute_php_pooled)
    let fcgi_req = {
        let mut r = FastCgiRequest::new(
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
        .headers(req.headers.clone())
        .body(req.body.clone());

        if !path_info.trim().is_empty() {
            let translated = vhost_ctx
                .doc_root
                .join(path_info.trim_start_matches('/'))
                .to_string_lossy()
                .into_owned();
            r = r.path_info(path_info).path_translated(translated);
        }
        r
    };

    let fcgi_client =
        FastCgiClient::with_pool(&vhost_ctx.php_upstream, Arc::clone(&state.upstream_pool));
    // [kart-8] Sabit 5 sn yerine yapılandırmadan (vhost.php.dial_timeout_ms / mod_fastcgi) gelen bağlantı zaman aşımı
    let dial_timeout = Duration::from_millis(vhost_ctx.php_dial_timeout_ms.max(1));
    let fcgi_resp = fcgi_client
        .execute_php_pooled(
            fcgi_req,
            dial_timeout,
            Duration::from_secs(vhost_ctx.php_timeout),
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    if !fcgi_resp.stderr.trim().is_empty() {
        append_error_log_limit(
            &state.base_dir,
            &format!(
                "[PHP STDERR] ({}): {}",
                script_name,
                fcgi_resp.stderr.trim()
            ),
            vhost_ctx.max_log_size_bytes,
        )
        .await;
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

    // [matris-cache-tags] LSCache başlık köprüsü (X-LiteSpeed-Cache-Control / -Tag / -Purge)
    let lscache = {
        let hdr_refs: Vec<(&str, &str)> = out_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        parse_lscache_headers(hdr_refs)
    };

    // Uygulamanın tetiklediği temizlik yalnız bu vhost'un `alan::etiket` kayıtlarını siler.
    if lscache.purge_all || !lscache.purge_tags.is_empty() {
        state
            .cache
            .apply_lscache_purge(&vhost_ctx.vhost_name, &lscache)
            .await;
    }

    // `public` yönergesi Set-Cookie / Cache-Control: private|no-store|no-cache yasaklarını ASLA aşmaz.
    let cache_forbidden = response_forbids_cache(&out_headers)
        || lscache.cacheable == Some(false)
        || lscache.is_private;
    let effective_ttl = lscache.max_age_secs.unwrap_or(vhost_ctx.cache_expire);

    let cache_eligible = php_cacheable_req
        && status == 200
        && !cache_forbidden
        && effective_ttl > 0
        && final_body.len() <= cache_max_object_bytes;

    if cache_eligible {
        let mut tags = Vec::new();
        append_domain_and_uri_cache_tags(&mut tags, &vhost_ctx.vhost_name, &req.path);
        for tag in &lscache.tags {
            let domain_tag = zmax_cache::ZMaxCache::format_domain_tag(&vhost_ctx.vhost_name, tag);
            for t in [tag.clone(), domain_tag] {
                if !tags.iter().any(|existing| existing == &t) {
                    tags.push(t);
                }
            }
        }
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
                effective_ttl,
                vhost_ctx.cache_stale_sec,
            )
            .await;
    }

    // Dahili LSCache yönergeleri istemciye sızdırılmaz.
    out_headers.retain(|(k, _)| {
        !(k.eq_ignore_ascii_case("x-litespeed-tag")
            || k.eq_ignore_ascii_case("x-litespeed-purge")
            || k.eq_ignore_ascii_case("x-litespeed-cache-control"))
    });

    Ok(Some(PreparedPhpResponse {
        status,
        reason,
        content_type,
        headers: out_headers,
        body: final_body,
        applied_gzip,
        cache_forbidden,
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
            let cache_status = if !php_cacheable_req || prep.cache_forbidden {
                Some("BYPASS")
            } else {
                Some("MISS")
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
                cache_status,
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
    let is_ws = vhost_ctx.proxy_websocket
        && extract_header(&req.headers, "upgrade")
            .map(|u| u.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
    let is_head = req.method.eq_ignore_ascii_case("HEAD");

    // RFC 9110 §7.6.1: Connection, çerçeveleme/Host alanı adlandırıyorsa istek reddedilir;
    // sessizce soymak vekil ile arka uç arasında istek çerçevesi ayrışmasına yol açar.
    if zmax_proxy::connection_names_protected_field(
        req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ) {
        let err_body = b"400 Bad Request - Connection header names a protected field\n";
        write_http_response(
            socket,
            400,
            "Bad Request",
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
        return Ok((400, false, sent_err_bytes));
    }

    let raw_target = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let mut connection_tokens = Vec::new();
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("connection") {
            for tok in v.split(',') {
                let t = tok.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    connection_tokens.push(t);
                }
            }
        }
    }

    let mut raw_head = format!(
        "{} {} HTTP/1.{}\r\n",
        req.method,
        raw_target,
        req.version.min(1)
    );
    for (k, v) in &req.headers {
        let kl = k.to_ascii_lowercase();
        // [kart-10: P0 request smuggling & RFC 9110 hop-by-hop temizliği]
        // Connection başlığındaki özel belirteçler ve hop-by-hop alanları elenir.
        // WebSocket durumunda Upgrade belirteci korunur.
        if !(is_ws && kl == "upgrade") && connection_tokens.contains(&kl) {
            continue;
        }
        // Gövde decode_chunked_stream ile çözüldüğünden, transfer-encoding başlığı upstream'e aktarılmaz!
        if matches!(
            kl.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "trailers"
        ) {
            continue;
        }
        if kl == "upgrade" && !is_ws {
            continue;
        }
        raw_head.push_str(&format!("{}: {}\r\n", k, v));
    }
    // Çözülmüş gerçek gövde uzunluğu Content-Length olarak eklenir
    if !req.body.is_empty()
        || req.method.eq_ignore_ascii_case("POST")
        || req.method.eq_ignore_ascii_case("PUT")
        || req.method.eq_ignore_ascii_case("PATCH")
    {
        raw_head.push_str(&format!("content-length: {}\r\n", req.body.len()));
    }
    raw_head.push_str("\r\n");

    // [kart-10: vhost'ta yoksa mod_proxy.toml genel değeri]
    let conn_sec = vhost_ctx
        .proxy_ext
        .connect_timeout_sec
        .unwrap_or(connect_timeout_sec);
    let conn_dur = Duration::from_secs(conn_sec.max(1));
    let init_dur = Duration::from_secs(vhost_ctx.proxy_ext.init_timeout_sec.max(1));
    let ka_dur = Duration::from_secs(vhost_ctx.proxy_ext.keep_alive_timeout_sec.max(1));

    // [kart-10: max_conns eşzamanlı aktif bağlantı denetimi; WebSocket tünelleri max_ws ile sınırlanır]
    if !is_ws
        && vhost_ctx.proxy_ext.max_conns > 0
        && !state
            .upstream_pool
            .try_acquire_conns_slot(&vhost_ctx.proxy_upstream, vhost_ctx.proxy_ext.max_conns)
    {
        let err_body = b"503 Service Unavailable - Upstream Connection Limit Reached\n";
        write_http_response(
            socket,
            503,
            "Service Unavailable",
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
        return Ok((503, false, sent_err_bytes));
    }

    struct UpstreamConnGuard<'a> {
        pool: &'a zmax_pool::UpstreamSocketPool,
        addr: &'a str,
        active: bool,
    }
    impl<'a> Drop for UpstreamConnGuard<'a> {
        fn drop(&mut self) {
            if self.active {
                self.pool.release_conns_slot(self.addr);
            }
        }
    }
    let _conn_guard = UpstreamConnGuard {
        pool: &state.upstream_pool,
        addr: &vhost_ctx.proxy_upstream,
        active: !is_ws && vhost_ctx.proxy_ext.max_conns > 0,
    };

    let proxy = ReverseProxy::new(&vhost_ctx.proxy_upstream)
        .with_timeouts(conn_dur, init_dur)
        .with_init_timeout(init_dur)
        .with_keep_alive_timeout(ka_dur)
        .with_resp_buffer(vhost_ctx.proxy_ext.resp_buffer)
        .with_preserve_host(vhost_ctx.proxy_preserve_host)
        .with_max_conns(vhost_ctx.proxy_ext.max_conns)
        .with_ws_idle_timeout(Duration::from_secs(
            vhost_ctx.proxy_ext.ws_idle_timeout_sec.max(1),
        ))
        .with_https(is_https);

    if is_ws {
        // [kart-10: vhost başına eşzamanlı WebSocket tüneli sınırı]
        let ws_key = format!("ws:{}", vhost_ctx.vhost_name);
        if !state
            .upstream_pool
            .try_acquire_conns_slot(&ws_key, vhost_ctx.proxy_ext.max_ws)
        {
            let err_body = b"503 Service Unavailable - WebSocket Connection Limit Reached\n";
            write_http_response(
                socket,
                503,
                "Service Unavailable",
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
            return Ok((503, false, sent_err_bytes));
        }
        let _ws_guard = UpstreamConnGuard {
            pool: &state.upstream_pool,
            addr: &ws_key,
            active: true,
        };
        match proxy
            .tunnel_websocket_request(
                socket,
                raw_head.as_bytes(),
                &req.body,
                SocketAddr::new(real_ip, 0),
            )
            .await
        {
            Ok((status, body_bytes)) => return Ok((status, false, body_bytes)),
            Err(err) => {
                if err.headers_sent {
                    if let Err(e) = socket.shutdown().await {
                        tracing::debug!(error = %e, "ters vekil: istemci soketi kapatilamadi");
                    }
                    return Ok((err.status.unwrap_or(502), false, err.body_bytes_sent));
                }
                let (code, reason, err_body): (u16, &str, &[u8]) = match &err.error {
                    ProxyError::BadRequest => (400, "Bad Request", b"400 Bad Request"),
                    ProxyError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        (504, "Gateway Timeout", b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
                    }
                    _ => (502, "Bad Gateway", b"502 Bad Gateway - Upstream Unavailable\n"),
                };
                write_http_response(
                    socket,
                    code,
                    reason,
                    &[("Content-Type".into(), "text/plain".into())],
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
                return Ok((code, false, sent_err_bytes));
            }
        }
    }

    let mut upstream_stream = match state
        .upstream_pool
        .acquire(&vhost_ctx.proxy_upstream, conn_dur)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            let is_timeout = err.kind() == std::io::ErrorKind::TimedOut;
            let (code, reason, err_body): (u16, &str, &[u8]) = if is_timeout {
                (504, "Gateway Timeout", b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
            } else {
                (502, "Bad Gateway", b"502 Bad Gateway - Proxy Upstream Unavailable\n")
            };
            write_http_response(
                socket,
                code,
                reason,
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
            return Ok((code, false, sent_err_bytes));
        }
    };

    match proxy
        .forward_streaming_on_stream(
            &mut upstream_stream,
            socket,
            raw_head.as_bytes(),
            &req.body,
            SocketAddr::new(real_ip, 0),
            keep_alive,
        )
        .await
    {
        Ok(res) => {
            if res.upstream_reusable {
                state
                    .upstream_pool
                    .release_with_ttl(&vhost_ctx.proxy_upstream, upstream_stream, ka_dur);
            }
            if !res.client_keep_alive {
                if let Err(e) = socket.shutdown().await {
                    tracing::debug!(error = %e, "ters vekil: istemci soketi kapatilamadi");
                }
            }
            Ok((res.status, res.client_keep_alive, res.body_bytes))
        }
        Err(err) => {
            if err.headers_sent {
                if let Err(e) = socket.shutdown().await {
                    tracing::debug!(error = %e, "ters vekil: istemci soketi kapatilamadi");
                }
                return Ok((err.status.unwrap_or(502), false, err.body_bytes_sent));
            }
            let (code, reason, err_body): (u16, &str, &[u8]) = match &err.error {
                ProxyError::BadRequest => (400, "Bad Request", b"400 Bad Request"),
                ProxyError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    (504, "Gateway Timeout", b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
                }
                _ => (502, "Bad Gateway", b"502 Bad Gateway - Proxy Upstream Unavailable\n"),
            };
            write_http_response(
                socket,
                code,
                reason,
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
            Ok((code, false, sent_err_bytes))
        }
    }
}

/// HTTP/2 yanıt gövdesi için üst sınır: arka uç okuyucu ile h2 yazıcı arasındaki kanal en çok bu kadar
/// parça (her biri <= 8 KiB okuma) tutar; dolunca arka uçtan okuma durur (geri basınç). Yanıtın
/// tamamı hiçbir koşulda bellekte toplanmaz.
const H2_PROXY_STREAM_QUEUE_CHUNKS: usize = 8;

/// HTTP/2 vekil yanıtının çözülmüş gövde parçaları (hata = akış sıfırlanır).
pub type H2BodyReceiver = tokio::sync::mpsc::Receiver<Result<bytes::Bytes, std::io::Error>>;

/// Arka uç bağlantı yuvası (`max_conns` / `max_ws`); yanıt akışı görevine taşınabilsin diye sahiplidir.
struct OwnedConnSlot {
    state: Arc<ServerState>,
    addr: String,
    active: bool,
}

impl Drop for OwnedConnSlot {
    fn drop(&mut self) {
        if self.active {
            self.state.upstream_pool.release_conns_slot(&self.addr);
        }
    }
}

fn h2_text_reply(
    status: u16,
    msg: &'static [u8],
) -> (
    u16,
    Vec<(String, String)>,
    bytes::Bytes,
    Option<H2BodyReceiver>,
) {
    (
        status,
        vec![("content-type".into(), "text/plain; charset=utf-8".into())],
        bytes::Bytes::from_static(msg),
        None,
    )
}

fn h2_proxy_error_reply(
    err: &ProxyError,
) -> (
    u16,
    Vec<(String, String)>,
    bytes::Bytes,
    Option<H2BodyReceiver>,
) {
    match err {
        ProxyError::BadRequest => h2_text_reply(400, b"400 Bad Request\n"),
        ProxyError::Io(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            h2_text_reply(504, b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
        }
        _ => h2_text_reply(502, b"502 Bad Gateway - Proxy Upstream Unavailable\n"),
    }
}

/// HTTP/2 üzerinden gelen vekil vhost isteklerini arka uç HTTP/1.1 sunucusuna iletir. Yanıt başı
/// hemen döner; gövde (Content-Length / chunked çözülmüş) `H2BodyReceiver` ile artımlı akar.
async fn serve_h2_proxy_request(
    state: &Arc<ServerState>,
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    vhost_ctx: &ResolvedVHostContext,
    default_connect_timeout_sec: u64,
) -> Result<
    (
        u16,
        Vec<(String, String)>,
        bytes::Bytes,
        Option<H2BodyReceiver>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    // RFC 9110 §7.6.1: Connection, çerçeveleme/Host alanı adlandırıyorsa istek reddedilir.
    if zmax_proxy::connection_names_protected_field(
        req.headers.iter().map(|(k, v)| (k.as_str(), v.as_str())),
    ) {
        return Ok(h2_text_reply(
            400,
            b"400 Bad Request - Connection header names a protected field\n",
        ));
    }
    let raw_target = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };
    let mut connection_tokens = Vec::new();
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("connection") {
            for tok in v.split(',') {
                let t = tok.trim().to_ascii_lowercase();
                if !t.is_empty() {
                    connection_tokens.push(t);
                }
            }
        }
    }

    let mut raw_head = format!("{} {} HTTP/1.1\r\n", req.method, raw_target);
    for (k, v) in &req.headers {
        let kl = k.to_ascii_lowercase();
        // [kart-10: RFC 9110 hop-by-hop ve smuggling temizliği]
        if connection_tokens.contains(&kl) {
            continue;
        }
        if matches!(
            kl.as_str(),
            "transfer-encoding"
                | "content-length"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailer"
                | "trailers"
                | "upgrade"
        ) {
            continue;
        }
        raw_head.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !req.body.is_empty()
        || req.method.eq_ignore_ascii_case("POST")
        || req.method.eq_ignore_ascii_case("PUT")
        || req.method.eq_ignore_ascii_case("PATCH")
    {
        raw_head.push_str(&format!("content-length: {}\r\n", req.body.len()));
    }
    raw_head.push_str("\r\n");

    let conn_sec = vhost_ctx
        .proxy_ext
        .connect_timeout_sec
        .unwrap_or(default_connect_timeout_sec);
    let conn_dur = Duration::from_secs(conn_sec.max(1));
    let init_dur = Duration::from_secs(vhost_ctx.proxy_ext.init_timeout_sec.max(1));
    let ka_dur = Duration::from_secs(vhost_ctx.proxy_ext.keep_alive_timeout_sec.max(1));

    if vhost_ctx.proxy_ext.max_conns > 0
        && !state
            .upstream_pool
            .try_acquire_conns_slot(&vhost_ctx.proxy_upstream, vhost_ctx.proxy_ext.max_conns)
    {
        return Ok(h2_text_reply(
            503,
            b"503 Service Unavailable - Upstream Connection Limit Reached\n",
        ));
    }
    let slot = OwnedConnSlot {
        state: Arc::clone(state),
        addr: vhost_ctx.proxy_upstream.clone(),
        active: vhost_ctx.proxy_ext.max_conns > 0,
    };

    let proxy = ReverseProxy::new(&vhost_ctx.proxy_upstream)
        .with_timeouts(conn_dur, init_dur)
        .with_init_timeout(init_dur)
        .with_keep_alive_timeout(ka_dur)
        .with_resp_buffer(vhost_ctx.proxy_ext.resp_buffer)
        .with_preserve_host(vhost_ctx.proxy_preserve_host)
        .with_max_conns(vhost_ctx.proxy_ext.max_conns)
        .with_https(true);

    let (mut upstream_stream, is_from_pool) = match state
        .upstream_pool
        .acquire_tagged_with_timeout(&vhost_ctx.proxy_upstream, conn_dur)
        .await
    {
        Ok(res) => res,
        Err(err) => {
            return Ok(if err.kind() == std::io::ErrorKind::TimedOut {
                h2_text_reply(504, b"504 Gateway Timeout - Proxy Upstream Timed Out\n")
            } else {
                h2_text_reply(502, b"502 Bad Gateway - Proxy Upstream Unavailable\n")
            });
        }
    };

    let client_addr = SocketAddr::new(real_ip, 0);
    let first = proxy
        .begin_decoded_response(
            &mut upstream_stream,
            raw_head.as_bytes(),
            &req.body,
            client_addr,
        )
        .await;
    let (head, mut reader) = match first {
        Ok(ok) => ok,
        // Havuzdaki bayat (arka uç tarafından kapatılmış) bağlantı: bir kez taze bağlantıyla dene.
        // Zaman aşımı ve geçersiz istek yeniden denenmez.
        Err(err)
            if is_from_pool
                && matches!(&err.error, ProxyError::Io(e) if e.kind() != std::io::ErrorKind::TimedOut) =>
        {
            let mut fresh = match state
                .upstream_pool
                .dial_fresh_with_timeout(&vhost_ctx.proxy_upstream, conn_dur)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "h2 vekil: taze upstream baglantisi acilamadi");
                    return Ok(h2_proxy_error_reply(&ProxyError::Connect(e.to_string())));
                }
            };
            match proxy
                .begin_decoded_response(&mut fresh, raw_head.as_bytes(), &req.body, client_addr)
                .await
            {
                Ok(ok) => {
                    upstream_stream = fresh;
                    ok
                }
                Err(e) => return Ok(h2_proxy_error_reply(&e.error)),
            }
        }
        Err(err) => return Ok(h2_proxy_error_reply(&err.error)),
    };

    if reader.is_finished() {
        if reader.upstream_reusable() {
            state.upstream_pool.release_with_ttl(
                &vhost_ctx.proxy_upstream,
                upstream_stream,
                ka_dur,
            );
        }
        return Ok((head.status, head.headers, bytes::Bytes::new(), None));
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(
        H2_PROXY_STREAM_QUEUE_CHUNKS,
    );
    let pool_state = Arc::clone(state);
    let upstream_addr = vhost_ctx.proxy_upstream.clone();
    // Görevin sahibi `tx`'tir: istemci akışı bırakınca (`tx.closed()`) görev biter, arka uç soketi
    // ve bağlantı yuvası düşürülür; arka uç sessizse `init_timeout` okumayı keser.
    tokio::spawn(async move {
        let _slot = slot;
        loop {
            let next = tokio::select! {
                r = reader.next_chunk(&mut upstream_stream) => r,
                _ = tx.closed() => return,
            };
            match next {
                Ok(Some(chunk)) => {
                    if tx.send(Ok(bytes::Bytes::from(chunk))).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(err) => {
                    let io_err = match err {
                        ProxyError::Io(e) => e,
                        other => std::io::Error::other(other.to_string()),
                    };
                    if tx.send(Err(io_err)).await.is_err() {
                        tracing::debug!("h2 vekil: istemci akisi hata bildirilmeden once kapandi");
                    }
                    return;
                }
            }
        }
        if reader.upstream_reusable() {
            pool_state
                .upstream_pool
                .release_with_ttl(&upstream_addr, upstream_stream, ka_dur);
        }
    });
    Ok((head.status, head.headers, bytes::Bytes::new(), Some(rx)))
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
            if let Ok(meta) = tokio::fs::metadata(&alt_path).await {
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

    let mut tags = Vec::new();
    append_domain_and_uri_cache_tags(&mut tags, &vhost_ctx.vhost_name, static_path);
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

#[cfg(target_os = "linux")]
async fn try_stream_tcp_sendfile(
    tcp_stream: &mut TcpStream,
    file: &tokio::fs::File,
    offset: &mut u64,
    remaining: &mut u64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::io::AsRawFd;

    tcp_stream.flush().await?;
    let out_fd = tcp_stream.as_raw_fd();
    let in_fd = file.as_raw_fd();
    let sendfile_write_timeout = Duration::from_secs(30);

    while *remaining > 0 {
        tokio::time::timeout(sendfile_write_timeout, tcp_stream.writable())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "sendfile soket yazma zaman aşımı",
                )
            })??;
        let chunk_cap = usize::try_from(*remaining)
            .unwrap_or(usize::MAX)
            .min(1024 * 1024);
        match tcp_stream.try_io(tokio::io::Interest::WRITABLE, || {
            zmax_static::try_sendfile_chunk(out_fd, in_fd, offset, chunk_cap)
        }) {
            Ok(0) => {
                // Beklenmeyen EOF durumunda kalanı tamponlu yedek akışla tamamla
                return Ok(false);
            }
            Ok(n) => {
                let n_u64 = u64::try_from(n).unwrap_or(*remaining);
                *remaining = remaining.saturating_sub(n_u64);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
                ) || matches!(
                    err.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSOCK | libc::EOPNOTSUPP)
                ) =>
            {
                return Ok(false);
            }
            Err(err) => return Err(Box::new(err)),
        }
    }

    Ok(true)
}

async fn stream_file_range_pooled<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    file: &mut tokio::fs::File,
    file_offset: u64,
    mut remaining: u64,
    is_https: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin + 'static,
{
    // [kart-8] Linux düz TCP (!is_https) statik aktarımında gerçek `sendfile(2)` sıfır-kopya yolu.
    // TLS bağlantılarında (`TlsStream<TcpStream>`) baytlar rustls ile kullanıcı alanında
    // şifrelendiği için çekirdek içi sendfile(2) kullanılamaz; doğrudan BufferPool tamponlu
    // okuma/yazma yedek yoluna düşülür.
    if !is_https && is_sendfile_supported() {
        if let Some(_tcp_stream) = (socket as &mut dyn std::any::Any).downcast_mut::<TcpStream>() {
            #[cfg(target_os = "linux")]
            {
                let mut cur_offset = file_offset;
                if try_stream_tcp_sendfile(_tcp_stream, file, &mut cur_offset, &mut remaining)
                    .await?
                {
                    return Ok(());
                }
                file.seek(std::io::SeekFrom::Start(cur_offset)).await?;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file_offset;

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

/// `[cache] respect_request_cache_control` (varsayılan KAPALI): istek `Cache-Control`/`Pragma` başlıkları önbelleği atlatır mı?
async fn respect_request_cache_control(state: &Arc<ServerState>) -> bool {
    state
        .runtime
        .read()
        .await
        .config
        .cache
        .respect_request_cache_control
}

fn request_has_bypass_cookie_or_auth(
    headers: &[(String, String)],
    respect_request_cache_control: bool,
) -> bool {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("authorization") {
            return true;
        }
        // Yapılandırma açık değilse bu başlıklar yok sayılır (istemci kaynaklı PHP amplifikasyonu).
        if respect_request_cache_control {
            if k.eq_ignore_ascii_case("cache-control")
                || k.eq_ignore_ascii_case("x-litespeed-cache-control")
            {
                let lower = v.to_ascii_lowercase();
                if lower.contains("no-cache")
                    || lower.contains("no-store")
                    || lower.contains("private")
                {
                    return true;
                }
            }
            if k.eq_ignore_ascii_case("pragma") && v.to_ascii_lowercase().contains("no-cache") {
                return true;
            }
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
        if k.eq_ignore_ascii_case("x-litespeed-cache-control") {
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

/// `PURGE` isteği / `X-LiteSpeed-Purge` istek başlığı için yetki denetimi (HTTP/1.1 ve HTTP/2 ortak).
///
/// Özellik `[cache] purge_enabled = true` değilse KAPALIDIR. Açıkken istek ya `purge_key_header`
/// başlığında `purge_key` değerini (sabit zamanlı karşılaştırma) taşımalı ya da istemci IP'si
/// `purge_allow_ips` (IP/CIDR) listesinde olmalıdır; ikisi de yapılandırılmamışsa hiçbir istek yetkili değildir.
pub(crate) fn authorize_purge(
    cfg: &zmax_config::CacheConfig,
    headers: &[(String, String)],
    client_ip: IpAddr,
) -> bool {
    if !cfg.purge_enabled {
        return false;
    }
    if !cfg.purge_key.is_empty() {
        if let Some(given) = extract_header(headers, &cfg.purge_key_header) {
            if !given.is_empty() && crate::api::constant_time_eq(given, &cfg.purge_key) {
                return true;
            }
        }
    }
    cfg.purge_allow_ips
        .iter()
        .any(|spec| zmax_security::ip_matches_cidr_spec(client_ip, spec.trim()))
}

/// Ortak PURGE isteği sonucu (HTTP/1.1 ve HTTP/2 aynı karar yolunu kullanır).
pub(crate) enum PurgeRequestOutcome {
    /// İstek PURGE değil; normal akış sürer.
    NotPurge,
    /// PURGE isteği yetkisiz: 403, önbellek değişmez.
    Forbidden,
    /// Yetkili PURGE yapıldı; gerçekte silinen girdi sayısı.
    Done(usize),
}

/// `PURGE` metodu veya `X-LiteSpeed-Purge` istek başlığını yetki denetiminden geçirip uygular.
pub(crate) async fn process_cache_purge_request(
    state: &Arc<ServerState>,
    vhost_name: &str,
    req: &ParsedHttpRequest,
    client_ip: IpAddr,
) -> PurgeRequestOutcome {
    let purge_header = extract_header(&req.headers, "x-litespeed-purge");
    if !req.method.eq_ignore_ascii_case("PURGE") && purge_header.is_none() {
        return PurgeRequestOutcome::NotPurge;
    }
    let allowed = {
        let rt = state.runtime.read().await;
        authorize_purge(&rt.config.cache, &req.headers, client_ip)
    };
    if !allowed {
        return PurgeRequestOutcome::Forbidden;
    }
    PurgeRequestOutcome::Done(
        handle_lscache_request_purge(state, vhost_name, &req.path, purge_header).await,
    )
}

/// Yetkili isteği vhost kapsamında uygular ve gerçekte silinen benzersiz girdi sayısını döner.
///
/// `X-LiteSpeed-Purge` varsa (`*` veya etiket listesi) yalnız bu vhost'un `alan::etiket` kayıtları silinir;
/// yoksa `PURGE <yol>` o vhost'un ilgili yolundaki girdileri siler (başka vhost etkilenmez).
async fn handle_lscache_request_purge(
    state: &Arc<ServerState>,
    vhost_name: &str,
    path: &str,
    purge_header: Option<&str>,
) -> usize {
    match purge_header {
        Some(hdr) => {
            let hdrs = [("x-litespeed-purge", hdr)];
            let directive = parse_lscache_headers(hdrs.iter().copied());
            state
                .cache
                .apply_lscache_purge(vhost_name, &directive)
                .await
        }
        None => state.cache.purge_by_domain_uri(vhost_name, path).await,
    }
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
    let safe_path_owned = zmax_security::waf_events::redact_sensitive_url_target(path);
    let safe_path = if safe_path_owned.is_empty() {
        "/"
    } else {
        safe_path_owned.as_str()
    };
    state.record_access_log_detailed(
        ip,
        method,
        safe_path,
        status,
        started.elapsed(),
        actual_bytes,
        referer.unwrap_or(""),
        user_agent.unwrap_or(""),
    );
    let line = format!(
        "{} - - \"{} {} {}\" {} {}\r\n",
        ip, method, safe_path, http_version, status, bytes_str
    );
    append_access_log_limit(&state.base_dir, &line, max_log_size_bytes).await;

    record_and_log_vhost(
        state,
        ip,
        method,
        safe_path,
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
        let rel_page_opt = ctx.error_docs.pages.get(&status).or_else(|| {
            if status == 404 {
                ctx.error_docs.not_found.as_ref()
            } else {
                None
            }
        });
        if let Some(rel_page) = rel_page_opt {
            let custom_dir = if ctx.error_docs.dir.trim().is_empty() {
                None
            } else {
                Some(Path::new(ctx.error_docs.dir.trim()))
            };
            let handler = StaticFileHandler::new(&ctx.doc_root);
            let loaded = handler
                .resolve_error_doc_file(&ctx.doc_root, custom_dir, rel_page)
                .unwrap_or_else(|_| default_msg.to_vec());
            if loaded.is_empty() {
                if default_msg.is_empty() {
                    format!("{} {}\n", status, reason).into_bytes()
                } else {
                    default_msg.to_vec()
                }
            } else {
                loaded
            }
        } else if default_msg.is_empty() {
            format!("{} {}\n", status, reason).into_bytes()
        } else {
            default_msg.to_vec()
        }
    } else if default_msg.is_empty() {
        format!("{} {}\n", status, reason).into_bytes()
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
// Neden izinli: `proxy_stream` yalniz bu fonksiyonun cikti kanalidir (tek cagiran h2_engine); bunu
// sonuc demetine eklemek ~25 donus noktasini degistirirdi.
#[allow(clippy::too_many_arguments)]
pub async fn handle_h2_dispatched_request(
    req: &ParsedHttpRequest,
    real_ip: IpAddr,
    state: &Arc<ServerState>,
    is_https: bool,
    listen_port: u16,
    tls_sni: Option<&str>,
    req_id: &str,
    proxy_stream: &mut Option<H2BodyReceiver>,
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

    let (policies, vhost_ctx, is_unknown_host) = {
        let rt = state.runtime.read().await;
        let policies = rt.policies.clone();
        let vh_opt = match_vhost(&rt.vhosts, effective_host);
        let is_unknown_host =
            !rt.vhosts.is_empty() && !effective_host.trim().is_empty() && vh_opt.is_none();
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
                // [v1-1b] [vhost.security] ve [vhost.acl] kurallari tutarli birlestirilir
                vhost_acl_engine: crate::security_pipeline::build_merged_vhost_acl(
                    &vh.entry.security,
                    &vh.entry.acl,
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
                // [kart-10]
                proxy_ext: vh.entry.proxy_ext.clone(),
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
                acme_root: crate::acme_runtime::resolve_vhost_acme_root(
                    Some(&vh.entry),
                    &state.base_dir,
                ),
                auth: vh.entry.auth.clone(),
                php_dial_timeout_ms: resolve_php_dial_timeout_ms(
                    vh.entry.php.dial_timeout_ms,
                    policies.fastcgi.dial_timeout_ms,
                ),
                autoindex: vh.entry.static_files.autoindex,
                block_dangerous_files: vh.entry.security.block_dangerous_files,
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
                // [kart-10]
                proxy_ext: zmax_config::ProxyExtConfig::default(),
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
                acme_root: None,
                auth: zmax_config::VHostAuthSection::default(),
                php_dial_timeout_ms: resolve_php_dial_timeout_ms(
                    None,
                    policies.fastcgi.dial_timeout_ms,
                ),
                autoindex: policies.static_policy.directory_browsing,
                block_dangerous_files: false,
            },
        };
        (policies, ctx, is_unknown_host)
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

    // [kart-12-a] Bilinmeyen Host: server_name eşleşmeyen istek için güvenli varsayılan 403 Forbidden
    if is_unknown_host {
        let resp_body = bytes::Bytes::from_static(b"403 Forbidden - Unknown Host\n");
        let headers = vec![
            ("content-type".into(), "text/plain; charset=utf-8".into()),
            ("x-request-id".into(), req_id.to_string()),
        ];
        return Ok((403, headers, resp_body, log_meta));
    }

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
            let target_uri = if req.query.is_empty() {
                req.path.clone()
            } else {
                format!("{}?{}", req.path, req.query)
            };
            crate::security_pipeline::record_waf_block(
                state,
                &vhost_ctx,
                &real_ip.to_string(),
                &req.method,
                &target_uri,
                &violation,
            );
            let safe_waf_path = zmax_security::waf_events::sanitize_waf_path(&target_uri);
            let safe_waf_rule = zmax_security::waf_events::format_waf_rule_label(&violation);
            let err_line = format!(
                "[WAF] [{}] {} {} {} -> {}",
                vhost_ctx.vhost_name, real_ip, req.method, safe_waf_path, safe_waf_rule
            );
            append_error_log_limit(&state.base_dir, &err_line, vhost_ctx.max_log_size_bytes).await;
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
                ("x-waf-violation".into(), safe_waf_rule),
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

    // 4. [kart-9] Basic Authentication ($apr1$ & Argon2id)
    let auth_decision =
        crate::security_pipeline::evaluate_basic_auth(
            &vhost_ctx,
            real_ip,
            &req.path,
            &req.headers,
            &state.basic_auth,
            &state.base_dir,
            &state.ban_manager,
        )
        .await;
    if let Some(denial) =
        crate::security_pipeline::build_auth_denial(
            &vhost_ctx,
            &auth_decision,
            (!req_id.is_empty()).then_some(req_id),
        )
    {
        return Ok((
            denial.status,
            denial.headers,
            bytes::Bytes::from(denial.body),
            log_meta,
        ));
    }

    // 4b. [matris-cache-tags] PURGE metodu / X-LiteSpeed-Purge istek basligi (HTTP/1.1 ile ayni yetki denetimi)
    match process_cache_purge_request(state, &vhost_ctx.vhost_name, req, real_ip).await {
        PurgeRequestOutcome::NotPurge => {}
        outcome => {
            let (status, purge_body) = match outcome {
                PurgeRequestOutcome::Done(n) => (200, format!("Purged {n} entries\n")),
                _ => (403, "403 Forbidden\n".to_string()),
            };
            let resp_hdrs = vec![
                ("content-type".into(), "text/plain; charset=utf-8".into()),
                ("x-request-id".into(), req_id.to_string()),
            ];
            return Ok((status, resp_hdrs, bytes::Bytes::from(purge_body), log_meta));
        }
    }

    // 4.5. Ters Vekil Yönlendirmesi (HTTP/2 -> Upstream HTTP/1.1)
    if vhost_ctx.proxy_enabled
        && !vhost_ctx.proxy_upstream.trim().is_empty()
        && req.path.starts_with(&vhost_ctx.proxy_path_prefix)
    {
        match serve_h2_proxy_request(
            state,
            req,
            real_ip,
            &vhost_ctx,
            policies.proxy.connect_timeout_sec,
        )
        .await
        {
            Ok((status, mut headers, body, stream)) => {
                headers.push(("x-request-id".into(), req_id.to_string()));
                // Gövde akışı varsa h2 motoru parça parça yazar (`body` boş kalır).
                *proxy_stream = stream;
                return Ok((status, headers, body, log_meta));
            }
            Err(e) => {
                tracing::warn!(error = %e, "H2 proxy request forward failed");
                let body = bytes::Bytes::from_static(b"502 Bad Gateway - Proxy Forward Failed\n");
                let headers = vec![
                    ("content-type".into(), "text/plain; charset=utf-8".into()),
                    ("x-request-id".into(), req_id.to_string()),
                ];
                return Ok((502, headers, body, log_meta));
            }
        }
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
        autoindex: vhost_ctx.autoindex,
        block_dangerous_files: vhost_ctx.block_dangerous_files,
    };
    let (effective_path, is_php_route, eff_query) = if is_acme_challenge(&req.path) {
        (req.path.clone(), false, req.query.clone())
    } else {
        let route_res = state.htaccess_resolver.resolve_with_info(&route_req);
        match route_res.outcome {
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
                let body = if let Some(custom_err) = route_res.error_documents.get(&403) {
                    let clean = custom_err.trim_start_matches('/');
                    std::fs::read(vhost_ctx.doc_root.join(clean))
                        .unwrap_or_else(|_| b"403 Forbidden\n".to_vec())
                } else if let Some(rel) = vhost_ctx.error_docs.pages.get(&403) {
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
                let rel_opt = vhost_ctx
                    .error_docs
                    .pages
                    .get(&404)
                    .or(vhost_ctx.error_docs.not_found.as_ref());
                let body = if let Some(rel) = rel_opt {
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
        }
    };

    // 6. FastCGI (PHP) veya Statik Dosya Yonlendirme
    if is_php_route && vhost_ctx.php_enabled {
        let is_head = req.method.eq_ignore_ascii_case("HEAD");
        let respect_req_cc = respect_request_cache_control(state).await;
        let php_cacheable_req = vhost_ctx.cache_enabled
            && req.method.eq_ignore_ascii_case("GET")
            && !request_has_bypass_cookie_or_auth(&req.headers, respect_req_cc);
        // HTTP/1.1 ile ayni anahtar (istemcinin ham yolu + etkin sorgu): purge ve HIT iki protokolde ortak.
        let php_cache_key = build_cache_key(
            &vhost_ctx.vhost_name,
            is_https,
            &req.method,
            &req.path,
            &eff_query,
            Some("identity"),
        );
        if php_cacheable_req {
            if let CacheLookup::Fresh(cached) = state.cache.get_with_stale(&php_cache_key).await {
                state.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                let body = if is_head || cached.status == 204 || cached.status == 304 {
                    bytes::Bytes::new()
                } else {
                    cached.body
                };
                let resp_headers = vec![
                    ("content-type".into(), cached.content_type),
                    ("x-cache".into(), "HIT".to_string()),
                    ("x-request-id".into(), req_id.to_string()),
                ];
                return Ok((cached.status, resp_headers, body, log_meta));
            }
        }
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
            php_cacheable_req,
            &php_cache_key,
            MAX_STATIC_CACHE_BYTES,
            is_head,
        )
        .await;

        match prep_res {
            Ok(Some(prep)) => {
                let mut resp_headers = prep.headers;
                let cache_status = if !php_cacheable_req || prep.cache_forbidden {
                    "BYPASS"
                } else {
                    "MISS"
                };
                resp_headers.push(("x-cache".into(), cache_status.to_string()));
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
    let resolved = if is_acme_challenge(&effective_path) {
        match vhost_ctx.acme_root.as_deref() {
            Some(vhost_root) => {
                static_handler.resolve_acme_challenge_with_root(&effective_path, Some(vhost_root))
            }
            None => static_handler.resolve_acme_challenge(&effective_path),
        }
    } else {
        static_handler
            .resolve_with_index(&effective_path, &vhost_ctx.index_files)
            .or_else(|| resolve_predecoded_static_file(&vhost_ctx.doc_root, &effective_path))
    };
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
            let rel_opt = vhost_ctx
                .error_docs
                .pages
                .get(&404)
                .or(vhost_ctx.error_docs.not_found.as_ref());
            let body = if let Some(rel) = rel_opt {
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

#[cfg(test)]
mod kart8_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn fastcgi_pooled_execution_and_httpoxy_prevention_pipeline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fcgi_addr = listener.local_addr().unwrap().to_string();

        let accepted_count = Arc::new(AtomicUsize::new(0));
        let acc_clone = accepted_count.clone();

        let srv = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                acc_clone.fetch_add(1, Ordering::SeqCst);
                loop {
                    let mut buf = vec![0u8; 8192];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => break,
                    };
                    let raw_req = &buf[..n];

                    // HTTP_PROXY sızıntı kontrolü
                    let req_str = String::from_utf8_lossy(raw_req);
                    assert!(
                        !req_str.contains("HTTP_PROXY"),
                        "HTTPoxy sızıntısı tespit edildi!"
                    );
                    assert!(
                        !req_str.contains("http_proxy"),
                        "HTTPoxy sızıntısı tespit edildi!"
                    );

                    // FastCGI yanıtı: 200 OK
                    let resp_body = b"Content-Type: text/plain\r\n\r\nHello from pooled PHP";
                    let len_be = (resp_body.len() as u16).to_be_bytes();
                    let mut out = Vec::new();
                    out.extend_from_slice(&[1, 6, 0, 1, len_be[0], len_be[1], 0, 0]);
                    out.extend_from_slice(resp_body);
                    out.extend_from_slice(&[1, 6, 0, 1, 0, 0, 0, 0]);
                    out.extend_from_slice(&[1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                    let _ = stream.write_all(&out).await;
                    let _ = stream.flush().await;
                }
            }
        });

        let pool = Arc::new(zmax_pool::UpstreamSocketPool::new(4));
        let client = FastCgiClient::with_pool(&fcgi_addr, pool.clone());

        // Proxy başlığı ile istek gönder (HTTPoxy saldırı vektörü)
        let req = FastCgiRequest::new("GET", "/test.php", "/test.php", "/srv/test.php", "/srv")
            .header("Proxy", "http://evil-attacker-proxy.invalid:8888")
            .header("proxy", "http://another-evil.invalid")
            .header("Host", "example.test");

        let res = client
            .execute_php_pooled(req, Duration::from_secs(2), Duration::from_secs(2))
            .await
            .expect("FastCGI havuzlu istek başarılı olmalı");

        assert_eq!(res.status, 200);
        assert_eq!(res.body, b"Hello from pooled PHP");

        // İkinci istek: Havuzun bağlantıyı yeniden kullandığını doğrula
        let req2 = FastCgiRequest::new("GET", "/test2.php", "/test2.php", "/srv/test2.php", "/srv")
            .header("Host", "example.test");

        let res2 = client
            .execute_php_pooled(req2, Duration::from_secs(2), Duration::from_secs(2))
            .await
            .expect("İkinci havuzlu istek başarılı olmalı");

        assert_eq!(res2.status, 200);
        assert_eq!(accepted_count.load(Ordering::SeqCst), 1);

        srv.abort();
    }

    fn build_kart8_test_state(tag: &str, mod_fastcgi_toml: Option<&str>) -> Arc<ServerState> {
        use crate::api::{RuntimeState, ServerStats};
        use crate::modules_runtime::{compile_policies, compute_effective_auth};
        use std::collections::VecDeque;
        use std::sync::Mutex;
        use tokio::sync::RwLock;
        use zmax_config::{resolve_path, LoadedModules, LoadedVHost, VHostEntry, ZMaxConfig};

        let base =
            std::env::temp_dir().join(format!("zmax_kart8_we_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let www_root = base.join("www").join("html");
        std::fs::create_dir_all(&www_root).unwrap();
        std::fs::create_dir_all(base.join("modules")).unwrap();
        std::fs::create_dir_all(base.join("logs")).unwrap();
        std::fs::create_dir_all(base.join("admin")).unwrap();

        if let Some(toml_body) = mod_fastcgi_toml {
            std::fs::write(base.join("modules").join("mod_fastcgi.toml"), toml_body).unwrap();
        }

        let entry = VHostEntry {
            name: "kart8.test".into(),
            document_root: "www/html".into(),
            ..Default::default()
        };
        let vh = LoadedVHost {
            resolved_doc_root: resolve_path(&base, &entry.document_root),
            entry,
            file_name: "kart8.test.toml".into(),
        };

        let mut cfg = ZMaxConfig::parse_toml("").unwrap();
        cfg.cache.enabled = false;
        let modules = LoadedModules::load_from_dir(&base.join("modules")).unwrap();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);

        Arc::new(ServerState {
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                4 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            limiter: RwLock::new(zmax_security::RateLimiter::new(u32::MAX)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::new(3, 60, 300)),
            buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
            upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::default()),
            runtime: RwLock::new(RuntimeState {
                config: cfg,
                vhosts: vec![vh],
                modules,
                policies,
                redis_client: None,
                auth,
                conf_path: base.join("zmax.toml"),
                vhosts_dir: base.join("conf").join("vhosts"),
                modules_dir: base.join("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                base.join("admin"),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(crate::logger::AsyncLogManager::new(
                base.clone(),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                10,
                16,
            )),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            access_logs: Mutex::new(VecDeque::with_capacity(64)),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: std::sync::atomic::AtomicU64::new(0),
                cache_hits: std::sync::atomic::AtomicU64::new(0),
                cache_misses: std::sync::atomic::AtomicU64::new(0),
            },
        })
    }

    async fn send_plain_tcp_http_request(addr: SocketAddr, req_raw: &[u8]) -> (String, Vec<u8>) {
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(req_raw).await.unwrap();
        client.shutdown().await.unwrap();

        let mut full = Vec::new();
        client.read_to_end(&mut full).await.unwrap();
        let split = full
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("HTTP yanit baslik sonu bulunmali");
        let head = String::from_utf8_lossy(&full[..split]).into_owned();
        let body = full[split + 4..].to_vec();
        (head, body)
    }

    #[tokio::test]
    async fn handle_web_connection_plain_tcp_large_file_and_range_transfer() {
        let state = build_kart8_test_state("sendfile_tcp", None);
        let doc_root = state.base_dir.join("www").join("html");
        let payload_len = MAX_STATIC_CACHE_BYTES + 65_537;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        std::fs::write(doc_root.join("large.bin"), &payload).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st_srv = Arc::clone(&state);
        let srv_task = tokio::spawn(async move {
            for _ in 0..2 {
                let (socket, peer) = listener.accept().await.unwrap();
                let st_conn = Arc::clone(&st_srv);
                tokio::spawn(async move {
                    let _ = handle_web_connection(socket, peer, st_conn, false, addr.port()).await;
                });
            }
        });

        // 1. Düz TCP tam dosya (>2 MiB): BYPASS akış yolu (Linux'ta sendfile(2), diğerlerinde BufferPool)
        let (head_full, body_full) = send_plain_tcp_http_request(
            addr,
            b"GET /large.bin HTTP/1.1\r\nHost: kart8.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(head_full.starts_with("HTTP/1.1 200 OK"), "{head_full}");
        assert!(head_full.contains("X-Cache: BYPASS"), "{head_full}");
        assert_eq!(body_full.len(), payload.len());
        assert_eq!(body_full, payload, "Tam dosya gövdesi birebir eşleşmeli");

        // 2. Düz TCP büyük Range (>2 MiB dilim): 206 Partial Content akışı
        let range_start = 1024usize;
        let range_end = payload.len() - 1;
        let range_req = format!(
            "GET /large.bin HTTP/1.1\r\nHost: kart8.test\r\nRange: bytes={}-{}\r\nConnection: close\r\n\r\n",
            range_start, range_end
        );
        let (head_rng, body_rng) = send_plain_tcp_http_request(addr, range_req.as_bytes()).await;
        assert!(
            head_rng.starts_with("HTTP/1.1 206 Partial Content"),
            "{head_rng}"
        );
        assert_eq!(body_rng, payload[range_start..=range_end]);

        // 3. TLS yolu (is_https = true): sendfile kullanılmadan BufferPool yedek yolu ile tam eşleşme
        let (mut c_tls_sim, s_tls_sim) = tokio::io::duplex(256 * 1024);
        let st_tls = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:41999".parse().unwrap();
        let tls_task =
            tokio::spawn(
                async move { handle_web_connection(s_tls_sim, peer, st_tls, true, 443).await },
            );
        c_tls_sim
            .write_all(b"GET /large.bin HTTP/1.1\r\nHost: kart8.test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        c_tls_sim.shutdown().await.unwrap();
        let mut raw_tls = Vec::new();
        c_tls_sim.read_to_end(&mut raw_tls).await.unwrap();
        tls_task.await.unwrap().unwrap();
        let split_tls = raw_tls.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert_eq!(&raw_tls[split_tls + 4..], &payload[..]);

        srv_task.abort();
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn php_dial_timeout_ms_resolved_from_config_and_vhost() {
        assert_eq!(resolve_php_dial_timeout_ms(None, 420), 420);
        assert_eq!(resolve_php_dial_timeout_ms(Some(0), 420), 420);
        assert_eq!(resolve_php_dial_timeout_ms(Some(1234), 420), 1234);
        assert_eq!(resolve_php_dial_timeout_ms(None, 0), 1);

        let mod_toml = "[module]\nname = \"mod_fastcgi\"\nenabled = true\n\n[settings]\ndial_timeout_ms = 420\n";
        let state = build_kart8_test_state("dial_timeout", Some(mod_toml));

        // Sahte FastCGI sunucusu
        let fcgi_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fcgi_addr = fcgi_listener.local_addr().unwrap().to_string();
        let fcgi_srv = tokio::spawn(async move {
            while let Ok((mut stream, _)) = fcgi_listener.accept().await {
                let mut buf = vec![0u8; 8192];
                if stream.read(&mut buf).await.unwrap_or(0) > 0 {
                    let resp_body = b"Content-Type: text/plain\r\n\r\nOK_CFG_DIAL";
                    let len_be = (resp_body.len() as u16).to_be_bytes();
                    let mut out = Vec::new();
                    out.extend_from_slice(&[1, 6, 0, 1, len_be[0], len_be[1], 0, 0]);
                    out.extend_from_slice(resp_body);
                    out.extend_from_slice(&[1, 6, 0, 1, 0, 0, 0, 0]);
                    out.extend_from_slice(&[1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                    let _ = stream.write_all(&out).await;
                    let _ = stream.flush().await;
                }
            }
        });

        let doc_root = state.base_dir.join("www").join("html");
        std::fs::write(doc_root.join("info.php"), b"<?php echo 'ok'; ?>").unwrap();
        {
            let mut rt = state.runtime.write().await;
            assert_eq!(rt.policies.fastcgi.dial_timeout_ms, 420);
            rt.vhosts[0].entry.php.enabled = true;
            rt.vhosts[0].entry.php.upstream = fcgi_addr.clone();
            rt.vhosts[0].entry.php.dial_timeout_ms = Some(1234);
        }

        // 1. handle_web_connection üzerinden gerçek TCP PHP isteği
        let web_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_listener.local_addr().unwrap();
        let st_srv = Arc::clone(&state);
        let web_task = tokio::spawn(async move {
            let (socket, peer) = web_listener.accept().await.unwrap();
            let _ = handle_web_connection(socket, peer, st_srv, false, web_addr.port()).await;
        });

        let (head, body) = send_plain_tcp_http_request(
            web_addr,
            b"GET /info.php HTTP/1.1\r\nHost: kart8.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert_eq!(&body, b"OK_CFG_DIAL");
        let _ = web_task.await;

        // 2. Doğrudan vhost_ctx.php_dial_timeout_ms ayarının mod_fastcgi ile uyumlu çözülüşü
        let ctx_zero_vhost = {
            let rt = state.runtime.read().await;
            resolve_php_dial_timeout_ms(None, rt.policies.fastcgi.dial_timeout_ms)
        };
        assert_eq!(ctx_zero_vhost, 420);

        fcgi_srv.abort();
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    /// Kabul kuyruğunu dolduran, `accept` etmeyen bir dinleyici: sonraki `connect` çağrıları (Linux ve
    /// Windows'ta) SYN kuyruğunda takılır; bağlantı zaman aşımının GERÇEKTEN uygulandığını ölçmek için.
    /// Dönen değerler düşürülene kadar (test sonuna dek) kuyruk dolu kalır.
    fn blackhole_listener() -> (SocketAddr, Vec<std::net::TcpStream>, socket2::Socket) {
        use socket2::{Domain, Socket, Type};
        let sock = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        sock.bind(&bind.into()).unwrap();
        sock.listen(1).unwrap();
        let addr = sock.local_addr().unwrap().as_socket().unwrap();
        let mut held = Vec::new();
        for _ in 0..64 {
            match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(250)) {
                Ok(c) => held.push(c),
                Err(_) => return (addr, held, sock),
            }
        }
        panic!("kabul kuyruğu dolmadı; bağlantı zaman aşımı testi güvenilmez");
    }

    /// `mod_fastcgi.dial_timeout_ms` (politika) vhost `dial_timeout_ms` vermediğinde GERÇEKTEN kullanılır:
    /// bağlantı kurulamayan arka uçta yanıt, politika süresine (~400 ms) yakın gelir; 3 sn / 5 sn
    /// varsayılanına DEĞİL.
    #[tokio::test]
    async fn php_dial_timeout_policy_applies_when_vhost_unset_slow_upstream() {
        let mod_toml = "[module]\nname = \"mod_fastcgi\"\nenabled = true\n\n[settings]\ndial_timeout_ms = 400\n";
        let state = build_kart8_test_state("dial_slow_policy", Some(mod_toml));
        let (bh_addr, _held, _listener) = blackhole_listener();
        std::fs::write(
            state.base_dir.join("www").join("html").join("info.php"),
            b"<?php echo 'ok'; ?>",
        )
        .unwrap();
        {
            let mut rt = state.runtime.write().await;
            assert_eq!(rt.policies.fastcgi.dial_timeout_ms, 400);
            rt.vhosts[0].entry.php.enabled = true;
            rt.vhosts[0].entry.php.upstream = bh_addr.to_string();
        }

        let web_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_listener.local_addr().unwrap();
        let st_srv = Arc::clone(&state);
        let web_task = tokio::spawn(async move {
            let (socket, peer) = web_listener.accept().await.unwrap();
            let _ = handle_web_connection(socket, peer, st_srv, false, web_addr.port()).await;
        });
        let started = std::time::Instant::now();
        let (head, _body) = send_plain_tcp_http_request(
            web_addr,
            b"GET /info.php HTTP/1.1\r\nHost: kart8.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let elapsed = started.elapsed();
        let _ = web_task.await;
        assert!(head.starts_with("HTTP/1.1 502"), "502 beklenirdi: {head}");
        assert!(
            elapsed >= Duration::from_millis(350),
            "politika süresinden önce kesildi: {elapsed:?}"
        );
        // Zaman ölçümüne (yük altında oynak) değil, bağlantıya UYGULANAN değere bakılır: havuz hata metni
        // `tokio::time::timeout`a verilen süreyi taşır.
        let log = std::fs::read_to_string(state.base_dir.join("logs").join("error.log"))
            .unwrap_or_default();
        assert!(
            log.contains("baglanti zaman asimi (400 ms)"),
            "politika dial_timeout_ms=400 bağlantıya uygulanmadı; hata günlüğü: {log}"
        );
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    /// vhost `php.dial_timeout_ms = Some(900)` verildiğinde politika (400 ms) DEĞİL vhost değeri, bağlantı
    /// kurulamayan arka uçta gerçekten uygulanır (yanıt ~900 ms'de gelir).
    #[tokio::test]
    async fn php_dial_timeout_vhost_value_applies_slow_upstream() {
        let mod_toml = "[module]\nname = \"mod_fastcgi\"\nenabled = true\n\n[settings]\ndial_timeout_ms = 400\n";
        let state = build_kart8_test_state("dial_slow_vhost", Some(mod_toml));
        let (bh_addr, _held, _listener) = blackhole_listener();
        std::fs::write(
            state.base_dir.join("www").join("html").join("info.php"),
            b"<?php echo 'ok'; ?>",
        )
        .unwrap();
        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.php.enabled = true;
            rt.vhosts[0].entry.php.upstream = bh_addr.to_string();
            rt.vhosts[0].entry.php.dial_timeout_ms = Some(900);
        }

        let web_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_listener.local_addr().unwrap();
        let st_srv = Arc::clone(&state);
        let web_task = tokio::spawn(async move {
            let (socket, peer) = web_listener.accept().await.unwrap();
            let _ = handle_web_connection(socket, peer, st_srv, false, web_addr.port()).await;
        });
        let started = std::time::Instant::now();
        let (head, _body) = send_plain_tcp_http_request(
            web_addr,
            b"GET /info.php HTTP/1.1\r\nHost: kart8.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        let elapsed = started.elapsed();
        let _ = web_task.await;
        assert!(head.starts_with("HTTP/1.1 502"), "502 beklenirdi: {head}");
        assert!(
            elapsed >= Duration::from_millis(800),
            "vhost değeri (900 ms) uygulanmadı, politika kazandı: {elapsed:?}"
        );
        let log = std::fs::read_to_string(state.base_dir.join("logs").join("error.log"))
            .unwrap_or_default();
        assert!(
            log.contains("baglanti zaman asimi (900 ms)"),
            "vhost dial_timeout_ms=900 bağlantıya uygulanmadı; hata günlüğü: {log}"
        );
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }
}
