use super::cache_policy::{request_has_bypass_cookie_or_auth, respect_request_cache_control};
use super::cached_response::{write_cached_php_response, write_cached_static_response};
use super::context::{resolve_php_dial_timeout_ms, ResolvedVHostContext};
use super::http_write::{
    default_status_reason, write_error_response, write_http_response, write_not_found,
};
use super::logging::record_and_log;
use super::php::{fetch_and_cache_php, serve_php_request};
use super::proxy_h1::serve_proxy_request;
use super::purge::{process_cache_purge_request, PurgeRequestOutcome};
use super::request_util::is_acme_challenge;
use super::static_files::{
    negotiable_image_cache_tag, resolve_predecoded_static_file, revalidate_static_cache,
    serve_static_file,
};
use super::DEFAULT_LOG_MAX_BYTES;
use crate::api::{
    read_http_request_with_limits, send_http_read_error, ParsedHttpRequest, ServerState,
};
use crate::modules_runtime::{append_error_log_limit, resolve_vhost_security_headers};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use zmax_cache::{build_cache_key, CacheLookup, StampedeSlot};
use zmax_compress::{negotiate_encoding, ContentEncoding};
use zmax_config::match_vhost;
use crate::pipeline::l3_realip::resolve_real_ip;
use zmax_httpparser::{extract_header, HttpReadLimits};
use zmax_rewrite::{HtAccessResolver, RewriteEngine, RouteOutcome, RouteRequest};
use zmax_security::IpAccessList;
use zmax_static::StaticFileHandler;
use zmax_timeout::with_idle_timeout;

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

    let real_ip: IpAddr = resolve_real_ip(&policies.realip, peer_addr.ip(), &req.headers);
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
