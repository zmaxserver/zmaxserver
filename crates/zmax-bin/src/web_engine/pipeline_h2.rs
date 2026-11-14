use super::cache_policy::{request_has_bypass_cookie_or_auth, respect_request_cache_control};
use super::context::{resolve_php_dial_timeout_ms, LogMeta, ResolvedVHostContext};
use super::php::execute_and_prepare_php;
use super::proxy_h2::{serve_h2_proxy_request, H2BodyReceiver};
use super::purge::{process_cache_purge_request, PurgeRequestOutcome};
use super::request_util::is_acme_challenge;
use super::static_files::resolve_predecoded_static_file;
use super::{DEFAULT_LOG_MAX_BYTES, MAX_STATIC_CACHE_BYTES};
use crate::api::{ParsedHttpRequest, ServerState};
use crate::modules_runtime::append_error_log_limit;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use zmax_cache::{build_cache_key, CacheLookup};
use zmax_config::match_vhost;
use zmax_rewrite::RouteOutcome;
use zmax_security::IpAccessList;
use zmax_static::{check_if_none_match, StaticFileHandler};

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
                acme_root: crate::config::acme::resolve_vhost_acme_root(
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
