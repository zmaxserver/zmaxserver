use super::super::*;

pub(crate) async fn health_version<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
    strict_api_only: bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/health" || (strict_api_only && req_path == "/") {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let (vhosts_len, mods_len) = {
            let rt = state.runtime.read().await;
            (rt.vhosts.len(), rt.modules.len())
        };
        let json = format!(
            r#"{{"ok":true,"status":"ok","engine":"zmax","version":"{}","pid":{},"uptime_seconds":{},"vhosts":{},"modules":{},"uptime_sec":{},"contract_version":"{}","generation":{}}}"#,
            env!("ZMAX_VERSION"),
            std::process::id(),
            uptime_secs,
            vhosts_len,
            mods_len,
            uptime_secs,
            crate::api::bridge::CONTRACT_VERSION,
            crate::core::state::CONFIG_GENERATION.load(std::sync::atomic::Ordering::SeqCst)
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 1a. Genel sürüm ucu: token'sız, salt okunur, yalnız sürüm (WebAdmin başlığı/alt bilgisi için).
    // Muafiyet yalnız bu tam yol + GET içindir; başka hiçbir uç nokta token kapısından muaf değildir.
    if req_path == "/api/version" && req.method == "GET" {
        let json = format!(r#"{{"version":"{}"}}"#, env!("ZMAX_VERSION"));
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn metrics<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if (req_path == "/metrics" || req_path == "/api/v1/metrics") && req.method == "GET" {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let total = state.stats.total_requests.load(Ordering::Relaxed);
        let hits = state.stats.cache_hits.load(Ordering::Relaxed);
        let misses = state.stats.cache_misses.load(Ordering::Relaxed);
        let banned_count = state.ban_manager.list_banned().len();
        let waf_total = state.waf_events.total_count();
        let waf_24h = state.waf_events.last_24h_count();
        let (vhosts_len, mods_len) = {
            let rt = state.runtime.read().await;
            (rt.vhosts.len(), rt.modules.len())
        };
        let body = format!(
            "# HELP zmax_uptime_seconds ZMax sunucusunun calisma suresi (saniye).\n\
             # TYPE zmax_uptime_seconds gauge\n\
             zmax_uptime_seconds {}\n\
             # HELP zmax_requests_total Toplam islenen HTTP istek sayisi.\n\
             # TYPE zmax_requests_total counter\n\
             zmax_requests_total {}\n\
             # HELP zmax_cache_hits_total L1/L2 onbellek isabet sayisi.\n\
             # TYPE zmax_cache_hits_total counter\n\
             zmax_cache_hits_total {}\n\
             # HELP zmax_cache_misses_total L1/L2 onbellek iska sayisi.\n\
             # TYPE zmax_cache_misses_total counter\n\
             zmax_cache_misses_total {}\n\
             # HELP zmax_vhosts_loaded Yuklu sanal konak (vHost) sayisi.\n\
             # TYPE zmax_vhosts_loaded gauge\n\
             zmax_vhosts_loaded {}\n\
             # HELP zmax_modules_loaded Yuklu modul sayisi.\n\
             # TYPE zmax_modules_loaded gauge\n\
             zmax_modules_loaded {}\n\
             # HELP zmax_banned_ips Aktif yasakli IP sayisi.\n\
             # TYPE zmax_banned_ips gauge\n\
             zmax_banned_ips {}\n\
             # HELP zmax_waf_events_total Toplam engellenen WAF olay sayisi.\n\
             # TYPE zmax_waf_events_total counter\n\
             zmax_waf_events_total {}\n\
             # HELP zmax_waf_blocked_24h Son 24 saatte engellenen WAF olay sayisi.\n\
             # TYPE zmax_waf_blocked_24h gauge\n\
             zmax_waf_blocked_24h {}\n",
            uptime_secs, total, hits, misses, vhosts_len, mods_len, banned_count, waf_total, waf_24h
        );
        send_response_with_content_type(
            socket,
            200,
            "OK",
            "text/plain; version=0.0.4; charset=utf-8",
            &cors_origin,
            &body,
        )
        .await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn status<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/status" && req.method == "GET" {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let total = state.stats.total_requests.load(Ordering::Relaxed);
        let hits = state.stats.cache_hits.load(Ordering::Relaxed);
        let misses = state.stats.cache_misses.load(Ordering::Relaxed);
        let banned_count = state.ban_manager.list_banned().len();
        let waf_total = state.waf_events.total_count();
        let waf_24h = state.waf_events.last_24h_count();
        let waf_recent = state.waf_events.recent_count();

        let rt = state.runtime.read().await;
        let workers = if rt.config.server.workers == 0 {
            zmax_runtime::detect_worker_threads()
        } else {
            rt.config.server.workers
        };
        let cfg = &rt.config;
        let json = format!(
            r#"{{"ok":true,"running":true,"engine":"zmax","version":"{}","pid":{},"uptime_seconds":{},"total_requests":{},"cache_hits":{},"cache_misses":{},"workers":{},"ram_mb":12,"vhosts_loaded":{},"active_sites":{},"modules_loaded":{},"banned_count":{},"waf_events_total":{},"waf_blocked_24h":{},"waf":{{"events_total":{},"blocked_24h":{},"recent_count":{}}},"ports":{{"http":{},"https":{},"admin":{},"api":{}}},"listeners":{{"http":"{}:{}","https":"{}:{}","admin":"{}:{}","api":"{}:{}"}},"cache":{{"enabled":{},"memory_cache_mb":{},"default_ttl_seconds":{},"disk_enabled":{}}},"security":{{"rate_limit_enabled":{},"rate_limit_per_minute":{},"keep_alive_timeout_sec":{},"slowloris_header_timeout_sec":{},"max_body_size_mb":{},"waf_events_total":{},"waf_blocked_24h":{}}},"vhosts_dir":"{}","config_path":"{}"}}"#,
            env!("ZMAX_VERSION"),
            std::process::id(),
            uptime_secs,
            total,
            hits,
            misses,
            workers,
            rt.vhosts.len(),
            rt.vhosts.len(),
            rt.modules.len(),
            banned_count,
            waf_total,
            waf_24h,
            waf_total,
            waf_24h,
            waf_recent,
            cfg.listeners.http.port,
            cfg.listeners.https.port,
            cfg.listeners.admin.port,
            cfg.listeners.api.port,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            cfg.cache.enabled,
            cfg.cache.memory_cache_mb,
            cfg.cache.default_ttl_seconds,
            state.cache.disk_dir().is_some(),
            cfg.security.rate_limit_enabled,
            cfg.security.rate_limit_per_minute,
            cfg.security.keep_alive_timeout_sec,
            cfg.security.slowloris_header_timeout_sec,
            cfg.security.max_body_size_mb,
            waf_total,
            waf_24h,
            json_escape(&rt.vhosts_dir.to_string_lossy()),
            json_escape(&rt.conf_path.to_string_lossy()),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn modules_list<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/modules" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let items: Vec<String> = rt
            .modules
            .list()
            .iter()
            .map(|m| {
                let cat_key = module_category_key(&m.meta.name, &m.meta.category);
                let rel_file = format!("modules/{}", m.file_name);
                format!(
                    r#"{{"name":"{}","version":"{}","category":"{}","categoryKey":"{}","file":"{}","enabled":{}}}"#,
                    json_escape(&m.meta.name),
                    json_escape(&m.meta.version),
                    json_escape(&m.meta.category),
                    cat_key,
                    json_escape(&rel_file),
                    m.meta.enabled
                )
            })
            .collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"modules":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn modules_toggle<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/modules/toggle"
        && req.method == "POST"
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let Some(name) = extract_json_string(&body_str, "name") else {
            let err = r#"{"ok":false,"error":"Modul adi (name) zorunludur."}"#;
            send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
            return Ok(true);
        };
        let desired = extract_json_bool(&body_str, "enabled");

        let mut rt = state.runtime.write().await;
        let res = match desired {
            Some(en) => rt.modules.set_enabled(&name, en).map(|()| en),
            None => rt.modules.toggle_enabled(&name),
        };
        match res {
            Ok(new_state) => {
                super::super::audit::kayit(state, "api", if new_state { "modul-ac" } else { "modul-kapat" }, &name, true).await;
                let cfg_clone = rt.config.clone();
                let policies = compile_policies(&cfg_clone, &rt.modules);
                let new_rate = policies.effective_rate_limit;
                let redis_client = build_redis_client(&rt.modules);
                rt.policies = policies;
                rt.redis_client = redis_client;
                drop(rt);

                let mut limiter = state.limiter.write().await;
                *limiter = zmax_security::RateLimiter::new(new_rate);

                let json = format!(
                    r#"{{"ok":true,"name":"{}","enabled":{}}}"#,
                    json_escape(&name),
                    new_state
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(msg) => {
                drop(rt);
                super::super::audit::kayit(state, "api", "modul-degistir", &name, false).await;
                let json = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&msg));
                send_json_response(socket, 404, "Not Found", &cors_origin, &json).await?;
            }
        }
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn ports<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if req_path == "/api/v1/ports" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let panel_ports: Vec<String> = KNOWN_PANEL_PORTS.iter().map(|p| p.to_string()).collect();
        let active_ports = [
            cfg.listeners.http.port,
            cfg.listeners.https.port,
            cfg.listeners.admin.port,
            cfg.listeners.api.port,
        ];
        let collision = active_ports.iter().any(|p| KNOWN_PANEL_PORTS.contains(p));
        let json = format!(
            r#"{{"ok":true,"collision_detected":{},"ports":{{"http":{},"https":{},"admin":{},"api":{}}},"listeners":{{"http":"{}:{}","https":"{}:{}","admin":"{}:{}","api":"{}:{}"}},"tls":{{"https":{},"admin":{},"api":{}}},"unix_socket":"{}","known_panel_ports":[{}]}}"#,
            collision,
            cfg.listeners.http.port,
            cfg.listeners.https.port,
            cfg.listeners.admin.port,
            cfg.listeners.api.port,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            cfg.listeners.https.ssl,
            cfg.listeners.admin.ssl,
            cfg.listeners.api.ssl,
            json_escape(&cfg.listeners.api.unix_socket),
            panel_ports.join(","),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) async fn handle<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if metrics(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if status(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if modules_list(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if modules_toggle(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if ports(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if super::super::services::config_service::reload(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if super::super::services::config_service::config(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    Ok(false)
}

