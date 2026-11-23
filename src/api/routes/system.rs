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
    let clean = req_path.trim_end_matches('/');
    if clean == "/healthz" || clean == "/health" || (strict_api_only && clean.is_empty()) {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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

    // 1a. Genel altyapı sürüm ucu (/version): token'sız, salt okunur probe.
    if clean == "/version" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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
    let clean = req_path.trim_end_matches('/');
    if clean == "/metrics" || clean == "/api/v1/metrics" || clean == "/api/metrics" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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

/// Süreç yerleşik bellek kullanımı (MB); Linux dışında veya okunamazsa 0.
fn rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|t| t.split_whitespace().nth(1).and_then(|v| v.parse::<u64>().ok()))
        .map(|pages| pages * 4096 / (1024 * 1024))
        .unwrap_or(0)
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
    let clean = req_path.trim_end_matches('/');
    if clean == "/api/v1/status" || clean == "/api/status" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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
            r#"{{"ok":true,"running":true,"engine":"zmax","version":"{}","pid":{},"uptime_seconds":{},"total_requests":{},"cache_hits":{},"cache_misses":{},"workers":{},"ram_mb":{},"vhosts_loaded":{},"active_sites":{},"modules_loaded":{},"banned_count":{},"waf_events_total":{},"waf_blocked_24h":{},"waf":{{"events_total":{},"blocked_24h":{},"recent_count":{}}},"ports":{{"http":{},"https":{},"admin":{},"api":{}}},"listeners":{{"http":"{}:{}","https":"{}:{}","admin":"{}:{}","api":"{}:{}"}},"cache":{{"enabled":{},"memory_cache_mb":{},"default_ttl_seconds":{},"disk_enabled":{}}},"security":{{"rate_limit_enabled":{},"rate_limit_per_minute":{},"keep_alive_timeout_sec":{},"slowloris_header_timeout_sec":{},"max_body_size_mb":{},"waf_events_total":{},"waf_blocked_24h":{}}},"vhosts_dir":"{}","config_path":"{}"}}"#,
            env!("ZMAX_VERSION"),
            std::process::id(),
            uptime_secs,
            total,
            hits,
            misses,
            workers,
            rss_mb(),
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
    let clean = req_path.trim_end_matches('/');
    if clean == "/api/v1/modules" || clean == "/api/modules" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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
    let clean = req_path.trim_end_matches('/');
    if clean == "/api/v1/modules/toggle" || clean == "/api/modules/toggle" {
        if req.method != "POST" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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
    let clean = req_path.trim_end_matches('/');
    if clean == "/api/v1/ports" || clean == "/api/ports" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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

fn json_to_toml(val: serde_json::Value) -> toml::Value {
    match val {
        serde_json::Value::Null => toml::Value::String(String::new()),
        serde_json::Value::Bool(b) => toml::Value::Boolean(b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                toml::Value::Integer(i)
            } else if let Some(f) = n.as_f64() {
                toml::Value::Float(f)
            } else {
                toml::Value::Integer(0)
            }
        }
        serde_json::Value::String(s) => toml::Value::String(s),
        serde_json::Value::Array(arr) => {
            toml::Value::Array(arr.into_iter().map(json_to_toml).collect())
        }
        serde_json::Value::Object(map) => {
            let mut tmap = toml::map::Map::new();
            for (k, v) in map {
                tmap.insert(k, json_to_toml(v));
            }
            toml::Value::Table(tmap)
        }
    }
}

/// ZMax yapılandırma değişikliklerini zmax.toml dosyasına atomik olarak yazar.
async fn persist_zmax_config(conf_path: &Path, config: &ZMaxConfig) {
    let mut doc = if let Ok(content) = tokio::fs::read_to_string(conf_path).await {
        toml::from_str::<toml::Value>(&content).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::Value::Table(toml::map::Map::new())
    };

    if let Some(map) = doc.as_table_mut() {
        if let Ok(server_str) = toml::to_string(&config.server) {
            if let Ok(server_val) = toml::from_str::<toml::Value>(&server_str) {
                map.insert("server".to_string(), server_val);
            }
        }
        if let Ok(tuning_str) = toml::to_string(&config.tuning) {
            if let Ok(tuning_val) = toml::from_str::<toml::Value>(&tuning_str) {
                map.insert("tuning".to_string(), tuning_val);
            }
        }
        if let Ok(security_str) = toml::to_string(&config.security) {
            if let Ok(security_val) = toml::from_str::<toml::Value>(&security_str) {
                map.insert("security".to_string(), security_val);
            }
        }
        if let Ok(jval) = serde_json::to_value(&config.extapps) {
            let toml_arr = json_to_toml(jval);
            map.insert("extapps".to_string(), toml_arr.clone());
            if let Some(srv) = map.get_mut("server").and_then(|s| s.as_table_mut()) {
                srv.insert("ext_apps".to_string(), toml_arr);
            }
        }
        if let Ok(jval) = serde_json::to_value(&config.listeners.custom) {
            let listeners_table = map.entry("listeners".to_string()).or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
            if let Some(lt) = listeners_table.as_table_mut() {
                lt.insert("custom".to_string(), json_to_toml(jval));
            }
        }
    }

    let updated = toml::to_string_pretty(&doc).unwrap_or_default();
    if !updated.is_empty() {
        if let Some(parent) = conf_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let tmp = conf_path.with_extension("tmp");
        if tokio::fs::write(&tmp, updated.as_bytes()).await.is_ok() {
            if tokio::fs::rename(&tmp, conf_path).await.is_err() {
                let _ = tokio::fs::remove_file(&tmp).await;
                let _ = tokio::fs::write(conf_path, updated.as_bytes()).await;
            }
        }
    }
}

pub(super) async fn config_server<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let clean_path = req_path.trim_end_matches('/');
    let is_config_server = clean_path == "/api/v1/config/server" || clean_path == "/api/config/server";

    if is_config_server && (req.method == "GET" || req.method == "HEAD") {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let tuning = &cfg.tuning;

        let ext_apps_json: Vec<String> = if !cfg.extapps.is_empty() {
            cfg.extapps.iter().map(|app| {
                format!(
                    r#"{{"id":"{}","name":"{}","type":"{}","address":"{}","max_conns":{},"instances":{},"priority":0}}"#,
                    json_escape(&app.id),
                    json_escape(&app.name),
                    json_escape(&app.app_type),
                    json_escape(&app.address),
                    app.max_conns,
                    app.instances
                )
            }).collect()
        } else {
            vec![
                r#"{"id":"lsphp83","name":"LSPHP 8.3 (Varsayilan)","type":"LSAPI","address":"127.0.0.1:9083","max_conns":35,"instances":10,"priority":0}"#.to_string(),
                r#"{"id":"lsphp82","name":"LSPHP 8.2","type":"LSAPI","address":"127.0.0.1:9082","max_conns":30,"instances":5,"priority":0}"#.to_string(),
                r#"{"id":"lsphp81","name":"LSPHP 8.1","type":"LSAPI","address":"127.0.0.1:9081","max_conns":25,"instances":5,"priority":0}"#.to_string(),
                r#"{"id":"nodejs_default","name":"Node.js App Server","type":"Proxy","address":"127.0.0.1:3000","max_conns":100,"instances":1,"priority":1}"#.to_string(),
            ]
        };

        let json = format!(
            r#"{{"ok":true,"server":{{"server_name":"{}","workers":{},"cpu_affinity":{},"user":"{}","group":"{}"}},"tuning":{{"max_connections":{},"connection_timeout":{},"keep_alive_timeout":{},"max_keep_alive_req":{},"gzip_enabled":{},"brotli_enabled":{},"min_compress_size":{},"ssl_cache_size":{},"ssl_cache_timeout":{},"http3_enabled":{},"http3_port":{}}},"ext_apps":[{}],"script_handlers":[{{"suffix":"php","handler":"lsphp83","note":"Standart PHP isleyici"}},{{"suffix":"php83","handler":"lsphp83","note":"PHP 8.3"}},{{"suffix":"php82","handler":"lsphp82","note":"PHP 8.2"}},{{"suffix":"php81","handler":"lsphp81","note":"PHP 8.1"}}],"security":{{"per_client_conn_limit":100,"conn_limit_window":10,"cgi_cpu_limit":10,"cgi_mem_limit":300,"recaptcha_enabled":false,"bubblewrap_enabled":true,"global_allowed_ips":"127.0.0.1, 192.168.0.0/16","global_denied_ips":"","keep_alive_timeout_sec":{},"slowloris_header_timeout_sec":{},"max_body_size_mb":{}}}}}"#,
            json_escape(&cfg.server.server_name),
            cfg.server.workers,
            cfg.server.cpu_affinity,
            json_escape(&cfg.server.user),
            json_escape(&cfg.server.group),
            tuning.max_connections,
            tuning.connection_timeout,
            tuning.keep_alive_timeout,
            tuning.max_keep_alive_req,
            tuning.gzip_enabled,
            tuning.brotli_enabled,
            tuning.min_compress_size,
            tuning.ssl_cache_size,
            tuning.ssl_cache_timeout,
            tuning.http3_enabled,
            tuning.http3_port,
            ext_apps_json.join(","),
            cfg.security.keep_alive_timeout_sec,
            cfg.security.slowloris_header_timeout_sec,
            cfg.security.max_body_size_mb,
        );
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }
    if is_config_server && (req.method == "POST" || req.method == "PUT") {
        let body_val: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);
        let mut rt = state.runtime.write().await;

        let get_u64 = |key: &str, parent: &str| -> Option<u64> {
            body_val.get(parent).and_then(|p| p.get(key)).and_then(|v| v.as_u64())
                .or_else(|| body_val.get(key).and_then(|v| v.as_u64()))
        };
        let get_bool = |key: &str, parent: &str| -> Option<bool> {
            body_val.get(parent).and_then(|p| p.get(key)).and_then(|v| v.as_bool())
                .or_else(|| body_val.get(key).and_then(|v| v.as_bool()))
        };
        let get_str = |key: &str, parent: &str| -> Option<String> {
            body_val.get(parent).and_then(|p| p.get(key)).and_then(|v| v.as_str()).map(|s| s.to_string())
                .or_else(|| body_val.get(key).and_then(|v| v.as_str()).map(|s| s.to_string()))
        };

        if let Some(mc) = get_u64("max_connections", "tuning") {
            rt.config.tuning.max_connections = mc as u32;
        }
        if let Some(ct) = get_u64("connection_timeout", "tuning") {
            rt.config.tuning.connection_timeout = ct;
        }
        if let Some(kat) = get_u64("keep_alive_timeout", "tuning") {
            rt.config.tuning.keep_alive_timeout = kat;
        }
        if let Some(mkr) = get_u64("max_keep_alive_req", "tuning") {
            rt.config.tuning.max_keep_alive_req = mkr as u32;
        }
        if let Some(gz) = get_bool("gzip_enabled", "tuning") {
            rt.config.tuning.gzip_enabled = gz;
        }
        if let Some(br) = get_bool("brotli_enabled", "tuning") {
            rt.config.tuning.brotli_enabled = br;
        }
        if let Some(mcs) = get_u64("min_compress_size", "tuning") {
            rt.config.tuning.min_compress_size = mcs as usize;
        }
        if let Some(scs) = get_u64("ssl_cache_size", "tuning") {
            rt.config.tuning.ssl_cache_size = scs as usize;
        }
        if let Some(sct) = get_u64("ssl_cache_timeout", "tuning") {
            rt.config.tuning.ssl_cache_timeout = sct;
        }
        if let Some(h3) = get_bool("http3_enabled", "tuning") {
            rt.config.tuning.http3_enabled = h3;
        }
        if let Some(h3p) = get_u64("http3_port", "tuning") {
            rt.config.tuning.http3_port = h3p as u16;
        }

        if let Some(name) = get_str("server_name", "server") {
            rt.config.server.server_name = name;
        }
        if let Some(w) = get_u64("workers", "server") {
            rt.config.server.workers = w as usize;
        }
        if let Some(aff) = get_bool("cpu_affinity", "server") {
            rt.config.server.cpu_affinity = aff;
        }
        if let Some(u) = get_str("user", "server") {
            rt.config.server.user = u;
        }
        if let Some(g) = get_str("group", "server") {
            rt.config.server.group = g;
        }

        if let Some(kat_sec) = get_u64("keep_alive_timeout_sec", "security") {
            rt.config.security.keep_alive_timeout_sec = kat_sec;
        }
        if let Some(slh) = get_u64("slowloris_header_timeout_sec", "security") {
            rt.config.security.slowloris_header_timeout_sec = slh;
        }

        let cfg_clone = rt.config.clone();
        let conf_path = rt.conf_path.clone();
        drop(rt);

        persist_zmax_config(&conf_path, &cfg_clone).await;
        super::super::audit::kayit(state, "api", "config_server_update", "server_tuning", true).await;
        let res = r#"{"ok":true,"message":"Sunucu ayarlari basariyla guncellendi."}"#;
        send_json_response(socket, 200, "OK", cors_origin, res).await?;
        return Ok(true);
    }

    if is_config_server {
        let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
        send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn listeners_endpoint<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let clean_path = req_path.split('?').next().unwrap_or(req_path).trim_end_matches('/');
    let is_listeners_base = clean_path == "/api/v1/listeners" || clean_path == "/api/listeners";
    let is_listeners_sub = (clean_path.starts_with("/api/v1/listeners/") || clean_path.starts_with("/api/listeners/")) && !is_listeners_base;

    if !is_listeners_base && !is_listeners_sub {
        return Ok(false);
    }

    if is_listeners_base && !matches!(req.method.as_str(), "GET" | "POST" | "HEAD" | "PUT" | "DELETE") {
        let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
        send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
        return Ok(true);
    }

    if is_listeners_base && req.method == "GET" {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let mut list_json = Vec::new();
        list_json.push(format!(
            r#"{{"id":"http_default","name":"Default HTTP ({})","ip":"{}","port":{},"secure":false,"protocol":"HTTP/1.1, HTTP/2","vhost_mappings":["*"],"status":"active"}}"#,
            cfg.listeners.http.port,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port
        ));
        list_json.push(format!(
            r#"{{"id":"https_default","name":"Default HTTPS ({})","ip":"{}","port":{},"secure":true,"protocol":"HTTP/2, HTTP/3 (QUIC)","tls_versions":["TLSv1.2","TLSv1.3"],"vhost_mappings":["* (SNI)"],"status":"{}"}}"#,
            cfg.listeners.https.port,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            if cfg.listeners.https.enabled { "active" } else { "standby" }
        ));
        list_json.push(format!(
            r#"{{"id":"admin_listener","name":"WebAdmin Konsolu","ip":"{}","port":{},"secure":{},"protocol":"HTTP/1.1","vhost_mappings":["_admin_internal"],"status":"active"}}"#,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            cfg.listeners.admin.ssl
        ));
        for l in &cfg.listeners.custom {
            let vhosts_map_str = l.vhost_mappings.iter().map(|v| format!("\"{}\"", json_escape(v))).collect::<Vec<_>>().join(",");
            let tls_str = l.tls_versions.iter().map(|v| format!("\"{}\"", json_escape(v))).collect::<Vec<_>>().join(",");
            list_json.push(format!(
                r#"{{"id":"{}","name":"{}","ip":"{}","port":{},"secure":{},"protocol":"{}","tls_versions":[{}],"vhost_mappings":[{}],"status":"{}"}}"#,
                json_escape(&l.id),
                json_escape(&l.name),
                json_escape(&l.address),
                l.port,
                l.secure,
                json_escape(&l.protocol),
                tls_str,
                vhosts_map_str,
                if l.enabled { "active" } else { "disabled" }
            ));
        }
        let json = format!(r#"{{"ok":true,"count":{},"listeners":[{}]}}"#, list_json.len(), list_json.join(","));
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if is_listeners_sub && req.method == "GET" {
        let path_id = req_path
            .strip_prefix("/api/v1/listeners/")
            .or_else(|| req_path.strip_prefix("/api/listeners/"))
            .map(|s| s.trim_matches('/').to_string())
            .unwrap_or_default();

        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        if path_id == "http_default" {
            let json = format!(
                r#"{{"ok":true,"listener":{{"id":"http_default","name":"Default HTTP ({})","ip":"{}","port":{},"secure":false,"protocol":"HTTP/1.1, HTTP/2","vhost_mappings":["*"],"status":"active"}}}}"#,
                cfg.listeners.http.port,
                json_escape(&cfg.listeners.http.address),
                cfg.listeners.http.port
            );
            send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            return Ok(true);
        } else if path_id == "https_default" {
            let json = format!(
                r#"{{"ok":true,"listener":{{"id":"https_default","name":"Default HTTPS ({})","ip":"{}","port":{},"secure":true,"protocol":"HTTP/2, HTTP/3 (QUIC)","tls_versions":["TLSv1.2","TLSv1.3"],"vhost_mappings":["* (SNI)"],"status":"{}"}}}}"#,
                cfg.listeners.https.port,
                json_escape(&cfg.listeners.https.address),
                cfg.listeners.https.port,
                if cfg.listeners.https.enabled { "active" } else { "standby" }
            );
            send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            return Ok(true);
        } else if path_id == "admin_listener" {
            let json = format!(
                r#"{{"ok":true,"listener":{{"id":"admin_listener","name":"WebAdmin Konsolu","ip":"{}","port":{},"secure":{},"protocol":"HTTP/1.1","vhost_mappings":["_admin_internal"],"status":"active"}}}}"#,
                json_escape(&cfg.listeners.admin.address),
                cfg.listeners.admin.port,
                cfg.listeners.admin.ssl
            );
            send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            return Ok(true);
        } else if let Some(l) = cfg.listeners.custom.iter().find(|l| l.id.eq_ignore_ascii_case(&path_id)) {
            let vhosts_map_str = l.vhost_mappings.iter().map(|v| format!("\"{}\"", json_escape(v))).collect::<Vec<_>>().join(",");
            let tls_str = l.tls_versions.iter().map(|v| format!("\"{}\"", json_escape(v))).collect::<Vec<_>>().join(",");
            let json = format!(
                r#"{{"ok":true,"listener":{{"id":"{}","name":"{}","ip":"{}","port":{},"secure":{},"protocol":"{}","tls_versions":[{}],"vhost_mappings":[{}],"status":"{}"}}}}"#,
                json_escape(&l.id),
                json_escape(&l.name),
                json_escape(&l.address),
                l.port,
                l.secure,
                json_escape(&l.protocol),
                tls_str,
                vhosts_map_str,
                if l.enabled { "active" } else { "disabled" }
            );
            send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            return Ok(true);
        } else {
            let err = r#"{"ok":false,"error":"Dinleyici bulunamadi"}"#;
            send_json_response(socket, 404, "Not Found", cors_origin, err).await?;
            return Ok(true);
        }
    }

    if (is_listeners_base || is_listeners_sub) && (req.method == "POST" || req.method == "PUT") {
        let body_val: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);

        let path_id = if is_listeners_sub {
            req_path.strip_prefix("/api/v1/listeners/")
                .or_else(|| req_path.strip_prefix("/api/listeners/"))
                .map(|s| s.trim_matches('/').to_string())
        } else {
            None
        };

        let id = path_id
            .or_else(|| body_val.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("listener_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));

        let name = body_val.get("name").and_then(|v| v.as_str()).unwrap_or("Yeni Dinleyici").to_string();
        let address = body_val.get("ip")
            .or_else(|| body_val.get("address"))
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0.0").to_string();
        let port = body_val.get("port").and_then(|v| v.as_u64()).unwrap_or(80) as u16;
        let secure = body_val.get("secure").and_then(|v| v.as_bool()).unwrap_or(false);
        let enabled = body_val.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

        let protocol = body_val.get("protocol").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| {
            if secure { "HTTP/2, HTTP/3 (QUIC)".to_string() } else { "HTTP/1.1, HTTP/2".to_string() }
        });

        let vhost_mappings: Vec<String> = body_val.get("vhost_mappings")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(|| vec!["*".to_string()]);

        let tls_versions: Vec<String> = body_val.get("tls_versions")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_else(|| vec!["1.2".to_string(), "1.3".to_string()]);

        let cert_file = body_val.get("cert_file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let key_file = body_val.get("key_file").and_then(|v| v.as_str()).unwrap_or("").to_string();

        let mut rt = state.runtime.write().await;
        if let Some(existing) = rt.config.listeners.custom.iter_mut().find(|l| l.id == id) {
            existing.name = name;
            existing.address = address.clone();
            existing.port = port;
            existing.secure = secure;
            existing.protocol = protocol;
            existing.vhost_mappings = vhost_mappings;
            existing.tls_versions = tls_versions;
            existing.cert_file = cert_file;
            existing.key_file = key_file;
            existing.enabled = enabled;
        } else {
            rt.config.listeners.custom.push(zmax_config::ListenerConfig {
                id: id.clone(),
                name,
                address: address.clone(),
                port,
                secure,
                protocol,
                vhost_mappings,
                tls_versions,
                cert_file,
                key_file,
                enabled,
                ..Default::default()
            });
        }
        let cfg_clone = rt.config.clone();
        let conf_path = rt.conf_path.clone();
        drop(rt);

        persist_zmax_config(&conf_path, &cfg_clone).await;
        super::super::audit::kayit(state, "api", "listener_save", &format!("{}:{}", address, port), true).await;
        let json = format!(r#"{{"ok":true,"id":"{}","message":"Dinleyici basariyla kaydedildi."}}"#, json_escape(&id));
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if (is_listeners_base || is_listeners_sub) && req.method == "DELETE" {
        let body_str = String::from_utf8_lossy(&req.body);
        let path_id = if is_listeners_sub {
            clean_path.strip_prefix("/api/v1/listeners/")
                .or_else(|| clean_path.strip_prefix("/api/listeners/"))
                .map(|s| s.trim_matches('/').to_string())
        } else {
            None
        };

        let target_id = path_id
            .or_else(|| extract_json_string(&body_str, "id"))
            .unwrap_or_default();

        if target_id.is_empty() {
            let err = r#"{"ok":false,"error":"Silinecek dinleyici ID belirtilmedi"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        }

        if target_id == "http_default" || target_id == "https_default" || target_id == "admin_listener" {
            let err = r#"{"ok":false,"error":"Varsayilan sistem dinleyicisi silinemez"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        }

        let mut rt = state.runtime.write().await;
        let initial_len = rt.config.listeners.custom.len();
        rt.config.listeners.custom.retain(|l| {
            !l.id.eq_ignore_ascii_case(&target_id) && !l.name.eq_ignore_ascii_case(&target_id)
        });

        if rt.config.listeners.custom.len() == initial_len {
            drop(rt);
            let err = r#"{"ok":false,"error":"Belirtilen ID ile dinleyici bulunamadi"}"#;
            send_json_response(socket, 404, "Not Found", cors_origin, err).await?;
            return Ok(true);
        }

        let cfg_clone = rt.config.clone();
        let conf_path = rt.conf_path.clone();
        drop(rt);

        persist_zmax_config(&conf_path, &cfg_clone).await;
        super::super::audit::kayit(state, "api", "listener_delete", &target_id, true).await;
        let json = format!(r#"{{"ok":true,"id":"{}","message":"Dinleyici basariyla silindi."}}"#, json_escape(&target_id));
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if is_listeners_base || is_listeners_sub {
        let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
        send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
        return Ok(true);
    }

    Ok(false)
}

pub(super) async fn extapps_endpoint<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let clean_path = req_path.split('?').next().unwrap_or(req_path).trim_end_matches('/');
    let is_extapps_base = clean_path == "/api/v1/extapps" || clean_path == "/api/extapps";
    let is_extapps_sub = (clean_path.starts_with("/api/v1/extapps/") || clean_path.starts_with("/api/extapps/")) && !is_extapps_base;

    if !is_extapps_base && !is_extapps_sub {
        return Ok(false);
    }

    if is_extapps_base && !matches!(req.method.as_str(), "GET" | "POST" | "HEAD" | "PUT" | "DELETE") {
        let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
        send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
        return Ok(true);
    }

    if is_extapps_base && req.method == "GET" {
        let rt = state.runtime.read().await;
        let extapps_list: Vec<String> = if !rt.config.extapps.is_empty() {
            rt.config.extapps.iter().map(|app| {
                let env_str = serde_json::to_string(&app.env_vars).unwrap_or_else(|_| "{}".to_string());
                format!(
                    r#"{{"id":"{}","name":"{}","type":"{}","address":"{}","max_conns":{},"instances":{},"init_timeout":{},"retry_timeout":{},"persist_conn":{},"enabled":{},"env_vars":{}}}"#,
                    json_escape(&app.id),
                    json_escape(&app.name),
                    json_escape(&app.app_type),
                    json_escape(&app.address),
                    app.max_conns,
                    app.instances,
                    app.init_timeout,
                    app.retry_timeout,
                    app.persist_conn,
                    app.enabled,
                    env_str
                )
            }).collect()
        } else {
            vec![
                r#"{"id":"lsphp83","name":"LSPHP 8.3 (Varsayilan)","type":"LSAPI","address":"127.0.0.1:9083","max_conns":35,"instances":10,"init_timeout":60,"retry_timeout":0,"persist_conn":true,"enabled":true,"env_vars":{}}"#.to_string(),
                r#"{"id":"lsphp82","name":"LSPHP 8.2","type":"LSAPI","address":"127.0.0.1:9082","max_conns":30,"instances":5,"init_timeout":60,"retry_timeout":0,"persist_conn":true,"enabled":true,"env_vars":{}}"#.to_string(),
                r#"{"id":"lsphp81","name":"LSPHP 8.1","type":"LSAPI","address":"127.0.0.1:9081","max_conns":25,"instances":5,"init_timeout":60,"retry_timeout":0,"persist_conn":true,"enabled":true,"env_vars":{}}"#.to_string(),
                r#"{"id":"nodejs_default","name":"Node.js App Server","type":"Proxy","address":"127.0.0.1:3000","max_conns":100,"instances":1,"init_timeout":60,"retry_timeout":0,"persist_conn":true,"enabled":true,"env_vars":{}}"#.to_string(),
            ]
        };

        let json = format!(
            r#"{{"ok":true,"count":{},"extapps":[{}],"ext_apps":[{}],"apps":[{}]}}"#,
            extapps_list.len(),
            extapps_list.join(","),
            extapps_list.join(","),
            extapps_list.join(",")
        );
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if is_extapps_sub && req.method == "GET" {
        let path_id = clean_path
            .strip_prefix("/api/v1/extapps/")
            .or_else(|| clean_path.strip_prefix("/api/extapps/"))
            .map(|s| s.trim_matches('/').to_string())
            .unwrap_or_default();

        let rt = state.runtime.read().await;
        if let Some(app) = rt.config.extapps.iter().find(|a| a.id.eq_ignore_ascii_case(&path_id)) {
            let env_str = serde_json::to_string(&app.env_vars).unwrap_or_else(|_| "{}".to_string());
            let json = format!(
                r#"{{"ok":true,"app":{{"id":"{}","name":"{}","type":"{}","address":"{}","max_conns":{},"instances":{},"init_timeout":{},"retry_timeout":{},"persist_conn":{},"enabled":{},"env_vars":{}}}}}"#,
                json_escape(&app.id),
                json_escape(&app.name),
                json_escape(&app.app_type),
                json_escape(&app.address),
                app.max_conns,
                app.instances,
                app.init_timeout,
                app.retry_timeout,
                app.persist_conn,
                app.enabled,
                env_str
            );
            send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            return Ok(true);
        } else if path_id == "lsphp83" || path_id == "lsphp82" || path_id == "lsphp81" || path_id == "nodejs_default" {
            let (name, app_type, address, max_conns, instances) = match path_id.as_str() {
                "lsphp83" => ("LSPHP 8.3 (Varsayilan)", "LSAPI", "127.0.0.1:9083", 35, 10),
                "lsphp82" => ("LSPHP 8.2", "LSAPI", "127.0.0.1:9082", 30, 5),
                "lsphp81" => ("LSPHP 8.1", "LSAPI", "127.0.0.1:9081", 25, 5),
                _ => ("Node.js App Server", "Proxy", "127.0.0.1:3000", 100, 1),
            };
            let json = format!(
                r#"{{"ok":true,"app":{{"id":"{}","name":"{}","type":"{}","address":"{}","max_conns":{},"instances":{},"init_timeout":60,"retry_timeout":0,"persist_conn":true,"enabled":true,"env_vars":{{}}}}}}"#,
                path_id, name, app_type, address, max_conns, instances
            );
            send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            return Ok(true);
        } else {
            let err = r#"{"ok":false,"error":"Harici uygulama havuzu bulunamadi"}"#;
            send_json_response(socket, 404, "Not Found", cors_origin, err).await?;
            return Ok(true);
        }
    }

    if (is_extapps_base || is_extapps_sub) && (req.method == "POST" || req.method == "PUT") {
        let body_val: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or(serde_json::Value::Null);

        let path_id = if is_extapps_sub {
            clean_path.strip_prefix("/api/v1/extapps/")
                .or_else(|| clean_path.strip_prefix("/api/extapps/"))
                .map(|s| s.trim_matches('/').to_string())
        } else {
            None
        };

        let id = path_id
            .or_else(|| body_val.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| format!("app_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)));

        let name = match body_val.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.trim().is_empty() => n.to_string(),
            _ => {
                let err = r#"{"ok":false,"error":"Harici uygulama adi (name) zorunludur"}"#;
                send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
                return Ok(true);
            }
        };

        let address = match body_val.get("address").or_else(|| body_val.get("socket")).or_else(|| body_val.get("addr")).and_then(|v| v.as_str()) {
            Some(a) if !a.trim().is_empty() => a.to_string(),
            _ => {
                let err = r#"{"ok":false,"error":"Harici uygulama adresi (address) zorunludur"}"#;
                send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
                return Ok(true);
            }
        };

        let app_type = body_val.get("type").or_else(|| body_val.get("app_type")).and_then(|v| v.as_str()).unwrap_or("LSAPI").to_string();
        let max_conns = body_val.get("max_conns").or_else(|| body_val.get("max_connections")).and_then(|v| v.as_u64()).unwrap_or(30) as u32;
        let instances = body_val.get("instances").and_then(|v| v.as_u64()).unwrap_or(5) as u32;
        let init_timeout = body_val.get("init_timeout").and_then(|v| v.as_u64()).unwrap_or(60);
        let retry_timeout = body_val.get("retry_timeout").and_then(|v| v.as_u64()).unwrap_or(0);
        let persist_conn = body_val.get("persist_conn").and_then(|v| v.as_bool()).unwrap_or(true);
        let enabled = body_val.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);

        let mut env_vars = std::collections::HashMap::new();
        if let Some(env_obj) = body_val.get("env_vars").and_then(|v| v.as_object()) {
            for (k, v) in env_obj {
                if let Some(s) = v.as_str() {
                    env_vars.insert(k.clone(), s.to_string());
                }
            }
        }

        let mut rt = state.runtime.write().await;
        if let Some(existing) = rt.config.extapps.iter_mut().find(|a| a.id == id) {
            existing.name = name;
            existing.app_type = app_type;
            existing.address = address;
            existing.max_conns = max_conns;
            existing.instances = instances;
            existing.init_timeout = init_timeout;
            existing.retry_timeout = retry_timeout;
            existing.persist_conn = persist_conn;
            existing.enabled = enabled;
            existing.env_vars = env_vars;
        } else {
            rt.config.extapps.push(zmax_config::ExternalAppConfig {
                id: id.clone(),
                name,
                app_type,
                address,
                max_conns,
                env_vars,
                init_timeout,
                retry_timeout,
                persist_conn,
                instances,
                enabled,
                ..Default::default()
            });
        }
        let cfg_clone = rt.config.clone();
        let conf_path = rt.conf_path.clone();
        drop(rt);

        persist_zmax_config(&conf_path, &cfg_clone).await;
        super::super::audit::kayit(state, "api", "extapp_save", &id, true).await;
        let json = format!(r#"{{"ok":true,"id":"{}","message":"Harici uygulama havuzu basariyla kaydedildi."}}"#, json_escape(&id));
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if (is_extapps_base || is_extapps_sub) && req.method == "DELETE" {
        let body_str = String::from_utf8_lossy(&req.body);
        let path_id = if is_extapps_sub {
            clean_path.strip_prefix("/api/v1/extapps/")
                .or_else(|| clean_path.strip_prefix("/api/extapps/"))
                .map(|s| s.trim_matches('/').to_string())
        } else {
            None
        };

        let target_id = path_id
            .or_else(|| extract_json_string(&body_str, "id"))
            .unwrap_or_default();

        if target_id.is_empty() {
            let err = r#"{"ok":false,"error":"Silinecek harici uygulama ID belirtilmedi"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        }

        let mut rt = state.runtime.write().await;
        let initial_len = rt.config.extapps.len();
        rt.config.extapps.retain(|a| !a.id.eq_ignore_ascii_case(&target_id) && !a.name.eq_ignore_ascii_case(&target_id));

        if rt.config.extapps.len() == initial_len {
            drop(rt);
            let err = r#"{"ok":false,"error":"Belirtilen ID ile harici uygulama bulunamadi"}"#;
            send_json_response(socket, 404, "Not Found", cors_origin, err).await?;
            return Ok(true);
        }

        let cfg_clone = rt.config.clone();
        let conf_path = rt.conf_path.clone();
        drop(rt);

        persist_zmax_config(&conf_path, &cfg_clone).await;
        super::super::audit::kayit(state, "api", "extapp_delete", &target_id, true).await;
        let json = format!(r#"{{"ok":true,"id":"{}","message":"Harici uygulama havuzu basariyla silindi."}}"#, json_escape(&target_id));
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if is_extapps_base || is_extapps_sub {
        let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
        send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
        return Ok(true);
    }

    Ok(false)
}

pub(super) async fn livestats_endpoint<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let clean = req_path.trim_end_matches('/');
    if clean == "/api/v1/livestats" || clean == "/api/livestats" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let total = state.stats.total_requests.load(Ordering::Relaxed);
        let hits = state.stats.cache_hits.load(Ordering::Relaxed);
        let misses = state.stats.cache_misses.load(Ordering::Relaxed);
        let req_rate = if uptime_secs > 0 { total / uptime_secs } else { 0 };

        let pool_stats = state.upstream_pool.stats();
        let idle_conns = pool_stats.active_idle;

        let rt = state.runtime.read().await;
        let vhosts_count = rt.vhosts.len();
        let workers = if rt.config.server.workers == 0 {
            zmax_runtime::detect_worker_threads()
        } else {
            rt.config.server.workers
        };

        // Gerçek havuz verilerini derle
        let mut pools_json = Vec::new();
        for app in &rt.config.extapps {
            let idle = state.upstream_pool.idle_count(&app.address);
            pools_json.push(format!(
                r#"{{"name":"{}","total":{},"in_use":0,"idle":{},"max_reached":0}}"#,
                json_escape(&app.id),
                app.max_conns,
                idle
            ));
        }

        // Dinleyici - VHost haritalama matrisini gerçek konfigürasyondan derle
        let mut mappings_json = Vec::new();
        let cfg = &rt.config;
        mappings_json.push(format!(
            r#"{{"listener":"Default HTTP ({})","ip_port":"{}:{}","vhosts":["*"],"status":"{}"}}"#,
            cfg.listeners.http.port,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            if cfg.listeners.http.enabled { "active" } else { "standby" }
        ));
        mappings_json.push(format!(
            r#"{{"listener":"Default HTTPS ({})","ip_port":"{}:{}","vhosts":["* (SNI)"],"status":"{}"}}"#,
            cfg.listeners.https.port,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            if cfg.listeners.https.enabled { "active" } else { "standby" }
        ));
        mappings_json.push(format!(
            r#"{{"listener":"WebAdmin Konsolu","ip_port":"{}:{}","vhosts":["_admin_internal"],"status":"{}"}}"#,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            if cfg.listeners.admin.enabled { "active" } else { "standby" }
        ));
        for l in &cfg.listeners.custom {
            let vhosts_arr: Vec<String> = l.vhost_mappings.iter().map(|v| format!("\"{}\"", json_escape(v))).collect();
            mappings_json.push(format!(
                r#"{{"listener":"{}","ip_port":"{}:{}","vhosts":[{}],"status":"{}"}}"#,
                json_escape(&l.name),
                json_escape(&l.address),
                l.port,
                vhosts_arr.join(","),
                if l.enabled { "active" } else { "disabled" }
            ));
        }

        let json = format!(
            r#"{{"ok":true,"metrics":{{"req_rate":{},"traffic_in_mbps":0.0,"traffic_out_mbps":0.0,"ssl_handshakes_sec":0,"active_conns":0,"idle_conns":{},"uptime_seconds":{},"total_requests":{},"cache_hits":{},"cache_misses":{},"vhosts":{},"workers":{}}},"pools":[{}],"mappings":[{}]}}"#,
            req_rate,
            idle_conns,
            uptime_secs,
            total,
            hits,
            misses,
            vhosts_count,
            workers,
            pools_json.join(","),
            mappings_json.join(",")
        );
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn config_validate_rollback<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if (req_path == "/api/v1/config/validate" || req_path == "/api/config/validate") && req.method == "POST" {
        let body_str = String::from_utf8_lossy(&req.body);
        let parse_result = toml::from_str::<zmax_config::ZMaxConfig>(&body_str);
        match parse_result {
            Ok(cfg) => {
                let mut issues: Vec<String> = Vec::new();
                if cfg.listeners.http.port == cfg.listeners.https.port {
                    issues.push("HTTP ve HTTPS portu ayni olamaz".to_string());
                }
                if cfg.listeners.admin.port == cfg.listeners.http.port || cfg.listeners.admin.port == cfg.listeners.https.port {
                    issues.push("Admin portu web portlari ile cakismamali".to_string());
                }
                if issues.is_empty() {
                    let json = r#"{"ok":true,"valid":true,"errors":[],"message":"Yapilandirma semasi ve mantiksal baglantilari gecerli."}"#;
                    send_json_response(socket, 200, "OK", cors_origin, json).await?;
                } else {
                    let errs = issues.iter().map(|s| format!("\"{}\"", json_escape(s))).collect::<Vec<_>>().join(",");
                    let json = format!(r#"{{"ok":false,"valid":false,"errors":[{}],"message":"Mantiksal yapilandirma hatalari bulundu."}}"#, errs);
                    send_json_response(socket, 400, "Bad Request", cors_origin, &json).await?;
                }
            }
            Err(e) => {
                let json = format!(r#"{{"ok":false,"valid":false,"errors":["{}"],"message":"TOML sema hatasi"}}"#, json_escape(&e.to_string()));
                send_json_response(socket, 400, "Bad Request", cors_origin, &json).await?;
            }
        }
        return Ok(true);
    }

    if (req_path == "/api/v1/config/rollback" || req_path == "/api/config/rollback") && req.method == "POST" {
        let rt = state.runtime.read().await;
        let conf_path = rt.conf_path.clone();
        drop(rt);

        let bak_path = format!("{}.bak", conf_path.display());
        if std::path::Path::new(&bak_path).exists() {
            if let Ok(bak_content) = std::fs::read_to_string(&bak_path) {
                let _ = std::fs::write(&conf_path, &bak_content);
                let _ = reload_runtime_state(state).await;
                super::super::audit::kayit(state, "api", "config_rollback", "onceki-yedek", true).await;
                let json = r#"{"ok":true,"status":"rolled_back","message":"Onceki calisan yapilandirmaya basariyla donuldu."}"#;
                send_json_response(socket, 200, "OK", cors_origin, json).await?;
                return Ok(true);
            }
        }
        let json = r#"{"ok":false,"error":"Geri donulecek yedek yapilandirma dosyasi (.bak) bulunamadi."}"#;
        send_json_response(socket, 404, "Not Found", cors_origin, json).await?;
        return Ok(true);
    }

    if (req_path == "/api/v1/config/history" || req_path == "/api/config/history") && req.method == "GET" {
        let json = r#"{"ok":true,"history":[{"generation":1,"action":"initial_boot","status":"applied","timestamp":"2026-11-22T20:00:00Z"}]}"#;
        send_json_response(socket, 200, "OK", cors_origin, json).await?;
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
    if config_validate_rollback(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if metrics(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if status(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if config_server(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if listeners_endpoint(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if extapps_endpoint(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if livestats_endpoint(socket, req, state, req_path, cors_origin).await? {
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
    let clean = req_path.trim_end_matches('/');
    if clean == "/api/v1/health" || clean == "/api/health" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
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
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }
    if clean == "/api/v1/version" || clean == "/api/version" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
        let json = format!(r#"{{"version":"{}"}}"#, env!("ZMAX_VERSION"));
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }
    if clean == "/api/v1/session/verify" || clean == "/api/session/verify" {
        if req.method != "GET" && req.method != "HEAD" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
        let (admin_tok, read_tok) = {
            let rt = state.runtime.read().await;
            (rt.auth.api_token.clone(), rt.auth.api_read_token.clone())
        };
        let is_read = match super::super::auth::authorize_role(req, &admin_tok, &read_tok, false, true) {
            Some(super::super::auth::AuthRole::Read) => true,
            _ => false,
        };
        let (role, user) = if is_read {
            ("read", "readonly")
        } else {
            ("admin", "admin")
        };
        let json = format!(r#"{{"ok":true,"authenticated":true,"role":"{}","user":"{}"}}"#, role, user);
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }
    Ok(false)
}

