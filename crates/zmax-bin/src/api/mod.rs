//! # ZMax Evrensel Kontrol API Yönlendiricisi
//! Hosting kontrol panelleri (zPanel, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia, aaPanel vb.)
//! ve dahili WebAdmin UI için ortak REST JSON API katmanı (`/api/v1/*` + `/api/*`).

use crate::modules_runtime::{
    append_error_log, build_redis_client, compile_policies,
    module_category_key, CompiledPolicies,
};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use zmax_config::{
    resolve_path, serialize_vhost_toml, validate_domain, LoadedModules,
    LoadedVHost, VHostEntry, ZMaxConfig, KNOWN_PANEL_PORTS,
};
use zmax_httpparser::{
    read_http1_request_buffered, HttpReadError, HttpReadLimits, HttpRequestData,
};
use zmax_obfuscate::zpoly;

pub use crate::core::state::{
    current_hms_utc, AccessLogRecord, RuntimeState, ServerState, ServerStats,
};

mod auth;
mod guard;
mod http;

pub use auth::*;
pub use guard::*;
pub use http::*;


pub use crate::config::reload::{
    refresh_tls_certs, reload_runtime_state,
};

fn format_vhost_json(v: &LoadedVHost) -> String {
    zmax_config::vhost_json::format_loaded_vhost_json(v)
}

fn classify_ban_reason_key(reason: &str) -> &'static str {
    let lower = reason.to_ascii_lowercase();
    if lower.contains("slowloris") {
        "reason_slowloris"
    } else if lower.contains("rate") || lower.contains("limit") {
        "reason_ratelimit"
    } else if lower.contains("brute") || lower.contains("wp-login") || lower.contains("xmlrpc") {
        "reason_bruteforce"
    } else {
        "reason_waf"
    }
}

async fn write_vhost_atomic_with_rollback(
    vhosts_dir: &Path,
    domain: &str,
    entry: &VHostEntry,
    state: &Arc<ServerState>,
) -> Result<usize, String> {
    tokio::fs::create_dir_all(vhosts_dir)
        .await
        .map_err(|e| format!("vhosts dizini oluşturulamadı: {}", e))?;

    let file_name = format!("{}.toml", domain);
    let target = vhosts_dir.join(&file_name);
    let tmp_path = vhosts_dir.join(format!(".{}.tmp", file_name));

    // Var olan dosyanın içeriğini belleğe yedekle (varsa)
    let backup_bytes: Option<Vec<u8>> = if target.exists() {
        match tokio::fs::read(&target).await {
            Ok(bytes) => Some(bytes),
            Err(e) => return Err(format!("Mevcut vHost dosyası yedeklenemedi: {}", e)),
        }
    } else {
        None
    };

    let toml_text =
        serialize_vhost_toml(entry).map_err(|e| format!("TOML serileştirme hatası: {}", e))?;
    let content = format!(
        "# ZMax Server API tarafından otomatik yönetilen Sanal Konak ({})\n{}",
        domain, toml_text
    );

    // 1. Önce geçici dosyaya yaz
    if let Err(e) = tokio::fs::write(&tmp_path, content.as_bytes()).await {
        return Err(format!("Geçici vHost dosyası yazılamadı: {}", e));
    }

    // 2. Atomik rename ile asıl dosyanın üzerine taşı
    if let Err(e) = tokio::fs::rename(&tmp_path, &target).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(format!("vHost dosyası taşınamadı: {}", e));
    }

    // 3. Çalışma zamanı durumunu (runtime) reload et
    match reload_runtime_state(state).await {
        Ok(count) => {
            // Aktif çalışma zamanındaki vHost ile yazılanın birebir eşit olduğunu doğrula
            let rt = state.runtime.read().await;
            if let Some(loaded) = rt
                .vhosts
                .iter()
                .find(|v| v.entry.name.eq_ignore_ascii_case(domain))
            {
                if let Some(diff) = zmax_config::vhost_entry_diff(entry, &loaded.entry) {
                    drop(rt);
                    rollback_vhost_file(&target, backup_bytes.as_deref()).await;
                    let _ = reload_runtime_state(state).await;
                    return Err(format!(
                        "Aktif çalışma zamanı yapılandırması yazılanla eşleşmiyor: {}",
                        diff
                    ));
                }
            }
            Ok(count)
        }
        Err(err) => {
            // RELOAD HATASI: Çalışan eski TOML dosyasına geri dön (ROLLBACK)
            rollback_vhost_file(&target, backup_bytes.as_deref()).await;
            let _ = reload_runtime_state(state).await;
            Err(format!(
                "vHost uygulanamadı, çalışan TOML geri yüklendi: {}",
                err
            ))
        }
    }
}

async fn rollback_vhost_file(target: &Path, backup: Option<&[u8]>) {
    match backup {
        Some(old_content) => {
            let _ = tokio::fs::write(target, old_content).await;
        }
        None => {
            let _ = tokio::fs::remove_file(target).await;
        }
    }
}

fn merge_vhost_json_patch(
    base: &VHostEntry,
    domain: &str,
    body: &[u8],
) -> Result<VHostEntry, String> {
    zmax_config::vhost_json::merge_vhost_json_patch(base, domain, body)
}

/// Hem WebAdmin (`/api/*`) hem Kontrol API (`/api/v1/*`) isteklerini tek noktadan işler.
/// Eşleşen bir API yolu varsa `Ok(true)` döner; WebAdmin statik dosyası sunulacaksa `Ok(false)` döner.
pub async fn handle_api_route<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    strict_api_only: bool,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let (cors_origin, expected_token, require_token, proxy_prefix) = {
        let rt = state.runtime.read().await;
        let (tok, req_tok, prefix) = if strict_api_only {
            (
                rt.auth.api_token.clone(),
                rt.auth.api_require_token,
                rt.config.listeners.api.proxy_prefix.clone(),
            )
        } else {
            (
                rt.auth.admin_token.clone(),
                rt.auth.admin_require_token,
                rt.config.listeners.admin.proxy_prefix.clone(),
            )
        };
        (
            rt.config.listeners.api.cors_allow_origin.clone(),
            tok,
            req_tok,
            prefix,
        )
    };

    let req_path = normalize_panel_request_path(&req.path, &proxy_prefix);
    let is_api_or_metrics_path = req_path.starts_with("/api/") || req_path == "/metrics";
    if !is_api_or_metrics_path && !strict_api_only {
        return Ok(false);
    }

    // CORS Preflight
    if req.method == "OPTIONS" {
        let origin = if cors_origin.is_empty() {
            "*"
        } else {
            &cors_origin
        };
        let resp = format!(
            "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: {}\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-ZMax-Token, X-ZMax-Purge-Key\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            origin
        );
        socket.write_all(resp.as_bytes()).await?;
        return Ok(true);
    }

    // 1. Public Health Check (Panel / Systemd / Load Balancer probe)
    if req_path == "/api/v1/health" || (strict_api_only && req_path == "/") {
        let uptime_secs = state.stats.start_time.elapsed().as_secs();
        let (vhosts_len, mods_len) = {
            let rt = state.runtime.read().await;
            (rt.vhosts.len(), rt.modules.len())
        };
        let json = format!(
            r#"{{"ok":true,"status":"ok","engine":"zmax","version":"{}","pid":{},"uptime_seconds":{},"vhosts":{},"modules":{}}}"#,
            env!("ZMAX_VERSION"),
            std::process::id(),
            uptime_secs,
            vhosts_len,
            mods_len
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

    // Token kontrolü (yapılandırılmışsa veya dinleyici loopback dışındaysa zorunlu)
    if !is_authorized(req, &expected_token, require_token) {
        let err =
            r#"{"ok":false,"error":"Yetkisiz erisim: Gecerli Bearer veya X-ZMax-Token gerekli."}"#;
        send_json_response(socket, 401, "Unauthorized", &cors_origin, err).await?;
        return Ok(true);
    }

    // 1b. Prometheus Metrik Ucu (/metrics ve /api/v1/metrics)
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

    // 2. Durum ve Telemetri (/api/status ve /api/v1/status)
    if (req_path == "/api/status" || req_path == "/api/v1/status") && req.method == "GET" {
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

    // 3. Modüller Listesi (GET /api/v1/modules ve /api/modules)
    if (req_path == "/api/v1/modules" || req_path == "/api/modules") && req.method == "GET" {
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

    // 3b. Modül Aç/Kapat (POST /api/v1/modules/toggle)
    if (req_path == "/api/v1/modules/toggle" || req_path == "/api/modules/toggle")
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
                let json = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&msg));
                send_json_response(socket, 404, "Not Found", &cors_origin, &json).await?;
            }
        }
        return Ok(true);
    }

    // 4. Yasaklı IP Listesi ve Yasak Kaldırma (/api/v1/security/bans, /api/v1/security/unban)
    if (req_path == "/api/v1/security/bans" || req_path == "/api/security/bans")
        && req.method == "GET"
    {
        let now_hms = current_hms_utc();
        let bans = state.ban_manager.list_banned();
        let items: Vec<String> = bans
            .iter()
            .map(|b| {
                let reason_key = classify_ban_reason_key(&b.reason);
                let rem_json = match b.remaining_secs {
                    Some(s) => s.to_string(),
                    None => "null".to_string(),
                };
                format!(
                    r#"{{"ip":"{}","reasonKey":"{}","reason":"{}","permanent":{},"remaining_secs":{},"time":"{}"}}"#,
                    json_escape(&b.ip.to_string()),
                    reason_key,
                    json_escape(&b.reason),
                    b.permanent,
                    rem_json,
                    now_hms
                )
            })
            .collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"bans":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    if (req_path == "/api/v1/security/unban" || req_path == "/api/security/unban")
        && req.method == "POST"
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_ip = extract_json_string(&body_str, "ip").unwrap_or_default();
        let Ok(ip) = raw_ip.trim().parse::<IpAddr>() else {
            let err = r#"{"ok":false,"error":"Gecersiz IP adresi."}"#;
            send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
            return Ok(true);
        };
        let existed = state.ban_manager.unban(ip);
        state.wp_guard.reset(ip);
        let json = format!(
            r#"{{"ok":true,"ip":"{}","unbanned":{}}}"#,
            json_escape(&ip.to_string()),
            existed
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 5. Canlı ve Dosya Tabanlı Erişim/Hata Logları (GET /api/v1/logs ve /api/logs)
    if (req_path == "/api/v1/logs" || req_path == "/api/logs") && req.method == "GET" {
        let domain_q = parse_query_param(&req.query, "domain")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let kind_q = parse_query_param(&req.query, "kind")
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let lines_q =
            parse_query_param(&req.query, "lines").and_then(|s| s.trim().parse::<usize>().ok());

        if domain_q.is_some() || kind_q.as_deref() == Some("error") {
            let kind = kind_q.unwrap_or_else(|| "access".to_string());
            if kind != "access" && kind != "error" {
                let err = r#"{"ok":false,"error":"Gecersiz kind parametresi (access veya error olmali)"}"#;
                send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
                return Ok(true);
            }
            let limit = lines_q.unwrap_or(100).min(5000);

            let (resolved_domain, target_path) = if let Some(raw_domain) = domain_q {
                let domain = match validate_domain(&raw_domain) {
                    Ok(d) => d,
                    Err(msg) => {
                        let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                        send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                        return Ok(true);
                    }
                };

                let rt = state.runtime.read().await;
                let found = rt.vhosts.iter().find(|v| {
                    v.entry.name.eq_ignore_ascii_case(&domain)
                        || v.entry
                            .aliases
                            .iter()
                            .any(|a| a.eq_ignore_ascii_case(&domain))
                });
                let vhost = match found {
                    Some(v) => v,
                    None => {
                        let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
                        send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
                        return Ok(true);
                    }
                };

                let raw_rel = if kind == "error" {
                    vhost.entry.logging.error_log.trim()
                } else {
                    vhost.entry.logging.access_log.trim()
                };
                let path = if !raw_rel.is_empty() {
                    resolve_path(&state.base_dir, raw_rel)
                } else {
                    let per_vhost = resolve_path(
                        &state.base_dir,
                        &format!("logs/{}.{}.log", vhost.entry.name, kind),
                    );
                    if per_vhost.exists() {
                        per_vhost
                    } else {
                        let global_rel = if kind == "error" {
                            if rt.config.logging.error_log.trim().is_empty() {
                                "logs/error.log"
                            } else {
                                rt.config.logging.error_log.trim()
                            }
                        } else if rt.config.logging.access_log.trim().is_empty() {
                            "logs/access.log"
                        } else {
                            rt.config.logging.access_log.trim()
                        };
                        resolve_path(&state.base_dir, global_rel)
                    }
                };
                (Some(vhost.entry.name.clone()), path)
            } else {
                let rt = state.runtime.read().await;
                let global_rel = if rt.config.logging.error_log.trim().is_empty() {
                    "logs/error.log"
                } else {
                    rt.config.logging.error_log.trim()
                };
                (None, resolve_path(&state.base_dir, global_rel))
            };

            state.log_manager.flush().await;
            let tail_lines = match state.log_manager.read_tail_lines(&target_path, limit).await {
                Ok(lines) => lines,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("Log dosyasi okunamadi: {}", e)
                    })
                    .to_string();
                    send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err)
                        .await?;
                    return Ok(true);
                }
            };

            let json = serde_json::json!({
                "ok": true,
                "domain": resolved_domain,
                "kind": kind,
                "path": target_path.to_string_lossy(),
                "count": tail_lines.len(),
                "lines": tail_lines,
                "logs": tail_lines
            })
            .to_string();
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        }

        let snapshot: Vec<AccessLogRecord> = state
            .access_logs
            .lock()
            .map(|q| {
                let take_n = lines_q
                    .unwrap_or(MAX_IN_MEMORY_LOGS)
                    .min(MAX_IN_MEMORY_LOGS);
                q.iter().take(take_n).cloned().collect()
            })
            .unwrap_or_default();
        let items: Vec<serde_json::Value> = snapshot
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "time": entry.time,
                    "ip": entry.ip,
                    "method": entry.method,
                    "path": entry.path,
                    "status": entry.status,
                    "latency": entry.latency,
                    "bytes_sent": entry.bytes_sent,
                    "request_id": entry.request_id,
                    "domain": entry.domain
                })
            })
            .collect();
        let json = serde_json::json!({
            "ok": true,
            "kind": "access",
            "count": items.len(),
            "logs": items
        })
        .to_string();
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 5b. Log Dosyalarını Yeniden Açma / Logrotate (POST /api/v1/logs/reopen ve /api/logs/reopen)
    if (req_path == "/api/v1/logs/reopen" || req_path == "/api/logs/reopen") && req.method == "POST"
    {
        state.log_manager.reopen_all().await;
        let dropped = state.log_manager.dropped_count();
        let json = serde_json::json!({
            "ok": true,
            "status": "reopened",
            "dropped": dropped,
            "message": "Tum log dosyalari flush edildi ve yeniden acilmak uzere serbest birakildi."
        })
        .to_string();
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 6. Port Keşif ve Çakışma Matrisi (/api/v1/ports)
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

    // 7. Önbellek Temizleme (/api/purge veya /api/v1/cache/purge — domain+tag, domain, tag, uri/key veya tümü)
    if (req_path == "/api/purge" || req_path == "/api/v1/cache/purge") && req.method == "POST" {
        let payload: serde_json::Value = if req.body.iter().all(|b| b.is_ascii_whitespace()) {
            serde_json::json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("Gecersiz JSON govdesi: {}", e)
                    })
                    .to_string();
                    send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                    return Ok(true);
                }
            }
        };

        let domain_opt = payload
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let tag_opt = payload
            .get("tag")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let tags_opt = payload
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            })
            .filter(|v| !v.is_empty());
        let uri_opt = payload
            .get("uri")
            .or_else(|| payload.get("key"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let redis_opt = state.runtime.read().await.redis_client.clone();

        match (domain_opt, tag_opt, tags_opt, uri_opt) {
            (Some(domain), Some(tag), _, _) => {
                let purged = state.cache.purge_by_domain_tag(&domain, &tag).await;
                if let Some(redis) = redis_opt {
                    let ev = zmax_redis::ClusterSyncEvent::PurgeTag {
                        domain: domain.clone(),
                        tag: tag.clone(),
                    };
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_event(&ev),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_tag",
                    "domain": domain,
                    "tag": tag,
                    "purged": purged,
                    "message": "Secili alan adi ve etiket onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, Some(tags), _) => {
                let purged = state.cache.purge_by_tags(&domain, &tags).await;
                if let Some(redis) = redis_opt {
                    let d = domain.clone();
                    let t_list = tags.clone();
                    tokio::spawn(async move {
                        for t in t_list {
                            let ev = zmax_redis::ClusterSyncEvent::PurgeTag {
                                domain: d.clone(),
                                tag: t,
                            };
                            let _ = tokio::time::timeout(
                                Duration::from_millis(250),
                                redis.publish_event(&ev),
                            )
                            .await;
                        }
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_tags",
                    "domain": domain,
                    "tags": tags,
                    "purged": purged,
                    "message": "Secili alan adi etiketleri temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, Some(tag), _, _) => {
                let purged = state.cache.purge_by_tag(&tag).await;
                if let Some(redis) = redis_opt {
                    let msg = format!("tag:{}", tag);
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_purge(&msg),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "tag",
                    "tag": tag,
                    "purged": purged,
                    "message": "Secili etiket onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, None, Some(tags), None) => {
                let mut purged = 0;
                for t in &tags {
                    purged += state.cache.purge_by_tag(t).await;
                }
                if let Some(redis) = redis_opt {
                    let t_list = tags.clone();
                    tokio::spawn(async move {
                        for t in t_list {
                            let msg = format!("tag:{}", t);
                            let _ = tokio::time::timeout(
                                Duration::from_millis(250),
                                redis.publish_purge(&msg),
                            )
                            .await;
                        }
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "tags",
                    "tags": tags,
                    "purged": purged,
                    "message": "Secili etiketler onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, None, None) => {
                let purged = state.cache.purge_by_domain(&domain).await;
                if let Some(redis) = redis_opt {
                    let ev = zmax_redis::ClusterSyncEvent::PurgeDomain {
                        domain: domain.clone(),
                    };
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_event(&ev),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain",
                    "domain": domain,
                    "purged": purged,
                    "message": "Secili alan adi onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, None, Some(target_uri)) => {
                let purged = state.cache.purge_by_domain_uri(&domain, &target_uri).await;
                if let Some(redis) = redis_opt {
                    let d = domain.clone();
                    let u = target_uri.clone();
                    tokio::spawn(async move {
                        let msg = format!("{}:{}", d, u);
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_purge(&msg),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_uri",
                    "domain": domain,
                    "uri": target_uri,
                    "purged": purged,
                    "message": "Secili alan adi ve URI onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (_, _, _, Some(target_uri)) => {
                let purged = state.cache.purge_by_uri(&target_uri).await;
                if let Some(redis) = redis_opt {
                    let msg = target_uri.clone();
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_purge(&msg),
                        )
                        .await;
                    });
                }
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "uri",
                    "uri": target_uri,
                    "key": target_uri,
                    "purged": purged,
                    "message": "Secili onbellek anahtari veya URI temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, None, None, None) => {
                state.cache.purge_all().await;
                if let Some(redis) = redis_opt {
                    tokio::spawn(async move {
                        let _ = tokio::time::timeout(
                            Duration::from_millis(250),
                            redis.publish_event(&zmax_redis::ClusterSyncEvent::PurgeAll),
                        )
                        .await;
                    });
                }
                let json = r#"{"ok":true,"status":"success","scope":"all","message":"L1 & L2 Onbellegi tamamen temizlendi!"}"#;
                send_json_response(socket, 200, "OK", &cors_origin, json).await?;
                return Ok(true);
            }
        }
    }

    // 8. Yapılandırma, Modüller ve vHost Sıcak Yenileme (/api/reload veya /api/v1/reload)
    if (req_path == "/api/reload" || req_path == "/api/v1/reload") && req.method == "POST" {
        match reload_runtime_state(state).await {
            Ok(vhosts_count) => {
                state.cache.purge_all().await;
                let json = format!(
                    r#"{{"ok":true,"status":"reloaded","vhosts_loaded":{},"message":"Yapilandirma, moduller ve vHost tablosu sifir kesintiyle yenilendi."}}"#,
                    vhosts_count
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(e) => {
                let json = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &json)
                    .await?;
            }
        }
        return Ok(true);
    }

    // 9. Aktif Konfigürasyon Okuma (/api/v1/config)
    if req_path == "/api/v1/config" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let cfg = &rt.config;
        let token_configured = !rt.auth.api_token.is_empty();
        let json = format!(
            r#"{{"ok":true,"server":{{"server_name":"{}","workers":{},"cpu_affinity":{}}},"listeners":{{"http":{{"enabled":{},"address":"{}","port":{},"reuse_port":{}}},"https":{{"enabled":{},"address":"{}","port":{},"ssl":{}}},"admin":{{"enabled":{},"address":"{}","port":{},"document_root":"{}","require_token":{},"ssl":{},"proxy_prefix":"{}"}},"api":{{"enabled":{},"address":"{}","port":{},"require_token":{},"token_configured":{},"unix_socket":"{}","ssl":{},"proxy_prefix":"{}"}}}},"cache":{{"enabled":{},"memory_cache_mb":{},"default_ttl_seconds":{}}},"security":{{"rate_limit_enabled":{},"rate_limit_per_minute":{},"keep_alive_timeout_sec":{},"block_path_traversal":{},"max_body_size_mb":{}}},"vhosts_dir":"{}"}}"#,
            json_escape(&cfg.server.server_name),
            cfg.server.workers,
            cfg.server.cpu_affinity,
            cfg.listeners.http.enabled,
            json_escape(&cfg.listeners.http.address),
            cfg.listeners.http.port,
            cfg.listeners.http.reuse_port,
            cfg.listeners.https.enabled,
            json_escape(&cfg.listeners.https.address),
            cfg.listeners.https.port,
            cfg.listeners.https.ssl,
            cfg.listeners.admin.enabled,
            json_escape(&cfg.listeners.admin.address),
            cfg.listeners.admin.port,
            json_escape(&cfg.listeners.admin.document_root),
            rt.auth.admin_require_token,
            cfg.listeners.admin.ssl,
            json_escape(&cfg.listeners.admin.proxy_prefix),
            cfg.listeners.api.enabled,
            json_escape(&cfg.listeners.api.address),
            cfg.listeners.api.port,
            rt.auth.api_require_token,
            token_configured,
            json_escape(&cfg.listeners.api.unix_socket),
            cfg.listeners.api.ssl,
            json_escape(&cfg.listeners.api.proxy_prefix),
            cfg.cache.enabled,
            cfg.cache.memory_cache_mb,
            cfg.cache.default_ttl_seconds,
            cfg.security.rate_limit_enabled,
            cfg.security.rate_limit_per_minute,
            cfg.security.keep_alive_timeout_sec,
            cfg.security.block_path_traversal,
            cfg.security.max_body_size_mb,
            json_escape(&cfg.vhosts_dir.path),
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 10. Sanal Konak Listesi (GET /api/v1/vhosts)
    if req_path == "/api/v1/vhosts" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let items: Vec<String> = rt.vhosts.iter().map(format_vhost_json).collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"vhosts":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 11. Yeni Sanal Konak Oluşturma / Güncelleme (POST /api/v1/vhosts veya PUT /api/v1/vhosts/<domain>)
    if (req_path == "/api/v1/vhosts" && req.method == "POST")
        || (req_path.starts_with("/api/v1/vhosts/")
            && (req.method == "PUT" || req.method == "POST"))
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_domain = req_path
            .strip_prefix("/api/v1/vhosts/")
            .map(|s| s.to_string())
            .or_else(|| extract_json_string(&body_str, "domain"))
            .or_else(|| extract_json_string(&body_str, "name"))
            .unwrap_or_default();

        let domain = match validate_domain(&raw_domain) {
            Ok(d) => d,
            Err(msg) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        let (existing_opt, vhosts_dir) = {
            let rt = state.runtime.read().await;
            (
                rt.vhosts
                    .iter()
                    .find(|v| v.entry.name.eq_ignore_ascii_case(&domain))
                    .map(|v| v.entry.clone()),
                rt.vhosts_dir.clone(),
            )
        };

        let mut base_entry = existing_opt.unwrap_or_else(|| VHostEntry {
            name: domain.clone(),
            document_root: format!("www/{}", domain),
            ..VHostEntry::default()
        });

        if let Some(doc_root) = extract_json_string(&body_str, "document_root") {
            if doc_root.contains("..") || doc_root.contains('\0') || doc_root.trim().is_empty() {
                let err = r#"{"ok":false,"error":"Gecersiz document_root yolu"}"#;
                send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
                return Ok(true);
            }
            base_entry.document_root = doc_root;
        }

        let entry = match merge_vhost_json_patch(&base_entry, &domain, &req.body) {
            Ok(e) => e,
            Err(e) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        match write_vhost_atomic_with_rollback(&vhosts_dir, &domain, &entry, state).await {
            Ok(count) => {
                let json = format!(
                    r#"{{"ok":true,"status":"saved","domain":"{}","vhosts_loaded":{}}}"#,
                    json_escape(&domain),
                    count
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(e) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
            }
        }
        return Ok(true);
    }

    // 12. Tekil Sanal Konak Okuma veya Silme (GET / DELETE /api/v1/vhosts/<domain>)
    if let Some(raw_domain) = req_path.strip_prefix("/api/v1/vhosts/") {
        let domain = match validate_domain(raw_domain) {
            Ok(d) => d,
            Err(msg) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        if req.method == "GET" {
            let rt = state.runtime.read().await;
            if let Some(found) = rt
                .vhosts
                .iter()
                .find(|v| v.entry.name.eq_ignore_ascii_case(&domain))
            {
                let json = format!(r#"{{"ok":true,"vhost":{}}}"#, format_vhost_json(found));
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            } else {
                let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
                send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
            }
            return Ok(true);
        }

        if req.method == "DELETE" {
            let vhosts_dir = state.runtime.read().await.vhosts_dir.clone();
            let target = vhosts_dir.join(format!("{}.toml", domain));
            if !target.exists() {
                let err = r#"{"ok":false,"error":"Silinecek sanal konak dosyasi bulunamadi"}"#;
                send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
                return Ok(true);
            }
            if let Err(e) = tokio::fs::remove_file(&target).await {
                let err = format!(
                    r#"{{"ok":false,"error":"Dosya silinemedi: {}"}}"#,
                    json_escape(&e.to_string())
                );
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err)
                    .await?;
                return Ok(true);
            }
            let count = reload_runtime_state(state).await.unwrap_or(0);
            let json = format!(
                r#"{{"ok":true,"status":"deleted","domain":"{}","vhosts_loaded":{}}}"#,
                json_escape(&domain),
                count
            );
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        }
    }

    // Eşleşmeyen /api/* ucu
    let err = r#"{"ok":false,"error":"Bilinmeyen veya desteklenmeyen API uc noktasi"}"#;
    send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
    Ok(true)
}

use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use zmax_httpparser::resolve_real_ip;

/// Dahili Evrensel Kontrol API Yöneticisi (Varsayılan: 127.0.0.1:19486)
pub(crate) async fn handle_api_connection<S>(
    mut socket: S,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut leftover = Vec::with_capacity(4096);
    let (max_body, trusted_proxies) = {
        let rt = state.runtime.read().await;
        (
            rt.config.security.max_body_size_mb.clamp(1, 64) * 1024 * 1024,
            rt.config.listeners.api.trusted_proxies.clone(),
        )
    };
    let limits = HttpReadLimits {
        max_header_bytes: 64 * 1024,
        max_body_bytes: max_body,
        header_timeout: Duration::from_secs(10),
        body_timeout: Duration::from_secs(15),
    };
    let req = match read_http_request_with_limits(&mut socket, &mut leftover, limits).await {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(()),
        Err(err) => {
            send_http_read_error(&mut socket, &err).await;
            return Ok(());
        }
    };
    let real_ip = resolve_real_ip(
        peer_addr.ip(),
        &req.headers,
        "x-forwarded-for",
        &trusted_proxies,
        true,
    );
    let is_local_control = peer_addr.ip().is_loopback() && real_ip.is_loopback();
    if !is_local_control
        && (state.ban_manager.is_banned(peer_addr.ip()) || state.ban_manager.is_banned(real_ip))
    {
        crate::web_engine::write_http_response(
            &mut socket,
            403,
            "Forbidden",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            b"403 Forbidden - IP Blocked",
            None,
            req.method.eq_ignore_ascii_case("HEAD"),
            false,
            false,
            0,
            None,
            None,
        )
        .await?;
        return Ok(());
    }
    let _ = handle_api_route(&mut socket, &req, &state, true).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::sync::Mutex;
    use std::time::Instant;
    use tokio::sync::RwLock;
    use crate::modules_runtime::compute_effective_auth;

    #[test]
    fn test_json_extractors() {
        let body = r#"{"domain":"site.com","document_root":"www/site","php_enabled":true,"cache_expire":600,"aliases":["www.site.com","m.site.com"]}"#;
        assert_eq!(
            extract_json_string(body, "domain").as_deref(),
            Some("site.com")
        );
        assert_eq!(
            extract_json_string(body, "document_root").as_deref(),
            Some("www/site")
        );
        assert_eq!(extract_json_bool(body, "php_enabled"), Some(true));
        assert_eq!(extract_json_u64(body, "cache_expire"), Some(600));
        assert_eq!(
            extract_json_string_array(body, "aliases"),
            Some(vec!["www.site.com".to_string(), "m.site.com".to_string()])
        );
    }

    #[test]
    fn test_authorization_check() {
        let req = ParsedHttpRequest {
            method: "GET".to_string(),
            path: "/api/v1/status".to_string(),
            query: String::new(),
            version: 1,
            host: "127.0.0.1".to_string(),
            headers: vec![("Authorization".to_string(), "Bearer secret-key".to_string())],
            body: Vec::new(),
            keep_alive: false,
        };
        assert!(is_authorized(&req, "secret-key", true));
        assert!(!is_authorized(&req, "wrong-key", true));
        assert!(is_authorized(&req, "", false));
    }

    #[test]
    fn test_normalize_panel_request_path() {
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console/api/status", "/v1/zmax/console"),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console/api/status", "/v1/zmax/console/"),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console", "/v1/zmax/console"),
            "/"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console/", "/v1/zmax/console"),
            "/"
        );
        assert_eq!(
            normalize_panel_request_path("/api/status", "/v1/zmax/console"),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/v1/zmax/console2/api/status", "/v1/zmax/console"),
            "/v1/zmax/console2/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/api/status", ""),
            "/api/status"
        );
        assert_eq!(
            normalize_panel_request_path("/api/status", "/"),
            "/api/status"
        );
    }

    #[tokio::test]
    async fn test_prometheus_metrics_config_ports_and_proxy_prefix_routing() {
        use tokio::io::AsyncReadExt;

        let cfg = ZMaxConfig::parse_toml(
            r#"
[listeners.admin]
enabled = true
address = "127.0.0.1"
port = 19485
ssl = true
tls_cert = "certs/admin.pem"
tls_key = "certs/admin.key"
proxy_prefix = "/v1/zmax/console"
require_token = true
token = "adm-secret-token"

[listeners.api]
enabled = true
address = "127.0.0.1"
port = 19486
ssl = false
proxy_prefix = "/v1/zmax/api"
require_token = true
token = "api-secret-token"
"#,
        )
        .unwrap();

        let modules = LoadedModules::default();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);
        let state = Arc::new(ServerState {
            base_dir: PathBuf::from("."),
            cache: zmax_cache::ZMaxCache::new(1024 * 1024, 60),
            limiter: RwLock::new(zmax_security::RateLimiter::new(1000)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::default()),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
            buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
            upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::default()),
            runtime: RwLock::new(RuntimeState {
                config: cfg,
                vhosts: Vec::new(),
                modules,
                policies,
                redis_client: None,
                auth,
                conf_path: PathBuf::from("conf/zmax.toml"),
                vhosts_dir: PathBuf::from("conf/vhosts"),
                modules_dir: PathBuf::from("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(PathBuf::from(
                ".",
            ))),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(crate::logger::AsyncLogManager::new(
                PathBuf::from("."),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                250,
                64,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::new()),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: AtomicU64::new(17),
                cache_hits: AtomicU64::new(11),
                cache_misses: AtomicU64::new(6),
            },
        });
        state
            .ban_manager
            .ban("203.0.113.10".parse().unwrap(), "rate limit", 60);

        async fn call_route(
            state: &Arc<ServerState>,
            strict_api_only: bool,
            method: &str,
            path: &str,
            headers: Vec<(String, String)>,
        ) -> (bool, String) {
            let (mut client, mut server) = tokio::io::duplex(64 * 1024);
            let req = ParsedHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                query: String::new(),
                version: 1,
                host: "127.0.0.1".to_string(),
                headers,
                body: Vec::new(),
                keep_alive: false,
            };
            let st = Arc::clone(state);
            let task = tokio::spawn(async move {
                let handled = handle_api_route(&mut server, &req, &st, strict_api_only)
                    .await
                    .unwrap();
                let _ = server.shutdown().await;
                handled
            });
            let mut out = Vec::new();
            client.read_to_end(&mut out).await.unwrap();
            let handled = task.await.unwrap();
            (handled, String::from_utf8_lossy(&out).into_owned())
        }

        // Yetkisiz /metrics talebi 401 dönmeli
        let (handled_unauth, resp_unauth) =
            call_route(&state, true, "GET", "/metrics", Vec::new()).await;
        assert!(handled_unauth);
        assert!(
            resp_unauth.starts_with("HTTP/1.1 401 Unauthorized"),
            "{resp_unauth}"
        );

        // Ön ek soyulmuş Prometheus /metrics (API dinleyici)
        let api_auth = vec![(
            "Authorization".to_string(),
            "Bearer api-secret-token".to_string(),
        )];
        let (handled_metrics, resp_metrics) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/metrics",
            api_auth.clone(),
        )
        .await;
        assert!(handled_metrics);
        assert!(
            resp_metrics.starts_with("HTTP/1.1 200 OK"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_uptime_seconds "),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_requests_total 17\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_cache_hits_total 11\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_cache_misses_total 6\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_vhosts_loaded 0\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_modules_loaded 0\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_banned_ips 1\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_waf_events_total 0\n"),
            "{resp_metrics}"
        );
        assert!(
            resp_metrics.contains("zmax_waf_blocked_24h 0\n"),
            "{resp_metrics}"
        );

        // WAF olayı kaydedildiğinde /metrics ve /api/v1/status sayaçları yansımalı
        state.waf_events.record_violation(
            &zmax_security::WafViolation::SqlInjection("union select".to_string()),
            "site.test",
            "127.0.0.1",
            "GET",
            "/arama?password=Secret&id=1",
        );
        let (handled_waf_metrics, resp_waf_metrics) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/metrics",
            api_auth.clone(),
        )
        .await;
        assert!(handled_waf_metrics);
        assert!(
            resp_waf_metrics.contains("zmax_waf_events_total 1\n"),
            "{resp_waf_metrics}"
        );
        assert!(
            resp_waf_metrics.contains("zmax_waf_blocked_24h 1\n"),
            "{resp_waf_metrics}"
        );

        let (handled_waf_status, resp_waf_status) = call_route(
            &state,
            true,
            "GET",
            "/v1/zmax/api/api/v1/status",
            api_auth.clone(),
        )
        .await;
        assert!(handled_waf_status);
        assert!(
            resp_waf_status.contains(r#""waf_events_total":1,"waf_blocked_24h":1"#),
            "{resp_waf_status}"
        );
        assert!(!resp_waf_status.contains("Secret"), "{resp_waf_status}");

        // Panel taraması için /api/v1/metrics (Admin dinleyici + ön ek soyma)
        let adm_auth = vec![("X-ZMax-Token".to_string(), "adm-secret-token".to_string())];
        let (handled_panel_metrics, resp_panel_metrics) = call_route(
            &state,
            false,
            "GET",
            "/v1/zmax/console/api/v1/metrics",
            adm_auth.clone(),
        )
        .await;
        assert!(handled_panel_metrics);
        assert!(
            resp_panel_metrics.contains("zmax_requests_total 17\n"),
            "{resp_panel_metrics}"
        );

        // /api/v1/config ssl ve proxy_prefix alanlarını token/key sızdırmadan dönmeli
        let (handled_cfg, resp_cfg) = call_route(
            &state,
            false,
            "GET",
            "/v1/zmax/console/api/v1/config",
            adm_auth,
        )
        .await;
        assert!(handled_cfg);
        assert!(
            resp_cfg.contains(r#""ssl":true,"proxy_prefix":"/v1/zmax/console""#),
            "{resp_cfg}"
        );
        assert!(
            resp_cfg.contains(r#""ssl":false,"proxy_prefix":"/v1/zmax/api""#),
            "{resp_cfg}"
        );
        assert!(!resp_cfg.contains("adm-secret-token"));
        assert!(!resp_cfg.contains("api-secret-token"));
        assert!(!resp_cfg.contains("admin.key"));

        // /api/v1/ports tls nesnesini dönmeli
        let (handled_ports, resp_ports) =
            call_route(&state, true, "GET", "/v1/zmax/api/api/v1/ports", api_auth).await;
        assert!(handled_ports);
        assert!(
            resp_ports.contains(r#""tls":{"https":true,"admin":true,"api":false}"#),
            "{resp_ports}"
        );

        // Admin kök yolu API olarak yakalanmamalı (statik UI düşmeli), API kökü health dönmeli
        let (handled_admin_root, _) =
            call_route(&state, false, "GET", "/v1/zmax/console", Vec::new()).await;
        assert!(!handled_admin_root);

        let (handled_api_root, resp_api_root) =
            call_route(&state, true, "GET", "/v1/zmax/api", Vec::new()).await;
        assert!(handled_api_root);
        assert!(
            resp_api_root.contains(r#""status":"ok""#),
            "{resp_api_root}"
        );
    }

    #[tokio::test]
    async fn test_vhost_api_crud_full_fields_put_get_equality_and_atomic_rollback() {
        use tokio::io::AsyncReadExt;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let test_dir =
            std::env::temp_dir().join(format!("zmax_test_crud_{}_{}", std::process::id(), nanos));
        let conf_dir = test_dir.join("conf");
        let vhosts_dir = conf_dir.join("vhosts");
        let modules_dir = test_dir.join("modules");
        let www_dir = test_dir.join("www");
        std::fs::create_dir_all(&vhosts_dir).unwrap();
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::create_dir_all(&www_dir).unwrap();

        let conf_path = conf_dir.join("zmax.toml");
        std::fs::write(
            &conf_path,
            r#"
[server]
server_name = "ZMax/Test"

[vhosts_dir]
path = "conf/vhosts"
"#,
        )
        .unwrap();

        let cfg = ZMaxConfig::load_or_default(&conf_path).unwrap();
        let modules = LoadedModules::default();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);

        let state = Arc::new(ServerState {
            base_dir: test_dir.clone(),
            cache: zmax_cache::ZMaxCache::new(1024 * 1024, 60),
            limiter: RwLock::new(zmax_security::RateLimiter::new(1000)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::default()),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
            buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
            upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::default()),
            runtime: RwLock::new(RuntimeState {
                config: cfg,
                vhosts: Vec::new(),
                modules,
                policies,
                redis_client: None,
                auth,
                conf_path: conf_path.clone(),
                vhosts_dir: vhosts_dir.clone(),
                modules_dir: modules_dir.clone(),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                test_dir.clone(),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(crate::logger::AsyncLogManager::new(
                test_dir.clone(),
                test_dir.join("logs/access.log"),
                test_dir.join("logs/error.log"),
                250,
                64,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::new()),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: AtomicU64::new(0),
                cache_hits: AtomicU64::new(0),
                cache_misses: AtomicU64::new(0),
            },
        });

        async fn run_api_req(
            state: &Arc<ServerState>,
            method: &str,
            path: &str,
            body: &[u8],
        ) -> (bool, String) {
            let (mut client, mut server) = tokio::io::duplex(64 * 1024);
            let req = ParsedHttpRequest {
                method: method.to_string(),
                path: path.to_string(),
                query: String::new(),
                version: 1,
                host: "127.0.0.1".to_string(),
                headers: Vec::new(),
                body: body.to_vec(),
                keep_alive: false,
            };
            let st = Arc::clone(state);
            let task = tokio::spawn(async move {
                let handled = handle_api_route(&mut server, &req, &st, true)
                    .await
                    .unwrap();
                let _ = server.shutdown().await;
                handled
            });
            let mut out = Vec::new();
            client.read_to_end(&mut out).await.unwrap();
            let handled = task.await.unwrap();
            (handled, String::from_utf8_lossy(&out).into_owned())
        }

        let toml_file = vhosts_dir.join("crud.test.toml");

        // 1. PUT /api/v1/vhosts/crud.test - Tüm alanların yazılması
        let put_body = r#"{
            "document_root": "www/crud.test",
            "aliases": ["www.crud.test"],
            "hotlink_protection": true,
            "allow_ips": ["10.0.0.1/32"],
            "deny_ips": ["192.168.1.100"],
            "waf_enabled": true,
            "wp_brute_force": false,
            "waf_exclude_paths": ["/muaf/yol"],
            "security_headers": true,
            "hsts": true,
            "logging_enabled": true,
            "access_log": "logs/crud_access.log",
            "error_log": "logs/crud_error.log",
            "log_format": "%h %l %u %t \"%r\" %>s %b",
            "max_log_size_mb": 42,
            "also_write_global": false,
            "error_docs_enabled": true,
            "error_docs_dir": "errors",
            "error_docs_pages": {
                "404": "404.html",
                "500": "500.html"
            },
            "rewrite_enabled": true,
            "try_files": true,
            "htaccess": false,
            "rewrite_rules": [
                {
                    "pattern": "^/eski$",
                    "target": "/yeni",
                    "status": 301,
                    "flags": ["L"],
                    "last": true
                }
            ],
            "http2": true,
            "strict_sni": true,
            "tls_min_version": "1.3"
        }"#;

        let (handled, resp) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            put_body.as_bytes(),
        )
        .await;
        assert!(handled);
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains(r#""status":"saved""#), "{resp}");
        assert!(
            toml_file.exists(),
            "vHost TOML dosyası diske yazılmış olmalıdır"
        );

        let original_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert!(!original_toml.is_empty());

        // 2. GET /api/v1/vhosts/crud.test - Geri okuma ve birebir eşitlik
        let (handled_get, resp_get) =
            run_api_req(&state, "GET", "/api/v1/vhosts/crud.test", &[]).await;
        assert!(handled_get);
        assert!(resp_get.starts_with("HTTP/1.1 200 OK"), "{resp_get}");

        let body_json = resp_get.split("\r\n\r\n").nth(1).unwrap();
        let v: serde_json::Value = serde_json::from_str(body_json).unwrap();
        assert_eq!(v["ok"], true);
        let vhost = &v["vhost"];

        assert_eq!(vhost["domain"], "crud.test");
        assert_eq!(vhost["document_root"], "www/crud.test");
        assert_eq!(vhost["hotlink_protection"], true);
        assert_eq!(vhost["security"]["hotlink_protection"], true);
        assert_eq!(vhost["allow_ips"], serde_json::json!(["10.0.0.1/32"]));
        assert_eq!(
            vhost["security"]["allow_ips"],
            serde_json::json!(["10.0.0.1/32"])
        );
        assert_eq!(vhost["deny_ips"], serde_json::json!(["192.168.1.100"]));
        assert_eq!(vhost["waf_enabled"], true);
        assert_eq!(vhost["security"]["waf_enabled"], true);
        assert_eq!(vhost["wp_brute_force"], false);
        assert_eq!(vhost["waf_exclude_paths"], serde_json::json!(["/muaf/yol"]));
        assert_eq!(vhost["security_headers"], true);
        assert_eq!(vhost["headers"]["security_headers"], true);
        assert_eq!(vhost["hsts"], true);
        assert_eq!(vhost["logging_enabled"], true);
        assert_eq!(vhost["access_log"], "logs/crud_access.log");
        assert_eq!(vhost["error_log"], "logs/crud_error.log");
        assert_eq!(vhost["log_format"], "%h %l %u %t \"%r\" %>s %b");
        assert_eq!(vhost["max_log_size_mb"], 42);
        assert_eq!(vhost["also_write_global"], false);
        assert_eq!(vhost["error_docs_enabled"], true);
        assert_eq!(vhost["error_docs_dir"], "errors");
        assert_eq!(vhost["error_docs_pages"]["404"], "404.html");
        assert_eq!(vhost["error_docs_pages"]["500"], "500.html");
        assert_eq!(vhost["rewrite_enabled"], true);
        assert_eq!(vhost["rewrite_rules"][0]["pattern"], "^/eski$");
        assert_eq!(vhost["rewrite_rules"][0]["status"], 301);
        assert_eq!(vhost["http2"], true);
        assert_eq!(vhost["tls_min_version"], "1.3");

        // Aktif çalışma zamanındaki nesne eşitliği
        {
            let rt = state.runtime.read().await;
            let loaded = rt
                .vhosts
                .iter()
                .find(|x| x.entry.name == "crud.test")
                .expect("vHost runtime'da bulunmalıdır");
            assert!(loaded.entry.security.hotlink_protection);
            assert_eq!(loaded.entry.security.allow_ips, vec!["10.0.0.1/32"]);
            assert_eq!(loaded.entry.security.waf_exclude_paths, vec!["/muaf/yol"]);
            assert_eq!(loaded.entry.rewrite.rules.len(), 1);
            assert_eq!(
                loaded.entry.error_docs.pages.get(&404).map(String::as_str),
                Some("404.html")
            );
        }

        // 3. Bozuk JSON durumunda 400 Bad Request ve dosyanın DEĞİŞMEMESİ
        let (handled_bad, resp_bad) =
            run_api_req(&state, "PUT", "/api/v1/vhosts/crud.test", b"{bozuk_json:").await;
        assert!(handled_bad);
        assert!(
            resp_bad.starts_with("HTTP/1.1 400 Bad Request"),
            "{resp_bad}"
        );
        let after_bad_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert_eq!(
            after_bad_toml, original_toml,
            "Bozuk JSON sonrası TOML dosyası asla değişmemelidir"
        );

        // 4. Geçersiz alan (geçersiz IP ACL) durumunda 400 Bad Request ve dosyanın DEĞİŞMEMESİ
        let (handled_inv, resp_inv) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            br#"{"allow_ips":["gecersiz_ip_degeri"]}"#,
        )
        .await;
        assert!(handled_inv);
        assert!(
            resp_inv.starts_with("HTTP/1.1 400 Bad Request"),
            "{resp_inv}"
        );
        let after_inv_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert_eq!(
            after_inv_toml, original_toml,
            "Geçersiz alan sonrası TOML dosyası asla değişmemelidir"
        );

        // 5. Path traversal durumunda 400 Bad Request ve dosyanın DEĞİŞMEMESİ
        let (handled_trav, resp_trav) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            br#"{"document_root":"../../../etc/passwd"}"#,
        )
        .await;
        assert!(handled_trav);
        assert!(
            resp_trav.starts_with("HTTP/1.1 400 Bad Request"),
            "{resp_trav}"
        );
        let after_trav_toml = std::fs::read_to_string(&toml_file).unwrap();
        assert_eq!(
            after_trav_toml, original_toml,
            "Traversal saldırısı sonrası TOML dosyası asla değişmemelidir"
        );

        // 6. Kısmi Alan Güncellemesi (Patch)
        let patch_body = r#"{"hotlink_protection": false, "security": {"waf_enabled": false}}"#;
        let (handled_patch, resp_patch) = run_api_req(
            &state,
            "PUT",
            "/api/v1/vhosts/crud.test",
            patch_body.as_bytes(),
        )
        .await;
        assert!(handled_patch);
        assert!(resp_patch.starts_with("HTTP/1.1 200 OK"), "{resp_patch}");

        let (handled_patch_get, resp_patch_get) =
            run_api_req(&state, "GET", "/api/v1/vhosts/crud.test", &[]).await;
        assert!(handled_patch_get);
        let patch_json: serde_json::Value =
            serde_json::from_str(resp_patch_get.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        let patch_vhost = &patch_json["vhost"];
        assert_eq!(patch_vhost["hotlink_protection"], false);
        assert_eq!(patch_vhost["security"]["waf_enabled"], false);
        // Önceki alanlar korunmuş olmalıdır
        assert_eq!(patch_vhost["allow_ips"], serde_json::json!(["10.0.0.1/32"]));
        assert_eq!(patch_vhost["error_docs_pages"]["404"], "404.html");
        assert_eq!(patch_vhost["rewrite_rules"][0]["pattern"], "^/eski$");

        // Temizlik
        let _ = std::fs::remove_dir_all(&test_dir);
    }
}
