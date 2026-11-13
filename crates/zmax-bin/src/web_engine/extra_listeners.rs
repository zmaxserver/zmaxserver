//! `[[listeners.extra]]`: keyfi portta (kendi TLS sertifikasıyla) dinleyip her isteği SABİT bir arka uca
//! ileten ters vekil dinleyicileri. Arka uç yalnız yapılandırmadan gelir (Host/mutlak URI'den türetilmez).
//! İstek iletimi mevcut `proxy_h1::serve_proxy_request` ile yapılır; güvenlik kapısı (yasaklı IP, global ACL)
//! ve hız sınırı çekirdek boru hattıyla aynı bileşenleri kullanır.
//! SIGHUP / `POST /api/v1/reload` -> `reconcile`: ekler, çıkarır, ayarları ve sertifikayı canlı günceller.

use super::context::ResolvedVHostContext;
use super::http_write::write_http_response;
use super::logging::record_and_log;
use super::proxy_h1::serve_proxy_request;
use crate::api::{read_http_request_with_limits, send_http_read_error, ParsedHttpRequest, ServerState};
use crate::modules_runtime::{append_error_log, resolve_vhost_security_headers};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use zmax_config::{resolve_path, ExtraListenerConfig};
use zmax_httpparser::{resolve_real_ip, HttpReadLimits};
use zmax_security::IpAccessList;
use zmax_tls::{CertSource, SniResolver};

struct Running {
    cfg_tx: watch::Sender<Arc<ExtraListenerConfig>>,
    resolver: Arc<SniResolver>,
    stop_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    /// Soketi yeniden kurmayı gerektiren alanlar: (adres, port, TLS var mı).
    bound: (String, u16, bool),
}

type Registry = Mutex<HashMap<usize, HashMap<String, Running>>>;

fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn state_key(state: &Arc<ServerState>) -> usize {
    Arc::as_ptr(state) as *const () as usize
}

fn bound_key(c: &ExtraListenerConfig) -> (String, u16, bool) {
    (c.address.trim().to_string(), c.port, c.ssl.is_some())
}

fn cert_source(c: &ExtraListenerConfig, base_dir: &std::path::Path) -> Option<CertSource> {
    c.ssl.as_ref().map(|ssl| CertSource {
        label: format!("extra:{}", c.name),
        names: Vec::new(),
        cert_path: resolve_path(base_dir, ssl.cert.trim()),
        key_path: resolve_path(base_dir, ssl.key.trim()),
    })
}

/// Sertifika çiftinin gerçekten yüklenebildiğini (ayrıştırma + eşleşme) geçici çözümleyicide sınar.
fn probe_cert(src: &CertSource) -> Result<(), String> {
    let report = SniResolver::new().replace(std::slice::from_ref(src));
    if report.loaded == 1 {
        Ok(())
    } else {
        let why = report
            .skipped
            .first()
            .map(|s| s.reason.clone())
            .unwrap_or_else(|| "bilinmeyen neden".into());
        Err(format!("TLS sertifikası yüklenemedi ({}): {}", src.cert_path.display(), why))
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn start_one(
    state: &Arc<ServerState>,
    cfg: &ExtraListenerConfig,
    base_dir: &std::path::Path,
) -> Result<Running, String> {
    cfg.validate()?;
    let ip = cfg.bind_ip()?;
    let addr = SocketAddr::new(ip, cfg.port);
    let resolver = Arc::new(SniResolver::new());
    let acceptor = match cert_source(cfg, base_dir) {
        Some(src) => {
            probe_cert(&src)?;
            resolver.replace(&[src]);
            Some(
                zmax_tls::build_acceptor_with_alpn(Arc::clone(&resolver), vec![b"http/1.1".to_vec()])
                    .map_err(|e| format!("TLS kabul edici kurulamadı: {e}"))?,
            )
        }
        None => None,
    };
    let listener = crate::create_reuse_listener(addr, 1024, false)
        .map_err(|e| format!("{addr} dinlenemedi: {e}"))?;
    println!(
        "* Ek Dinleyici  : {}://{} ({}) -> {}",
        if acceptor.is_some() { "https" } else { "http" },
        addr,
        cfg.name,
        cfg.upstream
    );

    let (cfg_tx, cfg_rx) = watch::channel(Arc::new(cfg.clone()));
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let active = Arc::new(AtomicUsize::new(0));
    let state_c = Arc::clone(state);
    let task = tokio::spawn(async move {
        loop {
            let (socket, peer) = tokio::select! {
                _ = stop_rx.changed() => break,
                acc = listener.accept() => match acc {
                    Ok(v) => v,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let cfg_now = cfg_rx.borrow().clone();
            if active.load(Ordering::Relaxed) >= cfg_now.max_client_conns {
                drop(socket);
                continue;
            }
            active.fetch_add(1, Ordering::Relaxed);
            let guard = ActiveGuard(Arc::clone(&active));
            let _ = socket.set_nodelay(true);
            let s = Arc::clone(&state_c);
            let acc = acceptor.clone();
            tokio::spawn(async move {
                let _guard = guard;
                match acc {
                    Some(tls) => {
                        if let Ok(Ok(stream)) =
                            tokio::time::timeout(Duration::from_secs(10), tls.accept(socket)).await
                        {
                            let _ = handle_conn(stream, peer, s, cfg_now, true).await;
                        }
                    }
                    None => {
                        let _ = handle_conn(socket, peer, s, cfg_now, false).await;
                    }
                }
            });
        }
    });

    Ok(Running {
        cfg_tx,
        resolver,
        stop_tx,
        task,
        bound: bound_key(cfg),
    })
}

/// Yapılandırmadaki ek dinleyicileri çalışan kümeyle uzlaştırır: yenileri açar, silinen/soketi değişenleri
/// kapatır, diğerlerinin ayarlarını ve sertifikasını canlı günceller. Hata mesajlarını döndürür.
pub async fn reconcile(state: &Arc<ServerState>) -> Vec<String> {
    let (desired, base_dir): (Vec<ExtraListenerConfig>, _) = {
        let rt = state.runtime.read().await;
        (
            rt.config.listeners.extra.iter().filter(|e| e.enabled).cloned().collect(),
            state.base_dir.clone(),
        )
    };
    let key = state_key(state);
    let mut errors = Vec::new();

    // 1) Kaldırılan veya soket parametresi değişen dinleyicileri durdur.
    let mut stopping = Vec::new();
    {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let map = reg.entry(key).or_default();
        let names: Vec<String> = map.keys().cloned().collect();
        for n in names {
            let keep = desired
                .iter()
                .any(|d| d.name == n && map.get(&n).map(|r| r.bound == bound_key(d)).unwrap_or(false));
            if !keep {
                if let Some(r) = map.remove(&n) {
                    let _ = r.stop_tx.send(true);
                    stopping.push((n, r.task));
                }
            }
        }
    }
    for (n, task) in stopping {
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        println!("* Ek Dinleyici  : '{n}' kapatıldı.");
    }

    // 2) Var olanları güncelle, yenileri başlat.
    for d in desired {
        let existing = {
            let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            reg.get(&key)
                .and_then(|m| m.get(&d.name))
                .map(|r| (r.cfg_tx.clone(), Arc::clone(&r.resolver)))
        };
        if let Some((tx, resolver)) = existing {
            if let Some(src) = cert_source(&d, &base_dir) {
                match probe_cert(&src) {
                    Ok(()) => {
                        resolver.replace(&[src]);
                    }
                    Err(e) => errors.push(format!("ek dinleyici '{}': {e} (eski sertifika korunuyor)", d.name)),
                }
            }
            tx.send_replace(Arc::new(d));
            continue;
        }
        match start_one(state, &d, &base_dir) {
            Ok(r) => {
                let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
                reg.entry(key).or_default().insert(d.name.clone(), r);
            }
            Err(e) => errors.push(format!("ek dinleyici '{}' başlatılamadı: {e}", d.name)),
        }
    }

    for e in &errors {
        eprintln!("[Ek Dinleyici] {e}");
        append_error_log(&state.base_dir, &format!("[Ek Dinleyici] {e}")).await;
    }
    errors
}

/// Yol önekine göre sabit arka ucu seçer (en uzun önek kazanır; yoksa varsayılan `upstream`).
fn select_upstream(cfg: &ExtraListenerConfig, path: &str) -> Result<String, String> {
    let best = cfg
        .routes
        .iter()
        .filter(|r| path.starts_with(&r.path_prefix) || path == r.path_prefix.trim_end_matches('/'))
        .max_by_key(|r| r.path_prefix.len());
    match best {
        Some(r) => zmax_config::extra_listener::parse_upstream(&r.upstream),
        None => cfg.upstream_addr(),
    }
}

#[allow(clippy::too_many_arguments)]
fn synthetic_ctx(
    cfg: &ExtraListenerConfig,
    upstream: String,
    policies: &crate::modules_runtime::CompiledPolicies,
    global_acl: IpAccessList,
    max_log_size_bytes: u64,
    doc_root: std::path::PathBuf,
) -> ResolvedVHostContext {
    ResolvedVHostContext {
        doc_root,
        index_files: Vec::new(),
        php_enabled: false,
        php_upstream: String::new(),
        php_upstreams: Vec::new(),
        php_lb_policy: "least_conn".to_string(),
        php_timeout: 5,
        cache_enabled: false,
        cache_expire: 1,
        cache_stale_sec: 0,
        vhost_name: format!("extra:{}", cfg.name),
        vhost_aliases: Vec::new(),
        force_https: false,
        hotlink_protection: false,
        hotlink_config: zmax_config::HotlinkConfig::default(),
        global_acl,
        vhost_acl: IpAccessList::default(),
        vhost_acl_engine: zmax_security::VhostAcl::default(),
        rewrite_enabled: false,
        rewrite_try_files: false,
        rewrite_htaccess: false,
        rewrite_rules: Vec::new(),
        proxy_enabled: true,
        proxy_upstream: upstream,
        proxy_path_prefix: "/".to_string(),
        proxy_preserve_host: cfg.preserve_host,
        proxy_websocket: cfg.websocket,
        proxy_ext: cfg.proxy_ext.clone(),
        auto_webp: false,
        auto_avif: false,
        etag_enabled: false,
        last_modified_header: false,
        max_log_size_bytes,
        headers_policy: resolve_vhost_security_headers(
            policies.headers_enabled,
            &policies.security_headers,
            None,
        ),
        // Panel API'si JSON/çok parçalı gövde gönderir; WAF yalnız vhost'larda uygulanır (LiteSpeed paneli de WAF'sızdı).
        waf_enabled: Some(false),
        waf_exclude_paths: Vec::new(),
        error_docs: zmax_config::VHostErrorDocsSection::default(),
        logging: zmax_config::VHostLoggingSection::default(),
        tls_http2: false,
        acme_root: None,
        auth: zmax_config::VHostAuthSection::default(),
        php_dial_timeout_ms: 1,
        autoindex: false,
        block_dangerous_files: false,
    }
}

async fn handle_conn<S>(
    mut socket: S,
    peer: SocketAddr,
    state: Arc<ServerState>,
    cfg: Arc<ExtraListenerConfig>,
    is_https: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let mut leftover = Vec::with_capacity(4096);
    let mut idx = 0usize;
    loop {
        let (hdr_t, body_t, ka_t, max_h, max_b) = {
            let rt = state.runtime.read().await;
            let sec = &rt.config.security;
            (
                sec.slowloris_header_timeout_sec.max(1),
                sec.slowloris_body_timeout_sec.max(1),
                sec.keep_alive_timeout_sec.max(1),
                sec.max_header_size_kb.max(8) * 1024,
                sec.max_body_size_mb.max(1) * 1024 * 1024,
            )
        };
        let limits = HttpReadLimits {
            max_header_bytes: max_h,
            max_body_bytes: max_b,
            header_timeout: Duration::from_secs(hdr_t),
            body_timeout: Duration::from_secs(body_t),
        };
        let read = read_http_request_with_limits(&mut socket, &mut leftover, limits);
        let res = if idx > 0 {
            // Keep-Alive bağlantıda sonraki isteği boşta bekleme sınırı.
            match tokio::time::timeout(Duration::from_secs(ka_t + hdr_t + body_t), read).await {
                Ok(r) => r,
                Err(_) => break,
            }
        } else {
            read.await
        };
        let req = match res {
            Ok(Some(r)) => r,
            Ok(None) => break,
            Err(err) => {
                send_http_read_error(&mut socket, &err).await;
                break;
            }
        };
        idx += 1;
        if !handle_request(&mut socket, peer, &state, &cfg, is_https, ka_t, req).await? {
            break;
        }
    }
    Ok(())
}

async fn handle_request<S>(
    socket: &mut S,
    peer: SocketAddr,
    state: &Arc<ServerState>,
    cfg: &Arc<ExtraListenerConfig>,
    is_https: bool,
    keep_alive_timeout_sec: u64,
    req: ParsedHttpRequest,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let started = Instant::now();
    state.stats.total_requests.fetch_add(1, Ordering::Relaxed);
    let is_head = req.method.eq_ignore_ascii_case("HEAD");

    let (policies, global_acl, max_log, https_port) = {
        let rt = state.runtime.read().await;
        let mb = rt.config.logging.max_log_size_mb.saturating_mul(1024 * 1024);
        (
            rt.policies.clone(),
            IpAccessList::new(
                rt.config.security.allow_ips.clone(),
                rt.config.security.deny_ips.clone(),
            ),
            if mb == 0 { super::DEFAULT_LOG_MAX_BYTES } else { mb },
            rt.config.listeners.https.port,
        )
    };
    let real_ip = if policies.realip.enabled {
        resolve_real_ip(
            peer.ip(),
            &req.headers,
            &policies.realip.header_name,
            &policies.realip.trusted_proxies,
            policies.realip.recursive,
        )
    } else {
        peer.ip()
    };
    let real_ip_str = real_ip.to_string();
    let ctx_upstream = select_upstream(cfg, &req.path);
    let upstream_ok = ctx_upstream.is_ok();
    let ctx = synthetic_ctx(
        cfg,
        ctx_upstream.unwrap_or_default(),
        &policies,
        global_acl,
        max_log,
        state.base_dir.clone(),
    );
    let referer = zmax_httpparser::extract_header(&req.headers, "referer");
    let ua = zmax_httpparser::extract_header(&req.headers, "user-agent");

    // Yerel hata yanıtı + günlük (yalnız bu dosyadaki reddetme yolları için).
    macro_rules! deny {
        ($code:expr, $reason:expr, $body:expr) => {{
            let body: &[u8] = $body;
            write_http_response(
                socket,
                $code,
                $reason,
                &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
                body,
                Some(body.len()),
                is_head,
                is_https,
                false,
                keep_alive_timeout_sec,
                ctx.headers_policy.as_ref(),
                None,
            )
            .await?;
            record_and_log(
                state,
                &real_ip_str,
                &req.method,
                &req.path,
                $code,
                started,
                Some(&ctx),
                if is_head { 0 } else { body.len() },
                referer,
                ua,
                "HTTP/1.1",
                "",
            )
            .await;
            return Ok(false);
        }};
    }

    if !upstream_ok {
        deny!(502, "Bad Gateway", b"502 Bad Gateway - Invalid Upstream Configuration\n");
    }

    let verdict = crate::security_pipeline::evaluate_request_security(
        &ctx,
        real_ip,
        peer.ip(),
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
        false,
    );
    if let crate::security_pipeline::SecurityVerdict::Blocked { reason } = &verdict {
        deny!(403, "Forbidden", reason.as_bytes());
    }
    if !matches!(verdict, crate::security_pipeline::SecurityVerdict::Allowed) {
        deny!(403, "Forbidden", b"403 Forbidden\n");
    }
    if !state.limiter.read().await.check_allowed(real_ip) {
        deny!(429, "Too Many Requests", b"Too Many Requests!");
    }

    let (status, still_alive, bytes) = serve_proxy_request(
        socket,
        state,
        &req,
        real_ip,
        is_https,
        &ctx,
        policies.proxy.connect_timeout_sec,
        req.keep_alive,
    )
    .await?;
    record_and_log(
        state,
        &real_ip_str,
        &req.method,
        &req.path,
        status,
        started,
        Some(&ctx),
        bytes,
        referer,
        ua,
        "HTTP/1.1",
        "",
    )
    .await;
    Ok(still_alive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zmax_config::{ExtraRouteConfig, ExtraSslConfig};

    fn cfg() -> ExtraListenerConfig {
        ExtraListenerConfig {
            name: "t".into(),
            enabled: true,
            address: "127.0.0.1".into(),
            port: 1,
            ssl: Some(ExtraSslConfig { cert: "c".into(), key: "k".into() }),
            upstream: "http://127.0.0.1:8035".into(),
            routes: vec![
                ExtraRouteConfig { path_prefix: "/phpmyadmin/".into(), upstream: "127.0.0.1:8091".into() },
                ExtraRouteConfig { path_prefix: "/phpmyadmin/api/".into(), upstream: "127.0.0.1:8092".into() },
            ],
            preserve_host: true,
            websocket: true,
            max_client_conns: 8,
            proxy_ext: Default::default(),
        }
    }

    #[test]
    fn route_longest_prefix_and_default() {
        let c = cfg();
        assert_eq!(select_upstream(&c, "/x").unwrap(), "127.0.0.1:8035");
        assert_eq!(select_upstream(&c, "/phpmyadmin").unwrap(), "127.0.0.1:8091");
        assert_eq!(select_upstream(&c, "/phpmyadmin/index.php").unwrap(), "127.0.0.1:8091");
        assert_eq!(select_upstream(&c, "/phpmyadmin/api/v1").unwrap(), "127.0.0.1:8092");
        // önek tam eşleşme değilse varsayılan (yol öneki sınır dışı)
        assert_eq!(select_upstream(&c, "/phpmyadmin2/x").unwrap(), "127.0.0.1:8035");
    }
}
