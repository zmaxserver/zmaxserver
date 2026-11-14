//! # ZMax Server (zmax)
//! Evrensel panel uyumlu (zPanel, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia vb.),
//! çakışmasız port mimarili, bellek güvenli yüksek hızlı Rust HTTP motoru ve WebAdmin konsolu.

mod config;
mod acme_runtime;
mod api;
mod core;
mod h2_engine;
mod logger;
mod modules;
mod modules_runtime;
pub mod security_pipeline;
mod web_engine;

use api::{
    compute_effective_auth, handle_api_connection, handle_api_route, normalize_panel_request_path, read_http_request_with_limits,
    refresh_tls_certs, send_http_read_error, RuntimeState, ServerState, ServerStats,
};
#[cfg(not(target_env = "musl"))]
use mimalloc::MiMalloc;
use modules_runtime::{
    append_error_log, build_redis_client, compile_policies,
};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use zmax_config::{load_vhosts_dir, resolve_path, LoadedModules, ZMaxConfig};
use zmax_httpparser::{resolve_real_ip, HttpReadLimits};
use zmax_obfuscate::zpoly;

#[cfg(not(target_env = "musl"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

struct CliOptions {
    show_version: bool,
    check_only: bool,
    fix_tls_perms: bool,
    config_override: Option<PathBuf>,
}

fn parse_cli_args() -> CliOptions {
    let mut opts = CliOptions {
        show_version: false,
        check_only: false,
        fix_tls_perms: false,
        config_override: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-v" | "--version" => opts.show_version = true,
            "-t" | "--check" | "--test" => opts.check_only = true,
            "--fix-tls-perms" => opts.fix_tls_perms = true,
            "-c" | "--config" => {
                if let Some(p) = args.next() {
                    opts.config_override = Some(PathBuf::from(p));
                }
            }
            _ => {}
        }
    }
    opts
}

fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(s) = path.to_str() {
            if let Some(stripped) = s.strip_prefix(r"\\?\") {
                return PathBuf::from(stripped);
            }
        }
    }
    path
}

fn has_zmax_layout(dir: &Path) -> bool {
    dir.join("conf").join("zmax.toml").exists() || dir.join("admin").join("index.html").exists()
}

fn resolve_base_dir() -> PathBuf {
    if let Ok(home) = std::env::var("ZMAX_HOME") {
        let p = PathBuf::from(home.trim());
        if !home.trim().is_empty() && p.exists() {
            return p;
        }
    }

    let raw_exe = std::env::current_exe().unwrap_or_default();
    let exe_path = std::fs::canonicalize(&raw_exe)
        .map(strip_windows_verbatim_prefix)
        .unwrap_or(raw_exe);

    let candidate = if let Some(parent) = exe_path.parent() {
        if parent.ends_with("bin") || parent.ends_with("release") || parent.ends_with("debug") {
            parent.parent().unwrap_or(parent).to_path_buf()
        } else {
            parent.to_path_buf()
        }
    } else {
        PathBuf::from(".")
    };

    if has_zmax_layout(&candidate) {
        return candidate;
    }
    if let Ok(cwd) = std::env::current_dir() {
        if has_zmax_layout(&cwd) {
            return cwd;
        }
    }
    #[cfg(unix)]
    {
        let unix_default = Path::new("/usr/local/zmax");
        if has_zmax_layout(unix_default) {
            return unix_default.to_path_buf();
        }
    }
    candidate
}

/// Yapılandırılabilir `SO_REUSEADDR` / opsiyonel `SO_REUSEPORT` soket bağlayıcısı.
fn create_reuse_listener(
    addr: SocketAddr,
    backlog: i32,
    reuse_port: bool,
) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, None)?;
    #[cfg(unix)]
    {
        socket.set_reuse_address(true)?;
        if reuse_port {
            let _ = socket.set_reuse_port(true);
        }
    }
    #[cfg(not(unix))]
    {
        // Windows'ta SO_REUSEADDR baska bir surecin aktif dinledigi portu calmaya izin verir; guvenlik icin kapatilir.
        socket.set_reuse_address(false)?;
        let _ = reuse_port;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog.max(128))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// Yapılandırmadaki TLS sertifika/anahtar dosya yollarını (vhost + admin/api dinleyicileri) toplar.
fn collect_tls_key_paths(
    base_dir: &Path,
    config: &ZMaxConfig,
    vhosts: &[zmax_config::LoadedVHost],
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for raw in [
        &config.listeners.admin.tls_key,
        &config.listeners.admin.tls_cert,
        &config.listeners.api.tls_key,
        &config.listeners.api.tls_cert,
    ]
    .into_iter()
    .chain(
        config
            .listeners
            .extra
            .iter()
            .filter_map(|e| e.ssl.as_ref())
            .flat_map(|s| [&s.key, &s.cert]),
    ) {
        if !raw.trim().is_empty() {
            paths.push(resolve_path(base_dir, raw));
        }
    }
    for vh in vhosts {
        for raw in [&vh.entry.ssl.key, &vh.entry.ssl.certificate] {
            if !raw.trim().is_empty() {
                paths.push(resolve_path(base_dir, raw));
            }
        }
    }
    paths
}

/// `zmax --fix-tls-perms`: certbot/panel yenilemesinden sonra (root olarak, ör. `--deploy-hook`)
/// TLS anahtar/sertifika dosyalarını servis grubunun okuyabileceği hâle getirir (root:grup, grup okuma biti).
/// Çalışan sunucu düşürme sonrası root olmadığından bu işi kendisi yapamaz.
fn run_fix_tls_perms(
    base_dir: &Path,
    config: &ZMaxConfig,
    vhosts: &[zmax_config::LoadedVHost],
) -> Result<(), Box<dyn std::error::Error>> {
    let paths = collect_tls_key_paths(base_dir, config, vhosts);
    if !zmax_core::is_running_as_root() {
        println!(
            "[Bilgi] --fix-tls-perms root gerektirir; root olmadığından {} TLS yolu için işlem yapılmadı.",
            paths.len()
        );
        return Ok(());
    }
    if config.server.group.trim().is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server.group boş: TLS anahtarlarının hangi gruba okutulacağı belirsiz",
        )
        .into());
    }
    match zmax_core::ensure_tls_keys_readable_by_group(&config.server.group, &paths) {
        Ok(changed) => {
            println!(
                "[OK] TLS izinleri uygulandı: {} yoldan {} dosya değişti (grup='{}').",
                paths.len(),
                changed,
                config.server.group
            );
            Ok(())
        }
        Err(err) => Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, err).into()),
    }
}

fn parse_bind_addr(ip: &str, port: u16) -> Result<SocketAddr, String> {
    let formatted = if ip.contains(':') && !ip.starts_with('[') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    formatted
        .parse::<SocketAddr>()
        .map_err(|e| format!("Gecersiz dinleme adresi ({}): {}", formatted, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = parse_cli_args();
    if cli.show_version {
        println!("ZMax Server v{} (ZePanel Universal Engine)", env!("ZMAX_VERSION"));
        return Ok(());
    }

    let base_dir = resolve_base_dir();
    let env_conf = std::env::var("ZMAX_CONF")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from);
    let explicit_conf = cli.config_override.is_some() || env_conf.is_some();
    let conf_path = cli
        .config_override
        .or(env_conf)
        .unwrap_or_else(|| base_dir.join("conf").join("zmax.toml"));

    if (explicit_conf || cli.check_only) && !conf_path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Yapilandirma dosyasi bulunamadi: {}", conf_path.display()),
        )
        .into());
    }

    let config = ZMaxConfig::load_or_default(&conf_path)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let vhosts_dir = resolve_path(&base_dir, &config.vhosts_dir.path);
    let vhosts = load_vhosts_dir(&vhosts_dir, &base_dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let modules_dir = base_dir.join("modules");
    let modules = LoadedModules::load_from_dir(&modules_dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let validation_warnings = config
        .validate_workspace_layout(&base_dir, &vhosts, &modules)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    config::acme::apply_global_acme_root(&config, &base_dir);

    if cli.fix_tls_perms {
        return run_fix_tls_perms(&base_dir, &config, &vhosts);
    }

    if cli.check_only {
        for w in &validation_warnings {
            println!("[UYARI] {}", w);
        }
        println!(
            "[OK] Yapilandirma dogrulandi: {} | HTTP={}:{} | Admin={}:{} | API={}:{} | vHosts={} | Moduller={}",
            conf_path.display(),
            config.listeners.http.address,
            config.listeners.http.port,
            config.listeners.admin.address,
            config.listeners.admin.port,
            config.listeners.api.address,
            config.listeners.api.port,
            vhosts.len(),
            modules.len()
        );
        return Ok(());
    }

    println!(
        "{}",
        zpoly!("============================================================").as_str()
    );
    println!(
        "{}",
        zpoly!(concat!("  ⚡ ZMax Server v", env!("ZMAX_VERSION"), " - ZePanel Universal Web Engine")).as_str()
    );
    println!(
        "{}",
        zpoly!("============================================================").as_str()
    );

    let www_dir = base_dir.join("www").join("html");
    let admin_dir = resolve_path(&base_dir, &config.listeners.admin.document_root);
    let logs_dir = base_dir.join("logs");
    let disk_cache_dir = resolve_path(&base_dir, &config.cache.disk_cache_dir);

    let _ = tokio::fs::create_dir_all(&www_dir).await;
    let _ = tokio::fs::create_dir_all(&admin_dir).await;
    let _ = tokio::fs::create_dir_all(&logs_dir).await;
    let _ = tokio::fs::create_dir_all(&disk_cache_dir).await;

    let workers = if config.server.workers == 0 {
        zmax_core::num_cpus_estimate().max(zmax_runtime::detect_worker_threads())
    } else {
        config.server.workers
    };
    let policies = compile_policies(&config, &modules);
    let redis_client = build_redis_client(&modules);
    let auth = compute_effective_auth(&config);
    for notice in &auth.auto_generated_notices {
        eprintln!("{}", notice);
        append_error_log(&base_dir, notice).await;
    }

    println!(
        "{}",
        zpoly!("* Mimari: Asenkron Work-Stealing Workers (Tokio/IOCP/epoll)").as_str()
    );
    println!(
        "{}",
        zpoly!("* Bellek Ayirici: mimalloc (Ultra-Low Memory: ~12 MB)").as_str()
    );
    println!(
        "* Cekirdek Sayisi: {} {}",
        workers,
        zpoly!("Asenkron Worker aktif.").as_str()
    );
    println!("* Kok Dizin: {}", base_dir.display());
    println!(
        "* Yapilandirma: {} ({} sanal konak, {} modul yuklendi)",
        conf_path.display(),
        vhosts.len(),
        modules.len()
    );

    let cache_bytes = config.cache.memory_cache_mb.max(16) * 1024 * 1024;
    let cache_ttl = config.cache.default_ttl_seconds.max(10);
    let rate_max = policies.effective_rate_limit;
    let fastcgi_pool_size = policies.fastcgi.pool_size.max(8);

    let http_addr = parse_bind_addr(&config.listeners.http.address, config.listeners.http.port)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let admin_addr = parse_bind_addr(&config.listeners.admin.address, config.listeners.admin.port)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let api_addr = parse_bind_addr(&config.listeners.api.address, config.listeners.api.port)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let http_backlog = config.listeners.http.backlog as i32;
    let http_reuse_port = config.listeners.http.reuse_port;
    let http_nodelay = config.listeners.http.tcp_nodelay;
    let http_port = config.listeners.http.port;
    let https_port = config.listeners.https.port;
    let api_enabled = config.listeners.api.enabled && api_addr != admin_addr;
    let admin_enabled = config.listeners.admin.enabled;
    let http_enabled = config.listeners.http.enabled;
    let https_enabled = config.listeners.https.enabled && config.listeners.https.ssl;
    let https_addr = parse_bind_addr(&config.listeners.https.address, config.listeners.https.port)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    #[cfg(unix)]
    let unix_api_sock = config.listeners.api.unix_socket.clone();

    let log_mgr = Arc::new(logger::AsyncLogManager::new(
        base_dir.clone(),
        PathBuf::from(config.logging.access_log.clone()),
        PathBuf::from(config.logging.error_log.clone()),
        config.logging.batch_flush_ms,
        config.logging.batch_buffer_kb,
    ));
    let admin_sni = Arc::new(zmax_tls::SniResolver::new());
    let api_sni = Arc::new(zmax_tls::SniResolver::new());
    let htaccess_res = Arc::new(zmax_rewrite::HtAccessResolver::new());
    let shutdown_coord = Arc::new(zmax_runtime::ShutdownCoordinator::new());

    let state = Arc::new(ServerState {
        base_dir,
        cache: zmax_cache::ZMaxCache::with_disk_dir(cache_bytes, cache_ttl, &disk_cache_dir),
        limiter: RwLock::new(zmax_security::RateLimiter::new(rate_max)),
        ban_manager: Arc::new(zmax_security::IpBanManager::new()),
        wp_guard: Arc::new(zmax_security::WpBruteForceGuard::default()),
        basic_auth: Arc::new(zmax_security::BasicAuthManager::with_max_concurrent_hashes(
            config.security.auth_max_concurrent_hashes,
        )),
        buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
        upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::new(fastcgi_pool_size)),
        runtime: RwLock::new(RuntimeState {
            config,
            vhosts,
            modules,
            policies,
            redis_client,
            auth,
            conf_path,
            vhosts_dir,
            modules_dir,
        }),
        admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(admin_dir)),
        tls: Arc::new(zmax_tls::SniResolver::new()),
        admin_tls: admin_sni,
        api_tls: api_sni,
        log_manager: log_mgr,
        htaccess_resolver: htaccess_res,
        shutdown: shutdown_coord,
        waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
        access_logs: Mutex::new(VecDeque::with_capacity(200)),
        stats: ServerStats {
            start_time: Instant::now(),
            total_requests: std::sync::atomic::AtomicU64::new(0),
            cache_hits: std::sync::atomic::AtomicU64::new(0),
            cache_misses: std::sync::atomic::AtomicU64::new(0),
        },
    });

    // Arka plan bellek & havuz bakım görevi
    {
        let maint_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                let _ = maint_state.upstream_pool.purge_expired();
                let _ = maint_state.limiter.read().await.purge_expired();
                let _ = maint_state.ban_manager.list_banned();
            }
        });
    }

    if http_enabled {
        let web_listener = create_reuse_listener(http_addr, http_backlog, http_reuse_port)?;
        println!("* Web Sunucusu  : http://{}", http_addr);
        let state_web = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                if let Ok((socket, peer_addr)) = web_listener.accept().await {
                    if http_nodelay {
                        let _ = socket.set_nodelay(true);
                    }
                    let s = Arc::clone(&state_web);
                    tokio::spawn(async move {
                        let _ = web_engine::handle_web_connection(
                            socket, peer_addr, s, false, http_port,
                        )
                        .await;
                    });
                }
            }
        });
    }

    if https_enabled {
        let loaded = {
            let rt = state.runtime.read().await;
            refresh_tls_certs(&state.tls, &rt.vhosts, &state.base_dir).await
        };
        if loaded == 0 {
            eprintln!("[TLS] Uyari: yuklenen sertifika yok; HTTPS el sikismalari reddedilecek.");
        }
        let alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = zmax_tls::build_acceptor_with_alpn(Arc::clone(&state.tls), alpn_protocols)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let https_listener = create_reuse_listener(https_addr, http_backlog, http_reuse_port)?;
        println!(
            "* HTTPS Sunucu  : https://{} (TLS 1.2/1.3, ALPN h2/http/1.1, {} sertifika)",
            https_addr, loaded
        );
        let state_tls = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                if let Ok((socket, peer_addr)) = https_listener.accept().await {
                    if http_nodelay {
                        let _ = socket.set_nodelay(true);
                    }
                    let s = Arc::clone(&state_tls);
                    let acc = acceptor.clone();
                    tokio::spawn(async move {
                        let hs =
                            tokio::time::timeout(Duration::from_secs(10), acc.accept(socket)).await;
                        if let Ok(Ok(tls_stream)) = hs {
                            let alpn = zmax_tls::negotiated_alpn(&tls_stream);
                            let sni = zmax_tls::client_sni(&tls_stream).map(|s| s.to_string());
                            if alpn.as_deref() == Some(b"h2") {
                                let _ = h2_engine::handle_h2_connection(
                                    tls_stream, peer_addr, s, true, https_port, sni,
                                )
                                .await;
                            } else {
                                let _ = web_engine::handle_web_connection(
                                    tls_stream, peer_addr, s, true, https_port,
                                )
                                .await;
                            }
                        }
                    });
                }
            }
        });
    }

    let (admin_tls_cfg, api_tls_cfg) = {
        let rt = state.runtime.read().await;
        (
            (
                rt.config.listeners.admin.ssl,
                rt.config.listeners.admin.tls_cert.clone(),
                rt.config.listeners.admin.tls_key.clone(),
            ),
            (
                rt.config.listeners.api.ssl,
                rt.config.listeners.api.tls_cert.clone(),
                rt.config.listeners.api.tls_key.clone(),
            ),
        )
    };

    if admin_enabled {
        let admin_acceptor = if admin_tls_cfg.0 {
            let cert_p = resolve_path(&state.base_dir, &admin_tls_cfg.1);
            let key_p = resolve_path(&state.base_dir, &admin_tls_cfg.2);
            let cert_src = zmax_tls::CertSource {
                label: "admin".to_string(),
                names: Vec::new(),
                cert_path: cert_p,
                key_path: key_p,
            };
            let _ = state.admin_tls.replace(&[cert_src]);
            Some(
                zmax_tls::build_acceptor_with_alpn(
                    Arc::clone(&state.admin_tls),
                    vec![b"http/1.1".to_vec()],
                )
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("WebAdmin TLS baslatilamadi: {e}"),
                    )
                })?,
            )
        } else {
            None
        };
        let admin_listener = create_reuse_listener(admin_addr, 512, false)?;
        if admin_acceptor.is_some() {
            println!("* WebAdmin UI   : https://{} (TLS aktif)", admin_addr);
        } else {
            println!("* WebAdmin UI   : http://{}", admin_addr);
        }
        let state_admin = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                if let Ok((socket, peer_addr)) = admin_listener.accept().await {
                    let s = Arc::clone(&state_admin);
                    let acc = admin_acceptor.clone();
                    tokio::spawn(async move {
                        if let Some(tls_acc) = acc {
                            let hs = tokio::time::timeout(
                                Duration::from_secs(10),
                                tls_acc.accept(socket),
                            )
                            .await;
                            if let Ok(Ok(tls_stream)) = hs {
                                let _ =
                                    handle_admin_connection(tls_stream, peer_addr, s, true).await;
                            }
                        } else {
                            let _ = handle_admin_connection(socket, peer_addr, s, false).await;
                        }
                    });
                }
            }
        });
    }

    if api_enabled {
        let api_acceptor = if api_tls_cfg.0 {
            let cert_p = resolve_path(&state.base_dir, &api_tls_cfg.1);
            let key_p = resolve_path(&state.base_dir, &api_tls_cfg.2);
            let cert_src = zmax_tls::CertSource {
                label: "api".to_string(),
                names: Vec::new(),
                cert_path: cert_p,
                key_path: key_p,
            };
            let _ = state.api_tls.replace(&[cert_src]);
            Some(
                zmax_tls::build_acceptor_with_alpn(
                    Arc::clone(&state.api_tls),
                    vec![b"http/1.1".to_vec()],
                )
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Kontrol API TLS baslatilamadi: {e}"),
                    )
                })?,
            )
        } else {
            None
        };
        let api_listener = create_reuse_listener(api_addr, 512, false)?;
        if api_acceptor.is_some() {
            println!(
                "* Kontrol API   : https://{}/api/v1/health (TLS aktif)",
                api_addr
            );
        } else {
            println!("* Kontrol API   : http://{}/api/v1/health", api_addr);
        }
        let state_api = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                if let Ok((socket, peer_addr)) = api_listener.accept().await {
                    let s = Arc::clone(&state_api);
                    let acc = api_acceptor.clone();
                    tokio::spawn(async move {
                        if let Some(tls_acc) = acc {
                            let hs = tokio::time::timeout(
                                Duration::from_secs(10),
                                tls_acc.accept(socket),
                            )
                            .await;
                            if let Ok(Ok(tls_stream)) = hs {
                                let _ = handle_api_connection(tls_stream, peer_addr, s).await;
                            }
                        } else {
                            let _ = handle_api_connection(socket, peer_addr, s).await;
                        }
                    });
                }
            }
        });
    }

    // [ek-dinleyici] [[listeners.extra]]: sabit arka uçlu TLS ters vekil dinleyicileri (fail-closed)
    let extra_errors = web_engine::reconcile_extra_listeners(&state).await;
    if !extra_errors.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, extra_errors.join("; ")).into());
    }

    #[cfg(unix)]
    if !unix_api_sock.trim().is_empty() {
        let sock_path = PathBuf::from(unix_api_sock.trim());
        if let Some(parent) = sock_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let _ = tokio::fs::remove_file(&sock_path).await;
        if let Ok(unix_listener) = tokio::net::UnixListener::bind(&sock_path) {
            println!("* API Unix Soket: {}", sock_path.display());
            let state_unix = Arc::clone(&state);
            tokio::spawn(async move {
                loop {
                    if let Ok((mut stream, _)) = unix_listener.accept().await {
                        let s = Arc::clone(&state_unix);
                        tokio::spawn(async move {
                            let mut leftover = Vec::with_capacity(4096);
                            let limits = HttpReadLimits {
                                max_header_bytes: 64 * 1024,
                                max_body_bytes: 4 * 1024 * 1024,
                                header_timeout: Duration::from_secs(10),
                                body_timeout: Duration::from_secs(15),
                            };
                            match read_http_request_with_limits(&mut stream, &mut leftover, limits)
                                .await
                            {
                                Ok(Some(req)) => {
                                    let _ = handle_api_route(&mut stream, &req, &s, true).await;
                                }
                                Err(err) => send_http_read_error(&mut stream, &err).await,
                                Ok(None) => {}
                            }
                        });
                    }
                }
            });
        }
    }

    // [kart-8] drop_privileges bağlama: dinleyiciler bağlandıktan sonra kök yetkilerini yapılandırılan kullanıcıya düşür
    'yetki_dusurme: {
        let (
            priv_user,
            priv_group,
            access_log_cfg,
            error_log_cfg,
            disk_cache_cfg,
            tmp_dir_cfg,
            tls_paths,
        ) = {
            let rt = state.runtime.read().await;
            (
                rt.config.server.user.clone(),
                rt.config.server.group.clone(),
                rt.config.logging.access_log.clone(),
                rt.config.logging.error_log.clone(),
                rt.config.cache.disk_cache_dir.clone(),
                rt.config.server.tmp_dir.clone(),
                collect_tls_key_paths(&state.base_dir, &rt.config, &rt.vhosts),
            )
        };

        // Boş user/group: root değilse atla (gönderilen conf/zmax.toml böyledir); root'ta fail-closed.
        match zmax_core::plan_privilege_drop(
            &priv_user,
            &priv_group,
            zmax_core::is_running_as_root(),
        ) {
            Err(err) => {
                eprintln!("[KRİTİK GÜVENLİK HATASI] Yetki düşürme başarısız: {}", err);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Yetki düşürme başarısız (fail-closed): {}", err),
                )
                .into());
            }
            Ok(zmax_core::PrivilegeDropPlan::Skip) => {
                println!(
                    "[Bilgi] server.user/server.group boş ve süreç root değil: yetki düşürme atlandı."
                );
                break 'yetki_dusurme;
            }
            Ok(zmax_core::PrivilegeDropPlan::Drop) => {}
        }

        let log_path = state.base_dir.join("logs");
        let vhost_logs_path = log_path.join("vhosts");
        let cache_path = state.base_dir.join("cache");
        let disk_cache_path = resolve_path(&state.base_dir, &disk_cache_cfg);
        let access_log_path = resolve_path(&state.base_dir, &access_log_cfg);
        let error_log_path = resolve_path(&state.base_dir, &error_log_cfg);
        // Tahmin edilebilir ortak /tmp/zmax yerine yapılandırılabilir (server.tmp_dir), varsayılan <kök>/tmp.
        let tmp_path = if tmp_dir_cfg.trim().is_empty() {
            state.base_dir.join("tmp")
        } else {
            resolve_path(&state.base_dir, tmp_dir_cfg.trim())
        };

        for dir in [&log_path, &vhost_logs_path, &cache_path, &disk_cache_path] {
            if let Err(err) = tokio::fs::create_dir_all(dir).await {
                return Err(std::io::Error::new(
                    err.kind(),
                    format!(
                        "[KRİTİK GÜVENLİK HATASI] Yetki düşürme öncesi dizin oluşturulamadı ('{}'): {}",
                        dir.display(),
                        err
                    ),
                )
                .into());
            }
        }
        if let Err(err) = zmax_core::prepare_private_tmp_dir(&tmp_path, &priv_user) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "[KRİTİK GÜVENLİK HATASI] Geçici dizin güvenli hazırlanamadı: {}",
                    err
                ),
            )
            .into());
        }
        for log_file in [&access_log_path, &error_log_path] {
            if let Some(parent) = log_file.parent() {
                if !parent.as_os_str().is_empty() {
                    if let Err(err) = tokio::fs::create_dir_all(parent).await {
                        return Err(std::io::Error::new(
                            err.kind(),
                            format!(
                                "[KRİTİK GÜVENLİK HATASI] Günlük dizini oluşturulamadı ('{}'): {}",
                                parent.display(),
                                err
                            ),
                        )
                        .into());
                    }
                }
            }
        }

        let acme_path = state.base_dir.join("acme");
        let ssl_path = state.base_dir.join("ssl");
        for dir in [&acme_path, &ssl_path] {
            if let Err(err) = tokio::fs::create_dir_all(dir).await {
                return Err(std::io::Error::new(
                    err.kind(),
                    format!(
                        "[KRİTİK GÜVENLİK HATASI] Yetki düşürme öncesi dizin oluşturulamadı ('{}'): {}",
                        dir.display(),
                        err
                    ),
                )
                .into());
            }
        }

        let base_ownership_paths = vec![
            log_path,
            vhost_logs_path,
            cache_path,
            disk_cache_path,
            access_log_path,
            error_log_path,
            tmp_path,
            acme_path,
            ssl_path,
        ];

        #[cfg(unix)]
        let ownership_paths: Vec<PathBuf> = {
            let mut paths = base_ownership_paths;
            if !unix_api_sock.trim().is_empty() {
                paths.push(PathBuf::from(unix_api_sock.trim()));
            }
            paths
        };
        #[cfg(not(unix))]
        let ownership_paths: Vec<PathBuf> = base_ownership_paths;

        if let Err(err) = zmax_core::drop_privileges_with_paths_and_tls(
            &priv_user,
            &priv_group,
            &ownership_paths,
            &tls_paths,
        ) {
            eprintln!(
                "[KRİTİK GÜVENLİK HATASI] Yetki düşürme başarısız (root={}, user='{}', group='{}'): {}",
                zmax_core::is_running_as_root(),
                priv_user,
                priv_group,
                err
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Yetki düşürme başarısız (fail-closed): {}", err),
            )
            .into());
        }

        // Düşürme sonrası: TLS anahtar/sertifika yolları yeni kimlikle okunabiliyor mu? (kapanış doğrulaması)
        for (path, err) in zmax_core::unreadable_paths(&tls_paths) {
            let line = format!(
                "[TLS] Yetki düşürme sonrası okunamıyor ('{}'): {}. Anahtarı hizmet grubunun okuyabileceği şekilde \
                 (root:{} 0640) ayarlayın; yenilemeden sonra 'zmax --fix-tls-perms' çalıştırın.",
                path.display(),
                err,
                priv_group
            );
            eprintln!("{}", line);
            append_error_log(&state.base_dir, &line).await;
        }
    }

    #[cfg(unix)]
    {
        let state_sighup = Arc::clone(&state);
        tokio::spawn(async move {
            if let Ok(mut sighup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            {
                while sighup.recv().await.is_some() {
                    match api::reload_runtime_state(&state_sighup).await {
                        Ok(vhost_count) => {
                            state_sighup.cache.purge_all().await;
                            println!(
                                "[Yeniden Yuklendi] SIGHUP alindi -> {} sanal konak ve yapilandirma yenilendi.",
                                vhost_count
                            );
                        }
                        Err(err) => {
                            eprintln!("[SIGHUP Hata] Yeniden yukleme basarisiz: {}", err);
                            append_error_log(
                                &state_sighup.base_dir,
                                &format!("[SIGHUP Hata] {}", err),
                            )
                            .await;
                        }
                    }
                }
            }
        });

        let state_sigusr1 = Arc::clone(&state);
        tokio::spawn(async move {
            if let Ok(mut sigusr1) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
            {
                while sigusr1.recv().await.is_some() {
                    state_sigusr1.log_manager.reopen_all().await;
                    println!("[LOG] SIGUSR1 alindi -> Gunluk dosyalari yeniden acildi.");
                }
            }
        });
    }

    println!("------------------------------------------------------------");
    println!("⚡ ZMax Server tum panellerle sifir port cakismasiyla hazir!");

    zmax_runtime::wait_for_shutdown_signal().await;
    println!("[Kapatiliyor] ZMax Server zarif sekilde sonlandirildi.");
    Ok(())
}

/// Vue 3 WebAdmin Yönetim Paneli Yöneticisi (Varsayılan: 127.0.0.1:19485)
async fn handle_admin_connection<S>(
    mut socket: S,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
    is_https: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (proxy_prefix, trusted_proxies) = {
        let rt = state.runtime.read().await;
        (
            rt.config.listeners.admin.proxy_prefix.clone(),
            rt.config.listeners.admin.trusted_proxies.clone(),
        )
    };
    let mut leftover = Vec::with_capacity(4096);
    let limits = HttpReadLimits {
        max_header_bytes: 64 * 1024,
        max_body_bytes: 4 * 1024 * 1024,
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
        web_engine::write_http_response(
            &mut socket,
            403,
            "Forbidden",
            &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
            b"403 Forbidden - IP Blocked",
            None,
            req.method.eq_ignore_ascii_case("HEAD"),
            is_https,
            false,
            0,
            None,
            None,
        )
        .await?;
        return Ok(());
    }

    if handle_api_route(&mut socket, &req, &state, false).await? {
        return Ok(());
    }

    let normalized_path = normalize_panel_request_path(&req.path, &proxy_prefix);
    let req_file = if normalized_path == "/" || normalized_path == "/index.html" {
        "/index.html"
    } else {
        normalized_path.as_str()
    };

    let indexes = vec!["index.html".to_string()];
    let resolved = {
        let handler = state.admin_static_handler.read().await;
        handler
            .resolve_with_index(req_file, &indexes)
            .or_else(|| handler.resolve("/index.html"))
    };

    if let Some(file_info) = resolved {
        if let Ok(content) = tokio::fs::read(&file_info.path).await {
            let mime = if req_file.ends_with(".js") {
                "application/javascript; charset=utf-8"
            } else if req_file.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if req_file.ends_with(".html") || req_file == "/index.html" {
                "text/html; charset=utf-8"
            } else {
                file_info.mime_type
            };

            web_engine::write_http_response(
                &mut socket,
                200,
                "OK",
                &[
                    ("Content-Type".into(), mime.to_string()),
                    ("X-Content-Type-Options".into(), "nosniff".into()),
                ],
                &content,
                Some(content.len()),
                req.method.eq_ignore_ascii_case("HEAD"),
                is_https,
                false,
                0,
                None,
                None,
            )
            .await?;
            return Ok(());
        }
    }

    let not_found = b"404 Admin File Not Found";
    web_engine::write_http_response(
        &mut socket,
        404,
        "Not Found",
        &[("Content-Type".into(), "text/plain; charset=utf-8".into())],
        not_found,
        Some(not_found.len()),
        req.method.eq_ignore_ascii_case("HEAD"),
        is_https,
        false,
        0,
        None,
        None,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::reload_runtime_state;
    use crate::web_engine::{https_redirect_location, is_acme_challenge};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn run_request(state: &Arc<ServerState>, https: bool, raw: &str) -> String {
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        run_request_with_peer(state, peer, https, raw).await
    }

    async fn run_request_with_peer(
        state: &Arc<ServerState>,
        peer: SocketAddr,
        https: bool,
        raw: &str,
    ) -> String {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let st = Arc::clone(state);
        let port = if https { 443 } else { 80 };
        let task = tokio::spawn(async move {
            web_engine::handle_web_connection(server, peer, st, https, port).await
        });
        client.write_all(raw.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn run_request_raw(state: &Arc<ServerState>, https: bool, raw: &[u8]) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let st = Arc::clone(state);
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let port = if https { 443 } else { 80 };
        let task = tokio::spawn(async move {
            web_engine::handle_web_connection(server, peer, st, https, port).await
        });
        client.write_all(raw).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        out
    }

    fn test_state_with(tag: &str, force_https: bool, cfg_override: &str) -> Arc<ServerState> {
        let base = std::env::temp_dir().join(format!("zmax_bin_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("www").join("site");
        std::fs::create_dir_all(root.join(".well-known").join("acme-challenge")).unwrap();
        std::fs::create_dir_all(root.join("altklasor")).unwrap();
        std::fs::create_dir_all(base.join("modules")).unwrap();
        std::fs::create_dir_all(base.join("admin")).unwrap();
        std::fs::write(root.join("index.html"), "ANASAYFA").unwrap();
        std::fs::write(root.join("altklasor").join("index.html"), "ALT_INDEX").unwrap();
        std::fs::write(root.join("günaydın dünya.txt"), "TURKCE_DOSYA").unwrap();
        std::fs::write(root.join("range.bin"), b"0123456789ABCDEF").unwrap();
        std::fs::write(root.join(".env"), "SECRET=1234").unwrap();
        std::fs::write(
            root.join(".well-known")
                .join("acme-challenge")
                .join("tok123"),
            "tok123.anahtar",
        )
        .unwrap();
        std::fs::write(base.join("admin").join("index.html"), "ADMIN_UI").unwrap();

        let mut entry = zmax_config::VHostEntry {
            name: "site.test".into(),
            aliases: vec!["www.site.test".into()],
            document_root: "www/site".into(),
            ..Default::default()
        };
        entry.security.force_https = force_https;
        entry.php.enabled = false;
        let vh = zmax_config::LoadedVHost {
            resolved_doc_root: resolve_path(&base, &entry.document_root),
            entry,
            file_name: "site.test.toml".into(),
        };
        let mut cfg = ZMaxConfig::parse_toml(cfg_override).unwrap();
        cfg.listeners.https.port = 443;
        if cfg_override.is_empty() {
            cfg.cache.enabled = false;
        }
        let modules = LoadedModules::load_from_dir(&base.join("modules")).unwrap();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);
        Arc::new(ServerState {
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                16 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            limiter: RwLock::new(zmax_security::RateLimiter::new(u32::MAX)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::new(3, 60, 300)),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
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
                vhosts_dir: base.join("vhosts"),
                modules_dir: base.join("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                base.join("admin"),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(logger::AsyncLogManager::new(
                base.clone(),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                250,
                64,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::with_capacity(64)),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: std::sync::atomic::AtomicU64::new(0),
                cache_hits: std::sync::atomic::AtomicU64::new(0),
                cache_misses: std::sync::atomic::AtomicU64::new(0),
            },
        })
    }

    fn test_state(tag: &str) -> Arc<ServerState> {
        test_state_with(tag, true, "")
    }

    #[tokio::test]
    async fn force_https_redirects_http_but_not_acme_and_not_https() {
        let state = test_state("fh");
        let r = run_request(
            &state,
            false,
            "GET /a/b?x=1 HTTP/1.1\r\nHost: site.test\r\n\r\n",
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 301 Moved Permanently"), "{r}");
        assert!(r.contains("Location: https://site.test/a/b?x=1\r\n"), "{r}");

        let acme = run_request(
            &state,
            false,
            "GET /.well-known/acme-challenge/tok123 HTTP/1.1\r\nHost: site.test\r\n\r\n",
        )
        .await;
        assert!(acme.starts_with("HTTP/1.1 200 OK"), "{acme}");
        assert!(acme.ends_with("tok123.anahtar"), "{acme}");

        let tls = run_request(&state, true, "GET / HTTP/1.1\r\nHost: site.test\r\n\r\n").await;
        assert!(
            tls.starts_with("HTTP/1.1 200 OK") && tls.ends_with("ANASAYFA"),
            "{tls}"
        );
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn static_utf8_subdir_range_etag_head_and_hidden_block() {
        let state = test_state_with("static", false, "");
        // 1. Türkçe ve boşluklu dosya adı (%-decode)
        let r_tr = run_request(
            &state,
            false,
            "GET /g%C3%BCnayd%C4%B1n%20d%C3%BCnya.txt HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r_tr.starts_with("HTTP/1.1 200 OK"), "{r_tr}");
        assert!(r_tr.ends_with("TURKCE_DOSYA"), "{r_tr}");

        // 2. Alt dizin index çözümlemesi
        let r_dir = run_request(
            &state,
            false,
            "GET /altklasor/ HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_dir.starts_with("HTTP/1.1 200 OK") && r_dir.ends_with("ALT_INDEX"),
            "{r_dir}"
        );

        // 3. ETag çıkar + If-None-Match 304 doğrulaması
        let etag_line = r_dir
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("etag:"))
            .unwrap()
            .split_once(':')
            .unwrap()
            .1
            .trim();
        let r_304 = run_request(
            &state,
            false,
            &format!(
                "GET /altklasor/ HTTP/1.1\r\nHost: site.test\r\nIf-None-Match: {}\r\nConnection: close\r\n\r\n",
                etag_line
            ),
        )
        .await;
        assert!(r_304.starts_with("HTTP/1.1 304 Not Modified"), "{r_304}");

        // 4. Byte Range 206 ve taşan 416
        let r_206 = run_request(
            &state,
            false,
            "GET /range.bin HTTP/1.1\r\nHost: site.test\r\nRange: bytes=2-5\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r_206.starts_with("HTTP/1.1 206 Partial Content"), "{r_206}");
        assert!(r_206.contains("Content-Range: bytes 2-5/16\r\n"), "{r_206}");
        assert!(r_206.ends_with("2345"), "{r_206}");

        let r_416 = run_request(
            &state,
            false,
            "GET /range.bin HTTP/1.1\r\nHost: site.test\r\nRange: bytes=999-1005\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_416.starts_with("HTTP/1.1 416 Range Not Satisfiable"),
            "{r_416}"
        );

        // 5. HEAD gövdesiz ama Content-Length doğru
        let r_head = run_request(
            &state,
            false,
            "HEAD /range.bin HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r_head.starts_with("HTTP/1.1 200 OK"), "{r_head}");
        assert!(r_head.contains("Content-Length: 16\r\n"), "{r_head}");
        assert!(r_head.ends_with("\r\n\r\n"), "{r_head}");

        // 6. Gizli .env dosyası 403 Forbidden
        let r_env = run_request(
            &state,
            false,
            "GET /.env HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r_env.starts_with("HTTP/1.1 403 Forbidden"), "{r_env}");
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn keepalive_pipelining_gzip_and_413_payload_limit() {
        let state = test_state_with("ka", false, "[security]\nmax_body_size_mb = 1\n");
        let big_html = "<div>Merhaba ZMax GZIP Testi</div>".repeat(40);
        std::fs::write(
            state.base_dir.join("www").join("site").join("big.html"),
            &big_html,
        )
        .unwrap();

        // 1. Tek bağlantıda 2 Keep-Alive isteği + 2. istekte gzip
        let two_reqs = concat!(
            "GET /index.html HTTP/1.1\r\nHost: site.test\r\n\r\n",
            "GET /big.html HTTP/1.1\r\nHost: site.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
        );
        let resp_bytes = run_request_raw(&state, false, two_reqs.as_bytes()).await;
        let resp_lossy = String::from_utf8_lossy(&resp_bytes);
        assert!(
            resp_lossy.contains("Connection: keep-alive"),
            "{resp_lossy}"
        );
        assert!(
            resp_lossy.contains("Content-Encoding: gzip"),
            "{resp_lossy}"
        );
        assert!(resp_lossy.contains("ANASAYFA"), "{resp_lossy}");

        // 2. 1 MiB aşan Content-Length -> sessiz kesme yok, 413 Payload Too Large!
        let oversized =
            "POST /index.html HTTP/1.1\r\nHost: site.test\r\nContent-Length: 2097152\r\n\r\n";
        let r_413 = run_request(&state, false, oversized).await;
        assert!(
            r_413.starts_with("HTTP/1.1 413 Payload Too Large"),
            "{r_413}"
        );
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn wp_bruteforce_ban_and_non_loopback_admin_auth() {
        let state = test_state_with(
            "sec",
            false,
            "[listeners.admin]\naddress = \"0.0.0.0\"\nrequire_token = false\ntoken = \"\"\n",
        );
        // Loopback dışı admin bind -> otomatik token zorunlu kılınmış olmalı!
        {
            let rt = state.runtime.read().await;
            assert!(rt.auth.admin_require_token);
            assert!(!rt.auth.admin_token.is_empty());
        }

        // Yetkisiz admin API isteği 401 dönmeli
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let st = Arc::clone(&state);
        let peer: SocketAddr = "192.168.1.50:40000".parse().unwrap();
        let t = tokio::spawn(async move { handle_admin_connection(server, peer, st, false).await });
        client
            .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        t.await.unwrap().unwrap();
        let admin_resp = String::from_utf8_lossy(&out);
        assert!(
            admin_resp.starts_with("HTTP/1.1 401 Unauthorized"),
            "{admin_resp}"
        );

        // WP Brute force 4. denemede 403 ve ban_manager kaydı
        for i in 0..4 {
            let r = run_request(
                &state,
                false,
                "POST /wp-login.php HTTP/1.1\r\nHost: site.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
            if i == 3 {
                assert!(r.starts_with("HTTP/1.1 403 Forbidden"), "{r}");
            }
        }
        assert!(!state.ban_manager.list_banned().is_empty());
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[test]
    fn redirect_keeps_host_path_and_query() {
        assert_eq!(
            https_redirect_location("site.com", "/a/b.php", "x=1&y=2", 443).as_deref(),
            Some("https://site.com/a/b.php?x=1&y=2")
        );
        assert_eq!(
            https_redirect_location("site.com:80", "/", "", 443).as_deref(),
            Some("https://site.com/")
        );
        assert_eq!(
            https_redirect_location("site.com:19480", "/x", "", 19483).as_deref(),
            Some("https://site.com:19483/x")
        );
        assert_eq!(
            https_redirect_location("[::1]:80", "/x", "", 443).as_deref(),
            Some("https://[::1]/x")
        );
    }

    #[test]
    fn redirect_rejects_bad_host() {
        assert!(https_redirect_location("", "/", "", 443).is_none());
        assert!(https_redirect_location("evil.com/@x", "/", "", 443).is_none());
        assert!(https_redirect_location("a b", "/", "", 443).is_none());
    }

    #[test]
    fn acme_challenge_path_is_exempt() {
        assert!(is_acme_challenge("/.well-known/acme-challenge/tokenABC"));
        assert!(!is_acme_challenge("/.well-known/security.txt"));
        assert!(!is_acme_challenge("/index.html"));
    }

    #[tokio::test]
    async fn wordpress_htaccess_permalink_and_fastcgi_headers() {
        use std::collections::HashMap;
        let state = test_state_with("wpfcgi", false, "");
        let doc_root = state.base_dir.join("www").join("site");
        std::fs::write(doc_root.join("index.php"), "<?php echo 'wp';").unwrap();
        std::fs::write(
            doc_root.join(".htaccess"),
            "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n",
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fcgi_addr = listener.local_addr().unwrap();

        // Sahte FastCGI sunucusu: gelen FCGI_PARAMS & FCGI_STDIN'i okuyup başlıklarla yanıtlar
        let mock_fcgi = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = sock.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                req_buf.extend_from_slice(&tmp[..n]);
                // Boş FCGI_STDIN kaydını görünce dur (type=5, content_len=0)
                if req_buf
                    .windows(8)
                    .any(|w| w[0] == 1 && w[1] == 5 && w[4] == 0 && w[5] == 0)
                {
                    break;
                }
            }

            let mut params_raw = Vec::new();
            let mut stdin_raw = Vec::new();
            let mut p = req_buf.as_slice();
            while p.len() >= 8 {
                let rtype = p[1];
                let clen = u16::from_be_bytes([p[4], p[5]]) as usize;
                let plen = p[6] as usize;
                p = &p[8..];
                let data = &p[..clen];
                if rtype == 4 {
                    params_raw.extend_from_slice(data);
                } else if rtype == 5 {
                    stdin_raw.extend_from_slice(data);
                }
                p = &p[clen + plen..];
            }

            // FCGI_PARAMS çözümle
            let mut decoded_params: HashMap<String, String> = HashMap::new();
            let mut q = params_raw.as_slice();
            let read_len = |s: &mut &[u8]| -> usize {
                let b0 = s[0];
                if (b0 & 0x80) == 0 {
                    *s = &s[1..];
                    b0 as usize
                } else {
                    let val = u32::from_be_bytes([s[0] & 0x7f, s[1], s[2], s[3]]) as usize;
                    *s = &s[4..];
                    val
                }
            };
            while !q.is_empty() {
                let kl = read_len(&mut q);
                let vl = read_len(&mut q);
                let k = String::from_utf8_lossy(&q[..kl]).into_owned();
                let v = String::from_utf8_lossy(&q[kl..kl + vl]).into_owned();
                q = &q[kl + vl..];
                decoded_params.insert(k, v);
            }

            let summary = format!(
                "Status: 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; HttpOnly\r\n\r\nSCRIPT={}|URI={}|COOKIE={}|CT={}|HTTPS={}|SCHEME={}|BODY={}",
                decoded_params.get("SCRIPT_NAME").cloned().unwrap_or_default(),
                decoded_params.get("REQUEST_URI").cloned().unwrap_or_default(),
                decoded_params.get("HTTP_COOKIE").cloned().unwrap_or_default(),
                decoded_params.get("CONTENT_TYPE").cloned().unwrap_or_default(),
                decoded_params.get("HTTPS").cloned().unwrap_or_default(),
                decoded_params.get("REQUEST_SCHEME").cloned().unwrap_or_default(),
                String::from_utf8_lossy(&stdin_raw)
            );

            // FCGI_STDOUT + empty STDOUT + FCGI_END_REQUEST
            let mut out = Vec::new();
            let payload = summary.as_bytes();
            let len_be = (payload.len() as u16).to_be_bytes();
            out.extend_from_slice(&[1, 6, 0, 1, len_be[0], len_be[1], 0, 0]);
            out.extend_from_slice(payload);
            out.extend_from_slice(&[1, 6, 0, 1, 0, 0, 0, 0]);
            out.extend_from_slice(&[1, 3, 0, 1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            sock.write_all(&out).await.unwrap();
        });

        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.php.enabled = true;
            rt.vhosts[0].entry.php.upstream = fcgi_addr.to_string();
        }

        let resp = run_request(
            &state,
            true,
            "POST /merhaba-yazi/?s=ara HTTP/1.1\r\nHost: site.test\r\nCookie: sid=xyz\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\nConnection: close\r\n\r\na=1&b=2",
        )
        .await;
        mock_fcgi.await.unwrap();

        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("Set-Cookie: a=1; Path=/"), "{resp}");
        assert!(resp.contains("Set-Cookie: b=2; HttpOnly"), "{resp}");
        assert!(
            resp.contains("SCRIPT=/index.php|URI=/merhaba-yazi/?s=ara|COOKIE=sid=xyz|CT=application/x-www-form-urlencoded|HTTPS=on|SCHEME=https|BODY=a=1&b=2"),
            "{resp}"
        );
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn reverse_proxy_routes_backend_http() {
        let state = test_state_with("proxy", false, "");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = listener.local_addr().unwrap();

        let backend = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let n = sock.read(&mut buf).await.unwrap();
            let req_txt = String::from_utf8_lossy(&buf[..n]);
            assert!(req_txt.contains("X-Forwarded-For: 127.0.0.1"), "{req_txt}");
            assert!(req_txt.contains("X-Forwarded-Proto: http"), "{req_txt}");
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nPROXY_BODY",
            )
            .await
            .unwrap();
        });

        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.proxy.enabled = true;
            rt.vhosts[0].entry.proxy.upstream = up_addr.to_string();
            rt.vhosts[0].entry.proxy.path_prefix = "/api-node".into();
        }

        let resp = run_request(
            &state,
            false,
            "GET /api-node/ping HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        backend.await.unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("PROXY_BODY"),
            "{resp}"
        );
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn api_modules_bans_unban_logs_and_tag_purge() {
        let state = test_state_with("apiv1", false, "");
        std::fs::write(
            state.base_dir.join("modules").join("mod_gzip.toml"),
            "[module]\nname = \"mod_gzip\"\nversion = \"1.0.0\"\ncategory = \"Performans\"\nenabled = true\n",
        )
        .unwrap();
        reload_runtime_state(&state).await.unwrap();

        state.ban_manager.ban(
            "10.20.30.40".parse().unwrap(),
            "WordPress brute-force (11 deneme)",
            300,
        );
        state.record_access_log(
            "127.0.0.1",
            "GET",
            "/test-log",
            200,
            Duration::from_millis(2),
        );
        state
            .cache
            .set_with_ttl(
                "k1".into(),
                zmax_cache::CachedResponse {
                    status: 200,
                    content_type: "text/plain".into(),
                    body: bytes::Bytes::from_static(b"hi"),
                    tags: vec!["etiket1".into()],
                },
                60,
            )
            .await;

        let call_api = |method: &str, path: &str, body: &str| {
            let st = Arc::clone(&state);
            let m = method.to_string();
            let p = path.to_string();
            let b = body.to_string();
            async move {
                let (mut client, mut server) = tokio::io::duplex(64 * 1024);
                let parsed = api::ParsedHttpRequest {
                    method: m,
                    path: p,
                    query: String::new(),
                    version: 1,
                    host: "127.0.0.1".into(),
                    headers: vec![],
                    body: b.into_bytes(),
                    keep_alive: false,
                };
                let t = tokio::spawn(async move {
                    let _ = handle_api_route(&mut server, &parsed, &st, true).await;
                });
                let mut out = Vec::new();
                client.read_to_end(&mut out).await.unwrap();
                t.await.unwrap();
                String::from_utf8_lossy(&out).into_owned()
            }
        };

        let mods = call_api("GET", "/api/v1/modules", "").await;
        assert!(
            mods.contains("\"mod_gzip\"") && mods.contains("\"categoryKey\":\"perf\""),
            "{mods}"
        );

        let bans = call_api("GET", "/api/v1/security/bans", "").await;
        assert!(
            bans.contains("10.20.30.40") && bans.contains("reason_bruteforce"),
            "{bans}"
        );

        let unban = call_api("POST", "/api/v1/security/unban", r#"{"ip":"10.20.30.40"}"#).await;
        assert!(unban.contains("\"unbanned\":true"), "{unban}");
        assert!(!state.ban_manager.is_banned("10.20.30.40".parse().unwrap()));

        let logs = call_api("GET", "/api/v1/logs", "").await;
        assert!(logs.contains("/test-log"), "{logs}");

        let purge = call_api("POST", "/api/v1/cache/purge", r#"{"tag":"etiket1"}"#).await;
        assert!(
            purge.contains("\"scope\":\"tag\"") && purge.contains("\"purged\":1"),
            "{purge}"
        );
        assert!(state.cache.get("k1").await.is_none());

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn dual_listener_same_port_is_rejected_without_reuse_port() {
        let first = create_reuse_listener("127.0.0.1:0".parse().unwrap(), 128, false).unwrap();
        let port = first.local_addr().unwrap().port();
        let second =
            create_reuse_listener(format!("127.0.0.1:{}", port).parse().unwrap(), 128, false);
        assert!(
            second.is_err(),
            "reuse_port=false iken ayni porta ikinci dinleyici baglanamamali"
        );
        drop(first);
    }

    async fn run_request_from_peer(state: &Arc<ServerState>, peer_str: &str, raw: &str) -> String {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let st = Arc::clone(state);
        let peer: SocketAddr = peer_str.parse().unwrap();
        let task = tokio::spawn(async move {
            web_engine::handle_web_connection(server, peer, st, false, 80).await
        });
        client.write_all(raw.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    fn decode_fcgi_params_map(bytes: &[u8]) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        let mut i = 0usize;
        while i < bytes.len() {
            let name_len = if bytes[i] & 0x80 == 0 {
                let l = bytes[i] as usize;
                i += 1;
                l
            } else if i + 4 <= bytes.len() {
                let l =
                    u32::from_be_bytes([bytes[i] & 0x7f, bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                        as usize;
                i += 4;
                l
            } else {
                break;
            };
            let val_len = if i < bytes.len() && bytes[i] & 0x80 == 0 {
                let l = bytes[i] as usize;
                i += 1;
                l
            } else if i + 4 <= bytes.len() {
                let l =
                    u32::from_be_bytes([bytes[i] & 0x7f, bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                        as usize;
                i += 4;
                l
            } else {
                break;
            };
            if i + name_len + val_len > bytes.len() {
                break;
            }
            let name = String::from_utf8_lossy(&bytes[i..i + name_len]).into_owned();
            let val =
                String::from_utf8_lossy(&bytes[i + name_len..i + name_len + val_len]).into_owned();
            map.insert(name, val);
            i += name_len + val_len;
        }
        map
    }

    fn build_fcgi_record(rec_type: u8, req_id: u16, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u16;
        let mut out = Vec::with_capacity(8 + payload.len());
        out.push(1);
        out.push(rec_type);
        out.extend_from_slice(&req_id.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
        out.push(0);
        out.push(0);
        out.extend_from_slice(payload);
        out
    }

    #[tokio::test]
    async fn ip_acl_cidr_allow_and_deny_enforced() {
        let cfg_toml = "[security]\ndeny_ips = [\"203.0.113.0/24\"]\n[cache]\nenabled = false\n";
        let state = test_state_with("ip_acl", false, cfg_toml);
        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.security.allow_ips = vec!["10.10.0.0/16".into()];
        }

        let r_ok = run_request_from_peer(
            &state,
            "10.10.5.5:41000",
            "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_ok.starts_with("HTTP/1.1 200 OK") && r_ok.contains("ANASAYFA"),
            "{r_ok}"
        );

        let r_non_allow = run_request_from_peer(
            &state,
            "192.168.1.9:41001",
            "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_non_allow.contains("403 Forbidden") && r_non_allow.contains("IP Access Denied"),
            "{r_non_allow}"
        );

        let r_global_deny = run_request_from_peer(
            &state,
            "203.0.113.77:41002",
            "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r_global_deny.contains("403 Forbidden"), "{r_global_deny}");

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn hotlink_protection_blocks_foreign_referer_and_allows_same_host() {
        let state = test_state_with("hotlink", false, "");
        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.security.hotlink_protection = true;
            std::fs::write(rt.vhosts[0].resolved_doc_root.join("logo.png"), b"PNGDATA").unwrap();
        }

        let blocked = run_request(
            &state,
            false,
            "GET /logo.png HTTP/1.1\r\nHost: site.test\r\nReferer: https://spammer.example/x.html\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            blocked.starts_with("HTTP/1.1 403 Forbidden") && blocked.contains("Hotlink Protection"),
            "{blocked}"
        );

        let allowed_same = run_request(
            &state,
            false,
            "GET /logo.png HTTP/1.1\r\nHost: site.test\r\nReferer: https://www.site.test/anasayfa\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            allowed_same.starts_with("HTTP/1.1 200 OK") && allowed_same.contains("PNGDATA"),
            "{allowed_same}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn webp_and_avif_accept_negotiation_sets_vary_accept() {
        let state = test_state_with("img_neg", false, "[cache]\nenabled = false\n");
        std::fs::write(
            state.base_dir.join("modules").join("mod_static.toml"),
            "[module]\nname = \"mod_static\"\nenabled = true\n\n[settings]\nauto_webp = true\nauto_avif = true\n",
        )
        .unwrap();
        {
            let mut rt = state.runtime.write().await;
            let root = &rt.vhosts[0].resolved_doc_root;
            std::fs::write(root.join("foto.jpg"), b"JPEG_RAW").unwrap();
            std::fs::write(root.join("foto.webp"), b"WEBP_OPT").unwrap();
            std::fs::write(root.join("foto.avif"), b"AVIF_OPT").unwrap();
            rt.modules = LoadedModules::load_from_dir(&rt.modules_dir).unwrap();
            rt.policies = compile_policies(&rt.config, &rt.modules);
        }

        let avif = run_request(
            &state,
            false,
            "GET /foto.jpg HTTP/1.1\r\nHost: site.test\r\nAccept: image/avif,image/webp,*/*\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(avif.starts_with("HTTP/1.1 200 OK"), "{avif}");
        assert!(avif.contains("Content-Type: image/avif"), "{avif}");
        assert!(avif.contains("Vary:") && avif.contains("Accept"), "{avif}");
        assert!(avif.ends_with("AVIF_OPT"), "{avif}");

        let webp = run_request(
            &state,
            false,
            "GET /foto.jpg HTTP/1.1\r\nHost: site.test\r\nAccept: image/webp,*/*\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            webp.contains("Content-Type: image/webp") && webp.ends_with("WEBP_OPT"),
            "{webp}"
        );

        let jpeg = run_request(
            &state,
            false,
            "GET /foto.jpg HTTP/1.1\r\nHost: site.test\r\nAccept: image/png,*/*\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            jpeg.contains("Content-Type: image/jpeg") && jpeg.ends_with("JPEG_RAW"),
            "{jpeg}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn php_path_info_and_translated_resolved_in_web_engine() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fcgi_addr = listener.local_addr().unwrap().to_string();

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let mut param_bytes = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
                let mut offset = 0usize;
                let mut seen_stdin_end = false;
                while offset + 8 <= raw.len() {
                    let rec_type = raw[offset + 1];
                    let c_len = u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]) as usize;
                    let pad = raw[offset + 6] as usize;
                    let total = 8 + c_len + pad;
                    if offset + total > raw.len() {
                        break;
                    }
                    let payload = &raw[offset + 8..offset + 8 + c_len];
                    if rec_type == 4 {
                        param_bytes.extend_from_slice(payload);
                    } else if rec_type == 5 && c_len == 0 {
                        seen_stdin_end = true;
                    }
                    offset += total;
                }
                raw.drain(..offset);
                if seen_stdin_end {
                    break;
                }
            }
            let params = decode_fcgi_params_map(&param_bytes);
            let body = format!(
                "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nPI={}|PT={}|PS={}",
                params.get("PATH_INFO").cloned().unwrap_or_default(),
                params.get("PATH_TRANSLATED").cloned().unwrap_or_default(),
                params.get("PHP_SELF").cloned().unwrap_or_default(),
            );
            let mut resp = build_fcgi_record(6, 1, body.as_bytes());
            resp.extend_from_slice(&build_fcgi_record(6, 1, &[]));
            resp.extend_from_slice(&build_fcgi_record(3, 1, &[0, 0, 0, 0, 0, 0, 0, 0]));
            sock.write_all(&resp).await.unwrap();
            let _ = sock.shutdown().await;
        });

        let state = test_state_with("php_pi", false, "[cache]\nenabled = false\n");
        {
            let mut rt = state.runtime.write().await;
            std::fs::write(rt.vhosts[0].resolved_doc_root.join("index.php"), "<?php").unwrap();
            rt.vhosts[0].entry.php.enabled = true;
            rt.vhosts[0].entry.php.upstream = fcgi_addr;
            rt.policies.fastcgi.enabled = true;
        }

        let resp = run_request(
            &state,
            false,
            "GET /index.php/urun/42?renk=mavi HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        server_task.await.unwrap();

        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(resp.contains("PI=/urun/42|"), "{resp}");
        assert!(resp.contains("|PS=/index.php/urun/42"), "{resp}");
        assert!(
            resp.contains("urun\\42|") || resp.contains("urun/42|"),
            "PATH_TRANSLATED bekleneni icermeli: {resp}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn cache_swr_serves_stale_and_revalidates() {
        let cfg =
            "[cache]\nenabled = true\ndefault_ttl_seconds = 60\nstale_while_revalidate_sec = 30\n";
        let state = test_state_with("swr_static", false, cfg);
        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.cache.enabled = true;
        }

        let key = zmax_cache::build_cache_key(
            "site.test",
            false,
            "GET",
            "/index.html",
            "",
            Some("identity"),
        );
        state
            .cache
            .set_with_ttl_and_stale(
                key.clone(),
                zmax_cache::CachedResponse {
                    status: 200,
                    content_type: "text/html; charset=utf-8".into(),
                    body: bytes::Bytes::from_static(b"BAYAT_YANIT"),
                    tags: vec!["site.test".into()],
                },
                0,
                30,
            )
            .await;

        let stale_resp = run_request(
            &state,
            false,
            "GET /index.html HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(stale_resp.contains("X-Cache: STALE"), "{stale_resp}");
        assert!(stale_resp.contains("BAYAT_YANIT"), "{stale_resp}");

        // Sabit sleep yerine arka plan yenileme liderinin StampedeGuard (Notify) sinyaliyle bekle
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if matches!(
                state.cache.get_with_stale(&key).await,
                zmax_cache::CacheLookup::Fresh(_)
            ) {
                break;
            }
            match state.cache.try_acquire_fill(&key) {
                zmax_cache::StampedeSlot::Follower(notify) => {
                    let notified = notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if matches!(
                        state.cache.get_with_stale(&key).await,
                        zmax_cache::CacheLookup::Fresh(_)
                    ) {
                        break;
                    }
                    tokio::time::timeout_at(deadline, notified)
                        .await
                        .expect("SWR arka plan yenilemesi zaman asimina ugradi");
                }
                zmax_cache::StampedeSlot::Leader(guard) => {
                    drop(guard);
                    assert!(
                        matches!(
                            state.cache.get_with_stale(&key).await,
                            zmax_cache::CacheLookup::Fresh(_)
                        ),
                        "SWR yenileme lideri tamamlandigi halde onbellek taze olmaliydi"
                    );
                    break;
                }
            }
        }

        let fresh_resp = run_request(
            &state,
            false,
            "GET /index.html HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(fresh_resp.contains("X-Cache: HIT"), "{fresh_resp}");
        assert!(fresh_resp.contains("ANASAYFA"), "{fresh_resp}");

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn reverse_proxy_uses_upstream_pool_for_keepalive() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = listener.local_addr().unwrap().to_string();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_srv = Arc::clone(&accepts);

        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            accepts_srv.fetch_add(1, AtomicOrdering::SeqCst);
            let mut buf = [0u8; 4096];
            for _ in 0..2 {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                sock.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nPONG",
                )
                .await
                .unwrap();
                sock.flush().await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        });

        let state = test_state_with("proxy_pool", false, "[cache]\nenabled = false\n");
        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.proxy.enabled = true;
            rt.vhosts[0].entry.proxy.upstream = up_addr.clone();
            rt.vhosts[0].entry.proxy.path_prefix = "/api".into();
            rt.policies.proxy.enabled = true;
        }

        let r1 = run_request(
            &state,
            false,
            "GET /api/ping HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r1.starts_with("HTTP/1.1 200 OK") && r1.ends_with("PONG"),
            "{r1}"
        );
        assert_eq!(state.upstream_pool.idle_count(&up_addr), 1);

        let r2 = run_request(
            &state,
            false,
            "GET /api/ping HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r2.starts_with("HTTP/1.1 200 OK") && r2.ends_with("PONG"),
            "{r2}"
        );
        srv.await.unwrap();

        assert_eq!(accepts.load(AtomicOrdering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn panel_admin_proxy_prefix_and_tls_validation() {
        let cfg = "[listeners.admin]\nproxy_prefix = \"/zmax-panel\"\ntrusted_proxies = [\"127.0.0.1\"]\n";
        let state = test_state_with("admin_prefix", false, cfg);
        let peer: SocketAddr = "127.0.0.1:52000".parse().unwrap();

        let (mut client_ui, server_ui) = tokio::io::duplex(64 * 1024);
        let st_ui = Arc::clone(&state);
        let t_ui =
            tokio::spawn(
                async move { handle_admin_connection(server_ui, peer, st_ui, false).await },
            );
        client_ui
            .write_all(b"GET /zmax-panel/index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        client_ui.shutdown().await.unwrap();
        let mut out_ui = Vec::new();
        client_ui.read_to_end(&mut out_ui).await.unwrap();
        t_ui.await.unwrap().unwrap();
        let ui_str = String::from_utf8_lossy(&out_ui);
        assert!(
            ui_str.starts_with("HTTP/1.1 200 OK") && ui_str.contains("ADMIN_UI"),
            "{ui_str}"
        );

        let (mut client_api, server_api) = tokio::io::duplex(64 * 1024);
        let st_api = Arc::clone(&state);
        let t_api =
            tokio::spawn(
                async move { handle_admin_connection(server_api, peer, st_api, true).await },
            );
        client_api
            .write_all(b"GET /zmax-panel/api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        client_api.shutdown().await.unwrap();
        let mut out_api = Vec::new();
        client_api.read_to_end(&mut out_api).await.unwrap();
        t_api.await.unwrap().unwrap();
        let api_str = String::from_utf8_lossy(&out_api);
        assert!(
            api_str.starts_with("HTTP/1.1 200 OK") && api_str.contains("\"status\":\"ok\""),
            "{api_str}"
        );

        let bad_tls = zmax_tls::build_single_cert_acceptor(
            &state.base_dir.join("yok.crt"),
            &state.base_dir.join("yok.key"),
        );
        assert!(bad_tls.is_err());

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn api_and_admin_allow_loopback_unban_even_when_loopback_banned_but_block_remote() {
        let state = test_state_with("ban_ctrl", false, "");
        state
            .ban_manager
            .ban("127.0.0.1".parse().unwrap(), "wp-login test", 300);
        state
            .ban_manager
            .ban("198.51.100.77".parse().unwrap(), "wp-login remote", 300);

        // Yerel loopback API çağrısı ban kaldırmak için erişebilmeli
        let (mut c_local, s_local) = tokio::io::duplex(64 * 1024);
        let st_local = Arc::clone(&state);
        let local_peer: SocketAddr = "127.0.0.1:53000".parse().unwrap();
        let t_local =
            tokio::spawn(async move { handle_api_connection(s_local, local_peer, st_local).await });
        c_local
            .write_all(b"GET /api/v1/security/bans HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        c_local.shutdown().await.unwrap();
        let mut out_local = Vec::new();
        c_local.read_to_end(&mut out_local).await.unwrap();
        t_local.await.unwrap().unwrap();
        let local_str = String::from_utf8_lossy(&out_local);
        assert!(
            local_str.starts_with("HTTP/1.1 200 OK") && local_str.contains("127.0.0.1"),
            "{local_str}"
        );

        // Uzak banlı IP ise API ve WebAdmin dinleyicilerinden 403 almalı
        let (mut c_remote, s_remote) = tokio::io::duplex(64 * 1024);
        let st_remote = Arc::clone(&state);
        let remote_peer: SocketAddr = "198.51.100.77:53001".parse().unwrap();
        let t_remote = tokio::spawn(async move {
            handle_admin_connection(s_remote, remote_peer, st_remote, false).await
        });
        c_remote
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        c_remote.shutdown().await.unwrap();
        let mut out_remote = Vec::new();
        c_remote.read_to_end(&mut out_remote).await.unwrap();
        t_remote.await.unwrap().unwrap();
        let remote_str = String::from_utf8_lossy(&out_remote);
        assert!(
            remote_str.starts_with("HTTP/1.1 403 Forbidden"),
            "{remote_str}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    fn test_state_two_vhosts(tag: &str) -> Arc<ServerState> {
        let base =
            std::env::temp_dir().join(format!("zmax_bin_2vh_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root_a = base.join("www").join("vhost-a");
        let root_b = base.join("www").join("vhost-b");
        let err_a = root_a.join("err");
        std::fs::create_dir_all(&err_a).unwrap();
        std::fs::create_dir_all(&root_b).unwrap();
        std::fs::create_dir_all(base.join("modules")).unwrap();
        std::fs::create_dir_all(base.join("admin")).unwrap();
        std::fs::create_dir_all(base.join("logs")).unwrap();

        std::fs::write(root_a.join("index.html"), "VHOST_A_BODY_12345").unwrap();
        std::fs::write(err_a.join("404.html"), "CUSTOM_404_PAGE_FOR_VHOST_A").unwrap();
        std::fs::write(root_b.join("index.html"), "VHOST_B_BODY_67890").unwrap();
        std::fs::write(
            base.join("modules").join("mod_security.toml"),
            "[module]\nname = \"mod_security\"\nenabled = true\n\n[settings]\nsql_injection_inspection = true\npath_traversal_shield = true\n",
        )
        .unwrap();
        std::fs::write(
            base.join("modules").join("mod_coreruleset.toml"),
            "[module]\nname = \"mod_coreruleset\"\nenabled = true\n\n[settings]\nblock_sql_injection = true\n",
        )
        .unwrap();

        let mut entry_a = zmax_config::VHostEntry {
            name: "vhost-a.test".into(),
            aliases: vec!["www.vhost-a.test".into()],
            document_root: "www/vhost-a".into(),
            ..Default::default()
        };
        entry_a.logging.enabled = true;
        entry_a.logging.access_log = "logs/vhost-a.access.log".into();
        entry_a.logging.error_log = "logs/vhost-a.error.log".into();
        entry_a.security.waf_enabled = Some(true);
        entry_a.security.waf_exclude_paths = vec!["/muaf-yol".into()];
        entry_a.error_docs.dir = "err".into();
        entry_a.error_docs.pages.insert(404, "404.html".into());
        entry_a.php.enabled = false;

        let mut entry_b = zmax_config::VHostEntry {
            name: "vhost-b.test".into(),
            aliases: vec!["www.vhost-b.test".into()],
            document_root: "www/vhost-b".into(),
            ..Default::default()
        };
        entry_b.logging.enabled = true;
        entry_b.logging.access_log = "logs/vhost-b.access.log".into();
        entry_b.logging.error_log = "logs/vhost-b.error.log".into();
        entry_b.security.waf_enabled = Some(false);
        entry_b.php.enabled = false;

        let vh_a = zmax_config::LoadedVHost {
            resolved_doc_root: resolve_path(&base, &entry_a.document_root),
            entry: entry_a,
            file_name: "vhost-a.test.toml".into(),
        };
        let vh_b = zmax_config::LoadedVHost {
            resolved_doc_root: resolve_path(&base, &entry_b.document_root),
            entry: entry_b,
            file_name: "vhost-b.test.toml".into(),
        };

        let mut cfg = ZMaxConfig::parse_toml("").unwrap();
        cfg.cache.enabled = false;
        let modules = LoadedModules::load_from_dir(&base.join("modules")).unwrap();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);

        Arc::new(ServerState {
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                16 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            limiter: RwLock::new(zmax_security::RateLimiter::new(u32::MAX)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::new(3, 60, 300)),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
            buffer_pool: Arc::new(zmax_pool::BufferPool::default()),
            upstream_pool: Arc::new(zmax_pool::UpstreamSocketPool::default()),
            runtime: RwLock::new(RuntimeState {
                config: cfg,
                vhosts: vec![vh_a, vh_b],
                modules,
                policies,
                redis_client: None,
                auth,
                conf_path: base.join("zmax.toml"),
                vhosts_dir: base.join("vhosts"),
                modules_dir: base.join("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                base.join("admin"),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(logger::AsyncLogManager::new(
                base.clone(),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                10,
                16,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::with_capacity(64)),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: std::sync::atomic::AtomicU64::new(0),
                cache_hits: std::sync::atomic::AtomicU64::new(0),
                cache_misses: std::sync::atomic::AtomicU64::new(0),
            },
        })
    }

    #[tokio::test]
    async fn two_vhosts_isolated_logging_and_reopen_writes_to_new_file() {
        let state = test_state_two_vhosts("log_iso");
        let r1 = run_request(
            &state,
            false,
            "GET / HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n",
        )
        .await;
        assert!(
            r1.starts_with("HTTP/1.1 200 OK") && r1.contains("VHOST_A_BODY_12345"),
            "{r1}"
        );

        let r2 = run_request(
            &state,
            false,
            "GET / HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n",
        )
        .await;
        assert!(
            r2.starts_with("HTTP/1.1 200 OK") && r2.contains("VHOST_B_BODY_67890"),
            "{r2}"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        state.log_manager.flush().await;

        let log_a = state.base_dir.join("logs").join("vhost-a.access.log");
        let log_b = state.base_dir.join("logs").join("vhost-b.access.log");
        assert!(log_a.is_file(), "vhost-a log dosyasi olusmali");
        assert!(log_b.is_file(), "vhost-b log dosyasi olusmali");

        let content_a = std::fs::read_to_string(&log_a).unwrap();
        let content_b = std::fs::read_to_string(&log_b).unwrap();

        let line_a = content_a.lines().next().unwrap_or("");
        assert!(
            line_a.contains("GET / HTTP/1.1"),
            "Istek satiri bulunmali: {line_a}"
        );
        assert!(
            line_a.contains("[") && line_a.contains("]"),
            "Zaman damgasi olmali: {line_a}"
        );
        let parts_a: Vec<&str> = line_a.split_whitespace().collect();
        let status_idx_a = parts_a
            .iter()
            .position(|&p| p == "200")
            .expect("200 status kodu bulunmali");
        let bytes_sent_a: usize = parts_a[status_idx_a + 1]
            .parse()
            .expect("Sayisal bayt degeri olmali");
        assert_eq!(
            bytes_sent_a, 18,
            "vhost-a govde uzunlugu (VHOST_A_BODY_12345 = 18 bayt) olmali: {line_a}"
        );
        assert!(!line_a.contains(" 200 - "), "'-' bayt reddedilmeli");
        assert!(!line_a.contains(" 200 0 "), "'0' bayt reddedilmeli");

        let line_b = content_b.lines().next().unwrap_or("");
        let parts_b: Vec<&str> = line_b.split_whitespace().collect();
        let status_idx_b = parts_b
            .iter()
            .position(|&p| p == "200")
            .expect("200 status kodu bulunmali");
        let bytes_sent_b: usize = parts_b[status_idx_b + 1]
            .parse()
            .expect("Sayisal bayt degeri olmali");
        assert_eq!(
            bytes_sent_b, 18,
            "vhost-b govde uzunlugu (VHOST_B_BODY_67890 = 18 bayt) olmali: {line_b}"
        );

        // reopen_all cagir ve yeni log satirini dogrula
        state.log_manager.reopen_all().await;
        let r3 = run_request(
            &state,
            false,
            "GET / HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n",
        )
        .await;
        assert!(r3.starts_with("HTTP/1.1 200 OK"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        state.log_manager.flush().await;

        let content_a2 = std::fs::read_to_string(&log_a).unwrap();
        assert_eq!(
            content_a2.lines().count(),
            2,
            "reopen_all sonrasi yeni satirlar yazilmali"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn vhost_custom_error_docs_404_vs_default() {
        let state = test_state_two_vhosts("err_docs");
        let r_a = run_request(
            &state,
            false,
            "GET /yok-sayfa.html HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n",
        )
        .await;
        assert!(r_a.starts_with("HTTP/1.1 404 Not Found"), "{r_a}");
        assert!(
            r_a.contains("CUSTOM_404_PAGE_FOR_VHOST_A"),
            "vhost-a ozel 404 sayfasi dondurmelidir: {r_a}"
        );

        let r_b = run_request(
            &state,
            false,
            "GET /yok-sayfa.html HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n",
        )
        .await;
        assert!(r_b.starts_with("HTTP/1.1 404 Not Found"), "{r_b}");
        assert!(
            !r_b.contains("CUSTOM_404_PAGE_FOR_VHOST_A"),
            "vhost-b varsayilan sayfa dondurmelidir: {r_b}"
        );
        assert!(
            r_b.contains("404 Not Found")
                || r_b.contains("Sayfa Bulunamadı")
                || r_b.contains("ZMax"),
            "{r_b}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn vhost_per_domain_waf_policy_and_exclude_paths() {
        let state = test_state_two_vhosts("waf_policy");
        // vhost-a WAF acik -> 403 Forbidden
        let r_a_attack = run_request(
            &state,
            false,
            "GET /?q=union+select+1,2,3 HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n",
        )
        .await;
        assert!(
            r_a_attack.starts_with("HTTP/1.1 403 Forbidden"),
            "vhost-a WAF saldiriyi engellemeli: {r_a_attack}"
        );

        // vhost-a muaf yol -> 403 olmamali
        let r_a_exempt = run_request(
            &state,
            false,
            "GET /muaf-yol?q=union+select+1,2,3 HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n",
        )
        .await;
        assert!(
            !r_a_exempt.starts_with("HTTP/1.1 403 Forbidden"),
            "vhost-a muaf yol engellenmemeli: {r_a_exempt}"
        );

        // vhost-b WAF kapali -> 200 OK (engellenmemeli)
        let r_b_attack = run_request(
            &state,
            false,
            "GET /?q=union+select+1,2,3 HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n",
        )
        .await;
        assert!(
            r_b_attack.starts_with("HTTP/1.1 200 OK"),
            "vhost-b WAF kapali oldugu icin gecmeli: {r_b_attack}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn http2_and_http1_real_request_isolation_and_coexistence() {
        let state = test_state_two_vhosts("h2_coexist");

        // 1. HTTP/2 gerçek istek akışı (h2 client <-> h2 server handle_h2_connection)
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let st_h2 = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:51234".parse().unwrap();
        let h2_srv = tokio::spawn(async move {
            let _ = h2_engine::handle_h2_connection(server_io, peer, st_h2, false, 80, None).await;
        });

        let (mut client, h2_conn) = h2::client::handshake(client_io)
            .await
            .expect("h2 client handshake");
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("http://vhost-a.test/")
            .header("host", "vhost-a.test")
            .body(())
            .unwrap();

        let (response, _send_stream) = client.send_request(req, true).expect("h2 send request");
        let resp = response.await.expect("h2 response");
        let (parts, mut body_stream) = resp.into_parts();
        assert_eq!(
            parts.status,
            http::StatusCode::OK,
            "HTTP/2 yaniti 200 OK olmalidir"
        );

        let mut body_buf = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let b = chunk.expect("h2 data chunk");
            body_buf.extend_from_slice(&b);
            let _ = body_stream.flow_control().release_capacity(b.len());
        }
        let body_str = String::from_utf8_lossy(&body_buf);
        assert!(
            body_str.contains("VHOST_A_BODY_12345"),
            "HTTP/2 govdesi dogru donmeli: {body_str}"
        );

        // 2. Eşzamanlı HTTP/1.1 isteği etkilenmemeli ve doğru dönmeli
        let r_h1 = run_request(
            &state,
            false,
            "GET / HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n",
        )
        .await;
        assert!(
            r_h1.starts_with("HTTP/1.1 200 OK") && r_h1.contains("VHOST_B_BODY_67890"),
            "HTTP/1.1 etkilenmemeli: {r_h1}"
        );

        let _ = h2_srv;
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn kart2_real_bytes_all_response_types_and_panel_compatibility() {
        // 1. Mock proxy backend
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            // Req 1: GET
            let (mut sock, _) = proxy_listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nPROXY_DATA",
            )
            .await
            .unwrap();
            let _ = sock.shutdown().await;

            // Req 2: HEAD
            let (mut sock2, _) = proxy_listener.accept().await.unwrap();
            let mut buf2 = [0u8; 1024];
            let _ = sock2.read(&mut buf2).await.unwrap();
            sock2
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = sock2.shutdown().await;
        });

        // 2. Mock FastCGI backend
        let fcgi_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fcgi_addr = fcgi_listener.local_addr().unwrap().to_string();
        let fcgi_task = tokio::spawn(async move {
            // Req 1: GET
            {
                let (mut sock, _) = fcgi_listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await.unwrap();
                let body = "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nFASTCGI_OUTPUT"; // 14 bayt
                let mut resp = build_fcgi_record(6, 1, body.as_bytes());
                resp.extend_from_slice(&build_fcgi_record(6, 1, &[]));
                resp.extend_from_slice(&build_fcgi_record(3, 1, &[0, 0, 0, 0, 0, 0, 0, 0]));
                sock.write_all(&resp).await.unwrap();
                let _ = sock.shutdown().await;
            }
            // Req 2: HEAD
            {
                let (mut sock, _) = fcgi_listener.accept().await.unwrap();
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await.unwrap();
                let body = "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\nFASTCGI_OUTPUT";
                let mut resp = build_fcgi_record(6, 1, body.as_bytes());
                resp.extend_from_slice(&build_fcgi_record(6, 1, &[]));
                resp.extend_from_slice(&build_fcgi_record(3, 1, &[0, 0, 0, 0, 0, 0, 0, 0]));
                sock.write_all(&resp).await.unwrap();
                let _ = sock.shutdown().await;
            }
        });

        // 3. Test State olusturma
        let base = std::env::temp_dir().join(format!("zmax_bin_kart2_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("www").join("vhost-k2");
        let err_dir = root.join("err");
        std::fs::create_dir_all(&err_dir).unwrap();
        std::fs::create_dir_all(base.join("modules")).unwrap();
        std::fs::create_dir_all(base.join("admin")).unwrap();
        std::fs::create_dir_all(base.join("logs")).unwrap();

        std::fs::write(root.join("index.html"), "VHOST_K2_BODY_STATIC_12345").unwrap(); // 26 bayt
        std::fs::write(root.join("cached.html"), "CACHED_BODY_HIT_67890").unwrap(); // 21 bayt
        std::fs::write(root.join("test.php"), "<?php // test").unwrap();
        std::fs::write(err_dir.join("404.html"), "CUSTOM_404_PAGE_FOR_K2_TEST").unwrap(); // 27 bayt

        std::fs::write(
            base.join("modules").join("mod_security.toml"),
            "[module]\nname = \"mod_security\"\nenabled = true\n\n[settings]\nsql_injection_inspection = true\npath_traversal_shield = true\n",
        )
        .unwrap();
        std::fs::write(
            base.join("modules").join("mod_coreruleset.toml"),
            "[module]\nname = \"mod_coreruleset\"\nenabled = true\n\n[settings]\nblock_sql_injection = true\n",
        )
        .unwrap();

        let mut entry = zmax_config::VHostEntry {
            name: "k2.test".into(),
            aliases: vec!["www.k2.test".into()],
            document_root: "www/vhost-k2".into(),
            ..Default::default()
        };
        entry.logging.enabled = true;
        entry.logging.access_log = "logs/k2.access.log".into();
        entry.logging.error_log = "logs/k2.error.log".into();
        entry.security.waf_enabled = Some(true);
        entry.security.waf_exclude_paths = vec!["/muaf-waf".into()];
        entry.error_docs.dir = "err".into();
        entry.error_docs.pages.insert(404, "404.html".into());
        entry.cache.enabled = true;
        entry.cache.expire = 60;
        entry.proxy.enabled = true;
        entry.proxy.upstream = proxy_addr.to_string();
        entry.proxy.path_prefix = "/proxy".to_string();
        entry.php.enabled = true;
        entry.php.upstream = fcgi_addr;

        let vh = zmax_config::LoadedVHost {
            resolved_doc_root: resolve_path(&base, &entry.document_root),
            entry,
            file_name: "k2.test.toml".into(),
        };

        let mut cfg = ZMaxConfig::parse_toml("").unwrap();
        cfg.cache.enabled = true;
        let modules = LoadedModules::load_from_dir(&base.join("modules")).unwrap();
        let mut policies = compile_policies(&cfg, &modules);
        policies.fastcgi.enabled = true;
        policies.proxy.enabled = true;
        let auth = compute_effective_auth(&cfg);

        let state = Arc::new(ServerState {
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                16 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            limiter: RwLock::new(zmax_security::RateLimiter::new(u32::MAX)),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::new(3, 60, 300)),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
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
                vhosts_dir: base.join("vhosts"),
                modules_dir: base.join("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                base.join("admin"),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(logger::AsyncLogManager::new(
                base.clone(),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                10,
                16,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::with_capacity(64)),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: std::sync::atomic::AtomicU64::new(0),
                cache_hits: std::sync::atomic::AtomicU64::new(0),
                cache_misses: std::sync::atomic::AtomicU64::new(0),
            },
        });

        // 4. Istekleri gonder:
        // 1. Statik GET
        let r_static_get = run_request(
            &state,
            false,
            "GET /index.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_static_get.starts_with("HTTP/1.1 200 OK")
                && r_static_get.contains("VHOST_K2_BODY_STATIC_12345"),
            "{r_static_get}"
        );
        let etag = r_static_get
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("etag:"))
            .map(|l| l.split(':').nth(1).unwrap().trim())
            .unwrap_or("");

        // 2. Statik HEAD
        let r_static_head = run_request(
            &state,
            false,
            "HEAD /index.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_static_head.starts_with("HTTP/1.1 200 OK")
                && !r_static_head.contains("VHOST_K2_BODY_STATIC_12345"),
            "{r_static_head}"
        );

        // 3. 304 Not Modified
        let r_304 = run_request(&state, false, &format!("GET /index.html HTTP/1.1\r\nHost: k2.test\r\nIf-None-Match: {}\r\nConnection: close\r\n\r\n", etag)).await;
        assert!(r_304.starts_with("HTTP/1.1 304 Not Modified"), "{r_304}");

        // 4. Range Request GET (206)
        let r_range_get = run_request(&state, false, "GET /index.html HTTP/1.1\r\nHost: k2.test\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n").await;
        assert!(
            r_range_get.starts_with("HTTP/1.1 206 Partial Content")
                && r_range_get.contains("VHOST"),
            "{r_range_get}"
        );

        // 5. Range Request HEAD (206)
        let r_range_head = run_request(&state, false, "HEAD /index.html HTTP/1.1\r\nHost: k2.test\r\nRange: bytes=0-4\r\nConnection: close\r\n\r\n").await;
        assert!(
            r_range_head.starts_with("HTTP/1.1 206 Partial Content")
                && !r_range_head.contains("VHOST"),
            "{r_range_head}"
        );

        // 6. ErrorDoc 404 GET
        let r_404_get = run_request(
            &state,
            false,
            "GET /yok-sayfa.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_404_get.starts_with("HTTP/1.1 404 Not Found")
                && r_404_get.contains("CUSTOM_404_PAGE_FOR_K2_TEST"),
            "{r_404_get}"
        );

        // 7. ErrorDoc 404 HEAD
        let r_404_head = run_request(
            &state,
            false,
            "HEAD /yok-sayfa.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_404_head.starts_with("HTTP/1.1 404 Not Found")
                && !r_404_head.contains("CUSTOM_404_PAGE_FOR_K2_TEST"),
            "{r_404_head}"
        );

        // 8. ErrorDoc 403 GET (WAF engeli)
        let r_403_get = run_request(
            &state,
            false,
            "GET /?q=union+select+1 HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_403_get.starts_with("HTTP/1.1 403 Forbidden"),
            "{r_403_get}"
        );

        // 9. ErrorDoc 403 HEAD (WAF engeli)
        let r_403_head = run_request(
            &state,
            false,
            "HEAD /?q=union+select+1 HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_403_head.starts_with("HTTP/1.1 403 Forbidden"),
            "{r_403_head}"
        );

        // 10. Cache Warmup (MISS)
        let r_c_miss = run_request(
            &state,
            false,
            "GET /cached.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_c_miss.starts_with("HTTP/1.1 200 OK") && r_c_miss.contains("CACHED_BODY_HIT_67890"),
            "{r_c_miss}"
        );

        // 11. Cache HIT GET
        let r_c_hit = run_request(
            &state,
            false,
            "GET /cached.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_c_hit.starts_with("HTTP/1.1 200 OK") && r_c_hit.contains("CACHED_BODY_HIT_67890"),
            "{r_c_hit}"
        );

        // 12. Cache HIT HEAD
        let r_c_head = run_request(
            &state,
            false,
            "HEAD /cached.html HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_c_head.starts_with("HTTP/1.1 200 OK") && !r_c_head.contains("CACHED_BODY_HIT_67890"),
            "{r_c_head}"
        );

        // 13. Reverse Proxy GET
        let r_proxy_get = run_request(
            &state,
            false,
            "GET /proxy/hello HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_proxy_get.starts_with("HTTP/1.1 200 OK") && r_proxy_get.contains("PROXY_DATA"),
            "{r_proxy_get}"
        );

        // 14. Reverse Proxy HEAD
        let r_proxy_head = run_request(
            &state,
            false,
            "HEAD /proxy/hello HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_proxy_head.starts_with("HTTP/1.1 200 OK") && !r_proxy_head.contains("PROXY_DATA"),
            "{r_proxy_head}"
        );

        // 15. FastCGI PHP GET
        let r_fcgi_get = run_request(
            &state,
            false,
            "GET /test.php HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_fcgi_get.starts_with("HTTP/1.1 200 OK") && r_fcgi_get.contains("FASTCGI_OUTPUT"),
            "{r_fcgi_get}"
        );

        // 16. FastCGI PHP HEAD
        let r_fcgi_head = run_request(
            &state,
            false,
            "HEAD /test.php HTTP/1.1\r\nHost: k2.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r_fcgi_head.starts_with("HTTP/1.1 200 OK") && !r_fcgi_head.contains("FASTCGI_OUTPUT"),
            "{r_fcgi_head}"
        );

        let _ = proxy_task.await;
        let _ = fcgi_task.await;

        // 17, 18, 19: HTTP/2 İstekleri (h2 client)
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);
        let st_h2 = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:51234".parse().unwrap();
        let h2_srv = tokio::spawn(async move {
            let _ = h2_engine::handle_h2_connection(server_io, peer, st_h2, false, 80, None).await;
        });
        let (mut client, h2_conn) = h2::client::handshake(client_io)
            .await
            .expect("h2 client handshake");
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        // H2 GET
        {
            let req = http::Request::builder()
                .method("GET")
                .uri("http://k2.test/index.html")
                .header("host", "k2.test")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            assert_eq!(body_buf.len(), 26);
        }

        // H2 HEAD
        {
            let req = http::Request::builder()
                .method("HEAD")
                .uri("http://k2.test/index.html")
                .header("host", "k2.test")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            assert_eq!(body_buf.len(), 0);
        }

        // H2 304
        {
            let req = http::Request::builder()
                .method("GET")
                .uri("http://k2.test/index.html")
                .header("host", "k2.test")
                .header("if-none-match", etag)
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::NOT_MODIFIED);
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            assert_eq!(body_buf.len(), 0);
        }

        drop(client);
        let _ = h2_srv;

        // 5. Günlük dosyasını bekle ve flush et
        tokio::time::sleep(Duration::from_millis(60)).await;
        state.log_manager.flush().await;

        let log_path = state.base_dir.join("logs").join("k2.access.log");
        assert!(log_path.is_file(), "k2.access.log oluşturulmalı");
        let content = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert_eq!(
            lines.len(),
            19,
            "Toplam 19 istek günlüğe kaydedilmeli: {content}"
        );

        // Beklenen (durum, bayt_str) tablosu:
        let expected_records: Vec<(u16, &str)> = vec![
            (200, "26"),        // 1. Statik GET
            (200, "-"),         // 2. Statik HEAD -> NCSA '-' kurali
            (304, "-"),         // 3. 304 Not Modified -> NCSA '-' kurali
            (206, "5"),         // 4. Range GET (0-4 = 5 bayt)
            (206, "-"),         // 5. Range HEAD -> '-'
            (404, "27"),        // 6. 404 GET (custom 404 sayfası 27 bayt)
            (404, "-"),         // 7. 404 HEAD -> '-'
            (403, "CHECK_POS"), // 8. 403 GET (WAF engeli)
            (403, "-"),         // 9. 403 HEAD -> '-'
            (200, "21"),        // 10. Cache MISS
            (200, "21"),        // 11. Cache HIT GET (21 bayt)
            (200, "-"),         // 12. Cache HIT HEAD -> '-'
            (200, "10"),        // 13. Proxy GET (10 bayt, baslik haric gercek govde!)
            (200, "-"),         // 14. Proxy HEAD -> '-'
            (200, "14"),        // 15. FastCGI GET (14 bayt)
            (200, "-"),         // 16. FastCGI HEAD -> '-'
            (200, "26"),        // 17. HTTP/2 GET (26 bayt)
            (200, "-"),         // 18. HTTP/2 HEAD -> '-'
            (304, "-"),         // 19. HTTP/2 304 -> '-'
        ];

        for (i, (exp_status, exp_bytes)) in expected_records.iter().enumerate() {
            let line = lines[i];
            // Format dogrulama: %h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
            assert!(
                line.contains("[") && line.contains(" +0000] \""),
                "Zaman damgasi hatali: {line}"
            );
            assert!(
                line.starts_with("127.0.0.1 - - ["),
                "IP/ident baslangici hatali: {line}"
            );

            let parts: Vec<&str> = line.split('"').collect();
            assert!(parts.len() >= 3, "Quoted kisimlar bulunamadi: {line}");
            let status_bytes_str = parts[2].trim();
            let tokens: Vec<&str> = status_bytes_str.split_whitespace().collect();
            assert!(tokens.len() >= 2, "Status ve bytes ayrilamadi: {line}");
            let status: u16 = tokens[0].parse().unwrap();
            let bytes_val = tokens[1];

            assert_eq!(
                status, *exp_status,
                "Satir {i} status kodu uyusmuyor: {line}"
            );
            if *exp_bytes == "CHECK_POS" {
                let parsed_b: usize = bytes_val
                    .parse()
                    .expect("Pozitif sayisal bayt degeri olmali");
                assert!(
                    parsed_b > 0,
                    "403 yanitinda govde bayti pozitif olmali: {line}"
                );
            } else {
                assert_eq!(
                    bytes_val, *exp_bytes,
                    "Satir {i} ({line}) beklenen bayt '{exp_bytes}' vermedi"
                );
            }
        }

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn test_kart5_pipeline_http1_and_http2_security() {
        let base = std::env::temp_dir().join(format!("zmax_bin_k5_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("www").join("k5");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(base.join("modules")).unwrap();
        std::fs::write(
            base.join("modules").join("mod_security.toml"),
            "[module]\nname = \"mod_security\"\nenabled = true\n\n[settings]\nsql_injection_inspection = true\npath_traversal_shield = true\n",
        )
        .unwrap();
        std::fs::write(
            base.join("modules").join("mod_coreruleset.toml"),
            "[module]\nname = \"mod_coreruleset\"\nenabled = true\n\n[settings]\nblock_sql_injection = true\n",
        )
        .unwrap();
        std::fs::write(root.join("resim.png"), "RESIM_ICERIK_PNG_12345").unwrap();
        std::fs::write(root.join("sayfa.html"), "SAYFA_ICERIK_HTML_67890").unwrap();

        let mut entry = zmax_config::VHostEntry {
            name: "kart5.test".into(),
            aliases: vec!["sub.kart5.test".into()],
            document_root: "www/k5".into(),
            ..Default::default()
        };
        entry.security.force_https = true;
        entry.hotlink.enabled = true;
        entry.hotlink.allowed_referers = vec![
            "kart5.test".into(),
            "*.kart5.test".into(),
            "ortak.test".into(),
        ];
        entry.hotlink.extensions = vec!["png".into(), "jpg".into(), "webp".into()];
        entry.security.allow_ips = vec!["127.0.0.1".into(), "10.0.0.0/8".into()];
        entry.security.deny_ips = vec!["192.168.1.100".into(), "172.16.0.0/16".into()];
        entry.security.waf_enabled = Some(true);
        entry.tls.http2 = true;

        let vh = zmax_config::LoadedVHost {
            resolved_doc_root: resolve_path(&base, &entry.document_root),
            entry,
            file_name: "kart5.test.toml".into(),
        };

        let mut cfg = ZMaxConfig::parse_toml("[waf]\nenabled = true\n").unwrap();
        cfg.listeners.https.port = 443;
        cfg.cache.enabled = false;
        let modules = LoadedModules::load_from_dir(&base.join("modules")).unwrap();
        let policies = compile_policies(&cfg, &modules);
        let auth = compute_effective_auth(&cfg);

        let state = Arc::new(ServerState {
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                4 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            limiter: tokio::sync::RwLock::new(zmax_security::RateLimiter::new(1000)),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::new(10, 60, 300)),
            basic_auth: Arc::new(zmax_security::BasicAuthManager::new()),
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
                vhosts_dir: base.join("vhosts"),
                modules_dir: base.join("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(
                base.join("admin"),
            )),
            tls: Arc::new(zmax_tls::SniResolver::new()),
            admin_tls: Arc::new(zmax_tls::SniResolver::new()),
            api_tls: Arc::new(zmax_tls::SniResolver::new()),
            log_manager: Arc::new(logger::AsyncLogManager::new(
                base.clone(),
                PathBuf::from("logs/access.log"),
                PathBuf::from("logs/error.log"),
                250,
                64,
            )),
            htaccess_resolver: Arc::new(zmax_rewrite::HtAccessResolver::new()),
            shutdown: Arc::new(zmax_runtime::ShutdownCoordinator::new()),
            waf_events: Arc::new(zmax_security::waf_events::WafEventStore::new()),
            access_logs: Mutex::new(VecDeque::with_capacity(64)),
            stats: ServerStats {
                start_time: Instant::now(),
                total_requests: std::sync::atomic::AtomicU64::new(0),
                cache_hits: std::sync::atomic::AtomicU64::new(0),
                cache_misses: std::sync::atomic::AtomicU64::new(0),
            },
        });

        // -------------------------------------------------------------
        // KISIM 1: HTTP/1.1 İstek Hattı Güvenlik Denetimleri
        // -------------------------------------------------------------

        // 1.1 Yabancı Referer -> 403 Forbidden (Hotlink Protection)
        let r1 = run_request(
            &state,
            true,
            "GET /resim.png HTTP/1.1\r\nHost: kart5.test\r\nReferer: http://saldirgan.com/sayfa\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r1.starts_with("HTTP/1.1 403 Forbidden"),
            "H1.1 403 olmalı: {r1}"
        );
        assert!(
            r1.contains("Hotlink Protection"),
            "H1.1 hotlink body içermeli: {r1}"
        );

        // 1.2 Boş Referer -> 200 OK (Doğrudan erişim izinli)
        let r2 = run_request(
            &state,
            true,
            "GET /resim.png HTTP/1.1\r\nHost: kart5.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r2.starts_with("HTTP/1.1 200 OK"), "H1.2 200 olmalı: {r2}");
        assert!(
            r2.ends_with("RESIM_ICERIK_PNG_12345"),
            "H1.2 içerik eşleşmeli: {r2}"
        );

        // 1.3 İzinli Referer -> 200 OK
        let r3 = run_request(
            &state,
            true,
            "GET /resim.png HTTP/1.1\r\nHost: kart5.test\r\nReferer: https://kart5.test/sayfa.html\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r3.starts_with("HTTP/1.1 200 OK"), "H1.3 200 olmalı: {r3}");

        // 1.4 Joker İzinli Referer (*.kart5.test) -> 200 OK
        let r4 = run_request(
            &state,
            true,
            "GET /resim.png HTTP/1.1\r\nHost: kart5.test\r\nReferer: https://img.kart5.test/galeri\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r4.starts_with("HTTP/1.1 200 OK"), "H1.4 200 olmalı: {r4}");

        // 1.5 Korunmayan Uzantı (HTML) -> 200 OK (Yabancı Referer olsa dahi)
        let r5 = run_request(
            &state,
            true,
            "GET /sayfa.html HTTP/1.1\r\nHost: kart5.test\r\nReferer: http://saldirgan.com/\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r5.starts_with("HTTP/1.1 200 OK"), "H1.5 200 olmalı: {r5}");

        // 1.6 Deny CIDR IP -> 403 Forbidden (IP Access Denied)
        let peer_denied: SocketAddr = "172.16.5.10:50000".parse().unwrap();
        let r6 = run_request_with_peer(
            &state,
            peer_denied,
            true,
            "GET /sayfa.html HTTP/1.1\r\nHost: kart5.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r6.starts_with("HTTP/1.1 403 Forbidden"),
            "H1.6 403 olmalı: {r6}"
        );
        assert!(
            r6.contains("IP Access Denied"),
            "H1.6 ACL body içermeli: {r6}"
        );

        // 1.7 WAF SQLi Engeli -> 403 Forbidden (WAF Blocked)
        let r7 = run_request(
            &state,
            true,
            "GET /sayfa.html?q=union+select+1 HTTP/1.1\r\nHost: kart5.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r7.starts_with("HTTP/1.1 403 Forbidden"),
            "H1.7 403 olmalı: {r7}"
        );
        assert!(r7.contains("WAF Blocked"), "H1.7 WAF body içermeli: {r7}");

        // 1.8 force_https -> 301 Moved Permanently (HTTP isteğinde)
        let r8 = run_request(
            &state,
            false,
            "GET /sayfa.html HTTP/1.1\r\nHost: kart5.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            r8.starts_with("HTTP/1.1 301 Moved Permanently"),
            "H1.8 301 olmalı: {r8}"
        );
        assert!(
            r8.contains("Location: https://kart5.test/sayfa.html"),
            "H1.8 redirect header olmalı: {r8}"
        );

        // -------------------------------------------------------------
        // KISIM 2: HTTP/2 İstek Hattı Güvenlik Denetimleri (Gerçek h2 Client)
        // -------------------------------------------------------------

        async fn make_h2_client(
            state: &Arc<ServerState>,
            peer: SocketAddr,
            is_https: bool,
        ) -> (
            h2::client::SendRequest<bytes::Bytes>,
            tokio::task::JoinHandle<()>,
        ) {
            let (client_io, server_io) = tokio::io::duplex(256 * 1024);
            let st = Arc::clone(state);
            let port = if is_https { 443 } else { 80 };
            let srv_task = tokio::spawn(async move {
                let _ = h2_engine::handle_h2_connection(server_io, peer, st, is_https, port, None)
                    .await;
            });
            let (client, h2_conn) = h2::client::handshake(client_io)
                .await
                .expect("h2 client handshake");
            let conn_task = tokio::spawn(async move {
                let _ = h2_conn.await;
            });
            let wait_task = tokio::spawn(async move {
                let _ = srv_task.await;
                let _ = conn_task.await;
            });
            (client, wait_task)
        }

        let loopback_peer: SocketAddr = "127.0.0.1:51234".parse().unwrap();

        // 2.1 HTTP/2 Yabancı Referer -> 403 Forbidden (Hotlink Protection)
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/resim.png")
                .header("host", "kart5.test")
                .header("referer", "http://saldirgan.com/sayfa")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(
                resp.status(),
                http::StatusCode::FORBIDDEN,
                "H2.1 403 olmalı"
            );
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            let body_str = String::from_utf8_lossy(&body_buf);
            assert!(
                body_str.contains("Hotlink Protection"),
                "H2.1 hotlink body içermeli: {body_str}"
            );
        }

        // 2.2 HTTP/2 Boş Referer -> 200 OK
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/resim.png")
                .header("host", "kart5.test")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK, "H2.2 200 olmalı");
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            assert_eq!(body_buf, b"RESIM_ICERIK_PNG_12345", "H2.2 içerik eşleşmeli");
        }

        // 2.3 HTTP/2 İzinli Referer -> 200 OK
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/resim.png")
                .header("host", "kart5.test")
                .header("referer", "https://kart5.test/sayfa.html")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK, "H2.3 200 olmalı");
        }

        // 2.4 HTTP/2 Joker İzinli Referer (*.kart5.test) -> 200 OK
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/resim.png")
                .header("host", "kart5.test")
                .header("referer", "https://sub.kart5.test/galeri")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK, "H2.4 200 olmalı");
        }

        // 2.5 HTTP/2 Korunmayan Uzantı (HTML) -> 200 OK (Yabancı Referer olsa dahi)
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/sayfa.html")
                .header("host", "kart5.test")
                .header("referer", "http://saldirgan.com/")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK, "H2.5 200 olmalı");
        }

        // 2.6 HTTP/2 Deny CIDR IP -> 403 Forbidden (IP Access Denied)
        {
            let (mut client, _task) = make_h2_client(&state, peer_denied, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/sayfa.html")
                .header("host", "kart5.test")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(
                resp.status(),
                http::StatusCode::FORBIDDEN,
                "H2.6 403 olmalı"
            );
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            let body_str = String::from_utf8_lossy(&body_buf);
            assert!(
                body_str.contains("IP Access Denied"),
                "H2.6 ACL body içermeli: {body_str}"
            );
        }

        // 2.7 HTTP/2 WAF SQLi Engeli -> 403 Forbidden (WAF Blocked)
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, true).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("https://kart5.test/sayfa.html?q=union+select+1")
                .header("host", "kart5.test")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(
                resp.status(),
                http::StatusCode::FORBIDDEN,
                "H2.7 403 olmalı"
            );
            let mut body_stream = resp.into_body();
            let mut body_buf = Vec::new();
            while let Some(chunk) = body_stream.data().await {
                let b = chunk.unwrap();
                body_buf.extend_from_slice(&b);
                let _ = body_stream.flow_control().release_capacity(b.len());
            }
            let body_str = String::from_utf8_lossy(&body_buf);
            assert!(
                body_str.contains("WAF Blocked"),
                "H2.7 WAF body içermeli: {body_str}"
            );
        }

        // 2.8 HTTP/2 force_https -> 301 Moved Permanently (HTTP üzerinden geldiğinde)
        {
            let (mut client, _task) = make_h2_client(&state, loopback_peer, false).await;
            let req = http::Request::builder()
                .method("GET")
                .uri("http://kart5.test/sayfa.html")
                .header("host", "kart5.test")
                .body(())
                .unwrap();
            let (response, _) = client.send_request(req, true).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(
                resp.status(),
                http::StatusCode::MOVED_PERMANENTLY,
                "H2.8 301 olmalı"
            );
            let loc = resp.headers().get("location").unwrap().to_str().unwrap();
            assert_eq!(
                loc, "https://kart5.test/sayfa.html",
                "H2.8 location başlığı eşleşmeli"
            );
        }

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[test]
    fn k8_collect_tls_key_paths_resolves_listener_and_vhost_files_and_skips_empty() {
        let base = std::env::temp_dir().join("zmax_k8_collect_tls");
        let cfg = ZMaxConfig::parse_toml(
            "[listeners.admin]\ntls_key = \"certs/admin.key\"\ntls_cert = \"\"\n\n[listeners.api]\ntls_cert = \"certs/api.pem\"\n",
        )
        .unwrap();
        let entry = zmax_config::VHostEntry {
            name: "a.test".into(),
            document_root: "www/a".into(),
            ssl: zmax_config::VHostSslSection {
                certificate: "certs/a.pem".into(),
                key: "certs/a.key".into(),
            },
            ..Default::default()
        };
        let vh = zmax_config::LoadedVHost {
            resolved_doc_root: base.join("www/a"),
            entry,
            file_name: "a.test.toml".into(),
        };
        let got = collect_tls_key_paths(&base, &cfg, &[vh]);
        assert_eq!(
            got,
            vec![
                resolve_path(&base, "certs/admin.key"),
                resolve_path(&base, "certs/api.pem"),
                resolve_path(&base, "certs/a.key"),
                resolve_path(&base, "certs/a.pem"),
            ]
        );
    }

    #[tokio::test]
    async fn test_slowloris_header_drip_timeout_returns_408_and_closes_socket() {
        // Matris §1/§8: Slowloris başlık damlatma saldırısında soketin zaman aşımına uğrayıp 408 ile kapatılması.
        let state = test_state_with(
            "slow_hdr",
            false,
            "[security]\nslowloris_header_timeout_sec = 1\nslowloris_body_timeout_sec = 10\nkeep_alive_timeout_sec = 10\n",
        );
        let (client, server) = tokio::io::duplex(64 * 1024);
        let st = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let task = tokio::spawn(async move {
            web_engine::handle_web_connection(server, peer, st, false, 80).await
        });

        let start = Instant::now();
        let (mut client_read, mut client_write) = tokio::io::split(client);

        // Başlık kısmı gönderiliyor ama bitirilmiyor (\r\n\r\n yok)
        client_write
            .write_all(
                b"GET /index.html HTTP/1.1\r\nHost: site.test\r\nUser-Agent: Slowloris-Sim\r\n",
            )
            .await
            .unwrap();

        // Saldırgan 25 adım boyunca her 150 ms'de bir başlık damlatıyor (toplam 3.75 saniye sürecek damlatma)
        let drip_task = tokio::spawn(async move {
            for i in 0..25 {
                tokio::time::sleep(Duration::from_millis(150)).await;
                if client_write
                    .write_all(format!("X-Slow-Header-{i}: val\r\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // İstemci damlatma sürerken eşzamanlı olarak sunucunun yanıtını okur.
        // Yeni koddaki kümülatif header_deadline sayesinde ~1.0-1.1 sn içinde 408 gelip soket kapatılmalıdır.
        let mut out = Vec::new();
        let _ = client_read.read_to_end(&mut out).await;
        let elapsed = start.elapsed();
        let _ = drip_task.await;

        let resp = String::from_utf8_lossy(&out);
        assert!(
            resp.starts_with("HTTP/1.1 408 Request Timeout"),
            "Slowloris başlık aşımı 408 dönmeli: {resp}"
        );
        assert!(
            resp.contains("Connection: close"),
            "Zaman aşımında bağlantı kapatılmalı: {resp}"
        );
        assert!(
            elapsed < Duration::from_millis(1500),
            "408 Request Timeout damlatma bitmeden (< 1.5 sn) gelmelidir! Geçen süre: {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "408 zaman aşımı 1 saniyeden önce tetiklenmemelidir! Geçen süre: {elapsed:?}"
        );

        let _ = task.await;
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn test_slowloris_body_drip_timeout_returns_408_and_closes_socket() {
        // Matris §1/§8: Content-Length gövdesi yavaş aktarıldığında body_timeout dolunca 408 ile kapatılması.
        let state = test_state_with(
            "slow_body",
            false,
            "[security]\nslowloris_header_timeout_sec = 10\nslowloris_body_timeout_sec = 1\nkeep_alive_timeout_sec = 10\n",
        );
        let (client, server) = tokio::io::duplex(64 * 1024);
        let st = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:50002".parse().unwrap();
        let task = tokio::spawn(async move {
            web_engine::handle_web_connection(server, peer, st, false, 80).await
        });

        let start = Instant::now();
        let (mut client_read, mut client_write) = tokio::io::split(client);

        // Başlık tamam, 10000 baytlık gövde vaat ediliyor
        client_write
            .write_all(
                b"POST /index.html HTTP/1.1\r\nHost: site.test\r\nContent-Length: 10000\r\n\r\n",
            )
            .await
            .unwrap();

        // Yavaş gövde damlatma (25 adım * 150 ms = 3.75 saniye sürecek damlatma)
        let drip_task = tokio::spawn(async move {
            for _ in 0..25 {
                tokio::time::sleep(Duration::from_millis(150)).await;
                if client_write.write_all(b"CHUNK").await.is_err() {
                    break;
                }
            }
        });

        let mut out = Vec::new();
        let _ = client_read.read_to_end(&mut out).await;
        let elapsed = start.elapsed();
        let _ = drip_task.await;

        let resp = String::from_utf8_lossy(&out);
        assert!(
            resp.starts_with("HTTP/1.1 408 Request Timeout"),
            "Slowloris gövde aşımı 408 dönmeli: {resp}"
        );
        assert!(
            resp.contains("Connection: close"),
            "Gövde aşımında bağlantı kapatılmalı: {resp}"
        );
        assert!(
            elapsed < Duration::from_millis(1500),
            "Gövde 408 damlatma bitmeden (< 1.5 sn) gelmelidir! Geçen süre: {elapsed:?}"
        );
        assert!(
            elapsed >= Duration::from_millis(900),
            "Gövde 408 zaman aşımı 1 saniyeden önce tetiklenmemelidir! Geçen süre: {elapsed:?}"
        );

        let _ = task.await;
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn test_keep_alive_idle_timeout_safely_closes_connection() {
        // Matris §1/§8: İlk istek başarıyla tamamlandıktan sonra boşta bekleyen keep-alive soketin
        // keep_alive_timeout dolduğunda güvenle (EOF ile) kapatılması.
        let state = test_state_with(
            "ka_idle",
            false,
            "[security]\nslowloris_header_timeout_sec = 10\nslowloris_body_timeout_sec = 10\nkeep_alive_timeout_sec = 1\n",
        );
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let st = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:50003".parse().unwrap();
        let task = tokio::spawn(async move {
            web_engine::handle_web_connection(server, peer, st, false, 80).await
        });

        // 1. İstek gönderilir
        client
            .write_all(b"GET /index.html HTTP/1.1\r\nHost: site.test\r\n\r\n")
            .await
            .unwrap();

        // 200 OK ve Keep-Alive başlığı okunur
        let mut resp_buf = [0u8; 1024];
        let n = client.read(&mut resp_buf).await.unwrap();
        let resp = String::from_utf8_lossy(&resp_buf[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 200 OK"),
            "İlk istek 200 dönmeli: {resp}"
        );
        assert!(
            resp.contains("Connection: keep-alive"),
            "Keep-Alive başlığı olmalı: {resp}"
        );
        assert!(
            resp.contains("Keep-Alive: timeout=1"),
            "Timeout bildirim başlığı olmalı: {resp}"
        );

        // İstemci ikinci istek göndermez, boşta bekler (idle).
        // Sunucu 1 saniyelik keep_alive_timeout sonunda soketi temizce kapatmalıdır (EOF).
        let mut idle_buf = [0u8; 64];
        let next_n = client.read(&mut idle_buf).await.unwrap();
        assert_eq!(
            next_n, 0,
            "Idle timeout dolunca soket EOF (0 bayt) ile kapanmalıdır"
        );

        let _ = task.await;
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn test_h2_handshake_timeout_drops_unresponsive_raw_tcp_client() {
        // Matris P1: HTTP/2 el sıkışması göndermeyen ham TCP istemcinin 10 saniyelik
        // handshake zaman aşımı dolduğunda kesildiğini ve soketin kapatıldığını kanıtlayan test.
        let state = test_state("h2_hs_raw");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        let st = Arc::clone(&state);
        let server_task = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            h2_engine::handle_h2_connection(sock, peer, st, false, local_addr.port(), None).await
        });

        // Ham TCP istemcisi bağlanır ancak hiçbir HTTP/2 Preface / Handshake göndermez
        let mut raw_client = tokio::net::TcpStream::connect(local_addr).await.unwrap();

        let start = Instant::now();
        let mut out = Vec::new();
        let _ = raw_client.read_to_end(&mut out).await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_secs(9),
            "Handshake zaman aşımı 10s dolmadan kesilmemeli: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "Handshake zaman aşımı 10s dolunca soketi kesmeli: {elapsed:?}"
        );

        let res = server_task.await.unwrap();
        assert!(
            res.is_err(),
            "Sunucu handshake zaman aşımı hatası üretmelidir"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("zaman aşımı") || err_msg.contains("TimedOut") || err_msg.contains("timed out"),
            "Zaman aşımı mesajı içermelidir: {err_msg}"
        );

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn test_h2_idle_stream_timeout_closes_connection() {
        // Matris P1: HTTP/2 bağlantısı kurulduktan sonra ilk stream'i göndermeyen istemcinin
        // header_timeout dolunca accept döngüsünden çıkıp bağlantıyı kapattığı doğrulanır.
        let state = test_state_with(
            "h2_idle",
            false,
            "[security]\nslowloris_header_timeout_sec = 1\nslowloris_body_timeout_sec = 10\nkeep_alive_timeout_sec = 1\n",
        );
        let (client, server) = tokio::io::duplex(64 * 1024);
        let st = Arc::clone(&state);
        let peer: SocketAddr = "127.0.0.1:50005".parse().unwrap();
        let server_task = tokio::spawn(async move {
            h2_engine::handle_h2_connection(server, peer, st, false, 80, None).await
        });

        // İstemci HTTP/2 el sıkışmasını tamamlar
        let (_send_req, client_conn) = h2::client::handshake(client).await.unwrap();
        let client_task = tokio::spawn(async move {
            let _ = client_conn.await;
        });

        // İstemci hiçbir stream açmaz (boşta bekler). Sunucudaki header_timeout (1s) dolunca
        // sunucu accept döngüsünden çıkar ve bağlantıyı kapatır.
        let start = Instant::now();
        let _ = client_task.await;
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(900),
            "H2 stream bekleme zaman aşımından önce kesilmemeli: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(2500),
            "H2 stream bekleme zaman aşımı zamanında kesmeli: {elapsed:?}"
        );

        let _ = server_task.await;
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn test_matrix_bounds_defaults_and_validation() {
        // Matris §1 / §8: Varsayılan 10s header, 30s body, 65s keep-alive doğrulaması
        let def = zmax_config::ZMaxConfig::default();
        assert_eq!(def.security.slowloris_header_timeout_sec, 10);
        assert_eq!(def.security.slowloris_body_timeout_sec, 30);
        assert_eq!(def.security.keep_alive_timeout_sec, 65);

        // 0 değerinin yapılandırma doğrulamasında reddedildiğini onayla
        let mut bad_header = zmax_config::ZMaxConfig::default();
        bad_header.security.slowloris_header_timeout_sec = 0;
        assert!(bad_header.validate().is_err());

        let mut bad_body = zmax_config::ZMaxConfig::default();
        bad_body.security.slowloris_body_timeout_sec = 0;
        assert!(bad_body.validate().is_err());

        let mut bad_ka = zmax_config::ZMaxConfig::default();
        bad_ka.security.keep_alive_timeout_sec = 0;
        assert!(bad_ka.validate().is_err());
    }
}
