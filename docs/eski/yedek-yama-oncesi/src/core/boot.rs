use crate::api::admin_static::handle_admin_connection;
use crate::api::{
    compute_effective_auth, handle_api_connection, handle_api_route, normalize_panel_request_path,
    read_http_request_with_limits, refresh_tls_certs, send_http_read_error,
};
use crate::core::state::{RuntimeState, ServerState, ServerStats};
use crate::modules_runtime::{append_error_log, build_redis_client, compile_policies};
use crate::pipeline::l2_protocol::h2 as h2_engine;
use crate::{config, logger, web_engine};
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

pub struct CliOptions {
    pub show_version: bool,
    pub check_only: bool,
    pub fix_tls_perms: bool,
    pub config_override: Option<PathBuf>,
}

pub fn parse_cli_args() -> CliOptions {
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

pub fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
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

pub fn has_zmax_layout(dir: &Path) -> bool {
    dir.join("conf").join("zmax.toml").exists() || dir.join("admin").join("index.html").exists()
}

pub fn resolve_base_dir() -> PathBuf {
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
pub fn create_reuse_listener(
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
pub fn collect_tls_key_paths(
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
pub fn run_fix_tls_perms(
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

pub fn parse_bind_addr(ip: &str, port: u16) -> Result<SocketAddr, String> {
    let formatted = if ip.contains(':') && !ip.starts_with('[') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    formatted
        .parse::<SocketAddr>()
        .map_err(|e| format!("Gecersiz dinleme adresi ({}): {}", formatted, e))
}

/// ZMax Server ana çalıştırma fonksiyonu
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
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

    crate::redis::events::spawn_subscriber(Arc::clone(&state));

    if http_enabled {
        let web_listener = create_reuse_listener(http_addr, http_backlog, http_reuse_port)?;
        println!("* Web Sunucusu  : http://{}", http_addr);
        web_engine::spawn_http_accept_loop(web_listener, Arc::clone(&state), http_nodelay, http_port);
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
        web_engine::spawn_https_accept_loop(
            https_listener,
            acceptor,
            Arc::clone(&state),
            http_nodelay,
            https_port,
        );
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
                                    let _ = handle_api_route(&mut stream, &req, &s, true, true).await;
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
                    match crate::api::reload_runtime_state(&state_sighup).await {
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

