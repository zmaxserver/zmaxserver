use crate::pipeline::l5_router::resolve_php_dial_timeout_ms;
use super::pipeline_h1::handle_web_connection;
use super::MAX_STATIC_CACHE_BYTES;
use crate::api::ServerState;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use zmax_fastcgi::{FastCgiClient, FastCgiRequest};

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
    use crate::api::compute_effective_auth;
    use crate::modules_runtime::compile_policies;
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

