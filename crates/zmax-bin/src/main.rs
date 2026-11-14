//! # ZMax Server (zmax)
//! Evrensel panel uyumlu (zPanel, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia vb.),
//! çakışmasız port mimarili, bellek güvenli yüksek hızlı Rust HTTP motoru ve WebAdmin konsolu.

pub mod api;
pub mod config;
mod core;
mod h2_engine;
mod logger;
pub mod modules;
mod modules_runtime;
pub mod pipeline;
pub mod redis;
mod web_engine;

use api::{handle_api_route, RuntimeState, ServerState, ServerStats};
use modules_runtime::{compile_policies, compute_effective_auth};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use zmax_config::{resolve_path, LoadedModules, ZMaxConfig};

#[cfg(not(target_env = "musl"))]
use mimalloc::MiMalloc;

#[cfg(not(target_env = "musl"))]
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub use api::handle_api_connection;
pub use core::boot::{
    create_reuse_listener, handle_admin_connection, parse_bind_addr, resolve_base_dir, CliOptions,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    core::boot::run().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::reload_runtime_state;
    use crate::web_engine::{https_redirect_location, is_acme_challenge};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn run_request(state: &Arc<ServerState>, https: bool, raw: &str) -> String {
        let (mut client, server) = tokio::io::duplex(256 * 1024);
        let st = Arc::clone(state);
        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
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
            root.join(".well-known").join("acme-challenge").join("tok123"),
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
        let auth = compute_effective_auth(&cfg, None);
        Arc::new(ServerState {
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                16 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            limiter: RwLock::new(zmax_security::RateLimiter::new(u32::MAX)),
            conn_limiter: Arc::new(zmax_security::ConnLimiter::new(0, Vec::new())),
            backend_semaphores: dashmap::DashMap::new(),
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
                vhosts_dir: base.join("vhosts"),
                modules_dir: base.join("modules"),
            }),
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(base.join("admin"))),
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
        let r = run_request(&state, false, "GET /a/b?x=1 HTTP/1.1\r\nHost: site.test\r\n\r\n").await;
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
        assert!(tls.starts_with("HTTP/1.1 200 OK") && tls.ends_with("ANASAYFA"), "{tls}");
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
        assert!(r_dir.starts_with("HTTP/1.1 200 OK") && r_dir.ends_with("ALT_INDEX"), "{r_dir}");

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
        assert!(r_416.starts_with("HTTP/1.1 416 Range Not Satisfiable"), "{r_416}");

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
        std::fs::write(state.base_dir.join("www").join("site").join("big.html"), &big_html).unwrap();

        // 1. Tek bağlantıda 2 Keep-Alive isteği + 2. istekte gzip
        let two_reqs = concat!(
            "GET /index.html HTTP/1.1\r\nHost: site.test\r\n\r\n",
            "GET /big.html HTTP/1.1\r\nHost: site.test\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
        );
        let resp_bytes = run_request_raw(&state, false, two_reqs.as_bytes()).await;
        let resp_lossy = String::from_utf8_lossy(&resp_bytes);
        assert!(resp_lossy.contains("Connection: keep-alive"), "{resp_lossy}");
        assert!(resp_lossy.contains("Content-Encoding: gzip"), "{resp_lossy}");
        assert!(resp_lossy.contains("ANASAYFA"), "{resp_lossy}");

        // 2. 1 MiB aşan Content-Length -> sessiz kesme yok, 413 Payload Too Large!
        let oversized = "POST /index.html HTTP/1.1\r\nHost: site.test\r\nContent-Length: 2097152\r\n\r\n";
        let r_413 = run_request(&state, false, oversized).await;
        assert!(r_413.starts_with("HTTP/1.1 413 Payload Too Large"), "{r_413}");
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
        assert!(admin_resp.starts_with("HTTP/1.1 401 Unauthorized"), "{admin_resp}");

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
                if req_buf.windows(8).any(|w| w[0] == 1 && w[1] == 5 && w[4] == 0 && w[5] == 0) {
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
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nPROXY_BODY")
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
        assert!(resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("PROXY_BODY"), "{resp}");
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

        state.ban_manager.ban("10.20.30.40".parse().unwrap(), "WordPress brute-force (11 deneme)", 300);
        state.record_access_log("127.0.0.1", "GET", "/test-log", 200, Duration::from_millis(2));
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
        assert!(mods.contains("\"mod_gzip\"") && mods.contains("\"categoryKey\":\"perf\""), "{mods}");

        let bans = call_api("GET", "/api/v1/security/bans", "").await;
        assert!(bans.contains("10.20.30.40") && bans.contains("reason_bruteforce"), "{bans}");

        let unban = call_api("POST", "/api/v1/security/unban", r#"{"ip":"10.20.30.40"}"#).await;
        assert!(unban.contains("\"unbanned\":true"), "{unban}");
        assert!(!state.ban_manager.is_banned("10.20.30.40".parse().unwrap()));

        let logs = call_api("GET", "/api/v1/logs", "").await;
        assert!(logs.contains("/test-log"), "{logs}");

        let purge = call_api("POST", "/api/v1/cache/purge", r#"{"tag":"etiket1"}"#).await;
        assert!(purge.contains("\"scope\":\"tag\"") && purge.contains("\"purged\":1"), "{purge}");
        assert!(state.cache.get("k1").await.is_none());

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn dual_listener_same_port_is_rejected_without_reuse_port() {
        let first = create_reuse_listener("127.0.0.1:0".parse().unwrap(), 128, false).unwrap();
        let port = first.local_addr().unwrap().port();
        let second = create_reuse_listener(
            format!("127.0.0.1:{}", port).parse().unwrap(),
            128,
            false,
        );
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
                let l = u32::from_be_bytes([bytes[i] & 0x7f, bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
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
                let l = u32::from_be_bytes([bytes[i] & 0x7f, bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
                i += 4;
                l
            } else {
                break;
            };
            if i + name_len + val_len > bytes.len() {
                break;
            }
            let name = String::from_utf8_lossy(&bytes[i..i + name_len]).into_owned();
            let val = String::from_utf8_lossy(&bytes[i + name_len..i + name_len + val_len]).into_owned();
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
        assert!(r_ok.starts_with("HTTP/1.1 200 OK") && r_ok.contains("ANASAYFA"), "{r_ok}");

        let r_non_allow = run_request_from_peer(
            &state,
            "192.168.1.9:41001",
            "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r_non_allow.contains("403 Forbidden") && r_non_allow.contains("IP Access Denied"), "{r_non_allow}");

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
        assert!(blocked.starts_with("HTTP/1.1 403 Forbidden") && blocked.contains("Hotlink Protection"), "{blocked}");

        let allowed_same = run_request(
            &state,
            false,
            "GET /logo.png HTTP/1.1\r\nHost: site.test\r\nReferer: https://www.site.test/anasayfa\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(allowed_same.starts_with("HTTP/1.1 200 OK") && allowed_same.contains("PNGDATA"), "{allowed_same}");

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
        assert!(webp.contains("Content-Type: image/webp") && webp.ends_with("WEBP_OPT"), "{webp}");

        let jpeg = run_request(
            &state,
            false,
            "GET /foto.jpg HTTP/1.1\r\nHost: site.test\r\nAccept: image/png,*/*\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(jpeg.contains("Content-Type: image/jpeg") && jpeg.ends_with("JPEG_RAW"), "{jpeg}");

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
        let cfg = "[cache]\nenabled = true\ndefault_ttl_seconds = 60\nstale_while_revalidate_sec = 30\n";
        let state = test_state_with("swr_static", false, cfg);
        {
            let mut rt = state.runtime.write().await;
            rt.vhosts[0].entry.cache.enabled = true;
        }

        let key = zmax_cache::build_cache_key("site.test", false, "GET", "/index.html", "", Some("identity"));
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

        tokio::time::sleep(Duration::from_millis(120)).await;

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
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nPONG")
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
        assert!(r1.starts_with("HTTP/1.1 200 OK") && r1.ends_with("PONG"), "{r1}");
        assert_eq!(state.upstream_pool.idle_count(&up_addr), 1);

        let r2 = run_request(
            &state,
            false,
            "GET /api/ping HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(r2.starts_with("HTTP/1.1 200 OK") && r2.ends_with("PONG"), "{r2}");
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
        let t_ui = tokio::spawn(async move {
            handle_admin_connection(server_ui, peer, st_ui, false).await
        });
        client_ui
            .write_all(b"GET /zmax-panel/index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        client_ui.shutdown().await.unwrap();
        let mut out_ui = Vec::new();
        client_ui.read_to_end(&mut out_ui).await.unwrap();
        t_ui.await.unwrap().unwrap();
        let ui_str = String::from_utf8_lossy(&out_ui);
        assert!(ui_str.starts_with("HTTP/1.1 200 OK") && ui_str.contains("ADMIN_UI"), "{ui_str}");

        let (mut client_api, server_api) = tokio::io::duplex(64 * 1024);
        let st_api = Arc::clone(&state);
        let t_api = tokio::spawn(async move {
            handle_admin_connection(server_api, peer, st_api, true).await
        });
        client_api
            .write_all(b"GET /zmax-panel/api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        client_api.shutdown().await.unwrap();
        let mut out_api = Vec::new();
        client_api.read_to_end(&mut out_api).await.unwrap();
        t_api.await.unwrap().unwrap();
        let api_str = String::from_utf8_lossy(&out_api);
        assert!(api_str.starts_with("HTTP/1.1 200 OK") && api_str.contains("\"status\":\"ok\""), "{api_str}");

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
        let t_local = tokio::spawn(async move {
            handle_api_connection(s_local, local_peer, st_local).await
        });
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
        assert!(remote_str.starts_with("HTTP/1.1 403 Forbidden"), "{remote_str}");

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    fn test_state_two_vhosts(tag: &str) -> Arc<ServerState> {
        let base = std::env::temp_dir().join(format!("zmax_bin_2vh_{}_{}", tag, std::process::id()));
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
        entry_a.error_docs.enabled = true; // web_engine özel hata sayfasını yalnız [vhost.error_docs] enabled=true iken sunar
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
        let auth = compute_effective_auth(&cfg, None);

        Arc::new(ServerState {
            base_dir: base.clone(),
            cache: zmax_cache::ZMaxCache::with_disk_dir(
                16 * 1024 * 1024,
                60,
                base.join("cachedata"),
            ),
            limiter: RwLock::new(zmax_security::RateLimiter::new(u32::MAX)),
            conn_limiter: Arc::new(zmax_security::ConnLimiter::new(0, Vec::new())),
            backend_semaphores: dashmap::DashMap::new(),
            ban_manager: Arc::new(zmax_security::IpBanManager::new()),
            wp_guard: Arc::new(zmax_security::WpBruteForceGuard::new(3, 60, 300)),
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
            admin_static_handler: RwLock::new(zmax_static::StaticFileHandler::new(base.join("admin"))),
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
        let r1 = run_request(&state, false, "GET / HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n").await;
        assert!(r1.starts_with("HTTP/1.1 200 OK") && r1.contains("VHOST_A_BODY_12345"), "{r1}");

        let r2 = run_request(&state, false, "GET / HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n").await;
        assert!(r2.starts_with("HTTP/1.1 200 OK") && r2.contains("VHOST_B_BODY_67890"), "{r2}");

        tokio::time::sleep(Duration::from_millis(50)).await;
        state.log_manager.flush().await;

        let log_a = state.base_dir.join("logs").join("vhost-a.access.log");
        let log_b = state.base_dir.join("logs").join("vhost-b.access.log");
        assert!(log_a.is_file(), "vhost-a log dosyasi olusmali");
        assert!(log_b.is_file(), "vhost-b log dosyasi olusmali");

        let content_a = std::fs::read_to_string(&log_a).unwrap();
        let content_b = std::fs::read_to_string(&log_b).unwrap();

        let line_a = content_a.lines().next().unwrap_or("");
        assert!(line_a.contains("GET / HTTP/1.1"), "Istek satiri bulunmali: {line_a}");
        assert!(line_a.contains("[") && line_a.contains("]"), "Zaman damgasi olmali: {line_a}");
        let parts_a: Vec<&str> = line_a.split_whitespace().collect();
        let status_idx_a = parts_a.iter().position(|&p| p == "200").expect("200 status kodu bulunmali");
        let bytes_sent_a: usize = parts_a[status_idx_a + 1].parse().expect("Sayisal bayt degeri olmali");
        assert_eq!(bytes_sent_a, 18, "vhost-a govde uzunlugu (VHOST_A_BODY_12345 = 18 bayt) olmali: {line_a}");
        assert!(!line_a.contains(" 200 - "), "'-' bayt reddedilmeli");
        assert!(!line_a.contains(" 200 0 "), "'0' bayt reddedilmeli");

        let line_b = content_b.lines().next().unwrap_or("");
        let parts_b: Vec<&str> = line_b.split_whitespace().collect();
        let status_idx_b = parts_b.iter().position(|&p| p == "200").expect("200 status kodu bulunmali");
        let bytes_sent_b: usize = parts_b[status_idx_b + 1].parse().expect("Sayisal bayt degeri olmali");
        assert_eq!(bytes_sent_b, 18, "vhost-b govde uzunlugu (VHOST_B_BODY_67890 = 18 bayt) olmali: {line_b}");

        // reopen_all cagir ve yeni log satirini dogrula
        state.log_manager.reopen_all().await;
        let r3 = run_request(&state, false, "GET / HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n").await;
        assert!(r3.starts_with("HTTP/1.1 200 OK"));
        tokio::time::sleep(Duration::from_millis(50)).await;
        state.log_manager.flush().await;

        let content_a2 = std::fs::read_to_string(&log_a).unwrap();
        assert_eq!(content_a2.lines().count(), 2, "reopen_all sonrasi yeni satirlar yazilmali");

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn vhost_custom_error_docs_404_vs_default() {
        let state = test_state_two_vhosts("err_docs");
        let r_a = run_request(&state, false, "GET /yok-sayfa.html HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n").await;
        assert!(r_a.starts_with("HTTP/1.1 404 Not Found"), "{r_a}");
        assert!(r_a.contains("CUSTOM_404_PAGE_FOR_VHOST_A"), "vhost-a ozel 404 sayfasi dondurmelidir: {r_a}");

        let r_b = run_request(&state, false, "GET /yok-sayfa.html HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n").await;
        assert!(r_b.starts_with("HTTP/1.1 404 Not Found"), "{r_b}");
        assert!(!r_b.contains("CUSTOM_404_PAGE_FOR_VHOST_A"), "vhost-b varsayilan sayfa dondurmelidir: {r_b}");
        assert!(r_b.contains("404 Not Found") || r_b.contains("Sayfa Bulunamadı") || r_b.contains("ZMax"), "{r_b}");

        let _ = std::fs::remove_dir_all(&state.base_dir);
    }

    #[tokio::test]
    async fn vhost_per_domain_waf_policy_and_exclude_paths() {
        let state = test_state_two_vhosts("waf_policy");
        // vhost-a WAF acik -> 403 Forbidden
        let r_a_attack = run_request(&state, false, "GET /?q=union+select+1,2,3 HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n").await;
        assert!(r_a_attack.starts_with("HTTP/1.1 403 Forbidden"), "vhost-a WAF saldiriyi engellemeli: {r_a_attack}");

        // vhost-a muaf yol -> 403 olmamali
        let r_a_exempt = run_request(&state, false, "GET /muaf-yol?q=union+select+1,2,3 HTTP/1.1\r\nHost: vhost-a.test\r\n\r\n").await;
        assert!(!r_a_exempt.starts_with("HTTP/1.1 403 Forbidden"), "vhost-a muaf yol engellenmemeli: {r_a_exempt}");

        // vhost-b WAF kapali -> 200 OK (engellenmemeli)
        let r_b_attack = run_request(&state, false, "GET /?q=union+select+1,2,3 HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n").await;
        assert!(r_b_attack.starts_with("HTTP/1.1 200 OK"), "vhost-b WAF kapali oldugu icin gecmeli: {r_b_attack}");

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

        let (mut client, h2_conn) = h2::client::handshake(client_io).await.expect("h2 client handshake");
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
        assert_eq!(parts.status, http::StatusCode::OK, "HTTP/2 yaniti 200 OK olmalidir");

        let mut body_buf = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let b = chunk.expect("h2 data chunk");
            body_buf.extend_from_slice(&b);
            let _ = body_stream.flow_control().release_capacity(b.len());
        }
        let body_str = String::from_utf8_lossy(&body_buf);
        assert!(body_str.contains("VHOST_A_BODY_12345"), "HTTP/2 govdesi dogru donmeli: {body_str}");

        // 2. Eşzamanlı HTTP/1.1 isteği etkilenmemeli ve doğru dönmeli
        let r_h1 = run_request(&state, false, "GET / HTTP/1.1\r\nHost: vhost-b.test\r\n\r\n").await;
        assert!(r_h1.starts_with("HTTP/1.1 200 OK") && r_h1.contains("VHOST_B_BODY_67890"), "HTTP/1.1 etkilenmemeli: {r_h1}");

        let _ = h2_srv;
        let _ = std::fs::remove_dir_all(&state.base_dir);
    }
}
