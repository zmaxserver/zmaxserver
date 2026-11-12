use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};
use tokio_rustls::TlsConnector;

const TEST_HTTP_PORT: u16 = 21100;
const TEST_HTTPS_PORT: u16 = 21101;
const TEST_API_PORT: u16 = 21102;
const TEST_ADMIN_PORT: u16 = 21103;

static PORT_BLOCK_LOCK: Mutex<()> = Mutex::const_new(());

struct ZMaxProcessGuard {
    child: Child,
    base_dir: PathBuf,
}

impl Drop for ZMaxProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

async fn read_http_head<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 512];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .expect("HTTP basligi okunurken zaman asimi")
            .expect("HTTP basligi okuma hatasi");
        assert!(n > 0, "HTTP basligi bitmeden baglanti kapandi");
        buf.extend_from_slice(&tmp[..n]);
    }
    buf
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn read_http_response_complete<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut raw = Vec::with_capacity(2048);
    let mut tmp = [0u8; 1024];
    let head_end = loop {
        if let Some(pos) = find_header_end(&raw) {
            break pos;
        }
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
            .await
            .expect("HTTP yanit basligi zaman asimi")
            .expect("HTTP yanit okuma hatasi");
        assert!(n > 0, "Yanit basligi gelmeden soket kapandi");
        raw.extend_from_slice(&tmp[..n]);
    };

    let head_str = String::from_utf8_lossy(&raw[..head_end]).into_owned();
    let content_len = head_str.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse::<usize>().ok()
        } else {
            None
        }
    });

    if let Some(cl) = content_len {
        let total = head_end + cl;
        while raw.len() < total {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
                .await
                .expect("Content-Length govde okuma zaman asimi")
                .expect("Content-Length govde okuma hatasi");
            assert!(n > 0, "Govde tamamlanmadan soket kapandi");
            raw.extend_from_slice(&tmp[..n]);
        }
        raw.truncate(total);
    } else {
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut tmp))
                .await
                .expect("Govde EOF okuma zaman asimi")
                .expect("Govde okuma hatasi");
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&tmp[..n]);
        }
    }

    String::from_utf8_lossy(&raw).into_owned()
}

fn encode_ws_masked_text_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mask = [0x37u8, 0xFA, 0x21, 0x3D];
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.push(0x81); // FIN + Text opcode
    frame.push(0x80 | (payload.len() as u8));
    frame.extend_from_slice(&mask);
    for (idx, b) in payload.iter().enumerate() {
        frame.push(b ^ mask[idx % 4]);
    }
    frame
}

async fn read_ws_masked_text_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0] & 0x0f, 0x01, "WS text frame bekleniyordu");
    assert_ne!(hdr[1] & 0x80, 0, "Istemci WS frame maskeli olmali");
    let len = (hdr[1] & 0x7f) as usize;
    assert!(len < 126);
    let mut mask = [0u8; 4];
    stream.read_exact(&mut mask).await.unwrap();
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await.unwrap();
    for (idx, b) in data.iter_mut().enumerate() {
        *b ^= mask[idx % 4];
    }
    data
}

fn encode_ws_unmasked_text_frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 126);
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x81);
    frame.push(payload.len() as u8);
    frame.extend_from_slice(payload);
    frame
}

async fn read_ws_unmasked_text_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0] & 0x0f, 0x01, "Sunucu WS text frame bekleniyordu");
    assert_eq!(hdr[1] & 0x80, 0, "Sunucu WS frame maskesiz olmali");
    let len = (hdr[1] & 0x7f) as usize;
    assert!(len < 126);
    let mut data = vec![0u8; len];
    stream.read_exact(&mut data).await.unwrap();
    data
}

fn write_test_workspace(
    base_dir: &Path,
    xff_upstream: &str,
    https_upstream: &str,
    sse_upstream: &str,
    ws_upstream: &str,
    timeout_upstream: &str,
) -> rustls::pki_types::CertificateDer<'static> {
    std::fs::create_dir_all(base_dir.join("conf").join("vhosts")).unwrap();
    std::fs::create_dir_all(base_dir.join("modules")).unwrap();
    std::fs::create_dir_all(base_dir.join("admin")).unwrap();
    std::fs::create_dir_all(base_dir.join("www").join("html")).unwrap();
    std::fs::create_dir_all(base_dir.join("certs")).unwrap();
    std::fs::create_dir_all(base_dir.join("logs")).unwrap();
    std::fs::write(base_dir.join("admin").join("index.html"), "ADMIN").unwrap();
    std::fs::write(
        base_dir.join("www").join("html").join("index.html"),
        "DEFAULT",
    )
    .unwrap();

    // HTTPS vHost icin kendinden imzali test sertifikasi
    let ck = rcgen::generate_simple_self_signed(vec![
        "https.kart10.test".to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap();
    let cert_der = ck.cert.der().clone();
    std::fs::write(base_dir.join("certs").join("https.pem"), ck.cert.pem()).unwrap();
    std::fs::write(
        base_dir.join("certs").join("https.key"),
        ck.signing_key.serialize_pem(),
    )
    .unwrap();

    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax-Kart10-Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {TEST_HTTP_PORT}

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {TEST_HTTPS_PORT}
ssl = true

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {TEST_API_PORT}

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {TEST_ADMIN_PORT}
document_root = "admin"

[security]
rate_limit_enabled = false
waf_enabled = false

[cache]
enabled = false

[vhosts_dir]
path = "conf/vhosts"
"#
    );
    std::fs::write(base_dir.join("conf").join("zmax.toml"), zmax_toml).unwrap();

    let mod_proxy = r#"[module]
name = "mod_proxy"
version = "1.0.0"
category = "Proxy"
enabled = true

[settings]
preserve_host = true
websocket_upgrade = true
connect_timeout_sec = 5
"#;
    std::fs::write(base_dir.join("modules").join("mod_proxy.toml"), mod_proxy).unwrap();

    let vhost_configs = [
        (
            "01-xff.toml",
            format!(
                r#"[vhost]
name = "xff.kart10.test"
document_root = "www/html"

[vhost.php]
enabled = false

[vhost.proxy]
enabled = true
upstream = "{xff_upstream}"
path_prefix = "/"
preserve_host = true
websocket = false

[vhost.proxy_ext]
init_timeout_sec = 10
keep_alive_timeout_sec = 60
resp_buffer = false
"#
            ),
        ),
        (
            "02-https.toml",
            format!(
                r#"[vhost]
name = "https.kart10.test"
document_root = "www/html"

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "certs/https.pem"
key = "certs/https.key"

[vhost.proxy]
enabled = true
upstream = "{https_upstream}"
path_prefix = "/"
preserve_host = true
websocket = true

[vhost.proxy_ext]
init_timeout_sec = 10
keep_alive_timeout_sec = 60
resp_buffer = false
"#
            ),
        ),
        (
            "03-sse.toml",
            format!(
                r#"[vhost]
name = "sse.kart10.test"
document_root = "www/html"

[vhost.php]
enabled = false

[vhost.proxy]
enabled = true
upstream = "{sse_upstream}"
path_prefix = "/"
preserve_host = true
websocket = false

[vhost.proxy_ext]
init_timeout_sec = 15
keep_alive_timeout_sec = 60
resp_buffer = false
"#
            ),
        ),
        (
            "04-ws.toml",
            format!(
                r#"[vhost]
name = "ws.kart10.test"
document_root = "www/html"

[vhost.php]
enabled = false

[vhost.proxy]
enabled = true
upstream = "{ws_upstream}"
path_prefix = "/"
preserve_host = true
websocket = true

[vhost.proxy_ext]
init_timeout_sec = 15
keep_alive_timeout_sec = 60
resp_buffer = false
"#
            ),
        ),
        (
            "05-timeout.toml",
            format!(
                r#"[vhost]
name = "timeout.kart10.test"
document_root = "www/html"

[vhost.php]
enabled = false

[vhost.proxy]
enabled = true
upstream = "{timeout_upstream}"
path_prefix = "/"
preserve_host = true
websocket = false

[vhost.proxy_ext]
init_timeout_sec = 1
keep_alive_timeout_sec = 30
connect_timeout_sec = 2
resp_buffer = false
"#
            ),
        ),
    ];

    for (fname, content) in vhost_configs {
        std::fs::write(base_dir.join("conf").join("vhosts").join(fname), content).unwrap();
    }

    cert_der
}

async fn spawn_zmax_and_wait_ready(base_dir: &Path) -> ZMaxProcessGuard {
    let exe_path = env!("CARGO_BIN_EXE_zmax");
    let conf_path = base_dir.join("conf").join("zmax.toml");
    let mut child = Command::new(exe_path)
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", base_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("zmax ikilisi baslatilamadi");

    let stdout = child.stdout.take().expect("stdout pipe alinamadi");
    let stderr = child.stderr.take().expect("stderr pipe alinamadi");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        while let Ok(n) = reader.read_line(&mut line) {
            if n == 0 {
                break;
            }
            line.clear();
        }
    });

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut tx = Some(ready_tx);
        let mut log_buf = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    if let Some(sender) = tx.take() {
                        let _ = sender.send(Err(format!(
                            "zmax hazir olmadan sonlandi. stdout:\n{log_buf}"
                        )));
                    }
                    break;
                }
                Ok(_) => {
                    if log_buf.len() < 4096 {
                        log_buf.push_str(&line);
                    }
                    if line.contains("hazir!") {
                        if let Some(sender) = tx.take() {
                            let _ = sender.send(Ok(()));
                        }
                    }
                }
                Err(e) => {
                    if let Some(sender) = tx.take() {
                        let _ = sender.send(Err(format!("stdout okuma hatasi: {e}")));
                    }
                    break;
                }
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(10), ready_rx).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(msg))) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(base_dir);
            panic!("zmax baslatma hatasi: {msg}");
        }
        Ok(Err(_)) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(base_dir);
            panic!("zmax hazir kanali beklenmedik sekilde kapandi");
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(base_dir);
            panic!("zmax 10 saniye icinde hazir durumuna gecmedi");
        }
    }

    ZMaxProcessGuard {
        child,
        base_dir: base_dir.to_path_buf(),
    }
}

#[tokio::test]
async fn kart10_e2e_reverse_proxy_xff_https_sse_websocket_and_timeout() {
    let _guard = PORT_BLOCK_LOCK.lock().await;

    // 1. Sahte XFF + Keep-Alive backend
    let xff_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let xff_addr = xff_listener.local_addr().unwrap().to_string();
    let xff_accepts = Arc::new(AtomicUsize::new(0));
    let xff_accepts_srv = Arc::clone(&xff_accepts);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = xff_listener.accept().await {
            xff_accepts_srv.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                loop {
                    let mut buf = Vec::with_capacity(2048);
                    let mut tmp = [0u8; 512];
                    loop {
                        let n = match sock.read(&mut tmp).await {
                            Ok(0) => return,
                            Ok(n) => n,
                            Err(_) => return,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if find_header_end(&buf).is_some() {
                            break;
                        }
                    }
                    let req = String::from_utf8_lossy(&buf).into_owned();
                    let body = format!("OK|{}", req.replace("\r\n", "|"));
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    if sock.write_all(resp.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = sock.flush().await;
                }
            });
        }
    });

    // 2. Sahte HTTPS backend
    let https_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_addr = https_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = https_listener.accept().await {
            tokio::spawn(async move {
                let req_bytes = read_http_head(&mut sock).await;
                let req = String::from_utf8_lossy(&req_bytes).into_owned();
                let body = req.replace("\r\n", "|");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.flush().await;
            });
        }
    });

    // 3. Sahte SSE backend (ilk heartbeat hemen gonderilir, Notify ile istemcinin aldigini bekler)
    let sse_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sse_addr = sse_listener.local_addr().unwrap().to_string();
    let sse_first_received = Arc::new(Notify::new());
    let sse_srv_wait = Arc::clone(&sse_first_received);
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = sse_listener.accept().await {
            let _req = read_http_head(&mut sock).await;
            let head_and_hb1 = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream; charset=utf-8\r\n",
                "Cache-Control: no-cache\r\n",
                "Transfer-Encoding: chunked\r\n\r\n",
                "f\r\n: heartbeat 1\n\n\r\n"
            );
            sock.write_all(head_and_hb1.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();

            // Istemci 1. heartbeat parcasini gercekten okuyana dek akisi acik tut
            sse_srv_wait.notified().await;

            let hb2_and_end = "d\r\ndata: bitti\n\n\r\n0\r\n\r\n";
            sock.write_all(hb2_and_end.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        }
    });

    // 4. Sahte WebSocket yankı backend
    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = ws_listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = ws_listener.accept().await {
            let req_bytes = read_http_head(&mut sock).await;
            let req_str = String::from_utf8_lossy(&req_bytes);
            assert!(
                req_str.contains("Upgrade: websocket\r\n"),
                "WS Upgrade eksik: {req_str}"
            );
            assert!(
                req_str.contains("X-Forwarded-For: 192.0.2.99, 127.0.0.1\r\n"),
                "WS X-Forwarded-For append eksik: {req_str}"
            );

            let resp101 = concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
            );
            sock.write_all(resp101.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();

            let msg = read_ws_masked_text_frame(&mut sock).await;
            let echo_frame = encode_ws_unmasked_text_frame(&msg);
            sock.write_all(&echo_frame).await.unwrap();
            sock.flush().await.unwrap();
        }
    });

    // 5. Sahte yavas backend (init_timeout_sec = 1 testi)
    let timeout_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let timeout_addr = timeout_listener.local_addr().unwrap().to_string();
    let timeout_release = Arc::new(Notify::new());
    let timeout_srv_wait = Arc::clone(&timeout_release);
    tokio::spawn(async move {
        if let Ok((_sock, _)) = timeout_listener.accept().await {
            timeout_srv_wait.notified().await;
        }
    });

    // Test çalışma dizini & gerçek zmax başlatma (portlar 21100-21103)
    let base_dir = std::env::temp_dir().join(format!("zmax_kart10_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base_dir);
    let cert_der = write_test_workspace(
        &base_dir,
        &xff_addr,
        &https_addr,
        &sse_addr,
        &ws_addr,
        &timeout_addr,
    );
    let _zmax = spawn_zmax_and_wait_ready(&base_dir).await;

    // --- Senaryo A: HTTP X-Forwarded-For append + cift yonlu Keep-Alive (istemci & upstream havuz) ---
    {
        let mut client = TcpStream::connect(("127.0.0.1", TEST_HTTP_PORT))
            .await
            .unwrap();
        let req1 = concat!(
            "GET /one HTTP/1.1\r\n",
            "Host: xff.kart10.test\r\n",
            "X-Forwarded-For: 10.20.30.40\r\n\r\n"
        );
        client.write_all(req1.as_bytes()).await.unwrap();
        let resp1 = read_http_response_complete(&mut client).await;
        assert!(resp1.starts_with("HTTP/1.1 200 OK"), "{resp1}");
        assert!(
            resp1.contains("X-Forwarded-For: 10.20.30.40, 127.0.0.1"),
            "XFF append basarisiz: {resp1}"
        );
        assert!(
            resp1.contains("X-Forwarded-Proto: http"),
            "X-Forwarded-Proto http olmali: {resp1}"
        );
        assert!(
            resp1.contains("X-Forwarded-Host: xff.kart10.test"),
            "X-Forwarded-Host eksik: {resp1}"
        );

        // Ayni istemci TCP baglantisindan 2. istek: istemci + upstream keep-alive birlikte calismali
        let req2 = concat!(
            "GET /two HTTP/1.1\r\n",
            "Host: xff.kart10.test\r\n",
            "X-Forwarded-For: 1.1.1.1, 2.2.2.2\r\n",
            "Connection: close\r\n\r\n"
        );
        client.write_all(req2.as_bytes()).await.unwrap();
        let resp2 = read_http_response_complete(&mut client).await;
        assert!(resp2.starts_with("HTTP/1.1 200 OK"), "{resp2}");
        assert!(
            resp2.contains("X-Forwarded-For: 1.1.1.1, 2.2.2.2, 127.0.0.1"),
            "Coklu XFF append basarisiz: {resp2}"
        );
        assert_eq!(
            xff_accepts.load(Ordering::SeqCst),
            1,
            "Upstream keep-alive havuzu tek TCP baglantisini yeniden kullanmali"
        );
    }

    // --- Senaryo B: HTTPS (21101) uzerinden X-Forwarded-Proto: https, X-Forwarded-Host ve XFF append ---
    {
        let mut root_store = RootCertStore::empty();
        root_store.add(cert_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls_cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls_cfg));

        let tcp = TcpStream::connect(("127.0.0.1", TEST_HTTPS_PORT))
            .await
            .unwrap();
        let server_name = ServerName::try_from("https.kart10.test").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();

        let req = concat!(
            "GET /panel HTTP/1.1\r\n",
            "Host: https.kart10.test\r\n",
            "X-Forwarded-For: 198.51.100.77\r\n",
            "X-Forwarded-Proto: http\r\n",
            "Connection: close\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        let resp = read_http_response_complete(&mut tls).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(
            resp.contains("X-Forwarded-Proto: https"),
            "HTTPS'te X-Forwarded-Proto: https zorunlu: {resp}"
        );
        assert!(
            resp.contains("X-Forwarded-Host: https.kart10.test"),
            "HTTPS'te X-Forwarded-Host eksik: {resp}"
        );
        assert!(
            resp.contains("X-Forwarded-For: 198.51.100.77, 127.0.0.1"),
            "HTTPS XFF append hatali: {resp}"
        );
    }

    // --- Senaryo C: SSE (respBuffer 0) gecikmesiz parca iletimi (<= 1 sn) ---
    {
        let mut client = TcpStream::connect(("127.0.0.1", TEST_HTTP_PORT))
            .await
            .unwrap();
        let req = concat!(
            "GET /events HTTP/1.1\r\n",
            "Host: sse.kart10.test\r\n",
            "Accept: text/event-stream\r\n",
            "Connection: close\r\n\r\n"
        );
        let started = Instant::now();
        client.write_all(req.as_bytes()).await.unwrap();

        let mut received = Vec::with_capacity(1024);
        let mut tmp = [0u8; 512];
        while !String::from_utf8_lossy(&received).contains(": heartbeat 1") {
            let n = tokio::time::timeout(Duration::from_secs(1), client.read(&mut tmp))
                .await
                .expect("SSE ilk heartbeat parcasi 1 saniye icinde istemciye ulasmali")
                .unwrap();
            assert!(n > 0, "Ilk heartbeat gelmeden SSE akisi kesildi");
            received.extend_from_slice(&tmp[..n]);
        }
        assert!(
            started.elapsed() <= Duration::from_secs(1),
            "SSE gecikmesi 1 saniyeyi asti: {:?}",
            started.elapsed()
        );

        // Ilk parca alindi -> arka uca 2. parcayi gondermesi ve bitirmesi icin sinyal ver
        sse_first_received.notify_one();

        while !String::from_utf8_lossy(&received).contains("data: bitti") {
            let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut tmp))
                .await
                .expect("SSE ikinci parcasi zaman asimi")
                .unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&tmp[..n]);
        }
        let full = String::from_utf8_lossy(&received);
        assert!(full.contains("Content-Type: text/event-stream"), "{full}");
        assert!(full.contains(": heartbeat 1"), "{full}");
        assert!(full.contains("data: bitti"), "{full}");
    }

    // --- Senaryo D: WebSocket Upgrade el sikismasi ve yanki (echo) testi ---
    {
        let mut client = TcpStream::connect(("127.0.0.1", TEST_HTTP_PORT))
            .await
            .unwrap();
        let hs_req = concat!(
            "GET /ws/shell HTTP/1.1\r\n",
            "Host: ws.kart10.test\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            "Sec-WebSocket-Version: 13\r\n",
            "X-Forwarded-For: 192.0.2.99\r\n\r\n"
        );
        client.write_all(hs_req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        // 101 yanitini oku
        let mut resp_buf = Vec::new();
        let mut tmp = [0u8; 512];
        while !resp_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(3), client.read(&mut tmp))
                .await
                .expect("WS 101 yanit zaman asimi")
                .unwrap();
            assert!(n > 0);
            resp_buf.extend_from_slice(&tmp[..n]);
        }
        let head_end = find_header_end(&resp_buf).unwrap();
        let hs_resp = String::from_utf8_lossy(&resp_buf[..head_end]);
        assert!(hs_resp.starts_with("HTTP/1.1 101"), "{hs_resp}");
        assert!(
            hs_resp.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            "{hs_resp}"
        );

        // Gercek RFC 6455 masked text frame gonder ve unmasked yanki al
        let payload = b"ZMax Kart10 WS Yanki";
        let frame = encode_ws_masked_text_frame(payload);
        client.write_all(&frame).await.unwrap();
        client.flush().await.unwrap();

        let echoed = tokio::time::timeout(
            Duration::from_secs(3),
            read_ws_unmasked_text_frame(&mut client),
        )
        .await
        .expect("WS yanki zaman asimi");
        assert_eq!(echoed, payload);
    }

    // --- Senaryo E: init_timeout_sec = 1 zaman asimi (504 Gateway Timeout) ---
    {
        let mut client = TcpStream::connect(("127.0.0.1", TEST_HTTP_PORT))
            .await
            .unwrap();
        let req = concat!(
            "GET /hang HTTP/1.1\r\n",
            "Host: timeout.kart10.test\r\n",
            "Connection: close\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let resp = read_http_response_complete(&mut client).await;
        assert!(
            resp.starts_with("HTTP/1.1 504 Gateway Timeout"),
            "init_timeout_sec=1 dolunca 504 donmeli: {resp}"
        );
        timeout_release.notify_one();
    }

    // --- Senaryo F: P0 Request Smuggling Korumasi (Chunked / TE filtresi) ---
    {
        let mut client = TcpStream::connect(("127.0.0.1", TEST_HTTP_PORT))
            .await
            .unwrap();
        // Smuggled istegi taklit eden govde: Cozulunce "0\r\n\r\nGET /smuggled..." olusur
        let smuggled_data = "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: xff.kart10.test\r\n\r\n";
        let chunked_payload = format!("{:x}\r\n{}\r\n0\r\n\r\n", smuggled_data.len(), smuggled_data);
        let req = format!(
            "POST /submit HTTP/1.1\r\nHost: xff.kart10.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{}",
            chunked_payload
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let resp = read_http_response_complete(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "Smuggling testi 200 donmeli: {resp}");
        // Upstream'e giden istekte Transfer-Encoding basligi kesinlikle DUSURULMUS olmali!
        assert!(!resp.contains("Transfer-Encoding:"), "Upstream'e Transfer-Encoding basligi gitmemeli: {resp}");
        // Govde cozulmus olarak tek bir parca halinde Content-Length ile iletilmeli
        let expected_cl = format!("content-length: {}", smuggled_data.len());
        let expected_cl_upper = format!("Content-Length: {}", smuggled_data.len());
        assert!(
            resp.contains(&expected_cl) || resp.contains(&expected_cl_upper),
            "Upstream Content-Length basligi gormeli (beklenen: {}): {resp}",
            smuggled_data.len()
        );
    }

    // --- Senaryo G: RFC 9110 Hop-by-hop Baslik Temizligi ---
    {
        let mut client = TcpStream::connect(("127.0.0.1", TEST_HTTP_PORT))
            .await
            .unwrap();
        let req = concat!(
            "GET /hop-by-hop-test HTTP/1.1\r\n",
            "Host: xff.kart10.test\r\n",
            "Connection: close, X-Hop-Custom\r\n",
            "X-Hop-Custom: gizli-deger\r\n",
            "Keep-Alive: timeout=5\r\n",
            "Proxy-Connection: keep-alive\r\n",
            "TE: trailers\r\n",
            "Trailer: X-Checksum\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.flush().await.unwrap();

        let resp = read_http_response_complete(&mut client).await;
        assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
        assert!(!resp.contains("X-Hop-Custom:"), "Connection'da listelenen baslik upstream'e gecmemeli: {resp}");
        assert!(!resp.contains("Keep-Alive:"), "Keep-Alive upstream'e gecmemeli: {resp}");
        assert!(!resp.contains("Proxy-Connection:"), "Proxy-Connection upstream'e gecmemeli: {resp}");
        assert!(!resp.contains("TE:"), "TE upstream'e gecmemeli: {resp}");
        assert!(!resp.contains("Trailer:"), "Trailer upstream'e gecmemeli: {resp}");
    }

    // --- Senaryo H: HTTP/2 TLS ALPN h2 Uzerinden Ters Vekil Istegi ---
    {
        let mut root_store = RootCertStore::empty();
        root_store.add(cert_der.clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut h2_cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        h2_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(h2_cfg));

        let tcp = TcpStream::connect(("127.0.0.1", TEST_HTTPS_PORT))
            .await
            .unwrap();
        let server_name = ServerName::try_from("https.kart10.test").unwrap();
        let tls = connector.connect(server_name, tcp).await.unwrap();

        let (mut client, h2_conn) = h2::client::handshake(tls).await.unwrap();
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let req = http::Request::builder()
            .method("GET")
            .uri("https://https.kart10.test/h2-proxy-test")
            .header("Host", "https.kart10.test")
            .body(())
            .unwrap();
        let (response, _send_stream) = client.send_request(req, true).unwrap();
        let (head, mut body) = response.await.unwrap().into_parts();
        assert_eq!(head.status, 200);

        let mut body_bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let data = chunk.unwrap();
            body_bytes.extend_from_slice(&data);
        }
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(
            body_str.contains("X-Forwarded-Proto: https"),
            "H2 vekil isteginde X-Forwarded-Proto: https olmali: {body_str}"
        );
        assert!(
            body_str.contains("X-Forwarded-Host: https.kart10.test"),
            "H2 vekil isteginde X-Forwarded-Host olmali: {body_str}"
        );
    }
}

#[test]
fn kart10_config_loads_proxy_ext_from_vhosts_dir() {
    let base = std::env::temp_dir().join(format!("zmax_kart10_cfg_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let vhosts_dir = base.join("conf").join("vhosts");
    std::fs::create_dir_all(&vhosts_dir).unwrap();
    std::fs::create_dir_all(base.join("www").join("panel")).unwrap();

    let toml_content = r#"[vhost]
name = "panel.local.test"
document_root = "www/panel"

[vhost.proxy]
enabled = true
upstream = "127.0.0.1:8026"
path_prefix = "/"
preserve_host = true
websocket = true

[vhost.proxy_ext]
init_timeout_sec = 300
keep_alive_timeout_sec = 60
connect_timeout_sec = 10
resp_buffer = false
max_conns = 128
"#;
    std::fs::write(vhosts_dir.join("panel.toml"), toml_content).unwrap();

    let loaded = zmax_config::load_vhosts_dir(&vhosts_dir, &base).unwrap();
    assert_eq!(loaded.len(), 1);
    let vh = &loaded[0].entry;
    assert_eq!(vh.proxy.upstream, "127.0.0.1:8026");
    assert_eq!(vh.proxy_ext.init_timeout_sec, 300);
    assert_eq!(vh.proxy_ext.keep_alive_timeout_sec, 60);
    assert_eq!(vh.proxy_ext.connect_timeout_sec, 10);
    assert!(!vh.proxy_ext.resp_buffer);
    assert_eq!(vh.proxy_ext.max_conns, 128);
    assert!(vh.validate().is_ok());

    let proxy = zmax_proxy::ReverseProxy::new(&vh.proxy.upstream)
        .with_init_timeout(Duration::from_secs(vh.proxy_ext.init_timeout_sec))
        .with_keep_alive_timeout(Duration::from_secs(vh.proxy_ext.keep_alive_timeout_sec))
        .with_resp_buffer(vh.proxy_ext.resp_buffer)
        .with_preserve_host(vh.proxy.preserve_host)
        .with_max_conns(vh.proxy_ext.max_conns);
    assert_eq!(proxy.init_timeout(), Duration::from_secs(300));
    assert_eq!(proxy.keep_alive_timeout(), Duration::from_secs(60));
    assert!(!proxy.resp_buffer());
    assert_eq!(proxy.max_conns(), 128);

    let _ = std::fs::remove_dir_all(&base);
}
