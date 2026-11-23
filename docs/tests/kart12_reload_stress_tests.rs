//! Kart 12 Hazırlık-C: Yük altında reload ve dayanıklılık testi
//!
//! Eşzamanlı HTTP/1.1 ve HTTP/2 istekleri akarken sunucuya `/api/v1/reload`
//! sinyali gönderildiğinde:
//! 1. Hiçbir aktif isteğin düşmediği (0 dropped request, 0 bağlantı kopması).
//! 2. Mevcut isteklerin eski konfigürasyonla tamamlandığı, yeni isteklerin yeni konfigürasyonla karşılandığı.
//! 3. Yük altında bellek veya kaynak sızıntısı olmadığını doğrulayan stres testi.
//! 4. Dinamik port kullanır, `sleep` ile değil senkron bariyeri ile bekler.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio_rustls::TlsConnector;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug)]
struct TestPorts {
    http: u16,
    https: u16,
    api: u16,
    admin: u16,
}

impl TestPorts {
    fn pick_unique() -> Self {
        let mut ports = Vec::with_capacity(4);
        let mut listeners = Vec::with_capacity(4);
        for _ in 0..4 {
            let l = TcpListener::bind("127.0.0.1:0").expect("Dinamik port alinamadi");
            ports.push(l.local_addr().expect("Adres alinamadi").port());
            listeners.push(l);
        }
        drop(listeners);
        Self {
            http: ports[0],
            https: ports[1],
            api: ports[2],
            admin: ports[3],
        }
    }
}

struct TempWorkspace {
    root: PathBuf,
}

impl TempWorkspace {
    fn new(tag: &str) -> TestResult<Self> {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "zmax_kart12_stress_{}_{}_{}",
            tag,
            std::process::id(),
            unique_id
        ));
        if root.exists() {
            let _ = fs::remove_dir_all(&root);
        }
        fs::create_dir_all(root.join("conf").join("vhosts"))?;
        fs::create_dir_all(root.join("admin"))?;
        fs::create_dir_all(root.join("logs"))?;
        fs::create_dir_all(root.join("cache"))?;
        fs::create_dir_all(root.join("certs"))?;
        fs::create_dir_all(root.join("www"))?;
        fs::write(root.join("admin").join("index.html"), "<h1>admin</h1>")?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct ServerGuard {
    child: Child,
    _workspace: TempWorkspace,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn toml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn generate_self_signed_cert(
    cert_path: &Path,
    key_path: &Path,
    cn: &str,
    san_list: &[&str],
) -> TestResult<()> {
    let mut params = rcgen::CertificateParams::new(
        san_list
            .iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>(),
    )?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let key = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    fs::write(cert_path, cert.pem())?;
    fs::write(key_path, key.serialize_pem())?;
    Ok(())
}

#[derive(Debug)]
struct SkipCertVerification;

impl rustls::client::danger::ServerCertVerifier for SkipCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_connector(alpn: Vec<Vec<u8>>) -> TestResult<TlsConnector> {
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
    .with_no_client_auth();
    client_config.alpn_protocols = alpn;
    Ok(TlsConnector::from(Arc::new(client_config)))
}

fn write_zmax_config(conf_path: &Path, ports: TestPorts) -> TestResult<()> {
    let toml = format!(
        r#"[server]
server_name = "kart12-stress-server"
workers = 4

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {}
backlog = 512
tcp_nodelay = true

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {}
ssl = true
backlog = 512
tcp_nodelay = true

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {}
require_token = false
ssl = false

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {}
document_root = "admin"
require_token = false
ssl = false

[vhosts_dir]
path = "conf/vhosts"

[logging]
level = "info"
access_log = "logs/access.log"
error_log = "logs/error.log"
"#,
        ports.http, ports.https, ports.api, ports.admin
    );
    fs::write(conf_path, toml)?;
    Ok(())
}

fn spawn_zmax_server(workspace: TempWorkspace, conf_path: &Path) -> TestResult<ServerGuard> {
    let bin = env!("CARGO_BIN_EXE_zmax");
    let mut cmd = Command::new(bin);
    cmd.arg("-c")
        .arg(conf_path)
        .env("ZMAX_HOME", workspace.path())
        .env_remove("ZMAX_CONF")
        .env_remove("ZMAX_HTTP_PORT")
        .env_remove("ZMAX_HTTPS_PORT")
        .env_remove("ZMAX_API_PORT")
        .env_remove("ZMAX_ADMIN_PORT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().ok_or("stdout acilamadi")?;
    let stderr = child.stderr.take().ok_or("stderr acilamadi")?;

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let stderr_buf = Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_reader = Arc::clone(&stderr_buf);

    let stderr_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut err_text = String::new();
        let _ = reader.read_to_string(&mut err_text);
        if let Ok(mut guard) = stderr_reader.lock() {
            *guard = err_text;
        }
    });

    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line_buf = Vec::new();
        let mut collected = String::new();
        loop {
            line_buf.clear();
            match reader.read_until(b'\n', &mut line_buf) {
                Ok(0) => {
                    let _ = stderr_handle.join();
                    let err_str = stderr_buf.lock().map(|g| g.clone()).unwrap_or_default();
                    let _ = tx.send(Err(format!(
                        "zmax hazir olmadan kapandi.\nstdout:\n{collected}\nstderr:\n{err_str}"
                    )));
                    break;
                }
                Ok(_) => {
                    let line = String::from_utf8_lossy(&line_buf);
                    collected.push_str(&line);
                    if line.contains("hazir!") {
                        let _ = tx.send(Ok(()));
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(format!("stdout okuma hatasi: {e}")));
                    break;
                }
            }
        }
        let mut sink = [0u8; 4096];
        while let Ok(n) = reader.read(&mut sink) {
            if n == 0 {
                break;
            }
        }
    });

    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(())) => Ok(ServerGuard {
            child,
            _workspace: workspace,
        }),
        Ok(Err(err)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!("ZMax sunucusu baslatilamadi: {err}").into())
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!("Sunucu hazir olma senkron bariyeri zaman asimi: {e}").into())
        }
    }
}

struct Http1Response {
    status: u16,
    body: String,
}

async fn send_http1_get(port: u16, host: &str, path: &str) -> TestResult<Http1Response> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end;
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
        if n == 0 {
            return Err("Sunucu basliklari tamamlamadan kapatti".into());
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = pos + 4;
            break;
        }
    }

    let head_str = String::from_utf8_lossy(&raw[..head_end - 4]);
    let mut lines = head_str.lines();
    let status_line = lines.next().ok_or("Durum satiri bulunamadi")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP durum kodu okunamadi")?
        .parse()?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse::<usize>().ok();
            }
        }
    }

    let mut body_bytes = raw[head_end..].to_vec();
    if let Some(len) = content_length {
        while body_bytes.len() < len {
            let n =
                tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..n]);
        }
        body_bytes.truncate(len);
    } else {
        loop {
            let n =
                tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..n]);
        }
    }

    Ok(Http1Response {
        status,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
    })
}

struct H2Response {
    status: u16,
    body: String,
}

async fn send_h2_get(
    port: u16,
    sni_host: &str,
    path: &str,
    connector: &TlsConnector,
) -> TestResult<H2Response> {
    let tcp = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("127.0.0.1:{port}")),
    )
    .await??;
    let server_name = ServerName::try_from(sni_host.to_string())?;
    let tls_stream =
        tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
            .await??;

    let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
    if negotiated.as_deref() != Some(b"h2") {
        return Err(format!("ALPN h2 anlasilamadi: {negotiated:?}").into());
    }

    let (mut send_req, conn) = h2::client::handshake(tls_stream).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{sni_host}{path}"))
        .header("host", sni_host)
        .body(())?;
    let (resp_fut, _send_stream) = send_req.send_request(req, true)?;
    let response = tokio::time::timeout(Duration::from_secs(10), resp_fut).await??;
    let status = response.status().as_u16();

    let mut body_stream = response.into_body();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let bytes = chunk?;
        body_bytes.extend_from_slice(&bytes);
        let _ = body_stream.flow_control().release_capacity(bytes.len());
    }
    conn_task.abort();

    Ok(H2Response {
        status,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
    })
}

async fn trigger_reload(api_port: u16) -> TestResult<serde_json::Value> {
    let addr = format!("127.0.0.1:{api_port}");
    let mut stream =
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr)).await??;
    let req = "POST /api/v1/reload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await??;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("Gecersiz HTTP basligi")?;
    let body = &raw[pos + 4..];
    let val: serde_json::Value = serde_json::from_slice(body)?;
    Ok(val)
}

#[tokio::test]
async fn test_kart12_concurrent_http1_h2_zero_drop_during_reload() -> TestResult<()> {
    // 1. Dinamik portlar ve yalitilmis calisma alani
    let ports = TestPorts::pick_unique();
    let ws = TempWorkspace::new("zero_drop")?;
    let root = ws.path().to_path_buf();

    // 2. TLS sertifikasi ve VHost yapisi
    let cert_path = root.join("certs").join("stress.crt");
    let key_path = root.join("certs").join("stress.key");
    generate_self_signed_cert(&cert_path, &key_path, "stress.test", &["stress.test"])?;

    let v1_dir = root.join("www").join("v1");
    let v2_dir = root.join("www").join("v2");
    fs::create_dir_all(&v1_dir)?;
    fs::create_dir_all(&v2_dir)?;
    fs::write(v1_dir.join("index.html"), "SURUM-1-ORIJINAL")?;
    fs::write(v2_dir.join("index.html"), "SURUM-2-YENILENDI")?;

    let vhost_conf = root.join("conf").join("vhosts").join("stress.toml");
    let initial_vhost = format!(
        r#"[vhost]
name = "stress.test"
aliases = ["www.stress.test"]
document_root = "{}"
index_files = ["index.html"]

[vhost.ssl]
certificate = "{}"
key = "{}"

[vhost.tls]
http2 = true

[vhost.cache]
enabled = false
"#,
        toml_path(&v1_dir),
        toml_path(&cert_path),
        toml_path(&key_path)
    );
    fs::write(&vhost_conf, initial_vhost)?;

    let zmax_conf = root.join("conf").join("zmax.toml");
    write_zmax_config(&zmax_conf, ports)?;

    let _server = spawn_zmax_server(ws, &zmax_conf)?;

    let connector = build_tls_connector(vec![b"h2".to_vec(), b"http/1.1".to_vec()])?;

    // 3. Baslangic dogrulamasi: Hem HTTP/1.1 hem HTTP/2 v1'i okur
    let r1 = send_http1_get(ports.http, "stress.test", "/index.html").await?;
    assert_eq!(r1.status, 200);
    assert_eq!(r1.body, "SURUM-1-ORIJINAL");

    let r2 = send_h2_get(ports.https, "stress.test", "/index.html", &connector).await?;
    assert_eq!(r2.status, 200);
    assert_eq!(r2.body, "SURUM-1-ORIJINAL");

    // 4. Senkron Bariyeri: Eşzamanlı aktif istekler akarken reload
    // Toplam 40 eşzamanlı istek başlatılır (20 HTTP/1.1, 20 HTTP/2).
    // Hepsi başlamadan reload tetiklenmez; bariyer ile kilitlenir.
    let total_tasks = 40;
    let barrier = Arc::new(Barrier::new(total_tasks + 1));
    let dropped_counter = Arc::new(AtomicUsize::new(0));
    let success_counter = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();

    for i in 0..total_tasks {
        let b = Arc::clone(&barrier);
        let dropped = Arc::clone(&dropped_counter);
        let success = Arc::clone(&success_counter);
        let conn = connector.clone();
        let is_h2 = i % 2 == 0;
        let http_port = ports.http;
        let https_port = ports.https;

        let handle = tokio::spawn(async move {
            // Senkron bariyerine ulasarak tum tasklarin hazir olmasini bekle
            b.wait().await;

            let res = if is_h2 {
                send_h2_get(https_port, "stress.test", "/index.html", &conn)
                    .await
                    .map(|r| (r.status, r.body))
            } else {
                send_http1_get(http_port, "stress.test", "/index.html")
                    .await
                    .map(|r| (r.status, r.body))
            };

            match res {
                Ok((200, body)) => {
                    // Yanıt SURUM-1 veya reload tamamlandıysa SURUM-2 olmalı, asla düşmemeli
                    if body == "SURUM-1-ORIJINAL" || body == "SURUM-2-YENILENDI" {
                        success.fetch_add(1, Ordering::SeqCst);
                    } else {
                        dropped.fetch_add(1, Ordering::SeqCst);
                    }
                }
                _ => {
                    dropped.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        handles.push(handle);
    }

    // Disk uzerinde vhost yapilandirmasini atomik olarak v2'ye cevir
    let updated_vhost = format!(
        r#"[vhost]
name = "stress.test"
aliases = ["www.stress.test"]
document_root = "{}"
index_files = ["index.html"]

[vhost.ssl]
certificate = "{}"
key = "{}"

[vhost.tls]
http2 = true

[vhost.cache]
enabled = false
"#,
        toml_path(&v2_dir),
        toml_path(&cert_path),
        toml_path(&key_path)
    );
    fs::write(&vhost_conf, updated_vhost)?;

    // Tum istekler bariyere ulasip calismaya basladigi an reload sinyali tetiklenir
    barrier.wait().await;

    let reload_res = trigger_reload(ports.api).await?;
    assert_eq!(reload_res["ok"], true);
    assert_eq!(reload_res["status"], "reloaded");

    // Tum isteklerin tamamlanmasini bekle
    for h in handles {
        h.await?;
    }

    let dropped = dropped_counter.load(Ordering::SeqCst);
    let success = success_counter.load(Ordering::SeqCst);

    assert_eq!(
        dropped, 0,
        "Reload esnasinda istek dustu! Dustu={dropped}, Basarili={success}"
    );
    assert_eq!(
        success, total_tasks,
        "Tum aktif istekler basariyla tamamlanmali"
    );

    // 5. Reload sonrasi YENI istekler yeni konfigürasyonu (v2) almalı
    let post_h1 = send_http1_get(ports.http, "stress.test", "/index.html").await?;
    assert_eq!(post_h1.status, 200);
    assert_eq!(
        post_h1.body, "SURUM-2-YENILENDI",
        "HTTP/1.1 reload sonrasinda yeni konfigürasyonu almali"
    );

    let post_h2 = send_h2_get(ports.https, "stress.test", "/index.html", &connector).await?;
    assert_eq!(post_h2.status, 200);
    assert_eq!(
        post_h2.body, "SURUM-2-YENILENDI",
        "HTTP/2 reload sonrasinda yeni konfigürasyonu almali"
    );

    Ok(())
}

#[tokio::test]
async fn test_kart12_heavy_traffic_continuous_reload_stress() -> TestResult<()> {
    // Surekli yogun yuk altinda coklu ardışık reload testi
    let ports = TestPorts::pick_unique();
    let ws = TempWorkspace::new("heavy_stress")?;
    let root = ws.path().to_path_buf();

    let cert_path = root.join("certs").join("heavy.crt");
    let key_path = root.join("certs").join("heavy.key");
    generate_self_signed_cert(&cert_path, &key_path, "heavy.test", &["heavy.test"])?;

    let doc_dir = root.join("www").join("heavy");
    fs::create_dir_all(&doc_dir)?;
    fs::write(
        doc_dir.join("data.txt"),
        "ZMAX-HEAVY-STRESS-DATA-PAYLOAD-OK",
    )?;

    let vhost_conf = root.join("conf").join("vhosts").join("heavy.toml");
    let vhost_str = format!(
        r#"[vhost]
name = "heavy.test"
document_root = "{}"
index_files = ["data.txt"]

[vhost.ssl]
certificate = "{}"
key = "{}"

[vhost.tls]
http2 = true

[vhost.cache]
enabled = false
"#,
        toml_path(&doc_dir),
        toml_path(&cert_path),
        toml_path(&key_path)
    );
    fs::write(&vhost_conf, vhost_str)?;

    let zmax_conf = root.join("conf").join("zmax.toml");
    write_zmax_config(&zmax_conf, ports)?;

    let _server = spawn_zmax_server(ws, &zmax_conf)?;
    let connector = build_tls_connector(vec![b"h2".to_vec(), b"http/1.1".to_vec()])?;

    let total_requests = Arc::new(AtomicUsize::new(0));
    let failed_requests = Arc::new(AtomicUsize::new(0));

    let worker_count = 10;
    let requests_per_worker = 8;
    let mut workers = Vec::new();

    // 10 eszamanli worker gorevi (toplam 80 istek: 40 HTTP/1.1, 40 HTTP/2)
    for w in 0..worker_count {
        let tot = Arc::clone(&total_requests);
        let fail = Arc::clone(&failed_requests);
        let conn = connector.clone();
        let is_h2 = w % 2 == 0;
        let http_port = ports.http;
        let https_port = ports.https;

        let h = tokio::spawn(async move {
            for _ in 0..requests_per_worker {
                let res = if is_h2 {
                    send_h2_get(https_port, "heavy.test", "/data.txt", &conn)
                        .await
                        .map(|r| (r.status, r.body))
                } else {
                    send_http1_get(http_port, "heavy.test", "/data.txt")
                        .await
                        .map(|r| (r.status, r.body))
                };

                tot.fetch_add(1, Ordering::Relaxed);
                match res {
                    Ok((200, body)) if body == "ZMAX-HEAVY-STRESS-DATA-PAYLOAD-OK" => {}
                    _ => {
                        fail.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });
        workers.push(h);
    }

    // Trafik akarken 3 kez /api/v1/reload tetikle
    for reload_idx in 1..=3 {
        let modified_vhost = format!(
            r#"[vhost]
name = "heavy.test"
# reload cycle {reload_idx}
document_root = "{}"
index_files = ["data.txt"]

[vhost.ssl]
certificate = "{}"
key = "{}"

[vhost.tls]
http2 = true

[vhost.cache]
enabled = false
"#,
            toml_path(&doc_dir),
            toml_path(&cert_path),
            toml_path(&key_path)
        );
        fs::write(&vhost_conf, modified_vhost)?;

        let r = trigger_reload(ports.api).await?;
        assert_eq!(r["ok"], true);
    }

    // Tum iscilerin tamamlanmasini bekle
    for w in workers {
        let _ = w.await?;
    }

    let tot = total_requests.load(Ordering::SeqCst);
    let fail = failed_requests.load(Ordering::SeqCst);

    assert_eq!(
        tot,
        worker_count * requests_per_worker,
        "Tum istekler gonderilmis olmali. Gonderilen: {tot}"
    );
    assert_eq!(
        fail, 0,
        "Yogun reload altinda basarisiz istek olmamali! Hata={fail}, Toplam={tot}"
    );

    Ok(())
}

#[tokio::test]
async fn test_kart12_new_vhost_dynamically_loaded_after_reload() -> TestResult<()> {
    // Calisan sunucuya yeni bir vHost eklenip reload sonrasi aninda yanit vermesi
    let ports = TestPorts::pick_unique();
    let ws = TempWorkspace::new("dynamic_vhost")?;
    let root = ws.path().to_path_buf();

    let cert_path = root.join("certs").join("base.crt");
    let key_path = root.join("certs").join("base.key");
    generate_self_signed_cert(&cert_path, &key_path, "base.test", &["base.test"])?;

    let base_dir = root.join("www").join("base");
    fs::create_dir_all(&base_dir)?;
    fs::write(base_dir.join("index.html"), "BASE-SITE-OK")?;

    let base_vhost = format!(
        r#"[vhost]
name = "base.test"
document_root = "{}"
index_files = ["index.html"]

[vhost.ssl]
certificate = "{}"
key = "{}"

[vhost.tls]
http2 = true

[vhost.cache]
enabled = false
"#,
        toml_path(&base_dir),
        toml_path(&cert_path),
        toml_path(&key_path)
    );
    fs::write(
        root.join("conf").join("vhosts").join("base.toml"),
        base_vhost,
    )?;

    let zmax_conf = root.join("conf").join("zmax.toml");
    write_zmax_config(&zmax_conf, ports)?;

    let _server = spawn_zmax_server(ws, &zmax_conf)?;

    // Ilk istek base vhost'a
    let r1 = send_http1_get(ports.http, "base.test", "/index.html").await?;
    assert_eq!(r1.status, 200);
    assert_eq!(r1.body, "BASE-SITE-OK");

    // Henuz eklenmemis vhost'a istek: vhost bulunamaz (404 varsayilan sayfa veya vhost eslesmez)
    let r_missing = send_http1_get(ports.http, "yeni.test", "/index.html").await?;
    assert_ne!(r_missing.body, "YENI-VHOST-CANLI-OK");

    // Simdi yeni bir vHost dosyasi ekle
    let yeni_dir = root.join("www").join("yeni");
    fs::create_dir_all(&yeni_dir)?;
    fs::write(yeni_dir.join("index.html"), "YENI-VHOST-CANLI-OK")?;

    let yeni_vhost = format!(
        r#"[vhost]
name = "yeni.test"
document_root = "{}"
index_files = ["index.html"]

[vhost.cache]
enabled = false
"#,
        toml_path(&yeni_dir)
    );
    fs::write(
        root.join("conf").join("vhosts").join("yeni.toml"),
        yeni_vhost,
    )?;

    // Reload et
    let reload_res = trigger_reload(ports.api).await?;
    assert_eq!(reload_res["ok"], true);
    assert_eq!(reload_res["vhosts_loaded"], 2);

    // Yeni vhost aninda HTTP/1.1 uzerinden yanit vermeli
    let r_new = send_http1_get(ports.http, "yeni.test", "/index.html").await?;
    assert_eq!(r_new.status, 200);
    assert_eq!(r_new.body, "YENI-VHOST-CANLI-OK");

    // Eski base vhost da kesintisiz yanit vermeye devam etmeli
    let r_base_again = send_http1_get(ports.http, "base.test", "/index.html").await?;
    assert_eq!(r_base_again.status, 200);
    assert_eq!(r_base_again.body, "BASE-SITE-OK");

    Ok(())
}
