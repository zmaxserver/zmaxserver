use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio_rustls::TlsConnector;

struct TestPorts {
    http: u16,
    https: u16,
    api: u16,
    admin: u16,
    upstream: u16,
}

impl TestPorts {
    fn pick_unique() -> Self {
        let mut ports = Vec::with_capacity(5);
        let mut listeners = Vec::with_capacity(5);
        for _ in 0..5 {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("Rastgele port alinamadi");
            ports.push(l.local_addr().expect("Adres alinamadi").port());
            listeners.push(l);
        }
        drop(listeners);
        Self {
            http: ports[0],
            https: ports[1],
            api: ports[2],
            admin: ports[3],
            upstream: ports[4],
        }
    }
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn build_tls_connector(
    alpn: Vec<Vec<u8>>,
    versions: Option<&[&'static rustls::SupportedProtocolVersion]>,
) -> TlsConnector {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ));

    let mut client_config = if let Some(vers) = versions {
        builder
            .with_protocol_versions(vers)
            .expect("TLS protokol surumleri gecersiz")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        builder
            .with_safe_default_protocol_versions()
            .expect("Varsayilan protokol surumleri gecersiz")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };

    client_config.alpn_protocols = alpn;
    TlsConnector::from(Arc::new(client_config))
}

struct ProtocolTestEnv {
    base_dir: PathBuf,
    ports: TestPorts,
    child: Option<Child>,
}

impl ProtocolTestEnv {
    async fn start() -> Self {
        let ports = TestPorts::pick_unique();
        let unique = format!(
            "zmax_ols_proto_{}_{}_{}",
            std::process::id(),
            ports.https,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let base_dir = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&base_dir);

        let conf_dir = base_dir.join("conf");
        let vhosts_dir = conf_dir.join("vhosts");
        let certs_dir = base_dir.join("certs");
        let modules_dir = base_dir.join("modules");
        let admin_dir = base_dir.join("admin");
        let logs_dir = base_dir.join("logs");

        std::fs::create_dir_all(&vhosts_dir).unwrap();
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::create_dir_all(&admin_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::write(admin_dir.join("index.html"), "ADMIN_OK").unwrap();

        // Kendinden imzali TLS test sertifikasi
        let ck = rcgen::generate_simple_self_signed(vec![
            "proto.test".to_string(),
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        std::fs::write(certs_dir.join("https.pem"), ck.cert.pem()).unwrap();
        std::fs::write(certs_dir.join("https.key"), ck.signing_key.serialize_pem()).unwrap();

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
        std::fs::write(modules_dir.join("mod_proxy.toml"), mod_proxy).unwrap();

        let zmax_toml = format!(
            r#"[server]
server_name = "ZMax-OLS-Protocol-Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {}

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {}
ssl = true

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {}
token = "test-admin-token-ols"

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {}
document_root = "admin"

[cache]
enabled = false

[security]
rate_limit_enabled = false
waf_enabled = false

[vhosts_dir]
path = "conf/vhosts"
"#,
            ports.http, ports.https, ports.api, ports.admin
        );
        std::fs::write(conf_dir.join("zmax.toml"), zmax_toml).unwrap();

        // 1. vHost: proto.test (TLS + HTTP/2 + Proxy desteği)
        let doc_root = base_dir.join("www").join("proto-site");
        std::fs::create_dir_all(&doc_root).unwrap();
        std::fs::write(doc_root.join("index.html"), "PROTO_INDEX_OK").unwrap();
        std::fs::write(doc_root.join("doc1.html"), "DOC1_CONTENT").unwrap();
        std::fs::write(doc_root.join("doc2.html"), "DOC2_CONTENT").unwrap();
        std::fs::write(doc_root.join("doc3.html"), "DOC3_CONTENT").unwrap();
        std::fs::write(doc_root.join("doc4.html"), "DOC4_CONTENT").unwrap();
        std::fs::write(doc_root.join("doc5.html"), "DOC5_CONTENT").unwrap();

        let vh_conf = format!(
            r#"[vhost]
name = "proto.test"
document_root = "www/proto-site"

[vhost.ssl]
certificate = "certs/https.pem"
key = "certs/https.key"

[vhost.tls]
http2 = true
min_version = "1.2"

[vhost.php]
enabled = false

[vhost.proxy]
enabled = true
upstream = "127.0.0.1:{}"
path_prefix = "/proxy"
preserve_host = true
"#,
            ports.upstream
        );
        std::fs::write(vhosts_dir.join("01-proto.toml"), vh_conf).unwrap();

        let bin = env!("CARGO_BIN_EXE_zmax");
        let mut child = Command::new(bin)
            .env("ZMAX_HOME", &base_dir)
            .env("ZMAX_HTTP_PORT", ports.http.to_string())
            .env("ZMAX_HTTPS_PORT", ports.https.to_string())
            .env("ZMAX_API_PORT", ports.api.to_string())
            .env("ZMAX_ADMIN_PORT", ports.admin.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("zmax sunucusu baslatilamadi");

        let stdout = child.stdout.take().expect("stdout alinamadi");
        let stderr = child.stderr.take().expect("stderr alinamadi");

        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                eprintln!("[zmax stdout] {}", line);
            }
        });
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                eprintln!("[zmax stderr] {}", line);
            }
        });

        // Port dinlenene kadar bekle (HTTP ve HTTPS)
        let mut ready = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if TcpStream::connect(("127.0.0.1", ports.http)).await.is_ok()
                && TcpStream::connect(("127.0.0.1", ports.https)).await.is_ok()
            {
                ready = true;
                break;
            }
        }
        assert!(ready, "zmax sunucusu beklenen surede baslamadi");

        Self {
            base_dir,
            ports,
            child: Some(child),
        }
    }

    async fn send_tls_h1(&self, host: &str, path: &str) -> (u16, String) {
        let connector = build_tls_connector(vec![b"http/1.1".to_vec()], None);
        let tcp = TcpStream::connect(("127.0.0.1", self.ports.https))
            .await
            .expect("tcp baglantisi");
        let server_name = ServerName::try_from(host.to_string()).expect("server name");
        let mut tls = connector.connect(server_name, tcp).await.expect("tls el sikismasi");

        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: zmax-proto-test\r\n\r\n",
            path, host
        );
        tls.write_all(req.as_bytes()).await.unwrap();
        tls.shutdown().await.unwrap();

        let mut buf = Vec::new();
        tls.read_to_end(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf).to_string();

        let (headers_part, body_part) = match raw.split_once("\r\n\r\n") {
            Some((h, b)) => (h, b),
            None => (raw.as_str(), ""),
        };
        let status_code: u16 = headers_part
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        (status_code, body_part.to_string())
    }

    async fn send_tls_h2(&self, host: &str, path: &str) -> (u16, String) {
        let connector = build_tls_connector(vec![b"h2".to_vec(), b"http/1.1".to_vec()], None);
        let tcp = TcpStream::connect(("127.0.0.1", self.ports.https))
            .await
            .expect("tcp baglantisi");
        let server_name = ServerName::try_from(host.to_string()).expect("server name");
        let tls = connector.connect(server_name, tcp).await.expect("tls el sikismasi");

        let (client, h2_conn) = h2::client::handshake(tls).await.expect("h2 client handshake");
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let mut client = client.ready().await.expect("client ready");
        let req = http::Request::builder()
            .method("GET")
            .uri(format!("https://{}{}", host, path))
            .header("Host", host)
            .body(())
            .unwrap();
        let (response, _send_stream) = client.send_request(req, true).unwrap();
        let (head, mut body) = response.await.unwrap().into_parts();

        let mut body_bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let data = chunk.unwrap();
            body_bytes.extend_from_slice(&data);
        }

        (head.status.as_u16(), String::from_utf8_lossy(&body_bytes).to_string())
    }

    async fn send_plain_http(&self, host: &str, path: &str) -> (u16, String) {
        let mut tcp = TcpStream::connect(("127.0.0.1", self.ports.http))
            .await
            .expect("tcp baglantisi");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );
        tcp.write_all(req.as_bytes()).await.unwrap();
        tcp.shutdown().await.unwrap();

        let mut buf = Vec::new();
        tcp.read_to_end(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf).to_string();

        let (headers_part, body_part) = match raw.split_once("\r\n\r\n") {
            Some((h, b)) => (h, b),
            None => (raw.as_str(), ""),
        };
        let status_code: u16 = headers_part
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        (status_code, body_part.to_string())
    }
}

impl Drop for ProtocolTestEnv {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

// 1. Protokol & ALPN: Aynı TLS portunda HTTP/1.1 ve HTTP/2 el sıkışması
#[tokio::test]
async fn test_alpn_negotiation_http1_and_http2_on_same_tls_port() {
    let env = ProtocolTestEnv::start().await;

    // A) Aynı TLS portuna ALPN http/1.1 ile bağlanma
    let (h1_status, h1_body) = env.send_tls_h1("proto.test", "/").await;
    assert_eq!(h1_status, 200, "Ayni TLS portunda HTTP/1.1 istegi 200 donmeli");
    assert_eq!(h1_body.trim(), "PROTO_INDEX_OK");

    // B) Aynı TLS portuna ALPN h2 ile bağlanma
    let (h2_status, h2_body) = env.send_tls_h2("proto.test", "/").await;
    assert_eq!(h2_status, 200, "Ayni TLS portunda HTTP/2 istegi 200 donmeli");
    assert_eq!(h2_body.trim(), "PROTO_INDEX_OK");

    // C) Eşzamanlı H1 ve H2 paralel istek gönderimi
    let (h1_res, h2_res) = tokio::join!(
        env.send_tls_h1("proto.test", "/doc1.html"),
        env.send_tls_h2("proto.test", "/doc2.html"),
    );
    assert_eq!(h1_res.0, 200);
    assert_eq!(h1_res.1.trim(), "DOC1_CONTENT");
    assert_eq!(h2_res.0, 200);
    assert_eq!(h2_res.1.trim(), "DOC2_CONTENT");
}

// 2. HTTP/2 Çoklu Akış (Multiplexing): Tek TCP bağlantısında birden fazla paralel stream
#[tokio::test]
async fn test_http2_multiplexed_concurrent_streams() {
    let env = ProtocolTestEnv::start().await;

    let connector = build_tls_connector(vec![b"h2".to_vec()], None);
    let tcp = TcpStream::connect(("127.0.0.1", env.ports.https))
        .await
        .expect("tcp baglantisi");
    let server_name = ServerName::try_from("proto.test".to_string()).unwrap();
    let tls = connector.connect(server_name, tcp).await.expect("tls baglantisi");

    let (client, h2_conn) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    // Tek bir TCP/TLS bağlantısı üzerinden 5 adet paralel stream aç
    let mut handles = Vec::new();
    for i in 1..=5 {
        let cl = client.clone();
        handles.push(tokio::spawn(async move {
            let mut cl = cl.ready().await.expect("client ready");
            let req = http::Request::builder()
                .method("GET")
                .uri(format!("https://proto.test/doc{}.html", i))
                .header("Host", "proto.test")
                .body(())
                .unwrap();
            let (response, _send_stream) = cl.send_request(req, true).unwrap();
            let (head, mut body) = response.await.unwrap().into_parts();
            assert_eq!(head.status, 200);

            let mut body_bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                body_bytes.extend_from_slice(&chunk.unwrap());
            }
            (i, String::from_utf8_lossy(&body_bytes).to_string())
        }));
    }

    for handle in handles {
        let (i, body) = handle.await.unwrap();
        assert_eq!(
            body.trim(),
            format!("DOC{}_CONTENT", i),
            "Stream {} verisi dogru olmali",
            i
        );
    }
}

// 3. TLS Sürümleri: TLS 1.2 ve TLS 1.3 bağlantılarının başarıyla kurulması
#[tokio::test]
async fn test_tls_version_negotiation_tls12_and_tls13() {
    let env = ProtocolTestEnv::start().await;

    // A) Yalnızca TLS 1.2 zorunlu istemci
    let conn_12 = build_tls_connector(vec![b"http/1.1".to_vec()], Some(&[&rustls::version::TLS12]));
    let tcp_12 = TcpStream::connect(("127.0.0.1", env.ports.https)).await.unwrap();
    let tls_12 = conn_12
        .connect(ServerName::try_from("proto.test".to_string()).unwrap(), tcp_12)
        .await
        .expect("TLS 1.2 el sikismasi basarili olmali");
    let mut tls_12 = tls_12;
    tls_12
        .write_all(b"GET /doc1.html HTTP/1.1\r\nHost: proto.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf_12 = Vec::new();
    tls_12.read_to_end(&mut buf_12).await.unwrap();
    let resp_12 = String::from_utf8_lossy(&buf_12);
    assert!(resp_12.contains("200 OK"), "TLS 1.2 yaniti 200 olmali: {resp_12}");
    assert!(resp_12.contains("DOC1_CONTENT"));

    // B) Yalnızca TLS 1.3 zorunlu istemci
    let conn_13 = build_tls_connector(vec![b"http/1.1".to_vec()], Some(&[&rustls::version::TLS13]));
    let tcp_13 = TcpStream::connect(("127.0.0.1", env.ports.https)).await.unwrap();
    let tls_13 = conn_13
        .connect(ServerName::try_from("proto.test".to_string()).unwrap(), tcp_13)
        .await
        .expect("TLS 1.3 el sikismasi basarili olmali");
    let mut tls_13 = tls_13;
    tls_13
        .write_all(b"GET /doc2.html HTTP/1.1\r\nHost: proto.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf_13 = Vec::new();
    tls_13.read_to_end(&mut buf_13).await.unwrap();
    let resp_13 = String::from_utf8_lossy(&buf_13);
    assert!(resp_13.contains("200 OK"), "TLS 1.3 yaniti 200 olmali: {resp_13}");
    assert!(resp_13.contains("DOC2_CONTENT"));
}

// 4. Yük Altında Dayanıklılık: Sürekli gelen istekler altında vHost yapılandırmasının yeniden yüklenmesi (reload)
#[tokio::test]
async fn test_resilience_under_load_with_concurrent_reload() {
    let env = ProtocolTestEnv::start().await;

    // 40 eşzamanlı istek arka planda gönderilirken canlı reload tetikle
    let mut tasks = Vec::new();
    for _ in 0..40 {
        let http_port = env.ports.http;
        tasks.push(tokio::spawn(async move {
            let mut stream = TcpStream::connect(("127.0.0.1", http_port)).await?;
            let req = "GET /index.html HTTP/1.1\r\nHost: proto.test\r\nConnection: close\r\n\r\n";
            stream.write_all(req.as_bytes()).await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            let res = String::from_utf8_lossy(&buf).to_string();
            if res.contains("200 OK") && res.contains("PROTO_INDEX_OK") {
                Ok::<(), std::io::Error>(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Hatali yanit: {res}"),
                ))
            }
        }));
    }

    // İstekler sürerken API portundan reload tetikle
    let mut api_stream = TcpStream::connect(("127.0.0.1", env.ports.api))
        .await
        .expect("api baglantisi");
    let reload_req = "POST /api/v1/reload HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer test-admin-token-ols\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    api_stream.write_all(reload_req.as_bytes()).await.unwrap();
    let mut api_buf = Vec::new();
    api_stream.read_to_end(&mut api_buf).await.unwrap();
    let api_res = String::from_utf8_lossy(&api_buf);
    assert!(
        api_res.contains("200 OK"),
        "Reload API 200 OK donmeli: {api_res}"
    );

    // Eşzamanlı tüm isteklerin sıfır kayıpla tamamlandığını doğrula
    for task in tasks {
        let res = task.await.unwrap();
        assert!(
            res.is_ok(),
            "Yuk altinda reload sirasinda baglanti dusmemeli: {:?}",
            res
        );
    }
}

// 5. Upstream Kesintisi: Upstream kapalıyken 502 Bad Gateway dönmesi, upstream açıldığında otomatik olarak 200 OK dönmesi
#[tokio::test]
async fn test_upstream_outage_returns_502_then_recovers_to_200() {
    let env = ProtocolTestEnv::start().await;

    // 1. Upstream henüz kapalıyken (dinleyici yokken) istek atıldığında: 502 Bad Gateway dönmeli
    let (status_down, body_down) = env.send_plain_http("proto.test", "/proxy/test").await;
    assert_eq!(
        status_down, 502,
        "Upstream kapaliyken 502 Bad Gateway donmeli, donen: {} {}",
        status_down, body_down
    );
    assert!(
        body_down.contains("502") || body_down.contains("Bad Gateway"),
        "Govdede 502 Bad Gateway yer almali: {body_down}"
    );

    // 2. Upstream sunucusunu dinamik porta ayağa kaldır
    let upstream_listener = tokio::net::TcpListener::bind(("127.0.0.1", env.ports.upstream))
        .await
        .expect("upstream dinleyici acilamadi");

    tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream_listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nUPSTREAM_OK";
                let _ = socket.write_all(resp.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });

    // 3. Upstream açıldıktan sonra istek atıldığında: Otomatik olarak 200 OK ve UPSTREAM_OK dönmeli
    // ZMax sunucusu yeniden başlatılmadan otomatik toparlanmalı!
    let mut recovered = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status_up, body_up) = env.send_plain_http("proto.test", "/proxy/test").await;
        if status_up == 200 && body_up.contains("UPSTREAM_OK") {
            recovered = true;
            break;
        }
    }

    assert!(
        recovered,
        "Upstream acildiginda ZMax otomatik olarak 200 OK ile servise devam etmeli"
    );
}

