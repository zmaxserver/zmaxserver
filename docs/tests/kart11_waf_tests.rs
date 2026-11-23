//! Kart 11 Entegrasyon Testleri:
//! Gerçek `zmax` sürecini `21040-21043` port bloğunda başlatarak HTTP/1.1 ve HTTP/2 (TLS ALPN h2)
//! üzerinden vHost WAF aç/kapa, `waf_exclude_paths`, `logs/waf_events.log` kayıtları,
//! parola/çerez gizliliği ve `/api/v1/status` + `/metrics` 24 saatlik sayaçlarını doğrular.

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const TEST_HTTP_PORT: u16 = 21040;
const TEST_HTTPS_PORT: u16 = 21041;
const TEST_API_PORT: u16 = 21042;
const TEST_ADMIN_PORT: u16 = 21043;

struct ProcessAndDirGuard {
    child: Option<Child>,
    base_dir: PathBuf,
}

impl Drop for ProcessAndDirGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

#[derive(Debug)]
struct AcceptSelfSignedCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptSelfSignedCertVerifier {
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

fn create_temp_workspace(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zmax_{tag}_{}_{}", std::process::id(), nanos));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("conf").join("vhosts")).unwrap();
    std::fs::create_dir_all(dir.join("modules")).unwrap();
    std::fs::create_dir_all(dir.join("certs")).unwrap();
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    std::fs::create_dir_all(dir.join("admin")).unwrap();
    std::fs::create_dir_all(dir.join("cachedata")).unwrap();
    std::fs::create_dir_all(dir.join("www").join("html")).unwrap();
    std::fs::create_dir_all(dir.join("www").join("waf-on").join("api").join("webhook")).unwrap();
    std::fs::create_dir_all(dir.join("www").join("waf-off")).unwrap();
    dir
}

fn write_test_certs(base_dir: &Path) {
    let ck = rcgen::generate_simple_self_signed(vec![
        "waf-on.test".to_string(),
        "waf-off.test".to_string(),
    ])
    .expect("test TLS sertifikasi uretilemedi");
    std::fs::write(base_dir.join("certs").join("waf.pem"), ck.cert.pem()).unwrap();
    std::fs::write(
        base_dir.join("certs").join("waf.key"),
        ck.signing_key.serialize_pem(),
    )
    .unwrap();
}

fn write_test_configs(base_dir: &Path) -> PathBuf {
    std::fs::write(base_dir.join("admin").join("index.html"), "ADMIN_OK").unwrap();
    std::fs::write(
        base_dir.join("www").join("html").join("index.html"),
        "DEFAULT_OK",
    )
    .unwrap();
    std::fs::write(
        base_dir.join("www").join("waf-on").join("index.html"),
        "WAF_ON_INDEX",
    )
    .unwrap();
    std::fs::write(
        base_dir
            .join("www")
            .join("waf-on")
            .join("api")
            .join("webhook")
            .join("index.html"),
        "WEBHOOK_OK",
    )
    .unwrap();
    std::fs::write(
        base_dir.join("www").join("waf-off").join("index.html"),
        "WAF_OFF_OK",
    )
    .unwrap();

    std::fs::write(
        base_dir.join("modules").join("mod_security.toml"),
        r#"[module]
name = "mod_security"
version = "1.0.0"
enabled = true

[settings]
token_bucket_rate_limit = 5000
slowloris_shield = true
path_traversal_shield = true
sql_injection_inspection = true
block_hidden_files = true
"#,
    )
    .unwrap();

    std::fs::write(
        base_dir.join("modules").join("mod_coreruleset.toml"),
        r#"[module]
name = "mod_coreruleset"
version = "1.0.0"
enabled = true

[settings]
block_sql_injection = true
block_cross_site_scripting = true
block_remote_code_execution = true
block_path_traversal = true
"#,
    )
    .unwrap();

    let conf_path = base_dir.join("conf").join("zmax.toml");
    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax/Kart11Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {TEST_HTTP_PORT}
reuse_port = false

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {TEST_HTTPS_PORT}
ssl = true
alpn = ["h2", "http/1.1"]

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {TEST_API_PORT}
require_token = false
token = ""

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {TEST_ADMIN_PORT}
document_root = "admin"
require_token = false
token = ""

[cache]
enabled = false

[security]
rate_limit_enabled = false
block_path_traversal = true

[logging]
access_log = "logs/access.log"
error_log = "logs/error.log"
batch_flush_ms = 50
batch_buffer_kb = 16
add_request_id = true

[vhosts_dir]
path = "conf/vhosts"
"#
    );
    std::fs::write(&conf_path, zmax_toml).unwrap();

    std::fs::write(
        base_dir
            .join("conf")
            .join("vhosts")
            .join("waf-on.test.toml"),
        r#"[vhost]
name = "waf-on.test"
document_root = "www/waf-on"

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "certs/waf.pem"
key = "certs/waf.key"

[vhost.tls]
http2 = true

[vhost.security]
waf_enabled = true
wp_brute_force = false
waf_exclude_paths = ["/api/webhook"]
"#,
    )
    .unwrap();

    std::fs::write(
        base_dir
            .join("conf")
            .join("vhosts")
            .join("waf-off.test.toml"),
        r#"[vhost]
name = "waf-off.test"
document_root = "www/waf-off"

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "certs/waf.pem"
key = "certs/waf.key"

[vhost.tls]
http2 = true

[vhost.security]
waf_enabled = false
wp_brute_force = false
"#,
    )
    .unwrap();

    conf_path
}

fn spawn_zmax_and_wait_ready(base_dir: &Path, conf_path: &Path) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zmax"));
    cmd.env("ZMAX_HOME", base_dir)
        .arg("-c")
        .arg(conf_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("zmax sureci baslatilamadi");
    let stdout = child.stdout.take().expect("stdout yakalanamadi");
    let stderr = child.stderr.take().expect("stderr yakalanamadi");

    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let (err_tx, err_rx) = mpsc::channel::<String>();

    std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            lines.push(line);
        }
        let _ = err_tx.send(lines.join("\n"));
    });

    std::thread::spawn(move || {
        let mut saw_http = false;
        let mut saw_https = false;
        let mut saw_api = false;
        let mut signaled = false;
        let mut out_lines = Vec::new();

        for line_res in BufReader::new(stdout).lines() {
            match line_res {
                Ok(line) => {
                    if line.contains("* Web Sunucusu") {
                        saw_http = true;
                    }
                    if line.contains("* HTTPS Sunucu") {
                        saw_https = true;
                    }
                    if line.contains("* Kontrol API") {
                        saw_api = true;
                    }
                    if !signaled {
                        out_lines.push(line);
                        if saw_http && saw_https && saw_api {
                            signaled = true;
                            let _ = ready_tx.send(Ok(()));
                            // Pipe kapanmasin ve zmax stdout yazarken BrokenPipe yemesin diye tuketmeye devam et.
                            out_lines.clear();
                        }
                    }
                }
                Err(e) => {
                    if !signaled {
                        let _ = ready_tx.send(Err(format!(
                            "stdout okuma hatasi: {e}\n{}",
                            out_lines.join("\n")
                        )));
                    }
                    return;
                }
            }
        }

        if !signaled {
            let _ = ready_tx.send(Err(format!(
                "zmax dinleyicileri acmadan sonlandi:\n{}",
                out_lines.join("\n")
            )));
        }
    });

    match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => child,
        Ok(Err(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = err_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            panic!("zmax acilisi basarisiz: {msg}\nstderr:\n{err_out}");
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = err_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            panic!("zmax hazirlik zaman asimi: {e}\nstderr:\n{err_out}");
        }
    }
}

async fn send_http1_raw(port: u16, raw_req: &str) -> (u16, String, String) {
    let addr = format!("127.0.0.1:{port}");
    let mut stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .expect("TCP baglanti zaman asimi")
        .expect("TCP baglantisi basarisiz");

    tokio::time::timeout(
        Duration::from_secs(10),
        stream.write_all(raw_req.as_bytes()),
    )
    .await
    .expect("HTTP yazma zaman asimi")
    .expect("HTTP yazma hatasi");

    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut buf))
        .await
        .expect("HTTP okuma zaman asimi")
        .expect("HTTP okuma hatasi");

    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status_line = head.lines().next().unwrap_or("");
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (code, head.to_string(), body.to_string())
}

async fn send_h2_tls_request(
    port: u16,
    sni_host: &str,
    uri: &str,
    host_header: &str,
    extra_headers: &[(&str, &str)],
) -> (u16, String) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptSelfSignedCertVerifier))
        .with_no_client_auth();
    ccfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(ccfg));

    let addr = format!("127.0.0.1:{port}");
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .expect("HTTPS TCP baglanti zaman asimi")
        .expect("HTTPS TCP baglanti hatasi");
    let server_name = ServerName::try_from(sni_host.to_string()).unwrap();
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .expect("TLS el sikisma zaman asimi")
        .expect("TLS el sikisma hatasi");

    {
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.alpn_protocol(),
            Some(b"h2".as_slice()),
            "ALPN h2 muzakere edilmelidir"
        );
    }

    let (mut client, h2_conn) = h2::client::handshake(tls)
        .await
        .expect("h2 istemci el sikismasi basarisiz");
    let conn_task = tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let mut builder = http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", host_header);
    for &(k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(()).unwrap();
    let (resp_fut, _) = client.send_request(req, true).unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), resp_fut)
        .await
        .expect("h2 yanit zaman asimi")
        .expect("h2 yanit hatasi");
    let status = resp.status().as_u16();
    let mut body_stream = resp.into_body();
    let mut body = Vec::new();
    while let Some(chunk_res) = tokio::time::timeout(Duration::from_secs(10), body_stream.data())
        .await
        .expect("h2 govde zaman asimi")
    {
        let chunk: Bytes = chunk_res.expect("h2 govde parcasi hatasi");
        body.extend_from_slice(&chunk);
        let _ = body_stream.flow_control().release_capacity(chunk.len());
    }
    drop(client);
    conn_task.abort();
    let _ = conn_task.await;

    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn kart11_waf_end_to_end_http1_http2_logging_and_counters() {
    let base_dir = create_temp_workspace("kart11_e2e");
    write_test_certs(&base_dir);
    let conf_path = write_test_configs(&base_dir);
    let child = spawn_zmax_and_wait_ready(&base_dir, &conf_path);

    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: base_dir.clone(),
    };

    let secrets = [
        "CokGizliParola789",
        "CokGizliQueryCerez",
        "CokGizliCerez123",
        "CokGizliToken456",
        "CokGizliMatrixParola11",
        "CokGizliH2Token",
        "CokGizliH2Parola",
        "CokGizliH2Cerez",
        "CokGizliH2Auth",
    ];

    // 1. Başlangıçta /api/v1/status ve /metrics sıfır WAF olayı göstermeli
    let (code_s0, _, body_s0) = send_http1_raw(
        TEST_API_PORT,
        "GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(code_s0, 200, "API status 200 olmali: {body_s0}");
    let s0: serde_json::Value = serde_json::from_str(&body_s0).unwrap();
    assert_eq!(s0["waf_events_total"], 0);
    assert_eq!(s0["waf_blocked_24h"], 0);
    assert_eq!(s0["waf"]["events_total"], 0);
    assert_eq!(s0["waf"]["blocked_24h"], 0);

    let (code_m0, _, body_m0) = send_http1_raw(
        TEST_API_PORT,
        "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(code_m0, 200, "API metrics 200 olmali: {body_m0}");
    assert!(body_m0.contains("zmax_waf_events_total 0\n"), "{body_m0}");
    assert!(body_m0.contains("zmax_waf_blocked_24h 0\n"), "{body_m0}");

    // 2. HTTP/1.1 WAF açık vHost üzerinde SQLi saldırısı (+ parola/çerez/token) -> 403
    let (code_h1_sqli, _, body_h1_sqli) = send_http1_raw(
        TEST_HTTP_PORT,
        "GET /giris;password=CokGizliMatrixParola11?password=CokGizliParola789&cookie=CokGizliQueryCerez&id=1%20UNION%20SELECT%201,2 HTTP/1.1\r\nHost: waf-on.test\r\nCookie: session=CokGizliCerez123\r\nAuthorization: Bearer CokGizliToken456\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        code_h1_sqli, 403,
        "HTTP/1.1 SQLi 403 olmali: {body_h1_sqli}"
    );
    assert!(body_h1_sqli.contains("WAF Blocked"), "{body_h1_sqli}");

    // 3. HTTP/1.1 waf_exclude_paths muaf yol -> 200 (sayaç artmamalı)
    let (code_h1_excl, _, body_h1_excl) = send_http1_raw(
        TEST_HTTP_PORT,
        "GET /api/webhook/index.html?id=1%20UNION%20SELECT%201,2 HTTP/1.1\r\nHost: waf-on.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        code_h1_excl, 200,
        "HTTP/1.1 muaf yol 200 olmali: {body_h1_excl}"
    );
    assert_eq!(body_h1_excl, "WEBHOOK_OK");

    // 4. HTTP/1.1 waf_enabled = false vHost -> 200 (sayaç artmamalı)
    let (code_h1_off, _, body_h1_off) = send_http1_raw(
        TEST_HTTP_PORT,
        "GET /index.html?id=1%20UNION%20SELECT%201,2 HTTP/1.1\r\nHost: waf-off.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        code_h1_off, 200,
        "HTTP/1.1 waf_enabled=false 200 olmali: {body_h1_off}"
    );
    assert_eq!(body_h1_off, "WAF_OFF_OK");

    // 5. HTTP/2 (TLS ALPN h2) WAF açık vHost üzerinde SQLi -> 403
    let (code_h2_sqli, body_h2_sqli) = send_h2_tls_request(
        TEST_HTTPS_PORT,
        "waf-on.test",
        "https://waf-on.test/sayfa;token=CokGizliH2Token?password=CokGizliH2Parola&q=union+select+1",
        "waf-on.test",
        &[
            ("cookie", "session=CokGizliH2Cerez"),
            ("authorization", "Bearer CokGizliH2Auth"),
        ],
    )
    .await;
    assert_eq!(code_h2_sqli, 403, "HTTP/2 SQLi 403 olmali: {body_h2_sqli}");
    assert!(body_h2_sqli.contains("WAF Blocked"), "{body_h2_sqli}");

    // 6. HTTP/2 waf_exclude_paths muaf yol -> 200
    let (code_h2_excl, body_h2_excl) = send_h2_tls_request(
        TEST_HTTPS_PORT,
        "waf-on.test",
        "https://waf-on.test/api/webhook/index.html?q=union+select+1",
        "waf-on.test",
        &[],
    )
    .await;
    assert_eq!(
        code_h2_excl, 200,
        "HTTP/2 muaf yol 200 olmali: {body_h2_excl}"
    );
    assert_eq!(body_h2_excl, "WEBHOOK_OK");

    // 7. HTTP/2 waf_enabled = false vHost -> 200
    let (code_h2_off, body_h2_off) = send_h2_tls_request(
        TEST_HTTPS_PORT,
        "waf-off.test",
        "https://waf-off.test/index.html?q=union+select+1",
        "waf-off.test",
        &[],
    )
    .await;
    assert_eq!(
        code_h2_off, 200,
        "HTTP/2 waf_enabled=false 200 olmali: {body_h2_off}"
    );
    assert_eq!(body_h2_off, "WAF_OFF_OK");

    // 8. API üzerinden waf-off.test için waf_enabled = true yaparak sıcak aç/kapa doğrulaması
    let put_payload = r#"{"waf_enabled":true}"#;
    let put_req = format!(
        "PUT /api/v1/vhosts/waf-off.test HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        put_payload.len(),
        put_payload
    );
    let (code_put, _, body_put) = send_http1_raw(TEST_API_PORT, &put_req).await;
    assert_eq!(code_put, 200, "vHost WAF acma PUT 200 olmali: {body_put}");

    let (code_h1_re_enabled, _, body_h1_re_enabled) = send_http1_raw(
        TEST_HTTP_PORT,
        "GET /index.html?id=1%20UNION%20SELECT%201,2 HTTP/1.1\r\nHost: waf-off.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(
        code_h1_re_enabled, 403,
        "waf_enabled=true yapildiktan sonra 403 olmali: {body_h1_re_enabled}"
    );

    // 9. Sleep/polling olmadan log worker kuyruğunu deterministik olarak diske boşalt
    let (code_reopen, _, body_reopen) = send_http1_raw(
        TEST_API_PORT,
        "POST /api/v1/logs/reopen HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(code_reopen, 200, "logs/reopen 200 olmali: {body_reopen}");

    // 10. logs/waf_events.log içeriğini doğrula (3 olay, gerekli alanlar, sıfır parola/çerez)
    let waf_log_path = base_dir.join("logs").join("waf_events.log");
    let waf_log_text = std::fs::read_to_string(&waf_log_path)
        .unwrap_or_else(|e| panic!("waf_events.log okunamadi ({}): {e}", waf_log_path.display()));
    let lines: Vec<&str> = waf_log_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        3,
        "Tam 3 WAF olayi yazilmis olmali:\n{waf_log_text}"
    );

    let mut parsed_events = Vec::new();
    for line in &lines {
        let ev: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("Gecersiz JSON satiri: {e} -> {line}"));
        assert!(ev["ts"]
            .as_str()
            .is_some_and(|s| s.contains('T') && s.ends_with('Z')));
        assert!(ev["ts_unix"].as_u64().is_some_and(|n| n > 0));
        assert_eq!(ev["ip"], "127.0.0.1");
        assert_eq!(ev["rule_id"], "942100");
        assert_eq!(ev["category"], "sqli");
        assert_eq!(ev["action"], "block");
        assert!(ev["rule"].as_str().is_some_and(|r| r.contains("SQLi")));
        assert!(ev["path"]
            .as_str()
            .is_some_and(|p| !p.contains("/api/webhook")));
        parsed_events.push(ev);
    }

    assert_eq!(parsed_events[0]["vhost"], "waf-on.test");
    assert_eq!(parsed_events[0]["path"], "/giris;password=?password=&cookie=&id=");
    assert_eq!(parsed_events[1]["vhost"], "waf-on.test");
    assert_eq!(parsed_events[1]["path"], "/sayfa;token=?password=&q=");
    assert_eq!(parsed_events[2]["vhost"], "waf-off.test");
    assert_eq!(parsed_events[2]["path"], "/index.html?id=");

    let error_log_text =
        std::fs::read_to_string(base_dir.join("logs").join("error.log")).unwrap_or_default();

    // 11. /api/v1/status ve /metrics sayaçlarının tam olarak 3 olduğunu ve gizli veri içermediğini doğrula
    let (code_s1, _, body_s1) = send_http1_raw(
        TEST_API_PORT,
        "GET /api/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(code_s1, 200, "API status 200 olmali: {body_s1}");
    let s1: serde_json::Value = serde_json::from_str(&body_s1).unwrap();
    assert_eq!(s1["waf_events_total"], 3, "{body_s1}");
    assert_eq!(s1["waf_blocked_24h"], 3, "{body_s1}");
    assert_eq!(s1["waf"]["events_total"], 3, "{body_s1}");
    assert_eq!(s1["waf"]["blocked_24h"], 3, "{body_s1}");
    assert_eq!(s1["waf"]["recent_count"], 3, "{body_s1}");
    assert_eq!(s1["security"]["waf_events_total"], 3, "{body_s1}");
    assert_eq!(s1["security"]["waf_blocked_24h"], 3, "{body_s1}");

    let (code_m1, _, body_m1) = send_http1_raw(
        TEST_API_PORT,
        "GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(code_m1, 200, "API metrics 200 olmali: {body_m1}");
    assert!(body_m1.contains("zmax_waf_events_total 3\n"), "{body_m1}");
    assert!(body_m1.contains("zmax_waf_blocked_24h 3\n"), "{body_m1}");

    for secret in secrets {
        assert!(
            !waf_log_text.contains(secret),
            "waf_events.log gizli deger ({secret}) icermemeli:\n{waf_log_text}"
        );
        assert!(
            !error_log_text.contains(secret),
            "error.log gizli deger ({secret}) icermemeli:\n{error_log_text}"
        );
        assert!(
            !body_s1.contains(secret),
            "API status gizli deger ({secret}) icermemeli:\n{body_s1}"
        );
        assert!(
            !body_m1.contains(secret),
            "API metrics gizli deger ({secret}) icermemeli:\n{body_m1}"
        );
    }
}

#[tokio::test]
async fn test_kart11_token_masking_and_waf_query_sanitization() {
    let raw_uuid_path = "/reset/550e8400-e29b-41d4-a716-446655440000/confirm?password=GizliSifre999&id=1%20UNION%20SELECT%201";
    let sanitized_uuid = zmax_security::waf_events::sanitize_waf_path(raw_uuid_path);
    assert_eq!(sanitized_uuid, "/reset/{token}/confirm?password=&id=");
    assert!(!sanitized_uuid.contains("550e8400-e29b-41d4-a716-446655440000"));
    assert!(!sanitized_uuid.contains("GizliSifre999"));

    let raw_hex_path = "/reset/4f5a6b7c8d9e0f1a2b3c4d5e/confirm?token=SecretTokenHex&q=union+select";
    let sanitized_hex = zmax_security::waf_events::sanitize_waf_path(raw_hex_path);
    assert_eq!(sanitized_hex, "/reset/{token}/confirm?token=&q=");
    assert!(!sanitized_hex.contains("4f5a6b7c8d9e0f1a2b3c4d5e"));
    assert!(!sanitized_hex.contains("SecretTokenHex"));

    let raw_encoded = "/api/v1/auth?%70assword=sec99&user_pass=adm1&pw=secret_pw&api-key=my_key&sessionid=sess_id_val&code=oauth_code_val";
    let sanitized_enc = zmax_security::waf_events::sanitize_waf_path(raw_encoded);
    assert!(sanitized_enc.contains("%70assword="));
    assert!(sanitized_enc.contains("user_pass="));
    assert!(sanitized_enc.contains("pw="));
    assert!(sanitized_enc.contains("api-key="));
    assert!(sanitized_enc.contains("sessionid="));
    assert!(sanitized_enc.contains("code="));
    assert!(!sanitized_enc.contains("sec99"));
    assert!(!sanitized_enc.contains("adm1"));
    assert!(!sanitized_enc.contains("secret_pw"));
    assert!(!sanitized_enc.contains("my_key"));
    assert!(!sanitized_enc.contains("sess_id_val"));
    assert!(!sanitized_enc.contains("oauth_code_val"));
}

#[tokio::test]
async fn test_kart11_waf_event_store_dropped_events_counter() {
    let store = zmax_security::waf_events::WafEventStore::new();
    assert_eq!(store.dropped_events(), 0);
    store.record_dropped();
    store.record_dropped();
    assert_eq!(store.dropped_events(), 2);
}
