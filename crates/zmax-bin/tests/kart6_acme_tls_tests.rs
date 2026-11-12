use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zmax_tls::extract_cert_serial_hex;

const HTTP_PORT: u16 = 21060;
const HTTPS_PORT: u16 = 21061;
const API_PORT: u16 = 21062;
const ADMIN_PORT: u16 = 21063;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct TempWorkspace {
    root: PathBuf,
}

impl TempWorkspace {
    fn new(tag: &str) -> TestResult<Self> {
        let root =
            std::env::temp_dir().join(format!("zmax_kart6_e2e_{}_{}", tag, std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(root.join("conf").join("vhosts"))?;
        std::fs::create_dir_all(root.join("admin"))?;
        std::fs::create_dir_all(root.join("logs"))?;
        std::fs::create_dir_all(root.join("cachedata"))?;
        std::fs::create_dir_all(root.join("certs"))?;
        std::fs::write(root.join("admin").join("index.html"), "<html>admin</html>")?;
        Ok(Self { root })
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_zmax_and_wait_ready(workspace: &Path, conf_path: &Path) -> TestResult<ServerGuard> {
    let bin = env!("CARGO_BIN_EXE_zmax");
    let mut cmd = Command::new(bin);
    cmd.arg("-c")
        .arg(conf_path)
        .env("ZMAX_HOME", workspace)
        .env_remove("ZMAX_ACME_ROOT")
        .env_remove("ZMAX_CONF")
        .env_remove("ZMAX_HTTP_PORT")
        .env_remove("ZMAX_HTTPS_PORT")
        .env_remove("ZMAX_ADMIN_PORT")
        .env_remove("ZMAX_API_PORT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn()?;
    let stdout = child.stdout.take().ok_or("zmax stdout yakalanamadi")?;
    let stderr = child.stderr.take().ok_or("zmax stderr yakalanamadi")?;

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let stderr_buf = Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_buf_reader = Arc::clone(&stderr_buf);

    let stderr_handle = std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut err_text = String::new();
        let _ = std::io::Read::read_to_string(&mut reader, &mut err_text);
        if let Ok(mut guard) = stderr_buf_reader.lock() {
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
                        "zmax hazir olmadan sonlandi.\nstdout:\n{collected}\nstderr:\n{err_str}"
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
        // Kalan stdout çıktısını borunun dolmaması için tüket
        let mut sink = [0u8; 4096];
        while let Ok(n) = std::io::Read::read(&mut reader, &mut sink) {
            if n == 0 {
                break;
            }
        }
    });

    match rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => Ok(ServerGuard { child }),
        Ok(Err(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!("Sunucu baslatilamadi: {msg}").into())
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!("Sunucu hazir sinyali zaman asimina ugradi: {e}").into())
        }
    }
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
    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key.serialize_pem())?;
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

struct HttpResp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

async fn send_http1_request(
    port: u16,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> TestResult<HttpResp> {
    let addr = format!("127.0.0.1:{port}");
    let mut stream =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr)).await??;
    let raw_req = if body.is_empty() {
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
    };
    stream.write_all(raw_req.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;

    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end;
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if n == 0 {
            return Err("Sunucu basliklari gondermeden baglantiyi kapatti".into());
        }
        raw.extend_from_slice(&chunk[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = pos + 4;
            break;
        }
    }

    let head_str = String::from_utf8_lossy(&raw[..head_end - 4]);
    let mut lines = head_str.lines();
    let status_line = lines.next().ok_or("Durum satiri eksik")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("HTTP durum kodu bulunamadi")?
        .parse()?;

    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().ok();
            }
            headers.push((key, val));
        }
    }

    let mut body_bytes = raw[head_end..].to_vec();
    match content_length {
        Some(expected_len) => {
            while body_bytes.len() < expected_len {
                let n =
                    tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
                if n == 0 {
                    break;
                }
                body_bytes.extend_from_slice(&chunk[..n]);
            }
            body_bytes.truncate(expected_len);
        }
        None => loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
            if n == 0 {
                break;
            }
            body_bytes.extend_from_slice(&chunk[..n]);
        },
    }

    Ok(HttpResp {
        status,
        headers,
        body: String::from_utf8_lossy(&body_bytes).into_owned(),
    })
}

async fn tls_handshake_serial_and_optional_h2_get(
    port: u16,
    sni_host: &str,
    h2_acme_path: Option<&str>,
) -> TestResult<(String, Option<(u16, String)>)> {
    let alpn = if h2_acme_path.is_some() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    let connector = build_tls_connector(alpn)?;
    let tcp = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{port}")),
    )
    .await??;
    let server_name = ServerName::try_from(sni_host.to_string())?;
    let tls_stream =
        tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp)).await??;

    let peer_der = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or("Sunucu sertifikasi alinamadi")?
        .as_ref()
        .to_vec();
    let serial_hex =
        extract_cert_serial_hex(&peer_der).ok_or("Sertifika seri numarasi ayristirilamadi")?;

    let h2_result = if let Some(path) = h2_acme_path {
        let negotiated = tls_stream.get_ref().1.alpn_protocol().map(|p| p.to_vec());
        if negotiated.as_deref() != Some(b"h2") {
            return Err(format!("ALPN h2 secilmedi: {negotiated:?}").into());
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
        let response = tokio::time::timeout(Duration::from_secs(5), resp_fut).await??;
        let status = response.status().as_u16();
        let mut body_stream = response.into_body();
        let mut body_bytes = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let bytes = chunk?;
            body_bytes.extend_from_slice(&bytes);
            let _ = body_stream.flow_control().release_capacity(bytes.len());
        }
        conn_task.abort();
        Some((status, String::from_utf8_lossy(&body_bytes).into_owned()))
    } else {
        None
    };

    Ok((serial_hex, h2_result))
}

fn toml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn write_zmax_toml(conf_path: &Path, acme_root_line: &str) -> TestResult<()> {
    let content = format!(
        r#"[server]
server_name = "ZMax-Kart6-Test"
workers = 2

[server.acme]
{acme_root_line}
force_https_exempt = true

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {HTTP_PORT}
backlog = 128
tcp_nodelay = true

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {HTTPS_PORT}
ssl = true

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {ADMIN_PORT}
document_root = "admin"
require_token = false

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {API_PORT}
require_token = false

[cache]
enabled = true
memory_cache_mb = 16
disk_cache_dir = "cachedata"
default_ttl_seconds = 60

[security]
rate_limit_enabled = false
block_path_traversal = true

[vhosts_dir]
path = "conf/vhosts"
"#
    );
    std::fs::write(conf_path, content)?;
    Ok(())
}

#[tokio::test]
async fn kart6_end_to_end_acme_root_precedence_traversal_and_tls_reload() -> TestResult<()> {
    let ws = TempWorkspace::new("all")?;
    let root = ws.path();

    // Ortak ve ozel ACME kokleri ile belge koklerini hazirla
    let global_acme_1 = root.join("global_acme_v1");
    let global_acme_2 = root.join("global_acme_v2");
    let vhost2_acme = root.join("vhost2_custom_acme");
    let site1_doc = root.join("www").join("site1");
    let site2_doc = root.join("www").join("site2");
    let site3_doc = root.join("www").join("site3_nowaf");

    for dir in [
        &global_acme_1.join(".well-known").join("acme-challenge"),
        &global_acme_2.join(".well-known").join("acme-challenge"),
        &vhost2_acme.join(".well-known").join("acme-challenge"),
        &site1_doc,
        &site2_doc.join(".well-known").join("acme-challenge"),
        &site3_doc,
    ] {
        std::fs::create_dir_all(dir)?;
    }

    // Normal sayfa + .htaccess (ACME challenge rewrite/redirect tarafindan ezilmemeli)
    std::fs::write(site1_doc.join("index.html"), "SITE1_HOME")?;
    std::fs::write(
        site1_doc.join(".htaccess"),
        "RewriteEngine On\nRewriteRule ^ /index.html [L]\n",
    )?;
    std::fs::write(site2_doc.join("index.html"), "SITE2_HOME")?;
    std::fs::write(site3_doc.join("index.html"), "SITE3_HOME")?;

    // Dis gizli dosya (traversal korumasi icin)
    std::fs::write(root.join("secret.txt"), "DISARI_GIZLI_BILGI")?;

    // (a) Sadece ortak global kokte bulunan challenge tokenlari (site1 docroot'ta yok)
    std::fs::write(
        global_acme_1
            .join(".well-known")
            .join("acme-challenge")
            .join("tok-global-nested"),
        "GLOBAL_NESTED_200_OK",
    )?;
    std::fs::write(global_acme_1.join("tok-global-flat"), "GLOBAL_FLAT_200_OK")?;

    // (b) Hem global hem vhost ozel kokte ayni adli token -> vhost ozel kok kazanmali
    std::fs::write(
        global_acme_1
            .join(".well-known")
            .join("acme-challenge")
            .join("tok-shared"),
        "FROM_GLOBAL_ROOT",
    )?;
    std::fs::write(
        vhost2_acme
            .join(".well-known")
            .join("acme-challenge")
            .join("tok-shared"),
        "FROM_VHOST2_CUSTOM_ACME_ROOT",
    )?;
    // docroot vs vhost ozel kok onceligi
    std::fs::write(
        site2_doc
            .join(".well-known")
            .join("acme-challenge")
            .join("tok-docroot-first"),
        "FROM_SITE2_DOCROOT",
    )?;
    std::fs::write(
        vhost2_acme
            .join(".well-known")
            .join("acme-challenge")
            .join("tok-docroot-first"),
        "FROM_VHOST2_CUSTOM_LOSER",
    )?;
    // Gizli nokta dosyasi (.hidden) hicbir durumda sunulmamali
    std::fs::write(
        vhost2_acme
            .join(".well-known")
            .join("acme-challenge")
            .join(".hidden"),
        "GIZLI_NOKTA_DOSYASI",
    )?;

    // Yenilenecek ikinci global kok dosyasi
    std::fs::write(
        global_acme_2
            .join(".well-known")
            .join("acme-challenge")
            .join("tok-reloaded"),
        "RELOADED_GLOBAL_ACME_TOKEN",
    )?;

    // (d) Ilk TLS sertifikasi (cert1)
    let cert_path = root.join("certs").join("site1.crt");
    let key_path = root.join("certs").join("site1.key");
    generate_self_signed_cert(&cert_path, &key_path, "site1.test", &["site1.test"])?;

    let conf_path = root.join("conf").join("zmax.toml");
    write_zmax_toml(
        &conf_path,
        &format!("acme_root = \"{}\"", toml_path(&global_acme_1)),
    )?;

    // vHost 1: Global ACME root kullanir, force_https = true, TLS sertifikali
    std::fs::write(
        root.join("conf").join("vhosts").join("01-site1.toml"),
        format!(
            r#"[vhost]
name = "site1.test"
document_root = "{}"

[vhost.ssl]
certificate = "{}"
key = "{}"

[vhost.security]
force_https = true
"#,
            toml_path(&site1_doc),
            toml_path(&cert_path),
            toml_path(&key_path),
        ),
    )?;

    // vHost 2: Kendi [vhost.acme] acme_root tanimli + WAF kapali test (.. traversal 404 kontrolu dahil)
    std::fs::write(
        root.join("conf").join("vhosts").join("02-site2.toml"),
        format!(
            r#"[vhost]
name = "site2.test"
document_root = "{}"

[vhost.acme]
acme_root = "{}"
"#,
            toml_path(&site2_doc),
            toml_path(&vhost2_acme),
        ),
    )?;

    // vHost 3: WAF devre disi birakilarak dogrudan static ACME cozumleyicisinin traversal -> 404 cevabini dogrula
    std::fs::write(
        root.join("conf").join("vhosts").join("03-site3-nowaf.toml"),
        format!(
            r#"[vhost]
name = "site3-nowaf.test"
document_root = "{}"

[vhost.security]
waf_enabled = false

[vhost.acme]
acme_root = "{}"
"#,
            toml_path(&site3_doc),
            toml_path(&vhost2_acme),
        ),
    )?;

    // Canli ZMax surecini baslat ve "hazir!" satirini bekle (sifir sleep / polling)
    let _server = spawn_zmax_and_wait_ready(root, &conf_path)?;

    // --- (a) Global acme_root: docroot'ta yok, ortak kokten 200 OK ve force_https muafiyeti ---
    let redirect_resp =
        send_http1_request(HTTP_PORT, "GET", "site1.test", "/index.html", b"").await?;
    assert_eq!(
        redirect_resp.status, 301,
        "Normal HTTP istegi force_https ile 301 almali"
    );

    let acme_nested = send_http1_request(
        HTTP_PORT,
        "GET",
        "site1.test",
        "/.well-known/acme-challenge/tok-global-nested",
        b"",
    )
    .await?;
    assert_eq!(acme_nested.status, 200);
    assert_eq!(
        acme_nested.header("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(acme_nested.body, "GLOBAL_NESTED_200_OK");

    let acme_flat = send_http1_request(
        HTTP_PORT,
        "GET",
        "site1.test",
        "/.well-known/acme-challenge/tok-global-flat",
        b"",
    )
    .await?;
    assert_eq!(acme_flat.status, 200);
    assert_eq!(acme_flat.body, "GLOBAL_FLAT_200_OK");

    let acme_missing = send_http1_request(
        HTTP_PORT,
        "GET",
        "site1.test",
        "/.well-known/acme-challenge/olmayan-token",
        b"",
    )
    .await?;
    assert_eq!(acme_missing.status, 404);

    // --- (b) vhost acme_root varsa o once (ve vhost docroot > vhost acme_root) ---
    let site2_shared = send_http1_request(
        HTTP_PORT,
        "GET",
        "site2.test",
        "/.well-known/acme-challenge/tok-shared",
        b"",
    )
    .await?;
    assert_eq!(site2_shared.status, 200);
    assert_eq!(site2_shared.body, "FROM_VHOST2_CUSTOM_ACME_ROOT");

    let site1_shared = send_http1_request(
        HTTP_PORT,
        "GET",
        "site1.test",
        "/.well-known/acme-challenge/tok-shared",
        b"",
    )
    .await?;
    assert_eq!(site1_shared.status, 200);
    assert_eq!(site1_shared.body, "FROM_GLOBAL_ROOT");

    let site2_docroot_pref = send_http1_request(
        HTTP_PORT,
        "GET",
        "site2.test",
        "/.well-known/acme-challenge/tok-docroot-first",
        b"",
    )
    .await?;
    assert_eq!(site2_docroot_pref.status, 200);
    assert_eq!(site2_docroot_pref.body, "FROM_SITE2_DOCROOT");

    let site2_isolated = send_http1_request(
        HTTP_PORT,
        "GET",
        "site2.test",
        "/.well-known/acme-challenge/tok-global-nested",
        b"",
    )
    .await?;
    assert_eq!(
        site2_isolated.status, 404,
        "Kendi vhost.acme.acme_root tanimli vhost global ACME koke dusmemeli"
    );

    // --- (c) Ortak kok disina .. -> 404 (WAF kapatilmis vhost uzerinde dogrudan static resolver kaniti) ---
    let traversal_raw = send_http1_request(
        HTTP_PORT,
        "GET",
        "site3-nowaf.test",
        "/.well-known/acme-challenge/../../secret.txt",
        b"",
    )
    .await?;
    assert_eq!(traversal_raw.status, 404);
    assert!(!traversal_raw.body.contains("DISARI_GIZLI_BILGI"));

    let traversal_encoded = send_http1_request(
        HTTP_PORT,
        "GET",
        "site3-nowaf.test",
        "/.well-known/acme-challenge/%2e%2e/%2e%2e/secret.txt",
        b"",
    )
    .await?;
    assert_eq!(traversal_encoded.status, 404);
    assert!(!traversal_encoded.body.contains("DISARI_GIZLI_BILGI"));

    let hidden_dotfile = send_http1_request(
        HTTP_PORT,
        "GET",
        "site3-nowaf.test",
        "/.well-known/acme-challenge/.hidden",
        b"",
    )
    .await?;
    assert_eq!(hidden_dotfile.status, 404);

    // --- (d) Ilk TLS sertifikasini (ve HTTP/2 ACME cozumlemesini) dogrula, yenile, /api/v1/reload cagir ---
    let (serial_before, h2_acme_res) = tls_handshake_serial_and_optional_h2_get(
        HTTPS_PORT,
        "site1.test",
        Some("/.well-known/acme-challenge/tok-global-nested"),
    )
    .await?;
    let (h2_status, h2_body) = h2_acme_res.ok_or("HTTP/2 ACME yaniti eksik")?;
    assert_eq!(h2_status, 200);
    assert_eq!(h2_body, "GLOBAL_NESTED_200_OK");

    // Diskteki sertifikayi yenile ve farkli seri numarali cert2 olustur
    generate_self_signed_cert(&cert_path, &key_path, "site1.test", &["site1.test"])?;

    // Ayrica zmax.toml uzerinde server.acme.acme_root degerini yeni ortak koke guncelle
    write_zmax_toml(
        &conf_path,
        &format!("acme_root = \"{}\"", toml_path(&global_acme_2)),
    )?;

    let reload_resp =
        send_http1_request(API_PORT, "POST", "127.0.0.1", "/api/v1/reload", b"").await?;
    assert_eq!(reload_resp.status, 200);
    assert!(
        reload_resp.body.contains("\"status\":\"reloaded\""),
        "Beklenmeyen reload yaniti: {}",
        reload_resp.body
    );

    // Reload sonrasi YENI TLS sertifika seri numarasi sunuldugunu kanitla
    let (serial_after, _) =
        tls_handshake_serial_and_optional_h2_get(HTTPS_PORT, "site1.test", None).await?;
    assert_ne!(
        serial_before, serial_after,
        "POST /api/v1/reload sonrasi yeni sertifika seri no sunulmali"
    );

    // Reload sonrasi yeni global acme_root guncellenmis olmali
    let reloaded_acme = send_http1_request(
        HTTP_PORT,
        "GET",
        "site1.test",
        "/.well-known/acme-challenge/tok-reloaded",
        b"",
    )
    .await?;
    assert_eq!(reloaded_acme.status, 200);
    assert_eq!(reloaded_acme.body, "RELOADED_GLOBAL_ACME_TOKEN");

    // Reload sirasinda acme_root bosaltilirsa clear_global_acme_root cagrilmamali (mevcut kok korunur)
    write_zmax_toml(&conf_path, "acme_root = \"\"")?;
    let reload_empty =
        send_http1_request(API_PORT, "POST", "127.0.0.1", "/api/v1/reload", b"").await?;
    assert_eq!(reload_empty.status, 200);

    let still_preserved = send_http1_request(
        HTTP_PORT,
        "GET",
        "site1.test",
        "/.well-known/acme-challenge/tok-reloaded",
        b"",
    )
    .await?;
    assert_eq!(still_preserved.status, 200);
    assert_eq!(still_preserved.body, "RELOADED_GLOBAL_ACME_TOKEN");

    Ok(())
}
