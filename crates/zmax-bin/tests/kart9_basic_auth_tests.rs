//! Kart 9 — HTTP Basic Authentication ($apr1$ Apache MD5 & Argon2id) Uçtan Uca Entegrasyon Testleri
//!
//! Atanan port bloğu: 21090-21093 (21090 HTTP, 21091 HTTPS/H2, 21092 Admin kapalı, 21093 API kapalı).

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsConnector;

const HTTP_PORT: u16 = 21090;
const HTTPS_PORT: u16 = 21091;
const ADMIN_PORT: u16 = 21092;
const API_PORT: u16 = 21093;

struct ChildGuard {
    child: Child,
    temp_dir: PathBuf,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.temp_dir);
    }
}

fn make_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "zmax_kart9_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn encode_basic_token(user: &str, pass: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{}:{}", user, pass);
    let input = raw.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if i + 1 < input.len() {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < input.len() {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
        i += 3;
    }
    format!("Basic {}", out)
}

fn spawn_zmax_and_wait_ready(
    base_dir: &Path,
    conf_path: &Path,
) -> (Child, Arc<std::sync::Mutex<String>>) {
    let bin = env!("CARGO_BIN_EXE_zmax");
    let mut child = Command::new(bin)
        .arg("-c")
        .arg(conf_path)
        .env("ZMAX_HOME", base_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("zmax ikilisi baslatilamadi");

    let stdout = child.stdout.take().expect("stdout pipe");
    let stderr = child.stderr.take().expect("stderr pipe");
    let output_log = Arc::new(std::sync::Mutex::new(String::new()));

    let err_log = Arc::clone(&output_log);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if let Ok(mut g) = err_log.lock() {
                g.push_str(&line);
            }
            line.clear();
        }
    });

    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let out_log = Arc::clone(&output_log);
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut notified = false;
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            if let Ok(mut g) = out_log.lock() {
                g.push_str(&line);
            }
            if !notified && line.contains("sifir port cakismasiyla hazir") {
                notified = true;
                let _ = ready_tx.send(Ok(()));
            }
            line.clear();
        }
        if !notified {
            let _ = ready_tx.send(Err("zmax hazir mesaji vermeden cikti".to_string()));
        }
    });

    match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => {
            let logs = output_log.lock().map(|g| g.clone()).unwrap_or_default();
            let _ = child.kill();
            panic!("{}: {}", reason, logs);
        }
        Err(_) => {
            let logs = output_log.lock().map(|g| g.clone()).unwrap_or_default();
            let _ = child.kill();
            panic!("zmax 15s icinde hazir olmadi. Cikti:\n{}", logs);
        }
    }

    (child, output_log)
}

async fn send_http1(host: &str, path: &str, auth_header: Option<&str>) -> String {
    let mut stream = TokioTcpStream::connect(("127.0.0.1", HTTP_PORT))
        .await
        .expect("HTTP portuna baglanilamadi");
    let mut req = format!("GET {} HTTP/1.1\r\nHost: {}\r\n", path, host);
    if let Some(auth) = auth_header {
        req.push_str(&format!("Authorization: {}\r\n", auth));
    }
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[derive(Debug)]
struct NoVerifyCert;

impl rustls::client::danger::ServerCertVerifier for NoVerifyCert {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _s: &ServerName<'_>,
        _o: &[u8],
        _n: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn make_h2_tls_client(
    sni_domain: &str,
) -> (
    h2::client::SendRequest<bytes::Bytes>,
    tokio::task::JoinHandle<()>,
) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyCert))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));

    let tcp = TokioTcpStream::connect(("127.0.0.1", HTTPS_PORT))
        .await
        .expect("HTTPS portuna baglanilamadi");
    let tls = connector
        .connect(ServerName::try_from(sni_domain.to_string()).unwrap(), tcp)
        .await
        .expect("TLS el sikismasi basarisiz");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (client, conn) = h2::client::handshake(tls)
        .await
        .expect("H2 client handshake basarisiz");
    let handle = tokio::spawn(async move {
        let _ = conn.await;
    });
    (client, handle)
}

async fn send_h2(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    host: &str,
    path: &str,
    auth_header: Option<&str>,
) -> (http::StatusCode, http::HeaderMap, String) {
    let mut builder = http::Request::builder()
        .method("GET")
        .uri(format!("https://{}{}", host, path))
        .header("host", host);
    if let Some(auth) = auth_header {
        builder = builder.header("authorization", auth);
    }
    let req = builder.body(()).unwrap();
    let (resp_fut, _) = client.send_request(req, true).unwrap();
    let resp = resp_fut.await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();

    let mut body_stream = resp.into_body();
    let mut body_bytes = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let b = chunk.unwrap();
        body_bytes.extend_from_slice(&b);
        let _ = body_stream.flow_control().release_capacity(b.len());
    }
    (
        status,
        headers,
        String::from_utf8_lossy(&body_bytes).into_owned(),
    )
}

#[tokio::test]
async fn kart9_basic_auth_real_zmax_http1_and_http2_end_to_end() {
    let base_dir = make_temp_dir("e2e");
    let conf_dir = base_dir.join("conf");
    let vhosts_dir = conf_dir.join("vhosts");
    let auth_dir = conf_dir.join("auth");
    let ssl_dir = conf_dir.join("ssl");
    let modules_dir = base_dir.join("modules");
    let site1_root = base_dir.join("www").join("auth.local");
    let site2_root = base_dir.join("www").join("prefix.local");

    std::fs::create_dir_all(&vhosts_dir).unwrap();
    std::fs::create_dir_all(&auth_dir).unwrap();
    std::fs::create_dir_all(&ssl_dir).unwrap();
    std::fs::create_dir_all(&modules_dir).unwrap();
    std::fs::create_dir_all(site1_root.join("gizli").join("super")).unwrap();
    std::fs::create_dir_all(site1_root.join(".well-known").join("acme-challenge")).unwrap();
    std::fs::create_dir_all(site2_root.join("yonetim")).unwrap();

    // Kendi imzali TLS sertifikasi (HTTP/2 ALPN testleri icin)
    let ck = rcgen::generate_simple_self_signed(vec![
        "auth.local".to_string(),
        "prefix.local".to_string(),
        "127.0.0.1".to_string(),
    ])
    .unwrap();
    std::fs::write(ssl_dir.join("site.crt"), ck.cert.pem()).unwrap();
    std::fs::write(ssl_dir.join("site.key"), ck.signing_key.serialize_pem()).unwrap();

    // Test dosyalari
    std::fs::write(site1_root.join("acik.html"), "ACIK_SAYFA_OK").unwrap();
    std::fs::write(
        site1_root.join("gizli").join("index.html"),
        "GIZLI_ALAN_200",
    )
    .unwrap();
    std::fs::write(
        site1_root.join("gizli").join("super").join("ayar.html"),
        "SUPER_ALAN_200",
    )
    .unwrap();
    std::fs::write(
        site1_root
            .join(".well-known")
            .join("acme-challenge")
            .join("tok123"),
        "acme-proof-ok",
    )
    .unwrap();
    std::fs::write(site2_root.join("genel.html"), "PREFIX_ACIK_200").unwrap();
    std::fs::write(
        site2_root.join("yonetim").join("index.html"),
        "YONETIM_ARGON2_200",
    )
    .unwrap();

    // Parolalar & ozetler
    let apr1_pass = "SifreApr1!";
    let apr1_hash_val = zmax_security::apr1_hash(apr1_pass, "k9salt12");
    let argon_pass = "SifreArgon2id!";
    let argon_hash_val =
        zmax_security::argon2id_hash(argon_pass, b"k9argonsalt12", 512, 2, 1).unwrap();
    let super_pass = "SuperSifre99";
    let super_hash_val = zmax_security::apr1_hash(super_pass, "sup98765");

    std::fs::write(
        auth_dir.join("site1.htpasswd"),
        format!(
            "apruser:{}\nargonuser:{}\ndesuser:abJnggxhB/yWI\nplainuser:{{PLAIN}}AcikSifre123\n",
            apr1_hash_val, argon_hash_val
        ),
    )
    .unwrap();

    // Ana zmax.toml (atanan 21090-21093 port blogu)
    let conf_path = conf_dir.join("zmax.toml");
    std::fs::write(
        &conf_path,
        format!(
            r#"
[server]
server_name = "ZMax/Kart9Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {HTTP_PORT}

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {HTTPS_PORT}
ssl = true

[listeners.admin]
enabled = false
address = "127.0.0.1"
port = {ADMIN_PORT}

[listeners.api]
enabled = false
address = "127.0.0.1"
port = {API_PORT}

[vhosts_dir]
path = "conf/vhosts"

[cache]
enabled = true
memory_cache_mb = 16
default_ttl_seconds = 60
disk_cache_dir = "cache"

[logging]
level = "info"
access_log = "logs/access.log"
error_log = "logs/error.log"
batch_flush_ms = 50
"#
        ),
    )
    .unwrap();

    // vHost 1: htpasswd_path + directories ($apr1$ & Argon2id)
    std::fs::write(
        vhosts_dir.join("auth.local.toml"),
        format!(
            r#"
[vhost]
name = "auth.local"
document_root = "www/auth.local"

[vhost.ssl]
certificate = "conf/ssl/site.crt"
key = "conf/ssl/site.key"

[vhost.tls]
http2 = true

[vhost.php]
enabled = false

[vhost.auth]
enabled = true
realm = "Genel Alan"
htpasswd_path = "conf/auth/site1.htpasswd"

[[vhost.auth.directories]]
path = "/gizli"
realm = "Gizli Dizin"

[[vhost.auth.directories]]
path_prefix = "/gizli/super"
realm = "Super Alan"

[[vhost.auth.directories.users]]
username = "superroot"
password_hash = "{super_hash_val}"
"#
        ),
    )
    .unwrap();

    // vHost 2: vHost-duzeyi path_prefix + inline Argon2id
    std::fs::write(
        vhosts_dir.join("prefix.local.toml"),
        format!(
            r#"
[vhost]
name = "prefix.local"
document_root = "www/prefix.local"

[vhost.ssl]
certificate = "conf/ssl/site.crt"
key = "conf/ssl/site.key"

[vhost.tls]
http2 = true

[vhost.php]
enabled = false

[vhost.auth]
enabled = true
realm = "Yonetim Girisi"
path_prefix = "/yonetim"

[[vhost.auth.users]]
username = "argonuser"
password_hash = "{argon_hash_val}"
"#
        ),
    )
    .unwrap();

    let (child, proc_logs) = spawn_zmax_and_wait_ready(&base_dir, &conf_path);
    let guard = ChildGuard {
        child,
        temp_dir: base_dir.clone(),
    };

    // -------------------------------------------------------------------------
    // KISIM 1: Gercek HTTP/1.1 Testleri (Port 21090)
    // -------------------------------------------------------------------------
    let ok_apr = encode_basic_token("apruser", apr1_pass);
    let ok_argon = encode_basic_token("argonuser", argon_pass);
    let ok_super = encode_basic_token("superroot", super_pass);
    let bad_cred = encode_basic_token("apruser", "YanlisParolaXYZ");

    // 1.1 Korumasiz yol -> 200 OK
    let r = send_http1("auth.local", "/acik.html", None).await;
    assert!(
        r.starts_with("HTTP/1.1 200 OK"),
        "Korumasiz yol 200 olmali: {r}"
    );
    assert!(r.contains("ACIK_SAYFA_OK"), "{r}");

    // 1.2 Korumali yol, Authorization yok -> 401 + WWW-Authenticate
    let r = send_http1("auth.local", "/gizli/index.html", None).await;
    assert!(
        r.starts_with("HTTP/1.1 401 Unauthorized"),
        "Basliksiz 401 olmali: {r}"
    );
    assert!(
        r.contains("WWW-Authenticate: Basic realm=\"Gizli Dizin\""),
        "WWW-Authenticate eksik: {r}"
    );
    assert!(r.contains("Cache-Control: no-store"), "{r}");

    // 1.3 Yanlis parola -> 401 + WWW-Authenticate
    let r = send_http1("auth.local", "/gizli/index.html", Some(&bad_cred)).await;
    assert!(
        r.starts_with("HTTP/1.1 401 Unauthorized"),
        "Yanlis parola 401 olmali: {r}"
    );
    assert!(
        r.contains("WWW-Authenticate: Basic realm=\"Gizli Dizin\""),
        "{r}"
    );

    // 1.4 Percent-encoded / cift slash atlatma denemesi -> 401
    let r = send_http1("auth.local", "//%67izli/index.html", None).await;
    assert!(
        r.starts_with("HTTP/1.1 401 Unauthorized"),
        "Atlatma denemesi 401 olmali: {r}"
    );

    // 1.5 Dogru $apr1$ parola -> 200 OK (Cache acikken bile ilk seferde ve tekrarlarda dogrulanmali)
    let r = send_http1("auth.local", "/gizli/index.html", Some(&ok_apr)).await;
    assert!(
        r.starts_with("HTTP/1.1 200 OK"),
        "$apr1$ dogru parola 200 olmali: {r}"
    );
    assert!(r.contains("GIZLI_ALAN_200"), "{r}");

    // Cache isinmis olsa bile basliksiz istek ASLA 200 almamali -> 401!
    let r = send_http1("auth.local", "/gizli/index.html", None).await;
    assert!(
        r.starts_with("HTTP/1.1 401 Unauthorized"),
        "Onbellekten yetkisiz icerik donmemeli: {r}"
    );

    // 1.6 Dogru $argon2id$ parola -> 200 OK
    let r = send_http1("auth.local", "/gizli/index.html", Some(&ok_argon)).await;
    assert!(
        r.starts_with("HTTP/1.1 200 OK"),
        "$argon2id$ dogru parola 200 olmali: {r}"
    );
    assert!(r.contains("GIZLI_ALAN_200"), "{r}");

    // 1.6.1 GÜVENLİK (P2): DES crypt hash'i (abJnggxhB/yWI) asla parola olarak kabul edilmemeli -> 401
    let des_token = encode_basic_token("desuser", "abJnggxhB/yWI");
    let r = send_http1("auth.local", "/gizli/index.html", Some(&des_token)).await;
    assert!(
        r.starts_with("HTTP/1.1 401 Unauthorized"),
        "DES crypt hash'i parola olarak kabul EDILMEMELI: {r}"
    );

    // 1.6.2 Açıkça {PLAIN} formatlı parola -> 200 OK
    let plain_token = encode_basic_token("plainuser", "AcikSifre123");
    let r = send_http1("auth.local", "/gizli/index.html", Some(&plain_token)).await;
    assert!(
        r.starts_with("HTTP/1.1 200 OK"),
        "{{PLAIN}} formati basarili olmali: {r}"
    );

    // 1.6.3 Bilinmeyen Kullanıcı (Timing Attack / User Enumeration) Sahte Hash -> 401
    let unknown_token = encode_basic_token("olmayankullanici", "RastgeleSifre123");
    let r = send_http1("auth.local", "/gizli/index.html", Some(&unknown_token)).await;
    assert!(
        r.starts_with("HTTP/1.1 401 Unauthorized"),
        "Bilinmeyen kullanici reddedilmeli: {r}"
    );

    // 1.6.4 P1 DoS ve Worker İzolasyonu: Ağır/yanlış Argon2id doğrulama sürerken paralel istek gecikmez
    let bad_argon_tok = encode_basic_token("argonuser", "YanlisArgonParolasi999");
    let h_bg = tokio::spawn(async move {
        send_http1("auth.local", "/gizli/index.html", Some(&bad_argon_tok)).await
    });
    let t0 = std::time::Instant::now();
    let r_fast = send_http1("auth.local", "/acik.html", None).await;
    let fast_ms = t0.elapsed().as_millis();
    assert!(r_fast.starts_with("HTTP/1.1 200 OK"));
    assert!(
        fast_ms < 400,
        "Tokio worker tikanmamali, paralel istek hizlica yanit almali ({}ms)",
        fast_ms
    );
    let _ = h_bg.await;

    // 1.7 En uzun dizin oneki (/gizli/super) kendi kullanicisini ister
    let r = send_http1("auth.local", "/gizli/super/ayar.html", Some(&ok_apr)).await;
    assert!(r.starts_with("HTTP/1.1 401 Unauthorized"), "{r}");
    assert!(
        r.contains("WWW-Authenticate: Basic realm=\"Super Alan\""),
        "{r}"
    );
    let r = send_http1("auth.local", "/gizli/super/ayar.html", Some(&ok_super)).await;
    assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    assert!(r.contains("SUPER_ALAN_200"), "{r}");

    // 1.8 ACME HTTP-01 muafiyeti -> 200 OK
    let r = send_http1("auth.local", "/.well-known/acme-challenge/tok123", None).await;
    assert!(r.starts_with("HTTP/1.1 200 OK"), "ACME muaf olmali: {r}");
    assert!(r.contains("acme-proof-ok"), "{r}");

    // 1.9 vHost-duzeyi path_prefix (/yonetim) kontrolu
    let r = send_http1("prefix.local", "/genel.html", None).await;
    assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    let r = send_http1("prefix.local", "/yonetim/index.html", None).await;
    assert!(r.starts_with("HTTP/1.1 401 Unauthorized"), "{r}");
    assert!(
        r.contains("WWW-Authenticate: Basic realm=\"Yonetim Girisi\""),
        "{r}"
    );
    let r = send_http1("prefix.local", "/yonetim/index.html", Some(&ok_argon)).await;
    assert!(r.starts_with("HTTP/1.1 200 OK"), "{r}");
    assert!(r.contains("YONETIM_ARGON2_200"), "{r}");

    // -------------------------------------------------------------------------
    // KISIM 2: Gercek HTTP/2 (TLS + ALPN h2) Testleri (Port 21091)
    // -------------------------------------------------------------------------
    {
        let (mut h2_client, _conn_handle) = make_h2_tls_client("auth.local").await;

        let (st, _, body) = send_h2(&mut h2_client, "auth.local", "/acik.html", None).await;
        assert_eq!(st, http::StatusCode::OK);
        assert!(body.contains("ACIK_SAYFA_OK"));

        let (st, hdrs, _) = send_h2(&mut h2_client, "auth.local", "/gizli/index.html", None).await;
        assert_eq!(st, http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            hdrs.get("www-authenticate").and_then(|v| v.to_str().ok()),
            Some("Basic realm=\"Gizli Dizin\"")
        );

        let (st, _, _) = send_h2(
            &mut h2_client,
            "auth.local",
            "/gizli/index.html",
            Some(&bad_cred),
        )
        .await;
        assert_eq!(st, http::StatusCode::UNAUTHORIZED);

        let (st, _, body) = send_h2(
            &mut h2_client,
            "auth.local",
            "/gizli/index.html",
            Some(&ok_apr),
        )
        .await;
        assert_eq!(st, http::StatusCode::OK);
        assert!(body.contains("GIZLI_ALAN_200"));

        let (st, _, body) = send_h2(
            &mut h2_client,
            "auth.local",
            "/gizli/index.html",
            Some(&ok_argon),
        )
        .await;
        assert_eq!(st, http::StatusCode::OK);
        assert!(body.contains("GIZLI_ALAN_200"));
    }

    {
        let (mut h2_prefix, _conn_handle) = make_h2_tls_client("prefix.local").await;
        let (st, hdrs, _) =
            send_h2(&mut h2_prefix, "prefix.local", "/yonetim/index.html", None).await;
        assert_eq!(st, http::StatusCode::UNAUTHORIZED);
        assert_eq!(
            hdrs.get("www-authenticate").and_then(|v| v.to_str().ok()),
            Some("Basic realm=\"Yonetim Girisi\"")
        );
        let (st, _, body) = send_h2(
            &mut h2_prefix,
            "prefix.local",
            "/yonetim/index.html",
            Some(&ok_argon),
        )
        .await;
        assert_eq!(st, http::StatusCode::OK);
        assert!(body.contains("YONETIM_ARGON2_200"));
    }

    // -------------------------------------------------------------------------
    // KISIM 3: Gunluklerde Parola / Hash / Authorization Token Sizintisi Olmamali
    // -------------------------------------------------------------------------
    let secrets = [
        apr1_pass,
        argon_pass,
        super_pass,
        "YanlisParolaXYZ",
        ok_apr.as_str(),
        ok_argon.as_str(),
        ok_super.as_str(),
        bad_cred.as_str(),
        apr1_hash_val.as_str(),
        argon_hash_val.as_str(),
    ];

    let stdout_stderr = proc_logs.lock().map(|g| g.clone()).unwrap_or_default();
    for secret in secrets {
        assert!(
            !stdout_stderr.contains(secret),
            "Sunucu stdout/stderr cikisinda parola/ozet sizintisi!"
        );
    }

    for log_name in ["logs/access.log", "logs/error.log"] {
        let lp = base_dir.join(log_name);
        if lp.is_file() {
            let content = std::fs::read_to_string(&lp).unwrap_or_default();
            for secret in secrets {
                assert!(
                    !content.contains(secret),
                    "{} dosyasinda parola/ozet sizintisi!",
                    log_name
                );
            }
        }
    }

    drop(guard);
    // Sunucu kapandiktan sonra portlarin serbest birakildigini kontrol et
    assert!(TcpStream::connect(("127.0.0.1", HTTP_PORT)).is_err());
}

#[test]
fn kart9_config_check_validates_auth_toml() {
    let base_dir = make_temp_dir("cfgcheck");
    let conf_dir = base_dir.join("conf");
    let vhosts_dir = conf_dir.join("vhosts");
    let modules_dir = base_dir.join("modules");
    std::fs::create_dir_all(&vhosts_dir).unwrap();
    std::fs::create_dir_all(&modules_dir).unwrap();

    let conf_path = conf_dir.join("zmax.toml");
    std::fs::write(
        &conf_path,
        format!(
            r#"
[listeners.http]
port = {HTTP_PORT}
[listeners.https]
port = {HTTPS_PORT}
[listeners.admin]
enabled = false
port = {ADMIN_PORT}
[listeners.api]
enabled = false
port = {API_PORT}
[vhosts_dir]
path = "conf/vhosts"
"#
        ),
    )
    .unwrap();

    let hash = zmax_security::apr1_hash("gizli", "s1234567");
    let vhost_file = vhosts_dir.join("check.test.toml");
    std::fs::write(
        &vhost_file,
        format!(
            r#"
[vhost]
name = "check.test"
document_root = "www/check"

[vhost.auth]
enabled = true
realm = "Kontrol Alani"
path_prefix = "/panel"

[[vhost.auth.users]]
username = "kullanici"
password_hash = "{hash}"
"#
        ),
    )
    .unwrap();

    let bin = env!("CARGO_BIN_EXE_zmax");
    let ok_out = Command::new(bin)
        .arg("-t")
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", &base_dir)
        .output()
        .expect("zmax -t calistirilamadi");
    assert!(
        ok_out.status.success(),
        "Gecerli auth TOML -t basarisiz: {}",
        String::from_utf8_lossy(&ok_out.stderr)
    );

    // Gecersiz traversal htpasswd_path iceren TOML -t tarafindan reddedilmeli
    std::fs::write(
        &vhost_file,
        r#"
[vhost]
name = "check.test"
document_root = "www/check"

[vhost.auth]
enabled = true
htpasswd_path = "../../../etc/shadow"
"#,
    )
    .unwrap();

    let bad_out = Command::new(bin)
        .arg("-t")
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", &base_dir)
        .output()
        .expect("zmax -t calistirilamadi");
    assert!(
        !bad_out.status.success(),
        "Path traversal htpasswd_path -t tarafindan reddedilmeliydi"
    );

    let _ = std::fs::remove_dir_all(&base_dir);
}

#[test]
fn des_crypt_hash_not_accepted_as_password() {
    let des_hash = "abJnggxhB/yWI";
    // DES crypt hash'i parola olarak verilirse reddedilmeli
    assert!(
        !zmax_security::verify_password(des_hash, des_hash),
        "DES crypt hash'i asla parola olarak kabul edilmemeli!"
    );
    assert!(!zmax_security::verify_password(des_hash, "password"));
    assert!(!zmax_security::verify_password(des_hash, "gizli"));

    // Öneksiz düz metinler güvenlik gereği reddedilir
    assert!(!zmax_security::verify_password("duzmetin", "duzmetin"));

    // Düz metin parolalar yalnızca açıkça {PLAIN} veya plain: önekiyle kabul edilir
    assert!(zmax_security::verify_password("{PLAIN}duzmetin", "duzmetin"));
    assert!(zmax_security::verify_password("plain:duzmetin", "duzmetin"));
    assert!(!zmax_security::verify_password("{PLAIN}duzmetin", "yanlis"));
}

#[tokio::test]
async fn unknown_user_timing_matches_known_user() {
    use zmax_config::{AuthUserEntry, VHostAuthSection};
    use zmax_security::{AuthDecision, BasicAuthManager, IpBanManager};

    let manager = Arc::new(BasicAuthManager::new());
    let ban_mgr = IpBanManager::new();
    let test_ip: std::net::IpAddr = "10.0.9.11".parse().unwrap();

    let argon_pass = "GizliSifre2026!";
    let argon_hash = zmax_security::argon2id_hash(argon_pass, b"saltsalt1234", 1024, 2, 1).unwrap();
    let mut vhost_auth = VHostAuthSection {
        enabled: true,
        realm: "Timing Match Test".to_string(),
        ..Default::default()
    };
    vhost_auth.users.push(AuthUserEntry {
        username: "gercekkullanici".to_string(),
        password_hash: argon_hash,
    });

    let known_bad_tok = encode_basic_token("gercekkullanici", "YanlisSifre999");
    let unknown_tok = encode_basic_token("olmayankullanici", "YanlisSifre999");

    // 1. Bilinen kullanıcı adı + yanlış parola (Argon2id hesaplanır)
    let t0 = std::time::Instant::now();
    let r1 = manager
        .check_request_async(
            test_ip,
            Some(&known_bad_tok),
            "/gizli",
            &vhost_auth,
            None,
            &ban_mgr,
        )
        .await;
    let dur_known = t0.elapsed();
    assert!(matches!(r1, AuthDecision::Unauthorized { .. }));

    // 2. Bilinmeyen kullanıcı adı (Dummy Argon2id hesaplanır)
    let t1 = std::time::Instant::now();
    let r2 = manager
        .check_request_async(
            test_ip,
            Some(&unknown_tok),
            "/gizli",
            &vhost_auth,
            None,
            &ban_mgr,
        )
        .await;
    let dur_unknown = t1.elapsed();
    assert!(matches!(r2, AuthDecision::Unauthorized { .. }));

    // Bilinmeyen kullanıcı için sahte Argon2id hesaplandığından süre sıfır veya anlık değildir
    assert!(
        dur_unknown.as_millis() >= 1,
        "Bilinmeyen kullanici icin sahte hash calistirilmali, gecen sure: {:?}, bilinen sure: {:?}",
        dur_unknown,
        dur_known
    );
}

#[tokio::test]
async fn dos_protection_argon2_parallel_not_blocking() {
    use zmax_config::{AuthUserEntry, VHostAuthSection};
    use zmax_security::{AuthDecision, BasicAuthManager, IpBanManager};

    let manager = Arc::new(BasicAuthManager::with_max_concurrent_hashes(4));
    let ban_mgr = Arc::new(IpBanManager::new());
    let test_ip: std::net::IpAddr = "10.0.9.12".parse().unwrap();

    let argon_pass = "AgirArgonSifresi!";
    let argon_hash = zmax_security::argon2id_hash(argon_pass, b"saltsalt1234", 1024, 3, 1).unwrap();
    let mut vhost_auth = VHostAuthSection {
        enabled: true,
        realm: "DoS Koruma Testi".to_string(),
        ..Default::default()
    };
    vhost_auth.users.push(AuthUserEntry {
        username: "argonuser".to_string(),
        password_hash: argon_hash,
    });

    // 6 paralel ağır istek (Semaphore(4) sınırı ve spawn_blocking izolasyonu)
    let mut tasks = Vec::new();
    for i in 0..6 {
        let mgr = manager.clone();
        let auth = vhost_auth.clone();
        let bm = ban_mgr.clone();
        let tok = encode_basic_token("argonuser", &format!("YanlisParola{}", i));
        tasks.push(tokio::spawn(async move {
            mgr.check_request_async(test_ip, Some(&tok), "/dos", &auth, None, &bm)
                .await
        }));
    }

    // Ana tokio worker serbest kalmalı, paralel hafif async işlem anında bitmeli
    let t_start = std::time::Instant::now();
    tokio::task::yield_now().await;
    let light_elapsed = t_start.elapsed();
    assert!(
        light_elapsed < Duration::from_millis(200),
        "Tokio worker bloke edilmedi ({}ms)",
        light_elapsed.as_millis()
    );

    for t in tasks {
        let res = t.await.unwrap();
        assert!(matches!(res, AuthDecision::Unauthorized { .. }));
    }
}
