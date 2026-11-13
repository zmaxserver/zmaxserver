//! [matris-cache-tags] PURGE yetkilendirmesi, önbelleğe alma güvenliği ve LSCache başlık köprüsü.
//!
//! Tüm testler gerçek `zmax` sürecini (dinamik portlar) başlatır; PHP için sahte bir FastCGI
//! sunucusu (istek sayacıyla) ve HTTP/2 için gerçek bir `h2` istemcisi (TLS ALPN) kullanılır.

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::TlsConnector;

const PURGE_KEY: &str = "test-purge-anahtari-0123456789";
static TEST_SEQ: AtomicUsize = AtomicUsize::new(1);

// ---------------------------------------------------------------- sahte FastCGI

struct MockFcgi {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
}

impl MockFcgi {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("sahte FastCGI portu");
        let addr = listener.local_addr().expect("yerel adres");
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));
        let (stop_bg, hits_bg) = (Arc::clone(&stop), Arc::clone(&hits));
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = conn else { continue };
                let hits_conn = Arc::clone(&hits_bg);
                std::thread::spawn(move || serve_fcgi_connection(stream, &hits_conn));
            }
        });
        Self { addr, stop, hits }
    }

    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for MockFcgi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(300));
    }
}

fn read_fcgi_len(buf: &mut &[u8]) -> Option<usize> {
    let first = *buf.first()?;
    if first & 0x80 != 0 {
        if buf.len() < 4 {
            return None;
        }
        let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) & 0x7FFF_FFFF;
        *buf = &buf[4..];
        usize::try_from(v).ok()
    } else {
        *buf = &buf[1..];
        Some(usize::from(first))
    }
}

fn decode_fcgi_params(mut buf: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    while !buf.is_empty() {
        let (Some(k), Some(v)) = (read_fcgi_len(&mut buf), read_fcgi_len(&mut buf)) else {
            break;
        };
        if buf.len() < k + v {
            break;
        }
        map.insert(
            String::from_utf8_lossy(&buf[..k]).into_owned(),
            String::from_utf8_lossy(&buf[k..k + v]).into_owned(),
        );
        buf = &buf[k + v..];
    }
    map
}

fn write_fcgi_record(stream: &mut TcpStream, rec_type: u8, req_id: u16, data: &[u8]) {
    let len = u16::try_from(data.len()).expect("kayit 65535 baytı aşmamalı");
    let hdr = [
        1,
        rec_type,
        (req_id >> 8) as u8,
        (req_id & 0xFF) as u8,
        (len >> 8) as u8,
        (len & 0xFF) as u8,
        0,
        0,
    ];
    let _ = stream.write_all(&hdr);
    if !data.is_empty() {
        let _ = stream.write_all(data);
    }
}

/// URI'ye göre CGI yanıtı; `seq` backend'e gelen toplam istek sırası (kullanıcıya özel içerik üretir).
fn cgi_response(uri: &str, seq: usize) -> String {
    let path = uri.split('?').next().unwrap_or(uri);
    let (extra, body) = match path {
        "/cookie.php" => (
            format!("Set-Cookie: sid=user{seq}\r\nX-LiteSpeed-Cache-Control: public, max-age=300\r\n"),
            format!("ozel-sayfa-kullanici{seq}"),
        ),
        "/private.php" => (
            "Cache-Control: private, max-age=300\r\nX-LiteSpeed-Cache-Control: public, max-age=300\r\n"
                .to_string(),
            format!("private-sayfa hit={seq}"),
        ),
        "/nostore.php" => (
            "Cache-Control: no-store\r\nX-LiteSpeed-Cache-Control: public\r\n".to_string(),
            format!("nostore-sayfa hit={seq}"),
        ),
        "/tag.php" => (
            "X-LiteSpeed-Cache-Control: public, max-age=300\r\nX-LiteSpeed-Tag: post:42, cat:7\r\n"
                .to_string(),
            format!("tag-sayfa hit={seq}"),
        ),
        "/nocache.php" => (
            "X-LiteSpeed-Cache-Control: no-cache\r\nX-LiteSpeed-Tag: gizli:1\r\n".to_string(),
            format!("nocache-sayfa hit={seq}"),
        ),
        "/purger.php" => (
            "X-LiteSpeed-Cache-Control: no-cache\r\nX-LiteSpeed-Purge: public, post:42\r\n"
                .to_string(),
            format!("purger-sayfa hit={seq}"),
        ),
        _ => (String::new(), format!("app-sayfa hit={seq}")),
    };
    format!("Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n{extra}\r\n{body}")
}

fn serve_fcgi_connection(mut stream: TcpStream, hits: &AtomicUsize) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut params_buf = Vec::new();
    let mut hdr = [0u8; 8];
    loop {
        if stream.read_exact(&mut hdr).is_err() {
            return;
        }
        let rec_type = hdr[1];
        let req_id = u16::from_be_bytes([hdr[2], hdr[3]]);
        let content_len = usize::from(u16::from_be_bytes([hdr[4], hdr[5]]));
        let padding_len = usize::from(hdr[6]);
        let mut content = vec![0u8; content_len];
        if content_len > 0 && stream.read_exact(&mut content).is_err() {
            return;
        }
        if padding_len > 0 {
            let mut pad = vec![0u8; padding_len];
            if stream.read_exact(&mut pad).is_err() {
                return;
            }
        }
        if rec_type == 4 && !content.is_empty() {
            params_buf.extend_from_slice(&content);
        } else if rec_type == 5 && content_len == 0 {
            let params = decode_fcgi_params(&params_buf);
            let uri = params
                .get("REQUEST_URI")
                .or_else(|| params.get("SCRIPT_NAME"))
                .cloned()
                .unwrap_or_else(|| "/".to_string());
            let seq = hits.fetch_add(1, Ordering::SeqCst) + 1;
            let cgi = cgi_response(&uri, seq);
            for chunk in cgi.as_bytes().chunks(60_000) {
                write_fcgi_record(&mut stream, 6, req_id, chunk);
            }
            write_fcgi_record(&mut stream, 6, req_id, &[]);
            write_fcgi_record(&mut stream, 3, req_id, &[0u8; 8]);
            let _ = stream.flush();
            return;
        }
    }
}

// ---------------------------------------------------------------- sunucu ortamı

struct Env {
    child: Option<Child>,
    base: PathBuf,
    http: u16,
    https: u16,
    api: u16,
    fcgi: MockFcgi,
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn free_ports<const N: usize>() -> [u16; N] {
    let listeners: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bos port ayrilmali"))
        .collect();
    let mut out = [0u16; N];
    for (slot, l) in out.iter_mut().zip(&listeners) {
        *slot = l.local_addr().expect("yerel adres").port();
    }
    out
}

fn toml_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn write_self_signed(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let params =
        rcgen::CertificateParams::new(vec![name.to_string()]).expect("sertifika parametresi");
    let key = rcgen::KeyPair::generate().expect("anahtar");
    let cert = params.self_signed(&key).expect("öz imzalı sertifika");
    let cert_path = dir.join(format!("{name}.crt"));
    let key_path = dir.join(format!("{name}.key"));
    fs::write(&cert_path, cert.pem()).expect("crt yazılmalı");
    fs::write(&key_path, key.serialize_pem()).expect("key yazılmalı");
    (cert_path, key_path)
}

/// `extra_cache_toml`: `[cache]` bölümüne eklenen satırlar.
fn start(extra_cache_toml: &str) -> Env {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("zmax_pauth_{}_{}", std::process::id(), seq));
    let _ = fs::remove_dir_all(&base);
    let vhosts_dir = base.join("conf").join("vhosts");
    let certs = base.join("certs");
    for d in [
        &vhosts_dir,
        &certs,
        &base.join("logs"),
        &base.join("cachedata"),
    ] {
        fs::create_dir_all(d).expect("dizin");
    }

    let [http, https, api] = free_ports::<3>();
    let fcgi = MockFcgi::start();

    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax-PurgeAuth-Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http}
backlog = 128
tcp_nodelay = true
reuse_port = false

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {https}
ssl = true

[listeners.admin]
enabled = false

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api}
require_token = false

[cache]
enabled = true
disk_cache_dir = "cachedata"
default_ttl_seconds = 300
{extra_cache_toml}

[security]
rate_limit_enabled = false

[logging]
access_log = "logs/access.log"
error_log = "logs/error.log"
log_level = "info"

[vhosts_dir]
path = "conf/vhosts"
"#
    );
    let conf_path = base.join("conf").join("zmax.toml");
    fs::write(&conf_path, zmax_toml).expect("zmax.toml");

    for host in ["site1.test", "site2.test"] {
        let root = base.join("www").join(host);
        fs::create_dir_all(&root).expect("docroot");
        fs::write(root.join("index.html"), format!("{host} anasayfa")).expect("index");
        fs::write(root.join("page.html"), format!("{host} sayfa")).expect("page");
        for script in [
            "app.php",
            "cookie.php",
            "private.php",
            "nostore.php",
            "tag.php",
            "nocache.php",
            "purger.php",
        ] {
            fs::write(root.join(script), "<?php // sahte").expect("php");
        }
        let (crt, key) = write_self_signed(&certs, host);
        let vhost = format!(
            r#"[vhost]
name = "{host}"
document_root = "{root}"
index_files = ["index.html", "index.php"]

[vhost.cache]
enabled = true
expire = 300

[vhost.php]
enabled = true
sapi = "fastcgi"
upstream = "{fcgi}"
timeout = 15
keep_conn = false

[vhost.rewrite]
enabled = true
try_files = true
htaccess = false

[vhost.security]
hotlink_protection = false
force_https = false
wp_brute_force = false

[vhost.headers]
security_headers = false
hsts = false

[vhost.ssl]
certificate = "{crt}"
key = "{key}"
"#,
            root = toml_path(&root),
            fcgi = fcgi.addr,
            crt = toml_path(&crt),
            key = toml_path(&key),
        );
        fs::write(vhosts_dir.join(format!("{host}.toml")), vhost).expect("vhost");
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", &base)
        .env_remove("ZMAX_CONF")
        .env_remove("ZMAX_HTTP_PORT")
        .env_remove("ZMAX_HTTPS_PORT")
        .env_remove("ZMAX_API_PORT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("zmax baslatilmali");
    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let env = Env {
        child: Some(child),
        base,
        http,
        https,
        api,
        fcgi,
    };

    // Hazır satırını bekle; sonra boru dolmasın diye çıktıları tüket.
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut sent = false;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => {
                    if !sent {
                        let _ = tx.send(false);
                    }
                    return;
                }
                Ok(_) => {
                    if !sent && line.contains("hazir") {
                        sent = true;
                        let _ = tx.send(true);
                    }
                }
            }
        }
    });
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = BufReader::new(stderr).read_to_end(&mut sink);
    });
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(true) => env,
        other => panic!("zmax hazir olamadi: {other:?}"),
    }
}

// ---------------------------------------------------------------- istemciler

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn x_cache(&self) -> &str {
        self.header("x-cache").unwrap_or("-")
    }
}

/// HTTP/1.1 (düz TCP) isteği.
fn h1(port: u16, method: &str, host: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("baglanti");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).expect("istek yazilmali");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("yanit okunmali");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("baslik ayraci yok: {:?}", String::from_utf8_lossy(&raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .expect("durum kodu");
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&raw[split + 4..]).into_owned(),
    }
}

fn get(env: &Env, host: &str, path: &str) -> Resp {
    h1(env.http, "GET", host, path, &[])
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

/// Gerçek HTTP/2 isteği (TLS ALPN `h2` zorunlu; seçilmezse test düşer).
fn h2(port: u16, method: &str, host: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio calisma zamani");
    rt.block_on(async move {
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protokol surumleri")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipCertVerification))
        .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(cfg));
        let tcp = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(("127.0.0.1", port)),
        )
        .await
        .expect("tcp zaman asimi")
        .expect("tcp baglantisi");
        let sni = ServerName::try_from(host.to_string()).expect("sni");
        let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(sni, tcp))
            .await
            .expect("tls zaman asimi")
            .expect("tls el sikismasi");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(&b"h2"[..]),
            "ALPN h2 secilmeli"
        );
        let (mut send_req, conn) = ::h2::client::handshake(tls).await.expect("h2 el sikismasi");
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("https://{host}{path}"))
            .header("host", host);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let request = builder.body(()).expect("h2 istegi");
        let (resp_fut, _) = send_req
            .send_request(request, true)
            .expect("istek gonderimi");
        let response = tokio::time::timeout(Duration::from_secs(5), resp_fut)
            .await
            .expect("h2 yanit zaman asimi")
            .expect("h2 yaniti");
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("h2 govde");
            let _ = body.flow_control().release_capacity(chunk.len());
            bytes.extend_from_slice(&chunk);
        }
        conn_task.abort();
        Resp {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    })
}

fn api_purge(env: &Env, json: &str) -> serde_json::Value {
    let addr = SocketAddr::from(([127, 0, 0, 1], env.api));
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("api baglanti");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let req = format!(
        "POST /api/v1/cache/purge HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        json.len(),
        json
    );
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("api ayraci");
    serde_json::from_slice(&raw[split + 4..]).expect("api json")
}

const KEY_HDR: &str = "X-ZMax-Purge-Key";

fn key_env() -> Env {
    start(&format!(
        "purge_enabled = true\npurge_key = \"{PURGE_KEY}\""
    ))
}

/// Sayfayı iki kez isteyip MISS sonra HIT'e geçtiğini doğrular.
fn warm(env: &Env, host: &str, path: &str) {
    let first = get(env, host, path);
    assert_eq!(first.status, 200, "{host}{path}: {first:?}");
    assert_eq!(
        first.x_cache(),
        "MISS",
        "{host}{path} ilk istek MISS olmalı: {first:?}"
    );
    let second = get(env, host, path);
    assert_eq!(
        second.x_cache(),
        "HIT",
        "{host}{path} ikinci istek HIT olmalı: {second:?}"
    );
}

fn assert_hit(env: &Env, host: &str, path: &str, why: &str) {
    let r = get(env, host, path);
    assert_eq!(r.x_cache(), "HIT", "{why}: {host}{path} HIT kalmalı: {r:?}");
}

// ---------------------------------------------------------------- testler

#[test]
fn purge_h1_unauthorized_is_403_and_cache_stays() {
    let env = key_env();
    warm(&env, "site1.test", "/");
    warm(&env, "site2.test", "/");

    // anahtarsız PURGE
    let r = h1(env.http, "PURGE", "site1.test", "/", &[]);
    assert_eq!(r.status, 403, "anahtarsız PURGE 403 olmalı: {r:?}");
    assert_hit(&env, "site1.test", "/", "anahtarsız PURGE sonrası");

    // yanlış anahtar (uzunluğu farklı ve aynı uzunlukta)
    for bad in ["yanlis", "test-purge-anahtari-012345678X", ""] {
        let r = h1(env.http, "PURGE", "site1.test", "/", &[(KEY_HDR, bad)]);
        assert_eq!(r.status, 403, "yanlış anahtar '{bad}' 403 olmalı: {r:?}");
    }
    assert_hit(&env, "site1.test", "/", "yanlış anahtarlı PURGE sonrası");

    // X-LiteSpeed-Purge istek başlığı (anahtarsız): hem GET hem PURGE
    let r = h1(
        env.http,
        "GET",
        "site1.test",
        "/",
        &[("X-LiteSpeed-Purge", "*")],
    );
    assert_eq!(
        r.status, 403,
        "yetkisiz X-LiteSpeed-Purge 403 olmalı: {r:?}"
    );
    let r = h1(
        env.http,
        "PURGE",
        "site1.test",
        "/",
        &[("X-LiteSpeed-Purge", "*")],
    );
    assert_eq!(
        r.status, 403,
        "yetkisiz PURGE+X-LiteSpeed-Purge 403 olmalı: {r:?}"
    );
    assert_hit(
        &env,
        "site1.test",
        "/",
        "yetkisiz X-LiteSpeed-Purge sonrası",
    );
    assert_hit(
        &env,
        "site2.test",
        "/",
        "yetkisiz istekler sonrası diğer vhost",
    );
}

#[test]
fn purge_h1_authorized_purges_only_own_vhost_with_real_counts() {
    let env = key_env();
    warm(&env, "site1.test", "/");
    warm(&env, "site2.test", "/");
    warm(&env, "site1.test", "/tag.php");
    warm(&env, "site2.test", "/tag.php");

    // URL purge: yalnız site1 "/" silinir, sayı gerçek (1)
    let r = h1(
        env.http,
        "PURGE",
        "site1.test",
        "/",
        &[(KEY_HDR, PURGE_KEY)],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, "Purged 1 entries\n", "{r:?}");
    assert_eq!(get(&env, "site1.test", "/").x_cache(), "MISS");
    assert_hit(
        &env,
        "site2.test",
        "/",
        "site1 URL purge sonrası diğer vhost",
    );
    assert_hit(&env, "site1.test", "/tag.php", "farklı URL korunmalı");

    // 0 girdi -> 0 (sabit +1 yok)
    let r = h1(
        env.http,
        "PURGE",
        "site1.test",
        "/yok-boyle-sayfa.html",
        &[(KEY_HDR, PURGE_KEY)],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, "Purged 0 entries\n", "0 girdi 0 sayılmalı: {r:?}");
    let r = h1(
        env.http,
        "PURGE",
        "site1.test",
        "/",
        &[
            (KEY_HDR, PURGE_KEY),
            ("X-LiteSpeed-Purge", "olmayan:etiket"),
        ],
    );
    assert_eq!(r.body, "Purged 0 entries\n", "olmayan etiket 0: {r:?}");

    // etiket purge (X-LiteSpeed-Purge: tag): yalnız site1 /tag.php
    let r = h1(
        env.http,
        "PURGE",
        "site1.test",
        "/",
        &[(KEY_HDR, PURGE_KEY), ("X-LiteSpeed-Purge", "post:42")],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, "Purged 1 entries\n", "{r:?}");
    assert_eq!(get(&env, "site1.test", "/tag.php").x_cache(), "MISS");
    assert_hit(
        &env,
        "site2.test",
        "/tag.php",
        "site1 etiket purge sonrası diğer vhost",
    );

    // site1 tamamı (*): site1 HIT'leri düşer, site2 kalır
    warm_if_needed(&env, "site1.test", "/page.html");
    let r = h1(
        env.http,
        "PURGE",
        "site1.test",
        "/",
        &[(KEY_HDR, PURGE_KEY), ("X-LiteSpeed-Purge", "*")],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert!(
        r.body.starts_with("Purged ") && r.body != "Purged 0 entries\n",
        "{r:?}"
    );
    assert_eq!(get(&env, "site1.test", "/page.html").x_cache(), "MISS");
    assert_hit(
        &env,
        "site2.test",
        "/",
        "site1 '*' purge sonrası diğer vhost",
    );
    assert_hit(
        &env,
        "site2.test",
        "/tag.php",
        "site1 '*' purge sonrası diğer vhost PHP",
    );
}

fn warm_if_needed(env: &Env, host: &str, path: &str) {
    let _ = get(env, host, path);
    assert_eq!(get(env, host, path).x_cache(), "HIT");
}

#[test]
fn purge_h2_unauthorized_is_403_and_authorized_works() {
    let env = key_env();
    warm(&env, "site1.test", "/");
    warm(&env, "site2.test", "/");
    warm(&env, "site1.test", "/tag.php");

    // gerçek h2 istemci: yetkisiz PURGE
    let r = h2(env.https, "PURGE", "site1.test", "/", &[]);
    assert_eq!(r.status, 403, "h2 anahtarsız PURGE 403 olmalı: {r:?}");
    let r = h2(
        env.https,
        "PURGE",
        "site1.test",
        "/",
        &[(KEY_HDR, "yanlis")],
    );
    assert_eq!(r.status, 403, "h2 yanlış anahtar 403 olmalı: {r:?}");
    let r = h2(
        env.https,
        "GET",
        "site1.test",
        "/",
        &[("x-litespeed-purge", "*")],
    );
    assert_eq!(
        r.status, 403,
        "h2 yetkisiz X-LiteSpeed-Purge 403 olmalı: {r:?}"
    );
    assert_hit(&env, "site1.test", "/", "h2 yetkisiz istekler sonrası");
    assert_hit(
        &env,
        "site1.test",
        "/tag.php",
        "h2 yetkisiz istekler sonrası PHP",
    );

    // yetkili h2 PURGE: 200, MISS; başka vhost etkilenmez
    let r = h2(
        env.https,
        "PURGE",
        "site1.test",
        "/",
        &[(KEY_HDR, PURGE_KEY)],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, "Purged 1 entries\n", "{r:?}");
    assert_eq!(get(&env, "site1.test", "/").x_cache(), "MISS");
    assert_hit(&env, "site2.test", "/", "h2 PURGE sonrası diğer vhost");

    // yetkili h2 etiket purge
    let r = h2(
        env.https,
        "PURGE",
        "site1.test",
        "/",
        &[(KEY_HDR, PURGE_KEY), ("x-litespeed-purge", "cat:7")],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, "Purged 1 entries\n", "{r:?}");
    assert_eq!(get(&env, "site1.test", "/tag.php").x_cache(), "MISS");
}

#[test]
fn purge_is_off_by_default_and_ip_allowlist_works() {
    // (a) purge_enabled yok (varsayılan KAPALI): anahtar tanımlı olsa bile 403
    {
        let env = start(&format!("purge_key = \"{PURGE_KEY}\""));
        warm(&env, "site1.test", "/");
        let r = h1(
            env.http,
            "PURGE",
            "site1.test",
            "/",
            &[(KEY_HDR, PURGE_KEY)],
        );
        assert_eq!(r.status, 403, "varsayılan kapalı: {r:?}");
        let r = h2(
            env.https,
            "PURGE",
            "site1.test",
            "/",
            &[(KEY_HDR, PURGE_KEY)],
        );
        assert_eq!(r.status, 403, "varsayılan kapalı (h2): {r:?}");
        assert_hit(&env, "site1.test", "/", "kapalı özellik");
    }
    // (b) açık ama ne anahtar ne IP tanımlı: hiç kimse yetkili değil
    {
        let env = start("purge_enabled = true");
        warm(&env, "site1.test", "/");
        let r = h1(env.http, "PURGE", "site1.test", "/", &[(KEY_HDR, "")]);
        assert_eq!(r.status, 403, "boş yapılandırma + boş anahtar: {r:?}");
        let r = h1(
            env.http,
            "PURGE",
            "site1.test",
            "/",
            &[(KEY_HDR, "herhangi")],
        );
        assert_eq!(r.status, 403, "{r:?}");
        assert_hit(&env, "site1.test", "/", "yetkisiz yapılandırma");
    }
    // (c) IP izin listesi: istemci 127.0.0.1 listede -> anahtarsız 200 (h1 ve h2)
    {
        let env = start("purge_enabled = true\npurge_allow_ips = [\"127.0.0.0/8\"]");
        warm(&env, "site1.test", "/");
        let r = h1(env.http, "PURGE", "site1.test", "/", &[]);
        assert_eq!(r.status, 200, "izinli IP: {r:?}");
        assert_eq!(get(&env, "site1.test", "/").x_cache(), "MISS");
        assert_hit(&env, "site1.test", "/", "yeniden doldurma");
        let r = h2(env.https, "PURGE", "site1.test", "/", &[]);
        assert_eq!(r.status, 200, "izinli IP (h2): {r:?}");
        assert_eq!(get(&env, "site1.test", "/").x_cache(), "MISS");
    }
    // (d) IP listesi var ama istemci listede değil
    {
        let env = start("purge_enabled = true\npurge_allow_ips = [\"10.9.8.7/32\"]");
        warm(&env, "site1.test", "/");
        let r = h1(env.http, "PURGE", "site1.test", "/", &[]);
        assert_eq!(r.status, 403, "izinsiz IP: {r:?}");
        let r = h2(env.https, "PURGE", "site1.test", "/", &[]);
        assert_eq!(r.status, 403, "izinsiz IP (h2): {r:?}");
        assert_hit(&env, "site1.test", "/", "izinsiz IP");
    }
}

#[test]
fn php_responses_with_cookie_or_private_are_never_cached() {
    let env = key_env();

    // Set-Cookie + "X-LiteSpeed-Cache-Control: public": iki kullanıcı birbirinin sayfasını görmez
    let u1 = get(&env, "site1.test", "/cookie.php");
    assert_eq!(u1.status, 200);
    assert_eq!(u1.x_cache(), "BYPASS", "{u1:?}");
    assert!(u1.body.contains("kullanici1"), "{u1:?}");
    assert!(
        u1.header("set-cookie")
            .is_some_and(|c| c.contains("sid=user1")),
        "{u1:?}"
    );
    let u2 = h1(
        env.http,
        "GET",
        "site1.test",
        "/cookie.php",
        &[("Cookie", "sid=user1")],
    );
    assert_ne!(
        u2.body, u1.body,
        "ikinci kullanıcı birincinin sayfasını görmemeli: {u2:?}"
    );
    assert!(u2.body.contains("kullanici2"), "{u2:?}");
    assert_eq!(env.fcgi.hit_count(), 2, "iki istek de backend'e gitmeli");
    // h2 üzerinden de aynı
    let u3 = h2(env.https, "GET", "site1.test", "/cookie.php", &[]);
    assert!(
        u3.body.contains("kullanici3"),
        "h2 de önbellekten servis edilmemeli: {u3:?}"
    );
    assert_eq!(env.fcgi.hit_count(), 3);

    // Cache-Control: private / no-store + X-LiteSpeed-Cache-Control: public
    for path in ["/private.php", "/nostore.php"] {
        let a = get(&env, "site1.test", path);
        let b = get(&env, "site1.test", path);
        assert_eq!(a.x_cache(), "BYPASS", "{path}: {a:?}");
        assert_eq!(b.x_cache(), "BYPASS", "{path}: {b:?}");
        assert_ne!(a.body, b.body, "{path} önbellekten gelmemeli");
    }
    assert_eq!(env.fcgi.hit_count(), 7);

    // kontrol: normal sayfa önbelleğe alınır
    warm(&env, "site1.test", "/app.php");
}

#[test]
fn request_cache_control_headers_do_not_bypass_cache_by_default() {
    let env = key_env();
    warm(&env, "site1.test", "/page.html");
    warm(&env, "site1.test", "/app.php");
    // https (h2) girdisi http'den ayrı anahtar kullanır; onu da ısıt.
    assert_eq!(
        h2(env.https, "GET", "site1.test", "/app.php", &[]).x_cache(),
        "MISS"
    );
    let hits_before = env.fcgi.hit_count();
    assert_eq!(hits_before, 2);

    let evil: [&[(&str, &str)]; 4] = [
        &[("Cache-Control", "no-cache")],
        &[("Cache-Control", "private, no-store")],
        &[("Pragma", "no-cache")],
        &[("X-LiteSpeed-Cache-Control", "no-cache")],
    ];
    for hdrs in evil {
        let s = h1(env.http, "GET", "site1.test", "/page.html", hdrs);
        assert_eq!(
            s.x_cache(),
            "HIT",
            "statik: istek başlığı {hdrs:?} önbelleği atlamamalı: {s:?}"
        );
        let p = h1(env.http, "GET", "site1.test", "/app.php", hdrs);
        assert_eq!(
            p.x_cache(),
            "HIT",
            "PHP: istek başlığı {hdrs:?} önbelleği atlamamalı: {p:?}"
        );
        let p2 = h2(env.https, "GET", "site1.test", "/app.php", hdrs);
        assert_eq!(
            p2.x_cache(),
            "HIT",
            "PHP h2: istek başlığı {hdrs:?} önbelleği atlamamalı: {p2:?}"
        );
    }
    assert_eq!(
        env.fcgi.hit_count(),
        hits_before,
        "istek başlıkları PHP'yi tetiklememeli"
    );
}

#[test]
fn php_lscache_tags_purge_and_headers_do_not_leak() {
    let env = key_env();

    // MISS: X-LiteSpeed-* yanıt başlıkları istemciye gitmez
    let first = get(&env, "site1.test", "/tag.php");
    assert_eq!(first.x_cache(), "MISS", "{first:?}");
    for h in [
        "x-litespeed-tag",
        "x-litespeed-cache-control",
        "x-litespeed-purge",
    ] {
        assert_eq!(first.header(h), None, "{h} istemciye sızmamalı: {first:?}");
    }
    let hit = get(&env, "site1.test", "/tag.php");
    assert_eq!(hit.x_cache(), "HIT");
    assert_eq!(hit.body, first.body);
    assert_eq!(env.fcgi.hit_count(), 1);
    // aynı sayfa site2'de ayrı girdi
    assert_eq!(get(&env, "site2.test", "/tag.php").x_cache(), "MISS");
    assert_eq!(get(&env, "site2.test", "/tag.php").x_cache(), "HIT");
    assert_eq!(env.fcgi.hit_count(), 2);

    // API: alan+etiket purge gerçek sayı (1) ve diğer vhost etkilenmez
    let p = api_purge(&env, r#"{"domain":"site1.test","tag":"post:42"}"#);
    assert_eq!(p["purged"], 1, "{p}");
    assert_eq!(get(&env, "site1.test", "/tag.php").x_cache(), "MISS");
    assert_hit(&env, "site2.test", "/tag.php", "site1 etiket purge sonrası");
    let p = api_purge(&env, r#"{"tag":"yok-boyle-bir-etiket"}"#);
    assert_eq!(p["purged"], 0, "{p}");
    // global etiket purge iki vhost'u da siler
    let p = api_purge(&env, r#"{"tag":"cat:7"}"#);
    assert_eq!(p["purged"], 2, "{p}");

    // X-LiteSpeed-Cache-Control: no-cache: önbelleğe alınmaz, etiket sızmaz
    let hits = env.fcgi.hit_count();
    let n1 = get(&env, "site1.test", "/nocache.php");
    let n2 = get(&env, "site1.test", "/nocache.php");
    assert_eq!(n1.x_cache(), "BYPASS", "{n1:?}");
    assert_eq!(n2.x_cache(), "BYPASS", "{n2:?}");
    assert_ne!(n1.body, n2.body);
    assert_eq!(env.fcgi.hit_count(), hits + 2);
    assert_eq!(n1.header("x-litespeed-tag"), None, "{n1:?}");
    assert_eq!(n1.header("x-litespeed-cache-control"), None, "{n1:?}");

    // uygulama kaynaklı purge: /purger.php (X-LiteSpeed-Purge: public, post:42) yalnız KENDİ vhost'unun etiketini siler
    assert_eq!(get(&env, "site1.test", "/tag.php").x_cache(), "MISS");
    assert_eq!(get(&env, "site2.test", "/tag.php").x_cache(), "MISS");
    assert_hit(&env, "site1.test", "/tag.php", "yeniden doldurma");
    assert_hit(&env, "site2.test", "/tag.php", "yeniden doldurma");
    let pg = get(&env, "site1.test", "/purger.php");
    assert_eq!(pg.header("x-litespeed-purge"), None, "{pg:?}");
    assert_eq!(
        get(&env, "site1.test", "/tag.php").x_cache(),
        "MISS",
        "uygulama purge'ü site1 girdisini silmeli"
    );
    assert_hit(
        &env,
        "site2.test",
        "/tag.php",
        "site1 uygulama purge'ü sonrası diğer vhost",
    );
}

#[test]
fn h2_php_cache_hit_and_purge_covers_both_schemes() {
    let env = key_env();
    let a = h2(env.https, "GET", "site1.test", "/app.php", &[]);
    assert_eq!(a.status, 200, "{a:?}");
    assert_eq!(a.x_cache(), "MISS", "{a:?}");
    let b = h2(env.https, "GET", "site1.test", "/app.php", &[]);
    assert_eq!(b.x_cache(), "HIT", "{b:?}");
    assert_eq!(b.body, a.body);
    assert_eq!(env.fcgi.hit_count(), 1, "h2 HIT backend'e gitmemeli");
    // http girdisi ayrı anahtardır (şema ayrı); ısıt.
    warm(&env, "site1.test", "/app.php");
    assert_eq!(env.fcgi.hit_count(), 2);
    // h2 PURGE yolu iki şemadaki girdileri de siler (gerçek sayı: 2)
    let r = h2(
        env.https,
        "PURGE",
        "site1.test",
        "/app.php",
        &[(KEY_HDR, PURGE_KEY)],
    );
    assert_eq!(r.status, 200, "{r:?}");
    assert_eq!(r.body, "Purged 2 entries\n", "{r:?}");
    assert_eq!(
        h2(env.https, "GET", "site1.test", "/app.php", &[]).x_cache(),
        "MISS"
    );
    assert_eq!(get(&env, "site1.test", "/app.php").x_cache(), "MISS");
}

/// Etiket bazlı PURGE: ZMax iç etiketleri (`domain::alan`, `alan::*`, `__uri:yol`) ve backend etiketi
/// (`post:42`, `tag=post:42`) gerçekten siler; başka vhost'un etiketiyle silme olmaz (izolasyon).
#[test]
fn purge_by_internal_and_backend_tags_deletes_and_keeps_vhost_isolation() {
    let env = key_env();
    let purge = |host: &str, tag: &str| {
        h1(
            env.http,
            "PURGE",
            host,
            "/",
            &[(KEY_HDR, PURGE_KEY), ("X-LiteSpeed-Purge", tag)],
        )
    };
    warm(&env, "site1.test", "/");
    warm(&env, "site2.test", "/");

    // İzolasyon: site1'den site2'nin iç etiketleri ASLA site2 girdisini silmez.
    for foreign in [
        "domain::site2.test",
        "domain:site2.test",
        "site2.test",
        "site2.test::*",
    ] {
        let r = purge("site1.test", foreign);
        assert_eq!(r.status, 200, "{foreign}: {r:?}");
        assert_eq!(r.body, "Purged 0 entries\n", "{foreign}: {r:?}");
        assert_hit(&env, "site2.test", "/", &format!("site1'den '{foreign}'"));
        assert_hit(&env, "site1.test", "/", &format!("site1'den '{foreign}'"));
    }

    // Kendi iç etiketleri gerçekten siler (bug: "Purged 0 entries" dönüp hiçbir şey silmiyordu).
    for own in [
        "domain::site1.test",
        "domain:site1.test",
        "site1.test::*",
        "__uri:/",
        "__path:/",
    ] {
        let r = purge("site1.test", own);
        assert_eq!(r.status, 200, "{own}: {r:?}");
        assert_eq!(r.body, "Purged 1 entries\n", "{own}: {r:?}");
        assert_eq!(
            get(&env, "site1.test", "/").x_cache(),
            "MISS",
            "{own}: site1 girdisi silinmeli"
        );
        assert_hit(
            &env,
            "site1.test",
            "/",
            &format!("{own} sonrası yeniden dolum"),
        );
        assert_hit(&env, "site2.test", "/", &format!("site1'den '{own}'"));
    }

    // Backend etiketi: düz (`post:42`) ve OLS yazımı (`tag=post:42`).
    warm(&env, "site1.test", "/tag.php");
    warm(&env, "site2.test", "/tag.php");
    for tag in ["post:42", "tag=post:42"] {
        let r = purge("site1.test", tag);
        assert_eq!(r.body, "Purged 1 entries\n", "{tag}: {r:?}");
        assert_eq!(
            get(&env, "site1.test", "/tag.php").x_cache(),
            "MISS",
            "{tag}"
        );
        assert_hit(&env, "site1.test", "/tag.php", "yeniden dolum");
        assert_hit(
            &env,
            "site2.test",
            "/tag.php",
            &format!("site1'den '{tag}'"),
        );
    }
}
