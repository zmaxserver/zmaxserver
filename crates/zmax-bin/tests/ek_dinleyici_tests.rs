//! `[[listeners.extra]]` uçtan uca testleri: gerçek `zmax` süreci, rastgele portlarda TLS ek dinleyici,
//! sahte arka uçlar. Açık vekil olmadığı (Host/mutlak URI ile arka uç değiştirilemez) negatif kontrollüdür.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("port");
    l.local_addr().expect("adres").port()
}

fn fwd(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

// ------------------------------------------------------------------ çalışma alanı / süreç

struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "zmax_ekdin_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        for d in ["conf/vhosts", "logs", "cache", "certs", "admin"] {
            std::fs::create_dir_all(root.join(d)).expect("dizin");
        }
        Self { root }
    }
    fn conf(&self) -> PathBuf {
        self.root.join("conf").join("zmax.toml")
    }
    fn cert(&self, name: &str) -> (PathBuf, PathBuf) {
        let c = self.root.join("certs").join(format!("{name}.crt"));
        let k = self.root.join("certs").join(format!("{name}.key"));
        let key = rcgen::KeyPair::generate().expect("anahtar");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("param");
        let cert = params.self_signed(&key).expect("sertifika");
        std::fs::write(&c, cert.pem()).expect("cert yaz");
        std::fs::write(&k, key.serialize_pem()).expect("key yaz");
        (c, k)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Server {
    child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn base_conf(api_port: u16, extra: &str) -> String {
    format!(
        r#"[server]
workers = 2

[listeners.http]
enabled = false

[listeners.https]
enabled = false

[listeners.admin]
enabled = false

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api_port}
require_token = false

[vhosts_dir]
path = "conf/vhosts"

[logging]
access_log = "logs/access.log"
error_log = "logs/error.log"

{extra}
"#
    )
}

fn extra_block(name: &str, port: u16, upstream: &str, cert: &(PathBuf, PathBuf), more: &str) -> String {
    format!(
        r#"[[listeners.extra]]
name = "{name}"
address = "127.0.0.1"
port = {port}
upstream = "{upstream}"
{more}
[listeners.extra.ssl]
cert = "{}"
key = "{}"
"#,
        fwd(&cert.0),
        fwd(&cert.1)
    )
}

fn spawn(ws: &Workspace) -> TestResult<Server> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .arg("-c")
        .arg(ws.conf())
        .env("ZMAX_HOME", &ws.root)
        .env_remove("ZMAX_CONF")
        .env_remove("ZMAX_HTTP_PORT")
        .env_remove("ZMAX_HTTPS_PORT")
        .env_remove("ZMAX_ADMIN_PORT")
        .env_remove("ZMAX_API_PORT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().ok_or("stdout")?;
    let stderr = child.stderr.take().ok_or("stderr")?;
    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let err_buf = Arc::new(Mutex::new(String::new()));
    let eb = Arc::clone(&err_buf);
    let eh = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut BufReader::new(stderr), &mut s);
        *eb.lock().unwrap() = s;
    });
    std::thread::spawn(move || {
        let mut r = BufReader::new(stdout);
        let mut collected = String::new();
        let mut line = Vec::new();
        loop {
            line.clear();
            match r.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => {
                    let _ = eh.join();
                    let e = err_buf.lock().map(|g| g.clone()).unwrap_or_default();
                    let _ = tx.send(Err(format!("hazir olmadan sonlandi\nstdout:{collected}\nstderr:{e}")));
                    return;
                }
                Ok(_) => {
                    let l = String::from_utf8_lossy(&line).into_owned();
                    collected.push_str(&l);
                    if l.contains("hazir!") {
                        let _ = tx.send(Ok(()));
                        break;
                    }
                }
            }
        }
        let mut sink = [0u8; 4096];
        while let Ok(n) = std::io::Read::read(&mut r, &mut sink) {
            if n == 0 {
                break;
            }
        }
    });
    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(())) => Ok(Server { child }),
        Ok(Err(m)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(m.into())
        }
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(format!("zaman asimi: {e}").into())
        }
    }
}

// ------------------------------------------------------------------ sahte arka uç

#[derive(Clone)]
struct Upstream {
    port: u16,
    hits: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<String>>>,
}

fn head_end(b: &[u8]) -> Option<usize> {
    b.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// `tag` yanıt gövdesine yazılır; WebSocket Upgrade isteğine 101 + yankı ile cevap verir.
async fn spawn_upstream(tag: &'static str) -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("upstream bind");
    let up = Upstream {
        port: l.local_addr().unwrap().port(),
        hits: Arc::new(AtomicUsize::new(0)),
        heads: Arc::new(Mutex::new(Vec::new())),
    };
    let u2 = up.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let u = u2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 16384];
                let he = loop {
                    if let Some(e) = head_end(&buf) {
                        break e;
                    }
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                };
                u.hits.fetch_add(1, Ordering::SeqCst);
                let head = String::from_utf8_lossy(&buf[..he]).into_owned();
                u.heads.lock().unwrap().push(head.clone());
                let lower = head.to_ascii_lowercase();
                if lower.contains("upgrade: websocket") {
                    let _ = s
                        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
                        .await;
                    loop {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if s.write_all(&tmp[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                }
                let cl: usize = lower
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0);
                let mut body_len = buf.len() - he;
                let mut sum: u64 = buf[he..].iter().map(|b| *b as u64).sum();
                while body_len < cl {
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            body_len += n;
                            sum += tmp[..n].iter().map(|b| *b as u64).sum::<u64>();
                        }
                    }
                }
                let body = format!("UP:{tag}\nBODYLEN:{body_len}\nSUM:{sum}\n{head}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    up
}

// ------------------------------------------------------------------ TLS istemcisi

#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
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

fn connector() -> TlsConnector {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(cfg))
}

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

async fn tls_connect(port: u16) -> TestResult<TlsStream> {
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(("127.0.0.1", port))).await??;
    let name = ServerName::try_from("localhost")?;
    Ok(tokio::time::timeout(Duration::from_secs(5), connector().connect(name, tcp)).await??)
}

struct Resp {
    status: u16,
    head: String,
    body: Vec<u8>,
}

impl Resp {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn read_resp<S: AsyncReadExt + Unpin>(s: &mut S) -> TestResult<Resp> {
    read_resp_with(s, Duration::from_secs(15)).await
}

async fn read_resp_with<S: AsyncReadExt + Unpin>(s: &mut S, per_read: Duration) -> TestResult<Resp> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 65536];
    loop {
        match tokio::time::timeout(per_read, s.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => raw.extend_from_slice(&tmp[..n]),
            Err(_) => return Err("okuma zaman asimi".into()),
        }
    }
    let he = head_end(&raw).ok_or("yanit basligi yok")?;
    let head = String::from_utf8_lossy(&raw[..he]).into_owned();
    let status = head.split_whitespace().nth(1).ok_or("durum")?.parse()?;
    Ok(Resp { status, head, body: raw[he..].to_vec() })
}

/// Ham istek gönderir (Connection: close eklenmiş olmalı), EOF'a kadar okur.
async fn tls_raw(port: u16, head: &str, body: &[u8]) -> TestResult<Resp> {
    let mut s = tls_connect(port).await?;
    s.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        s.write_all(body).await?;
    }
    s.flush().await?;
    read_resp(&mut s).await
}

async fn tls_get(port: u16, path: &str) -> TestResult<Resp> {
    tls_raw(port, &format!("GET {path} HTTP/1.1\r\nHost: panel.example\r\nConnection: close\r\n\r\n"), b"").await
}

async fn reload(api: u16) -> TestResult<serde_json::Value> {
    let mut s = TcpStream::connect(("127.0.0.1", api)).await?;
    s.write_all(b"POST /api/v1/reload HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    let r = read_resp(&mut s).await?;
    Ok(serde_json::from_slice(&r.body)?)
}

fn upstream_url(u: &Upstream) -> String {
    format!("http://127.0.0.1:{}", u.port)
}

// ------------------------------------------------------------------ testler

#[tokio::test]
async fn temel_proxy_baslik_iletimi_ve_xff() -> TestResult {
    let ws = Workspace::new("temel");
    let up = spawn_upstream("A").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(ws.conf(), base_conf(api, &extra_block("panel", port, &upstream_url(&up), &cert, "")))?;
    let _srv = spawn(&ws)?;

    let r = tls_raw(
        port,
        "GET /hello?x=1 HTTP/1.1\r\nHost: panel.example\r\nX-Custom: abc\r\nCookie: a=b\r\nConnection: close\r\n\r\n",
        b"",
    )
    .await?;
    assert_eq!(r.status, 200, "{}", r.head);
    let t = r.text();
    assert!(t.contains("UP:A"), "{t}");
    let lower = t.to_ascii_lowercase();
    assert!(t.contains("GET /hello?x=1 HTTP/1.1"), "{t}");
    assert!(lower.contains("x-custom: abc"), "{t}");
    assert!(lower.contains("cookie: a=b"), "{t}");
    assert!(lower.contains("x-forwarded-for: 127.0.0.1"), "{t}");
    assert!(lower.contains("x-forwarded-proto: https"), "{t}");
    assert!(lower.lines().any(|l| l.trim() == "host: panel.example"), "preserve_host=true: {t}");
    Ok(())
}

#[tokio::test]
async fn preserve_host_false_host_arka_uc_adresine_cevrilir() -> TestResult {
    let ws = Workspace::new("ph");
    let up = spawn_upstream("A").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(
        ws.conf(),
        base_conf(api, &extra_block("panel", port, &upstream_url(&up), &cert, "preserve_host = false")),
    )?;
    let _srv = spawn(&ws)?;
    let r = tls_get(port, "/").await?;
    let t = r.text().to_ascii_lowercase();
    assert!(t.contains(&format!("host: 127.0.0.1:{}", up.port)), "{t}");
    assert!(!t.lines().any(|l| l.trim() == "host: panel.example"), "{t}");
    Ok(())
}

#[tokio::test]
async fn buyuk_govde_butunlugu() -> TestResult {
    let ws = Workspace::new("buyuk");
    let up = spawn_upstream("A").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(ws.conf(), base_conf(api, &extra_block("panel", port, &upstream_url(&up), &cert, "")))?;
    let _srv = spawn(&ws)?;

    let body: Vec<u8> = (0..8 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let expected: u64 = body.iter().map(|b| *b as u64).sum();
    let head = format!(
        "POST /upload HTTP/1.1\r\nHost: panel.example\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let r = tls_raw(port, &head, &body).await?;
    assert_eq!(r.status, 200, "{}", r.head);
    let t = r.text();
    assert!(t.contains(&format!("BODYLEN:{}", body.len())), "{}", &t[..t.len().min(200)]);
    assert!(t.contains(&format!("SUM:{expected}")), "bayt toplami uyusmuyor");
    Ok(())
}

#[tokio::test]
async fn upstream_kapaliyken_502() -> TestResult {
    let ws = Workspace::new("k502");
    let dead = free_port(); // dinleyen yok
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(
        ws.conf(),
        base_conf(api, &extra_block("panel", port, &format!("http://127.0.0.1:{dead}"), &cert, "")),
    )?;
    let _srv = spawn(&ws)?;
    let r = tls_get(port, "/").await?;
    assert_eq!(r.status, 502, "{}", r.head);
    Ok(())
}

#[tokio::test]
async fn acik_vekil_yok_host_ve_mutlak_uri_ile_arka_uc_degismez() -> TestResult {
    let ws = Workspace::new("acik");
    let good = spawn_upstream("GOOD").await;
    let evil = spawn_upstream("EVIL").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(ws.conf(), base_conf(api, &extra_block("panel", port, &upstream_url(&good), &cert, "")))?;
    let _srv = spawn(&ws)?;

    // Negatif kontrol: sahte "EVIL" arka uç gerçekten ulaşılabilir ve sayaç çalışıyor.
    let mut direct = TcpStream::connect(("127.0.0.1", evil.port)).await?;
    direct.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await?;
    let d = read_resp(&mut direct).await?;
    assert!(d.text().contains("UP:EVIL"));
    assert_eq!(evil.hits.load(Ordering::SeqCst), 1, "sayac dogrudan istekle artmali");

    let evil_addr = format!("127.0.0.1:{}", evil.port);
    let attempts = [
        format!("GET /x HTTP/1.1\r\nHost: {evil_addr}\r\nConnection: close\r\n\r\n"),
        format!("GET http://{evil_addr}/x HTTP/1.1\r\nHost: {evil_addr}\r\nConnection: close\r\n\r\n"),
        format!("GET /x HTTP/1.1\r\nHost: panel.example\r\nX-Forwarded-Host: {evil_addr}\r\nX-Upstream: {evil_addr}\r\nX-Original-URL: http://{evil_addr}/\r\nConnection: close\r\n\r\n"),
        format!("GET //{evil_addr}/x HTTP/1.1\r\nHost: {evil_addr}\r\nConnection: close\r\n\r\n"),
    ];
    for a in &attempts {
        if let Ok(r) = tls_raw(port, a, b"").await {
            // Ya sabit arka uca gider ya reddedilir; asla EVIL'e gitmez.
            assert!(!r.text().contains("UP:EVIL"), "{a}\n{}", r.text());
        }
    }
    assert_eq!(evil.hits.load(Ordering::SeqCst), 1, "EVIL arka uca ek istek gitmemeli");
    assert!(good.hits.load(Ordering::SeqCst) >= 1, "istekler sabit arka uca gitmeli");
    Ok(())
}

#[tokio::test]
async fn websocket_yukseltme_ve_kapali_websocket() -> TestResult {
    let ws = Workspace::new("ws");
    let up = spawn_upstream("A").await;
    let (api, p_on, p_off) = (free_port(), free_port(), free_port());
    let cert = ws.cert("p");
    let extra = format!(
        "{}\n{}",
        extra_block("ws-on", p_on, &upstream_url(&up), &cert, ""),
        extra_block("ws-off", p_off, &upstream_url(&up), &cert, "websocket = false")
    );
    std::fs::write(ws.conf(), base_conf(api, &extra))?;
    let _srv = spawn(&ws)?;

    let upgrade = "GET /chat HTTP/1.1\r\nHost: panel.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    let mut s = tls_connect(p_on).await?;
    s.write_all(upgrade.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while head_end(&buf).is_none() {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut tmp)).await??;
        assert!(n > 0, "baglanti kapandi");
        buf.extend_from_slice(&tmp[..n]);
    }
    assert!(String::from_utf8_lossy(&buf).starts_with("HTTP/1.1 101"), "{}", String::from_utf8_lossy(&buf));
    s.write_all(b"ping-123").await?;
    let mut got = Vec::new();
    while got.len() < 8 {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut tmp)).await??;
        assert!(n > 0, "yanki gelmedi");
        got.extend_from_slice(&tmp[..n]);
    }
    assert_eq!(&got[..8], b"ping-123");

    // websocket = false: Upgrade başlığı arka uca iletilmez, 101 olmaz.
    let before = up.heads.lock().unwrap().len();
    let r = tls_raw(p_off, &upgrade.replace("Connection: Upgrade", "Connection: Upgrade, close"), b"").await?;
    assert_ne!(r.status, 101, "{}", r.head);
    let heads = up.heads.lock().unwrap().clone();
    if heads.len() > before {
        assert!(
            !heads[before..].iter().any(|h| h.to_ascii_lowercase().contains("upgrade: websocket")),
            "Upgrade arka uca sizdi"
        );
    }
    Ok(())
}

#[tokio::test]
async fn yol_onekine_gore_sabit_arka_uc() -> TestResult {
    let ws = Workspace::new("route");
    let main_up = spawn_upstream("MAIN").await;
    let pma = spawn_upstream("PMA").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    let more = format!(
        "[[listeners.extra.routes]]\npath_prefix = \"/phpmyadmin/\"\nupstream = \"{}\"\n",
        upstream_url(&pma)
    );
    // [[routes]] alt tablosu ssl tablosundan önce yazılırsa son [[listeners.extra]] girdisine bağlanır
    let block = format!(
        r#"[[listeners.extra]]
name = "panel"
address = "127.0.0.1"
port = {port}
upstream = "{}"
[listeners.extra.ssl]
cert = "{}"
key = "{}"
{more}
"#,
        upstream_url(&main_up),
        fwd(&cert.0),
        fwd(&cert.1)
    );
    std::fs::write(ws.conf(), base_conf(api, &block))?;
    let _srv = spawn(&ws)?;
    assert!(tls_get(port, "/").await?.text().contains("UP:MAIN"));
    assert!(tls_get(port, "/phpmyadmin/index.php").await?.text().contains("UP:PMA"));
    assert!(tls_get(port, "/phpmyadmin2/x").await?.text().contains("UP:MAIN"));
    Ok(())
}

#[tokio::test]
async fn reload_ile_ekleme_cikarma_guncelleme_ve_sertifika_yenileme() -> TestResult {
    let ws = Workspace::new("reload");
    let up_a = spawn_upstream("A").await;
    let up_b = spawn_upstream("B").await;
    let up_c = spawn_upstream("C").await;
    let (api, p1, p2) = (free_port(), free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(ws.conf(), base_conf(api, &extra_block("bir", p1, &upstream_url(&up_a), &cert, "")))?;
    let _srv = spawn(&ws)?;
    assert!(tls_get(p1, "/").await?.text().contains("UP:A"));
    assert!(tls_connect(p2).await.is_err(), "p2 henuz dinlenmemeli");

    // Aynı dinleyicinin arka ucu + yeni dinleyici (p2) eklenir; sertifika dosyası yenilenir.
    let serial_before = peer_cert_der(p1).await?;
    let cert2 = ws.cert("p"); // aynı yola yeni sertifika yazar
    let extra = format!(
        "{}\n{}",
        extra_block("bir", p1, &upstream_url(&up_b), &cert2, ""),
        extra_block("iki", p2, &upstream_url(&up_c), &cert2, "")
    );
    std::fs::write(ws.conf(), base_conf(api, &extra))?;
    let r = reload(api).await?;
    assert_eq!(r["ok"], true, "{r}");
    assert!(tls_get(p1, "/").await?.text().contains("UP:B"), "arka uc canli guncellenmeli");
    assert!(tls_get(p2, "/").await?.text().contains("UP:C"), "yeni dinleyici acilmali");
    assert_ne!(serial_before, peer_cert_der(p1).await?, "sertifika canli yenilenmeli");

    // 'bir' çıkarılır -> port kapanır; 'iki' sürer.
    std::fs::write(ws.conf(), base_conf(api, &extra_block("iki", p2, &upstream_url(&up_c), &cert2, "")))?;
    assert_eq!(reload(api).await?["ok"], true);
    assert!(tls_connect(p1).await.is_err(), "kaldirilan dinleyici kapanmali");
    assert!(tls_get(p2, "/").await?.text().contains("UP:C"));

    // Bozuk yapılandırma reload'u reddedilir, çalışan dinleyici etkilenmez.
    std::fs::write(ws.conf(), base_conf(api, "[[listeners.extra]]\nname=\"iki\"\nport=1\n"))?;
    let bad = reload(api).await?;
    assert_ne!(bad["ok"], true, "{bad}");
    assert!(tls_get(p2, "/").await?.text().contains("UP:C"));
    Ok(())
}

async fn peer_cert_der(port: u16) -> TestResult<Vec<u8>> {
    let s = tls_connect(port).await?;
    let certs = s.get_ref().1.peer_certificates().ok_or("sertifika yok")?;
    Ok(certs[0].as_ref().to_vec())
}

#[tokio::test]
async fn fail_closed_eksik_sertifika_bozuk_upstream_ve_acik_duz_http() -> TestResult {
    let cases: Vec<(&str, String)> = vec![
        (
            "eksik-sertifika",
            "[[listeners.extra]]\nname=\"x\"\nport=18999\nupstream=\"127.0.0.1:1\"\n[listeners.extra.ssl]\ncert=\"yok.crt\"\nkey=\"yok.key\"\n".to_string(),
        ),
        (
            "https-upstream",
            "[[listeners.extra]]\nname=\"x\"\nport=18999\nupstream=\"https://127.0.0.1:1\"\n[listeners.extra.ssl]\ncert=\"a\"\nkey=\"b\"\n".to_string(),
        ),
        (
            "duz-http-herkese-acik",
            "[[listeners.extra]]\nname=\"x\"\naddress=\"0.0.0.0\"\nport=18999\nupstream=\"127.0.0.1:1\"\n".to_string(),
        ),
    ];
    for (tag, block) in cases {
        let ws = Workspace::new(tag);
        std::fs::write(ws.conf(), base_conf(free_port(), &block))?;
        let out = Command::new(env!("CARGO_BIN_EXE_zmax"))
            .arg("-c")
            .arg(ws.conf())
            .arg("--check")
            .env("ZMAX_HOME", &ws.root)
            .output()?;
        assert!(!out.status.success(), "{tag}: --check basarili olmamali\n{}", String::from_utf8_lossy(&out.stdout));
    }

    // Sertifika dosyası var ama PEM bozuk: başlatma reddedilir (sunucu 'hazır' olmaz).
    let ws = Workspace::new("bozuk-pem");
    let bad = (ws.root.join("certs/bad.crt"), ws.root.join("certs/bad.key"));
    std::fs::write(&bad.0, "bozuk")?;
    std::fs::write(&bad.1, "bozuk")?;
    std::fs::write(ws.conf(), base_conf(free_port(), &extra_block("x", free_port(), "127.0.0.1:1", &bad, "")))?;
    assert!(spawn(&ws).is_err(), "bozuk PEM ile baslamamali");
    Ok(())
}

#[tokio::test]
async fn global_acl_ek_dinleyicide_de_gecerli() -> TestResult {
    let ws = Workspace::new("acl");
    let up = spawn_upstream("A").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    let conf = base_conf(api, &extra_block("panel", port, &upstream_url(&up), &cert, ""))
        .replace("[logging]", "[security]\ndeny_ips = [\"127.0.0.1\"]\n\n[logging]");
    std::fs::write(ws.conf(), conf)?;
    let _srv = spawn(&ws)?;
    let r = tls_get(port, "/").await?;
    assert_eq!(r.status, 403, "{}", r.head);
    assert_eq!(up.hits.load(Ordering::SeqCst), 0, "reddedilen istek arka uca ulasmamali");
    Ok(())
}

#[tokio::test]
async fn duz_http_loopback_dinleyici_ve_istemci_baglanti_siniri() -> TestResult {
    let ws = Workspace::new("duz");
    let up = spawn_upstream("A").await;
    let (api, p_plain, p_lim) = (free_port(), free_port(), free_port());
    let cert = ws.cert("p");
    let plain = format!(
        "[[listeners.extra]]\nname=\"yerel\"\naddress=\"127.0.0.1\"\nport={p_plain}\nupstream=\"{}\"\n",
        upstream_url(&up)
    );
    let extra = format!(
        "{plain}\n{}",
        extra_block("sinirli", p_lim, &upstream_url(&up), &cert, "max_client_conns = 1")
    );
    std::fs::write(ws.conf(), base_conf(api, &extra))?;
    let _srv = spawn(&ws)?;

    let mut s = TcpStream::connect(("127.0.0.1", p_plain)).await?;
    s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await?;
    let r = read_resp(&mut s).await?;
    assert_eq!(r.status, 200);
    assert!(r.text().to_ascii_lowercase().contains("x-forwarded-proto: http\r\n"), "{}", r.text());

    // max_client_conns = 1: ilk bağlantı açıkken ikincisi düşürülür; ilk kapanınca yeniden kabul edilir.
    let first = tls_connect(p_lim).await?;
    let second = tls_connect(p_lim).await;
    assert!(second.is_err(), "ikinci baglanti sinir nedeniyle reddedilmeli");
    drop(first);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(tls_get(p_lim, "/").await?.status, 200);
    Ok(())
}

// ------------------------------------------------------------------ panel uyum hataları (413/502 ve zaman aşımı)

/// Gövdeyi OKUMADAN 413 yazıp bağlantıyı hemen kapatan arka uç (Fastify `bodyLimit` davranışı).
async fn spawn_early_413(close_after: Duration) -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    // Küçük alıcı tamponu: gövde yazımı arka uç okumayınca hızla tıkanır (kabul edilen soketler devralır).
    let _ = socket2::SockRef::from(&l).set_recv_buffer_size(4096);
    let up = Upstream {
        port: l.local_addr().unwrap().port(),
        hits: Arc::new(AtomicUsize::new(0)),
        heads: Arc::new(Mutex::new(Vec::new())),
    };
    let u2 = up.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let u = u2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 16384];
                while head_end(&buf).is_none() {
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                u.hits.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"statusCode":413,"error":"Payload Too Large"}"#;
                let resp = format!(
                    "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
                tokio::time::sleep(close_after).await;
                drop(s); // okunmamış gövde baytları varken kapanış (RST)
            });
        }
    });
    up
}

/// İstek başını okuyup `delay` sonra 200 yanıtlayan arka uç.
async fn spawn_delayed(delay: Duration, tag: &'static str) -> Upstream {
    let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let up = Upstream {
        port: l.local_addr().unwrap().port(),
        hits: Arc::new(AtomicUsize::new(0)),
        heads: Arc::new(Mutex::new(Vec::new())),
    };
    let u2 = up.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let u = u2.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while head_end(&buf).is_none() {
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                u.hits.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                let body = format!("SLOW:{tag}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    up
}

async fn post_413_tekrar(close_after: Duration, mb: usize, reps: usize) -> TestResult {
    let ws = Workspace::new("e413");
    let up = spawn_early_413(close_after).await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    std::fs::write(ws.conf(), base_conf(api, &extra_block("panel", port, &upstream_url(&up), &cert, "")))?;
    let _srv = spawn(&ws)?;

    let body = vec![b'x'; mb * 1024 * 1024];
    let head = format!(
        "POST /api/v1/upload HTTP/1.1\r\nHost: panel.example\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut codes = Vec::new();
    for _ in 0..reps {
        let t = std::time::Instant::now();
        let r = tls_raw(port, &head, &body).await?;
        assert!(t.elapsed() < Duration::from_secs(10), "413 gecikti: {:?}", t.elapsed());
        codes.push(r.status);
        if r.status == 413 {
            assert!(r.text().contains("Payload Too Large"), "{}", r.text());
        }
    }
    assert_eq!(codes, vec![413u16; reps], "tum denemeler 413 olmali: {codes:?}");
    assert_eq!(up.hits.load(Ordering::SeqCst), reps);
    Ok(())
}

/// Arka uç 413 yazıp ~20 ms sonra okunmamış gövdeyle kapatır (RST): 5 MB gövde, 20 tekrar, hepsi 413.
/// Not: sıfır gecikmeli RST'de Windows alıcı tamponunu atar (yanıt OS düzeyinde kaybolur); Linux'ta tampon korunur.
#[tokio::test]
async fn upstream_erken_413_verip_kapatinca_5mb_govdede_413_iletilir_20_tekrar() -> TestResult {
    post_413_tekrar(Duration::from_millis(20), 5, 20).await
}

/// Arka uç 413'ü yazar ama gövdeyi HİÇ okumadan bağlantıyı açık tutar: istek yazımı tampon dolunca tıkanır.
/// Eşzamanlı yanıt dinleme yoksa vekil sonsuza dek yazmada takılır; olmalıdır ki 413 hemen iletilsin (OS'tan bağımsız).
#[tokio::test]
async fn upstream_413_yazip_govdeyi_okumayinca_yazma_tikanmaz_413_iletilir() -> TestResult {
    post_413_tekrar(Duration::from_secs(30), 60, 5).await
}

#[tokio::test]
async fn ek_dinleyici_init_timeout_300_35sn_gecikmeli_yanit_200() -> TestResult {
    let ws = Workspace::new("t35");
    let up = spawn_delayed(Duration::from_secs(35), "EK").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    // proxy_ext alt tablosu ssl tablosundan sonra yazılır (aynı [[listeners.extra]] girdisine bağlanır).
    let block = format!(
        "{}[listeners.extra.proxy_ext]\ninit_timeout_sec = 300\n",
        extra_block("panel", port, &upstream_url(&up), &cert, "")
    );
    std::fs::write(ws.conf(), base_conf(api, &block))?;
    let _srv = spawn(&ws)?;
    let started = std::time::Instant::now();
    let mut s = tls_connect(port).await?;
    s.write_all(b"GET /yavas HTTP/1.1\r\nHost: panel.example\r\nConnection: close\r\n\r\n").await?;
    let r = read_resp_with(&mut s, Duration::from_secs(120)).await?;
    assert!(started.elapsed() >= Duration::from_secs(34));
    assert_eq!(r.status, 200, "{}", r.head);
    assert!(r.text().contains("SLOW:EK"));
    Ok(())
}

#[tokio::test]
async fn ek_dinleyici_kisa_init_timeout_gecikmede_504_negatif_kontrol() -> TestResult {
    let ws = Workspace::new("t3");
    let up = spawn_delayed(Duration::from_secs(6), "EK").await;
    let (api, port) = (free_port(), free_port());
    let cert = ws.cert("p");
    let block = format!(
        "{}[listeners.extra.proxy_ext]\ninit_timeout_sec = 2\n",
        extra_block("panel", port, &upstream_url(&up), &cert, "")
    );
    std::fs::write(ws.conf(), base_conf(api, &block))?;
    let _srv = spawn(&ws)?;
    let r = tls_get(port, "/yavas").await?;
    assert_eq!(r.status, 504, "{}", r.head);
    Ok(())
}

#[tokio::test]
async fn vhost_proxy_init_timeout_300_35sn_gecikmeli_yanit_200() -> TestResult {
    let ws = Workspace::new("vh35");
    let up = spawn_delayed(Duration::from_secs(35), "VH").await;
    let (api, http) = (free_port(), free_port());
    std::fs::create_dir_all(ws.root.join("www/html"))?;
    let conf = base_conf(api, "").replace(
        "[listeners.http]\nenabled = false",
        &format!("[listeners.http]\nenabled = true\naddress = \"127.0.0.1\"\nport = {http}"),
    );
    std::fs::write(ws.conf(), conf)?;
    std::fs::write(
        ws.root.join("conf/vhosts/panel.example.toml"),
        format!(
            "[vhost]\nname = \"panel.example\"\ndocument_root = \"www/html\"\n\n[vhost.php]\nenabled = false\n\n[vhost.proxy]\nenabled = true\nupstream = \"{}\"\npath_prefix = \"/\"\n\n[vhost.proxy_ext]\nresp_buffer = false\ninit_timeout_sec = 300\n",
            format!("127.0.0.1:{}", up.port)
        ),
    )?;
    let _srv = spawn(&ws)?;
    let started = std::time::Instant::now();
    let mut s = TcpStream::connect(("127.0.0.1", http)).await?;
    s.write_all(b"GET /yavas HTTP/1.1\r\nHost: panel.example\r\nConnection: close\r\n\r\n").await?;
    let r = read_resp_with(&mut s, Duration::from_secs(120)).await?;
    assert_eq!(r.status, 200, "{} {} t={:?}", r.head, r.text(), started.elapsed());
    assert!(r.text().contains("SLOW:VH"));
    Ok(())
}
