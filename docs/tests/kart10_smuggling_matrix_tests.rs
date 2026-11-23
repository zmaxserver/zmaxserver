//! Kart 10 (ters vekil) kalici E2E testleri: gercek `zmax` sureci + upstream'in gordugu ISTEK SAYISINI
//! sayan sahte upstream. Tum portlar dinamiktir (`bind(:0)`), senkronizasyon icin `sleep` degil kosul
//! (Notify / kayit sayaci durgunlugu) beklenir. Zaman gecmesinin kendisinin test edildigi yerlerde
//! (keep-alive TTL, bosta sure) gecen sure testin konusudur.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener as StdListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify};
use tokio_rustls::TlsConnector;

/// Port secimi + zmax baslatma ayni anda tek testte yapilir (secilen port baska test tarafindan alinmasin).
static START_LOCK: Mutex<()> = Mutex::const_new(());

struct ZMaxProcessGuard {
    child: Child,
    base_dir: PathBuf,
}

impl Drop for ZMaxProcessGuard {
    fn drop(&mut self) {
        if let Err(e) = self.child.kill() {
            eprintln!("zmax sureci sonlandirilamadi: {e}");
        }
        if let Err(e) = self.child.wait() {
            eprintln!("zmax sureci beklenemedi: {e}");
        }
        if let Err(e) = std::fs::remove_dir_all(&self.base_dir) {
            eprintln!("test dizini silinemedi: {e}");
        }
    }
}

struct Fixture {
    _guard: ZMaxProcessGuard,
    http: u16,
    https: u16,
    cert: CertificateDer<'static>,
}

fn free_ports() -> [u16; 4] {
    let listeners: Vec<StdListener> = (0..4)
        .map(|_| StdListener::bind("127.0.0.1:0").expect("bos port alinamadi"))
        .collect();
    let mut out = [0u16; 4];
    for (i, l) in listeners.iter().enumerate() {
        out[i] = l.local_addr().expect("port adresi").port();
    }
    out
}

/// `proxy_ext` ek satirlari `ext` icinde verilir.
fn vhost_toml(name: &str, upstream: &str, websocket: bool, ext: &str) -> String {
    format!(
        r#"[vhost]
name = "{name}"
document_root = "www/html"

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "certs/https.pem"
key = "certs/https.key"

[vhost.proxy]
enabled = true
upstream = "{upstream}"
path_prefix = "/"
preserve_host = true
websocket = {websocket}

[vhost.proxy_ext]
resp_buffer = false
{ext}
"#
    )
}

fn write_workspace(
    base_dir: &Path,
    ports: [u16; 4],
    vhosts: &[(String, String)],
    mod_proxy_settings: &str,
) -> CertificateDer<'static> {
    let [http_port, https_port, api_port, admin_port] = ports;
    for d in [
        "conf/vhosts",
        "modules",
        "admin",
        "www/html",
        "certs",
        "logs",
    ] {
        std::fs::create_dir_all(base_dir.join(d)).expect("dizin olusturulamadi");
    }
    std::fs::write(base_dir.join("admin").join("index.html"), "ADMIN").expect("admin index");
    std::fs::write(base_dir.join("www/html/index.html"), "DEFAULT").expect("www index");

    let names: Vec<String> = vhosts.iter().map(|(n, _)| n.clone()).collect();
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    sans.extend(names);
    let ck = rcgen::generate_simple_self_signed(sans).expect("test sertifikasi");
    let cert_der = ck.cert.der().clone();
    std::fs::write(base_dir.join("certs/https.pem"), ck.cert.pem()).expect("pem");
    std::fs::write(
        base_dir.join("certs/https.key"),
        ck.signing_key.serialize_pem(),
    )
    .expect("key");

    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax-Kart10-Matris"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http_port}

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {https_port}
ssl = true

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api_port}

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {admin_port}
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
    std::fs::write(base_dir.join("conf/zmax.toml"), zmax_toml).expect("zmax.toml");

    let mod_proxy = format!(
        "[module]\nname = \"mod_proxy\"\nversion = \"1.0.0\"\ncategory = \"Proxy\"\nenabled = true\n\n[settings]\npreserve_host = true\nwebsocket_upgrade = true\n{mod_proxy_settings}\n"
    );
    std::fs::write(base_dir.join("modules/mod_proxy.toml"), mod_proxy).expect("mod_proxy.toml");

    for (i, (name, content)) in vhosts.iter().enumerate() {
        let file = format!("{:02}-{}.toml", i + 1, name.replace('.', "-"));
        std::fs::write(base_dir.join("conf/vhosts").join(file), content).expect("vhost dosyasi");
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

    let outcome = tokio::time::timeout(Duration::from_secs(15), ready_rx).await;
    let guard = ZMaxProcessGuard {
        child,
        base_dir: base_dir.to_path_buf(),
    };
    match outcome {
        Ok(Ok(Ok(()))) => guard,
        Ok(Ok(Err(msg))) => panic!("zmax baslatma hatasi: {msg}"),
        Ok(Err(_)) => panic!("zmax hazir kanali beklenmedik sekilde kapandi"),
        Err(_) => panic!("zmax 15 saniye icinde hazir durumuna gecmedi"),
    }
}

async fn start(tag: &str, vhosts: Vec<(String, String)>, mod_proxy_settings: &str) -> Fixture {
    let _lock = START_LOCK.lock().await;
    let ports = free_ports();
    let base = std::env::temp_dir().join(format!("k10m_{tag}_{}", std::process::id()));
    if base.exists() {
        std::fs::remove_dir_all(&base).expect("eski test dizini silinemedi");
    }
    let cert = write_workspace(&base, ports, &vhosts, mod_proxy_settings);
    let guard = spawn_zmax_and_wait_ready(&base).await;
    Fixture {
        _guard: guard,
        http: ports[0],
        https: ports[1],
        cert,
    }
}

// ---------------------------------------------------------------- sahte upstream

type Recs = Arc<StdMutex<Vec<String>>>;

#[derive(Clone)]
struct Upstream {
    addr: String,
    recs: Recs,
    accepted: Arc<AtomicUsize>,
    slow_started: Arc<Notify>,
    slow_gate: Arc<Notify>,
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Chunked govde tam mi? Tam ise tuketilen bayt sayisini doner.
fn chunked_len(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    loop {
        let p = b[i..].windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&b[i..i + p]).ok()?;
        let sz = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        i += p + 2;
        if sz == 0 {
            let q = b[i..].windows(2).position(|w| w == b"\r\n")?;
            if q == 0 {
                return Some(i + 2);
            }
            let r = b[i..].windows(4).position(|w| w == b"\r\n\r\n")?;
            return Some(i + r + 4);
        }
        if b.len() < i + sz + 2 {
            return None;
        }
        i += sz + 2;
    }
}

async fn read_more(s: &mut TcpStream, buf: &mut Vec<u8>, idle: Duration) -> bool {
    let mut tmp = [0u8; 4096];
    match tokio::time::timeout(idle, s.read(&mut tmp)).await {
        Ok(Ok(n)) if n > 0 => {
            buf.extend_from_slice(&tmp[..n]);
            true
        }
        _ => false,
    }
}

/// `idle_ms`: upstream'in bir sonraki istegi bekleme suresi (bu surede bayt gelmezse baglantiyi kapatir).
async fn spawn_upstream(idle_ms: u64) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let addr = listener.local_addr().expect("upstream adres").to_string();
    let up = Upstream {
        addr,
        recs: Arc::new(StdMutex::new(Vec::new())),
        accepted: Arc::new(AtomicUsize::new(0)),
        slow_started: Arc::new(Notify::new()),
        slow_gate: Arc::new(Notify::new()),
    };
    let up2 = up.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let cn = up2.accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(upstream_conn(
                s,
                cn,
                up2.clone(),
                Duration::from_millis(idle_ms),
            ));
        }
    });
    up
}

async fn upstream_conn(mut s: TcpStream, cn: usize, up: Upstream, idle: Duration) {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let hend = loop {
            if let Some(p) = head_end(&buf) {
                break p + 4;
            }
            if !read_more(&mut s, &mut buf, idle).await {
                if !buf.is_empty() {
                    up.recs.lock().expect("kilit").push(format!(
                        "conn{cn} ARTIK-BAYT {:?}",
                        String::from_utf8_lossy(&buf)
                            .chars()
                            .take(60)
                            .collect::<String>()
                    ));
                }
                return;
            }
        };
        let head = String::from_utf8_lossy(&buf[..hend]).to_string();
        let lower = head.to_ascii_lowercase();
        let first = head.lines().next().unwrap_or("").to_string();
        let path = first.split(' ').nth(1).unwrap_or("").to_string();
        let te_chunked = lower
            .lines()
            .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
        let cl: usize = lower
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-length:")
                    .map(|v| v.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0);
        let consumed;
        if te_chunked {
            loop {
                if let Some(n) = chunked_len(&buf[hend..]) {
                    consumed = hend + n;
                    break;
                }
                if !read_more(&mut s, &mut buf, idle).await {
                    return;
                }
            }
        } else {
            while buf.len() < hend + cl {
                if !read_more(&mut s, &mut buf, idle).await {
                    return;
                }
            }
            consumed = hend + cl;
        }
        let has_te = lower.lines().any(|l| l.starts_with("transfer-encoding"));
        let n_cl = lower
            .lines()
            .filter(|l| l.starts_with("content-length:"))
            .count();
        let has_host = lower.lines().any(|l| l.starts_with("host:"));
        up.recs.lock().expect("kilit").push(format!(
            "conn{cn} `{first}` cl={cl} nCL={n_cl} te_hdr={has_te} host={has_host}"
        ));
        buf.drain(..consumed);
        match path.as_str() {
            "/chunked" => {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").await;
                return;
            }
            "/chunked-ext" => {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trail: 1\r\n\r\n").await;
                return;
            }
            "/chunked-split" => {
                // Cerceve baytlari tek tek, TCP parcalari halinde gelir (artimli cozucuyu sinar)
                let wire: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
                for b in wire.chunks(3) {
                    if s.write_all(b).await.is_err() {
                        return;
                    }
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                return;
            }
            "/sse" => {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: 1\n\n\r\n").await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = s.write_all(b"9\r\ndata: 2\n\n\r\n0\r\n\r\n").await;
                return;
            }
            "/big" => {
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 2097152\r\n\r\n").await;
                let _ = s.write_all(&vec![b'a'; 1 << 20]).await;
                let _ = s.flush().await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                let _ = s.write_all(&vec![b'b'; 1 << 20]).await;
                return;
            }
            "/slow" => {
                up.slow_started.notify_one();
                let _ =
                    tokio::time::timeout(Duration::from_secs(20), up.slow_gate.notified()).await;
            }
            "/hang" => {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
            "/closed" => {
                return;
            }
            _ => {}
        }
        if s.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok",
        )
        .await
        .is_err()
        {
            return;
        }
    }
}

/// Kayit sayisi durgunlasana kadar bekler (upstream'e gec ulasan bayt/istek yakalansin diye).
async fn settle(recs: &Recs) {
    let mut last = recs.lock().expect("kilit").len();
    let mut stable = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    while stable < 5 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(150)).await;
        let now = recs.lock().expect("kilit").len();
        if now == last {
            stable += 1;
        } else {
            stable = 0;
            last = now;
        }
    }
}

// ---------------------------------------------------------------- HTTP/1.1 yardimcilari

async fn run_scenario(up: &Upstream, port: u16, name: &str, raw: &str) -> (usize, String) {
    up.recs.lock().expect("kilit").clear();
    let mut c = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("zmax'a baglanilamadi");
    c.write_all(raw.as_bytes()).await.expect("istek yazilamadi");
    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    let started = Instant::now();
    loop {
        let wait = if resp.is_empty() {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(500)
        };
        match tokio::time::timeout(wait, c.read(&mut tmp)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
        if started.elapsed() > Duration::from_secs(6) {
            break;
        }
    }
    drop(c);
    settle(&up.recs).await;
    let r = up.recs.lock().expect("kilit").clone();
    let status = String::from_utf8_lossy(&resp)
        .lines()
        .next()
        .unwrap_or("<yanit yok>")
        .to_string();
    let n = r.len();
    println!("[S] {name}: istemci=`{status}` upstream_kayit={n}");
    for x in &r {
        println!("      {x}");
    }
    (n, status)
}

/// Tek istek, `Connection: close`; (durum satiri, tum govde baytlari) doner.
async fn http1_once(port: u16, host: &str, path: &str) -> (String, Vec<u8>) {
    let mut c = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("zmax'a baglanilamadi");
    c.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("istek yazilamadi");
    let mut resp = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(30), c.read_to_end(&mut resp)).await;
    let line = String::from_utf8_lossy(&resp)
        .lines()
        .next()
        .unwrap_or("<yanit yok>")
        .to_string();
    (line, resp)
}

// ---------------------------------------------------------------- HTTP/2 yardimcilari

async fn h2_connect(fx: &Fixture, sni: &str) -> h2::client::SendRequest<bytes::Bytes> {
    let mut root_store = RootCertStore::empty();
    root_store.add(fx.cert.clone()).expect("kok sertifika");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls surumleri")
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(("127.0.0.1", fx.https))
        .await
        .expect("https baglantisi");
    let tls = connector
        .connect(ServerName::try_from(sni.to_string()).expect("sni"), tcp)
        .await
        .expect("tls el sikismasi");
    let (client, conn) = h2::client::handshake(tls).await.expect("h2 el sikismasi");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

struct H2Reply {
    status: u16,
    body: Vec<u8>,
    first_data: Option<Duration>,
    total: Duration,
}

async fn h2_get(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    host: &str,
    path: &str,
) -> H2Reply {
    let client = client.clone();
    let mut client = client.ready().await.expect("h2 hazir");
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://{host}{path}"))
        .header("host", host)
        .body(())
        .expect("istek");
    let t0 = Instant::now();
    let (resp, _s) = client.send_request(req, true).expect("h2 istek gonderimi");
    let (head, mut body) = tokio::time::timeout(Duration::from_secs(30), resp)
        .await
        .expect("h2 yanit zaman asimi")
        .expect("h2 yanit hatasi")
        .into_parts();
    let mut all = Vec::new();
    let mut first = None;
    while let Some(c) = body.data().await {
        let d = match c {
            Ok(d) => d,
            Err(_) => break,
        };
        let _ = body.flow_control().release_capacity(d.len());
        if first.is_none() && !d.is_empty() {
            first = Some(t0.elapsed());
        }
        all.extend_from_slice(&d);
    }
    H2Reply {
        status: head.status.as_u16(),
        body: all,
        first_data: first,
        total: t0.elapsed(),
    }
}

// ================================================================ TESTLER

/// P0 matrisi: her senaryoda upstream'in gordugu istek sayisi (1) ya da 400 + 0 istek.
#[tokio::test]
async fn k10_smuggling_matrix_upstream_request_count() {
    let up = spawn_upstream(300).await;
    let fx = start(
        "matris",
        vec![(
            "xff.kart10.test".to_string(),
            vhost_toml("xff.kart10.test", &up.addr, false, ""),
        )],
        "",
    )
    .await;

    let sm = "GET /smuggled HTTP/1.1\r\nHost: xff.kart10.test\r\n\r\n";
    let chunked = |inner: &str| format!("{:x}\r\n{}\r\n0\r\n\r\n", inner.len(), inner);
    let h = "Host: xff.kart10.test\r\n";

    // (ad, ham istek, beklenen upstream istek sayisi, beklenen durum oneki)
    let cases: Vec<(&str, String, usize, &str)> = vec![
        (
            "KONTROL 2 mesru pipeline istek",
            format!("GET /a HTTP/1.1\r\n{h}\r\nGET /b HTTP/1.1\r\n{h}Connection: close\r\n\r\n"),
            2,
            "HTTP/1.1 200",
        ),
        (
            "KONTROL mesru Connection: keep-alive + govde",
            format!("POST /p HTTP/1.1\r\n{h}Connection: keep-alive\r\nContent-Length: 3\r\n\r\nabc"),
            1,
            "HTTP/1.1 200",
        ),
        (
            "A chunked govde icinde gomulu 2. istek",
            format!("POST /victim HTTP/1.1\r\n{h}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{}", chunked(sm)),
            1,
            "HTTP/1.1 200",
        ),
        (
            "B Connection: Content-Length + gomulu istek",
            format!("POST /victim HTTP/1.1\r\n{h}Connection: Content-Length\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
        (
            "B2 connection: keep-alive, content-length",
            format!("POST /victim HTTP/1.1\r\n{h}connection: keep-alive, content-length\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
        (
            "B3 iki ayri Connection basligi (close + Content-Length)",
            format!("POST /victim HTTP/1.1\r\n{h}Connection: close\r\nConnection: Content-Length\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
        (
            "C Connection: Transfer-Encoding + chunked gomulu",
            format!("POST /victim HTTP/1.1\r\n{h}Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n{}", chunked(sm)),
            0,
            "HTTP/1.1 400",
        ),
        (
            "D Connection: Host + CL govde gomulu (Host'suz istek upstream'e gitmemeli)",
            format!("POST /victim HTTP/1.1\r\n{h}Connection: Host\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
        (
            "E CL+TE birlikte (TE chunked, CL kucuk)",
            format!("POST /victim HTTP/1.1\r\n{h}Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n{}", chunked(sm)),
            0,
            "HTTP/1.1 400",
        ),
        (
            "E2 CL+TE + Connection: Content-Length",
            format!("POST /victim HTTP/1.1\r\n{h}Connection: Content-Length\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n{}", chunked(sm)),
            0,
            "HTTP/1.1 400",
        ),
        (
            "F cift CL farkli deger",
            format!("POST /victim HTTP/1.1\r\n{h}Content-Length: 5\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
        (
            "F2 cift CL ayni deger",
            format!("POST /victim HTTP/1.1\r\n{h}Content-Length: {0}\r\nContent-Length: {0}\r\n\r\n{sm}", sm.len()),
            1,
            "HTTP/1.1 200",
        ),
        (
            "G TE: xchunked + CL (belirsiz TE)",
            format!("POST /victim HTTP/1.1\r\n{h}Transfer-Encoding: xchunked\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
        (
            "G2 `Transfer-Encoding : chunked` (bosluk) + CL",
            format!("POST /victim HTTP/1.1\r\n{h}Transfer-Encoding : chunked\r\nContent-Length: 4\r\n\r\n{}", chunked(sm)),
            0,
            "HTTP/1.1 400",
        ),
        (
            "H Connection: Content-Length, CL=0 + ardindan gomulu istek",
            format!("POST /victim HTTP/1.1\r\n{h}Connection: Content-Length\r\nContent-Length: 0\r\n\r\n{sm}"),
            0,
            "HTTP/1.1 400",
        ),
        (
            "I GET + Connection: Content-Length + govde",
            format!("GET /victim HTTP/1.1\r\n{h}Connection: Content-Length\r\nContent-Length: {}\r\n\r\n{sm}", sm.len()),
            0,
            "HTTP/1.1 400",
        ),
    ];

    let mut failures = Vec::new();
    for (name, raw, want_count, want_status) in &cases {
        let (n, status) = run_scenario(&up, fx.http, name, raw).await;
        if n != *want_count || !status.starts_with(want_status) {
            failures.push(format!(
                "{name}: upstream_istek={n} (beklenen {want_count}), istemci=`{status}` (beklenen `{want_status}`)"
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "smuggling matrisi basarisiz senaryolar:\n{}",
        failures.join("\n")
    );
}

/// HTTP/2: chunked yanit cozulur ("hello world"), SSE ve buyuk yanit AKAR (ilk veri hemen gelir).
#[tokio::test]
async fn k10_h2_chunked_decoded_and_sse_big_stream() {
    let up = spawn_upstream(300).await;
    let fx = start(
        "h2akis",
        vec![(
            "h2.kart10.test".to_string(),
            vhost_toml("h2.kart10.test", &up.addr, false, "init_timeout_sec = 15"),
        )],
        "",
    )
    .await;
    let mut client = h2_connect(&fx, "h2.kart10.test").await;

    for path in ["/chunked", "/chunked-ext", "/chunked-split"] {
        let r = h2_get(&mut client, "h2.kart10.test", path).await;
        assert_eq!(r.status, 200, "{path}");
        assert_eq!(
            String::from_utf8_lossy(&r.body),
            "hello world",
            "{path}: h2'de chunked upstream yaniti cozulmeli"
        );
    }

    let sse = h2_get(&mut client, "h2.kart10.test", "/sse").await;
    assert_eq!(sse.status, 200);
    let first = sse.first_data.expect("SSE'de hic veri gelmedi");
    println!("[H2] SSE ilk_veri={first:?} toplam={:?}", sse.total);
    assert!(
        first < Duration::from_millis(500),
        "SSE h2'de akmiyor (tamponlaniyor): ilk veri {first:?}"
    );
    assert!(
        sse.total >= Duration::from_secs(2),
        "SSE 2. olayi beklenmedi, toplam {:?}",
        sse.total
    );
    assert_eq!(String::from_utf8_lossy(&sse.body), "data: 1\n\ndata: 2\n\n");

    let big = h2_get(&mut client, "h2.kart10.test", "/big").await;
    assert_eq!(big.status, 200);
    let first = big.first_data.expect("buyuk yanitta hic veri gelmedi");
    println!(
        "[H2] BUYUK ilk_veri={first:?} toplam={:?} bayt={}",
        big.total,
        big.body.len()
    );
    assert!(
        first < Duration::from_millis(500),
        "buyuk yanit h2'de akmiyor: ilk veri {first:?}"
    );
    assert_eq!(big.body.len(), 2 * 1024 * 1024);
    assert!(big.body[..1 << 20].iter().all(|b| *b == b'a'));
    assert!(big.body[1 << 20..].iter().all(|b| *b == b'b'));
}

/// HTTP/2'de upstream zaman asimi h1 ile ayni: 504; upstream baglantiyi yanitsiz kapatirsa 502.
#[tokio::test]
async fn k10_h2_upstream_timeout_is_504_like_h1() {
    let up = spawn_upstream(300).await;
    let fx = start(
        "h2timeout",
        vec![(
            "h2t.kart10.test".to_string(),
            vhost_toml("h2t.kart10.test", &up.addr, false, "init_timeout_sec = 1"),
        )],
        "",
    )
    .await;

    let (line, _) = http1_once(fx.http, "h2t.kart10.test", "/hang").await;
    assert!(line.starts_with("HTTP/1.1 504"), "h1 referansi: {line}");

    let mut client = h2_connect(&fx, "h2t.kart10.test").await;
    let t0 = Instant::now();
    let r = h2_get(&mut client, "h2t.kart10.test", "/hang").await;
    println!("[H2] /hang durum={} sure={:?}", r.status, t0.elapsed());
    assert_eq!(r.status, 504, "h2'de upstream zaman asimi 504 olmali");
    assert!(t0.elapsed() < Duration::from_secs(10));

    let r = h2_get(&mut client, "h2t.kart10.test", "/closed").await;
    assert_eq!(r.status, 502, "yanitsiz kapanan upstream h2'de 502 olmali");
}

/// HTTP/2 yolunda istek smuggling: gomulu istek yalniz govde olarak gider (1 istek).
#[tokio::test]
async fn k10_h2_body_embedded_request_reaches_upstream_once() {
    let up = spawn_upstream(300).await;
    let fx = start(
        "h2smug",
        vec![(
            "h2s.kart10.test".to_string(),
            vhost_toml("h2s.kart10.test", &up.addr, false, ""),
        )],
        "",
    )
    .await;
    let client = h2_connect(&fx, "h2s.kart10.test").await;
    let mut client = client.ready().await.expect("h2 hazir");
    let sm = "GET /smuggled-h2 HTTP/1.1\r\nHost: h2s.kart10.test\r\n\r\n";

    up.recs.lock().expect("kilit").clear();
    let req = http::Request::builder()
        .method("POST")
        .uri("https://h2s.kart10.test/victim-h2")
        .header("host", "h2s.kart10.test")
        .header("content-length", sm.len().to_string())
        .body(())
        .expect("istek");
    let (resp, mut send) = client.send_request(req, false).expect("gonderim");
    send.send_data(bytes::Bytes::from(sm.to_string()), true)
        .expect("govde");
    let r = tokio::time::timeout(Duration::from_secs(10), resp)
        .await
        .expect("zaman asimi")
        .expect("yanit");
    assert_eq!(r.status().as_u16(), 200);
    settle(&up.recs).await;
    let recs = up.recs.lock().expect("kilit").clone();
    assert_eq!(recs.len(), 1, "h2 smuggling: kayitlar {recs:?}");
    assert!(recs[0].contains("/victim-h2"), "{recs:?}");

    // h2 istemcisi `Connection: Content-Length` gonderebilirse sunucu 400 ile reddetmeli;
    // istemci kendisi reddederse istek hic gitmez. Her iki durumda upstream 0 istek gormeli.
    up.recs.lock().expect("kilit").clear();
    let req = http::Request::builder()
        .method("POST")
        .uri("https://h2s.kart10.test/victim-h2b")
        .header("host", "h2s.kart10.test")
        .header("connection", "content-length")
        .header("content-length", sm.len().to_string())
        .body(())
        .expect("istek");
    let mut client = client.clone().ready().await.expect("h2 hazir");
    let mut status = None;
    if let Ok((resp, mut send)) = client.send_request(req, false) {
        let _ = send.send_data(bytes::Bytes::from(sm.to_string()), true);
        if let Ok(Ok(r)) = tokio::time::timeout(Duration::from_secs(5), resp).await {
            status = Some(r.status().as_u16());
        }
    }
    settle(&up.recs).await;
    let n = up.recs.lock().expect("kilit").len();
    println!("[H2] connection:content-length -> durum={status:?} upstream_istek={n}");
    assert_eq!(n, 0, "Connection: Content-Length h2'de upstream'e gitti");
    assert_ne!(status, Some(200));
}

/// `connect_timeout_sec` vhost'ta YOKSA mod_proxy.toml global degeri uygulanir (h1 ve h2 -> 504).
/// Kara delik (dolu accept kuyrugu) Windows'ta ~2 sn sonra RST ile reddedilir (502), Linux'ta sonsuza
/// asili kalir; bu yuzden olculen zaman asimlari 1 sn'dir (504 ancak zaman asimindan gelebilir).
#[tokio::test]
async fn k10_connect_timeout_global_fallback_when_vhost_has_none() {
    let hole = Blackhole::new();
    let fx = start(
        "ctg",
        vec![(
            "glob.kart10.test".to_string(),
            vhost_toml(
                "glob.kart10.test",
                &hole.addr,
                false,
                "init_timeout_sec = 30",
            ),
        )],
        "connect_timeout_sec = 1",
    )
    .await;

    // vhost'ta yok + global 1 -> 504 ~1 sn (eski kod: vhost varsayilani 10 hep kazanir)
    let t0 = Instant::now();
    let (line, _) = http1_once(fx.http, "glob.kart10.test", "/").await;
    let el = t0.elapsed();
    println!("[CT] h1 global: `{line}` sure={el:?}");
    assert!(line.starts_with("HTTP/1.1 504"), "{line}");
    assert!(
        el >= Duration::from_millis(800) && el < Duration::from_millis(1800),
        "global connect_timeout_sec=1 uygulanmadi: {el:?}"
    );

    // h2: ayni kural, 504
    let mut client = h2_connect(&fx, "glob.kart10.test").await;
    let t0 = Instant::now();
    let r = h2_get(&mut client, "glob.kart10.test", "/").await;
    let el = t0.elapsed();
    println!("[CT] h2 global: durum={} sure={el:?}", r.status);
    assert_eq!(r.status, 504);
    assert!(
        el >= Duration::from_millis(800) && el < Duration::from_millis(1800),
        "h2'de global connect_timeout_sec uygulanmadi: {el:?}"
    );
    drop(hole);
}

/// vhost'ta acik `connect_timeout_sec = 1` global 10'dan once gelir (h1 ve h2 -> 504 ~1 sn).
#[tokio::test]
async fn k10_connect_timeout_vhost_value_overrides_global() {
    let hole = Blackhole::new();
    let fx = start(
        "ctv",
        vec![(
            "vh.kart10.test".to_string(),
            vhost_toml(
                "vh.kart10.test",
                &hole.addr,
                false,
                "init_timeout_sec = 30\nconnect_timeout_sec = 1",
            ),
        )],
        "connect_timeout_sec = 10",
    )
    .await;
    let t0 = Instant::now();
    let (line, _) = http1_once(fx.http, "vh.kart10.test", "/").await;
    let el = t0.elapsed();
    println!("[CT] h1 vhost: `{line}` sure={el:?}");
    assert!(line.starts_with("HTTP/1.1 504"), "{line}");
    assert!(
        el >= Duration::from_millis(800) && el < Duration::from_millis(1800),
        "vhost connect_timeout_sec=1 uygulanmadi: {el:?}"
    );
    let mut client = h2_connect(&fx, "vh.kart10.test").await;
    let t0 = Instant::now();
    let r = h2_get(&mut client, "vh.kart10.test", "/").await;
    let el = t0.elapsed();
    println!("[CT] h2 vhost: durum={} sure={el:?}", r.status);
    assert_eq!(r.status, 504);
    assert!(el >= Duration::from_millis(800) && el < Duration::from_millis(1800));
    drop(hole);
}

/// `max_conns=1`: 1. istek sürerken esanli 2. istek 503, sonra 1. istek 200 ile biter.
#[tokio::test]
async fn k10_max_conns_limits_concurrent_upstream_requests() {
    let up = spawn_upstream(5_000).await;
    let fx = start(
        "maxconns",
        vec![(
            "mc.kart10.test".to_string(),
            vhost_toml(
                "mc.kart10.test",
                &up.addr,
                false,
                "max_conns = 1\ninit_timeout_sec = 30",
            ),
        )],
        "",
    )
    .await;
    let port = fx.http;
    let first = tokio::spawn(async move { http1_once(port, "mc.kart10.test", "/slow").await });
    tokio::time::timeout(Duration::from_secs(10), up.slow_started.notified())
        .await
        .expect("upstream /slow istegini gormedi");
    let (line2, _) = http1_once(fx.http, "mc.kart10.test", "/fast").await;
    println!("[MC] esanli 2. istek: `{line2}`");
    assert!(
        line2.starts_with("HTTP/1.1 503"),
        "max_conns=1 asildi: {line2}"
    );
    up.slow_gate.notify_one();
    let (line1, body1) = first.await.expect("1. istek gorevi");
    assert!(line1.starts_with("HTTP/1.1 200"), "{line1}");
    assert!(String::from_utf8_lossy(&body1).ends_with("ok"));
    // yuva serbest birakildi: yeni istek tekrar 200
    let (line3, _) = http1_once(fx.http, "mc.kart10.test", "/fast").await;
    assert!(
        line3.starts_with("HTTP/1.1 200"),
        "yuva serbest kalmadi: {line3}"
    );
}

/// `keep_alive_timeout_sec=1`: 2. istek hemen gelirse havuzdaki baglanti kullanilir (1 baglanti),
/// TTL dolduktan sonra yeni upstream baglantisi acilir. Kontrol: TTL=60 olan vhost eski baglantiyi korur.
#[tokio::test]
async fn k10_keep_alive_timeout_expires_pooled_upstream_connection() {
    let up_short = spawn_upstream(30_000).await;
    let up_long = spawn_upstream(30_000).await;
    let fx = start(
        "ka",
        vec![
            (
                "kas.kart10.test".to_string(),
                vhost_toml(
                    "kas.kart10.test",
                    &up_short.addr,
                    false,
                    "keep_alive_timeout_sec = 1",
                ),
            ),
            (
                "kal.kart10.test".to_string(),
                vhost_toml(
                    "kal.kart10.test",
                    &up_long.addr,
                    false,
                    "keep_alive_timeout_sec = 60",
                ),
            ),
        ],
        "",
    )
    .await;

    for (host, up) in [
        ("kas.kart10.test", &up_short),
        ("kal.kart10.test", &up_long),
    ] {
        let (l, _) = http1_once(fx.http, host, "/a").await;
        assert!(l.starts_with("HTTP/1.1 200"), "{l}");
        let (l, _) = http1_once(fx.http, host, "/b").await;
        assert!(l.starts_with("HTTP/1.1 200"), "{l}");
        assert_eq!(
            up.accepted.load(Ordering::SeqCst),
            1,
            "{host}: 2. istek havuzdaki baglantiyi kullanmali"
        );
    }
    // TTL'nin gecmesi testin konusudur (kisa vhost 1 sn)
    tokio::time::sleep(Duration::from_millis(1400)).await;
    for host in ["kas.kart10.test", "kal.kart10.test"] {
        let (l, _) = http1_once(fx.http, host, "/c").await;
        assert!(l.starts_with("HTTP/1.1 200"), "{l}");
    }
    assert_eq!(
        up_short.accepted.load(Ordering::SeqCst),
        2,
        "keep_alive_timeout_sec=1: TTL sonrasi yeni upstream baglantisi acilmaliydi"
    );
    assert_eq!(
        up_long.accepted.load(Ordering::SeqCst),
        1,
        "keep_alive_timeout_sec=60: baglanti korunmali"
    );
}

// ---------------------------------------------------------------- WebSocket

async fn spawn_ws_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("ws upstream bind");
    let addr = listener.local_addr().expect("adres").to_string();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                while head_end(&buf).is_none() {
                    if !read_more(&mut s, &mut buf, Duration::from_secs(10)).await {
                        return;
                    }
                }
                if s
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let mut tmp = [0u8; 1024];
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
            });
        }
    });
    addr
}

/// WS yukseltme istegi gonderir; (durum satiri, soket) doner.
async fn ws_open(port: u16, host: &str) -> (String, TcpStream) {
    let mut c = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("zmax'a baglanilamadi");
    c.write_all(
        format!("GET /chat HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").as_bytes(),
    )
    .await
    .expect("ws istegi");
    let mut buf = Vec::new();
    while head_end(&buf).is_none() {
        let mut tmp = [0u8; 1024];
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut tmp))
            .await
            .expect("ws yaniti zaman asimi")
            .expect("ws okuma");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let line = String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("<yok>")
        .to_string();
    (line, c)
}

/// `ws_idle_timeout_sec=1`: trafik akarken tunel acik kalir, sessiz tunel bosta surede kapanir.
#[tokio::test]
async fn k10_ws_idle_timeout_closes_silent_tunnel() {
    let ws = spawn_ws_echo().await;
    let fx = start(
        "wsidle",
        vec![(
            "ws.kart10.test".to_string(),
            vhost_toml("ws.kart10.test", &ws, true, "ws_idle_timeout_sec = 1"),
        )],
        "",
    )
    .await;
    let (line, mut c) = ws_open(fx.http, "ws.kart10.test").await;
    assert!(line.starts_with("HTTP/1.1 101"), "{line}");

    // 2,4 sn boyunca 400 ms araliklarla trafik: bosta sure sifirlanir, tunel acik kalir
    for i in 0..6u8 {
        c.write_all(&[b'x', i]).await.expect("tunel yazma");
        let mut echo = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut echo))
            .await
            .expect("echo zaman asimi (tunel erken kapandi)")
            .expect("echo okuma");
        assert_eq!(echo, [b'x', i]);
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    // sessizlik: sunucu en gec ~bosta sure + pay icinde tuneli kapatmali (eski kod: hic kapatmaz)
    let t0 = Instant::now();
    let mut tmp = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(8), c.read(&mut tmp)).await;
    let el = t0.elapsed();
    println!("[WS] sessiz tunel kapanma suresi={el:?} sonuc={r:?}");
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        other => panic!("sessiz tunel kapanmadi: {other:?}"),
    }
    assert!(el < Duration::from_secs(10), "tunel gec kapandi: {el:?}");
}

/// `max_ws=1`: ikinci es zamanli WebSocket 503; ilk kapaninca yuva serbest kalir.
#[tokio::test]
async fn k10_ws_max_connections_per_vhost() {
    let ws = spawn_ws_echo().await;
    let fx = start(
        "wsmax",
        vec![(
            "wsm.kart10.test".to_string(),
            vhost_toml(
                "wsm.kart10.test",
                &ws,
                true,
                "max_ws = 1\nws_idle_timeout_sec = 30",
            ),
        )],
        "",
    )
    .await;
    let (l1, c1) = ws_open(fx.http, "wsm.kart10.test").await;
    assert!(l1.starts_with("HTTP/1.1 101"), "{l1}");
    let (l2, _c2) = ws_open(fx.http, "wsm.kart10.test").await;
    println!("[WS] 2. es zamanli: `{l2}`");
    assert!(l2.starts_with("HTTP/1.1 503"), "max_ws=1 asildi: {l2}");
    drop(c1);
    // yuvanin serbest kalmasi sunucu tarafinda asenkron: kosul bekle (en cok 5 sn)
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (l3, c3) = ws_open(fx.http, "wsm.kart10.test").await;
        if l3.starts_with("HTTP/1.1 101") {
            drop(c3);
            break;
        }
        assert!(Instant::now() < deadline, "yuva serbest kalmadi: {l3}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------- yerel "kara delik" adresi

/// Accept kuyrugu dolu dinleyen yerel soket: yeni baglantilar tamamlanmaz (ag gerektirmez).
struct Blackhole {
    _listener: socket2::Socket,
    _fillers: Vec<socket2::Socket>,
    addr: String,
}

impl Blackhole {
    fn new() -> Self {
        use socket2::{Domain, Socket, Type};
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).expect("soket");
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("adres");
        listener.bind(&bind_addr.into()).expect("bind");
        listener.listen(0).expect("listen");
        let addr = listener
            .local_addr()
            .expect("yerel adres")
            .as_socket()
            .expect("ipv4");
        let mut fillers = Vec::new();
        for _ in 0..6 {
            let c = Socket::new(Domain::IPV4, Type::STREAM, None).expect("dolgu soketi");
            c.set_nonblocking(true).expect("nonblocking");
            let _ = c.connect(&addr.into());
            fillers.push(c);
        }
        // Onkosul: bu adrese yeni baglanti tamamlanmamali (aksi halde platform kuyrugu doldurmuyor)
        let probe = Socket::new(Domain::IPV4, Type::STREAM, None).expect("probe");
        let probe_res = probe.connect_timeout(&addr.into(), Duration::from_millis(500));
        assert!(
            probe_res.is_err(),
            "kara delik onkosulu saglanmadi: dolu kuyruklu dinleyiciye baglanti tamamlandi"
        );
        Blackhole {
            _listener: listener,
            _fillers: fillers,
            addr: addr.to_string(),
        }
    }
}
