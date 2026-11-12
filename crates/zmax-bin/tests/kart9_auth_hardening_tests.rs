//! Kart 9 sertleştirme testleri: GERÇEK `zmax` ikilisi + gerçek TCP / HTTP-2 (h2) istemci.
//!
//! Kapsam: sınırlı kuyruk (503), IP başına eşzamanlı doğrulama (429), sayaç doğrulamadan ÖNCE,
//! ban hattı (403), süre eşitleme, büyük/küçük harf, ayarlanabilirlik ve gerçek DoS ölçümü.
//! Tüm portlar dinamiktir (`bind(:0)`); kütüphane çağrısı değil, sunucu süreci sınanır.

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------

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

fn free_ports<const N: usize>() -> [u16; N] {
    let listeners: Vec<TcpListener> = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bos port baglanamadi"))
        .collect();
    let mut out = [0u16; N];
    for (slot, l) in out.iter_mut().zip(listeners.iter()) {
        *slot = l.local_addr().expect("yerel adres").port();
    }
    out
}

fn make_temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("saat")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("zmax_k9h_{}_{}_{}", tag, std::process::id(), nanos));
    std::fs::create_dir_all(&dir).expect("gecici dizin");
    dir
}

fn basic_token(user: &str, pass: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = format!("{user}:{pass}");
    let input = raw.as_bytes();
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((triple >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(triple & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    format!("Basic {out}")
}

fn spawn_zmax_and_wait_ready(base_dir: &Path, conf_path: &Path) -> Child {
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
    let log = Arc::new(std::sync::Mutex::new(String::new()));

    let err_log = Arc::clone(&log);
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

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    let out_log = Arc::clone(&log);
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
                let _ = tx.send(Ok(()));
            }
            line.clear();
        }
        if !notified {
            let _ = tx.send(Err("zmax hazir mesaji vermeden cikti".to_string()));
        }
    });

    match rx.recv_timeout(Duration::from_secs(30)) {
        Ok(Ok(())) => child,
        other => {
            let logs = log.lock().map(|g| g.clone()).unwrap_or_default();
            let _ = child.kill();
            panic!("zmax hazir degil ({other:?}). Cikti:\n{logs}");
        }
    }
}

/// Bu makinede (debug/release fark etmeksizin) tek doğrulaması en az `target_ms` süren
/// Argon2id parametresini seçer; testlerin kuyruk/süre davranışını anlamlı sınamasını sağlar.
fn pick_heavy_argon2(password: &str, target_ms: u128) -> (String, u128) {
    let mut m_kib: u32 = 1024;
    loop {
        let hash = zmax_security::argon2id_hash(password, b"k9hardsalt123456", m_kib, 3, 1)
            .expect("argon2id uretimi");
        let t = Instant::now();
        assert!(zmax_security::verify_argon2id(&hash, password));
        let ms = t.elapsed().as_millis();
        if ms >= target_ms || m_kib >= 65_536 {
            return (hash, ms.max(1));
        }
        m_kib *= 2;
    }
}

struct Env {
    _guard: ChildGuard,
    http: u16,
    https: u16,
    /// Tek doğrulamanın bu makinedeki süresi (ms)
    hash_ms: u128,
    /// `conf/auth/site.htpasswd` dosyasının yolu
    htpasswd: PathBuf,
    /// vHost belge kökü
    root: PathBuf,
}

const APR1_PASS: &str = "SifreApr1!";
const ARGON_PASS: &str = "SifreArgon2id!";

/// `security_extra`: `[security]` altına eklenen satırlar; `auth_extra`: `[vhost.auth]` altına eklenen satırlar.
fn start_env(tag: &str, security_extra: &str, auth_extra: &str) -> Env {
    let [http, https, admin, api] = free_ports::<4>();
    let base = make_temp_dir(tag);
    let conf = base.join("conf");
    let vhosts = conf.join("vhosts");
    let auth_dir = conf.join("auth");
    let ssl = conf.join("ssl");
    let root = base.join("www").join("auth.local");
    for d in [
        &vhosts,
        &auth_dir,
        &ssl,
        &base.join("modules"),
        &root.join("gizli"),
    ] {
        std::fs::create_dir_all(d).expect("dizin");
    }

    let ck =
        rcgen::generate_simple_self_signed(vec!["auth.local".to_string(), "127.0.0.1".to_string()])
            .expect("sertifika");
    std::fs::write(ssl.join("site.crt"), ck.cert.pem()).expect("crt");
    std::fs::write(ssl.join("site.key"), ck.signing_key.serialize_pem()).expect("key");

    std::fs::write(root.join("acik.html"), "ACIK_SAYFA_OK").expect("acik");
    std::fs::write(root.join("gizli").join("index.html"), "GIZLI_200").expect("gizli");

    let (argon_hash, hash_ms) = pick_heavy_argon2(ARGON_PASS, 300);
    let apr1 = zmax_security::apr1_hash(APR1_PASS, "k9salt12");
    std::fs::write(
        auth_dir.join("site.htpasswd"),
        format!("apruser:{apr1}\nargonuser:{argon_hash}\n"),
    )
    .expect("htpasswd");

    let conf_path = conf.join("zmax.toml");
    std::fs::write(
        &conf_path,
        format!(
            r#"
[server]
server_name = "ZMax/K9Hardening"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http}

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {https}
ssl = true

[listeners.admin]
enabled = false
address = "127.0.0.1"
port = {admin}

[listeners.api]
enabled = false
address = "127.0.0.1"
port = {api}

[vhosts_dir]
path = "conf/vhosts"

[cache]
enabled = false
memory_cache_mb = 16
default_ttl_seconds = 60
disk_cache_dir = "cache"

[security]
rate_limit_enabled = false
{security_extra}

[logging]
level = "info"
access_log = "logs/access.log"
error_log = "logs/error.log"
batch_flush_ms = 50
"#
        ),
    )
    .expect("zmax.toml");

    std::fs::write(
        vhosts.join("auth.local.toml"),
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
realm = "Sertlestirme"
path_prefix = "/gizli"
htpasswd_path = "conf/auth/site.htpasswd"
{auth_extra}
"#
        ),
    )
    .expect("vhost");

    let htpasswd = auth_dir.join("site.htpasswd");
    let child = spawn_zmax_and_wait_ready(&base, &conf_path);
    Env {
        _guard: ChildGuard {
            child,
            temp_dir: base,
        },
        http,
        https,
        hash_ms,
        htpasswd,
        root,
    }
}

#[derive(Debug, Clone)]
struct Resp {
    status: u16,
    head: String,
    elapsed: Duration,
}

impl Resp {
    fn has_header(&self, name: &str) -> bool {
        let needle = format!("\r\n{}:", name.to_ascii_lowercase());
        self.head.to_ascii_lowercase().contains(&needle)
    }
}

async fn http1(port: u16, path: &str, auth: Option<&str>) -> Resp {
    let t = Instant::now();
    let mut stream = TokioTcpStream::connect(("127.0.0.1", port))
        .await
        .expect("HTTP portuna baglanilamadi");
    let mut req = format!("GET {path} HTTP/1.1\r\nHost: auth.local\r\n");
    if let Some(a) = auth {
        req.push_str(&format!("Authorization: {a}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.expect("yazma");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("okuma");
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Resp {
        status,
        head: text,
        elapsed: t.elapsed(),
    }
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

async fn h2_client(port: u16) -> h2::client::SendRequest<bytes::Bytes> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("tls surumleri")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifyCert))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TokioTcpStream::connect(("127.0.0.1", port))
        .await
        .expect("HTTPS portuna baglanilamadi");
    let tls = connector
        .connect(
            ServerName::try_from("auth.local".to_string()).expect("sni"),
            tcp,
        )
        .await
        .expect("TLS el sikismasi");
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (client, conn) = h2::client::handshake(tls).await.expect("h2 el sikismasi");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

async fn h2_get(
    client: &mut h2::client::SendRequest<bytes::Bytes>,
    path: &str,
    auth: Option<&str>,
) -> u16 {
    let mut b = http::Request::builder()
        .method("GET")
        .uri(format!("https://auth.local{path}"))
        .header("host", "auth.local");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    let req = b.body(()).expect("istek");
    let mut ready = client.clone().ready().await.expect("h2 hazir");
    let (fut, _) = ready.send_request(req, true).expect("h2 gonder");
    let resp = fut.await.expect("h2 yanit");
    let status = resp.status().as_u16();
    let mut body = resp.into_body();
    while let Some(chunk) = body.data().await {
        let b = chunk.expect("govde");
        let _ = body.flow_control().release_capacity(b.len());
    }
    status
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[idx.saturating_sub(1).min(sorted.len() - 1)]
}

/// Aynı anda `n` adet yanlış parolalı (Argon2id) istek gönderir.
async fn flood_wrong_argon(port: u16, n: usize) -> Vec<Resp> {
    let mut tasks = Vec::new();
    for i in 0..n {
        let tok = basic_token("argonuser", &format!("Yanlis{i}"));
        tasks.push(tokio::spawn(async move {
            http1(port, "/gizli/index.html", Some(&tok)).await
        }));
    }
    let mut out = Vec::new();
    for t in tasks {
        out.push(t.await.expect("gorev"));
    }
    out
}

// ---------------------------------------------------------------------------
// Testler
// ---------------------------------------------------------------------------

/// Madde 1: semafor kuyruğu sınırlı; zaman aşımı 503 + Retry-After; kuyruk beklemesi sınırlı.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_queue_timeout_returns_503_with_retry_after_and_bounded_latency() {
    let env = start_env(
        "q503",
        "auth_max_concurrent_hashes = 1",
        "max_failed_attempts = 1000\nmax_concurrent_per_ip = 100\nqueue_timeout_ms = 500\nfail_min_ms = 100",
    );

    // Flood sürerken bağımsız statik istekler de ölçülür.
    let port = env.http;
    let flood = tokio::spawn(async move { flood_wrong_argon(port, 12).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut static_lat = Vec::new();
    for _ in 0..15 {
        let r = http1(env.http, "/acik.html", None).await;
        assert_eq!(r.status, 200, "statik yanit: {}", r.head);
        static_lat.push(r.elapsed);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let resps = flood.await.expect("flood");

    let n503 = resps.iter().filter(|r| r.status == 503).count();
    let max_ms = resps
        .iter()
        .map(|r| r.elapsed.as_millis())
        .max()
        .unwrap_or(0);
    let static_max_ms = static_lat.iter().map(|d| d.as_millis()).max().unwrap_or(0);
    println!(
        "K9H-OLCUM kuyruk: 503 sayisi={n503}/12, en yavas kimlik dogrulama={max_ms} ms, statik en yavas={static_max_ms} ms, hash={} ms",
        env.hash_ms
    );
    assert!(
        n503 >= 3,
        "kuyruk zaman asiminda 503 beklenir; durumlar: {:?} (hash {} ms)",
        resps.iter().map(|r| r.status).collect::<Vec<_>>(),
        env.hash_ms
    );
    for r in resps.iter().filter(|r| r.status == 503) {
        assert!(
            r.has_header("retry-after"),
            "503 Retry-After tasimali: {}",
            r.head
        );
    }
    let max_lat = resps.iter().map(|r| r.elapsed).max().unwrap_or_default();
    let bound = Duration::from_millis(500 + 100 + 1500) + Duration::from_millis(env.hash_ms as u64);
    assert!(
        max_lat < bound,
        "kimlik dogrulama gecikmesi sinirli olmali: {max_lat:?} >= {bound:?} (hash {} ms)",
        env.hash_ms
    );
    static_lat.sort();
    let worst = static_lat.last().copied().unwrap_or_default();
    assert!(
        worst < Duration::from_millis(200),
        "diger isteklerin gecikmesi < 200 ms olmali: {worst:?}"
    );
}

/// Madde 1: IP başına eşzamanlı doğrulama sınırı (varsayılan 2) aşılırsa 429.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_per_ip_concurrency_limit_returns_429() {
    let env = start_env(
        "perip",
        "auth_max_concurrent_hashes = 16",
        "max_failed_attempts = 1000\nqueue_timeout_ms = 5000\nfail_min_ms = 100",
    );
    let resps = flood_wrong_argon(env.http, 8).await;
    let n429 = resps.iter().filter(|r| r.status == 429).count();
    let n401 = resps.iter().filter(|r| r.status == 401).count();
    assert!(
        n429 >= 4 && n401 >= 1,
        "IP basina 2 esanli dogrulama: 429>=4 ve 401>=1 beklenir; durumlar: {:?}",
        resps.iter().map(|r| r.status).collect::<Vec<_>>()
    );
    assert!(
        resps
            .iter()
            .filter(|r| r.status == 429)
            .all(|r| r.has_header("retry-after")),
        "429 Retry-After tasimali"
    );
}

/// Madde 2: sayaç doğrulamadan ÖNCE; eşik aşıldıktan sonra Argon2 hesaplanmadan 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_counter_is_checked_before_verification_in_a_burst() {
    let env = start_env(
        "pre",
        "",
        "max_concurrent_per_ip = 100\nqueue_timeout_ms = 60000\nfail_min_ms = 100",
    );
    let t = Instant::now();
    let resps = flood_wrong_argon(env.http, 20).await;
    let total = t.elapsed();
    let n403 = resps.iter().filter(|r| r.status == 403).count();
    assert!(
        n403 >= 10,
        "esik (5) asilinca dogrulama yapilmadan 403 beklenir; durumlar: {:?}",
        resps.iter().map(|r| r.status).collect::<Vec<_>>()
    );
    let hashed = resps.iter().filter(|r| r.status == 401).count();
    assert!(
        hashed <= 6,
        "en fazla esik kadar dogrulama hesaplanir: {hashed}"
    );
    let bound = Duration::from_millis(100 + 2000) + Duration::from_millis(3 * env.hash_ms as u64);
    assert!(total < bound, "burst suresi {total:?} >= {bound:?}");
}

/// Madde 4: ≥6 hatalı deneme -> 403, araya başarılı giriş koymadan (HTTP/1.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_ban_after_six_failures_http1_without_success_in_between() {
    let env = start_env("ban1", "", "fail_min_ms = 0");
    let bad = basic_token("apruser", "YanlisParola");
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(
            http1(env.http, "/gizli/index.html", Some(&bad))
                .await
                .status,
        );
    }
    assert_eq!(statuses, vec![401, 401, 401, 401, 401, 403], "ban hatti");
    // Ban sonrası doğru kimlik bilgisi de 403 (IP banlı).
    let good = basic_token("apruser", APR1_PASS);
    let r = http1(env.http, "/gizli/index.html", Some(&good)).await;
    assert_eq!(r.status, 403, "banli IP dogru parolayla da 403: {}", r.head);
}

/// Madde 4: ban hattı HTTP/2 yolunda da çalışır (gerçek h2 istemci).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_ban_after_six_failures_http2() {
    let env = start_env("ban2", "", "fail_min_ms = 0");
    let mut client = h2_client(env.https).await;
    let bad = basic_token("apruser", "YanlisParola");
    let mut statuses = Vec::new();
    for _ in 0..6 {
        statuses.push(h2_get(&mut client, "/gizli/index.html", Some(&bad)).await);
    }
    assert_eq!(statuses, vec![401, 401, 401, 401, 401, 403], "h2 ban hatti");
}

/// Madde 2: başarıda sayaç sıfırlanır.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_success_resets_failure_counter() {
    let env = start_env("reset", "", "fail_min_ms = 0");
    let bad = basic_token("apruser", "YanlisParola");
    let good = basic_token("apruser", APR1_PASS);
    for _ in 0..4 {
        assert_eq!(
            http1(env.http, "/gizli/index.html", Some(&bad))
                .await
                .status,
            401
        );
    }
    assert_eq!(
        http1(env.http, "/gizli/index.html", Some(&good))
            .await
            .status,
        200
    );
    for i in 0..5 {
        let s = http1(env.http, "/gizli/index.html", Some(&bad))
            .await
            .status;
        assert_eq!(s, 401, "basari sonrasi {}. hata hala 401 olmali", i + 1);
    }
    assert_eq!(
        http1(env.http, "/gizli/index.html", Some(&bad))
            .await
            .status,
        403
    );
}

/// Madde 2: eşik `[vhost.auth]` içinden okunur (3 -> 4. deneme 403).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_threshold_is_read_from_vhost_auth_config() {
    let env = start_env("cfg", "", "max_failed_attempts = 3\nfail_min_ms = 0");
    let bad = basic_token("apruser", "YanlisParola");
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(
            http1(env.http, "/gizli/index.html", Some(&bad))
                .await
                .status,
        );
    }
    assert_eq!(statuses, vec![401, 401, 401, 403]);
}

/// Madde 3: kullanıcı numaralandırma kapalı; var/yok ve şemadan bağımsız süre.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_failure_time_is_equalized_for_known_and_unknown_users() {
    let env = start_env(
        "timing",
        "",
        "max_failed_attempts = 1000\nfail_min_ms = 250",
    );
    let known = basic_token("apruser", "YanlisParola");
    let unknown = basic_token("yokkullanici", "YanlisParola");
    let mut sum_known = Duration::ZERO;
    let mut sum_unknown = Duration::ZERO;
    let n = 20u32;
    for _ in 0..n {
        let a = http1(env.http, "/gizli/index.html", Some(&known)).await;
        let b = http1(env.http, "/gizli/index.html", Some(&unknown)).await;
        assert_eq!((a.status, b.status), (401, 401));
        sum_known += a.elapsed;
        sum_unknown += b.elapsed;
    }
    let (mk, mu) = (sum_known / n, sum_unknown / n);
    let diff = if mk > mu { mk - mu } else { mu - mk };
    assert!(
        diff < Duration::from_millis(50),
        "numaralandirma: bilinen {mk:?} / bilinmeyen {mu:?} farki {diff:?} >= 50 ms"
    );
    assert!(
        mk >= Duration::from_millis(240) && mu >= Duration::from_millis(240),
        "en az fail_min_ms (250) beklenir: {mk:?} / {mu:?}"
    );
}

/// Madde 5: büyük/küçük harf farkı korumayı atlatmaz (HTTP/1.1 ve HTTP/2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_path_case_variants_hit_the_same_protection() {
    let env = start_env("case", "", "");
    for p in [
        "/gizli/index.html",
        "/GIZLI/index.html",
        "/Gizli/INDEX.html",
    ] {
        let r = http1(env.http, p, None).await;
        assert_eq!(r.status, 401, "{p} korumaya girmeli: {}", r.head);
    }
    let mut c = h2_client(env.https).await;
    for p in ["/gizli/index.html", "/GIZLI/index.html"] {
        assert_eq!(h2_get(&mut c, p, None).await, 401, "h2 {p}");
    }
}

/// Madde 6: GERÇEK DoS ölçümü: 32 paralel yanlış parolalı istek altında bağımsız
/// statik isteğin p99 gecikmesi < 200 ms ve kimlik doğrulama gecikmesi sınırlı.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9h_dos_32_parallel_wrong_passwords_do_not_slow_static_requests() {
    let env = start_env(
        "dos",
        "",
        "max_failed_attempts = 100000\nmax_concurrent_per_ip = 1000\nqueue_timeout_ms = 500\nfail_min_ms = 100",
    );
    let port = env.http;
    let flood = tokio::spawn(async move { flood_wrong_argon(port, 32).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut lat = Vec::new();
    while !flood.is_finished() && lat.len() < 200 {
        let r = http1(env.http, "/acik.html", None).await;
        assert_eq!(r.status, 200, "statik: {}", r.head);
        lat.push(r.elapsed);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let resps = flood.await.expect("flood");
    assert!(lat.len() >= 10, "yeterli ornek toplanamadi: {}", lat.len());
    lat.sort();
    let p99 = percentile(&lat, 0.99);
    assert!(
        p99 < Duration::from_millis(200),
        "statik istek p99 = {p99:?} (>= 200 ms), ornek {}",
        lat.len()
    );
    let max_auth = resps.iter().map(|r| r.elapsed).max().unwrap_or_default();
    println!(
        "K9H-OLCUM dos32: statik p99={p99:?} (ornek {}), en yavas kimlik dogrulama={max_auth:?}, durumlar 503={} 429={} 401={} 403={}",
        lat.len(),
        resps.iter().filter(|r| r.status == 503).count(),
        resps.iter().filter(|r| r.status == 429).count(),
        resps.iter().filter(|r| r.status == 401).count(),
        resps.iter().filter(|r| r.status == 403).count()
    );
    let bound = Duration::from_millis(500 + 100 + 1500) + Duration::from_millis(env.hash_ms as u64);
    assert!(
        max_auth < bound,
        "kimlik dogrulama kuyrugu sinirsiz: en yavas {max_auth:?} >= {bound:?}"
    );
}

// ---------------------------------------------------------------------------
// R9b: bağımsız denetimden çıkan P1 bulgular
// ---------------------------------------------------------------------------

/// Bulgu 1: doğru parolalı tarayıcı (HTTP/1.1, 6 paralel bağlantı) hiçbir istekte 429 almamalı.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_correct_password_parallel_http1_all_200() {
    let env = start_env(
        "r9b_h1",
        "",
        "max_failed_attempts = 1000\nqueue_timeout_ms = 5000\nfail_min_ms = 100",
    );
    let tok = basic_token("argonuser", ARGON_PASS);
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let tok = tok.clone();
        let port = env.http;
        tasks.push(tokio::spawn(async move {
            http1(port, "/gizli/index.html", Some(&tok)).await
        }));
    }
    let mut statuses = Vec::new();
    for t in tasks {
        let r = t.await.expect("gorev");
        statuses.push(r.status);
    }
    assert!(
        statuses.iter().all(|s| *s == 200),
        "6 paralel dogru parolali istegin hepsi 200 olmali: {statuses:?}"
    );
}

/// Bulgu 1: HTTP/2 tek bağlantıda 8 eşzamanlı akış, doğru parola: hepsi 200.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_correct_password_parallel_http2_all_200() {
    let env = start_env(
        "r9b_h2",
        "",
        "max_failed_attempts = 1000\nqueue_timeout_ms = 5000\nfail_min_ms = 100",
    );
    let tok = basic_token("argonuser", ARGON_PASS);
    let client = h2_client(env.https).await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let tok = tok.clone();
        let mut c = client.clone();
        tasks.push(tokio::spawn(async move {
            h2_get(&mut c, "/gizli/index.html", Some(&tok)).await
        }));
    }
    let mut statuses = Vec::new();
    for t in tasks {
        statuses.push(t.await.expect("gorev"));
    }
    assert!(
        statuses.iter().all(|s| *s == 200),
        "8 eszamanli h2 akisinin hepsi 200 olmali: {statuses:?}"
    );
}

/// Bulgu 1: başarılı (kullanıcı, parola, özet) doğrulaması kısa süre önbellekten sunulur;
/// ısınmış istek Argon2'yi yeniden hesaplamaz (süre tek doğrulamanın altında kalır).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_successful_verification_is_cached_for_warm_requests() {
    let env = start_env(
        "r9b_cache",
        "",
        "max_failed_attempts = 1000\nqueue_timeout_ms = 5000\nfail_min_ms = 100",
    );
    let tok = basic_token("argonuser", ARGON_PASS);
    let first = http1(env.http, "/gizli/index.html", Some(&tok)).await;
    assert_eq!(first.status, 200, "ilk istek: {}", first.head);
    let mut warm = Vec::new();
    for _ in 0..7 {
        let r = http1(env.http, "/gizli/index.html", Some(&tok)).await;
        assert_eq!(r.status, 200, "isinmis istek: {}", r.head);
        warm.push(r.elapsed);
    }
    warm.sort();
    let median = warm[warm.len() / 2];
    assert!(
        median.as_millis() < env.hash_ms / 2,
        "onbellekli istek Argon2'yi tekrar hesaplamamali: medyan {median:?}, hash {} ms",
        env.hash_ms
    );
}

/// Bulgu 1: yanlış parola ASLA önbelleğe girmez/önbellekten geçmez; başarılı girişten sonra da 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_wrong_password_is_never_served_from_cache() {
    let env = start_env(
        "r9b_wrong",
        "",
        "max_failed_attempts = 1000\nqueue_timeout_ms = 5000\nfail_min_ms = 100",
    );
    let good = basic_token("argonuser", ARGON_PASS);
    assert_eq!(
        http1(env.http, "/gizli/index.html", Some(&good))
            .await
            .status,
        200
    );
    for (u, p) in [
        ("argonuser", "Yanlis1"),
        ("argonuser", ""),
        ("apruser", ARGON_PASS),
        ("argonuser", APR1_PASS),
    ] {
        let tok = basic_token(u, p);
        for _ in 0..2 {
            let r = http1(env.http, "/gizli/index.html", Some(&tok)).await;
            assert_eq!(r.status, 401, "{u}:{p} 401 olmali: {}", r.head);
            assert!(!r.head.contains("GIZLI_200"));
        }
    }
    assert_eq!(
        http1(env.http, "/gizli/index.html", Some(&good))
            .await
            .status,
        200,
        "dogru parola yanlis denemelerden sonra da calismali"
    );
}

/// Bulgu 1: htpasswd'de özet değişince önbellekteki başarı geçersiz olur (eski parola 401).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_cache_is_invalidated_when_stored_hash_changes() {
    let env = start_env(
        "r9b_inval",
        "",
        "max_failed_attempts = 1000\nqueue_timeout_ms = 5000\nfail_min_ms = 100",
    );
    let tok = basic_token("apruser", APR1_PASS);
    assert_eq!(
        http1(env.http, "/gizli/index.html", Some(&tok))
            .await
            .status,
        200
    );
    let new_hash = zmax_security::apr1_hash("YeniParola!", "k9salt99");
    std::fs::write(&env.htpasswd, format!("apruser:{new_hash}\n")).expect("htpasswd yaz");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let r = http1(env.http, "/gizli/index.html", Some(&tok)).await;
        if r.status == 401 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "ozet degisince eski parola 10 sn icinde 401 olmali (son durum {})",
            r.status
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let tok_new = basic_token("apruser", "YeniParola!");
    assert_eq!(
        http1(env.http, "/gizli/index.html", Some(&tok_new))
            .await
            .status,
        200
    );
}

/// Sahte upstream: her isteğe `UPSTREAM_SECRET` döner ve istek hedeflerini kaydeder
/// (gerçek bir upstream `..` yollarını kendisi çözüp korumalı içeriği sunabilir).
fn spawn_fake_upstream() -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("upstream portu");
    let port = listener.local_addr().expect("adres").port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let seen_t = Arc::clone(&seen);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for conn in listener.incoming() {
            let Ok(mut c) = conn else { continue };
            let seen_c = Arc::clone(&seen_t);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = c.read(&mut buf).unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                let target = text
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("")
                    .to_string();
                if let Ok(mut g) = seen_c.lock() {
                    g.push(target);
                }
                let body = "UPSTREAM_SECRET";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = c.write_all(resp.as_bytes());
            });
        }
    });
    (port, seen)
}

/// Bulgu 2: ACME muafiyeti `..` / `%2e%2e` ile korumalı yola kimlik doğrulamasız erişim sağlamaz
/// (ters vekil açık vhost: ham yol upstream'e gitseydi korumalı içerik sızardı).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_acme_exemption_cannot_bypass_auth_with_dot_dot() {
    let (up_port, seen) = spawn_fake_upstream();
    let env = start_env(
        "r9b_acme",
        "",
        &format!(
            "\n[vhost.security]\nwaf_enabled = false\n\n[vhost.proxy]\nenabled = true\nupstream = \"127.0.0.1:{up_port}\"\npath_prefix = \"/\"\n"
        ),
    );

    // Negatif kontrol: gerçek ACME belirteci kimlik doğrulamasız sunulmaya devam eder.
    let ok = http1(env.http, "/.well-known/acme-challenge/tok123", None).await;
    assert_eq!(ok.status, 200, "ACME muafiyeti korunmali: {}", ok.head);
    seen.lock().expect("kilit").clear();

    let bad = [
        "/.well-known/acme-challenge/../../gizli/index.html",
        "/.well-known/acme-challenge/%2e%2e/%2e%2e/gizli/index.html",
        "/.well-known/acme-challenge/%2E%2E/%2E%2E/gizli/index.html",
        "/.well-known/acme-challenge/..%2f..%2fgizli/index.html",
        "/.well-known/acme-challenge/..\\..\\gizli\\index.html",
        "/.well-known/acme-challenge/./../../gizli/index.html",
    ];
    for p in bad {
        let r = http1(env.http, p, None).await;
        assert!(
            r.status == 401 || r.status == 403,
            "{p}: 401/403 beklenir, gelen {} ({})",
            r.status,
            r.head.lines().next().unwrap_or("")
        );
        assert!(
            !r.head.contains("UPSTREAM_SECRET") && !r.head.contains("GIZLI_200"),
            "{p}: korumali icerik sizdi"
        );
    }
    let mut c = h2_client(env.https).await;
    for p in &bad[..2] {
        let st = h2_get(&mut c, p, None).await;
        assert!(st == 401 || st == 403, "h2 {p}: {st}");
    }
    let leaked = seen.lock().expect("kilit").clone();
    assert!(
        leaked.is_empty(),
        "kimlik dogrulamasiz `..` istekleri upstream'e ulasmamali: {leaked:?}"
    );
    assert_eq!(
        h2_get(&mut c, "/.well-known/acme-challenge/tok123", None).await,
        200,
        "h2 ACME muafiyeti korunmali"
    );
}

/// Bulgu 3 (Windows kaynaklı): sondaki nokta/boşluk ve 8.3 kısa ad korumayı atlatmaz.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn k9r_windows_trailing_dot_space_and_short_name_require_auth() {
    let env = start_env("r9b_win", "", "");
    for p in [
        "/gizli./index.html",
        "/gizli../index.html",
        "/gizli%2e/index.html",
        "/gizli%20/index.html",
        "/gizli./",
        "/GIZLI./index.html",
        "/GIZLI~1/index.html",
        "/gizli~1/index.html",
    ] {
        let r = http1(env.http, p, None).await;
        assert_eq!(r.status, 401, "{p}: 401 beklenir ({})", r.head);
        assert!(!r.head.contains("GIZLI_200"), "{p}: icerik sizdi");
    }
    let mut c = h2_client(env.https).await;
    for p in ["/gizli./index.html", "/GIZLI~1/index.html"] {
        assert_eq!(h2_get(&mut c, p, None).await, 401, "h2 {p}");
    }
    // Negatif kontrol: korumasız yollar etkilenmez.
    assert_eq!(http1(env.http, "/acik.html", None).await.status, 200);
    let other = http1(env.http, "/gizlix/index.html", None).await;
    assert_ne!(other.status, 401, "yakin adli korumasiz yol 401 olmamali");
}
