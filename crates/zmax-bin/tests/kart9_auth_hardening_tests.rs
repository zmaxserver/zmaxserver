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

    let child = spawn_zmax_and_wait_ready(&base, &conf_path);
    Env {
        _guard: ChildGuard {
            child,
            temp_dir: base,
        },
        http,
        https,
        hash_ms,
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
