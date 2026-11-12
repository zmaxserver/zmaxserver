use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static TEST_SEQ: AtomicUsize = AtomicUsize::new(100);

struct ServerGuard {
    child: Option<Child>,
    temp_dir: PathBuf,
}

impl ServerGuard {
    fn new(child: Child, temp_dir: PathBuf) -> Self {
        Self {
            child: Some(child),
            temp_dir,
        }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("boş port ayrılmalı");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

fn write_test_workspace(
    base: &Path,
    http_port: u16,
    api_port: u16,
) -> PathBuf {
    let conf_dir = base.join("conf");
    let vhosts_dir = conf_dir.join("vhosts");
    let admin_dir = base.join("admin");
    let logs_dir = base.join("logs");
    let cache_dir = base.join("cachedata");
    let site1_dir = base.join("www").join("site1");
    let site1_sub = site1_dir.join("sub");
    let site2_dir = base.join("www").join("site2");

    for d in [
        &conf_dir,
        &vhosts_dir,
        &admin_dir,
        &logs_dir,
        &cache_dir,
        &site1_dir,
        &site1_sub,
        &site2_dir,
    ] {
        fs::create_dir_all(d).expect("alt dizinler oluşturulmalı");
    }

    fs::write(admin_dir.join("index.html"), b"admin").expect("admin index yazılmalı");
    fs::write(site1_dir.join("page1.html"), b"site1 page1 content").expect("site1 page1");
    fs::write(site1_sub.join("page2.html"), b"site1 sub page2 content").expect("site1 page2");
    fs::write(site1_dir.join("common.html"), b"site1 common content").expect("site1 common");
    fs::write(site2_dir.join("page1.html"), b"site2 page1 content").expect("site2 page1");
    fs::write(site2_dir.join("common.html"), b"site2 common content").expect("site2 common");

    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax-Cache1-Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http_port}
backlog = 128
tcp_nodelay = true
reuse_port = false

[listeners.https]
enabled = false

[listeners.admin]
enabled = false

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api_port}
require_token = false

[cache]
enabled = true
disk_cache_dir = "cachedata"
default_ttl_seconds = 300

[logging]
access_log = "logs/access.log"
error_log = "logs/error.log"
log_level = "info"

[vhosts_dir]
path = "conf/vhosts"
"#
    );
    let conf_path = conf_dir.join("zmax.toml");
    fs::write(&conf_path, zmax_toml).expect("zmax.toml yazılmalı");

    let vhost1 = r#"[vhost]
name = "site1.test"
document_root = "www/site1"
index_files = ["index.html"]

[vhost.cache]
enabled = true
expire = 300

[vhost.static]
sendfile = false
"#;
    fs::write(vhosts_dir.join("site1.test.toml"), vhost1).expect("site1 vhost");

    let vhost2 = r#"[vhost]
name = "site2.test"
document_root = "www/site2"
index_files = ["index.html"]

[vhost.cache]
enabled = true
expire = 300

[vhost.static]
sendfile = false
"#;
    fs::write(vhosts_dir.join("site2.test.toml"), vhost2).expect("site2 vhost");

    conf_path
}

fn start_server(prefix: &str) -> (ServerGuard, SocketAddr, SocketAddr) {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("zmax_c1_{}_{}_{}", prefix, std::process::id(), seq));
    let _ = fs::remove_dir_all(&base);

    let http_port = pick_free_port();
    let api_port = pick_free_port();
    let conf_path = write_test_workspace(&base, http_port, api_port);

    let mut child = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", &base)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("zmax çalıştırılmalı");

    let stdout = child.stdout.take().expect("stdout");
    let stderr = child.stderr.take().expect("stderr");
    let guard = ServerGuard::new(child, base);

    let mut ready = false;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    while reader.read_line(&mut line).unwrap_or(0) > 0 {
        if line.contains("sifir port cakismasiyla hazir") {
            ready = true;
            break;
        }
        line.clear();
    }
    if !ready {
        let mut err_buf = String::new();
        let _ = BufReader::new(stderr).read_to_string(&mut err_buf);
        panic!("zmax hazır olamadı: son satır '{}', stderr: '{}'", line, err_buf);
    }

    let http_addr: SocketAddr = format!("127.0.0.1:{}", http_port).parse().unwrap();
    let api_addr: SocketAddr = format!("127.0.0.1:{}", api_port).parse().unwrap();

    (guard, http_addr, api_addr)
}

fn send_http_request(addr: SocketAddr, req_raw: &[u8]) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .expect("HTTP sunucuya bağlanılmalı");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(req_raw).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP header ayracı bulunmalı");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();
    (head, body)
}

fn send_api_json_post(addr: SocketAddr, path: &str, json_body: &str) -> (u16, serde_json::Value) {
    let body_bytes = json_body.as_bytes();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        body_bytes.len(),
        json_body
    );
    let (head, body) = send_http_request(addr, req.as_bytes());
    let status_code: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let parsed: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
    (status_code, parsed)
}

#[test]
fn domain_purge_clears_entries() {
    let (_guard, http_addr, api_addr) = start_server("dom");

    // 1. site1.test /page1.html -> MISS -> HIT
    let (h1_miss, b1_miss) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h1_miss.starts_with("HTTP/1.1 200 OK"), "{h1_miss}");
    assert!(h1_miss.contains("X-Cache: MISS"), "{h1_miss}");
    assert_eq!(&b1_miss, b"site1 page1 content");

    let (h1_hit, b1_hit) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h1_hit.contains("X-Cache: HIT"), "{h1_hit}");
    assert_eq!(&b1_hit, b"site1 page1 content");

    // 2. site1.test /sub/page2.html -> MISS -> HIT
    let (h2_miss, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h2_miss.contains("X-Cache: MISS"), "{h2_miss}");
    let (h2_hit, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h2_hit.contains("X-Cache: HIT"), "{h2_hit}");

    // 3. site2.test /page1.html -> MISS -> HIT
    let (hs2_miss, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(hs2_miss.contains("X-Cache: MISS"), "{hs2_miss}");
    let (hs2_hit, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(hs2_hit.contains("X-Cache: HIT"), "{hs2_hit}");

    // 4. Domain purge çağrısı: POST /api/v1/cache/purge {"domain":"site1.test"}
    let (status, body) = send_api_json_post(
        api_addr,
        "/api/v1/cache/purge",
        r#"{"domain":"site1.test"}"#,
    );
    assert_eq!(status, 200, "Domain purge 200 dönmeli: {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["scope"], "domain");
    let purged = body["purged"].as_u64().expect("purged sayısal olmalı");
    assert!(
        purged >= 2,
        "site1.test altındaki en az 2 nesne temizlenmeliydi, ancak {purged} döndü"
    );

    // 5. site1.test altındakiler tekrar MISS olmalı
    let (h1_after, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h1_after.contains("X-Cache: MISS"), "{h1_after}");

    let (h2_after, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h2_after.contains("X-Cache: MISS"), "{h2_after}");

    // 6. site2.test korunmuş olmalı (hâlâ HIT)
    let (hs2_after, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        hs2_after.contains("X-Cache: HIT"),
        "site2.test domain purge işleminden etkilenmemeliydi: {hs2_after}"
    );
}

#[test]
fn uri_purge_clears_entry() {
    let (_guard, http_addr, api_addr) = start_server("uri");

    // 1. Her iki sitede de /common.html önbelleğe alınsın
    let _ = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    let (h_c1_hit, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c1_hit.contains("X-Cache: HIT"), "{h_c1_hit}");

    let _ = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    let (h_c2_hit, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c2_hit.contains("X-Cache: HIT"), "{h_c2_hit}");

    // Farklı bir URI /page1.html de site2'de önbelleğe alınsın
    let _ = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    let (h_s2_hit, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_s2_hit.contains("X-Cache: HIT"), "{h_s2_hit}");

    // 2. Ham URI purge çağrısı: POST /api/v1/cache/purge {"uri":"/common.html"}
    let (status, body) = send_api_json_post(
        api_addr,
        "/api/v1/cache/purge",
        r#"{"uri":"/common.html"}"#,
    );
    assert_eq!(status, 200, "URI purge 200 dönmeli: {body}");
    assert_eq!(body["ok"], true);
    assert_eq!(body["scope"], "uri");
    let purged = body["purged"].as_u64().expect("purged sayısal olmalı");
    assert!(
        purged >= 2,
        "Tüm vHost'lardaki /common.html temizlenmeliydi, ancak {purged} döndü"
    );

    // 3. /common.html her iki sitede de MISS olmalı
    let (h_c1_after, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c1_after.contains("X-Cache: MISS"), "{h_c1_after}");

    let (h_c2_after, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c2_after.contains("X-Cache: MISS"), "{h_c2_after}");

    // 4. Ancak farklı URI /page1.html korunmuş olmalı (hâlâ HIT)
    let (h_s2_preserved, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        h_s2_preserved.contains("X-Cache: HIT"),
        "Farklı URI /page1.html korunmalıydı: {h_s2_preserved}"
    );
}

#[test]
fn no_cache_header_bypasses_cache() {
    let (_guard, http_addr, _api_addr) = start_server("nocache");

    // 1. X-LiteSpeed-Cache-Control: no-cache başlığı ile istek -> X-Cache: BYPASS dönmeli
    let (h_lsc_bypass, b_lsc) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nX-LiteSpeed-Cache-Control: no-cache\r\nConnection: close\r\n\r\n",
    );
    assert!(h_lsc_bypass.starts_with("HTTP/1.1 200 OK"), "{h_lsc_bypass}");
    assert!(h_lsc_bypass.contains("X-Cache: BYPASS"), "X-LiteSpeed-Cache-Control: no-cache durumunda BYPASS dönmeli: {h_lsc_bypass}");
    assert_eq!(&b_lsc, b"site1 page1 content");

    // 2. Cache-Control: no-cache başlığı ile istek -> X-Cache: BYPASS dönmeli
    let (h_cc_bypass, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
    );
    assert!(h_cc_bypass.starts_with("HTTP/1.1 200 OK"), "{h_cc_bypass}");
    assert!(h_cc_bypass.contains("X-Cache: BYPASS"), "Cache-Control: no-cache durumunda BYPASS dönmeli: {h_cc_bypass}");

    // 3. Normal istek (bypass başlığı olmadan) -> Önceki istekler önbelleğe yazılmadığı için MISS dönmeli
    let (h_norm_miss, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_norm_miss.contains("X-Cache: MISS"), "Önceki istekler bypass olduğu için bu istek MISS olmalı: {h_norm_miss}");

    // 4. İkinci normal istek -> Artık HIT olmalı
    let (h_norm_hit, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_norm_hit.contains("X-Cache: HIT"), "İkinci normal istek HIT olmalı: {h_norm_hit}");

    // 5. Önbellekte varken X-LiteSpeed-Cache-Control: no-cache gönderilirse yine BYPASS dönmeli
    let (h_force_bypass, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nX-LiteSpeed-Cache-Control: no-cache\r\nConnection: close\r\n\r\n",
    );
    assert!(h_force_bypass.contains("X-Cache: BYPASS"), "Önbellekte nesne olsa dahi bypass başlığıyla BYPASS dönmeli: {h_force_bypass}");
}

#[test]
fn private_header_bypasses_cache() {
    let (_guard, http_addr, _api_addr) = start_server("priv");

    // 1. X-LiteSpeed-Cache-Control: private başlığı ile istek -> X-Cache: BYPASS dönmeli
    let (h_priv_bypass, b_priv) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nX-LiteSpeed-Cache-Control: private\r\nConnection: close\r\n\r\n",
    );
    assert!(h_priv_bypass.starts_with("HTTP/1.1 200 OK"), "{h_priv_bypass}");
    assert!(h_priv_bypass.contains("X-Cache: BYPASS"), "X-LiteSpeed-Cache-Control: private durumunda BYPASS dönmeli: {h_priv_bypass}");
    assert_eq!(&b_priv, b"site1 sub page2 content");

    // 2. Cache-Control: private, no-store başlığı ile istek -> X-Cache: BYPASS dönmeli
    let (h_cc_priv, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nCache-Control: private, no-store\r\nConnection: close\r\n\r\n",
    );
    assert!(h_cc_priv.starts_with("HTTP/1.1 200 OK"), "{h_cc_priv}");
    assert!(h_cc_priv.contains("X-Cache: BYPASS"), "Cache-Control: private, no-store durumunda BYPASS dönmeli: {h_cc_priv}");

    // 3. X-LiteSpeed-Cache-Control: no-store başlığı ile istek -> X-Cache: BYPASS dönmeli
    let (h_lsc_nostore, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nX-LiteSpeed-Cache-Control: no-store\r\nConnection: close\r\n\r\n",
    );
    assert!(h_lsc_nostore.starts_with("HTTP/1.1 200 OK"), "{h_lsc_nostore}");
    assert!(h_lsc_nostore.contains("X-Cache: BYPASS"), "X-LiteSpeed-Cache-Control: no-store durumunda BYPASS dönmeli: {h_lsc_nostore}");

    // 4. Normal istek (bypass başlığı olmadan) -> Önceki istekler önbelleğe yazılmadığı için MISS dönmeli
    let (h_norm_miss, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_norm_miss.contains("X-Cache: MISS"), "Önceki istekler private bypass olduğu için bu istek MISS olmalı: {h_norm_miss}");

    // 5. İkinci normal istek -> HIT olmalı
    let (h_norm_hit, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_norm_hit.contains("X-Cache: HIT"), "İkinci normal istek HIT olmalı: {h_norm_hit}");

    // 6. Önbellekte varken X-LiteSpeed-Cache-Control: private gönderilirse yine BYPASS dönmeli
    let (h_force_priv, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nX-LiteSpeed-Cache-Control: private\r\nConnection: close\r\n\r\n",
    );
    assert!(h_force_priv.contains("X-Cache: BYPASS"), "Önbellekte nesne olsa dahi private başlığıyla BYPASS dönmeli: {h_force_priv}");
}
