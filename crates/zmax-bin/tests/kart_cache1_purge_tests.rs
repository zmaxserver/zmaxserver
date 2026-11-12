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
fn test_cache_domain_and_raw_uri_purge_pipeline_integration() {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("zmax_cache1_it_{}_{}", std::process::id(), seq));
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
    let _guard = ServerGuard::new(child, base.clone());

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

    // 1. site1.test /page1.html -> MISS -> sonra HIT
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

    // 2. site1.test /sub/page2.html -> MISS -> sonra HIT
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

    // 3. site2.test /page1.html -> MISS -> sonra HIT
    let (h_s2_miss, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_s2_miss.contains("X-Cache: MISS"), "{h_s2_miss}");
    let (h_s2_hit, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_s2_hit.contains("X-Cache: HIT"), "{h_s2_hit}");

    // =========================================================================
    // 4. Domain Purge Testi: POST /api/v1/cache/purge {"domain": "site1.test"}
    // =========================================================================
    let (st_dom, body_dom) = send_api_json_post(
        api_addr,
        "/api/v1/cache/purge",
        r#"{"domain":"site1.test"}"#,
    );
    assert_eq!(st_dom, 200, "Domain purge 200 dönmeli: {body_dom}");
    assert_eq!(body_dom["ok"], true);
    assert_eq!(body_dom["scope"], "domain");
    let purged_dom_cnt = body_dom["purged"].as_u64().expect("purged sayısal olmalı");
    assert!(
        purged_dom_cnt >= 2,
        "site1.test altındaki en az 2 nesne temizlenmeliydi, ancak {purged_dom_cnt} döndü"
    );

    // site1.test altındakiler tekrar MISS olmalı
    let (h1_after_purge, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h1_after_purge.contains("X-Cache: MISS"), "{h1_after_purge}");

    let (h2_after_purge, _) = send_http_request(
        http_addr,
        b"GET /sub/page2.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h2_after_purge.contains("X-Cache: MISS"), "{h2_after_purge}");

    // site2.test korunmuş olmalı (HIT)
    let (h_s2_preserved, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        h_s2_preserved.contains("X-Cache: HIT"),
        "site2.test domain purge işleminden etkilenmemeliydi: {h_s2_preserved}"
    );

    // =========================================================================
    // 5. Ham URI Purge Testi: POST /api/v1/cache/purge {"uri": "/common.html"}
    // =========================================================================
    // Her iki sitede de /common.html önbelleğe alınsın
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

    // Ham URI purge çağrısı
    let (st_uri, body_uri) = send_api_json_post(
        api_addr,
        "/api/v1/cache/purge",
        r#"{"uri":"/common.html"}"#,
    );
    assert_eq!(st_uri, 200, "URI purge 200 dönmeli: {body_uri}");
    assert_eq!(body_uri["ok"], true);
    assert_eq!(body_uri["scope"], "uri");
    let purged_uri_cnt = body_uri["purged"].as_u64().expect("purged sayısal olmalı");
    assert!(
        purged_uri_cnt >= 2,
        "Tüm vHost'lardaki /common.html temizlenmeliydi, ancak {purged_uri_cnt} döndü"
    );

    // Artık her iki sitede de /common.html MISS olmalı
    let (h_c1_miss, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c1_miss.contains("X-Cache: MISS"), "{h_c1_miss}");

    let (h_c2_miss, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c2_miss.contains("X-Cache: MISS"), "{h_c2_miss}");

    // Ancak site2.test /page1.html hâlâ HIT olmalı (korundu)
    let (h_s2_still_hit, _) = send_http_request(
        http_addr,
        b"GET /page1.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        h_s2_still_hit.contains("X-Cache: HIT"),
        "Farklı URI /page1.html korunmalıydı: {h_s2_still_hit}"
    );

    // =========================================================================
    // 6. Domain + URI Purge Testi: POST /api/v1/cache/purge {"domain":"site1.test","uri":"/common.html"}
    // =========================================================================
    // Yeniden HIT durumuna getir
    let _ = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    let (h_c1_hit2, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c1_hit2.contains("X-Cache: HIT"), "{h_c1_hit2}");

    let _ = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    let (h_c2_hit2, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c2_hit2.contains("X-Cache: HIT"), "{h_c2_hit2}");

    let (st_du, body_du) = send_api_json_post(
        api_addr,
        "/api/v1/cache/purge",
        r#"{"domain":"site1.test","uri":"/common.html"}"#,
    );
    assert_eq!(st_du, 200, "Domain+URI purge 200 dönmeli: {body_du}");
    assert_eq!(body_du["ok"], true);
    assert_eq!(body_du["scope"], "domain_uri");
    assert_eq!(body_du["purged"], 1);

    // Yalnız site1 /common.html silinmiş olmalı
    let (h_c1_after_du, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site1.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_c1_after_du.contains("X-Cache: MISS"), "{h_c1_after_du}");

    let (h_c2_after_du, _) = send_http_request(
        http_addr,
        b"GET /common.html HTTP/1.1\r\nHost: site2.test\r\nConnection: close\r\n\r\n",
    );
    assert!(
        h_c2_after_du.contains("X-Cache: HIT"),
        "site2 altındaki /common.html korunmalıydı: {h_c2_after_du}"
    );
}
