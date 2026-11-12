use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static PORT_LOCK: Mutex<()> = Mutex::new(());
static TEST_SEQ: AtomicUsize = AtomicUsize::new(1);

/// Test sürecinde bir kez bind(:0) ile ayrılan dinamik portlar (testler PORT_LOCK ile sıralı çalışır).
struct TestPorts {
    http: u16,
    fcgi: u16,
    spare_https: u16,
    api: u16,
}

fn ports() -> &'static TestPorts {
    static PORTS: OnceLock<TestPorts> = OnceLock::new();
    PORTS.get_or_init(|| {
        let listeners: Vec<TcpListener> = (0..4)
            .map(|_| TcpListener::bind("127.0.0.1:0").expect("bos port ayrilmali"))
            .collect();
        let p: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().expect("yerel adres").port())
            .collect();
        TestPorts {
            http: p[0],
            fcgi: p[1],
            spare_https: p[2],
            api: p[3],
        }
    })
}

struct TestEnv {
    base_dir: PathBuf,
    conf_path: PathBuf,
    vhost_a_root: PathBuf,
    vhost_b_root: PathBuf,
    cache_dir: PathBuf,
}

impl TestEnv {
    fn new(label: &str, php_enabled: bool) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let base_dir = std::env::temp_dir().join(format!(
            "zmax_cache_it_{}_{}_{}_{}",
            label,
            std::process::id(),
            seq,
            nanos
        ));

        let conf_dir = base_dir.join("conf");
        let vhosts_dir = conf_dir.join("vhosts");
        let vhost_a_root = base_dir.join("www").join("vhost-a");
        let vhost_b_root = base_dir.join("www").join("vhost-b");
        let default_www = base_dir.join("www").join("html");
        let cache_dir = base_dir.join("cachedata");
        let logs_dir = base_dir.join("logs");
        let admin_dir = base_dir.join("admin");

        for dir in [
            &conf_dir,
            &vhosts_dir,
            &vhost_a_root,
            &vhost_b_root,
            &default_www,
            &cache_dir,
            &logs_dir,
            &admin_dir,
        ] {
            fs::create_dir_all(dir).expect("Test alt dizini olusturulamadi");
        }

        fs::write(admin_dir.join("index.html"), "<html>admin</html>")
            .expect("admin index yazilamadi");
        fs::write(default_www.join("index.html"), "<html>default</html>")
            .expect("varsayilan index yazilamadi");

        let conf_path = conf_dir.join("zmax.toml");
        let (http_port, spare_https_port, api_port) =
            (ports().http, ports().spare_https, ports().api);
        let zmax_toml = format!(
            r#"[server]
server_name = "ZMax/CacheTest"
workers = 2
reuseport_workers = false
graceful_shutdown_secs = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http_port}
backlog = 512
tcp_nodelay = true
reuse_port = false

[listeners.https]
enabled = false
address = "127.0.0.1"
port = {spare_https_port}
ssl = false

[listeners.admin]
enabled = false
address = "127.0.0.1"
port = 19485
document_root = "admin"
require_token = false
token = ""

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api_port}
require_token = false
token = ""
cors_allow_origin = "*"

[cache]
enabled = true
memory_cache_mb = 16
disk_cache_dir = "cachedata"
default_ttl_seconds = 120
purge_key_header = "X-ZMax-Purge-Key"
stale_while_revalidate_sec = 0

[security]
slowloris_header_timeout_sec = 5
slowloris_body_timeout_sec = 10
keep_alive_timeout_sec = 5
rate_limit_enabled = false
rate_limit_per_minute = 2000
block_path_traversal = true
max_body_size_mb = 16
max_header_size_kb = 64

[logging]
access_log = "logs/access.log"
error_log = "logs/error.log"
log_level = "info"
batch_flush_ms = 50
batch_buffer_kb = 16
add_request_id = false

[vhosts_dir]
path = "conf/vhosts"
"#
        );
        fs::write(&conf_path, zmax_toml).expect("zmax.toml yazilamadi");

        let php_upstream = format!("127.0.0.1:{}", ports().fcgi);
        let write_vhost = |file: &str, name: &str, doc_root: &str| {
            let content = format!(
                r#"[vhost]
name = "{name}"
aliases = []
document_root = "{doc_root}"
index_files = ["index.html", "index.php"]

[vhost.cache]
enabled = true
expire = 120

[vhost.php]
enabled = {php_enabled}
sapi = "fastcgi"
upstream = "{php_upstream}"
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
"#
            );
            fs::write(vhosts_dir.join(file), content).expect("vhost toml yazilamadi");
        };

        write_vhost("01-vhost-a.toml", "vhost-a.test", "www/vhost-a");
        write_vhost("02-vhost-b.toml", "vhost-b.test", "www/vhost-b");

        Self {
            base_dir,
            conf_path,
            vhost_a_root,
            vhost_b_root,
            cache_dir,
        }
    }

    fn count_zcache_files(&self) -> usize {
        fs::read_dir(&self.cache_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("zcache"))
                    .count()
            })
            .unwrap_or(0)
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base_dir);
    }
}

struct ZMaxServerGuard {
    child: Child,
    stdout_thread: Option<JoinHandle<()>>,
    stderr_thread: Option<JoinHandle<()>>,
    _stderr_lines: Arc<Mutex<Vec<String>>>,
}

impl ZMaxServerGuard {
    fn start(env: &TestEnv) -> Self {
        let bin = env!("CARGO_BIN_EXE_zmax");
        let mut child = Command::new(bin)
            .env("ZMAX_HOME", &env.base_dir)
            .arg("-c")
            .arg(&env.conf_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("zmax sureci baslatilamadi");

        let stdout = child.stdout.take().expect("stdout pipe alinamadi");
        let stderr = child.stderr.take().expect("stderr pipe alinamadi");

        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines_bg = Arc::clone(&stderr_lines);
        let stderr_thread = std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(mut buf) = stderr_lines_bg.lock() {
                    buf.push(line);
                }
            }
        });

        let mut stdout_reader = BufReader::new(stdout);
        let mut seen_stdout = Vec::new();
        let mut ready = false;
        let mut line = String::new();
        while let Ok(n) = stdout_reader.read_line(&mut line) {
            if n == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
            let is_ready = trimmed.contains("hazir!");
            seen_stdout.push(trimmed);
            line.clear();
            if is_ready {
                ready = true;
                break;
            }
        }

        let stdout_thread = std::thread::spawn(move || {
            let mut sink = String::new();
            while let Ok(n) = stdout_reader.read_line(&mut sink) {
                if n == 0 {
                    break;
                }
                sink.clear();
            }
        });

        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            let err_dump = stderr_lines
                .lock()
                .map(|v| v.join("\n"))
                .unwrap_or_default();
            panic!(
                "zmax hazir sinyali alinamadan sonlandi.\nSTDOUT:\n{}\nSTDERR:\n{}",
                seen_stdout.join("\n"),
                err_dump
            );
        }

        Self {
            child,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            _stderr_lines: stderr_lines,
        }
    }
}

impl Drop for ZMaxServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(t) = self.stdout_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.stderr_thread.take() {
            let _ = t.join();
        }
    }
}

#[derive(Debug)]
struct HttpResp {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResp {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn body_str(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn send_http(
    port: u16,
    host: &str,
    method: &str,
    target: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResp {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("TCP baglanti hatasi ({}): {}", addr, e));
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nConnection: close\r\n"
    );
    let mut has_content_len = false;
    for (k, v) in extra_headers {
        if k.eq_ignore_ascii_case("content-length") {
            has_content_len = true;
        }
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() && !has_content_len {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .expect("HTTP istek basligi yazilamadi");
    if !body.is_empty() {
        stream.write_all(body).expect("HTTP govde yazilamadi");
    }
    let _ = stream.flush();

    let mut raw = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    let head_end;
    loop {
        let n = stream.read(&mut buf).expect("HTTP yanit okunamadi");
        if n == 0 {
            panic!(
                "Sunucu HTTP basliklari tamamlanmadan baglantiyi kapatti: {:?}",
                String::from_utf8_lossy(&raw)
            );
        }
        raw.extend_from_slice(&buf[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            head_end = pos + 4;
            break;
        }
    }

    let head_text = std::str::from_utf8(&raw[..head_end - 4]).expect("Gecersiz UTF-8 HTTP basligi");
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().expect("Bos HTTP durum satiri");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("Gecersiz HTTP durum satiri: {}", status_line));

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

    let mut body_out = raw[head_end..].to_vec();
    if method.eq_ignore_ascii_case("HEAD") {
        body_out.clear();
    } else if let Some(expected_len) = content_length {
        if body_out.len() < expected_len {
            let remaining = expected_len - body_out.len();
            let old_len = body_out.len();
            body_out.resize(old_len + remaining, 0);
            stream
                .read_exact(&mut body_out[old_len..])
                .expect("HTTP Content-Length govdesi eksik");
        } else {
            body_out.truncate(expected_len);
        }
    } else {
        stream
            .read_to_end(&mut body_out)
            .expect("HTTP govde sonu okunamadi");
    }

    HttpResp {
        status,
        headers,
        body: body_out,
    }
}

fn post_cache_purge(json_body: &str) -> serde_json::Value {
    let resp = send_http(
        ports().api,
        "127.0.0.1",
        "POST",
        "/api/v1/cache/purge",
        &[("Content-Type", "application/json")],
        json_body.as_bytes(),
    );
    assert_eq!(
        resp.status,
        200,
        "Purge API 200 donmedi ({}): {}",
        resp.status,
        resp.body_str()
    );
    serde_json::from_slice(&resp.body)
        .unwrap_or_else(|e| panic!("Purge API gecersiz JSON dondu ({}): {}", e, resp.body_str()))
}

const FCGI_VERSION_1: u8 = 1;
const FCGI_END_REQUEST: u8 = 3;
const FCGI_PARAMS: u8 = 4;
const FCGI_STDIN: u8 = 5;
const FCGI_STDOUT: u8 = 6;

fn decode_fcgi_nv_pairs(mut stream: &[u8]) -> HashMap<String, String> {
    fn read_len(buf: &mut &[u8]) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }
        if buf[0] & 0x80 != 0 {
            if buf.len() < 4 {
                return None;
            }
            let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) & 0x7FFF_FFFF;
            *buf = &buf[4..];
            Some(raw as usize)
        } else {
            let len = buf[0] as usize;
            *buf = &buf[1..];
            Some(len)
        }
    }

    let mut map = HashMap::new();
    while !stream.is_empty() {
        let Some(k_len) = read_len(&mut stream) else {
            break;
        };
        let Some(v_len) = read_len(&mut stream) else {
            break;
        };
        if stream.len() < k_len + v_len {
            break;
        }
        let key = String::from_utf8_lossy(&stream[..k_len]).into_owned();
        let val = String::from_utf8_lossy(&stream[k_len..k_len + v_len]).into_owned();
        stream = &stream[k_len + v_len..];
        map.insert(key, val);
    }
    map
}

fn write_fcgi_record(stream: &mut TcpStream, rec_type: u8, req_id: u16, data: &[u8]) {
    let hdr = [
        FCGI_VERSION_1,
        rec_type,
        (req_id >> 8) as u8,
        (req_id & 0xFF) as u8,
        (data.len() >> 8) as u8,
        (data.len() & 0xFF) as u8,
        0,
        0,
    ];
    let _ = stream.write_all(&hdr);
    if !data.is_empty() {
        let _ = stream.write_all(data);
    }
}

struct MockFastCgiServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    hits: Arc<AtomicUsize>,
    handle: Option<JoinHandle<()>>,
}

impl MockFastCgiServer {
    fn start(port: u16) -> Self {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr)
            .unwrap_or_else(|e| panic!("Mock FastCGI portu ({}) baglanamadi: {}", addr, e));
        let stop = Arc::new(AtomicBool::new(false));
        let hits = Arc::new(AtomicUsize::new(0));

        let stop_bg = Arc::clone(&stop);
        let hits_bg = Arc::clone(&hits);

        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = conn else {
                    continue;
                };
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }

                let mut params_buf = Vec::new();
                let mut hdr = [0u8; 8];

                loop {
                    if stream.read_exact(&mut hdr).is_err() {
                        break;
                    }
                    let rec_type = hdr[1];
                    let req_id = u16::from_be_bytes([hdr[2], hdr[3]]);
                    let content_len = u16::from_be_bytes([hdr[4], hdr[5]]) as usize;
                    let padding_len = hdr[6] as usize;

                    let mut content = vec![0u8; content_len];
                    if content_len > 0 && stream.read_exact(&mut content).is_err() {
                        break;
                    }
                    if padding_len > 0 {
                        let mut pad = vec![0u8; padding_len];
                        if stream.read_exact(&mut pad).is_err() {
                            break;
                        }
                    }

                    if rec_type == FCGI_PARAMS && !content.is_empty() {
                        params_buf.extend_from_slice(&content);
                    } else if rec_type == FCGI_STDIN && content_len == 0 {
                        let params = decode_fcgi_nv_pairs(&params_buf);
                        let host = params
                            .get("HTTP_HOST")
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        let uri = params
                            .get("REQUEST_URI")
                            .or_else(|| params.get("SCRIPT_NAME"))
                            .cloned()
                            .unwrap_or_else(|| "/".to_string());

                        let seq = hits_bg.fetch_add(1, Ordering::SeqCst) + 1;
                        let cgi_raw = if uri.starts_with("/nocache.php") {
                            format!(
                                "Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-cache, no-store\r\n\r\nhost={};uri={};hit={}",
                                host, uri, seq
                            )
                        } else if uri.starts_with("/lscache_nocache.php") {
                            format!(
                                "Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nX-LiteSpeed-Cache-Control: no-cache\r\n\r\nhost={};uri={};hit={}",
                                host, uri, seq
                            )
                        } else if uri.starts_with("/lscache_tag.php") {
                            format!(
                                "Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nX-LiteSpeed-Cache-Control: public, max-age=120\r\nX-LiteSpeed-Tag: post:42, cat:7\r\nX-LiteSpeed-Purge: public, post:99\r\n\r\nhost={};uri={};hit={}",
                                host, uri, seq
                            )
                        } else {
                            format!(
                                "Status: 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhost={};uri={};hit={}",
                                host, uri, seq
                            )
                        };

                        for chunk in cgi_raw.as_bytes().chunks(65_535) {
                            write_fcgi_record(&mut stream, FCGI_STDOUT, req_id, chunk);
                        }
                        write_fcgi_record(&mut stream, FCGI_STDOUT, req_id, &[]);
                        write_fcgi_record(&mut stream, FCGI_END_REQUEST, req_id, &[0u8; 8]);
                        let _ = stream.flush();
                        break;
                    }
                }
            }
        });

        Self {
            addr,
            stop,
            hits,
            handle: Some(handle),
        }
    }

    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for MockFastCgiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(500));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[test]
fn cache_host_isolation_and_miss_to_hit_static() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let env = TestEnv::new("host_iso", false);

    fs::write(env.vhost_a_root.join("index.html"), "HOST_A_ORIGIN_V1").unwrap();
    fs::write(env.vhost_b_root.join("index.html"), "HOST_B_ORIGIN_V1").unwrap();
    fs::write(env.vhost_a_root.join("item.html"), "ITEM_ORIGIN_V1").unwrap();

    let _srv = ZMaxServerGuard::start(&env);

    // 1. vhost-a.test /index.html -> MISS -> HIT
    let r_a1 = send_http(ports().http, "vhost-a.test", "GET", "/index.html", &[], &[]);
    assert_eq!(r_a1.status, 200);
    assert_eq!(r_a1.header("X-Cache"), Some("MISS"));
    assert_eq!(r_a1.body_str(), "HOST_A_ORIGIN_V1");

    let r_a2 = send_http(ports().http, "vhost-a.test", "GET", "/index.html", &[], &[]);
    assert_eq!(r_a2.status, 200);
    assert_eq!(r_a2.header("X-Cache"), Some("HIT"));
    assert_eq!(r_a2.body_str(), "HOST_A_ORIGIN_V1");

    // 2. vhost-b.test ayni URI (/index.html) -> Host izolasyonu sebebiyle MISS, kendi icerigi -> HIT
    let r_b1 = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(r_b1.status, 200);
    assert_eq!(r_b1.header("X-Cache"), Some("MISS"));
    assert_eq!(r_b1.body_str(), "HOST_B_ORIGIN_V1");

    let r_b2 = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(r_b2.status, 200);
    assert_eq!(r_b2.header("X-Cache"), Some("HIT"));
    assert_eq!(r_b2.body_str(), "HOST_B_ORIGIN_V1");

    // 3. Kaynak dosyalar diskte degisse de HIT eski onbelleklenmis icerigi sunar
    fs::write(env.vhost_a_root.join("index.html"), "HOST_A_ORIGIN_V2").unwrap();
    fs::write(env.vhost_b_root.join("index.html"), "HOST_B_ORIGIN_V2").unwrap();

    let r_a3 = send_http(ports().http, "vhost-a.test", "GET", "/index.html", &[], &[]);
    assert_eq!(r_a3.header("X-Cache"), Some("HIT"));
    assert_eq!(r_a3.body_str(), "HOST_A_ORIGIN_V1");

    let r_b3 = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(r_b3.header("X-Cache"), Some("HIT"));
    assert_eq!(r_b3.body_str(), "HOST_B_ORIGIN_V1");

    // 4. Query string anahtar izolasyonu: ?id=1 ve ?id=2 ayri cache girdisidir
    let q1_miss = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/item.html?id=1",
        &[],
        &[],
    );
    assert_eq!(q1_miss.status, 200);
    assert_eq!(q1_miss.header("X-Cache"), Some("MISS"));

    let q1_hit = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/item.html?id=1",
        &[],
        &[],
    );
    assert_eq!(q1_hit.header("X-Cache"), Some("HIT"));

    let q2_miss = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/item.html?id=2",
        &[],
        &[],
    );
    assert_eq!(q2_miss.status, 200);
    assert_eq!(q2_miss.header("X-Cache"), Some("MISS"));

    let q2_hit = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/item.html?id=2",
        &[],
        &[],
    );
    assert_eq!(q2_hit.header("X-Cache"), Some("HIT"));
}

#[test]
fn cache_l2_disk_persistence_across_restart() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let env = TestEnv::new("l2_persist", false);

    fs::write(env.vhost_a_root.join("l2page.html"), "L2_HOST_A_V1").unwrap();
    fs::write(env.vhost_b_root.join("l2page.html"), "L2_HOST_B_V1").unwrap();

    {
        let _srv1 = ZMaxServerGuard::start(&env);

        let r_a1 = send_http(
            ports().http,
            "vhost-a.test",
            "GET",
            "/l2page.html",
            &[],
            &[],
        );
        assert_eq!(r_a1.status, 200);
        assert_eq!(r_a1.header("X-Cache"), Some("MISS"));
        assert_eq!(r_a1.body_str(), "L2_HOST_A_V1");

        let r_b1 = send_http(
            ports().http,
            "vhost-b.test",
            "GET",
            "/l2page.html",
            &[],
            &[],
        );
        assert_eq!(r_b1.status, 200);
        assert_eq!(r_b1.header("X-Cache"), Some("MISS"));
        assert_eq!(r_b1.body_str(), "L2_HOST_B_V1");

        assert!(
            env.count_zcache_files() >= 2,
            "L2 disk onbellek .zcache dosyalari uretilmedi"
        );

        // Kaynak dosyalari degistir ve sunucu #1'i kapat (L1 RAM sifirlanir)
        fs::write(env.vhost_a_root.join("l2page.html"), "L2_HOST_A_DISK_V2").unwrap();
        fs::write(env.vhost_b_root.join("l2page.html"), "L2_HOST_B_DISK_V2").unwrap();
    }

    // Sunucu #2 ayni ZMAX_HOME ile baslar: L1 bos, L2 .zcache dosyasindan ilk istekte HIT donmeli
    let _srv2 = ZMaxServerGuard::start(&env);

    let r_a_after = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/l2page.html",
        &[],
        &[],
    );
    assert_eq!(r_a_after.status, 200);
    assert_eq!(r_a_after.header("X-Cache"), Some("HIT"));
    assert_eq!(r_a_after.body_str(), "L2_HOST_A_V1");

    let r_b_after = send_http(
        ports().http,
        "vhost-b.test",
        "GET",
        "/l2page.html",
        &[],
        &[],
    );
    assert_eq!(r_b_after.status, 200);
    assert_eq!(r_b_after.header("X-Cache"), Some("HIT"));
    assert_eq!(r_b_after.body_str(), "L2_HOST_B_V1");
}

#[test]
fn cache_api_purge_tag_uri_key_domain_and_all() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let env = TestEnv::new("api_purge", false);

    fs::write(env.vhost_a_root.join("index.html"), "A_INDEX_V1").unwrap();
    fs::write(env.vhost_a_root.join("page2.html"), "A_PAGE2_V1").unwrap();
    fs::write(env.vhost_b_root.join("index.html"), "B_INDEX_V1").unwrap();
    fs::write(env.vhost_b_root.join("page2.html"), "B_PAGE2_V1").unwrap();

    let _srv = ZMaxServerGuard::start(&env);

    // Tum sayfalari onbellege al (MISS -> HIT)
    for (host, path, expected) in [
        ("vhost-a.test", "/index.html", "A_INDEX_V1"),
        ("vhost-a.test", "/page2.html", "A_PAGE2_V1"),
        ("vhost-b.test", "/index.html", "B_INDEX_V1"),
        ("vhost-b.test", "/page2.html", "B_PAGE2_V1"),
    ] {
        let r1 = send_http(ports().http, host, "GET", path, &[], &[]);
        assert_eq!(r1.header("X-Cache"), Some("MISS"));
        assert_eq!(r1.body_str(), expected);
        let r2 = send_http(ports().http, host, "GET", path, &[], &[]);
        assert_eq!(r2.header("X-Cache"), Some("HIT"));
    }

    // Disk iceriklerini V2 olarak guncelle
    fs::write(env.vhost_a_root.join("index.html"), "A_INDEX_V2").unwrap();
    fs::write(env.vhost_a_root.join("page2.html"), "A_PAGE2_V2").unwrap();
    fs::write(env.vhost_b_root.join("index.html"), "B_INDEX_V2").unwrap();
    fs::write(env.vhost_b_root.join("page2.html"), "B_PAGE2_V2").unwrap();

    // 1. Tag purge ("vhost-a.test"): yalnizca vhost-a.test kayitlari silinir, vhost-b.test HIT kalir
    let purge_tag = post_cache_purge(r#"{"tag":"vhost-a.test"}"#);
    assert_eq!(purge_tag["ok"], true);
    assert_eq!(purge_tag["scope"], "tag");
    assert!(
        purge_tag["purged"].as_u64().unwrap_or(0) >= 2,
        "vhost-a.test etiketi en az 2 girdi temizlemeliydi: {}",
        purge_tag
    );

    let ra1 = send_http(ports().http, "vhost-a.test", "GET", "/index.html", &[], &[]);
    assert_eq!(ra1.header("X-Cache"), Some("MISS"));
    assert_eq!(ra1.body_str(), "A_INDEX_V2");

    let ra2 = send_http(ports().http, "vhost-a.test", "GET", "/page2.html", &[], &[]);
    assert_eq!(ra2.header("X-Cache"), Some("MISS"));
    assert_eq!(ra2.body_str(), "A_PAGE2_V2");

    let rb1 = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(rb1.header("X-Cache"), Some("HIT"));
    assert_eq!(rb1.body_str(), "B_INDEX_V1");

    // 2. URI purge (CACHE-1): alan+URI tek vhost'u etkiler, ham URI tum vhost'lara uygulanir.
    fs::write(env.vhost_a_root.join("index.html"), "A_INDEX_V3").unwrap();
    fs::write(env.vhost_a_root.join("page2.html"), "A_PAGE2_V3").unwrap();

    let purge_domain_uri = post_cache_purge(r#"{"domain":"vhost-a.test","uri":"/index.html"}"#);
    assert_eq!(purge_domain_uri["ok"], true);
    assert_eq!(purge_domain_uri["scope"], "domain_uri");
    assert_eq!(purge_domain_uri["purged"], 1);

    let ra_after_du = send_http(ports().http, "vhost-a.test", "GET", "/index.html", &[], &[]);
    assert_eq!(ra_after_du.header("X-Cache"), Some("MISS"));
    assert_eq!(ra_after_du.body_str(), "A_INDEX_V3");
    // vhost-b ayni URI korunur
    let rb_idx_hit = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(rb_idx_hit.header("X-Cache"), Some("HIT"));
    assert_eq!(rb_idx_hit.body_str(), "B_INDEX_V1");

    // Bilesik anahtar ile purge tekil girdiyi temizler
    let composite_key = zmax_cache::build_cache_key(
        "vhost-a.test",
        false,
        "GET",
        "/index.html",
        "",
        Some("identity"),
    );
    let purge_composite = post_cache_purge(&format!(r#"{{"uri":"{}"}}"#, composite_key));
    assert_eq!(purge_composite["ok"], true);
    assert_eq!(purge_composite["scope"], "uri");
    // CACHE-1 davranisi: bilesik anahtar yolu da ayristirilir; vhost-b /index.html de silinir (2).
    assert_eq!(purge_composite["purged"], 2);

    let ra_after_key = send_http(ports().http, "vhost-a.test", "GET", "/index.html", &[], &[]);
    assert_eq!(ra_after_key.header("X-Cache"), Some("MISS"));
    assert_eq!(ra_after_key.body_str(), "A_INDEX_V3");

    // Ham URI purge: iki vhost'un /page2.html girdisi de silinir (gercek sayi 2)
    let purge_raw_uri = post_cache_purge(r#"{"uri":"/page2.html"}"#);
    assert_eq!(purge_raw_uri["ok"], true);
    assert_eq!(purge_raw_uri["scope"], "uri");
    assert_eq!(purge_raw_uri["purged"], 2);
    let ra2_after_raw = send_http(ports().http, "vhost-a.test", "GET", "/page2.html", &[], &[]);
    assert_eq!(ra2_after_raw.header("X-Cache"), Some("MISS"));
    assert_eq!(ra2_after_raw.body_str(), "A_PAGE2_V3");
    let rb2_after_raw = send_http(ports().http, "vhost-b.test", "GET", "/page2.html", &[], &[]);
    assert_eq!(rb2_after_raw.header("X-Cache"), Some("MISS"));
    assert_eq!(rb2_after_raw.body_str(), "B_PAGE2_V2");

    // 3. Domain purge (CACHE-1): vhost-b.test altindaki girdiler silinir, vhost-a korunur.
    let purge_domain = post_cache_purge(r#"{"domain":"vhost-b.test"}"#);
    assert_eq!(purge_domain["ok"], true);
    assert_eq!(purge_domain["scope"], "domain");
    assert_eq!(purge_domain["purged"], 1);

    let rb_after_domain = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(rb_after_domain.header("X-Cache"), Some("MISS"));
    assert_eq!(rb_after_domain.body_str(), "B_INDEX_V2");
    let ra2_still_hit = send_http(ports().http, "vhost-a.test", "GET", "/page2.html", &[], &[]);
    assert_eq!(ra2_still_hit.header("X-Cache"), Some("HIT"));
    assert_eq!(ra2_still_hit.body_str(), "A_PAGE2_V3");

    // 4. Purge all ({}) tum L1 ve L2 (.zcache) girdilerini temizler -> her iki vhost da MISS olur
    let purge_all = post_cache_purge("{}");
    assert_eq!(purge_all["ok"], true);
    assert_eq!(purge_all["scope"], "all");
    assert_eq!(env.count_zcache_files(), 0);

    let ra2_after_all = send_http(ports().http, "vhost-a.test", "GET", "/page2.html", &[], &[]);
    assert_eq!(ra2_after_all.header("X-Cache"), Some("MISS"));
    assert_eq!(ra2_after_all.body_str(), "A_PAGE2_V3");

    let rb1_after_all = send_http(ports().http, "vhost-b.test", "GET", "/index.html", &[], &[]);
    assert_eq!(rb1_after_all.header("X-Cache"), Some("MISS"));
    assert_eq!(rb1_after_all.body_str(), "B_INDEX_V2");

    let rb2_after_all = send_http(ports().http, "vhost-b.test", "GET", "/page2.html", &[], &[]);
    assert_eq!(rb2_after_all.header("X-Cache"), Some("MISS"));
    assert_eq!(rb2_after_all.body_str(), "B_PAGE2_V2");
}

#[test]
fn cache_php_fastcgi_host_isolation_purge_and_lscache_bridge_status() {
    let _lock = PORT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let env = TestEnv::new("php_lscache", true);

    for script in [
        "app.php",
        "nocache.php",
        "lscache_nocache.php",
        "lscache_tag.php",
    ] {
        fs::write(env.vhost_a_root.join(script), "<?php // mock").unwrap();
        fs::write(env.vhost_b_root.join(script), "<?php // mock").unwrap();
    }

    let fcgi = MockFastCgiServer::start(ports().fcgi);
    let _srv = ZMaxServerGuard::start(&env);

    // 1. PHP FastCGI Host izolasyonu ve MISS -> HIT (backend sayaci HIT'te artmamali)
    let pa1 = send_http(ports().http, "vhost-a.test", "GET", "/app.php", &[], &[]);
    assert_eq!(pa1.status, 200);
    assert_eq!(pa1.header("X-Cache"), Some("MISS"));
    assert_eq!(pa1.body_str(), "host=vhost-a.test;uri=/app.php;hit=1");
    assert_eq!(fcgi.hit_count(), 1);

    let pa2 = send_http(ports().http, "vhost-a.test", "GET", "/app.php", &[], &[]);
    assert_eq!(pa2.status, 200);
    assert_eq!(pa2.header("X-Cache"), Some("HIT"));
    assert_eq!(pa2.body_str(), "host=vhost-a.test;uri=/app.php;hit=1");
    assert_eq!(fcgi.hit_count(), 1);

    let pb1 = send_http(ports().http, "vhost-b.test", "GET", "/app.php", &[], &[]);
    assert_eq!(pb1.status, 200);
    assert_eq!(pb1.header("X-Cache"), Some("MISS"));
    assert_eq!(pb1.body_str(), "host=vhost-b.test;uri=/app.php;hit=2");
    assert_eq!(fcgi.hit_count(), 2);

    let pb2 = send_http(ports().http, "vhost-b.test", "GET", "/app.php", &[], &[]);
    assert_eq!(pb2.status, 200);
    assert_eq!(pb2.header("X-Cache"), Some("HIT"));
    assert_eq!(pb2.body_str(), "host=vhost-b.test;uri=/app.php;hit=2");
    assert_eq!(fcgi.hit_count(), 2);

    // 2. Standart Cache-Control: no-cache ve Authorization BYPASS
    let nc1 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/nocache.php",
        &[],
        &[],
    );
    assert_eq!(nc1.status, 200);
    assert_eq!(nc1.header("X-Cache"), Some("BYPASS"));
    assert_eq!(nc1.body_str(), "host=vhost-a.test;uri=/nocache.php;hit=3");

    let nc2 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/nocache.php",
        &[],
        &[],
    );
    assert_eq!(nc2.status, 200);
    assert_eq!(nc2.header("X-Cache"), Some("BYPASS"));
    assert_eq!(nc2.body_str(), "host=vhost-a.test;uri=/nocache.php;hit=4");
    assert_eq!(fcgi.hit_count(), 4);

    let auth_bypass = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/app.php",
        &[("Authorization", "Bearer test-token")],
        &[],
    );
    assert_eq!(auth_bypass.status, 200);
    assert_eq!(auth_bypass.header("X-Cache"), Some("BYPASS"));
    assert_eq!(
        auth_bypass.body_str(),
        "host=vhost-a.test;uri=/app.php;hit=5"
    );
    assert_eq!(fcgi.hit_count(), 5);

    // 3. Tag purge (/api/v1/cache/purge {"tag":"vhost-a.test"}) PHP kaydini da temizler, vhost-b korunur
    let p_vhost_a = post_cache_purge(r#"{"tag":"vhost-a.test"}"#);
    assert_eq!(p_vhost_a["ok"], true);
    assert!(p_vhost_a["purged"].as_u64().unwrap_or(0) >= 1);

    let pa_after_purge = send_http(ports().http, "vhost-a.test", "GET", "/app.php", &[], &[]);
    assert_eq!(pa_after_purge.header("X-Cache"), Some("MISS"));
    assert_eq!(
        pa_after_purge.body_str(),
        "host=vhost-a.test;uri=/app.php;hit=6"
    );

    let pb_still_hit = send_http(ports().http, "vhost-b.test", "GET", "/app.php", &[], &[]);
    assert_eq!(pb_still_hit.header("X-Cache"), Some("HIT"));
    assert_eq!(
        pb_still_hit.body_str(),
        "host=vhost-b.test;uri=/app.php;hit=2"
    );
    assert_eq!(fcgi.hit_count(), 6);

    // 4. X-LiteSpeed-* LSCache koprusu (web_engine'e bagli):
    //    a) X-LiteSpeed-Cache-Control: no-cache -> onbellege alinmaz (BYPASS), her istek backend'e gider,
    //       ve yonerge istemciye sizmaz.
    let lsc_nc1 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/lscache_nocache.php",
        &[],
        &[],
    );
    assert_eq!(lsc_nc1.header("X-Cache"), Some("BYPASS"));
    assert_eq!(lsc_nc1.header("X-LiteSpeed-Cache-Control"), None);
    let lsc_nc2 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/lscache_nocache.php",
        &[],
        &[],
    );
    assert_eq!(
        lsc_nc2.header("X-Cache"),
        Some("BYPASS"),
        "X-LiteSpeed-Cache-Control: no-cache sayfasi onbellege alinmamali"
    );
    assert_eq!(fcgi.hit_count(), 8);

    //    b) X-LiteSpeed-Tag: post:42, cat:7 istemciye gitmez, cache.tags icine yazilir;
    //       tag ve domain+tag purge gercek silinen girdi sayisini doner.
    let lsc_tag1 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/lscache_tag.php",
        &[],
        &[],
    );
    assert_eq!(lsc_tag1.header("X-Cache"), Some("MISS"));
    assert_eq!(lsc_tag1.header("X-LiteSpeed-Tag"), None);
    assert_eq!(lsc_tag1.header("X-LiteSpeed-Cache-Control"), None);
    assert_eq!(lsc_tag1.header("X-LiteSpeed-Purge"), None);
    assert_eq!(fcgi.hit_count(), 9);

    let lsc_tag_hit = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/lscache_tag.php",
        &[],
        &[],
    );
    assert_eq!(lsc_tag_hit.header("X-Cache"), Some("HIT"));
    assert_eq!(fcgi.hit_count(), 9);

    let purge_none = post_cache_purge(r#"{"tag":"yok-boyle-bir-etiket"}"#);
    assert_eq!(purge_none["purged"], 0);

    let purge_domain_post_tag = post_cache_purge(r#"{"domain":"vhost-a.test","tag":"post:42"}"#);
    assert_eq!(purge_domain_post_tag["purged"], 1);

    let lsc_tag2 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/lscache_tag.php",
        &[],
        &[],
    );
    assert_eq!(lsc_tag2.header("X-Cache"), Some("MISS"));
    assert_eq!(fcgi.hit_count(), 10);

    let purge_post_tag = post_cache_purge(r#"{"tag":"post:42"}"#);
    assert_eq!(purge_post_tag["purged"], 1);

    let lsc_tag3 = send_http(
        ports().http,
        "vhost-a.test",
        "GET",
        "/lscache_tag.php",
        &[],
        &[],
    );
    assert_eq!(lsc_tag3.header("X-Cache"), Some("MISS"));
    assert_eq!(fcgi.hit_count(), 11);

    //    c) Kutuphane katmaninda (zmax_cache) X-LiteSpeed-* ayristirici ve vary yardimcilari hazirdir.
    let parsed = zmax_cache::parse_lscache_headers([
        ("X-LiteSpeed-Cache-Control", "public, max-age=120"),
        ("X-LiteSpeed-Tag", "post:42, cat:7"),
        ("X-LiteSpeed-Vary", "cookie=wp_lang, header=Accept-Language"),
    ]);
    assert_eq!(parsed.cacheable, Some(true));
    assert_eq!(parsed.tags, vec!["post:42", "cat:7"]);
    assert_eq!(parsed.vary_cookies, vec!["wp_lang"]);
    assert_eq!(parsed.vary_headers, vec!["accept-language"]);
}
