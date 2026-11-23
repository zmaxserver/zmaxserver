//! Kart 3b Entegrasyon Testleri:
//! Gerçek `zmax` sunucusu üzerinde Kontrol API (`PUT` / `POST` / `GET /api/v1/vhosts`)
//! aracılığıyla Kart 5 `hotlink` ve `acl` alanlarının JSON <-> TOML tam tur eşitliği,
//! geçersiz CIDR / hotlink değerlerinin 400 ile reddedilip diskteki TOML dosyasını
//! değiştirmemesi ve canlı HTTP hattında hotlink korumasının uygulanması doğrulanır.

use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zmax_config::vhost_json::vhost_entry_diff;
use zmax_config::{load_vhosts_dir, VHostEntry};

// AJAN_YAPISI.md §4 (a03 ajan port bloğu: 21030-21033)
const HTTP_PORT: u16 = 21030;
const HTTPS_PORT: u16 = 21031;
const API_PORT: u16 = 21032;
const ADMIN_PORT: u16 = 21033;

struct ZmaxProcessGuard {
    child: Child,
    root: PathBuf,
}

impl Drop for ZmaxProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| {
            panic!(
                "JSON ayrıştırma hatası ({}): gövde='{}'",
                e,
                String::from_utf8_lossy(&self.body)
            )
        })
    }
}

fn send_http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .unwrap_or_else(|e| panic!("127.0.0.1:{} bağlantısı kurulamadı: {}", port, e));
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("read timeout ayarlanamadı");
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .expect("write timeout ayarlanamadı");

    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n",
        method, path, port
    );
    let mut has_host_override = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("host") {
            has_host_override = true;
            req = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
                method, path, v
            );
            break;
        }
    }
    for (k, v) in headers {
        if has_host_override && k.eq_ignore_ascii_case("host") {
            continue;
        }
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if let Some(b) = body {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .expect("HTTP başlığı gönderilemedi");
    if let Some(b) = body {
        stream.write_all(b).expect("HTTP gövdesi gönderilemedi");
    }
    stream.flush().expect("HTTP isteği flush edilemedi");

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut chunk).expect("HTTP yanıtı okunamadı");
        if n == 0 {
            panic!(
                "HTTP başlık sonu bulunamadan bağlantı kapandı: {}",
                String::from_utf8_lossy(&buf)
            );
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let header_text = String::from_utf8_lossy(&buf[..header_end]);
    let status_line = header_text.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("HTTP durum kodu okunamadı: '{}'", status_line));

    let content_length: Option<usize> = header_text.lines().skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        if k.trim().eq_ignore_ascii_case("content-length") {
            v.trim().parse::<usize>().ok()
        } else {
            None
        }
    });

    if let Some(len) = content_length {
        while buf.len() < header_end + len {
            let n = stream
                .read(&mut chunk)
                .expect("HTTP gövdesi devamı okunamadı");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let end = (header_end + len).min(buf.len());
        HttpResponse {
            status,
            body: buf[header_end..end].to_vec(),
        }
    } else {
        loop {
            let n = stream.read(&mut chunk).expect("HTTP gövdesi EOF okunamadı");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        HttpResponse {
            status,
            body: buf[header_end..].to_vec(),
        }
    }
}

fn create_isolated_workspace() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!("zmax_kart3b_{}_{}", std::process::id(), nanos));
    fs::create_dir_all(root.join("conf").join("vhosts")).expect("conf/vhosts oluşturulamadı");
    fs::create_dir_all(root.join("modules")).expect("modules dizini oluşturulamadı");
    fs::create_dir_all(root.join("logs")).expect("logs dizini oluşturulamadı");
    fs::create_dir_all(root.join("cache")).expect("cache dizini oluşturulamadı");
    fs::create_dir_all(root.join("admin")).expect("admin dizini oluşturulamadı");
    fs::write(root.join("admin").join("index.html"), b"<h1>Admin</h1>")
        .expect("admin/index.html yazılamadı");

    let doc_root = root.join("www").join("kart3b-put.test");
    fs::create_dir_all(&doc_root).expect("www/kart3b-put.test oluşturulamadı");
    fs::write(doc_root.join("img.jpg"), b"\xff\xd8\xff\xe0KART3B-IMG").expect("img.jpg yazılamadı");
    fs::write(doc_root.join("index.html"), b"<h1>Kart 3b</h1>").expect("index.html yazılamadı");

    let zmax_toml = format!(
        r#"[server]
server_name = "kart3b-test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http}

[listeners.https]
enabled = false
address = "127.0.0.1"
port = {https}
ssl = false

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api}
require_token = false
ssl = false

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {admin}
document_root = "admin"
require_token = false
ssl = false

[vhosts_dir]
path = "conf/vhosts"

[logging]
level = "info"
access_log = "logs/access.log"
error_log = "logs/error.log"
"#,
        http = HTTP_PORT,
        https = HTTPS_PORT,
        api = API_PORT,
        admin = ADMIN_PORT,
    );
    fs::write(root.join("conf").join("zmax.toml"), zmax_toml).expect("conf/zmax.toml yazılamadı");

    root
}

fn spawn_zmax_server(root: &Path) -> ZmaxProcessGuard {
    let conf_path = root.join("conf").join("zmax.toml");
    let exe_path = env!("CARGO_BIN_EXE_zmax");
    let mut child = Command::new(exe_path)
        .env("ZMAX_HOME", root)
        .env("ZMAX_CONF", &conf_path)
        .arg("-c")
        .arg(&conf_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("zmax başlatılamadı ({}): {}", exe_path, e));

    let stdout = child.stdout.take().expect("stdout alınamadı");
    let stderr = child.stderr.take().expect("stderr alınamadı");

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        let mut lines_buf = Vec::new();
        let mut signaled = false;
        for line_res in reader.lines() {
            match line_res {
                Ok(line) => {
                    if !signaled {
                        let ready = line.contains("hazir!");
                        lines_buf.push(line);
                        if ready {
                            signaled = true;
                            lines_buf.clear();
                            let _ = tx.send(Ok(()));
                        }
                    }
                }
                Err(e) => {
                    if !signaled {
                        let _ = tx.send(Err(format!("stdout okuma hatası: {}", e)));
                    }
                    return;
                }
            }
        }
        if !signaled {
            let _ = tx.send(Err(format!(
                "zmax hazır mesajı vermeden stdout kapandı. Çıktı:\n{}",
                lines_buf.join("\n")
            )));
        }
    });

    let stderr_handle = std::thread::spawn(move || {
        let mut s = String::new();
        let mut r = stderr;
        let _ = r.read_to_string(&mut s);
        s
    });

    match rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = stderr_handle.join().unwrap_or_default();
            panic!("zmax başlatma hatası: {}\nstderr:\n{}", msg, err_out);
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = stderr_handle.join().unwrap_or_default();
            panic!("zmax 20 sn içinde hazır olmadı!\nstderr:\n{}", err_out);
        }
    }

    ZmaxProcessGuard {
        child,
        root: root.to_path_buf(),
    }
}

fn load_single_vhost(vhosts_dir: &Path, base_dir: &Path, domain: &str) -> VHostEntry {
    let loaded = load_vhosts_dir(vhosts_dir, base_dir)
        .unwrap_or_else(|e| panic!("vhosts dizini yüklenemedi: {}", e));
    loaded
        .into_iter()
        .find(|v| v.entry.name == domain)
        .unwrap_or_else(|| panic!("TOML içinde '{}' vHost bulunamadı", domain))
        .entry
}

#[test]
fn test_kart3b_api_hotlink_acl_roundtrip_invalid_cidr_and_live_http() {
    let root = create_isolated_workspace();
    let _guard = spawn_zmax_server(&root);
    let vhosts_dir = root.join("conf").join("vhosts");

    // 0. API sağlık kontrolü
    let health = send_http(API_PORT, "GET", "/api/v1/health", &[], None);
    assert_eq!(health.status, 200);
    assert_eq!(health.json()["ok"], json!(true));

    // =========================================================================
    // 1. PUT /api/v1/vhosts/kart3b-put.test -> TOML -> GET tam tur eşitliği
    // =========================================================================
    let put_payload = json!({
        "document_root": "www/kart3b-put.test",
        "hotlink": {
            "enabled": true,
            "allowed_referers": ["kart3b-put.test", "*.cdn3b.test"],
            "extensions": ["jpg", "png", "webp"]
        },
        "acl": {
            "allow_ips": ["10.10.0.0/16", "127.0.0.1", "2001:db8::/32"],
            "deny_ips": ["192.168.50.0/24", "198.51.100.7"]
        }
    });
    let put_bytes = serde_json::to_vec(&put_payload).unwrap();
    let put_resp = send_http(
        API_PORT,
        "PUT",
        "/api/v1/vhosts/kart3b-put.test",
        &[],
        Some(&put_bytes),
    );
    assert_eq!(
        put_resp.status,
        200,
        "PUT 200 dönmeli, gelen: {}",
        String::from_utf8_lossy(&put_resp.body)
    );
    assert_eq!(put_resp.json()["ok"], json!(true));
    assert_eq!(put_resp.json()["domain"], json!("kart3b-put.test"));

    // Diskteki TOML dosyasını ve ayrıştırılmış VHostEntry içeriğini doğrula
    let put_toml_path = vhosts_dir.join("kart3b-put.test.toml");
    assert!(put_toml_path.is_file(), "TOML dosyası diskte oluşmalı");
    let put_toml_text = fs::read_to_string(&put_toml_path).expect("TOML metni okunamadı");
    assert!(
        put_toml_text.contains("[vhost.hotlink]"),
        "TOML içinde [vhost.hotlink] olmalı:\n{}",
        put_toml_text
    );
    assert!(
        put_toml_text.contains("[vhost.acl]"),
        "TOML içinde [vhost.acl] olmalı:\n{}",
        put_toml_text
    );

    let disk_entry = load_single_vhost(&vhosts_dir, &root, "kart3b-put.test");
    assert!(disk_entry.hotlink.enabled);
    assert_eq!(
        disk_entry.hotlink.allowed_referers,
        vec!["kart3b-put.test", "*.cdn3b.test"]
    );
    assert_eq!(disk_entry.hotlink.extensions, vec!["jpg", "png", "webp"]);
    assert_eq!(
        disk_entry.acl.allow_ips,
        vec!["10.10.0.0/16", "127.0.0.1", "2001:db8::/32"]
    );
    assert_eq!(
        disk_entry.acl.deny_ips,
        vec!["192.168.50.0/24", "198.51.100.7"]
    );

    // GET /api/v1/vhosts/kart3b-put.test ile tam tur eşitliği doğrula
    let get_resp = send_http(API_PORT, "GET", "/api/v1/vhosts/kart3b-put.test", &[], None);
    assert_eq!(get_resp.status, 200);
    let get_json = get_resp.json();
    assert_eq!(get_json["ok"], json!(true));
    let vh = &get_json["vhost"];
    assert_eq!(vh["hotlink"]["enabled"], json!(true));
    assert_eq!(
        vh["hotlink"]["allowed_referers"],
        json!(["kart3b-put.test", "*.cdn3b.test"])
    );
    assert_eq!(vh["hotlink"]["extensions"], json!(["jpg", "png", "webp"]));
    assert_eq!(
        vh["acl"]["allow_ips"],
        json!(["10.10.0.0/16", "127.0.0.1", "2001:db8::/32"])
    );
    assert_eq!(
        vh["acl"]["deny_ips"],
        json!(["192.168.50.0/24", "198.51.100.7"])
    );
    assert_eq!(vh["hotlink_enabled"], json!(true));
    assert_eq!(
        vh["hotlink_allowed_referers"],
        json!(["kart3b-put.test", "*.cdn3b.test"])
    );
    assert_eq!(
        vh["allowed_referers"],
        json!(["kart3b-put.test", "*.cdn3b.test"])
    );
    assert_eq!(vh["hotlink_extensions"], json!(["jpg", "png", "webp"]));
    assert_eq!(vh["extensions"], json!(["jpg", "png", "webp"]));
    assert_eq!(
        vh["acl_allow_ips"],
        json!(["10.10.0.0/16", "127.0.0.1", "2001:db8::/32"])
    );
    assert_eq!(
        vh["acl_deny_ips"],
        json!(["192.168.50.0/24", "198.51.100.7"])
    );

    // Canlı HTTP motorunda API ile yazılan hotlink kuralının çalıştığını doğrula
    let hotlink_block = send_http(
        HTTP_PORT,
        "GET",
        "/img.jpg",
        &[
            ("Host", "kart3b-put.test"),
            ("Referer", "https://hirsiz-site.test/cal"),
        ],
        None,
    );
    assert_eq!(
        hotlink_block.status, 403,
        "İzinsiz referer .jpg için 403 dönmeli"
    );

    let hotlink_allow = send_http(
        HTTP_PORT,
        "GET",
        "/img.jpg",
        &[
            ("Host", "kart3b-put.test"),
            ("Referer", "https://static.cdn3b.test/galeri"),
        ],
        None,
    );
    assert_eq!(
        hotlink_allow.status, 200,
        "Wildcard izinli referer *.cdn3b.test için 200 dönmeli"
    );
    assert_eq!(hotlink_allow.body, b"\xff\xd8\xff\xe0KART3B-IMG");

    let non_protected_ext = send_http(
        HTTP_PORT,
        "GET",
        "/index.html",
        &[
            ("Host", "kart3b-put.test"),
            ("Referer", "https://hirsiz-site.test/"),
        ],
        None,
    );
    assert_eq!(
        non_protected_ext.status, 200,
        "Korunmayan .html uzantısı 200 dönmeli"
    );

    // =========================================================================
    // 2. Geçersiz CIDR ve geçersiz hotlink -> 400 Bad Request + dosya DEĞİŞMEZ
    // =========================================================================
    let baseline_toml_bytes = fs::read(&put_toml_path).expect("Baz TOML baytları okunamadı");

    let invalid_put_cases = [
        json!({ "acl": { "allow_ips": ["10.0.0.1/33"] } }),
        json!({ "acl": { "deny_ips": ["2001:db8::/129"] } }),
        json!({ "acl_allow_ips": ["gecersiz-cidr"] }),
        json!({ "acl_deny_ips": ["999.999.999.999"] }),
        json!({ "acl": { "allow_ips": [""] } }),
        json!({ "hotlink": { "extensions": ["bad/ext"] } }),
        json!({ "hotlink": { "allowed_referers": ["   "] } }),
        json!({ "hotlink": "not-an-object" }),
        json!({ "acl": ["127.0.0.1"] }),
    ];

    for (idx, bad_payload) in invalid_put_cases.iter().enumerate() {
        let body = serde_json::to_vec(bad_payload).unwrap();
        let resp = send_http(
            API_PORT,
            "PUT",
            "/api/v1/vhosts/kart3b-put.test",
            &[],
            Some(&body),
        );
        assert_eq!(
            resp.status,
            400,
            "Senaryo #{} 400 dönmeli (gövde={}): gelen={}",
            idx,
            bad_payload,
            String::from_utf8_lossy(&resp.body)
        );
        assert_eq!(resp.json()["ok"], json!(false));

        let current_bytes = fs::read(&put_toml_path).expect("Red sonrası TOML okunamadı");
        assert_eq!(
            current_bytes, baseline_toml_bytes,
            "Senaryo #{} reddedilince diskteki TOML baytları değişmemeli!",
            idx
        );
    }

    // Aktif bellekteki vHost değerlerinin de değişmediğini doğrula
    let after_err_get = send_http(API_PORT, "GET", "/api/v1/vhosts/kart3b-put.test", &[], None);
    assert_eq!(after_err_get.status, 200);
    assert_eq!(
        after_err_get.json()["vhost"]["acl"]["allow_ips"],
        json!(["10.10.0.0/16", "127.0.0.1", "2001:db8::/32"])
    );

    // =========================================================================
    // 3. POST /api/v1/vhosts (Flat alanlarla yeni vHost) + Geçersiz POST reddi
    // =========================================================================
    let post_payload = json!({
        "domain": "kart3b-post.test",
        "document_root": "www/kart3b-post.test",
        "hotlink_enabled": true,
        "hotlink_allowed_referers": ["kart3b-post.test", "app.kart3b-post.test"],
        "hotlink_extensions": ["mp4", "pdf"],
        "acl_allow_ips": ["172.16.0.0/12"],
        "acl_deny_ips": ["203.0.113.0/24"]
    });
    let post_bytes = serde_json::to_vec(&post_payload).unwrap();
    let post_resp = send_http(API_PORT, "POST", "/api/v1/vhosts", &[], Some(&post_bytes));
    assert_eq!(
        post_resp.status,
        200,
        "POST 200 dönmeli, gelen: {}",
        String::from_utf8_lossy(&post_resp.body)
    );
    assert_eq!(post_resp.json()["ok"], json!(true));
    assert_eq!(post_resp.json()["domain"], json!("kart3b-post.test"));

    let post_toml_path = vhosts_dir.join("kart3b-post.test.toml");
    assert!(
        post_toml_path.is_file(),
        "POST sonrası TOML dosyası oluşmalı"
    );
    let post_disk = load_single_vhost(&vhosts_dir, &root, "kart3b-post.test");
    assert!(post_disk.hotlink.enabled);
    assert_eq!(
        post_disk.hotlink.allowed_referers,
        vec!["kart3b-post.test", "app.kart3b-post.test"]
    );
    assert_eq!(post_disk.hotlink.extensions, vec!["mp4", "pdf"]);
    assert_eq!(post_disk.acl.allow_ips, vec!["172.16.0.0/12"]);
    assert_eq!(post_disk.acl.deny_ips, vec!["203.0.113.0/24"]);

    let post_get = send_http(
        API_PORT,
        "GET",
        "/api/v1/vhosts/kart3b-post.test",
        &[],
        None,
    );
    assert_eq!(post_get.status, 200);
    let post_vh = &post_get.json()["vhost"];
    assert_eq!(post_vh["hotlink"]["enabled"], json!(true));
    assert_eq!(
        post_vh["hotlink"]["allowed_referers"],
        json!(["kart3b-post.test", "app.kart3b-post.test"])
    );
    assert_eq!(post_vh["hotlink"]["extensions"], json!(["mp4", "pdf"]));
    assert_eq!(post_vh["acl"]["allow_ips"], json!(["172.16.0.0/12"]));
    assert_eq!(post_vh["acl"]["deny_ips"], json!(["203.0.113.0/24"]));

    // Liste ucunda da her iki vHost'un göründüğünü doğrula
    let list_resp = send_http(API_PORT, "GET", "/api/v1/vhosts", &[], None);
    assert_eq!(list_resp.status, 200);
    assert_eq!(list_resp.json()["count"], json!(2));

    // Geçersiz CIDR ile POST -> 400 ve yeni TOML dosyası OLUŞTURULMAZ
    let bad_post = json!({
        "domain": "kart3b-badpost.test",
        "document_root": "www/badpost",
        "acl": { "deny_ips": ["192.168.1.0/99"] }
    });
    let bad_post_bytes = serde_json::to_vec(&bad_post).unwrap();
    let bad_post_resp = send_http(
        API_PORT,
        "POST",
        "/api/v1/vhosts",
        &[],
        Some(&bad_post_bytes),
    );
    assert_eq!(bad_post_resp.status, 400);
    assert_eq!(bad_post_resp.json()["ok"], json!(false));
    assert!(
        !vhosts_dir.join("kart3b-badpost.test.toml").exists(),
        "Geçersiz POST sonrası TOML dosyası oluşturulmamalı!"
    );

    // =========================================================================
    // 4. Kısmi PUT güncellemesi -> diğer alt alanlar korunmalı + round-trip eşliği
    // =========================================================================
    let patch_payload = json!({
        "hotlink": { "enabled": false },
        "acl": { "deny_ips": ["203.0.113.42"] }
    });
    let patch_bytes = serde_json::to_vec(&patch_payload).unwrap();
    let patch_resp = send_http(
        API_PORT,
        "PUT",
        "/api/v1/vhosts/kart3b-put.test",
        &[],
        Some(&patch_bytes),
    );
    assert_eq!(patch_resp.status, 200);

    let patched_disk = load_single_vhost(&vhosts_dir, &root, "kart3b-put.test");
    assert!(!patched_disk.hotlink.enabled);
    assert_eq!(
        patched_disk.hotlink.allowed_referers,
        vec!["kart3b-put.test", "*.cdn3b.test"]
    );
    assert_eq!(patched_disk.hotlink.extensions, vec!["jpg", "png", "webp"]);
    assert_eq!(
        patched_disk.acl.allow_ips,
        vec!["10.10.0.0/16", "127.0.0.1", "2001:db8::/32"]
    );
    assert_eq!(patched_disk.acl.deny_ips, vec!["203.0.113.42"]);

    let patched_get = send_http(API_PORT, "GET", "/api/v1/vhosts/kart3b-put.test", &[], None);
    assert_eq!(patched_get.status, 200);
    let patched_json_entry: VHostEntry =
        serde_json::from_value(patched_get.json()["vhost"].clone())
            .expect("GET vhost JSON değeri VHostEntry olarak ayrıştırılabilmeli");
    assert_eq!(
        vhost_entry_diff(&patched_disk, &patched_json_entry),
        None,
        "GET JSON çıktısı ile diskteki TOML tam tur eşit olmalı"
    );

    // Hotlink artık false olduğu için önceki engelli referer ile .jpg 200 dönmeli
    let hotlink_disabled_req = send_http(
        HTTP_PORT,
        "GET",
        "/img.jpg",
        &[
            ("Host", "kart3b-put.test"),
            ("Referer", "https://hirsiz-site.test/cal"),
        ],
        None,
    );
    assert_eq!(hotlink_disabled_req.status, 200);
}
