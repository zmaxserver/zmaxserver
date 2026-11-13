//! Token'sız genel sürüm ucu (`GET /api/version`) testleri: GERÇEK `zmax` ikilisi + gerçek TCP.
//!
//! Hem admin hem API dinleyicisi token ZORUNLU yapılandırılır; yalnız `/api/version` (GET) muaf olmalı,
//! diğer yollar token'sız 401 kalmalıdır. Portlar dinamiktir (`bind(:0)`).

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Guard {
    child: Child,
    root: PathBuf,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
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

fn start(ports: [u16; 4]) -> Guard {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!("zmax_pubver_{}_{}", std::process::id(), nanos));
    for d in ["conf/vhosts", "modules", "logs", "cache", "admin"] {
        fs::create_dir_all(root.join(d)).expect("dizin olusturulamadi");
    }
    fs::write(root.join("admin").join("index.html"), b"<h1>Admin</h1>").expect("index.html");
    let toml = format!(
        r#"[server]
server_name = "pubver-test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {}

[listeners.https]
enabled = false
address = "127.0.0.1"
port = {}
ssl = false

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {}
token = "api-gizli-token"
require_token = true
ssl = false

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {}
document_root = "admin"
token = "admin-gizli-token"
require_token = true
ssl = false

[vhosts_dir]
path = "conf/vhosts"

[logging]
level = "info"
access_log = "logs/access.log"
error_log = "logs/error.log"
"#,
        ports[0], ports[1], ports[2], ports[3]
    );
    let conf = root.join("conf").join("zmax.toml");
    fs::write(&conf, toml).expect("zmax.toml yazilamadi");

    let mut child = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .env("ZMAX_HOME", &root)
        .env("ZMAX_CONF", &conf)
        .arg("-c")
        .arg(&conf)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("zmax baslatilamadi");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel::<bool>();
    std::thread::spawn(move || {
        let mut signaled = false;
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if !signaled && line.contains("hazir!") {
                signaled = true;
                let _ = tx.send(true);
            }
        }
        if !signaled {
            let _ = tx.send(false);
        }
    });
    let guard = Guard { child, root };
    assert!(
        matches!(rx.recv_timeout(Duration::from_secs(20)), Ok(true)),
        "zmax 20 sn icinde hazir olmadi"
    );
    guard
}

struct Resp {
    status: u16,
    head: String,
    body: String,
}

fn http(port: u16, method: &str, path: &str) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("baglanti");
    s.set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    );
    s.write_all(req.as_bytes()).expect("yazma");
    let mut buf = Vec::new();
    // Okuma hatası/zaman aşımı kısmi yanıtı geçersiz kılmaz; durum kodu 0 kalırsa assert yakalar.
    let _ = s.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    Resp {
        status,
        head: head.to_string(),
        body: body.to_string(),
    }
}

fn expected_version() -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../VERSION");
    fs::read_to_string(p).expect("VERSION").trim().to_string()
}

#[test]
fn version_endpoint_is_public_on_admin_and_api_but_nothing_else_is() {
    let ports = free_ports::<4>();
    let (api, admin) = (ports[2], ports[3]);
    let _g = start(ports);
    let ver = expected_version();
    let want = format!(r#"{{"version":"{ver}"}}"#);

    for port in [admin, api] {
        // Token'sız /api/version: 200 + doğru sürüm + JSON charset
        let r = http(port, "GET", "/api/version");
        assert_eq!(r.status, 200, "port {port}: {}", r.head);
        assert_eq!(r.body, want, "port {port}");
        assert!(
            r.head
                .to_ascii_lowercase()
                .contains("content-type: application/json; charset=utf-8"),
            "{}",
            r.head
        );

        // Muafiyet yalnız bu yolda: başka yollar token'sız 401 kalır
        for path in [
            "/api/status",
            "/api/v1/status",
            "/api/v1/vhosts",
            "/api/v1/security/bans",
            "/metrics",
        ] {
            let r = http(port, "GET", path);
            assert_eq!(r.status, 401, "port {port} {path}: {}", r.head);
        }

        // Yol varyantları ve yöntem muaf değil
        for path in [
            "/api/version/x",
            "/api/version/",
            "/api/versions",
            "/api/Version",
        ] {
            let r = http(port, "GET", path);
            assert!(
                r.status == 401 || r.status == 404,
                "port {port} {path}: {}",
                r.head
            );
            assert!(!r.body.contains(&ver), "{path} surum sizdirdi");
        }
        for method in ["POST", "PUT", "DELETE"] {
            let r = http(port, method, "/api/version");
            assert!(
                r.status == 401 || r.status == 404 || r.status == 405,
                "port {port} {method}: {}",
                r.head
            );
            assert!(!r.body.contains(&ver), "{method} surum sizdirdi");
        }
    }
}
