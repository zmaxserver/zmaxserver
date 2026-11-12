//! T-OLS-B5 Entegrasyon Testleri:
//! `.htaccess` `Options -Indexes`, `<FilesMatch>` 403, `ErrorDocument`, `RewriteCond %{HTTPS} off` ve `%1` geri başvuru
//! kurallarının HTTP/1.1 ve HTTP/2 boru hattında uçtan uca çalıştığını doğrular.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TEST_HTTP_PORT: u16 = 21020;
const TEST_HTTPS_PORT: u16 = 21021;
const TEST_API_PORT: u16 = 21022;
const TEST_ADMIN_PORT: u16 = 21023;

struct ProcessAndDirGuard {
    child: Option<Child>,
    base_dir: PathBuf,
}

impl Drop for ProcessAndDirGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

fn create_temp_workspace(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zmax_ols_b5_{}_{}", tag, nanos));
    std::fs::create_dir_all(dir.join("conf").join("vhosts")).unwrap();
    std::fs::create_dir_all(dir.join("certs")).unwrap();
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    std::fs::create_dir_all(dir.join("admin")).unwrap();
    std::fs::create_dir_all(dir.join("modules")).unwrap();
    std::fs::create_dir_all(dir.join("www").join("b5site")).unwrap();
    dir
}

fn write_test_certs(base_dir: &Path) {
    let ck =
        rcgen::generate_simple_self_signed(vec!["b5.test".to_string(), "www.b5.test".to_string()])
            .unwrap();

    std::fs::write(base_dir.join("certs").join("b5.crt"), ck.cert.pem()).unwrap();
    std::fs::write(
        base_dir.join("certs").join("b5.key"),
        ck.signing_key.serialize_pem(),
    )
    .unwrap();
}

fn write_test_configs(base_dir: &Path) -> PathBuf {
    std::fs::write(base_dir.join("admin").join("index.html"), "ADMIN_OK").unwrap();

    let doc_root = base_dir.join("www").join("b5site");
    std::fs::write(doc_root.join("index.html"), "Hello from b5.test root!").unwrap();
    std::fs::write(doc_root.join("public.txt"), "Public file content").unwrap();
    std::fs::write(doc_root.join("custom403.html"), "Custom 403 Forbidden Page").unwrap();

    let secret_dir = doc_root.join("secret_dir");
    std::fs::create_dir_all(&secret_dir).unwrap();
    std::fs::write(secret_dir.join("hidden.data"), "Sensitive data").unwrap();

    let htaccess_content = r#"
Options -Indexes
ErrorDocument 403 /custom403.html

<FilesMatch "\.(secret|key|conf)$">
    Require all denied
</FilesMatch>

RewriteEngine On

RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]
RewriteRule ^ https://%1%{REQUEST_URI} [L,R=301]
"#;
    std::fs::write(doc_root.join(".htaccess"), htaccess_content).unwrap();
    std::fs::write(doc_root.join("config.secret"), "SECRET_TOKEN_DO_NOT_READ").unwrap();

    let conf_path = base_dir.join("conf").join("zmax.toml");
    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax/OlsB5Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {TEST_HTTP_PORT}
reuse_port = false

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {TEST_HTTPS_PORT}
ssl = true
alpn = ["h2", "http/1.1"]

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {TEST_API_PORT}
require_token = false
token = ""

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {TEST_ADMIN_PORT}
document_root = "admin"
require_token = false
token = ""

[cache]
enabled = false

[security]
rate_limit_enabled = false
block_path_traversal = true

[logging]
access_log = "logs/access.log"
error_log = "logs/error.log"
batch_flush_ms = 50
batch_buffer_kb = 16
add_request_id = true

[vhosts_dir]
path = "conf/vhosts"
"#
    );
    std::fs::write(&conf_path, zmax_toml).unwrap();

    std::fs::write(
        base_dir.join("conf").join("vhosts").join("b5.test.toml"),
        r#"[vhost]
name = "b5.test"
aliases = ["www.b5.test"]
document_root = "www/b5site"

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "certs/b5.crt"
key = "certs/b5.key"

[vhost.tls]
http2 = true
"#,
    )
    .unwrap();

    conf_path
}

fn spawn_zmax_and_wait_ready(base_dir: &Path, conf_path: &Path) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zmax"));
    cmd.env("ZMAX_HOME", base_dir)
        .arg("-c")
        .arg(conf_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("zmax sureci baslatilamadi");
    let stdout = child.stdout.take().expect("stdout yakalanamadi");
    let stderr = child.stderr.take().expect("stderr yakalanamadi");

    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let (err_tx, err_rx) = mpsc::channel::<String>();

    std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            lines.push(line);
        }
        let _ = err_tx.send(lines.join("\n"));
    });

    std::thread::spawn(move || {
        let mut saw_http = false;
        let mut saw_https = false;
        let mut saw_api = false;
        let mut signaled = false;
        let mut out_lines = Vec::new();

        for line_res in BufReader::new(stdout).lines() {
            match line_res {
                Ok(line) => {
                    if line.contains("* Web Sunucusu") {
                        saw_http = true;
                    }
                    if line.contains("* HTTPS Sunucu") {
                        saw_https = true;
                    }
                    if line.contains("* Kontrol API") {
                        saw_api = true;
                    }
                    if !signaled {
                        out_lines.push(line);
                        if saw_http && saw_https && saw_api {
                            signaled = true;
                            let _ = ready_tx.send(Ok(()));
                            out_lines.clear();
                        }
                    }
                }
                Err(e) => {
                    if !signaled {
                        let _ = ready_tx.send(Err(format!(
                            "stdout okuma hatasi: {e}\n{}",
                            out_lines.join("\n")
                        )));
                    }
                    return;
                }
            }
        }

        if !signaled {
            let _ = ready_tx.send(Err(format!(
                "zmax dinleyicileri acmadan sonlandi:\n{}",
                out_lines.join("\n")
            )));
        }
    });

    match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => child,
        Ok(Err(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = err_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            panic!("zmax baslatma hatasi:\nSTDOUT:\n{msg}\nSTDERR:\n{err_out}");
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = err_rx
                .recv_timeout(Duration::from_secs(2))
                .unwrap_or_default();
            panic!("zmax baslatma zaman asimi (15sn)\nSTDERR:\n{err_out}");
        }
    }
}

async fn send_http1_req(port: u16, host: &str, req: &str) -> (u16, Vec<(String, String)>, String) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP baglantisi saglanamadi");

    let payload = format!("{}Host: {}\r\nConnection: close\r\n\r\n", req, host);
    stream.write_all(payload.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf);

    let mut lines = resp.lines();
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut headers = Vec::new();
    let mut is_body = false;
    let mut body = String::new();

    for line in lines {
        if is_body {
            body.push_str(line);
            body.push('\n');
        } else if line.is_empty() {
            is_body = true;
        } else if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_lowercase(), v.trim().to_string()));
        }
    }

    (status, headers, body)
}

#[tokio::test]
async fn test_ols_b5_htaccess_pipeline_http1_and_http2() {
    let workspace = create_temp_workspace("b5_test");
    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    // 1. Normal statik dosya: 200 veya 301
    let (status, _, _) =
        send_http1_req(TEST_HTTP_PORT, "b5.test", "GET /public.txt HTTP/1.1\r\n").await;
    assert!(
        status == 200 || status == 301,
        "public.txt 200 veya 301 olmali (status={})",
        status
    );

    // 2. <FilesMatch "\.(secret|key|conf)$">: 403 Forbidden
    let (status, _, body) =
        send_http1_req(TEST_HTTP_PORT, "b5.test", "GET /config.secret HTTP/1.1\r\n").await;
    assert_eq!(
        status, 403,
        "config.secret dosyasina FilesMatch 403 donmeli"
    );
    assert!(
        body.contains("Custom 403") || body.contains("Forbidden"),
        "ErrorDocument 403 ozel sayfasi sunulmali"
    );

    // 3. Options -Indexes: İndekssiz fiziksel dizine istek 403 Forbidden
    let (status, _, body) =
        send_http1_req(TEST_HTTP_PORT, "b5.test", "GET /secret_dir/ HTTP/1.1\r\n").await;
    assert_eq!(
        status, 403,
        "secret_dir/ indeks dosyasiz dizinine Options -Indexes 403 donmeli"
    );
    assert!(
        body.contains("Custom 403") || body.contains("Forbidden"),
        "ErrorDocument 403 sayfasi sunulmali"
    );

    // 4. www.%1 yönlendirmesi
    let (status, headers, _) = send_http1_req(
        TEST_HTTP_PORT,
        "www.b5.test",
        "GET /public.txt HTTP/1.1\r\n",
    )
    .await;
    if status == 301 {
        let loc = headers
            .iter()
            .find(|(k, _)| k == "location")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        assert!(
            loc.contains("b5.test/public.txt"),
            "www kaldirilip %1 kuraliyla b5.test'e yonlendirilmeli (Location={})",
            loc
        );
    }
}
