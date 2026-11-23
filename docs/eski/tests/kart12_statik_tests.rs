use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

struct TestPorts {
    http: u16,
    https: u16,
    api: u16,
    admin: u16,
}

impl TestPorts {
    fn pick_unique() -> Self {
        let mut ports = Vec::with_capacity(4);
        let mut listeners = Vec::with_capacity(4);
        for _ in 0..4 {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("Rastgele port alinamadi");
            ports.push(l.local_addr().expect("Adres alinamadi").port());
            listeners.push(l);
        }
        drop(listeners);
        Self {
            http: ports[0],
            https: ports[1],
            api: ports[2],
            admin: ports[3],
        }
    }
}

struct ZmaxTestEnv {
    base_dir: PathBuf,
    ports: TestPorts,
    child: Option<Child>,
}

impl ZmaxTestEnv {
    async fn start() -> Self {
        let ports = TestPorts::pick_unique();
        let unique = format!(
            "zmax_kart12_{}_{}_{}",
            std::process::id(),
            ports.http,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let base_dir = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&base_dir);

        let conf_dir = base_dir.join("conf");
        let vhosts_dir = conf_dir.join("vhosts");
        let ssl_dir = conf_dir.join("ssl");
        let modules_dir = base_dir.join("modules");
        let admin_dir = base_dir.join("admin");
        let logs_dir = base_dir.join("logs");

        std::fs::create_dir_all(&vhosts_dir).unwrap();
        std::fs::create_dir_all(&ssl_dir).unwrap();
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::create_dir_all(&admin_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::create_dir_all(base_dir.join("www").join("html")).unwrap();
        std::fs::write(admin_dir.join("index.html"), "ADMIN_OK").unwrap();

        let zmax_toml = format!(
            r#"
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

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {}
document_root = "admin"

[cache]
enabled = false

[security]
rate_limit_enabled = false
"#,
            ports.http, ports.https, ports.api, ports.admin
        );
        std::fs::write(conf_dir.join("zmax.toml"), zmax_toml).unwrap();

        // 1. Statik vHost 1: Özel error_docs.not_found tanımlı
        let doc_root1 = base_dir.join("www").join("errordoc-site");
        std::fs::create_dir_all(&doc_root1).unwrap();
        std::fs::write(doc_root1.join("index.html"), "SITE1_HOME").unwrap();
        std::fs::write(doc_root1.join("404_custom.html"), "OZEL_404_NOT_FOUND_DOC").unwrap();

        let vh1_conf = r#"[vhost]
name = "errordoc.test"
document_root = "www/errordoc-site"

[vhost.php]
enabled = false

[vhost.rewrite]
try_files = false

[vhost.error_docs]
enabled = true
not_found = "404_custom.html"
"#;
        std::fs::write(vhosts_dir.join("01-errordoc.toml"), vh1_conf).unwrap();

        // 2. Statik vHost 2: error_docs tanımlı değil (yerleşik 404 test)
        let doc_root2 = base_dir.join("www").join("builtin-site");
        std::fs::create_dir_all(&doc_root2).unwrap();
        std::fs::write(doc_root2.join("index.html"), "SITE2_HOME").unwrap();

        let vh2_conf = r#"[vhost]
name = "builtin.test"
document_root = "www/builtin-site"

[vhost.php]
enabled = false

[vhost.rewrite]
try_files = false
"#;
        std::fs::write(vhosts_dir.join("02-builtin.toml"), vh2_conf).unwrap();

        // 3. Statik vHost 3: Saf statik try_files permalink (/hakkimizda/ -> index.html)
        let doc_root3 = base_dir.join("www").join("permalink-site");
        std::fs::create_dir_all(&doc_root3).unwrap();
        std::fs::write(doc_root3.join("index.html"), "STATIK_INDEX_PERMALINK_OK").unwrap();

        let vh3_conf = r#"[vhost]
name = "permalink.test"
document_root = "www/permalink-site"

[vhost.php]
enabled = false

[vhost.rewrite]
enabled = true
try_files = true
"#;
        std::fs::write(vhosts_dir.join("03-permalink.toml"), vh3_conf).unwrap();

        let bin = env!("CARGO_BIN_EXE_zmax");
        let mut child = Command::new(bin)
            .env("ZMAX_HOME", &base_dir)
            .env("ZMAX_HTTP_PORT", ports.http.to_string())
            .env("ZMAX_HTTPS_PORT", ports.https.to_string())
            .env("ZMAX_API_PORT", ports.api.to_string())
            .env("ZMAX_ADMIN_PORT", ports.admin.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("zmax sunucusu baslatilamadi");

        let stdout = child.stdout.take().expect("stdout alinamadi");
        let stderr = child.stderr.take().expect("stderr alinamadi");

        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                eprintln!("[zmax stdout] {}", line);
            }
        });
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                eprintln!("[zmax stderr] {}", line);
            }
        });

        // Port dinlenene kadar bekle
        let mut ready = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if TcpStream::connect(("127.0.0.1", ports.http)).await.is_ok() {
                ready = true;
                break;
            }
        }
        assert!(ready, "zmax sunucusu beklenen surede baslamadi");

        Self {
            base_dir,
            ports,
            child: Some(child),
        }
    }

    async fn send_raw_http(&self, host: &str, path: &str) -> (u16, Vec<(String, String)>, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.ports.http))
            .await
            .expect("tcp baglantisi kurulamadi");
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: zmax-kart12-test\r\n\r\n",
            path, host
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let raw = String::from_utf8_lossy(&buf).to_string();

        let (headers_part, body_part) = match raw.split_once("\r\n\r\n") {
            Some((h, b)) => (h, b),
            None => (raw.as_str(), ""),
        };

        let mut lines = headers_part.lines();
        let status_line = lines.next().unwrap_or("");
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let mut headers = Vec::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
            }
        }

        (status_code, headers, body_part.to_string())
    }
}

impl Drop for ZmaxTestEnv {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

#[tokio::test]
async fn missing_path_returns_404_with_error_doc() {
    let env = ZmaxTestEnv::start().await;

    // 1. error_docs.not_found tanımlı vHost: özel hata sayfası döner
    let (status, _headers, body) = env.send_raw_http("errordoc.test", "/olmayan-sayfa-123").await;
    assert_eq!(status, 404, "Olmayan yola 404 donmeli");
    assert!(
        body.contains("OZEL_404_NOT_FOUND_DOC"),
        "error_docs.not_found icerigi donmeli, donen: {}",
        body
    );

    // 2. error_docs tanımlı olmayan vHost: yerleşik 404 döner, gövde boş olmamalı
    let (status2, _headers2, body2) = env.send_raw_http("builtin.test", "/tanimsiz-yol-456").await;
    assert_eq!(status2, 404, "Yerlesik vhost'ta olmayan yola 404 donmeli");
    assert!(
        !body2.trim().is_empty(),
        "Yerlesik 404 yanit govdesi bos olmamali"
    );
    assert!(
        body2.contains("404 Not Found"),
        "Yerlesik 404 govdesi 404 Not Found icermeli, donen: {}",
        body2
    );
}

#[tokio::test]
async fn unknown_host_returns_444_or_403() {
    let env = ZmaxTestEnv::start().await;

    // Tanımsız / bilinmeyen bir host başlığı ile istek gönderildiğinde:
    // Güvenli varsayılan olarak 403 Forbidden dönmeli ve hiçbir vHost içeriği sızmamalı
    let (status, headers, body) =
        env.send_raw_http("bilinmeyen-alan-adi.com", "/").await;
    assert_eq!(
        status, 403,
        "Bilinmeyen host basliginda guvenli 403 Forbidden donmeli"
    );

    // Baglanti kapatilmali
    let conn_header = headers
        .iter()
        .find(|(k, _)| k == "connection")
        .map(|(_, v)| v.as_str());
    assert_eq!(
        conn_header,
        Some("close"),
        "Connection: close basligi bulunmali"
    );

    // Diger vHost'larin ozel icerikleri sizmamali
    assert!(
        !body.contains("SITE1_HOME"),
        "VHost 1 icerigi sizmamali"
    );
    assert!(
        !body.contains("SITE2_HOME"),
        "VHost 2 icerigi sizmamali"
    );
    assert!(
        !body.contains("STATIK_INDEX_PERMALINK_OK"),
        "VHost 3 icerigi sizmamali"
    );
}

#[tokio::test]
async fn try_files_permalink_resolves_index() {
    let env = ZmaxTestEnv::start().await;

    // Saf statik vHost (PHP kapalı): /hakkimizda/ gibi fiziki olmayan yol try_files ile index.html'e çözülmeli
    let (status, _headers, body) = env.send_raw_http("permalink.test", "/hakkimizda/").await;
    assert_eq!(
        status, 200,
        "try_files ile statik permalink 200 donmeli, 404 olmamali"
    );
    assert_eq!(
        body.trim(),
        "STATIK_INDEX_PERMALINK_OK",
        "index.html govdesi donmeli"
    );

    // Alt yol /iletisim de index.html'e çözülmeli
    let (status_alt, _headers_alt, body_alt) =
        env.send_raw_http("permalink.test", "/iletisim").await;
    assert_eq!(
        status_alt, 200,
        "/iletisim permalink 200 donmeli"
    );
    assert_eq!(
        body_alt.trim(),
        "STATIK_INDEX_PERMALINK_OK",
        "index.html govdesi donmeli"
    );
}
