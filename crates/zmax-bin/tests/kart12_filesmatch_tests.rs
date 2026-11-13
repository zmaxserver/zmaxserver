//! Kart 12 Hazırlık B Entegrasyon Testleri:
//! 1. <FilesMatch> Deny/Require all denied: .env, .git, wp-config.php, xmlrpc.php, readme.html, license.txt -> 403
//! 2. Dizin listeleme kapali: autoindex off modunda indekssiz dizine istek -> 403
//! 3. Tehlikeli uzantilar: \.(sql|bak|log|sh|swp)$ -> 403
//! 4. Normal dosyalar -> 200 OK

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Copy)]
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
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("port baglanamadi");
            ports.push(l.local_addr().expect("local_addr alinamadi").port());
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
    let dir = std::env::temp_dir().join(format!("zmax_kart12_{}_{}_{}", tag, std::process::id(), nanos));
    std::fs::create_dir_all(dir.join("conf").join("vhosts")).unwrap();
    std::fs::create_dir_all(dir.join("certs")).unwrap();
    std::fs::create_dir_all(dir.join("logs")).unwrap();
    std::fs::create_dir_all(dir.join("admin")).unwrap();
    std::fs::create_dir_all(dir.join("modules")).unwrap();
    let site_dir = dir.join("www").join("kart12site");
    std::fs::create_dir_all(&site_dir).unwrap();

    // Normal dosyalar
    std::fs::write(site_dir.join("index.html"), "Hello from Kart12 index!").unwrap();
    std::fs::write(site_dir.join("normal.html"), "Normal HTML Content").unwrap();

    // Korunan ve tehlikeli dosyalar
    std::fs::write(site_dir.join(".env"), "DATABASE_PASSWORD=SuperSecretPassWord123").unwrap();
    std::fs::write(site_dir.join("wp-config.php"), "<?php define('DB_PASSWORD', 'secret');").unwrap();
    std::fs::write(site_dir.join("xmlrpc.php"), "<?php // XML-RPC endpoint").unwrap();
    std::fs::write(site_dir.join("readme.html"), "WordPress Readme content").unwrap();
    std::fs::write(site_dir.join("license.txt"), "WordPress License terms").unwrap();
    std::fs::write(site_dir.join("backup.sql"), "DROP DATABASE production;").unwrap();
    std::fs::write(site_dir.join("archive.bak"), "BINARY_BACKUP_DUMP").unwrap();
    std::fs::write(site_dir.join("access.log"), "2026-11-12 10:00:00 GET / 200").unwrap();
    std::fs::write(site_dir.join("deploy.sh"), "#!/bin/bash\necho deploy").unwrap();
    std::fs::write(site_dir.join("file.swp"), "VIM_SWAP_FILE_DATA").unwrap();

    // .git dizini ve dosyasi
    let git_dir = site_dir.join(".git");
    std::fs::create_dir_all(&git_dir).unwrap();
    std::fs::write(git_dir.join("config"), "[core]\nrepositoryformatversion = 0").unwrap();

    // autoindex testi icin indekssiz alt dizin
    let empty_dir = site_dir.join("private_dir");
    std::fs::create_dir_all(&empty_dir).unwrap();
    std::fs::write(empty_dir.join("subfile.txt"), "secret subfile").unwrap();

    dir
}

fn write_test_certs(base_dir: &Path) {
    let ck = rcgen::generate_simple_self_signed(vec!["kart12.test".to_string()]).unwrap();
    std::fs::write(base_dir.join("certs").join("kart12.crt"), ck.cert.pem()).unwrap();
    std::fs::write(
        base_dir.join("certs").join("kart12.key"),
        ck.signing_key.serialize_pem(),
    )
    .unwrap();
}

fn write_test_configs(base_dir: &Path, http_port: u16, https_port: u16, api_port: u16, admin_port: u16) -> PathBuf {
    std::fs::write(base_dir.join("admin").join("index.html"), "ADMIN_OK").unwrap();

    let conf_path = base_dir.join("conf").join("zmax.toml");
    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax/Kart12Test"
workers = 2

[listeners.http]
enabled = true
address = "127.0.0.1"
port = {http_port}
reuse_port = false

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {https_port}
ssl = true
alpn = ["h2", "http/1.1"]

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {api_port}
require_token = false
token = ""

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {admin_port}
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
        base_dir.join("conf").join("vhosts").join("kart12.test.toml"),
        r#"[vhost]
name = "kart12.test"
document_root = "www/kart12site"
autoindex = false

[vhost.security]
block_dangerous_files = true

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "certs/kart12.crt"
key = "certs/kart12.key"
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
        let mut saw_api = false;
        let mut signaled = false;
        let mut out_lines = Vec::new();

        for line_res in BufReader::new(stdout).lines() {
            match line_res {
                Ok(line) => {
                    if line.contains("* Web Sunucusu") {
                        saw_http = true;
                    }
                    if line.contains("* Kontrol API") {
                        saw_api = true;
                    }
                    if !signaled {
                        out_lines.push(line);
                        if saw_http && saw_api {
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
async fn dot_env_blocked_403() {
    let ports = TestPorts::pick_unique();
    let http_port = ports.http;
    let https_port = ports.https;
    let api_port = ports.api;
    let admin_port = ports.admin;

    let workspace = create_temp_workspace("dotenv");
    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace, http_port, https_port, api_port, admin_port);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    let (status, _, body) = send_http1_req(http_port, "kart12.test", "GET /.env HTTP/1.1\r\n").await;
    assert_eq!(status, 403, "/.env icin 403 Forbidden donmeli");
    assert!(!body.contains("SuperSecretPassWord123"), ".env dosya icerigi sizdirilmamali!");

    // Ek test: wp-config.php, xmlrpc.php, readme.html, license.txt
    let (s_wp, _, b_wp) = send_http1_req(http_port, "kart12.test", "GET /wp-config.php HTTP/1.1\r\n").await;
    assert_eq!(s_wp, 403, "/wp-config.php icin 403 Forbidden donmeli");
    assert!(!b_wp.contains("define('DB_PASSWORD'"), "wp-config.php icerigi sizdirilmamali!");

    let (s_xml, _, _) = send_http1_req(http_port, "kart12.test", "GET /xmlrpc.php HTTP/1.1\r\n").await;
    assert_eq!(s_xml, 403, "/xmlrpc.php icin 403 Forbidden donmeli");

    let (s_readme, _, _) = send_http1_req(http_port, "kart12.test", "GET /readme.html HTTP/1.1\r\n").await;
    assert_eq!(s_readme, 403, "/readme.html icin 403 Forbidden donmeli");

    let (s_lic, _, _) = send_http1_req(http_port, "kart12.test", "GET /license.txt HTTP/1.1\r\n").await;
    assert_eq!(s_lic, 403, "/license.txt icin 403 Forbidden donmeli");
}

#[tokio::test]
async fn dot_git_blocked_403() {
    let ports = TestPorts::pick_unique();
    let http_port = ports.http;
    let https_port = ports.https;
    let api_port = ports.api;
    let admin_port = ports.admin;

    let workspace = create_temp_workspace("dotgit");
    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace, http_port, https_port, api_port, admin_port);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    let (status_cfg, _, body_cfg) = send_http1_req(http_port, "kart12.test", "GET /.git/config HTTP/1.1\r\n").await;
    assert_eq!(status_cfg, 403, "/.git/config icin 403 Forbidden donmeli");
    assert!(!body_cfg.contains("repositoryformatversion"), ".git/config icerigi sizdirilmamali!");

    let (status_git, _, _) = send_http1_req(http_port, "kart12.test", "GET /.git HTTP/1.1\r\n").await;
    assert_eq!(status_git, 403, "/.git icin 403 Forbidden donmeli");
}

#[tokio::test]
async fn sql_extension_blocked_403() {
    let ports = TestPorts::pick_unique();
    let http_port = ports.http;
    let https_port = ports.https;
    let api_port = ports.api;
    let admin_port = ports.admin;

    let workspace = create_temp_workspace("sqlext");
    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace, http_port, https_port, api_port, admin_port);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    // .sql
    let (s_sql, _, b_sql) = send_http1_req(http_port, "kart12.test", "GET /backup.sql HTTP/1.1\r\n").await;
    assert_eq!(s_sql, 403, "/backup.sql icin 403 Forbidden donmeli");
    assert!(!b_sql.contains("DROP DATABASE"), "SQL icerigi sizdirilmamali!");

    // .bak
    let (s_bak, _, _) = send_http1_req(http_port, "kart12.test", "GET /archive.bak HTTP/1.1\r\n").await;
    assert_eq!(s_bak, 403, "/archive.bak icin 403 Forbidden donmeli");

    // .log
    let (s_log, _, _) = send_http1_req(http_port, "kart12.test", "GET /access.log HTTP/1.1\r\n").await;
    assert_eq!(s_log, 403, "/access.log icin 403 Forbidden donmeli");

    // .sh
    let (s_sh, _, _) = send_http1_req(http_port, "kart12.test", "GET /deploy.sh HTTP/1.1\r\n").await;
    assert_eq!(s_sh, 403, "/deploy.sh icin 403 Forbidden donmeli");

    // .swp
    let (s_swp, _, _) = send_http1_req(http_port, "kart12.test", "GET /file.swp HTTP/1.1\r\n").await;
    assert_eq!(s_swp, 403, "/file.swp icin 403 Forbidden donmeli");
}

#[tokio::test]
async fn directory_listing_disabled_403() {
    let ports = TestPorts::pick_unique();
    let http_port = ports.http;
    let https_port = ports.https;
    let api_port = ports.api;
    let admin_port = ports.admin;

    let workspace = create_temp_workspace("dirlist");
    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace, http_port, https_port, api_port, admin_port);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    // İndekssiz fiziksel alt dizin
    let (status, _, body) = send_http1_req(http_port, "kart12.test", "GET /private_dir/ HTTP/1.1\r\n").await;
    assert_eq!(status, 403, "autoindex kapaliyken indeks dosyasiz dizine istek 403 Forbidden donmeli");
    assert!(!body.contains("subfile.txt"), "Dizin listesi veya dosya icerigi gosterilmemeli!");

    // Slash olmadan da dizin kontrolü
    let (status_noslash, _, _) = send_http1_req(http_port, "kart12.test", "GET /private_dir HTTP/1.1\r\n").await;
    assert_eq!(status_noslash, 403, "autoindex kapaliyken indeks dosyasiz dizine (slashsiz) istek 403 Forbidden donmeli");
}

#[tokio::test]
async fn normal_file_served_200() {
    let ports = TestPorts::pick_unique();
    let http_port = ports.http;
    let https_port = ports.https;
    let api_port = ports.api;
    let admin_port = ports.admin;

    let workspace = create_temp_workspace("normal");
    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace, http_port, https_port, api_port, admin_port);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    // Normal dosya
    let (status_norm, _, body_norm) = send_http1_req(http_port, "kart12.test", "GET /normal.html HTTP/1.1\r\n").await;
    assert_eq!(status_norm, 200, "Normal statik dosya 200 OK donmeli");
    assert!(body_norm.contains("Normal HTML Content"), "Normal dosya icerigi dogru donmeli");

    // Root index.html
    let (status_idx, _, body_idx) = send_http1_req(http_port, "kart12.test", "GET / HTTP/1.1\r\n").await;
    assert_eq!(status_idx, 200, "Kok dizin index.html ile 200 OK donmeli");
    assert!(body_idx.contains("Hello from Kart12 index!"), "Index icerigi dogru donmeli");
}

#[tokio::test]
async fn autoindex_rewrite_precedence_pretty_200() {
    let ports = TestPorts::pick_unique();
    let http_port = ports.http;
    let https_port = ports.https;
    let api_port = ports.api;
    let admin_port = ports.admin;

    let workspace = create_temp_workspace("pretty200");
    let doc_root = workspace.join("www").join("kart12site");

    // Fiziksel indekssiz pretty/ dizini oluştur
    let pretty_dir = doc_root.join("pretty");
    std::fs::create_dir_all(&pretty_dir).unwrap();
    std::fs::write(pretty_dir.join("inner.txt"), "inner file").unwrap();

    // .htaccess içinde rewrite kuralı: ^pretty/?$ -> /normal.html
    let htaccess = "RewriteEngine On\nRewriteRule ^pretty/?$ /normal.html [L]\n";
    std::fs::write(doc_root.join(".htaccess"), htaccess).unwrap();

    write_test_certs(&workspace);
    let conf_path = write_test_configs(&workspace, http_port, https_port, api_port, admin_port);

    let child = spawn_zmax_and_wait_ready(&workspace, &conf_path);
    let _guard = ProcessAndDirGuard {
        child: Some(child),
        base_dir: workspace.clone(),
    };

    // İndekssiz pretty/ dizinine istek: rewrite kuralı autoindex'ten önce çalışıp normal.html sunmalı (200 OK)
    let (status, _, body) = send_http1_req(http_port, "kart12.test", "GET /pretty/ HTTP/1.1\r\n").await;
    assert_eq!(status, 200, "Rewrite kurali autoindex 403 oncesinde calismali ve 200 OK donmeli");
    assert!(body.contains("Normal HTML Content"), "normal.html icerigi sunulmali!");

    // Slashsiz /pretty istegi de 200 OK donmeli
    let (status2, _, body2) = send_http1_req(http_port, "kart12.test", "GET /pretty HTTP/1.1\r\n").await;
    assert_eq!(status2, 200, "Rewrite kurali /pretty icin 200 OK donmeli");
    assert!(body2.contains("Normal HTML Content"), "normal.html icerigi sunulmali!");
}
