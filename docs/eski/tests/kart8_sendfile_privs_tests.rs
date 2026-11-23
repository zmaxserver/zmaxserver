use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

static TEST_SEQ: AtomicUsize = AtomicUsize::new(1);

struct ChildGuard {
    child: Option<Child>,
    temp_dir: PathBuf,
}

impl ChildGuard {
    fn new(child: Child, temp_dir: PathBuf) -> Self {
        Self {
            child: Some(child),
            temp_dir,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

fn next_temp_workspace(tag: &str) -> PathBuf {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "zmax_kart8_int_{}_{}_{}",
        tag,
        std::process::id(),
        seq
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("geçici test dizini oluşturulmalı");
    dir
}

fn pick_test_http_port() -> u16 {
    // AJAN_YAPISI a08 port bloğundan (21080+) her test için ayrı port seç; meşgulse :0'a düş
    let offset = (TEST_SEQ.fetch_add(1, Ordering::Relaxed) % 4) as u16;
    let candidate = format!("127.0.0.1:{}", 21080 + offset);
    if let Ok(l) = TcpListener::bind(&candidate) {
        let p = l.local_addr().unwrap().port();
        drop(l);
        return p;
    }
    let l = TcpListener::bind("127.0.0.1:0").expect("boş loopback port bağlanmalı");
    l.local_addr().unwrap().port()
}

fn resolve_unpriv_pair() -> (&'static str, &'static str) {
    #[cfg(unix)]
    {
        let c_nobody = std::ffi::CString::new("nobody").expect("sabit ASCII");
        // SAFETY: `c_nobody` geçerli NUL-sonlandırmalı C dizesidir.
        let has_nobody_grp = !unsafe { libc::getgrnam(c_nobody.as_ptr()) }.is_null();
        if has_nobody_grp {
            ("nobody", "nobody")
        } else {
            ("nobody", "nogroup")
        }
    }
    #[cfg(not(unix))]
    {
        ("nobody", "nobody")
    }
}

fn write_test_site(
    base: &Path,
    http_port: u16,
    user: &str,
    group: &str,
    payload: &[u8],
) -> PathBuf {
    let conf_dir = base.join("conf");
    let vhosts_dir = conf_dir.join("vhosts");
    let modules_dir = base.join("modules");
    let www_dir = base.join("www").join("html");
    let admin_dir = base.join("admin");
    let logs_dir = base.join("logs");

    for d in [
        &conf_dir,
        &vhosts_dir,
        &modules_dir,
        &www_dir,
        &admin_dir,
        &logs_dir,
    ] {
        fs::create_dir_all(d).expect("alt dizin oluşturulmalı");
    }

    fs::write(admin_dir.join("index.html"), b"admin").expect("admin index yazılmalı");
    fs::write(www_dir.join("large.bin"), payload).expect("büyük test dosyası yazılmalı");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for d in [
            base,
            &conf_dir,
            &vhosts_dir,
            &modules_dir,
            base.join("www").as_path(),
            &www_dir,
        ] {
            let _ = fs::set_permissions(d, fs::Permissions::from_mode(0o755));
        }
        let _ = fs::set_permissions(www_dir.join("large.bin"), fs::Permissions::from_mode(0o644));
    }

    let zmax_toml = format!(
        r#"[server]
server_name = "ZMax-Kart8-Test"
user = "{user}"
group = "{group}"
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
enabled = false

[cache]
enabled = false
disk_cache_dir = "cachedata"

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

    let vhost_toml = r#"[vhost]
name = "kart8-bin.test"
document_root = "www/html"
index_files = ["index.html"]

[vhost.cache]
enabled = false

[vhost.php]
enabled = false

[vhost.static]
sendfile = true
precompressed = false
"#;
    fs::write(vhosts_dir.join("kart8-bin.test.toml"), vhost_toml).expect("vhost.toml yazılmalı");

    conf_path
}

fn read_http_response(addr: SocketAddr, req_raw: &[u8]) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .expect("zmax HTTP dinleyicisine bağlanılmalı");
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(req_raw).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("HTTP yanıtı sonuna kadar okunmalı");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP başlık/gövde ayracı bulunmalı");
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body = raw[split + 4..].to_vec();
    (head, body)
}

#[test]
fn zmax_binary_plain_tcp_serves_large_static_and_range() {
    let base = next_temp_workspace("plain_tcp_sendfile");
    let port = pick_test_http_port();
    let (user, group) = resolve_unpriv_pair();

    // MAX_STATIC_CACHE_BYTES (2 MiB) eşiğini aşan deterministik içerik
    let payload_len = 2 * 1024 * 1024 + 65_537;
    let payload: Vec<u8> = (0..payload_len)
        .map(|i| ((i * 31 + 7) % 251) as u8)
        .collect();
    let conf_path = write_test_site(&base, port, user, group, &payload);

    let mut child = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", &base)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("zmax ikilisi başlatılmalı");

    let stdout = child.stdout.take().expect("stdout borusu alınmalı");
    let stderr = child.stderr.take().expect("stderr borusu alınmalı");
    let _guard = ChildGuard::new(child, base.clone());

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
        panic!(
            "zmax ikilisi hazır mesajını basmadan sonlandı (son satır: '{}', stderr: '{}')",
            line, err_buf
        );
    }

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    // 1. Düz TCP üzerinde >2 MiB tam dosya aktarımı (Linux'ta sendfile(2), diğerlerinde BufferPool)
    let (head_full, body_full) = read_http_response(
        addr,
        b"GET /large.bin HTTP/1.1\r\nHost: kart8-bin.test\r\nConnection: close\r\n\r\n",
    );
    assert!(head_full.starts_with("HTTP/1.1 200 OK"), "{head_full}");
    assert!(
        head_full.contains("X-Cache: BYPASS"),
        "2 MiB üstü dosya BYPASS/sendfile akış yolundan geçmeli: {head_full}"
    );
    assert_eq!(body_full.len(), payload.len());
    assert_eq!(body_full, payload);

    // 2. Düz TCP üzerinde >2 MiB Range isteği (206 Partial Content)
    let start = 2048usize;
    let end = payload.len() - 1;
    let range_req = format!(
        "GET /large.bin HTTP/1.1\r\nHost: kart8-bin.test\r\nRange: bytes={}-{}\r\nConnection: close\r\n\r\n",
        start, end
    );
    let (head_rng, body_rng) = read_http_response(addr, range_req.as_bytes());
    assert!(
        head_rng.starts_with("HTTP/1.1 206 Partial Content"),
        "{head_rng}"
    );
    assert_eq!(body_rng, payload[start..=end]);
}

#[test]
fn zmax_binary_fails_closed_on_invalid_privilege_user() {
    let base = next_temp_workspace("privs_fail_closed");
    let port = pick_test_http_port();
    let conf_path = write_test_site(
        &base,
        port,
        "zmax_nonexistent_user_99999",
        "bad/group",
        b"hi",
    );

    let output = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .arg("-c")
        .arg(&conf_path)
        .env("ZMAX_HOME", &base)
        .output()
        .expect("zmax ikilisi çalıştırılmalı");

    let _ = fs::remove_dir_all(&base);
    assert!(
        !output.status.success(),
        "Geçersiz yetki düşürme ayarında sunucu fail-closed çıkmalıydı (stdout={}, stderr={})",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Yetki düşürme") || combined.contains("KRİTİK GÜVENLİK HATASI"),
        "Fail-closed güvenlik hata çıktısı bekleniyordu: {combined}"
    );
}

#[cfg(unix)]
#[test]
#[ignore = "Kök (root / euid == 0) yetkisi gerektirir; VM'de root ile --ignored olarak çalıştırın"]
fn root_drop_privileges_revokes_setuid_zero_integration() {
    assert!(
        zmax_core::is_running_as_root(),
        "Bu test root (euid == 0) olarak çalıştırılmalıdır"
    );
    let (user, group) = resolve_unpriv_pair();
    let base = next_temp_workspace("root_priv_revoke");
    let logs = base.join("logs");
    fs::create_dir_all(&logs).unwrap();

    zmax_core::drop_privileges_with_paths(user, group, &[&logs])
        .expect("Kök yetkiden düşürme başarılı olmalı");
    assert!(!zmax_core::is_running_as_root());

    // SAFETY: Yetkisiz süreçte `setuid(0)` çağrısının çekirdek tarafından EPERM ile reddedildiğini sınar.
    let rc = unsafe { libc::setuid(0) };
    let err = std::io::Error::last_os_error();
    assert_ne!(rc, 0);
    assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    let _ = fs::remove_dir_all(&base);
}
