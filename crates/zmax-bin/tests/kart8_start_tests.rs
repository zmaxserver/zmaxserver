//! Kart 8 başlatma güvenliği testleri (gerçek `zmax` süreci):
//! `server.user` / `server.group` verilmeyen yapılandırmalar (gönderilen `conf/zmax.toml` ve
//! varsa `packed/*/conf/zmax.toml` dahil) root OLMAYAN kullanıcıyla başlamalıdır.
//! root'ta boş user/group ise sunucu fail-closed reddetmelidir (yalnız Unix + root VM, `--ignored`).

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy)]
struct TestPorts {
    http: u16,
    https: u16,
    api: u16,
    admin: u16,
}

impl TestPorts {
    fn pick_unique() -> Self {
        let listeners: Vec<std::net::TcpListener> = (0..4)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").expect("rastgele port alınamadı"))
            .collect();
        let ports: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().expect("adres alınamadı").port())
            .collect();
        drop(listeners);
        Self {
            http: ports[0],
            https: ports[1],
            api: ports[2],
            admin: ports[3],
        }
    }
}

struct ZmaxGuard {
    child: Child,
    root: PathBuf,
}

impl Drop for ZmaxGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn new_root(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let root = std::env::temp_dir().join(format!(
        "zmax_kart8_start_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    for d in ["conf/vhosts", "modules", "logs", "cache", "admin"] {
        fs::create_dir_all(root.join(d)).expect("çalışma dizini oluşturulamadı");
    }
    fs::write(root.join("admin").join("index.html"), b"<h1>Admin</h1>")
        .expect("admin/index.html yazılamadı");
    root
}

/// Gönderilen yapılandırmadaki dinleyici portlarını/adreslerini yerel boş portlarla değiştirir
/// (`user`/`group` satırlarına DOKUNMAZ).
fn patch_listeners(conf: &str, ports: TestPorts) -> String {
    let mut out = String::with_capacity(conf.len());
    let mut section = String::new();
    for line in conf.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.to_string();
        }
        let key = trimmed.split('=').next().unwrap_or("").trim();
        let replaced = match (section.as_str(), key) {
            ("[listeners.http]", "port") => Some(format!("port = {}", ports.http)),
            ("[listeners.https]", "port") => Some(format!("port = {}", ports.https)),
            ("[listeners.api]", "port") => Some(format!("port = {}", ports.api)),
            ("[listeners.admin]", "port") => Some(format!("port = {}", ports.admin)),
            (
                "[listeners.http]" | "[listeners.https]" | "[listeners.api]" | "[listeners.admin]",
                "address",
            ) => Some("address = \"127.0.0.1\"".to_string()),
            _ => None,
        };
        out.push_str(&replaced.unwrap_or_else(|| line.to_string()));
        out.push('\n');
    }
    out
}

fn spawn_zmax(root: &Path) -> Result<ZmaxGuard, String> {
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
        .map_err(|e| format!("zmax başlatılamadı ({}): {}", exe_path, e))?;

    let stdout = child.stdout.take().expect("stdout alınamadı");
    let stderr = child.stderr.take().expect("stderr alınamadı");

    let (tx, rx) = mpsc::channel::<Result<(), String>>();
    std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut signaled = false;
        // Hazır olduktan sonra da okumaya devam eder: boru kapanırsa sunucunun println!'i patlamasın.
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => {
                    if !signaled {
                        if l.contains("hazir!") {
                            signaled = true;
                            let _ = tx.send(Ok(()));
                        } else {
                            seen.push(l);
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
                "zmax hazır mesajı vermeden stdout kapandı:\n{}",
                seen.join("\n")
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
        Ok(Ok(())) => Ok(ZmaxGuard {
            child,
            root: root.to_path_buf(),
        }),
        Ok(Err(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = stderr_handle.join().unwrap_or_default();
            let _ = fs::remove_dir_all(root);
            Err(format!("{}\nstderr:\n{}", msg, err_out))
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            let err_out = stderr_handle.join().unwrap_or_default();
            let _ = fs::remove_dir_all(root);
            Err(format!(
                "zmax 20 sn içinde hazır olmadı\nstderr:\n{}",
                err_out
            ))
        }
    }
}

fn http_get_status_line(port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("HTTP portuna bağlanılamadı");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

/// `user`/`group` HİÇ verilmeyen asgari yapılandırma root olmayan kullanıcıyla başlamalıdır.
#[test]
fn kart8_start_without_user_group_nonroot() {
    let root = new_root("nouser");
    let ports = TestPorts::pick_unique();
    let conf = format!(
        r#"[server]
server_name = "kart8-start"
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
access_log = "logs/access.log"
error_log = "logs/error.log"
"#,
        http = ports.http,
        https = ports.https,
        api = ports.api,
        admin = ports.admin,
    );
    assert!(
        !conf.contains("user ="),
        "test yapılandırması user içermemeli"
    );
    fs::write(root.join("conf").join("zmax.toml"), conf).unwrap();
    #[cfg(unix)]
    // SAFETY: `geteuid` salt-okunur POSIX sorgusudur.
    if unsafe { libc::geteuid() } == 0 {
        // root'ta boş user/group fail-closed olmalıdır; bu test yalnız root OLMAYAN durumu sınar.
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let guard = spawn_zmax(&root).unwrap_or_else(|e| panic!("zmax başlamadı: {}", e));
    let status = http_get_status_line(ports.http);
    assert!(
        status.starts_with("HTTP/1.1 "),
        "HTTP yanıtı alınamadı: '{}'",
        status
    );
    drop(guard);
}

/// Gönderilen `conf/zmax.toml` (user/group yorumlu) ve varsa `packed/*/conf/zmax.toml`
/// kopyaları root olmayan kullanıcıyla başlamalıdır.
#[test]
fn kart8_start_with_shipped_conf_nonroot() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("çalışma alanı kökü bulunamadı")
        .to_path_buf();
    let mut confs = vec![workspace.join("conf").join("zmax.toml")];
    if let Ok(rd) = fs::read_dir(workspace.join("packed")) {
        for e in rd.flatten() {
            let c = e.path().join("conf").join("zmax.toml");
            if c.is_file() {
                confs.push(c);
            }
        }
    }
    assert!(confs[0].is_file(), "gönderilen conf/zmax.toml bulunamadı");

    #[cfg(unix)]
    // SAFETY: `geteuid` salt-okunur POSIX sorgusudur.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    for (i, conf_path) in confs.iter().enumerate() {
        let raw = fs::read_to_string(conf_path)
            .unwrap_or_else(|e| panic!("{} okunamadı: {}", conf_path.display(), e));
        let root = new_root(&format!("shipped{}", i));
        let ports = TestPorts::pick_unique();
        fs::write(
            root.join("conf").join("zmax.toml"),
            patch_listeners(raw.trim_start_matches('\u{feff}'), ports),
        )
        .unwrap();
        let guard = spawn_zmax(&root)
            .unwrap_or_else(|e| panic!("{} ile zmax başlamadı: {}", conf_path.display(), e));
        let status = http_get_status_line(ports.http);
        assert!(
            status.starts_with("HTTP/1.1 "),
            "{}: HTTP yanıtı alınamadı: '{}'",
            conf_path.display(),
            status
        );
        drop(guard);
    }
}

/// root + boş user/group => süreç hata ile çıkmalı (fail-closed). Yalnız root VM'de:
/// `cargo test -p zmax-bin --test kart8_start_tests -- --ignored`
#[cfg(unix)]
#[test]
#[ignore = "root (euid == 0) gerektirir; Linux VM'de --ignored ile çalıştırın"]
fn kart8_root_with_empty_user_group_fails_closed() {
    // SAFETY: `geteuid` salt-okunur POSIX sorgusudur.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "bu test root olarak koşmalıdır"
    );
    let root = new_root("rootempty");
    let ports = TestPorts::pick_unique();
    let conf = format!(
        "[server]\nworkers = 1\n\n[listeners.http]\nenabled = true\naddress = \"127.0.0.1\"\nport = {}\n\n[listeners.https]\nenabled = false\nport = {}\n\n[listeners.api]\nenabled = true\naddress = \"127.0.0.1\"\nport = {}\nrequire_token = false\n\n[listeners.admin]\nenabled = true\naddress = \"127.0.0.1\"\nport = {}\ndocument_root = \"admin\"\nrequire_token = false\n\n[vhosts_dir]\npath = \"conf/vhosts\"\n",
        ports.http, ports.https, ports.api, ports.admin
    );
    fs::write(root.join("conf").join("zmax.toml"), conf).unwrap();
    let err = spawn_zmax(&root)
        .err()
        .expect("root + boş user/group başlamamalıydı");
    assert!(
        err.contains("fail-closed"),
        "beklenen fail-closed hatası yok: {}",
        err
    );
}

fn minimal_conf(ports: TestPorts, server_extra: &str) -> String {
    format!(
        "[server]\nserver_name = \"kart8-start\"\nworkers = 2\n{extra}\n\n[listeners.http]\nenabled = true\naddress = \"127.0.0.1\"\nport = {http}\n\n[listeners.https]\nenabled = false\naddress = \"127.0.0.1\"\nport = {https}\nssl = false\n\n[listeners.api]\nenabled = true\naddress = \"127.0.0.1\"\nport = {api}\nrequire_token = false\nssl = false\n\n[listeners.admin]\nenabled = true\naddress = \"127.0.0.1\"\nport = {admin}\ndocument_root = \"admin\"\nrequire_token = false\nssl = false\n\n[vhosts_dir]\npath = \"conf/vhosts\"\n\n[logging]\naccess_log = \"logs/access.log\"\nerror_log = \"logs/error.log\"\n",
        extra = server_extra,
        http = ports.http,
        https = ports.https,
        api = ports.api,
        admin = ports.admin,
    )
}

/// `zmax --fix-tls-perms` root olmayan kullanıcıda hata vermeden (işlem yapmadan) çıkar.
#[test]
fn kart8_fix_tls_perms_nonroot_is_noop_success() {
    #[cfg(unix)]
    // SAFETY: `geteuid` salt-okunur POSIX sorgusudur.
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = new_root("fixperms");
    let ports = TestPorts::pick_unique();
    fs::write(root.join("conf").join("zmax.toml"), minimal_conf(ports, "")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_zmax"))
        .env("ZMAX_HOME", &root)
        .arg("-c")
        .arg(root.join("conf").join("zmax.toml"))
        .arg("--fix-tls-perms")
        .output()
        .expect("zmax çalıştırılamadı");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = fs::remove_dir_all(&root);
    assert!(out.status.success(), "çıkış kodu 0 beklenirdi: {stdout}");
    assert!(
        stdout.contains("--fix-tls-perms root gerektirir"),
        "çıktı: {stdout}"
    );
}

/// Yetki düşürme yolu (user/group verilmiş): geçici dizin tahmin edilebilir `/tmp/zmax` DEĞİL,
/// `<kök>/tmp` altında hazırlanır (Windows'ta gerçek süreçle doğrulanır; Unix'te birim testleri + root VM).
#[cfg(not(unix))]
#[test]
fn kart8_start_with_user_group_prepares_private_tmp_under_root() {
    let root = new_root("tmpdir");
    let ports = TestPorts::pick_unique();
    fs::write(
        root.join("conf").join("zmax.toml"),
        minimal_conf(
            ports,
            "user = \"nobody\"\ngroup = \"nobody\"\ntmp_dir = \"run/gecici\"",
        ),
    )
    .unwrap();
    let guard = spawn_zmax(&root).unwrap_or_else(|e| panic!("zmax başlamadı: {}", e));
    assert!(
        root.join("run").join("gecici").is_dir(),
        "server.tmp_dir ile belirtilen dizin hazırlanmadı"
    );
    drop(guard);
}
