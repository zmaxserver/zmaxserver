use super::*;
use std::time::UNIX_EPOCH;

fn make_temp_dir(label: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let id = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "zmax_logger_{}_{}_{}",
        label,
        std::process::id(),
        id
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn ncsa_combined_formats_timestamp_numeric_bytes_and_escapes() {
    let dir = make_temp_dir("combined");
    let access = dir.join("logs").join("access.log");
    let error = dir.join("logs").join("error.log");
    let mgr = AsyncLogManager::new(dir.clone(), access.clone(), error, 50, 64);

    // 2026-11-11T21:00:00Z = 1_794_430_800
    let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);
    mgr.log_access(AccessLogEntry {
        timestamp: ts,
        client_ip: "203.0.113.5".to_string(),
        method: "GET".to_string(),
        target: "/urunler?sayfa=2".to_string(),
        protocol: "HTTP/2.0".to_string(),
        status: 200,
        bytes_sent: 0,
        referer: String::new(),
        user_agent: "ZMaxAgent/1.0 \"test\"\r\nline".to_string(),
        request_id: "zmx-1".to_string(),
        duration_ms: 1.25,
        domain: "site.test".to_string(),
        target_path: None,
        json_format: false,
        also_write_global: true,
        max_size_bytes: 0,
    });
    mgr.log_access(AccessLogEntry {
        timestamp: ts,
        client_ip: "198.51.100.7".to_string(),
        method: "POST".to_string(),
        target: "/api/submit".to_string(),
        protocol: "HTTP/1.1".to_string(),
        status: 201,
        bytes_sent: 4096,
        referer: "https://site.test/form".to_string(),
        user_agent: "Mozilla/5.0".to_string(),
        request_id: "zmx-2".to_string(),
        duration_ms: 4.5,
        domain: "site.test".to_string(),
        target_path: None,
        json_format: false,
        also_write_global: true,
        max_size_bytes: 0,
    });
    mgr.log_access(AccessLogEntry {
        timestamp: ts,
        client_ip: "192.0.2.1".to_string(),
        method: "HEAD".to_string(),
        target: "/status".to_string(),
        protocol: "HTTP/1.1".to_string(),
        status: 200,
        bytes_sent: 0,
        referer: "-".to_string(),
        user_agent: "curl/8.0".to_string(),
        request_id: "zmx-3".to_string(),
        duration_ms: 0.5,
        domain: "site.test".to_string(),
        target_path: None,
        json_format: false,
        also_write_global: true,
        max_size_bytes: 0,
    });
    mgr.log_access(AccessLogEntry {
        timestamp: ts,
        client_ip: "192.0.2.2".to_string(),
        method: "GET".to_string(),
        target: "/resim.png".to_string(),
        protocol: "HTTP/1.1".to_string(),
        status: 304,
        bytes_sent: 0,
        referer: "-".to_string(),
        user_agent: "curl/8.0".to_string(),
        request_id: "zmx-4".to_string(),
        duration_ms: 0.8,
        domain: "site.test".to_string(),
        target_path: None,
        json_format: false,
        also_write_global: true,
        max_size_bytes: 0,
    });
    mgr.flush().await;

    let content = tokio::fs::read_to_string(&access).await.unwrap();
    assert!(!content.contains('\r'), "LF sonu beklenir: {content}");
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(
        lines[0],
        "203.0.113.5 - - [11/Nov/2026:21:00:00 +0000] \"GET /urunler?sayfa=2 HTTP/2.0\" 200 - \"-\" \"ZMaxAgent/1.0 \\\"test\\\"  line\""
    );
    assert_eq!(
        lines[1],
        "198.51.100.7 - - [11/Nov/2026:21:00:00 +0000] \"POST /api/submit HTTP/1.1\" 201 4096 \"https://site.test/form\" \"Mozilla/5.0\""
    );
    assert_eq!(
        lines[2],
        "192.0.2.1 - - [11/Nov/2026:21:00:00 +0000] \"HEAD /status HTTP/1.1\" 200 - \"-\" \"curl/8.0\""
    );
    assert_eq!(
        lines[3],
        "192.0.2.2 - - [11/Nov/2026:21:00:00 +0000] \"GET /resim.png HTTP/1.1\" 304 - \"-\" \"curl/8.0\""
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn test_ncsa_combined_matches_panel_parse_access_specification() {
    let dir = make_temp_dir("panel_compat");
    let access = dir.join("logs").join("access.log");
    let error = dir.join("logs").join("error.log");
    let mgr = AsyncLogManager::new(dir.clone(), access.clone(), error, 50, 64);
    let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);

    // [kart-2] Tum yanit tipleri icin formatlama ve '-' kontrolu
    let entries = vec![
        (
            "127.0.0.1",
            "GET",
            "/index.html",
            "HTTP/1.1",
            200,
            512,
            "200 512",
        ),
        (
            "127.0.0.1",
            "HEAD",
            "/index.html",
            "HTTP/1.1",
            200,
            0,
            "200 -",
        ),
        (
            "127.0.0.1",
            "GET",
            "/not-modified.html",
            "HTTP/1.1",
            304,
            0,
            "304 -",
        ),
        (
            "127.0.0.1",
            "POST",
            "/no-content",
            "HTTP/1.1",
            204,
            0,
            "204 -",
        ),
        (
            "127.0.0.1",
            "GET",
            "/range.mp4",
            "HTTP/1.1",
            206,
            1024,
            "206 1024",
        ),
        (
            "127.0.0.1",
            "HEAD",
            "/range.mp4",
            "HTTP/1.1",
            206,
            0,
            "206 -",
        ),
        (
            "127.0.0.1",
            "GET",
            "/app.php",
            "HTTP/1.1",
            200,
            128,
            "200 128",
        ),
        (
            "127.0.0.1",
            "GET",
            "/proxy-api",
            "HTTP/1.1",
            200,
            256,
            "200 256",
        ),
        ("127.0.0.1", "GET", "/cached", "HTTP/1.1", 200, 64, "200 64"),
        (
            "127.0.0.1",
            "GET",
            "/yok.html",
            "HTTP/1.1",
            404,
            32,
            "404 32",
        ),
        (
            "127.0.0.1",
            "HEAD",
            "/yok.html",
            "HTTP/1.1",
            404,
            0,
            "404 -",
        ),
        ("127.0.0.1", "GET", "/yasak", "HTTP/1.1", 403, 30, "403 30"),
        ("127.0.0.1", "GET", "/hata", "HTTP/1.1", 500, 28, "500 28"),
        ("127.0.0.1", "GET", "/h2", "HTTP/2.0", 200, 50, "200 50"),
        ("127.0.0.1", "HEAD", "/h2", "HTTP/2.0", 200, 0, "200 -"),
        ("127.0.0.1", "GET", "/h2-304", "HTTP/2.0", 304, 0, "304 -"),
    ];

    for (ip, method, target, proto, status, bytes, _) in &entries {
        mgr.log_access(AccessLogEntry {
            timestamp: ts,
            client_ip: ip.to_string(),
            method: method.to_string(),
            target: target.to_string(),
            protocol: proto.to_string(),
            status: *status,
            bytes_sent: *bytes,
            referer: "-".to_string(),
            user_agent: "curl/8.0".to_string(),
            request_id: "req-1".to_string(),
            duration_ms: 0.5,
            domain: "panel.test".to_string(),
            target_path: None,
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        });
    }
    mgr.flush().await;

    let content = tokio::fs::read_to_string(&access).await.unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), entries.len());

    for (i, (_, _, _, _, _, _, expected_sb)) in entries.iter().enumerate() {
        let line = lines[i];
        assert!(
            line.contains(&format!("\" {} \"", expected_sb)),
            "Satir '{line}' beklenen '{expected_sb}' icermelidir"
        );
        // Go logs.ParseAccess formati: ^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)
        assert!(
            line.starts_with("127.0.0.1 - - [11/Nov/2026:21:00:00 +0000] \""),
            "Biçim hatası: {line}"
        );
        assert!(
            line.ends_with("\"-\" \"curl/8.0\""),
            "Referer/UA hatası: {line}"
        );
    }

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn json_format_writes_valid_single_line_json_and_tails() {
    let dir = make_temp_dir("json");
    let access = dir.join("logs").join("access.log");
    let error = dir.join("logs").join("error.log");
    let mgr = AsyncLogManager::new(dir.clone(), access.clone(), error, 50, 64);

    let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);
    for idx in 0..5usize {
        mgr.log_access(AccessLogEntry {
            timestamp: ts,
            client_ip: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            target: format!("/p/{idx}"),
            protocol: "HTTP/2.0".to_string(),
            status: 200,
            bytes_sent: 100 + idx,
            referer: "https://example.com/".to_string(),
            user_agent: "curl/8.0".to_string(),
            request_id: format!("req-{idx}"),
            duration_ms: 2.5,
            domain: "ornek.test".to_string(),
            target_path: None,
            json_format: true,
            also_write_global: true,
            max_size_bytes: 0,
        });
    }
    mgr.flush().await;

    let tail = mgr.read_tail_lines(&access, 3).await.unwrap();
    assert_eq!(tail.len(), 3);
    let parsed: serde_json::Value = serde_json::from_str(&tail[2]).unwrap();
    assert_eq!(parsed["ts"], "2026-11-11T21:00:00Z");
    assert_eq!(parsed["request_id"], "req-4");
    assert_eq!(parsed["domain"], "ornek.test");
    assert_eq!(parsed["ip"], "127.0.0.1");
    assert_eq!(parsed["method"], "GET");
    assert_eq!(parsed["target"], "/p/4");
    assert_eq!(parsed["proto"], "HTTP/2.0");
    assert_eq!(parsed["status"], 200);
    assert_eq!(parsed["bytes"], 104);
    assert_eq!(parsed["latency_ms"], 2.5);
    assert_eq!(parsed["referer"], "https://example.com/");
    assert_eq!(parsed["user_agent"], "curl/8.0");

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn per_vhost_target_rotation_and_reopen_all_writes_to_new_file() {
    let dir = make_temp_dir("reopen");
    let global_access = dir.join("logs").join("global_access.log");
    let global_error = dir.join("logs").join("global_error.log");
    let vhost_rel = PathBuf::from("logs/vhosts/site.access.log");
    let vhost_abs = dir.join(&vhost_rel);
    let rotated_archive = dir.join("logs/vhosts/site.access.log.rotated");

    let mgr = AsyncLogManager::new(
        dir.clone(),
        global_access.clone(),
        global_error.clone(),
        50,
        64,
    );
    let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);

    mgr.log_access(AccessLogEntry {
        timestamp: ts,
        client_ip: "10.0.0.1".to_string(),
        method: "GET".to_string(),
        target: "/once".to_string(),
        protocol: "HTTP/1.1".to_string(),
        status: 200,
        bytes_sent: 512,
        referer: String::new(),
        user_agent: "TestUA".to_string(),
        request_id: "r1".to_string(),
        duration_ms: 1.0,
        domain: "site.test".to_string(),
        target_path: Some(vhost_rel.clone()),
        json_format: false,
        also_write_global: true,
        max_size_bytes: 0,
    });
    mgr.flush().await;

    assert!(vhost_abs.is_file());
    assert!(global_access.is_file());

    // Açık dosya tanıtıcılarını bırak, eski dosyayı taşı, sonra reopen_all sonrası yeni dosyaya yaz
    mgr.reopen_all().await;
    tokio::fs::rename(&vhost_abs, &rotated_archive)
        .await
        .unwrap();

    mgr.log_access(AccessLogEntry {
        timestamp: ts,
        client_ip: "10.0.0.2".to_string(),
        method: "GET".to_string(),
        target: "/sonra".to_string(),
        protocol: "HTTP/1.1".to_string(),
        status: 200,
        bytes_sent: 1024,
        referer: String::new(),
        user_agent: "TestUA".to_string(),
        request_id: "r2".to_string(),
        duration_ms: 1.5,
        domain: "site.test".to_string(),
        target_path: Some(vhost_rel.clone()),
        json_format: false,
        also_write_global: false,
        max_size_bytes: 0,
    });
    mgr.flush().await;

    let new_body = tokio::fs::read_to_string(&vhost_abs).await.unwrap();
    assert!(new_body.contains("/sonra") && !new_body.contains("/once"));
    let old_body = tokio::fs::read_to_string(&rotated_archive).await.unwrap();
    assert!(old_body.contains("/once") && !old_body.contains("/sonra"));
    let global_body = tokio::fs::read_to_string(&global_access).await.unwrap();
    assert!(global_body.contains("/once") && !global_body.contains("/sonra"));

    // Boyut sınırı ile .1 rotasyonu
    let err_override = PathBuf::from("logs/vhosts/site.error.log");
    mgr.log_error(
        Some(err_override.clone()),
        "birinci-uzun-hata-mesaji-0123456789abcdef".to_string(),
        48,
        false,
    );
    mgr.log_error(
        Some(err_override.clone()),
        "ikinci-hata".to_string(),
        48,
        false,
    );
    mgr.flush().await;
    let err_abs = dir.join(&err_override);
    let err_dot_one = dir.join("logs/vhosts/site.error.log.1");
    assert!(err_dot_one.is_file());
    assert_eq!(
        tokio::fs::read_to_string(&err_abs).await.unwrap(),
        "ikinci-hata\n"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn log_waf_event_writes_sanitized_json_lines_and_keeps_access_error_intact() {
    let dir = make_temp_dir("waf_events");
    let access = dir.join("logs").join("access.log");
    let error = dir.join("logs").join("error.log");
    let waf_log = dir.join(DEFAULT_WAF_EVENTS_LOG);
    let mgr = AsyncLogManager::new(dir.clone(), access.clone(), error.clone(), 50, 64);

    let rec = zmax_security::waf_events::WafEventRecord::from_violation(
        &zmax_security::WafViolation::SqlInjection("union select".to_string()),
        "waf-test.local",
        "198.51.100.42",
        "GET",
        "/login?password=GizliSifre99&cookie=OturumCerez99&q=union+select",
        1_794_430_800,
    );
    mgr.log_waf_event(rec, None, 1024 * 1024, true);
    mgr.log_error(None, "normal-error-line".to_string(), 1024 * 1024, true);
    mgr.flush().await;

    let waf_content = tokio::fs::read_to_string(&waf_log).await.unwrap();
    assert_eq!(waf_content.lines().count(), 1);
    let parsed: serde_json::Value =
        serde_json::from_str(waf_content.lines().next().unwrap()).unwrap();
    assert_eq!(parsed["ts"], "2026-11-11T21:00:00Z");
    assert_eq!(parsed["vhost"], "waf-test.local");
    assert_eq!(parsed["ip"], "198.51.100.42");
    assert_eq!(parsed["rule_id"], "942100");
    assert_eq!(parsed["path"], "/login?password=&cookie=&q=");
    assert!(!waf_content.contains("GizliSifre99"), "{waf_content}");
    assert!(!waf_content.contains("OturumCerez99"), "{waf_content}");
    assert_eq!(mgr.dropped_events(), 0);

    let err_content = tokio::fs::read_to_string(&error).await.unwrap();
    assert_eq!(err_content, "normal-error-line\n");

    let _ = tokio::fs::remove_dir_all(&dir).await;
}
