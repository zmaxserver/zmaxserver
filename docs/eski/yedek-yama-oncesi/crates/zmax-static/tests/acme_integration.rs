use std::path::PathBuf;
use zmax_config::AcmeConfig;
use zmax_static::{
    clear_global_acme_root, is_acme_challenge_path, set_global_acme_root, StaticFileHandler,
};

fn create_temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zmax_acme_integ_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn test_acme_challenge_from_vhost_docroot() {
    let base = create_temp_dir("vhost");
    let docroot = base.join("www").join("example.com");
    let acme_dir = docroot.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&acme_dir).unwrap();

    let token_content = "vhost-token-abc123xyz";
    std::fs::write(acme_dir.join("challenge-1"), token_content).unwrap();

    let handler = StaticFileHandler::new(&docroot);
    let resolved = handler
        .resolve_acme_challenge_with_root("/.well-known/acme-challenge/challenge-1", None)
        .expect("vHost docroot altındaki ACME challenge bulunmalı");

    assert_eq!(resolved.mime_type, "text/plain; charset=utf-8");
    let content = std::fs::read_to_string(&resolved.path).unwrap();
    assert_eq!(content, token_content);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_acme_challenge_from_common_root_when_missing_in_docroot() {
    let base = create_temp_dir("common");
    let docroot = base.join("www").join("site.test");
    let common_root = base.join("var_www_acme");

    // Certbot webroot stili: common_root/.well-known/acme-challenge/token
    let common_nested = common_root.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&docroot).unwrap();
    std::fs::create_dir_all(&common_nested).unwrap();

    let token_nested = "common-token-nested-certbot-webroot";
    std::fs::write(common_nested.join("certbot-token"), token_nested).unwrap();

    // Düz ortak kök stili: common_root/flat-token
    let token_flat = "common-token-flat-certbot";
    std::fs::write(common_root.join("flat-token"), token_flat).unwrap();

    let handler = StaticFileHandler::new(&docroot);

    // 1. Nested certbot tokeni ortak kökten okunmalı
    let res_nested = handler
        .resolve_acme_challenge_with_root(
            "/.well-known/acme-challenge/certbot-token",
            Some(&common_root),
        )
        .expect("Nested certbot tokeni ortak kökten bulunmalı");
    assert_eq!(res_nested.mime_type, "text/plain; charset=utf-8");
    assert_eq!(
        std::fs::read_to_string(&res_nested.path).unwrap(),
        token_nested
    );

    // 2. Düz ortak kök tokeni ortak kökten okunmalı
    let res_flat = handler
        .resolve_acme_challenge_with_root(
            "/.well-known/acme-challenge/flat-token",
            Some(&common_root),
        )
        .expect("Düz token ortak kökten bulunmalı");
    assert_eq!(res_flat.mime_type, "text/plain; charset=utf-8");
    assert_eq!(std::fs::read_to_string(&res_flat.path).unwrap(), token_flat);

    // 3. Global ACME root yapılandırmasıyla otomatik fallback testi
    set_global_acme_root(&common_root);
    let res_global = handler
        .resolve_acme_challenge("/.well-known/acme-challenge/certbot-token")
        .expect("set_global_acme_root sonrası resolve_acme_challenge bulmalı");
    assert_eq!(
        std::fs::read_to_string(&res_global.path).unwrap(),
        token_nested
    );

    // handler.resolve() üzerinden de şeffaf çalışmalı
    let res_resolve = handler
        .resolve("/.well-known/acme-challenge/certbot-token")
        .expect("handler.resolve() ortak kök fallback'ini çalıştırmalı");
    assert_eq!(
        std::fs::read_to_string(&res_resolve.path).unwrap(),
        token_nested
    );
    clear_global_acme_root();

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_acme_challenge_prefers_vhost_docroot_over_common_root() {
    let base = create_temp_dir("priority");
    let docroot = base.join("docroot");
    let common = base.join("common");

    let vhost_acme = docroot.join(".well-known").join("acme-challenge");
    let common_acme = common.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&vhost_acme).unwrap();
    std::fs::create_dir_all(&common_acme).unwrap();

    std::fs::write(vhost_acme.join("token-xyz"), "VHOST_WINNER").unwrap();
    std::fs::write(common_acme.join("token-xyz"), "COMMON_LOSER").unwrap();

    let handler = StaticFileHandler::new(&docroot);
    let res = handler
        .resolve_acme_challenge_with_root("/.well-known/acme-challenge/token-xyz", Some(&common))
        .expect("token-xyz bulunmalı");

    assert_eq!(
        std::fs::read_to_string(&res.path).unwrap(),
        "VHOST_WINNER",
        "vHost docroot her zaman ortak köke göre önceliklidir"
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_acme_challenge_force_https_exempt_behavior() {
    let base = create_temp_dir("force_https");
    let docroot = base.join("site");
    let common = base.join("acme");
    let vhost_acme = docroot.join(".well-known").join("acme-challenge");
    let common_acme = common.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&vhost_acme).unwrap();
    std::fs::create_dir_all(&common_acme).unwrap();

    std::fs::write(vhost_acme.join("tok-vhost"), "TOK_VHOST_DATA").unwrap();
    std::fs::write(common_acme.join("tok-common"), "TOK_COMMON_DATA").unwrap();
    std::fs::write(docroot.join("index.html"), "GIZLI_ANASAYFA").unwrap();

    let acme_cfg = AcmeConfig::with_root(&common);
    assert!(acme_cfg.force_https_exempt);

    let handler = StaticFileHandler::new(&docroot);

    // Simüle edilen istek hattı karar mantığı (web_engine force_https & is_acme_challenge):
    let check_force_https_and_serve = |path: &str, is_https: bool, force_https: bool| -> (u16, Option<String>) {
        if !is_https && force_https && !is_acme_challenge_path(path) {
            // Normal istekler HTTPS'e 301 yönlendirmesi alır
            return (301, Some(format!("https://example.com{path}")));
        }

        // ACME istekleri veya normal HTTPS istekleri statik çözücüye gider
        if is_acme_challenge_path(path) {
            if let Some(info) = handler.resolve_acme_challenge_with_root(path, acme_cfg.root()) {
                let content = std::fs::read_to_string(&info.path).unwrap();
                return (200, Some(content));
            }
            return (404, None);
        }

        if let Some(info) = handler.resolve(path) {
            let content = std::fs::read_to_string(&info.path).unwrap();
            return (200, Some(content));
        }

        (404, None)
    };

    // 1. Normal HTTP isteğinde force_https açıkken 301 yönlendirmesi alınmalı
    let (status_home, loc_home) = check_force_https_and_serve("/index.html", false, true);
    assert_eq!(status_home, 301);
    assert_eq!(loc_home, Some("https://example.com/index.html".to_string()));

    // 2. vHost docroot altındaki ACME challenge HTTP isteğinde force_https açık olsa bile 200 OK dönmeli!
    let (status_vhost, body_vhost) =
        check_force_https_and_serve("/.well-known/acme-challenge/tok-vhost", false, true);
    assert_eq!(status_vhost, 200);
    assert_eq!(body_vhost, Some("TOK_VHOST_DATA".to_string()));

    // 3. Ortak kök altındaki ACME challenge HTTP isteğinde force_https açık olsa bile 200 OK dönmeli!
    let (status_comm, body_comm) =
        check_force_https_and_serve("/.well-known/acme-challenge/tok-common", false, true);
    assert_eq!(status_comm, 200);
    assert_eq!(body_comm, Some("TOK_COMMON_DATA".to_string()));

    // 4. Var olmayan ACME challenge isteğinde yönlendirme değil 404 dönmeli (ACME muafiyeti korunur)
    let (status_missing, _) =
        check_force_https_and_serve("/.well-known/acme-challenge/non-existent", false, true);
    assert_eq!(status_missing, 404);

    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn test_acme_challenge_security_guards() {
    let base = create_temp_dir("security");
    let docroot = base.join("site");
    let common = base.join("acme");
    let vhost_acme = docroot.join(".well-known").join("acme-challenge");
    std::fs::create_dir_all(&vhost_acme).unwrap();
    std::fs::create_dir_all(&common).unwrap();

    std::fs::write(base.join("passwd"), "root:x:0:0").unwrap();
    std::fs::write(vhost_acme.join(".hidden"), "GIZLI").unwrap();

    let handler = StaticFileHandler::new(&docroot);

    // Path traversal denemeleri engellenmeli
    assert!(handler
        .resolve_acme_challenge_with_root("/.well-known/acme-challenge/../passwd", Some(&common))
        .is_none());
    assert!(handler
        .resolve_acme_challenge_with_root("/.well-known/acme-challenge/%2e%2e/passwd", Some(&common))
        .is_none());
    assert!(handler
        .resolve_acme_challenge_with_root("/.well-known/acme-challenge/.hidden", Some(&common))
        .is_none());
    assert!(handler
        .resolve_acme_challenge_with_root("/.well-known/acme-challenge/", Some(&common))
        .is_none());

    let _ = std::fs::remove_dir_all(&base);
}
