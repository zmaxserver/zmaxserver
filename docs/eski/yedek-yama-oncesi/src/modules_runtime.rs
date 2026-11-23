//! Modül politikaları ve dinamik güvenlik/otomatik token denetimi.

use std::path::{Path, PathBuf};
use zmax_config::{LoadedModules, VHostEntry, ZMaxConfig};
use zmax_header::SecurityHeadersPolicy;

pub use crate::modules::policy::*;
pub use crate::modules::registry::module_category_key;
pub use crate::redis::build_redis_client;




#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::l7_handlers::static_files::select_negotiated_image_path;
    use crate::logger::rotate::append_line_with_rotation;
    use crate::pipeline::l5_router::{
        extract_referer_host, is_hotlink_blocked, is_hotlink_protected_extension,
    };

    #[test]
    fn hotlink_protection_blocks_external_media_but_allows_direct_and_self() {
        let protected = [
            "jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp", "mp4", "webm", "ogg",
            "mp3", "wav", "woff", "woff2", "ttf", "eot", "pdf", "zip",
        ];
        for ext in protected {
            assert!(
                is_hotlink_protected_extension(&format!("/assets/file.{ext}")),
                "{ext} korunmalı"
            );
            assert!(
                is_hotlink_protected_extension(&format!(
                    "C:\\www\\media\\ITEM.{}?v=2#top",
                    ext.to_ascii_uppercase()
                )),
                "{ext} büyük harf ve sorguyla da korunmalı"
            );
        }
        for open in [
            "/index.html",
            "/css/app.css",
            "/js/main.js",
            "/api/data.json",
            "/robots.txt",
            "/noext",
            "/.env",
        ] {
            assert!(!is_hotlink_protected_extension(open), "{open} korunmamalı");
        }

        assert_eq!(
            extract_referer_host("https://Alan.COM:8080/galeri/1?x=2#h").as_deref(),
            Some("alan.com")
        );
        assert_eq!(
            extract_referer_host("HTTP://user:pass@Sub.Site.Test:8443/sayfa").as_deref(),
            Some("sub.site.test")
        );
        assert_eq!(
            extract_referer_host("https://[::1]:8443/media").as_deref(),
            Some("[::1]")
        );
        assert_eq!(
            extract_referer_host("http://good.com@evil.com/steal").as_deref(),
            Some("evil.com")
        );
        assert_eq!(extract_referer_host(""), None);
        assert_eq!(extract_referer_host("/relative/page.html"), None);
        assert_eq!(extract_referer_host("about:blank"), None);
        assert_eq!(extract_referer_host("http:///no-host"), None);
        assert_eq!(extract_referer_host("https://alan.com:abc/bad"), None);
        assert_eq!(extract_referer_host("https://alan.com:+80/bad"), None);

        let aliases = vec![
            "partner.example".to_string(),
            "*.cdn-mirror.test".to_string(),
            "::1".to_string(),
        ];

        // Doğrudan istek veya boş/kırık referer engellenmemeli
        assert!(!is_hotlink_blocked(
            None,
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(!is_hotlink_blocked(
            Some("   "),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(!is_hotlink_blocked(
            Some("/local/page.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));

        // Korumasız uzantılar dış referer ile bile engellenmemeli
        assert!(!is_hotlink_blocked(
            Some("https://evil.com/ref"),
            "site.test",
            "site.test",
            &aliases,
            "/css/main.css"
        ));

        // Kendi domaini, portu soyulmuş host, alt alan adı ve alias izinli
        assert!(!is_hotlink_blocked(
            Some("HTTPS://SITE.TEST/post"),
            "site.test:8080",
            "site.test",
            &aliases,
            "/img/hero.png"
        ));
        assert!(!is_hotlink_blocked(
            Some("https://blog.site.test/yazi"),
            "site.test",
            "site.test",
            &aliases,
            "/video/clip.mp4"
        ));
        assert!(!is_hotlink_blocked(
            Some("https://sub.partner.example/embed"),
            "site.test",
            "site.test",
            &aliases,
            "/docs/manual.pdf"
        ));
        assert!(!is_hotlink_blocked(
            Some("https://edge1.cdn-mirror.test/page"),
            "site.test",
            "site.test",
            &aliases,
            "/fonts/ui.woff2"
        ));
        assert!(!is_hotlink_blocked(
            Some("http://[::1]:8443/index.html"),
            "[::1]:8080",
            "localhost",
            &aliases,
            "/img/logo.webp"
        ));

        // Harici domain ve sahte sonek/önek denemeleri engellenmeli
        assert!(is_hotlink_blocked(
            Some("https://evil.com/steal.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(is_hotlink_blocked(
            Some("https://evilsite.test/steal.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));
        assert!(is_hotlink_blocked(
            Some("https://site.test.evil.com/steal.html"),
            "site.test",
            "site.test",
            &aliases,
            "/img/hero.jpg"
        ));

        // www. normalizasyonu yapılmamalı
        assert!(is_hotlink_blocked(
            Some("https://site.test/page"),
            "www.site.test",
            "www.site.test",
            &[],
            "/img/hero.jpg"
        ));

        // IP adreslerinde ve "default" / "localhost" üzerinde subdomain eşleşmesi kapalı olmalı
        assert!(!is_hotlink_blocked(
            Some("http://127.0.0.1:3000/page"),
            "127.0.0.1:8080",
            "default",
            &[],
            "/img/hero.png"
        ));
        assert!(is_hotlink_blocked(
            Some("http://evil.127.0.0.1/page"),
            "127.0.0.1:8080",
            "default",
            &[],
            "/img/hero.png"
        ));
        assert!(is_hotlink_blocked(
            Some("http://evil.default/page"),
            "site.test",
            "default",
            &[],
            "/img/hero.png"
        ));
        assert!(is_hotlink_blocked(
            Some("http://evil.localhost/page"),
            "localhost:8080",
            "localhost",
            &[],
            "/img/hero.png"
        ));
    }

    fn make_temp_test_dir(label: &str) -> PathBuf {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "zmax_modules_runtime_{}_{}_{}",
            label,
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("geçici test dizini oluşturulmalı");
        dir
    }

    #[test]
    fn static_module_policy_compiles_with_expected_defaults_and_overrides() {
        let def = StaticModulePolicy::default();
        assert!(def.etag_enabled);
        assert!(def.last_modified_header);
        assert!(def.auto_webp);
        assert!(def.auto_avif);
        assert!(!def.directory_browsing);

        let cfg = ZMaxConfig::default();
        let empty_mods = LoadedModules::default();
        let compiled_missing = compile_policies(&cfg, &empty_mods);
        assert!(compiled_missing.static_policy.etag_enabled);
        assert!(compiled_missing.static_policy.last_modified_header);
        assert!(!compiled_missing.static_policy.auto_webp);
        assert!(!compiled_missing.static_policy.auto_avif);
        assert!(!compiled_missing.static_policy.directory_browsing);

        let dir = make_temp_test_dir("static_policy");
        let disabled_toml = r#"
[module]
name = "mod_static"
enabled = false

[settings]
etag_enabled = false
last_modified_header = false
auto_webp = true
auto_avif = true
directory_browsing = true
"#;
        std::fs::write(dir.join("mod_static.toml"), disabled_toml).unwrap();
        let disabled_mods = LoadedModules::load_from_dir(&dir).unwrap();
        let compiled_disabled = compile_policies(&cfg, &disabled_mods);
        assert!(compiled_disabled.static_policy.etag_enabled);
        assert!(compiled_disabled.static_policy.last_modified_header);
        assert!(!compiled_disabled.static_policy.auto_webp);
        assert!(!compiled_disabled.static_policy.auto_avif);
        assert!(!compiled_disabled.static_policy.directory_browsing);

        let enabled_toml = r#"
[module]
name = "mod_static"
enabled = true

[settings]
etag_enabled = false
last_modified_header = true
auto_webp = true
auto_avif = false
directory_browsing = true
"#;
        std::fs::write(dir.join("mod_static.toml"), enabled_toml).unwrap();
        let enabled_mods = LoadedModules::load_from_dir(&dir).unwrap();
        let compiled_enabled = compile_policies(&cfg, &enabled_mods);
        assert!(!compiled_enabled.static_policy.etag_enabled);
        assert!(compiled_enabled.static_policy.last_modified_header);
        assert!(compiled_enabled.static_policy.auto_webp);
        assert!(!compiled_enabled.static_policy.auto_avif);
        assert!(compiled_enabled.static_policy.directory_browsing);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn select_negotiated_image_prefers_avif_then_webp_safely() {
        let dir = make_temp_test_dir("negotiate");
        let outside = make_temp_test_dir("negotiate_outside");

        let jpg_path = dir.join("foto.jpg");
        let stem_avif = dir.join("foto.avif");
        let stem_webp = dir.join("foto.webp");
        std::fs::write(&jpg_path, b"jpg").unwrap();
        std::fs::write(&stem_avif, b"avif").unwrap();
        std::fs::write(&stem_webp, b"webp").unwrap();

        let canon_stem_avif = std::fs::canonicalize(&stem_avif).unwrap();
        let canon_stem_webp = std::fs::canonicalize(&stem_webp).unwrap();

        // AVIF + WebP destekleniyorsa AVIF öncelikli olmalı
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/avif,image/webp"), true, true),
            Some((canon_stem_avif, "image/avif"))
        );

        // Yalnız WebP destekleniyorsa WebP seçilmeli
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/webp,*/*;q=0.8"), true, true),
            Some((canon_stem_webp.clone(), "image/webp"))
        );

        // AVIF politikası kapalıysa WebP'ye düşmeli
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/avif,image/webp"), false, true),
            Some((canon_stem_webp.clone(), "image/webp"))
        );

        // q=0 ile reddedilen AVIF yerine WebP seçilmeli
        assert_eq!(
            select_negotiated_image_path(
                &jpg_path,
                Some("image/avif;q=0, image/webp;q=0.9"),
                true,
                true
            ),
            Some((canon_stem_webp, "image/webp"))
        );

        // <orig>.avif dosyası <stem>.avif dosyasından önce tercih edilmeli
        let orig_avif = dir.join("foto.jpg.avif");
        std::fs::write(&orig_avif, b"orig-avif").unwrap();
        let canon_orig_avif = std::fs::canonicalize(&orig_avif).unwrap();
        assert_eq!(
            select_negotiated_image_path(&jpg_path, Some("image/avif,image/webp"), true, true),
            Some((canon_orig_avif, "image/avif"))
        );

        // .txt dosyasında devreye girmemeli
        let txt_path = dir.join("notlar.txt");
        std::fs::write(&txt_path, b"text").unwrap();
        std::fs::write(dir.join("notlar.avif"), b"fake").unwrap();
        assert_eq!(
            select_negotiated_image_path(&txt_path, Some("image/avif,image/webp"), true, true),
            None
        );

        // .PNG ve .jpeg uzantıları büyük/küçük harf duyarsız çalışmalı
        let png_path = dir.join("logo.PNG");
        let png_webp = dir.join("logo.webp");
        std::fs::write(&png_path, b"png").unwrap();
        std::fs::write(&png_webp, b"webp").unwrap();
        assert_eq!(
            select_negotiated_image_path(&png_path, Some("IMAGE/WEBP"), true, true),
            Some((std::fs::canonicalize(&png_webp).unwrap(), "image/webp"))
        );

        // Varyant adında klasör varsa dosya olarak kabul edilmemeli
        let dir_fake_jpg = dir.join("klasor.jpeg");
        std::fs::write(&dir_fake_jpg, b"jpeg").unwrap();
        std::fs::create_dir_all(dir.join("klasor.avif")).unwrap();
        assert_eq!(
            select_negotiated_image_path(&dir_fake_jpg, Some("image/avif"), true, true),
            None
        );

        // Symlink ile parent dizin dışına kaçış engellenmeli
        let secret_avif = outside.join("gizli.avif");
        std::fs::write(&secret_avif, b"secret").unwrap();
        let symlink_jpg = dir.join("disari.jpg");
        std::fs::write(&symlink_jpg, b"jpg").unwrap();
        let symlink_avif = dir.join("disari.avif");
        #[cfg(unix)]
        let symlink_created = std::os::unix::fs::symlink(&secret_avif, &symlink_avif).is_ok();
        #[cfg(windows)]
        let symlink_created =
            std::os::windows::fs::symlink_file(&secret_avif, &symlink_avif).is_ok();
        if symlink_created {
            assert_eq!(
                select_negotiated_image_path(&symlink_jpg, Some("image/avif"), true, true),
                None
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[tokio::test]
    async fn append_line_with_rotation_rotates_to_dot_one_backup() {
        let dir = make_temp_test_dir("log_rotate");
        let log_file = dir.join("logs").join("custom.log");
        let backup_file = dir.join("logs").join("custom.log.1");

        append_line_with_rotation(&log_file, "birinci-log-satiri-0123456789abcdef", 64).await;
        assert!(!backup_file.exists(), "ilk satırda yedek oluşmamalı");

        append_line_with_rotation(&log_file, "ikinci-log-satiri-0123456789abcdef", 64).await;
        assert!(!backup_file.exists(), "eşik yazım öncesi aşılmadığı için henüz dönmemeli");

        append_line_with_rotation(&log_file, "ucuncu-temiz-satir", 64).await;
        assert!(backup_file.is_file(), "eşik aşıldığında .1 yedeği oluşmalı");
        let backup_body = tokio::fs::read_to_string(&backup_file).await.unwrap();
        assert!(backup_body.contains("birinci-log-satiri"));
        assert!(backup_body.contains("ikinci-log-satiri"));
        let active_body = tokio::fs::read_to_string(&log_file).await.unwrap();
        assert_eq!(active_body, "ucuncu-temiz-satir\n");

        // İkinci döndürmede önceki .1 üzerine taşınıp yeni içerik sıfırdan başlamalı
        append_line_with_rotation(
            &log_file,
            "dorduncu-uzun-satir-0123456789abcdef0123456789abcdef0123456789abcdef",
            64,
        )
        .await;
        append_line_with_rotation(&log_file, "besinci-satir", 64).await;
        let second_backup = tokio::fs::read_to_string(&backup_file).await.unwrap();
        assert!(second_backup.contains("dorduncu-uzun-satir"));
        assert!(!second_backup.contains("birinci-log-satiri"));
        assert_eq!(
            tokio::fs::read_to_string(&log_file).await.unwrap(),
            "besinci-satir\n"
        );

        // append_error_log_limit ve append_access_log_limit yardımcıları da aynı döndürmeyi kullanmalı
        append_error_log_limit(&dir, "err-uzun-satir-0123456789", 10).await;
        append_error_log_limit(&dir, "err-yeni", 10).await;
        assert!(dir.join("logs").join("error.log.1").is_file());
        assert_eq!(
            tokio::fs::read_to_string(dir.join("logs").join("error.log"))
                .await
                .unwrap(),
            "err-yeni\n"
        );

        append_access_log_limit(&dir, "acc-uzun-satir-0123456789\r\n", 10).await;
        append_access_log_limit(&dir, "acc-yeni\n", 10).await;
        assert!(dir.join("logs").join("access.log.1").is_file());
        assert_eq!(
            tokio::fs::read_to_string(dir.join("logs").join("access.log"))
                .await
                .unwrap(),
            "acc-yeni\n"
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn gzip_brotli_and_fastcgi_policies_compile_from_toml() {
        let dir = make_temp_test_dir("brotli_fcgi");
        std::fs::write(
            dir.join("mod_gzip.toml"),
            "[module]\nname = \"mod_gzip\"\nenabled = true\n\n[settings]\nmin_length = 1024\nvary_header = false\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("mod_brotli.toml"),
            "[module]\nname = \"mod_brotli\"\nenabled = false\n\n[settings]\nmin_length = 256\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("mod_fastcgi.toml"),
            "[module]\nname = \"mod_fastcgi\"\nenabled = true\n\n[settings]\ndefault_upstream = \"127.0.0.1:9001\"\nconnection_timeout_sec = 45\nkeep_alive_pool_size = 32\ndial_timeout_ms = 1500\nkeep_conn = false\n",
        )
        .unwrap();

        let cfg = ZMaxConfig::default();
        let mods = LoadedModules::load_from_dir(&dir).unwrap();
        let policies = compile_policies(&cfg, &mods);

        assert!(policies.gzip.enabled);
        assert!(!policies.gzip.brotli_enabled);
        assert_eq!(policies.gzip.min_length, 1024);
        assert!(!policies.gzip.vary_header);

        assert!(policies.fastcgi.enabled);
        assert_eq!(policies.fastcgi.default_upstream, "127.0.0.1:9001");
        assert_eq!(policies.fastcgi.timeout_sec, 45);
        assert_eq!(policies.fastcgi.pool_size, 32);
        assert_eq!(policies.fastcgi.dial_timeout_ms, 1500);
        assert!(!policies.fastcgi.keep_conn);

        std::fs::write(
            dir.join("mod_brotli.toml"),
            "[module]\nname = \"mod_brotli\"\nenabled = true\n",
        )
        .unwrap();
        let mods_on = LoadedModules::load_from_dir(&dir).unwrap();
        let policies_on = compile_policies(&cfg, &mods_on);
        assert!(policies_on.gzip.brotli_enabled);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
pub use crate::logger::rotate::{
    append_access_log_limit, append_error_log, append_error_log_limit,
};
