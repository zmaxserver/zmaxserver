//! # Kart 5 Entegrasyon Testleri
//! Hotlink koruması ve IP/CIDR ACL mekanizmasının kapsamlı senaryo testleri.

use std::net::IpAddr;
use std::str::FromStr;
use zmax_security::{
    is_hotlink_blocked, HotlinkGuard, VhostAcl,
};

#[test]
fn test_kart5_hotlink_acceptance_matrix() {
    let allowed_referers = vec![
        "guvenli.test".to_string(),
        "*.cdn-partner.net".to_string(),
        "192.168.1.10".to_string(),
    ];
    let extensions = vec![
        "jpg".to_string(),
        "png".to_string(),
        "gif".to_string(),
        "webp".to_string(),
        "mp4".to_string(),
    ];
    let vhost_name = "ornek.test";
    let vhost_aliases = vec!["www.ornek.test".to_string(), "resim.ornek.test".to_string()];

    // 1. Boş veya eksik referer: HER ZAMAN İZİNLİ (RewriteCond %{HTTP_REFERER} !^$)
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        None,
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some(""),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("    "),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));

    // 2. Kendi alan adı veya alias'ından gelen istek: İZİNLİ (200)
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("http://ornek.test/sayfa.html"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("https://www.ornek.test:8443/galeri"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("http://resim.ornek.test/"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));

    // 3. İzinli referer listesinden gelen istek: İZİNLİ (200)
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("https://guvenli.test/blog/yazi-1"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("http://statik.cdn-partner.net:8080/"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));

    // 4. Yabancı / İzinsiz kaynaktan gelen resim isteği: ENGELLİ (403)
    assert!(is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("http://baska.test/"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));
    assert!(is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("https://calici-site.com/index.html"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/resim.jpg"
    ));

    // 5. Yabancı referer olsa dahi korumasız dosya uzantısı (.html, .css, .js): İZİNLİ (200)
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("http://baska.test/"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/index.html"
    ));
    assert!(!is_hotlink_blocked(
        true,
        &allowed_referers,
        &extensions,
        Some("http://baska.test/"),
        "ornek.test",
        vhost_name,
        &vhost_aliases,
        "/main.css"
    ));
}

#[test]
fn test_kart5_acl_acceptance_matrix() {
    // Senaryo 1: CIDR Engeli (10.0.0.0/8 ve 192.168.1.0/24 engelli, diğerleri serbest)
    let acl_cidr = VhostAcl::new(
        vec![],
        vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()],
    );
    assert!(!acl_cidr.is_allowed(IpAddr::from_str("10.50.1.1").unwrap()));
    assert!(!acl_cidr.is_allowed(IpAddr::from_str("192.168.1.42").unwrap()));
    assert!(acl_cidr.is_allowed(IpAddr::from_str("192.168.2.42").unwrap()));
    assert!(acl_cidr.is_allowed(IpAddr::from_str("172.16.0.1").unwrap()));
    assert!(acl_cidr.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));

    // Senaryo 2: Beyaz Liste İstisnası (Genel CIDR engelli, ancak belirli ofis IP'si izinli)
    let acl_override = VhostAcl::new(
        vec!["192.168.1.100".to_string()],
        vec!["192.168.1.0/24".to_string()],
    );
    assert!(acl_override.is_allowed(IpAddr::from_str("192.168.1.100").unwrap())); // Beyaz liste istisnası
    assert!(!acl_override.is_allowed(IpAddr::from_str("192.168.1.101").unwrap())); // Engelli CIDR
    assert!(!acl_override.is_allowed(IpAddr::from_str("10.0.0.1").unwrap())); // Allow listesi dolu olduğu için sıkı mod

    // Senaryo 3: IPv6 CIDR Denetimi
    let acl_v6 = VhostAcl::new(
        vec!["2001:db8::1".to_string()],
        vec!["2001:db8::/32".to_string()],
    );
    assert!(acl_v6.is_allowed(IpAddr::from_str("2001:db8::1").unwrap()));
    assert!(!acl_v6.is_allowed(IpAddr::from_str("2001:db8::2").unwrap()));
    assert!(!acl_v6.is_allowed(IpAddr::from_str("2001:db8:1234::5678").unwrap()));
}

#[test]
fn test_kart5_guard_object_integration() {
    let guard = HotlinkGuard::new(
        true,
        vec!["allowed-partner.com".to_string()],
        vec!["jpg".to_string(), "webp".to_string()],
    );
    assert!(!guard.check(None, "vhost.test", "vhost.test", &[], "/img.jpg"));
    assert!(!guard.check(Some("http://vhost.test"), "vhost.test", "vhost.test", &[], "/img.jpg"));
    assert!(!guard.check(Some("https://allowed-partner.com/news"), "vhost.test", "vhost.test", &[], "/img.jpg"));
    assert!(guard.check(Some("http://evil-attacker.com/"), "vhost.test", "vhost.test", &[], "/img.jpg"));
    assert!(!guard.check(Some("http://evil-attacker.com/"), "vhost.test", "vhost.test", &[], "/api.json"));
}
