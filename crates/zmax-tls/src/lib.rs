//! # zmax-tls
//! TLS 1.3 / 1.2 (rustls + ring), dinleyici (listener) bazlı çoklu port mimarisi,
//! vhost başına SNI ve joker karakter (wildcard) sertifika seçimi,
//! ALPN müzakeresi (HTTP/1.1, HTTP/2, HTTP/3 hazırlığı),
//! ACME HTTP-01 challenge doğrulaması ve TLS oturum önbellek optimizasyonu.
//!
//! Davranış kararları:
//! * SNI eşleşmezse veya istemci SNI göndermezse: ilk yüklenen sertifika (vhost dosyalarının
//!   ada göre sıralı ilki) varsayılan olarak sunulur; hiç sertifika yoksa el sıkışma reddedilir.
//! * Joker karakter sertifikaları (`*.example.com`) alt alan adları ile otomatik eşleşir.
//! * ALPN varsayılan olarak `["h2", "http/1.1"]` sırasıyla duyurulur; istemci yalnız
//!   `http/1.1` sunarsa `http/1.1` seçilir, ayrıca `build_acceptor_with_alpn` veya `ListenerTlsBuilder` ile özelleştirilebilir.
//! * Bozuk/eksik sertifika veya anahtar dosyası sunucuyu çökertmez: o vhost atlanır ve
//!   `LoadReport::skipped` içinde nedeni döner (çağıran log'a yazar).
//! * Sertifika tablosu `SniResolver::replace`, `reload` veya `add_certificate_pem` ile
//!   dinleyiciyi yeniden başlatmadan çalışma zamanında kesintisiz değiştirilir.
//! * ACME HTTP-01 challenge istekleri (`/.well-known/acme-challenge/*`) bellek içi güvenli
//!   `AcmeChallengeStore` üzerinden yanıtlanır.
//! * TLS oturum sürdürme (session resumption) bellek sınırlı `InstrumentedSessionCache` ve
//!   `SessionTicket` rotasyonu ile yüksek performansta çalışır.

pub mod acme;
pub mod alpn;
pub mod listener;
pub mod session;
pub mod sni;

use std::path::Path;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

pub use acme::{
    base64url_encode, days_until_cert_expiry, days_until_cert_file_expiry,
    days_until_cert_pem_expiry, extract_cert_validity, is_acme_challenge_path,
    is_cert_due_for_renewal, is_cert_expired, parse_asn1_time, AcmeChallengeStore,
    AcmeManager, RenewalCandidate, RenewalOutcome, ACME_CHALLENGE_PREFIX,
};
pub use alpn::{
    default_alpn_protocols, format_alpn, negotiated_alpn, negotiated_alpn_enum, parse_alpn_list,
    AlpnConfig, AlpnProtocol, ALPN_H2, ALPN_H3, ALPN_H3_29, ALPN_HTTP10, ALPN_HTTP11,
};
pub use listener::{
    ClientAuthMode, ListenerTlsAcceptor, ListenerTlsBuilder, ListenerTlsConfig, TlsAcceptor,
    TlsVersion,
};
pub use session::{InstrumentedSessionCache, SessionCacheMetrics, TlsSessionConfig};
pub use sni::{
    extract_cert_serial_hex, load_certified_key, load_certified_key_from_pem, sources_from_vhosts,
    sources_from_vhosts_filtered, CertSource, LoadReport, SkippedCert, SniResolver,
};

/// Geriye dönük uyumluluk için statik TLS yapılandırma nesnesi.
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl TlsConfig {
    pub fn new(cert: String, key: String) -> Self {
        Self {
            cert_path: cert,
            key_path: key,
        }
    }
}

/// Tek sertifikalı dinleyiciler için sabit çözümleyici.
struct FixedCertResolver(Arc<CertifiedKey>);

impl std::fmt::Debug for FixedCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixedCertResolver")
    }
}

impl ResolvesServerCert for FixedCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn build_acceptor_with_resolver(
    resolver: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS surumleri ayarlanamadi: {}", e))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = alpn_protocols;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// TLS 1.2/1.3 kabul eden, varsayılan olarak ALPN `["h2", "http/1.1"]` duyuran kabul edici.
pub fn build_acceptor(resolver: Arc<SniResolver>) -> Result<TlsAcceptor, String> {
    build_acceptor_with_resolver(resolver, default_alpn_protocols())
}

/// Özel ALPN protokol listesiyle TLS 1.2/1.3 kabul edicisi oluşturur.
pub fn build_acceptor_with_alpn(
    resolver: Arc<SniResolver>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, String> {
    build_acceptor_with_resolver(resolver, alpn_protocols)
}

/// Tek bir sertifika ve özel anahtar çiftiyle TLS 1.2/1.3 kabul edicisi oluşturur (panel portları için).
pub fn build_single_cert_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor, String> {
    build_single_cert_acceptor_with_alpn(cert_path, key_path, vec![b"http/1.1".to_vec()])
}

/// Tek bir sertifika ve özel anahtar çiftiyle özel ALPN listeli TLS 1.2/1.3 kabul edicisi oluşturur.
pub fn build_single_cert_acceptor_with_alpn(
    cert_path: &Path,
    key_path: &Path,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsAcceptor, String> {
    let ck = load_certified_key(cert_path, key_path)?;
    build_acceptor_with_resolver(Arc::new(FixedCertResolver(Arc::new(ck))), alpn_protocols)
}

/// Sunucu tarafındaki TLS akışından istemcinin gönderdiği SNI alan adını okur.
pub fn client_sni<T>(stream: &tokio_rustls::server::TlsStream<T>) -> Option<String> {
    stream.get_ref().1.server_name().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::io::Write;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zmax_tls_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn make_cert(dir: &Path, stem: &str, names: &[&str]) -> CertSource {
        let ck = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        let c = dir.join(format!("{stem}.pem"));
        let k = dir.join(format!("{stem}.key"));
        std::fs::write(&c, ck.cert.pem()).unwrap();
        std::fs::write(&k, ck.signing_key.serialize_pem()).unwrap();
        CertSource {
            label: stem.to_string(),
            names: names.iter().map(|s| s.to_string()).collect(),
            cert_path: c,
            key_path: k,
        }
    }

    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &ServerName<'_>,
            _o: &[u8],
            _n: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    async fn assert_tls_handshake_and_echo(
        acceptor: TlsAcceptor,
        server_name: &'static str,
        expected_leaf: &CertificateDer<'_>,
        client_alpn: Vec<Vec<u8>>,
        expected_alpn: Option<&[u8]>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.unwrap();
            let srv_alpn = negotiated_alpn(&tls);
            let srv_sni = client_sni(&tls);
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            tls.write_all(b"pong").await.unwrap();
            tls.shutdown().await.ok();
            (srv_alpn, srv_sni)
        });

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut ccfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        ccfg.alpn_protocols = client_alpn;
        let connector = TlsConnector::from(Arc::new(ccfg));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from(server_name).unwrap(), tcp)
            .await
            .unwrap();
        {
            let (_, conn) = tls.get_ref();
            assert_eq!(conn.alpn_protocol(), expected_alpn);
            let peer = conn.peer_certificates().unwrap();
            assert_eq!(peer[0].as_ref(), expected_leaf.as_ref());
        }
        tls.write_all(b"ping").await.unwrap();
        let mut out = Vec::new();
        tls.read_to_end(&mut out).await.ok();
        assert_eq!(out, b"pong");

        let (srv_alpn, srv_sni) = server_task.await.unwrap();
        assert_eq!(srv_alpn.as_deref(), expected_alpn);
        assert_eq!(srv_sni.as_deref(), Some(server_name));
    }

    #[test]
    fn loads_certificate_and_selects_by_sni() {
        let d = temp_dir("sni");
        let a = make_cert(&d, "a", &["a.test", "www.a.test"]);
        let b = make_cert(&d, "b", &["b.test"]);
        let r = SniResolver::new();
        let rep = r.replace(&[a, b]);
        assert_eq!(rep.loaded, 2);
        assert!(rep.skipped.is_empty());
        let ca = r.lookup(Some("a.test")).unwrap();
        let cb = r.lookup(Some("B.TEST")).unwrap();
        let alias = r.lookup(Some("www.a.test")).unwrap();
        assert!(Arc::ptr_eq(&ca, &alias));
        assert!(!Arc::ptr_eq(&ca, &cb));
        // eşleşmeyen / SNI'siz -> ilk yüklenen (a)
        assert!(Arc::ptr_eq(&r.lookup(Some("yok.test")).unwrap(), &ca));
        assert!(Arc::ptr_eq(&r.lookup(None).unwrap(), &ca));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn broken_or_missing_files_are_skipped_without_panic() {
        let d = temp_dir("bad");
        let good = make_cert(&d, "good", &["good.test"]);
        let missing = CertSource {
            label: "missing".into(),
            names: vec!["missing.test".into()],
            cert_path: d.join("yok.pem"),
            key_path: d.join("yok.key"),
        };
        let garbage = {
            let c = d.join("g.pem");
            let k = d.join("g.key");
            std::fs::File::create(&c).unwrap().write_all(b"bu pem degil").unwrap();
            std::fs::File::create(&k).unwrap().write_all(b"bu da degil").unwrap();
            CertSource {
                label: "garbage".into(),
                names: vec!["garbage.test".into()],
                cert_path: c,
                key_path: k,
            }
        };
        // anahtar sertifikaya uymuyor
        let other = make_cert(&d, "other", &["other.test"]);
        let mismatch = CertSource {
            label: "mismatch".into(),
            names: vec!["mismatch.test".into()],
            cert_path: good.cert_path.clone(),
            key_path: other.key_path.clone(),
        };
        let r = SniResolver::new();
        let rep = r.replace(&[missing, garbage, mismatch, good]);
        assert_eq!(rep.loaded, 1);
        let labels: Vec<_> = rep.skipped.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels, ["missing", "garbage", "mismatch"]);
        assert!(rep.skipped.iter().all(|s| !s.reason.is_empty()));
        assert!(r.has_default());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn empty_table_has_no_default() {
        let r = SniResolver::new();
        assert!(!r.has_default());
        assert!(r.lookup(Some("x.test")).is_none());
    }

    #[test]
    fn reload_replaces_table() {
        let d = temp_dir("reload");
        let a = make_cert(&d, "a", &["a.test"]);
        let r = SniResolver::new();
        r.replace(std::slice::from_ref(&a));
        let before = r.lookup(Some("a.test")).unwrap();
        let a2 = make_cert(&d, "a", &["a.test"]);
        r.replace(&[a2]);
        let after = r.lookup(Some("a.test")).unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn reload_reads_updated_files_from_disk_and_updates_serial() {
        let d = temp_dir("reload_disk_serial");
        let cert_source = make_cert(&d, "site", &["ornek1.test"]);
        let resolver = Arc::new(SniResolver::new());
        let rep1 = resolver.replace(std::slice::from_ref(&cert_source));
        assert_eq!(rep1.loaded, 1);

        let serial_before = resolver
            .lookup_serial(Some("ornek1.test"))
            .expect("ilk sertifika serisi okunabilmeli");
        assert!(!serial_before.is_empty());

        let acceptor = build_acceptor(Arc::clone(&resolver)).unwrap();

        let leaf1 = CertificateDer::from_pem_file(&cert_source.cert_path).unwrap();
        assert_tls_handshake_and_echo(
            acceptor.clone(),
            "ornek1.test",
            &leaf1,
            vec![b"http/1.1".to_vec()],
            Some(b"http/1.1"),
        )
        .await;

        let _updated_cert = make_cert(&d, "site", &["ornek1.test"]);
        let leaf2 = CertificateDer::from_pem_file(&cert_source.cert_path).unwrap();
        assert_ne!(leaf1.as_ref(), leaf2.as_ref());

        let rep2 = resolver.reload();
        assert_eq!(rep2.loaded, 1);

        let serial_after = resolver
            .lookup_serial(Some("ornek1.test"))
            .expect("yenilenen sertifika serisi okunabilmeli");
        assert_ne!(serial_before, serial_after);

        assert_tls_handshake_and_echo(
            acceptor,
            "ornek1.test",
            &leaf2,
            vec![b"http/1.1".to_vec()],
            Some(b"http/1.1"),
        )
        .await;

        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn real_handshake_picks_sni_cert_and_alpn_http11() {
        let d = temp_dir("hs");
        let a = make_cert(&d, "a", &["a.test"]);
        let b = make_cert(&d, "b", &["b.test"]);
        let leaf_b = CertificateDer::from_pem_file(&b.cert_path).unwrap();
        let resolver = Arc::new(SniResolver::new());
        resolver.replace(&[a, b]);
        let acceptor = build_acceptor(Arc::clone(&resolver)).unwrap();

        assert_tls_handshake_and_echo(
            acceptor,
            "b.test",
            &leaf_b,
            vec![b"http/1.1".to_vec()],
            Some(b"http/1.1"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn build_single_cert_acceptor_works_for_panel_listener() {
        let d = temp_dir("panel_single");
        let panel = make_cert(&d, "panel", &["localhost"]);
        let leaf = CertificateDer::from_pem_file(&panel.cert_path).unwrap();

        assert!(build_single_cert_acceptor(&d.join("missing.pem"), &panel.key_path).is_err());

        let acceptor = build_single_cert_acceptor(&panel.cert_path, &panel.key_path).unwrap();
        assert_tls_handshake_and_echo(
            acceptor,
            "localhost",
            &leaf,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(b"http/1.1"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn build_acceptor_negotiates_h2_when_client_offers_h2_and_http11() {
        let d = temp_dir("alpn_h2");
        let a = make_cert(&d, "a", &["a.test"]);
        let b = make_cert(&d, "b", &["b.test"]);
        let leaf_b = CertificateDer::from_pem_file(&b.cert_path).unwrap();
        let resolver = Arc::new(SniResolver::new());
        resolver.replace(&[a, b]);
        let acceptor = build_acceptor(Arc::clone(&resolver)).unwrap();

        assert_tls_handshake_and_echo(
            acceptor,
            "b.test",
            &leaf_b,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(b"h2"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn build_acceptor_falls_back_to_http11_when_client_offers_only_http11() {
        let d = temp_dir("alpn_h1");
        let a = make_cert(&d, "a", &["a.test"]);
        let leaf_a = CertificateDer::from_pem_file(&a.cert_path).unwrap();
        let resolver = Arc::new(SniResolver::new());
        resolver.replace(&[a]);
        let acceptor = build_acceptor(Arc::clone(&resolver)).unwrap();

        assert_tls_handshake_and_echo(
            acceptor,
            "a.test",
            &leaf_a,
            vec![b"http/1.1".to_vec()],
            Some(b"http/1.1"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn build_acceptor_with_alpn_can_disable_h2() {
        let d = temp_dir("alpn_disable_h2");
        let a = make_cert(&d, "a", &["a.test"]);
        let leaf_a = CertificateDer::from_pem_file(&a.cert_path).unwrap();
        let resolver = Arc::new(SniResolver::new());
        resolver.replace(&[a]);
        let acceptor = build_acceptor_with_alpn(resolver, vec![b"http/1.1".to_vec()]).unwrap();

        assert_tls_handshake_and_echo(
            acceptor,
            "a.test",
            &leaf_a,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(b"http/1.1"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn parse_alpn_list_and_single_cert_with_alpn_work() {
        let parsed = parse_alpn_list(&[
            " H2 ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "HTTP/1.1".to_string(),
            "h2".to_string(),
        ]);
        assert_eq!(parsed, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        let d = temp_dir("alpn_single_h2");
        let panel = make_cert(&d, "panel", &["localhost"]);
        let leaf = CertificateDer::from_pem_file(&panel.cert_path).unwrap();
        let acceptor =
            build_single_cert_acceptor_with_alpn(&panel.cert_path, &panel.key_path, parsed).unwrap();

        assert_tls_handshake_and_echo(
            acceptor,
            "localhost",
            &leaf,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(b"h2"),
        )
        .await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn build_acceptor_allows_client_without_alpn() {
        let d = temp_dir("alpn_none");
        let a = make_cert(&d, "a", &["a.test"]);
        let leaf_a = CertificateDer::from_pem_file(&a.cert_path).unwrap();
        let resolver = Arc::new(SniResolver::new());
        resolver.replace(&[a]);
        let acceptor = build_acceptor(resolver).unwrap();

        assert_tls_handshake_and_echo(acceptor, "a.test", &leaf_a, Vec::new(), None).await;
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn listener_tls_builder_with_wildcard_sni_and_resumption() {
        let d = temp_dir("listener_wildcard");
        let wild = make_cert(&d, "wild", &["*.example.com", "example.com"]);
        let leaf_wild = CertificateDer::from_pem_file(&wild.cert_path).unwrap();

        let resolver = Arc::new(SniResolver::new());
        resolver.replace(&[wild]);

        let listener_acceptor = ListenerTlsBuilder::new("main_443")
            .with_resolver(Arc::clone(&resolver))
            .with_min_version(TlsVersion::Tls12)
            .with_max_version(TlsVersion::Tls13)
            .with_alpn(AlpnConfig::h2_and_http11())
            .with_session_config(TlsSessionConfig::new().with_capacity(1024))
            .build()
            .expect("ListenerTlsAcceptor derlenemedi");

        assert_eq!(listener_acceptor.name(), "main_443");
        assert_eq!(listener_acceptor.session_metrics().hits(), 0);

        // Alt alan adı (*.example.com) üzerinden başarılı el sıkışma
        assert_tls_handshake_and_echo(
            listener_acceptor.tls_acceptor().clone(),
            "api.example.com",
            &leaf_wild,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            Some(b"h2"),
        )
        .await;

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn acme_cert_expiry_and_validity_extraction() {
        let d = temp_dir("acme_expiry");
        let cert = make_cert(&d, "site", &["example.test"]);
        let der = CertificateDer::from_pem_file(&cert.cert_path).unwrap();

        let validity = extract_cert_validity(der.as_ref());
        assert!(validity.is_some(), "X.509 geçerlilik tarihleri ayrıştırılabilmeli");
        let (nb, na) = validity.unwrap();
        assert!(na > nb, "Bitiş tarihi başlangıçtan sonra olmalı");

        let days_left = days_until_cert_expiry(der.as_ref());
        assert!(days_left.is_some());
        // rcgen self-signed sertifikalar genelde 1 yıl geçerlidir (>= 300 gün)
        assert!(days_left.unwrap() > 0, "Yeni oluşturulan sertifikanın süresi geçerli olmalı");
        assert!(!is_cert_expired(der.as_ref()));

        let _ = std::fs::remove_dir_all(&d);
    }
}
