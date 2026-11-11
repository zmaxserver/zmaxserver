use std::path::{Path, PathBuf};
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use zmax_config::{LoadedVHost, VHostEntry};
use zmax_tls::{build_acceptor, extract_cert_serial_hex, CertSource, SniResolver};

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("zmax_tls_integ_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn generate_test_cert(dir: &Path, name: &str, san_list: &[&str]) -> CertSource {
    let mut params = rcgen::CertificateParams::new(
        san_list.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);

    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    let cert_path = dir.join(format!("{}.crt", name));
    let key_path = dir.join(format!("{}.key", name));

    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    CertSource {
        label: name.to_string(),
        names: san_list.iter().map(|s| s.to_string()).collect(),
        cert_path,
        key_path,
    }
}

#[derive(Debug)]
struct DangerSkipVerify;

impl rustls::client::danger::ServerCertVerifier for DangerSkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn perform_tls_handshake_and_get_peer_serial(
    acceptor: zmax_tls::TlsAcceptor,
    sni_hostname: &str,
) -> String {
    let (client_io, server_io) = tokio::io::duplex(8192);

    let server_task = tokio::spawn(async move {
        let mut tls = acceptor.accept(server_io).await.expect("TLS kabul hatası");
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.unwrap();
        tls.write_all(b"PONG").await.unwrap();
        tls.flush().await.unwrap();
    });

    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(DangerSkipVerify))
    .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(sni_hostname)
        .expect("Geçersiz SNI host adı")
        .to_owned();

    let mut client_tls = connector
        .connect(server_name, client_io)
        .await
        .expect("TLS istemci el sıkışması başarısız");

    let peer_cert_der = client_tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .expect("Sunucu sertifikası bulunamadı")
        .clone();

    client_tls.write_all(b"PING").await.unwrap();
    let mut resp = Vec::new();
    client_tls.read_to_end(&mut resp).await.ok();
    assert_eq!(&resp, b"PONG");

    server_task.await.unwrap();

    extract_cert_serial_hex(peer_cert_der.as_ref())
        .expect("Sertifika seri numarası ayrıştırılamadı")
}

#[tokio::test]
async fn test_tls_reload_serves_new_certificate_after_disk_renewal() {
    let dir = temp_dir("renewal");
    let cert1 = generate_test_cert(&dir, "ornek1", &["ornek1.test"]);
    let cert2 = generate_test_cert(&dir, "ornek2", &["ornek2.test"]);

    let resolver = Arc::new(SniResolver::new());
    let rep = resolver.replace(&[cert1.clone(), cert2.clone()]);
    assert_eq!(rep.loaded, 2);

    let acceptor = build_acceptor(Arc::clone(&resolver)).expect("TLS dinleyicisi kurulmalı");

    // 1. İlk sertifika el sıkışması ve seri numarası kontrolü
    let serial1_before = perform_tls_handshake_and_get_peer_serial(acceptor.clone(), "ornek1.test").await;
    let serial2_before = perform_tls_handshake_and_get_peer_serial(acceptor.clone(), "ornek2.test").await;
    assert_ne!(serial1_before, serial2_before);

    let lookup_serial1_before = resolver.lookup_serial(Some("ornek1.test")).unwrap();
    assert_eq!(serial1_before, lookup_serial1_before);

    // 2. Certbot yenileme simülasyonu: diskteki ornek1.crt ve ornek1.key dosyaları yenileniyor!
    let _cert1_renewed = generate_test_cert(&dir, "ornek1", &["ornek1.test"]);

    // 3. API reload / SIGHUP tetikleniyor: resolver.reload() diskteki dosyaları yeniden okuyor
    let reload_rep = resolver.reload();
    assert_eq!(reload_rep.loaded, 2);
    assert!(reload_rep.skipped.is_empty());

    let lookup_serial1_after = resolver.lookup_serial(Some("ornek1.test")).unwrap();
    assert_ne!(
        lookup_serial1_before, lookup_serial1_after,
        "Yenileme sonrası lookup_serial değişmiş olmalı (Önce: {}, Sonra: {})",
        lookup_serial1_before, lookup_serial1_after
    );

    // 4. Canlı TLS el sıkışmasında dinleyici yeniden başlatılmadan YENİ sertifikanın sunulduğu kanıtlanıyor!
    let serial1_after = perform_tls_handshake_and_get_peer_serial(acceptor.clone(), "ornek1.test").await;
    assert_eq!(serial1_after, lookup_serial1_after);
    assert_ne!(
        serial1_before, serial1_after,
        "El sıkışmada sunulan sertifikanın seri numarası güncellendi!"
    );

    // ornek2 sertifikası değişmediği için aynı kalmalı
    let serial2_after = perform_tls_handshake_and_get_peer_serial(acceptor.clone(), "ornek2.test").await;
    assert_eq!(serial2_before, serial2_after);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_tls_reload_from_vhosts_updates_sni_table() {
    let dir = temp_dir("vhost_reload");
    let _c = generate_test_cert(&dir, "vhost_site", &["vhost.test", "www.vhost.test"]);

    let mut entry = VHostEntry::default();
    entry.name = "vhost.test".to_string();
    entry.aliases = vec!["www.vhost.test".to_string()];
    entry.ssl.certificate = "vhost_site.crt".to_string();
    entry.ssl.key = "vhost_site.key".to_string();

    let loaded_vh = LoadedVHost {
        file_name: "vhost.toml".to_string(),
        entry,
        resolved_doc_root: dir.clone(),
    };

    let resolver = Arc::new(SniResolver::new());
    let rep = resolver.reload_from_vhosts(&[loaded_vh.clone()], &dir);
    assert_eq!(rep.loaded, 1);

    let acceptor = build_acceptor(Arc::clone(&resolver)).unwrap();
    let serial_before = perform_tls_handshake_and_get_peer_serial(acceptor.clone(), "vhost.test").await;
    let alias_serial_before =
        perform_tls_handshake_and_get_peer_serial(acceptor.clone(), "www.vhost.test").await;
    assert_eq!(serial_before, alias_serial_before);

    // Diskteki sertifikayı yenile
    let _ = generate_test_cert(&dir, "vhost_site", &["vhost.test", "www.vhost.test"]);

    // Yeniden yükleme
    let rep_after = resolver.reload_from_vhosts(&[loaded_vh], &dir);
    assert_eq!(rep_after.loaded, 1);

    let serial_after = perform_tls_handshake_and_get_peer_serial(acceptor, "vhost.test").await;
    assert_ne!(
        serial_before, serial_after,
        "vhost reload sonrası yeni sertifika başarıyla sunuldu"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
