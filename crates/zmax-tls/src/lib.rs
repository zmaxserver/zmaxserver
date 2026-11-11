//! # zmax-tls
//! TLS 1.3 / 1.2 (rustls + ring), vhost başına SNI sertifika seçimi ve ALPN.
//!
//! Davranış kararları:
//! * SNI eşleşmezse veya istemci SNI göndermezse: ilk yüklenen sertifika (vhost dosyalarının
//!   ada göre sıralı ilki) varsayılan olarak sunulur; hiç sertifika yoksa el sıkışma reddedilir.
//! * ALPN varsayılan olarak `["h2", "http/1.1"]` sırasıyla duyurulur; istemci yalnız
//!   `http/1.1` sunarsa `http/1.1` seçilir, ayrıca `build_acceptor_with_alpn` ile özelleştirilebilir.
//! * Bozuk/eksik sertifika veya anahtar dosyası sunucuyu çökertmez: o vhost atlanır ve
//!   `LoadReport::skipped` içinde nedeni döner (çağıran log'a yazar).
//! * Sertifika tablosu `SniResolver::replace` ile dinleyiciyi yeniden başlatmadan değiştirilir.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use zmax_config::{resolve_path, LoadedVHost};

pub use tokio_rustls::TlsAcceptor;

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

/// Bir sertifika çiftinin hangi alan adlarına hizmet edeceği.
#[derive(Debug, Clone)]
pub struct CertSource {
    pub label: String,
    pub names: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Atlanan bir vhost sertifikası ve nedeni.
#[derive(Debug, Clone)]
pub struct SkippedCert {
    pub label: String,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct LoadReport {
    pub loaded: usize,
    pub skipped: Vec<SkippedCert>,
}

#[derive(Default)]
struct CertTable {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

/// SNI ile sertifika seçen, çalışırken değiştirilebilir çözümleyici.
pub struct SniResolver {
    table: RwLock<Arc<CertTable>>,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SniResolver")
    }
}

impl SniResolver {
    pub fn new() -> Self {
        Self {
            table: RwLock::new(Arc::new(CertTable::default())),
        }
    }

    /// Kaynaklardan yeni tablo kurar ve tek hamlede değiştirir (sıfır kesinti).
    pub fn replace(&self, sources: &[CertSource]) -> LoadReport {
        let (table, report) = build_table(sources);
        if let Ok(mut guard) = self.table.write() {
            *guard = Arc::new(table);
        }
        report
    }

    pub fn has_default(&self) -> bool {
        self.table
            .read()
            .map(|t| t.default.is_some())
            .unwrap_or(false)
    }

    /// Verilen SNI adı için sertifika (eşleşme yoksa varsayılan).
    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let table = self.table.read().ok()?.clone();
        if let Some(name) = sni {
            let key = name.trim_end_matches('.').to_ascii_lowercase();
            if let Some(ck) = table.by_name.get(&key) {
                return Some(Arc::clone(ck));
            }
        }
        table.default.clone()
    }
}

impl Default for SniResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.lookup(client_hello.server_name())
    }
}

fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("sertifika dosyası açılamadı ({}): {}", cert_path.display(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("sertifika PEM hatası ({}): {}", cert_path.display(), e))?;
    if certs.is_empty() {
        return Err(format!("sertifika dosyasında CERTIFICATE yok ({})", cert_path.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("anahtar dosyası okunamadı ({}): {}", key_path.display(), e))?;
    let signing_key = any_supported_type(&key)
        .map_err(|e| format!("anahtar türü desteklenmiyor ({}): {}", key_path.display(), e))?;
    let ck = CertifiedKey::new(certs, signing_key);
    ck.keys_match()
        .map_err(|e| format!("sertifika ile anahtar uyuşmuyor: {}", e))?;
    Ok(ck)
}

fn build_table(sources: &[CertSource]) -> (CertTable, LoadReport) {
    let mut table = CertTable::default();
    let mut report = LoadReport::default();
    for src in sources {
        match load_certified_key(&src.cert_path, &src.key_path) {
            Ok(ck) => {
                let ck = Arc::new(ck);
                for n in &src.names {
                    let n = n.trim().trim_end_matches('.').to_ascii_lowercase();
                    if !n.is_empty() {
                        table.by_name.entry(n).or_insert_with(|| Arc::clone(&ck));
                    }
                }
                if table.default.is_none() {
                    table.default = Some(Arc::clone(&ck));
                }
                report.loaded += 1;
            }
            Err(reason) => {
                tracing::warn!("TLS sertifikasi atlandi [{}]: {}", src.label, reason);
                report.skipped.push(SkippedCert {
                    label: src.label.clone(),
                    reason,
                });
            }
        }
    }
    (table, report)
}

/// vhost tablosundan sertifika kaynaklarını çıkarır: `[vhost.ssl] certificate/key`
/// ikisi de doluysa; ad + alias adlarıyla. Boş olan vhost için sertifika yoktur.
pub fn sources_from_vhosts(vhosts: &[LoadedVHost], base_dir: &Path) -> Vec<CertSource> {
    vhosts
        .iter()
        .filter(|v| !v.entry.ssl.certificate.trim().is_empty() && !v.entry.ssl.key.trim().is_empty())
        .map(|v| {
            let mut names = vec![v.entry.name.clone()];
            names.extend(v.entry.aliases.iter().cloned());
            CertSource {
                label: v.file_name.clone(),
                names,
                cert_path: resolve_path(base_dir, v.entry.ssl.certificate.trim()),
                key_path: resolve_path(base_dir, v.entry.ssl.key.trim()),
            }
        })
        .collect()
}

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

fn default_alpn_protocols() -> Vec<Vec<u8>> {
    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
}

/// Yapılandırmadaki ALPN protokol adlarını (`"h2"`, `"http/1.1"` vb.) bayt listesine dönüştürür.
/// Boş girdileri ve yinelenen protokolleri sırayı bozmadan temizler.
pub fn parse_alpn_list(alpn: &[String]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for raw in alpn {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let bytes = if trimmed.eq_ignore_ascii_case("h2") {
            b"h2".to_vec()
        } else if trimmed.eq_ignore_ascii_case("http/1.1") {
            b"http/1.1".to_vec()
        } else {
            trimmed.as_bytes().to_vec()
        };
        if !out.contains(&bytes) {
            out.push(bytes);
        }
    }
    out
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

/// Sunucu tarafındaki TLS akışından müzakere edilen ALPN protokolünü okur.
pub fn negotiated_alpn<T>(stream: &tokio_rustls::server::TlsStream<T>) -> Option<Vec<u8>> {
    stream.get_ref().1.alpn_protocol().map(|p| p.to_vec())
}

/// Sunucu tarafındaki TLS akışından istemcinin gönderdiği SNI alan adını okur.
pub fn client_sni<T>(stream: &tokio_rustls::server::TlsStream<T>) -> Option<String> {
    stream.get_ref().1.server_name().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::io::Write;
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
        let a2 = make_cert(&d, "a", &["a.test"]); // aynı yola yeni sertifika
        r.replace(&[a2]);
        let after = r.lookup(Some("a.test")).unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
        let _ = std::fs::remove_dir_all(&d);
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
        let acceptor = build_single_cert_acceptor_with_alpn(&panel.cert_path, &panel.key_path, parsed)
            .unwrap();

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
}
