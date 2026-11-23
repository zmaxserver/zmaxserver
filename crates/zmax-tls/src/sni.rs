//! # zmax-tls :: sni
//! SNI (Server Name Indication) çoklu alan adı sertifika eşleme,
//! joker karakter (wildcard `*.example.com`) çözümleme ve çalışma zamanında
//! kesintisiz dinamik sertifika yenileme motoru.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use rustls::crypto::ring::sign::any_supported_type;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use zmax_config::{resolve_path, LoadedVHost};

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
    wildcards: HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

/// SNI ile sertifika seçen, wildcard eşleyen ve çalışırken değiştirilebilir çözümleyici.
pub struct SniResolver {
    table: RwLock<Arc<CertTable>>,
    sources: RwLock<Vec<CertSource>>,
    strict_sni: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for SniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let domain_count = self.table.read().map(|t| t.by_name.len() + t.wildcards.len()).unwrap_or(0);
        f.debug_struct("SniResolver")
            .field("domains", &domain_count)
            .field("has_default", &self.has_default())
            .field("strict_sni", &self.is_strict_sni())
            .finish()
    }
}

impl SniResolver {
    pub fn new() -> Self {
        Self {
            table: RwLock::new(Arc::new(CertTable::default())),
            sources: RwLock::new(Vec::new()),
            // Varsayılan gevşek tutulur; üretimde boot, config.listeners.https.strict_sni
            // değerini set_strict_sni() ile uygular (mevcut test istemcileri SNI göndermiyor).
            strict_sni: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Strict SNI modunu ayarlar: true ise eşleşmeyen veya SNI göndermeyen istemcilerin el sıkışması reddedilir.
    pub fn set_strict_sni(&self, strict: bool) {
        self.strict_sni.store(strict, std::sync::atomic::Ordering::SeqCst);
    }

    /// Strict SNI modunun etkin olup olmadığını döndürür.
    pub fn is_strict_sni(&self) -> bool {
        self.strict_sni.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Kaynaklardan yeni tablo kurar ve tek hamlede atomik olarak değiştirir (sıfır kesinti).
    /// Verilen kaynaklar ilerideki `reload()` çağrıları için saklanır.
    pub fn replace(&self, sources: &[CertSource]) -> LoadReport {
        if let Ok(mut s) = self.sources.write() {
            *s = sources.to_vec();
        }
        let (table, report) = build_table(sources);
        if let Ok(mut guard) = self.table.write() {
            *guard = Arc::new(table);
        }
        report
    }

    /// Saklanan sertifika kaynaklarını diskten YENİDEN okuyarak tabloyu atomik olarak günceller.
    /// Certbot veya ACME diskteki sertifikayı yenilediğinde dinleyiciyi durdurmadan yeni sertifikayı sunar.
    pub fn reload(&self) -> LoadReport {
        let current_sources = self.sources.read().map(|s| s.clone()).unwrap_or_default();
        let (table, report) = build_table(&current_sources);
        if let Ok(mut guard) = self.table.write() {
            *guard = Arc::new(table);
        }
        report
    }

    /// vhost tablosundaki güncel yapılandırmadan kaynakları çıkarır ve tabloyu günceller.
    pub fn reload_from_vhosts(&self, vhosts: &[LoadedVHost], base_dir: &Path) -> LoadReport {
        let sources = sources_from_vhosts(vhosts, base_dir);
        self.replace(&sources)
    }

    /// Çalışma zamanında (runtime) tek bir sertifikayı diskten okuyup anında tabloya ekler.
    pub fn add_certificate_source(&self, src: CertSource) -> Result<(), String> {
        let ck = Arc::new(load_certified_key(&src.cert_path, &src.key_path)?);
        self.register_certified_key(&src.names, ck);
        if let Ok(mut sources) = self.sources.write() {
            sources.retain(|s| s.label != src.label);
            sources.push(src);
        }
        Ok(())
    }

    /// Çalışma zamanında PEM dizesi olarak sağlanan sertifika ve özel anahtarı ekler (ACME için).
    pub fn add_certificate_pem(
        &self,
        label: &str,
        names: &[&str],
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<(), String> {
        let ck = Arc::new(load_certified_key_from_pem(cert_pem, key_pem)?);
        let names_vec: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        self.register_certified_key(&names_vec, ck);
        tracing::info!("TLS sertifikası PEM ile eklendi: [{}] {:?}", label, names);
        Ok(())
    }

    /// Önceden derlenmiş CertifiedKey nesnesini isim listesiyle tabloya kaydeder.
    pub fn register_certified_key(&self, names: &[String], ck: Arc<CertifiedKey>) {
        if let Ok(mut guard) = self.table.write() {
            let mut new_table = CertTable {
                by_name: guard.by_name.clone(),
                wildcards: guard.wildcards.clone(),
                default: guard.default.clone(),
            };
            for n in names {
                let n = n.trim().trim_end_matches('.').to_ascii_lowercase();
                if n.is_empty() {
                    continue;
                }
                if let Some(suffix) = n.strip_prefix("*.") {
                    new_table.wildcards.insert(suffix.to_string(), Arc::clone(&ck));
                } else {
                    new_table.by_name.insert(n, Arc::clone(&ck));
                }
            }
            if new_table.default.is_none() {
                new_table.default = Some(Arc::clone(&ck));
            }
            *guard = Arc::new(new_table);
        }
    }

    /// Belirtilen alan adını tablodan siler.
    pub fn remove_domain(&self, domain: &str) -> bool {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Ok(mut guard) = self.table.write() {
            let mut new_table = CertTable {
                by_name: guard.by_name.clone(),
                wildcards: guard.wildcards.clone(),
                default: guard.default.clone(),
            };
            let removed = if let Some(suffix) = d.strip_prefix("*.") {
                new_table.wildcards.remove(suffix).is_some()
            } else {
                new_table.by_name.remove(&d).is_some()
            };
            *guard = Arc::new(new_table);
            removed
        } else {
            false
        }
    }

    /// Çalışma zamanında tek bir vhost'un sertifikasını yükler ve tabloya ekler.
    pub fn add_vhost_certificate(&self, vhost: &LoadedVHost, base_dir: &Path) -> Result<(), String> {
        let cert_str = vhost.entry.ssl.certificate.trim();
        let key_str = vhost.entry.ssl.key.trim();
        if cert_str.is_empty() || key_str.is_empty() {
            return Err(format!("vhost '{}' SSL sertifika veya anahtar yolu boş", vhost.entry.name));
        }
        let cert_path = resolve_path(base_dir, cert_str);
        let key_path = resolve_path(base_dir, key_str);
        let mut names = vec![vhost.entry.name.clone()];
        names.extend(vhost.entry.aliases.iter().cloned());
        let src = CertSource {
            label: vhost.file_name.clone(),
            names,
            cert_path,
            key_path,
        };
        self.add_certificate_source(src)
    }

    /// Çalışma zamanında bir vhost'un alan adlarını ve takma adlarını tablodan kaldırır.
    pub fn remove_vhost_certificate(&self, vhost: &LoadedVHost) {
        self.remove_domain(&vhost.entry.name);
        for a in &vhost.entry.aliases {
            self.remove_domain(a);
        }
        if let Ok(mut sources) = self.sources.write() {
            sources.retain(|s| s.label != vhost.file_name);
        }
    }

    /// Çözümleyicide kayıtlı mevcut sertifika kaynaklarını döndürür.
    pub fn current_sources(&self) -> Vec<CertSource> {
        self.sources.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Varsayılan sertifika atanmış mı?
    pub fn has_default(&self) -> bool {
        self.table
            .read()
            .map(|t| t.default.is_some())
            .unwrap_or(false)
    }

    /// Kayıtlı alan adı sayısı (tam eşleşmeler + wildcard'lar).
    pub fn domain_count(&self) -> usize {
        self.table
            .read()
            .map(|t| t.by_name.len() + t.wildcards.len())
            .unwrap_or(0)
    }

    /// Kayıtlı tüm alan adlarının listesini döner.
    pub fn list_domains(&self) -> Vec<String> {
        let mut list = Vec::new();
        if let Ok(guard) = self.table.read() {
            list.extend(guard.by_name.keys().cloned());
            for w in guard.wildcards.keys() {
                list.push(format!("*.{}", w));
            }
        }
        list.sort();
        list
    }

    /// Belirtilen alan adının tabloda bulunup bulunmadığını sorgular.
    pub fn has_domain(&self, domain: &str) -> bool {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Ok(guard) = self.table.read() {
            if guard.by_name.contains_key(&d) {
                return true;
            }
            if let Some(suffix) = d.strip_prefix("*.") {
                if guard.wildcards.contains_key(suffix) {
                    return true;
                }
            }
            // Alt alan adı wildcard eşleşmesi
            let parts: Vec<&str> = d.split('.').collect();
            for i in 1..parts.len() {
                let candidate = parts[i..].join(".");
                if guard.wildcards.contains_key(&candidate) {
                    return true;
                }
            }
        }
        false
    }

    /// Verilen SNI adı için sertifika (önce tam eşleşme, sonra wildcard, yoksa varsayılan).
    pub fn lookup(&self, sni: Option<&str>) -> Option<Arc<CertifiedKey>> {
        let table = self.table.read().ok()?.clone();
        if let Some(name) = sni {
            let key = name.trim_end_matches('.').to_ascii_lowercase();
            // 1. Tam eşleşme (Exact Match)
            if let Some(ck) = table.by_name.get(&key) {
                return Some(Arc::clone(ck));
            }
            // 2. Joker karakter eşleşmesi (*.domain.com)
            let parts: Vec<&str> = key.split('.').collect();
            for i in 1..parts.len() {
                let candidate = parts[i..].join(".");
                if let Some(ck) = table.wildcards.get(&candidate) {
                    return Some(Arc::clone(ck));
                }
            }
        }
        if self.is_strict_sni() {
            // Strict SNI: Eşleşme yoksa veya SNI gönderilmediyse varsayılan sertifikaya düşme, el sıkışmayı reddet
            return None;
        }
        // 3. Eşleşme yoksa veya SNI gönderilmediyse varsayılan sertifika
        table.default.clone()
    }

    /// Belirtilen SNI adı (veya varsayılan) için sunulacak sertifikanın
    /// X.509 seri numarasını küçük harf onaltılık (hex) dize olarak döndürür.
    pub fn lookup_serial(&self, sni: Option<&str>) -> Option<String> {
        let ck = self.lookup(sni)?;
        let first_der = ck.cert.first()?;
        extract_cert_serial_hex(first_der.as_ref())
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

pub fn load_certified_key(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey, String> {
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

pub fn load_certified_key_from_pem(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey, String> {
    let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("PEM sertifika ayrıştırma hatası: {}", e))?;
    if certs.is_empty() {
        return Err("PEM içeriğinde geçerli CERTIFICATE bloğu bulunamadı".to_string());
    }

    let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .map_err(|e| format!("PEM özel anahtar ayrıştırma hatası: {}", e))?;
    let signing_key = any_supported_type(&key)
        .map_err(|e| format!("PEM anahtar türü desteklenmiyor: {}", e))?;
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
                    if n.is_empty() {
                        continue;
                    }
                    if let Some(suffix) = n.strip_prefix("*.") {
                        table.wildcards.entry(suffix.to_string()).or_insert_with(|| Arc::clone(&ck));
                    } else {
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

/// vhost tablosundan dinleyici eşlemelerine (vhost_mappings) göre filtrelenmiş sertifika kaynaklarını çıkarır.
/// Eğer `vhost_mappings` "*" içeriyorsa veya boşsa, tüm SSL tanımlı vhost'lar dahil edilir.
/// Aksi halde yalnızca eşleşen vhost'ların sertifikaları seçilir.
pub fn sources_from_vhosts_filtered(
    vhosts: &[LoadedVHost],
    base_dir: &Path,
    vhost_mappings: &[String],
) -> Vec<CertSource> {
    let match_all = vhost_mappings.is_empty() || vhost_mappings.iter().any(|m| m.trim() == "*");
    vhosts
        .iter()
        .filter(|v| {
            if v.entry.ssl.certificate.trim().is_empty() || v.entry.ssl.key.trim().is_empty() {
                return false;
            }
            if match_all {
                return true;
            }
            let vhost_name = v.entry.name.to_ascii_lowercase();
            let file_stem = v.file_name.trim_end_matches(".toml").to_ascii_lowercase();
            vhost_mappings.iter().any(|m| {
                let m_lower = m.trim().to_ascii_lowercase();
                if m_lower == "*" {
                    return true;
                }
                let target = m_lower.split(':').next().unwrap_or(&m_lower).trim();
                target == vhost_name
                    || target == file_stem
                    || v.entry.aliases.iter().any(|a| a.to_ascii_lowercase() == target)
            })
        })
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

/// Basit ASN.1 DER (Tag-Length-Value) ayrıştırıcısı.
fn parse_der_tlv<'a>(input: &'a [u8]) -> Option<(u8, &'a [u8], &'a [u8])> {
    if input.is_empty() {
        return None;
    }
    let tag = input[0];
    let mut i = 1;
    if i >= input.len() {
        return None;
    }
    let len_byte = input[i];
    i += 1;
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let count = (len_byte & 0x7f) as usize;
        if count == 0 || count > 4 || i + count > input.len() {
            return None;
        }
        let mut l = 0usize;
        for &b in &input[i..i + count] {
            l = (l << 8) | (b as usize);
        }
        i += count;
        l
    };
    if i + len > input.len() {
        return None;
    }
    let value = &input[i..i + len];
    let rest = &input[i + len..];
    Some((tag, value, rest))
}

/// Bir DER kodlu X.509 sertifikasının seri numarasını onaltılık (hex) dize olarak çıkarır.
pub fn extract_cert_serial_hex(cert_der: &[u8]) -> Option<String> {
    // 1. Certificate SEQUENCE
    let (tag, cert_val, _) = parse_der_tlv(cert_der)?;
    if tag != 0x30 {
        return None;
    }
    // 2. TBSCertificate SEQUENCE
    let (tag, mut tbs_val, _) = parse_der_tlv(cert_val)?;
    if tag != 0x30 {
        return None;
    }
    // 3. Opsiyonel [0] EXPLICIT version varsa geç
    if let Some((0xa0, _, rest)) = parse_der_tlv(tbs_val) {
        tbs_val = rest;
    }
    // 4. INTEGER serialNumber
    let (tag, serial_bytes, _) = parse_der_tlv(tbs_val)?;
    if tag != 0x02 || serial_bytes.is_empty() {
        return None;
    }
    // Pozitif ASN.1 INTEGER için baştaki 0x00 işaret baytını ayıkla
    let s_bytes = if serial_bytes.len() > 1 && serial_bytes[0] == 0 {
        &serial_bytes[1..]
    } else {
        serial_bytes
    };
    let mut hex = String::with_capacity(s_bytes.len() * 2);
    for b in s_bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    Some(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_ck(names: &[&str]) -> (String, String) {
        let ck = rcgen::generate_simple_self_signed(
            names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        (ck.cert.pem(), ck.signing_key.serialize_pem())
    }

    #[test]
    fn test_sni_wildcard_matching() {
        let (cert_pem, key_pem) = generate_test_ck(&["*.example.com", "example.com"]);
        let resolver = SniResolver::new();
        resolver
            .add_certificate_pem("wildcard", &["*.example.com", "example.com"], &cert_pem, &key_pem)
            .expect("Wildcard sertifika eklenemedi");

        assert!(resolver.has_domain("*.example.com"));
        assert!(resolver.has_domain("sub.example.com"));
        assert!(resolver.has_domain("foo.bar.example.com"));
        assert!(resolver.has_domain("example.com"));

        let ck1 = resolver.lookup(Some("sub.example.com"));
        assert!(ck1.is_some());
        let ck2 = resolver.lookup(Some("foo.bar.example.com"));
        assert!(ck2.is_some());
        assert!(Arc::ptr_eq(&ck1.unwrap(), &ck2.unwrap()));
    }

    #[test]
    fn test_sni_dynamic_registration_and_removal() {
        let (c1, k1) = generate_test_ck(&["site1.test"]);
        let (c2, k2) = generate_test_ck(&["site2.test"]);

        let resolver = SniResolver::new();
        assert_eq!(resolver.domain_count(), 0);

        resolver.add_certificate_pem("s1", &["site1.test"], &c1, &k1).unwrap();
        assert_eq!(resolver.domain_count(), 1);
        assert!(resolver.has_domain("site1.test"));

        resolver.add_certificate_pem("s2", &["site2.test"], &c2, &k2).unwrap();
        assert_eq!(resolver.domain_count(), 2);

        assert!(resolver.remove_domain("site1.test"));
        assert_eq!(resolver.domain_count(), 1);
        assert!(!resolver.has_domain("site1.test"));
    }

    #[test]
    fn test_sources_from_vhosts_filtered() {
        use zmax_config::{LoadedVHost, VHostEntry, VHostSslSection};
        let vh1 = LoadedVHost {
            file_name: "site1.toml".to_string(),
            resolved_doc_root: PathBuf::from("/var/zmax/site1"),
            entry: VHostEntry {
                name: "site1.com".to_string(),
                aliases: vec!["www.site1.com".to_string()],
                ssl: VHostSslSection {
                    certificate: "certs/site1.crt".to_string(),
                    key: "certs/site1.key".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let vh2 = LoadedVHost {
            file_name: "site2.toml".to_string(),
            resolved_doc_root: PathBuf::from("/var/zmax/site2"),
            entry: VHostEntry {
                name: "site2.com".to_string(),
                ssl: VHostSslSection {
                    certificate: "certs/site2.crt".to_string(),
                    key: "certs/site2.key".to_string(),
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let vhosts = vec![vh1, vh2];
        let base = Path::new("/var/zmax");

        // Yıldız "*" ile hepsi dahil edilmeli
        let all = sources_from_vhosts_filtered(&vhosts, base, &["*".to_string()]);
        assert_eq!(all.len(), 2);

        // Yalnızca site1 filtrelenmeli
        let filtered1 = sources_from_vhosts_filtered(&vhosts, base, &["site1.com".to_string()]);
        assert_eq!(filtered1.len(), 1);
        assert_eq!(filtered1[0].names[0], "site1.com");

        // Alias ile filtreleme
        let filtered_alias = sources_from_vhosts_filtered(&vhosts, base, &["www.site1.com".to_string()]);
        assert_eq!(filtered_alias.len(), 1);
        assert_eq!(filtered_alias[0].label, "site1.toml");
    }
}
