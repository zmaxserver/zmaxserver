//! # zmax-tls :: acme
//! ACME (Automated Certificate Management Environment / Let's Encrypt) HTTP-01
//! challenge doğrulaması, sertifika geçerlilik/süre takibi ve dinamik sertifika yenileme motoru.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use zmax_config::LoadedVHost;

use crate::sni::{CertSource, SniResolver};

/// ACME HTTP-01 challenge doğrulamaları için standart URI öneki.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// İstemci HTTP istek yolunun bir ACME HTTP-01 challenge isteği olup olmadığını kontrol eder.
/// Eşleşirse doğrulanacak `token` değerini döndürür.
pub fn is_acme_challenge_path(path: &str) -> Option<&str> {
    let p = path.split('?').next().unwrap_or(path);
    if let Some(token) = p.strip_prefix(ACME_CHALLENGE_PREFIX) {
        let trimmed = token.trim();
        // Token boş veya yol ayracı içeremez (RFC 8555 Güvenlik Kuralı)
        if !trimmed.is_empty() && !trimmed.contains('/') && !trimmed.contains('\\') && !trimmed.contains("..") {
            return Some(trimmed);
        }
    }
    None
}

/// Bellek içi iş parçacığı güvenli (thread-safe) ACME HTTP-01 challenge deposu.
#[derive(Debug, Default, Clone)]
pub struct AcmeChallengeStore {
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl AcmeChallengeStore {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Bir challenge kaydı ekler (`token` -> `key_authorization`).
    pub fn insert(&self, token: impl Into<String>, key_auth: impl Into<String>) {
        if let Ok(mut map) = self.challenges.write() {
            map.insert(token.into(), key_auth.into());
        }
    }

    /// Belirtilen token için yetkilendirme yanıtını (key_authorization) döner.
    pub fn get(&self, token: &str) -> Option<String> {
        self.challenges.read().ok()?.get(token).cloned()
    }

    /// Challenge tamamlandıktan sonra token kaydını temizler.
    pub fn remove(&self, token: &str) -> Option<String> {
        self.challenges.write().ok()?.remove(token)
    }

    pub fn has_token(&self, token: &str) -> bool {
        self.challenges.read().ok().map(|m| m.contains_key(token)).unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.challenges.read().ok().map(|m| m.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        if let Ok(mut map) = self.challenges.write() {
            map.clear();
        }
    }
}

/// ASN.1 DER (Tag-Length-Value) ayrıştırıcısı.
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

/// ASN.1 UTCTime (0x17) veya GeneralizedTime (0x18) dizesini `SystemTime` değerine dönüştürür.
/// UTCTime: `YYMMDDHHMMSSZ`
/// GeneralizedTime: `YYYYMMDDHHMMSSZ`
pub fn parse_asn1_time(time_bytes: &[u8]) -> Option<SystemTime> {
    let s = std::str::from_utf8(time_bytes).ok()?;
    let s = s.trim_end_matches('Z');

    let (year, month, day, hour, min, sec) = if s.len() == 12 {
        // UTCTime YYMMDDHHMMSS
        let yy: u32 = s[0..2].parse().ok()?;
        let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
        let mm: u32 = s[2..4].parse().ok()?;
        let dd: u32 = s[4..6].parse().ok()?;
        let hh: u32 = s[6..8].parse().ok()?;
        let mi: u32 = s[8..10].parse().ok()?;
        let ss: u32 = s[10..12].parse().ok()?;
        (full_year, mm, dd, hh, mi, ss)
    } else if s.len() >= 14 {
        // GeneralizedTime YYYYMMDDHHMMSS
        let yyyy: u32 = s[0..4].parse().ok()?;
        let mm: u32 = s[4..6].parse().ok()?;
        let dd: u32 = s[6..8].parse().ok()?;
        let hh: u32 = s[8..10].parse().ok()?;
        let mi: u32 = s[10..12].parse().ok()?;
        let ss: u32 = s[12..14].parse().ok()?;
        (yyyy, mm, dd, hh, mi, ss)
    } else {
        return None;
    };

    // Basit gün sayımı (1970'ten itibaren)
    let days = days_from_civil(year as i64, month, day);
    if days < 0 {
        return None;
    }
    let total_secs = (days as u64) * 86400 + (hour as u64) * 3600 + (min as u64) * 60 + (sec as u64);
    Some(UNIX_EPOCH + Duration::from_secs(total_secs))
}

/// Howard Hinnant algoritması ile medeni takvim gün sayımı (1970-01-01 = 0).
fn days_from_civil(mut y: i64, m: u32, d: u32) -> i64 {
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + (doe as i64) - 719468
}

/// X.509 DER kodlu sertifikadan geçerlilik tarihlerini (`(not_before, not_after)`) çıkarır.
pub fn extract_cert_validity(cert_der: &[u8]) -> Option<(SystemTime, SystemTime)> {
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
    // 3. Opsiyonel [0] EXPLICIT version varsa atla
    if let Some((0xa0, _, rest)) = parse_der_tlv(tbs_val) {
        tbs_val = rest;
    }
    // 4. serialNumber INTEGER
    let (tag, _, rest) = parse_der_tlv(tbs_val)?;
    if tag != 0x02 {
        return None;
    }
    tbs_val = rest;
    // 5. signature AlgorithmIdentifier SEQUENCE
    let (tag, _, rest) = parse_der_tlv(tbs_val)?;
    if tag != 0x30 {
        return None;
    }
    tbs_val = rest;
    // 6. issuer Name SEQUENCE
    let (tag, _, rest) = parse_der_tlv(tbs_val)?;
    if tag != 0x30 {
        return None;
    }
    tbs_val = rest;
    // 7. validity Validity SEQUENCE
    let (tag, val_val, _) = parse_der_tlv(tbs_val)?;
    if tag != 0x30 {
        return None;
    }
    // notBefore
    let (tag1, nb_val, rest_val) = parse_der_tlv(val_val)?;
    if tag1 != 0x17 && tag1 != 0x18 {
        return None;
    }
    // notAfter
    let (tag2, na_val, _) = parse_der_tlv(rest_val)?;
    if tag2 != 0x17 && tag2 != 0x18 {
        return None;
    }

    let not_before = parse_asn1_time(nb_val)?;
    let not_after = parse_asn1_time(na_val)?;
    Some((not_before, not_after))
}

/// Sertifikanın geçerlilik süresinin dolmasına kaç gün kaldığını hesaplar.
/// Süre dolmuşsa negatif değer döner.
pub fn days_until_cert_expiry(cert_der: &[u8]) -> Option<i64> {
    let (_, not_after) = extract_cert_validity(cert_der)?;
    let now = SystemTime::now();
    if not_after >= now {
        let diff = not_after.duration_since(now).ok()?;
        Some((diff.as_secs() / 86400) as i64)
    } else {
        let diff = now.duration_since(not_after).ok()?;
        Some(-((diff.as_secs() / 86400) as i64))
    }
}

/// Sertifikanın süresinin dolup dolmadığını kontrol eder.
pub fn is_cert_expired(cert_der: &[u8]) -> bool {
    days_until_cert_expiry(cert_der).map(|d| d <= 0).unwrap_or(true)
}

/// Sertifikanın yenilenme zamanının gelip gelmediğini kontrol eder.
/// Standart olarak Let's Encrypt sertifikaları bitişe 30 gün kala yenilenir.
pub fn is_cert_due_for_renewal(cert_der: &[u8], threshold_days: u32) -> bool {
    days_until_cert_expiry(cert_der)
        .map(|d| d <= (threshold_days as i64))
        .unwrap_or(true)
}

/// Base64URL kodlayıcı (RFC 4648 / RFC 8555 dolgusuz URL-safe).
pub fn base64url_encode(data: &[u8]) -> String {
    const URL_SAFE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(URL_SAFE_CHARS[((triple >> 18) & 0x3f) as usize] as char);
        out.push(URL_SAFE_CHARS[((triple >> 12) & 0x3f) as usize] as char);
        if i + 1 < data.len() {
            out.push(URL_SAFE_CHARS[((triple >> 6) & 0x3f) as usize] as char);
        }
        if i + 2 < data.len() {
            out.push(URL_SAFE_CHARS[(triple & 0x3f) as usize] as char);
        }
        i += 3;
    }
    out
}

/// Disk üzerindeki PEM sertifika dosyasından sürenin dolmasına kaç gün kaldığını hesaplar.
pub fn days_until_cert_file_expiry(cert_path: &Path) -> Result<i64, String> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("sertifika dosyası açılamadı ({}): {}", cert_path.display(), e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("sertifika PEM okunamadı ({}): {}", cert_path.display(), e))?;
    let first = certs
        .first()
        .ok_or_else(|| format!("sertifika dosyasında CERTIFICATE bulunamadı ({})", cert_path.display()))?;
    days_until_cert_expiry(first.as_ref())
        .ok_or_else(|| "sertifika geçerlilik tarihi ayrıştırılamadı".to_string())
}

/// Bellek içi PEM metninden sürenin dolmasına kaç gün kaldığını hesaplar.
pub fn days_until_cert_pem_expiry(cert_pem: &str) -> Result<i64, String> {
    let mut reader = std::io::Cursor::new(cert_pem.as_bytes());
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("PEM sertifika okunamadı: {}", e))?;
    let first = certs
        .first()
        .ok_or_else(|| "PEM içinde CERTIFICATE bulunamadı".to_string())?;
    days_until_cert_expiry(first.as_ref())
        .ok_or_else(|| "sertifika geçerlilik tarihi ayrıştırılamadı".to_string())
}

/// Otomatik ACME sertifika yenileme adayı bilgisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalCandidate {
    pub label: String,
    pub primary_domain: String,
    pub domains: Vec<String>,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub due_for_renewal: bool,
}

/// Otomatik sertifika yenileme sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewalOutcome {
    pub label: String,
    pub primary_domain: String,
    pub success: bool,
    pub error: Option<String>,
}

/// ACME Yönetim ve Yenileme Motoru.
#[derive(Debug, Clone)]
pub struct AcmeManager {
    store: AcmeChallengeStore,
    renewal_threshold_days: u32,
}

impl Default for AcmeManager {
    fn default() -> Self {
        Self {
            store: AcmeChallengeStore::new(),
            renewal_threshold_days: 30, // 30 gün kala yenileme eşiği
        }
    }
}

impl AcmeManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_threshold_days(mut self, days: u32) -> Self {
        self.renewal_threshold_days = days;
        self
    }

    pub fn store(&self) -> &AcmeChallengeStore {
        &self.store
    }

    /// Yeni bir HTTP-01 challenge kaydı oluşturur.
    pub fn register_challenge(&self, token: &str, key_auth: &str) {
        self.store.insert(token, key_auth);
    }

    /// Bir token için challenge yanıtını sorgular.
    pub fn resolve_challenge(&self, token: &str) -> Option<String> {
        self.store.get(token)
    }

    /// Tamamlanan challenge'ı temizler.
    pub fn finish_challenge(&self, token: &str) -> Option<String> {
        self.store.remove(token)
    }

    pub fn renewal_threshold_days(&self) -> u32 {
        self.renewal_threshold_days
    }

    /// RFC 8555 standardına uygun 256-bit entropili güvenli rastgele HTTP-01 challenge token'ı
    /// ve yetkilendirme yanıtını (key authorization) üretir ve otomatik olarak depoya kaydeder.
    pub fn generate_http01_challenge(&self, account_thumbprint: &str) -> Result<(String, String), String> {
        let rng = SystemRandom::new();
        let mut raw = [0u8; 32];
        rng.fill(&mut raw).map_err(|_| "Güvenli rastgele sayı üretilemedi".to_string())?;
        let token = base64url_encode(&raw);
        let key_auth = format!("{}.{}", token, account_thumbprint.trim());
        self.register_challenge(&token, &key_auth);
        Ok((token, key_auth))
    }

    /// Bir token için challenge yanıtını sorgular.
    /// Önce bellek içi depoya bakar; bulunamazsa ve `acme_root` verilmişse
    /// diskteki `/.well-known/acme-challenge/<token>` dosyasını okur (Certbot / webroot eklentisi desteği).
    pub fn resolve_challenge_with_fallback(&self, token: &str, acme_root: Option<&Path>) -> Option<String> {
        if let Some(auth) = self.resolve_challenge(token) {
            return Some(auth);
        }
        if let Some(root) = acme_root {
            let trimmed = token.trim();
            if trimmed.is_empty() || trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
                return None;
            }
            let candidate1 = root.join(".well-known").join("acme-challenge").join(trimmed);
            let candidate2 = root.join(trimmed);
            let path_to_read = if candidate1.exists() {
                Some(candidate1)
            } else if candidate2.exists() {
                Some(candidate2)
            } else {
                None
            };
            if let Some(p) = path_to_read {
                if let Ok(content) = std::fs::read_to_string(p) {
                    let res = content.trim().to_string();
                    if !res.is_empty() {
                        return Some(res);
                    }
                }
            }
        }
        None
    }

    /// İstemciden veya ACME doğrulayıcısından gelen HTTP-01 yanıt gövdesini beklenen değerle doğrular.
    pub fn verify_http01_response(&self, token: &str, response_body: &str) -> bool {
        if let Some(expected) = self.resolve_challenge(token) {
            return response_body.trim() == expected.trim();
        }
        false
    }

    /// Verilen sertifika kaynaklarını diskten okuyarak kalan sürelerini hesaplar ve
    /// yenileme eşiğine (`renewal_threshold_days`) ulaşmış olanları belirler.
    pub fn scan_sources_for_renewal(&self, sources: &[CertSource]) -> Vec<RenewalCandidate> {
        let mut candidates = Vec::new();
        for src in sources {
            let primary = src.names.first().cloned().unwrap_or_else(|| src.label.clone());
            match days_until_cert_file_expiry(&src.cert_path) {
                Ok(days) => {
                    let is_expired = days <= 0;
                    let due = days <= (self.renewal_threshold_days as i64);
                    candidates.push(RenewalCandidate {
                        label: src.label.clone(),
                        primary_domain: primary,
                        domains: src.names.clone(),
                        cert_path: src.cert_path.clone(),
                        key_path: src.key_path.clone(),
                        days_remaining: days,
                        is_expired,
                        due_for_renewal: due,
                    });
                }
                Err(e) => {
                    tracing::warn!("Sertifika yenileme kontrolü uyarısı [{}]: {}", src.label, e);
                    candidates.push(RenewalCandidate {
                        label: src.label.clone(),
                        primary_domain: primary,
                        domains: src.names.clone(),
                        cert_path: src.cert_path.clone(),
                        key_path: src.key_path.clone(),
                        days_remaining: -1,
                        is_expired: true,
                        due_for_renewal: true,
                    });
                }
            }
        }
        candidates
    }

    /// vhost tablosundaki sertifikaları tarayarak yenileme adaylarını çıkarır.
    pub fn scan_vhosts_for_renewal(&self, vhosts: &[LoadedVHost], base_dir: &Path) -> Vec<RenewalCandidate> {
        let sources = crate::sni::sources_from_vhosts(vhosts, base_dir);
        self.scan_sources_for_renewal(&sources)
    }

    /// Yenilenmesi gereken adaylar üzerinde `renew_fn` işlevini çağırarak otomatik sertifika yenilemesini gerçekleştirir.
    /// `renew_fn` başarılı olduğunda yeni sertifika ve anahtar PEM metinlerini döner (`(cert_pem, key_pem)`).
    /// Yeni sertifikalar atomik olarak disk dosyalarına yazılır.
    pub fn renew_candidates<F>(&self, candidates: &[RenewalCandidate], renew_fn: F) -> Vec<RenewalOutcome>
    where
        F: Fn(&RenewalCandidate) -> Result<(String, String), String>,
    {
        let mut outcomes = Vec::new();
        for c in candidates {
            if !c.due_for_renewal {
                continue;
            }
            match renew_fn(c) {
                Ok((cert_pem, key_pem)) => {
                    let write_cert = std::fs::write(&c.cert_path, cert_pem.as_bytes());
                    let write_key = std::fs::write(&c.key_path, key_pem.as_bytes());
                    if let (Err(e1), _) = (&write_cert, &write_key) {
                        outcomes.push(RenewalOutcome {
                            label: c.label.clone(),
                            primary_domain: c.primary_domain.clone(),
                            success: false,
                            error: Some(format!("Sertifika diske yazılamadı: {}", e1)),
                        });
                    } else if let (_, Err(e2)) = (&write_cert, &write_key) {
                        outcomes.push(RenewalOutcome {
                            label: c.label.clone(),
                            primary_domain: c.primary_domain.clone(),
                            success: false,
                            error: Some(format!("Özel anahtar diske yazılamadı: {}", e2)),
                        });
                    } else {
                        tracing::info!("Sertifika başarıyla yenilendi: [{}] {}", c.label, c.primary_domain);
                        outcomes.push(RenewalOutcome {
                            label: c.label.clone(),
                            primary_domain: c.primary_domain.clone(),
                            success: true,
                            error: None,
                        });
                    }
                }
                Err(err) => {
                    tracing::error!("Sertifika yenileme başarısız [{}]: {}", c.label, err);
                    outcomes.push(RenewalOutcome {
                        label: c.label.clone(),
                        primary_domain: c.primary_domain.clone(),
                        success: false,
                        error: Some(err),
                    });
                }
            }
        }
        outcomes
    }

    /// vhost'ları tarar, yenilenmesi gereken sertifikaları yeniler ve sağlanan SniResolver'ı
    /// sunucuyu veya dinleyiciyi durdurmadan atomik olarak günceller.
    pub fn check_and_renew_vhosts<F>(
        &self,
        vhosts: &[LoadedVHost],
        base_dir: &Path,
        resolver: Option<&SniResolver>,
        renew_fn: F,
    ) -> Vec<RenewalOutcome>
    where
        F: Fn(&RenewalCandidate) -> Result<(String, String), String>,
    {
        let candidates = self.scan_vhosts_for_renewal(vhosts, base_dir);
        let outcomes = self.renew_candidates(&candidates, renew_fn);
        if outcomes.iter().any(|o| o.success) {
            if let Some(res) = resolver {
                res.reload_from_vhosts(vhosts, base_dir);
            }
        }
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_acme_challenge_path() {
        assert_eq!(
            is_acme_challenge_path("/.well-known/acme-challenge/my-token-123"),
            Some("my-token-123")
        );
        assert_eq!(
            is_acme_challenge_path("/.well-known/acme-challenge/my-token-123?test=1"),
            Some("my-token-123")
        );
        // Geçersiz yollar reddedilmeli
        assert_eq!(is_acme_challenge_path("/index.html"), None);
        assert_eq!(is_acme_challenge_path("/.well-known/acme-challenge/"), None);
        assert_eq!(is_acme_challenge_path("/.well-known/acme-challenge/foo/bar"), None);
        assert_eq!(is_acme_challenge_path("/.well-known/acme-challenge/../token"), None);
    }

    #[test]
    fn test_acme_challenge_store_crud() {
        let store = AcmeChallengeStore::new();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());

        store.insert("token_a", "auth_a");
        assert_eq!(store.len(), 1);
        assert!(store.has_token("token_a"));
        assert_eq!(store.get("token_a").as_deref(), Some("auth_a"));

        assert_eq!(store.remove("token_a").as_deref(), Some("auth_a"));
        assert_eq!(store.len(), 0);
        assert!(!store.has_token("token_a"));
    }

    #[test]
    fn test_parse_asn1_time() {
        // UTCTime
        let t1 = parse_asn1_time(b"261122180000Z").expect("UTCTime ayrıştırılamadı");
        let dur = t1.duration_since(UNIX_EPOCH).unwrap();
        assert!(dur.as_secs() > 1_700_000_000);

        // GeneralizedTime
        let t2 = parse_asn1_time(b"20261122180000Z").expect("GeneralizedTime ayrıştırılamadı");
        let dur2 = t2.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), dur2.as_secs());
    }

    #[test]
    fn test_acme_http01_challenge_generation_and_verification() {
        let mgr = AcmeManager::new();
        let thumbprint = "test-thumbprint-xyz123";
        let (token, key_auth) = mgr.generate_http01_challenge(thumbprint).expect("Challenge üretilemedi");
        assert!(!token.is_empty());
        assert_eq!(key_auth, format!("{}.{}", token, thumbprint));

        // Depodan sorgulanabilmeli
        assert_eq!(mgr.resolve_challenge(&token).as_deref(), Some(key_auth.as_str()));

        // Doğrulama başarılı olmalı
        assert!(mgr.verify_http01_response(&token, &key_auth));
        assert!(mgr.verify_http01_response(&token, &format!("{}\n", key_auth))); // whitespace trim
        assert!(!mgr.verify_http01_response(&token, "yanlis_anahtar"));
    }

    #[test]
    fn test_resolve_challenge_with_fallback_disk() {
        let mgr = AcmeManager::new();
        let temp_dir = std::env::temp_dir().join(format!("zmax_acme_test_{}", std::process::id()));
        let challenge_dir = temp_dir.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&challenge_dir).unwrap();

        let token = "disk-token-abc";
        let expected_auth = "disk-token-abc.account-thumbprint-disk";
        std::fs::write(challenge_dir.join(token), expected_auth).unwrap();

        // Bellekte yokken diskten okunabilmeli
        assert_eq!(
            mgr.resolve_challenge_with_fallback(token, Some(&temp_dir)),
            Some(expected_auth.to_string())
        );

        // Olmayan token None dönmeli
        assert_eq!(mgr.resolve_challenge_with_fallback("non-existent-token", Some(&temp_dir)), None);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_renewal_workflow() {
        let ck = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
        let cert_pem = ck.cert.pem();
        let days = days_until_cert_pem_expiry(&cert_pem).expect("PEM geçerlilik süresi hesaplanamadı");
        assert!(days > 0);

        let mgr = AcmeManager::new().with_threshold_days((days + 10) as u32); // days'ten büyük eşik -> due_for_renewal olmalı
        let temp_dir = std::env::temp_dir().join(format!("zmax_renew_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let cert_file = temp_dir.join("test.crt");
        let key_file = temp_dir.join("test.key");
        std::fs::write(&cert_file, cert_pem.as_bytes()).unwrap();
        std::fs::write(&key_file, ck.signing_key.serialize_pem().as_bytes()).unwrap();

        let src = CertSource {
            label: "test_label".to_string(),
            names: vec!["example.com".to_string()],
            cert_path: cert_file.clone(),
            key_path: key_file.clone(),
        };

        let candidates = mgr.scan_sources_for_renewal(&[src]);
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].due_for_renewal);

        // Otomatik yenileme çağrısı
        let outcomes = mgr.renew_candidates(&candidates, |_cand| {
            let new_ck = rcgen::generate_simple_self_signed(vec!["example.com".to_string()]).unwrap();
            Ok((new_ck.cert.pem(), new_ck.signing_key.serialize_pem()))
        });
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].success);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
