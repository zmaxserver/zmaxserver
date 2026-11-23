//! # zmax-security :: acl
//! Sanal konak ve küresel düzeyde IP ve CIDR tabanlı erişim kontrolü (Allow / Deny listeleri).

use std::net::IpAddr;
use crate::{ip_matches_cidr_spec, is_valid_ip_or_cidr};

/// Tekil IP ve CIDR kurallarını değerlendiren erişim kontrol listesi motoru.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VhostAcl {
    pub allow_ips: Vec<String>,
    pub deny_ips: Vec<String>,
}

impl VhostAcl {
    /// Yeni bir `VhostAcl` oluşturur.
    pub fn new(allow_ips: Vec<String>, deny_ips: Vec<String>) -> Self {
        Self { allow_ips, deny_ips }
    }

    /// Kural listelerinin her ikisinin de boş olup olmadığını bildirir.
    pub fn is_empty(&self) -> bool {
        self.allow_ips.is_empty() && self.deny_ips.is_empty()
    }

    /// İstemci IP adresinin erişim iznine sahip olup olmadığını denetler.
    ///
    /// Değerlendirme Sırası ve Mantığı:
    /// 1. `allow_ips` listesindeki herhangi bir IP veya CIDR ile eşleşirse: **İZİN VERİLİR** (`true`).
    ///    (Beyaz liste istisnaları, geniş yasak bloklarını ezer.)
    /// 2. `deny_ips` listesindeki herhangi bir IP veya CIDR ile eşleşirse: **ENGELLENİR** (`false`).
    /// 3. Eğer `allow_ips` listesinde en az bir geçerli kural varsa (sıkı beyaz liste modu)
    ///    ve istemci IP eşleşmediyse: **ENGELLENİR** (`false`).
    /// 4. Diğer tüm durumlarda varsayılan olarak: **İZİN VERİLİR** (`true`).
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // 1. İzinli IP listesi kontrolü
        if self.allow_ips.iter().any(|spec| ip_matches_cidr_spec(ip, spec)) {
            return true;
        }

        // 2. Yasaklı IP listesi kontrolü
        if self.deny_ips.iter().any(|spec| ip_matches_cidr_spec(ip, spec)) {
            return false;
        }

        // 3. Sıkı beyaz liste kontrolü
        if self.allow_ips.iter().any(|spec| is_valid_ip_or_cidr(spec)) {
            return false;
        }

        true
    }

    /// IP adresini metin olarak alır ve doğrular; geçersiz IP durumunda `false` döner.
    pub fn is_allowed_str(&self, ip_str: &str) -> bool {
        match ip_str.trim().parse::<IpAddr>() {
            Ok(ip) => self.is_allowed(ip),
            Err(_) => false,
        }
    }
}

/// Fonksiyonel yardımcı: Verilen IP adresinin allow/deny kurallarına göre izinli olup olmadığını döner.
pub fn is_ip_allowed(allow_ips: &[String], deny_ips: &[String], ip: IpAddr) -> bool {
    if allow_ips.iter().any(|spec| ip_matches_cidr_spec(ip, spec)) {
        return true;
    }
    if deny_ips.iter().any(|spec| ip_matches_cidr_spec(ip, spec)) {
        return false;
    }
    if allow_ips.iter().any(|spec| is_valid_ip_or_cidr(spec)) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_acl_empty_allows_all() {
        let acl = VhostAcl::default();
        assert!(acl.is_empty());
        assert!(acl.is_allowed(IpAddr::from_str("127.0.0.1").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.100").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("::1").unwrap()));
    }

    #[test]
    fn test_acl_deny_single_ip() {
        let acl = VhostAcl::new(vec![], vec!["192.168.1.50".to_string()]);
        assert!(!acl.is_allowed(IpAddr::from_str("192.168.1.50").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.51").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("10.0.0.1").unwrap()));
    }

    #[test]
    fn test_acl_deny_cidr() {
        let acl = VhostAcl::new(vec![], vec!["10.0.0.0/8".to_string()]);
        assert!(!acl.is_allowed(IpAddr::from_str("10.1.2.3").unwrap()));
        assert!(!acl.is_allowed(IpAddr::from_str("10.255.255.255").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("11.0.0.1").unwrap()));
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.1").unwrap()));
    }

    #[test]
    fn test_acl_allow_overrides_deny() {
        // 192.168.1.0/24 yasaklı, ancak 192.168.1.50 istisna olarak izinli
        let acl = VhostAcl::new(
            vec!["192.168.1.50".to_string()],
            vec!["192.168.1.0/24".to_string()],
        );
        assert!(acl.is_allowed(IpAddr::from_str("192.168.1.50").unwrap()));
        assert!(!acl.is_allowed(IpAddr::from_str("192.168.1.51").unwrap()));
        assert!(!acl.is_allowed(IpAddr::from_str("192.168.1.1").unwrap()));
        // Sıkı beyaz liste: allow listesi tanımlı olduğu için 10.0.0.1 de giremez
        assert!(!acl.is_allowed(IpAddr::from_str("10.0.0.1").unwrap()));
    }

    #[test]
    fn test_acl_ipv6_cidr() {
        let acl = VhostAcl::new(
            vec!["2001:db8::1".to_string()],
            vec!["2001:db8::/32".to_string()],
        );
        assert!(acl.is_allowed(IpAddr::from_str("2001:db8::1").unwrap()));
        assert!(!acl.is_allowed(IpAddr::from_str("2001:db8::2").unwrap()));
        assert!(!acl.is_allowed(IpAddr::from_str("2001:db8:ffff::1").unwrap()));
    }

    #[test]
    fn test_acl_is_allowed_str() {
        let acl = VhostAcl::new(vec![], vec!["1.2.3.4".to_string()]);
        assert!(!acl.is_allowed_str("1.2.3.4"));
        assert!(acl.is_allowed_str("1.2.3.5"));
        assert!(!acl.is_allowed_str("invalid-ip"));
    }
}
