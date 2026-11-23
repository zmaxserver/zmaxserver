//! # Port Cloaking, Banner Stripping & Stealth Shell Engine (zmax-security::port_cloak)
//!
//! Bu modül, port tarayıcılarına (Nmap, Masscan, Shodan, ZGrab) ve dış saldırganlara karşı
//! sunucu portlarını ve servis kabuklarını tamamen hayalet (stealth) hale getirir:
//! 1. **Silent Drop (Sessiz İmha):** Yetkisiz istemcilere HTTP 401/403 yerine TCP RST / Shutdown uygular;
//!    böylece tarayıcılar portu "Closed" veya "Filtered" algılar.
//! 2. **Port Knocking & SPA:** Gizli anahtar doğrulanmadan yönetim portlarına erişilemez.
//! 3. **Banner Cloaking:** `Server`, `X-Powered-By`, `X-LiteSpeed` vb. parmak izi başlıklarını yok eder.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PortCloakConfig {
    pub enabled: bool,
    pub stealth_drop: bool,
    pub strip_server_banner: bool,
    pub fake_server_banner: Option<String>,
    pub knock_secret: String,
    pub knock_ttl_sec: u64,
}

impl Default for PortCloakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            stealth_drop: true,
            strip_server_banner: true,
            fake_server_banner: None,
            knock_secret: String::new(),
            knock_ttl_sec: 3600,
        }
    }
}

pub struct PortCloakManager {
    config: PortCloakConfig,
    authorized_knock_ips: Arc<DashMap<IpAddr, Instant>>,
}

impl PortCloakManager {
    pub fn new(config: PortCloakConfig) -> Self {
        Self {
            config,
            authorized_knock_ips: Arc::new(DashMap::new()),
        }
    }

    /// IP adresinin knocking ile veya loopback olarak yetkili olup olmadığını denetler.
    pub fn is_ip_authorized(&self, ip: IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        if !self.config.enabled {
            return true;
        }
        if let Some(auth_time) = self.authorized_knock_ips.get(&ip) {
            if auth_time.elapsed().as_secs() < self.config.knock_ttl_sec {
                return true;
            } else {
                drop(auth_time);
                self.authorized_knock_ips.remove(&ip);
            }
        }
        false
    }

    /// Gizli knocking parametresiyle IP yetkilendirmesi yapar.
    pub fn attempt_knock(&self, ip: IpAddr, provided_secret: &str) -> bool {
        if !self.config.enabled || self.config.knock_secret.is_empty() {
            return false;
        }
        // Zamanlama saldırılarına (timing attack) karşı sabit zamanlı kıyaslama
        let secret_bytes = self.config.knock_secret.as_bytes();
        let provided_bytes = provided_secret.as_bytes();
        if secret_bytes.len() != provided_bytes.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in secret_bytes.iter().zip(provided_bytes.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            self.authorized_knock_ips.insert(ip, Instant::now());
            true
        } else {
            false
        }
    }

    /// Dışarıya giden HTTP başlıklarından sunucu parmak izlerini (Server, X-Powered-By vb.) temizler veya maskeler.
    pub fn cloak_response_headers(&self, headers: &mut Vec<(String, String)>) {
        if !self.config.enabled {
            return;
        }

        // Güvenliği açığa vuran başlıkları sil
        headers.retain(|(k, _)| {
            let lower = k.to_ascii_lowercase();
            lower != "x-powered-by"
                && lower != "x-litespeed-cache"
                && lower != "x-turbo-charged-by"
                && lower != "x-aspnet-version"
        });

        if self.config.strip_server_banner {
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("server"));
            if let Some(ref fake) = self.config.fake_server_banner {
                headers.push(("Server".to_string(), fake.clone()));
            }
        }
    }

    /// Süresi dolmuş knocking oturumlarını temizler.
    pub fn purge_expired(&self) {
        let ttl = self.config.knock_ttl_sec;
        self.authorized_knock_ips.retain(|_, time| time.elapsed().as_secs() < ttl);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_loopback_always_authorized() {
        let mgr = PortCloakManager::new(PortCloakConfig::default());
        assert!(mgr.is_ip_authorized(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_remote_ip_requires_knock() {
        let mut cfg = PortCloakConfig::default();
        cfg.knock_secret = "gizli-kapi-anahtari-12345".to_string();
        let mgr = PortCloakManager::new(cfg);

        let remote_ip = IpAddr::V4(Ipv4Addr::new(45, 33, 32, 156));
        assert!(!mgr.is_ip_authorized(remote_ip));

        // Yanlış anahtar
        assert!(!mgr.attempt_knock(remote_ip, "yanlis-anahtar"));
        assert!(!mgr.is_ip_authorized(remote_ip));

        // Doğru anahtar ile knocking
        assert!(mgr.attempt_knock(remote_ip, "gizli-kapi-anahtari-12345"));
        assert!(mgr.is_ip_authorized(remote_ip));
    }

    #[test]
    fn test_banner_stripping_and_masking() {
        let mut cfg = PortCloakConfig::default();
        cfg.strip_server_banner = true;
        cfg.fake_server_banner = Some("cloudflare".to_string());
        let mgr = PortCloakManager::new(cfg);

        let mut headers = vec![
            ("Server".to_string(), "ZMaxServer v1.0.09".to_string()),
            ("X-Powered-By".to_string(), "PHP/8.4".to_string()),
            ("Content-Type".to_string(), "text/html".to_string()),
        ];

        mgr.cloak_response_headers(&mut headers);

        assert!(!headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-powered-by")));
        let server_hdr = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("server"));
        assert!(server_hdr.is_some());
        assert_eq!(server_hdr.unwrap().1, "cloudflare");
    }
}
