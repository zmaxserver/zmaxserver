//! # zmax-config :: security_ext
//! Sanal konak (vHost) düzeyinde hotlink koruması ve IP erişim denetimi (ACL) yapılandırması.

use serde::{Deserialize, Serialize};

/// Varsayılan korunan dosya uzantıları.
pub fn default_hotlink_extensions() -> Vec<String> {
    vec![
        "jpg".to_string(),
        "jpeg".to_string(),
        "png".to_string(),
        "gif".to_string(),
        "webp".to_string(),
        "svg".to_string(),
        "mp4".to_string(),
        "mp3".to_string(),
        "pdf".to_string(),
        "zip".to_string(),
    ]
}

/// Sanal konak hotlink koruma yapılandırması.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct HotlinkConfig {
    /// Hotlink korumasının etkin olup olmadığı.
    pub enabled: bool,
    /// Doğrudan veya alt alan adları üzerinden erişimine izin verilen Referer alan adları.
    pub allowed_referers: Vec<String>,
    /// Hotlink korumasına tabi tutulacak dosya uzantıları.
    pub extensions: Vec<String>,
}

impl Default for HotlinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_referers: Vec::new(),
            extensions: default_hotlink_extensions(),
        }
    }
}

impl HotlinkConfig {
    /// Hotlink yapılandırmasını kurallara göre doğrular.
    pub fn validate(&self, scope: &str) -> Result<(), String> {
        if self.allowed_referers.len() > 100 {
            return Err(format!(
                "{} için izinli referer sayısı en çok 100 olabilir (mevcut: {})",
                scope,
                self.allowed_referers.len()
            ));
        }
        for referer in &self.allowed_referers {
            let trimmed = referer.trim();
            if trimmed.is_empty() {
                return Err(format!("{} içinde boş referer tanımı geçersizdir", scope));
            }
            if trimmed.len() > 253 {
                return Err(format!(
                    "{} içinde referer '{}' çok uzun (en çok 253 karakter)",
                    scope, trimmed
                ));
            }
        }
        for ext in &self.extensions {
            let trimmed = ext.trim().trim_start_matches('.');
            if trimmed.is_empty() {
                return Err(format!("{} içinde boş dosya uzantısı geçersizdir", scope));
            }
            if !trimmed.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err(format!(
                    "{} içinde geçersiz dosya uzantısı karakteri: '{}'",
                    scope, ext
                ));
            }
        }
        Ok(())
    }
}

/// Sanal konak IP erişim denetim listesi (ACL).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(default)]
pub struct VhostAclConfig {
    /// İzin verilen tekil IP adresleri veya CIDR ağları.
    pub allow_ips: Vec<String>,
    /// Yasaklanan tekil IP adresleri veya CIDR ağları.
    pub deny_ips: Vec<String>,
}

impl VhostAclConfig {
    /// IP ACL kurallarını tekil IP ve CIDR biçimlerine göre doğrular.
    pub fn validate(&self, scope: &str) -> Result<(), String> {
        if self.allow_ips.len() > 1000 {
            return Err(format!(
                "{} için allow_ips kural sayısı 1000'i aşamaz (mevcut: {})",
                scope,
                self.allow_ips.len()
            ));
        }
        if self.deny_ips.len() > 1000 {
            return Err(format!(
                "{} için deny_ips kural sayısı 1000'i aşamaz (mevcut: {})",
                scope,
                self.deny_ips.len()
            ));
        }
        for ip in &self.allow_ips {
            crate::validate_ip_or_cidr(ip).map_err(|e| {
                format!(
                    "{} için geçersiz allow_ips öğesi ('{}'): {}",
                    scope, ip, e
                )
            })?;
        }
        for ip in &self.deny_ips {
            crate::validate_ip_or_cidr(ip).map_err(|e| {
                format!("{} için geçersiz deny_ips öğesi ('{}'): {}", scope, ip, e)
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotlink_config_default_and_validation() {
        let def = HotlinkConfig::default();
        assert!(!def.enabled);
        assert!(def.allowed_referers.is_empty());
        assert_eq!(def.extensions.len(), 10);
        assert!(def.validate("test_vhost").is_ok());

        let invalid = HotlinkConfig {
            enabled: true,
            allowed_referers: vec!["   ".to_string()],
            extensions: vec!["jpg".to_string()],
        };
        assert!(invalid.validate("test_vhost").is_err());

        let invalid_ext = HotlinkConfig {
            enabled: true,
            allowed_referers: vec!["example.com".to_string()],
            extensions: vec!["bad/ext".to_string()],
        };
        assert!(invalid_ext.validate("test_vhost").is_err());
    }

    #[test]
    fn test_vhost_acl_config_validation() {
        let acl = VhostAclConfig {
            allow_ips: vec![
                "192.168.1.100".to_string(),
                "10.0.0.0/8".to_string(),
                "2001:db8::/32".to_string(),
            ],
            deny_ips: vec!["1.2.3.4".to_string(), "172.16.0.0/12".to_string()],
        };
        assert!(acl.validate("test_vhost").is_ok());

        let bad_allow = VhostAclConfig {
            allow_ips: vec!["999.999.999.999".to_string()],
            deny_ips: vec![],
        };
        assert!(bad_allow.validate("test_vhost").is_err());

        let bad_deny = VhostAclConfig {
            allow_ips: vec![],
            deny_ips: vec!["10.0.0.1/99".to_string()],
        };
        assert!(bad_deny.validate("test_vhost").is_err());
    }

    #[test]
    fn test_vhost_entry_toml_with_security_ext() {
        let toml_str = r#"
name = "secure.test"
document_root = "www/html"

[hotlink]
enabled = true
allowed_referers = ["ornek.test", "*.cdn.test"]
extensions = ["jpg", "png", "webp"]

[acl]
allow_ips = ["192.168.1.50"]
deny_ips = ["192.168.1.0/24"]
"#;
        let vh: crate::VHostEntry = toml::from_str(toml_str).expect("TOML ayrıştırılmalı");
        assert!(vh.hotlink.enabled);
        assert_eq!(vh.hotlink.allowed_referers, vec!["ornek.test", "*.cdn.test"]);
        assert_eq!(vh.hotlink.extensions, vec!["jpg", "png", "webp"]);
        assert_eq!(vh.acl.allow_ips, vec!["192.168.1.50"]);
        assert_eq!(vh.acl.deny_ips, vec!["192.168.1.0/24"]);
        assert!(vh.validate().is_ok());

        // Effective helpers
        let eff_hl = vh.effective_hotlink();
        assert!(eff_hl.enabled);
        assert_eq!(eff_hl.allowed_referers.len(), 2);

        let eff_acl = vh.effective_acl();
        assert_eq!(eff_acl.allow_ips.len(), 1);
        assert_eq!(eff_acl.deny_ips.len(), 1);
    }
}
