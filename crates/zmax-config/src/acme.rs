//! ACME HTTP-01 challenge ve sertifika yenileme yapılandırması.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// Ortak ACME HTTP-01 doğrulama ve force_https muafiyet ayarları.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct AcmeConfig {
    /// Ortak ACME challenge kök dizini (ör. /var/www/acme).
    /// Tanımlıysa ve vhost belge kökünde challenge dosyası bulunamazsa
    /// bu dizinde aranır.
    pub acme_root: Option<PathBuf>,

    /// force_https etkin olsa dahi /.well-known/acme-challenge/*
    /// isteklerinin HTTPS'e yönlendirilmeden 200 OK ile sunulması.
    #[serde(default = "default_true")]
    pub force_https_exempt: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            acme_root: None,
            force_https_exempt: true,
        }
    }
}

impl AcmeConfig {
    pub fn new(acme_root: Option<PathBuf>) -> Self {
        Self {
            acme_root,
            force_https_exempt: true,
        }
    }

    pub fn with_root<P: AsRef<Path>>(root: P) -> Self {
        Self {
            acme_root: Some(root.as_ref().to_path_buf()),
            force_https_exempt: true,
        }
    }

    pub fn is_exempt(&self) -> bool {
        self.force_https_exempt
    }

    pub fn root(&self) -> Option<&Path> {
        self.acme_root.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_config_defaults() {
        let def = AcmeConfig::default();
        assert!(def.acme_root.is_none());
        assert!(def.force_https_exempt);
        assert!(def.is_exempt());
        assert!(def.root().is_none());
    }

    #[test]
    fn test_acme_config_with_root() {
        let cfg = AcmeConfig::with_root("/var/www/acme");
        assert_eq!(cfg.root(), Some(Path::new("/var/www/acme")));
        assert!(cfg.force_https_exempt);
    }

    #[test]
    fn test_acme_config_deserialize_toml() {
        let toml_str = r#"
            acme_root = "/var/www/acme"
            force_https_exempt = false
        "#;
        let parsed: AcmeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.acme_root, Some(PathBuf::from("/var/www/acme")));
        assert!(!parsed.force_https_exempt);

        let minimal: AcmeConfig = toml::from_str("").unwrap();
        assert!(minimal.acme_root.is_none());
        assert!(minimal.force_https_exempt);
    }
}
