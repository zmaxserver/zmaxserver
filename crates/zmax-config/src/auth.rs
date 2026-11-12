//! ZMax vHost Basic Authentication (Parola Korumalı Dizinler) Yapılandırma Modülü
//!
//! Apache htpasswd uyumlu $apr1$ MD5, SHA-1 ve düz metin parola korumalı dizin yapılandırması.

use serde::{Deserialize, Serialize};

fn default_realm() -> String {
    "Restricted Area".to_string()
}

/// vHost genelinde ve dizin bazlı HTTP Basic Authentication yapılandırması.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct VHostAuthSection {
    /// Parola koruması aktif mi?
    pub enabled: bool,
    /// Varsayılan HTTP Basic Realm başlığı
    #[serde(default = "default_realm")]
    pub realm: String,
    /// htpasswd dosya yolu (örn. /etc/zpanel/auth/example.com.htpasswd)
    pub htpasswd_path: Option<String>,
    /// Doğrudan yapılandırma dosyasında tanımlı kullanıcılar (username:hash)
    #[serde(default)]
    pub users: Vec<AuthUserEntry>,
    /// Dizin bazında koruma kuralları (örn. /admin, /gizli)
    #[serde(default)]
    pub directories: Vec<VHostAuthDirectory>,
}

impl Default for VHostAuthSection {
    fn default() -> Self {
        Self {
            enabled: false,
            realm: default_realm(),
            htpasswd_path: None,
            users: Vec::new(),
            directories: Vec::new(),
        }
    }
}

/// Dizin bazında tanımlanan parola koruma kuralı.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct VHostAuthDirectory {
    /// Korumalı yol öneki (örn. /admin veya /yonetim/)
    pub path: String,
    /// Bu dizine özel realm adı
    #[serde(default = "default_realm")]
    pub realm: String,
    /// Bu dizine özel htpasswd dosya yolu (None ise vhost genelindekini kullanır)
    pub htpasswd_path: Option<String>,
    /// Bu dizine özel kullanıcı listesi
    #[serde(default)]
    pub users: Vec<AuthUserEntry>,
}

impl Default for VHostAuthDirectory {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            realm: default_realm(),
            htpasswd_path: None,
            users: Vec::new(),
        }
    }
}

/// Kullanıcı adı ve şifre özeti
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct AuthUserEntry {
    pub username: String,
    pub password_hash: String,
}

impl Default for AuthUserEntry {
    fn default() -> Self {
        Self {
            username: String::new(),
            password_hash: String::new(),
        }
    }
}

impl AuthUserEntry {
    pub fn new(username: impl Into<String>, password_hash: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password_hash: password_hash.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_section_defaults() {
        let auth = VHostAuthSection::default();
        assert!(!auth.enabled);
        assert_eq!(auth.realm, "Restricted Area");
        assert!(auth.htpasswd_path.is_none());
        assert!(auth.users.is_empty());
        assert!(auth.directories.is_empty());
    }

    #[test]
    fn test_auth_section_toml_roundtrip() {
        let toml_str = r#"
            enabled = true
            realm = "Yonetici Paneli"
            htpasswd_path = "/etc/zpanel/auth/yonetim.htpasswd"

            [[users]]
            username = "admin"
            password_hash = "$apr1$xyz$hash123"

            [[directories]]
            path = "/admin"
            realm = "Admin Girisi"
        "#;

        let parsed: VHostAuthSection = toml::from_str(toml_str).expect("TOML parse fail");
        assert!(parsed.enabled);
        assert_eq!(parsed.realm, "Yonetici Paneli");
        assert_eq!(parsed.users.len(), 1);
        assert_eq!(parsed.users[0].username, "admin");
        assert_eq!(parsed.directories.len(), 1);
        assert_eq!(parsed.directories[0].path, "/admin");
        assert_eq!(parsed.directories[0].realm, "Admin Girisi");
    }
}
