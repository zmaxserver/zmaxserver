//! ZMax vHost Basic Authentication (Parola Korumalı Dizinler) Yapılandırma Modülü
//!
//! Apache htpasswd uyumlu `$apr1$` MD5, Argon2id (`$argon2id$`), `{SHA}` ve düz metin parola korumalı dizin yapılandırması.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// vHost geneli için isteğe bağlı dizin öneki (örn. `/gizli`); None ise tüm yollar (veya sadece `directories`) korunur
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// htpasswd dosya yolu (örn. /etc/zpanel/auth/example.com.htpasswd veya conf/auth/example.htpasswd)
    pub htpasswd_path: Option<String>,
    /// Doğrudan yapılandırma dosyasında tanımlı kullanıcılar (username:password_hash)
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
            path_prefix: None,
            htpasswd_path: None,
            users: Vec::new(),
            directories: Vec::new(),
        }
    }
}

impl VHostAuthSection {
    /// Tüm Basic Auth yapılandırma alanlarını (realm, dizin önekleri, htpasswd dosya yolları, kullanıcılar) doğrular.
    pub fn validate(&self, scope: &str) -> Result<(), String> {
        validate_realm(scope, "auth.realm", &self.realm)?;
        if let Some(ref prefix) = self.path_prefix {
            validate_auth_path_prefix(scope, "auth.path_prefix", prefix)?;
        }
        if let Some(ref path) = self.htpasswd_path {
            validate_htpasswd_path(scope, "auth.htpasswd_path", path)?;
        }
        for (idx, user) in self.users.iter().enumerate() {
            user.validate(scope, &format!("auth.users[{}]", idx))?;
        }
        for (idx, dir) in self.directories.iter().enumerate() {
            dir.validate(scope, idx)?;
        }
        Ok(())
    }
}

/// Dizin bazında tanımlanan parola koruma kuralı.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct VHostAuthDirectory {
    /// Korumalı yol öneki (örn. /admin veya /yonetim/)
    #[serde(default, alias = "path_prefix")]
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

impl VHostAuthDirectory {
    /// Dizin koruma kuralının alanlarını doğrular.
    pub fn validate(&self, scope: &str, idx: usize) -> Result<(), String> {
        validate_auth_path_prefix(
            scope,
            &format!("auth.directories[{}].path", idx),
            &self.path,
        )?;
        validate_realm(
            scope,
            &format!("auth.directories[{}].realm", idx),
            &self.realm,
        )?;
        if let Some(ref path) = self.htpasswd_path {
            validate_htpasswd_path(
                scope,
                &format!("auth.directories[{}].htpasswd_path", idx),
                path,
            )?;
        }
        for (ui, user) in self.users.iter().enumerate() {
            user.validate(scope, &format!("auth.directories[{}].users[{}]", idx, ui))?;
        }
        Ok(())
    }
}

/// Kullanıcı adı ve şifre özeti
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(default)]
pub struct AuthUserEntry {
    pub username: String,
    pub password_hash: String,
}

impl fmt::Debug for AuthUserEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthUserEntry")
            .field("username", &self.username)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

impl AuthUserEntry {
    pub fn new(username: impl Into<String>, password_hash: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password_hash: password_hash.into(),
        }
    }

    pub fn validate(&self, scope: &str, field: &str) -> Result<(), String> {
        let user = self.username.trim();
        if user.is_empty() || user.contains(':') || user.chars().any(|c| c.is_control()) {
            return Err(format!(
                "{} için geçersiz {} kullanıcı adı (boş, ':' veya kontrol karakteri yasak)",
                scope, field
            ));
        }
        if self.password_hash.trim().is_empty()
            || self
                .password_hash
                .chars()
                .any(|c| matches!(c, '\r' | '\n' | '\0'))
        {
            return Err(format!(
                "{} için geçersiz {} parola özeti (boş veya kontrol karakteri yasak)",
                scope, field
            ));
        }
        Ok(())
    }
}

fn validate_realm(scope: &str, field: &str, realm: &str) -> Result<(), String> {
    if realm.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(format!(
            "{} için geçersiz {} değeri: satır sonu veya NUL karakteri içeremez",
            scope, field
        ));
    }
    Ok(())
}

fn validate_auth_path_prefix(scope: &str, field: &str, raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err(format!(
            "{} için geçersiz {} yolu ('{}'): '/' ile başlamalıdır",
            scope, field, raw
        ));
    }
    if trimmed.contains('\0')
        || trimmed.contains('\\')
        || trimmed.split('/').any(|seg| seg == "..")
        || trimmed.chars().any(|c| c.is_control())
    {
        return Err(format!(
            "{} için güvensiz {} yolu ('{}')",
            scope, field, raw
        ));
    }
    Ok(())
}

fn validate_htpasswd_path(scope: &str, field: &str, raw: &str) -> Result<(), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.chars().any(|c| c.is_control())
        || trimmed.split(['/', '\\']).any(|seg| seg == "..")
    {
        return Err(format!(
            "{} için geçersiz veya güvensiz {} dosya yolu ('{}')",
            scope, field, raw
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_section_defaults() {
        let auth = VHostAuthSection::default();
        assert!(!auth.enabled);
        assert_eq!(auth.realm, "Restricted Area");
        assert!(auth.path_prefix.is_none());
        assert!(auth.htpasswd_path.is_none());
        assert!(auth.users.is_empty());
        assert!(auth.directories.is_empty());
    }

    #[test]
    fn test_auth_section_toml_roundtrip_and_path_prefix_alias() {
        let toml_str = r#"
            enabled = true
            realm = "Yonetici Paneli"
            path_prefix = "/gizli"
            htpasswd_path = "/etc/zpanel/auth/yonetim.htpasswd"

            [[users]]
            username = "admin"
            password_hash = "$apr1$xyz$hash123"

            [[directories]]
            path_prefix = "/admin"
            realm = "Admin Girisi"
        "#;

        let parsed: VHostAuthSection = toml::from_str(toml_str).expect("TOML parse fail");
        assert!(parsed.enabled);
        assert_eq!(parsed.realm, "Yonetici Paneli");
        assert_eq!(parsed.path_prefix.as_deref(), Some("/gizli"));
        assert_eq!(parsed.users.len(), 1);
        assert_eq!(parsed.users[0].username, "admin");
        assert_eq!(parsed.directories.len(), 1);
        assert_eq!(parsed.directories[0].path, "/admin");
        assert_eq!(parsed.directories[0].realm, "Admin Girisi");
        assert!(parsed.validate("vHost 'test.local'").is_ok());
    }

    #[test]
    fn test_auth_validation_rejects_traversal_and_header_injection() {
        let mut bad_path = VHostAuthSection::default();
        bad_path.htpasswd_path = Some("../../etc/shadow".to_string());
        assert!(bad_path.validate("vHost 'a'").is_err());

        let mut bad_realm = VHostAuthSection::default();
        bad_realm.realm = "Panel\r\nX-Inject: 1".to_string();
        assert!(bad_realm.validate("vHost 'a'").is_err());

        let mut bad_prefix = VHostAuthSection::default();
        bad_prefix.path_prefix = Some("admin".to_string());
        assert!(bad_prefix.validate("vHost 'a'").is_err());

        let entry = AuthUserEntry::new("admin", "super_secret_hash_value");
        let debug_str = format!("{:?}", entry);
        assert!(!debug_str.contains("super_secret_hash_value"));
        assert!(debug_str.contains("[REDACTED]"));
    }
}
