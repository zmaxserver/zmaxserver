//! # zmax-config :: proxy_ext
//! Sanal konak (vHost) düzeyinde ters vekil (reverse proxy) zaman aşımı, keep-alive ve tamponsuz akış ayarları.

use serde::{Deserialize, Serialize};

fn default_init_timeout_sec() -> u64 {
    60
}

fn default_keep_alive_timeout_sec() -> u64 {
    60
}

fn default_max_conns() -> usize {
    100
}

fn default_ws_idle_timeout_sec() -> u64 {
    300
}

fn default_max_ws() -> usize {
    1000
}

/// Sanal konak ters vekil genişletilmiş yapılandırması (`[vhost.proxy_ext]`).
/// OpenLiteSpeed `initTimeout`, `pcKeepAliveTimeout`, `respBuffer` ve `maxConns` direktiflerinin karşılığıdır.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(default)]
pub struct ProxyExtConfig {
    /// Arka uçtan ilk yanıt veya sonraki akış parçası için bekleme süresi (saniye). OLS `initTimeout` karşılığı.
    #[serde(default = "default_init_timeout_sec")]
    pub init_timeout_sec: u64,
    /// Arka uç TCP keep-alive bekleme süresi (saniye). OLS `pcKeepAliveTimeout` karşılığı.
    #[serde(default = "default_keep_alive_timeout_sec")]
    pub keep_alive_timeout_sec: u64,
    /// Arka uca TCP bağlantı kurma zaman aşımı (saniye). `None` ise `mod_proxy.toml`
    /// `connect_timeout_sec` (genel ayar) uygulanır; vhost'ta yazılmışsa o kazanır.
    #[serde(default)]
    pub connect_timeout_sec: Option<u64>,
    /// Yanıt tamponlama (`false` = OLS `respBuffer 0` tamponsuz anında akış; SSE için önerilen).
    pub resp_buffer: bool,
    /// En fazla eşzamanlı arka uç bağlantısı sınırı (OLS `maxConns`).
    #[serde(default = "default_max_conns")]
    pub max_conns: usize,
    /// WebSocket tünelinde iki yönde de bayt akmadığında tünelin kapatıldığı boşta süre (saniye).
    #[serde(default = "default_ws_idle_timeout_sec")]
    pub ws_idle_timeout_sec: u64,
    /// Vhost başına en fazla eşzamanlı WebSocket tüneli; aşılırsa yükseltme isteği 503 alır.
    #[serde(default = "default_max_ws")]
    pub max_ws: usize,
}

impl Default for ProxyExtConfig {
    fn default() -> Self {
        Self {
            init_timeout_sec: default_init_timeout_sec(),
            keep_alive_timeout_sec: default_keep_alive_timeout_sec(),
            connect_timeout_sec: None,
            resp_buffer: false,
            max_conns: default_max_conns(),
            ws_idle_timeout_sec: default_ws_idle_timeout_sec(),
            max_ws: default_max_ws(),
        }
    }
}

impl ProxyExtConfig {
    /// Genişletilmiş ters vekil ayarlarını sınır değerlere göre doğrular.
    pub fn validate(&self, scope: &str) -> Result<(), String> {
        if self.init_timeout_sec == 0 || self.init_timeout_sec > 86_400 {
            return Err(format!(
                "{} için init_timeout_sec 1..=86400 saniye aralığında olmalıdır (mevcut: {})",
                scope, self.init_timeout_sec
            ));
        }
        if self.keep_alive_timeout_sec == 0 || self.keep_alive_timeout_sec > 86_400 {
            return Err(format!(
                "{} için keep_alive_timeout_sec 1..=86400 saniye aralığında olmalıdır (mevcut: {})",
                scope, self.keep_alive_timeout_sec
            ));
        }
        if let Some(connect) = self.connect_timeout_sec {
            if connect == 0 || connect > 300 {
                return Err(format!(
                    "{} için connect_timeout_sec 1..=300 saniye aralığında olmalıdır (mevcut: {})",
                    scope, connect
                ));
            }
        }
        if self.ws_idle_timeout_sec == 0 || self.ws_idle_timeout_sec > 86_400 {
            return Err(format!(
                "{} için ws_idle_timeout_sec 1..=86400 saniye aralığında olmalıdır (mevcut: {})",
                scope, self.ws_idle_timeout_sec
            ));
        }
        if self.max_ws == 0 || self.max_ws > 100_000 {
            return Err(format!(
                "{} için max_ws 1..=100000 aralığında olmalıdır (mevcut: {})",
                scope, self.max_ws
            ));
        }
        if self.max_conns == 0 || self.max_conns > 100_000 {
            return Err(format!(
                "{} için max_conns 1..=100000 aralığında olmalıdır (mevcut: {})",
                scope, self.max_conns
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_ext_defaults_and_validation() {
        let def = ProxyExtConfig::default();
        assert_eq!(def.init_timeout_sec, 60);
        assert_eq!(def.keep_alive_timeout_sec, 60);
        assert_eq!(def.connect_timeout_sec, None);
        assert_eq!(def.ws_idle_timeout_sec, 300);
        assert_eq!(def.max_ws, 1000);
        assert!(!def.resp_buffer);
        assert_eq!(def.max_conns, 100);
        assert!(def.validate("vhost.proxy_ext").is_ok());

        let bad_init = ProxyExtConfig {
            init_timeout_sec: 0,
            ..ProxyExtConfig::default()
        };
        assert!(bad_init.validate("vhost.proxy_ext").is_err());

        let bad_ka = ProxyExtConfig {
            keep_alive_timeout_sec: 0,
            ..ProxyExtConfig::default()
        };
        assert!(bad_ka.validate("vhost.proxy_ext").is_err());

        let bad_conn = ProxyExtConfig {
            connect_timeout_sec: Some(0),
            ..ProxyExtConfig::default()
        };
        assert!(bad_conn.validate("vhost.proxy_ext").is_err());

        let bad_conns = ProxyExtConfig {
            max_conns: 0,
            ..ProxyExtConfig::default()
        };
        assert!(bad_conns.validate("vhost.proxy_ext").is_err());
    }

    #[test]
    fn test_vhost_entry_toml_with_proxy_ext() {
        let toml_str = r#"
name = "panel.example.test"
document_root = "www/html"

[proxy]
enabled = true
upstream = "127.0.0.1:8026"
path_prefix = "/"
preserve_host = true
websocket = true

[proxy_ext]
init_timeout_sec = 300
keep_alive_timeout_sec = 45
connect_timeout_sec = 5
resp_buffer = false
max_conns = 250
"#;
        let vh: crate::VHostEntry = toml::from_str(toml_str).expect("TOML ayrıştırılmalı");
        assert!(vh.proxy.enabled);
        assert_eq!(vh.proxy.upstream, "127.0.0.1:8026");
        assert_eq!(vh.proxy_ext.init_timeout_sec, 300);
        assert_eq!(vh.proxy_ext.keep_alive_timeout_sec, 45);
        assert_eq!(vh.proxy_ext.connect_timeout_sec, Some(5));
        assert!(!vh.proxy_ext.resp_buffer);
        assert_eq!(vh.proxy_ext.max_conns, 250);
        assert!(vh.validate().is_ok());
    }

    #[test]
    fn test_vhost_entry_toml_without_proxy_ext_uses_unbuffered_defaults() {
        let toml_str = r#"
name = "legacy.example.test"
document_root = "www/html"

[proxy]
enabled = true
upstream = "127.0.0.1:3000"
"#;
        let vh: crate::VHostEntry = toml::from_str(toml_str).expect("TOML ayrıştırılmalı");
        assert!(!vh.proxy_ext.resp_buffer);
        assert_eq!(vh.proxy_ext.init_timeout_sec, 60);
        assert_eq!(vh.proxy_ext.keep_alive_timeout_sec, 60);
        assert!(vh.validate().is_ok());
    }
}
