//! # zmax-config :: extra_listener
//! `[[listeners.extra]]`: keyfi port üzerinde (kendi TLS sertifikasıyla) dinleyip her isteği
//! SABİT bir arka uca ileten ters vekil dinleyicileri. Arka uç yalnız yapılandırmadan gelir;
//! istek başlıklarından (Host, mutlak URI vb.) asla türetilmez, dolayısıyla açık vekil oluşmaz.

use crate::{resolve_path, ProxyExtConfig};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;

fn default_true() -> bool {
    true
}

fn default_address() -> String {
    "0.0.0.0".to_string()
}

fn default_max_client_conns() -> usize {
    1024
}

/// Ek dinleyicinin TLS sertifika/anahtar yolları (PEM).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ExtraSslConfig {
    pub cert: String,
    pub key: String,
}

/// Yol önekine göre sabit arka uç (ör. `/phpmyadmin/` -> başka bir yerel port).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ExtraRouteConfig {
    pub path_prefix: String,
    pub upstream: String,
}

/// Tek bir `[[listeners.extra]]` girdisi.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ExtraListenerConfig {
    /// Benzersiz ad (günlük/kayıt anahtarı): harf, rakam, `-`, `_`.
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_address")]
    pub address: String,
    pub port: u16,
    /// Yoksa dinleyici düz HTTP olur ve yalnız loopback adreslerinde izin verilir (fail-closed).
    #[serde(default)]
    pub ssl: Option<ExtraSslConfig>,
    /// Varsayılan sabit arka uç: `http://host:port` veya `host:port`. `https://` desteklenmez.
    pub upstream: String,
    /// İsteğe bağlı yol öneki -> sabit arka uç eşlemeleri (en uzun önek kazanır).
    #[serde(default)]
    pub routes: Vec<ExtraRouteConfig>,
    #[serde(default = "default_true")]
    pub preserve_host: bool,
    #[serde(default = "default_true")]
    pub websocket: bool,
    /// Bu dinleyiciye aynı anda kabul edilen en fazla istemci bağlantısı.
    #[serde(default = "default_max_client_conns")]
    pub max_client_conns: usize,
    /// Arka uç zaman aşımları, `max_conns`, `max_ws` vb. (vhost `proxy_ext` ile aynı şema).
    #[serde(default)]
    pub proxy_ext: ProxyExtConfig,
}

/// `http://host:port` / `host:port` biçimini `host:port` olarak normalleştirir; aksi hâlde hata.
pub fn parse_upstream(raw: &str) -> Result<String, String> {
    let s = raw.trim();
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err("https:// arka uç desteklenmiyor (arka uca TLS istemcisi yok); http://host:port kullanın".into());
    }
    let rest = if lower.starts_with("http://") { &s[7..] } else { s };
    if rest.contains("://") {
        return Err(format!("desteklenmeyen arka uç şeması: '{raw}'"));
    }
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("geçersiz arka uç adresi: '{raw}'"));
    }
    if rest.contains(['/', '@', '?', '#', '\\']) {
        return Err(format!("arka uç yalnız host:port olmalı (yol/kullanıcı bilgisi yok): '{raw}'"));
    }
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| format!("arka uçta port yok: '{raw}'"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("arka uç portu geçersiz: '{raw}'"))?;
    if port == 0 {
        return Err(format!("arka uç portu 0 olamaz: '{raw}'"));
    }
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        inner.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    };
    if !host_ok {
        return Err(format!("arka uç host adı geçersiz: '{raw}'"));
    }
    Ok(format!("{host}:{port}"))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn ips_overlap(a: IpAddr, b: IpAddr) -> bool {
    a == b || a.is_unspecified() || b.is_unspecified()
}

impl ExtraListenerConfig {
    /// Dinleme adresi (IP).
    pub fn bind_ip(&self) -> Result<IpAddr, String> {
        self.address
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map_err(|e| format!("adres geçersiz ('{}'): {e}", self.address))
    }

    /// Varsayılan arka uç (`host:port`).
    pub fn upstream_addr(&self) -> Result<String, String> {
        parse_upstream(&self.upstream)
    }

    /// Alan düzeyi doğrulama (dosya varlığı hariç; bkz. `validate_extra_listener_files`).
    pub fn validate(&self) -> Result<(), String> {
        let scope = format!("listeners.extra '{}'", self.name);
        if !valid_name(&self.name) {
            return Err(format!(
                "listeners.extra adı geçersiz ('{}'): yalnız harf, rakam, '-' ve '_' (1-64)",
                self.name
            ));
        }
        if self.port == 0 {
            return Err(format!("{scope}: port 0 olamaz"));
        }
        let ip = self.bind_ip().map_err(|e| format!("{scope}: {e}"))?;
        match &self.ssl {
            Some(ssl) => {
                if ssl.cert.trim().is_empty() || ssl.key.trim().is_empty() {
                    return Err(format!("{scope}: ssl.cert ve ssl.key boş olamaz"));
                }
            }
            None => {
                if !ip.is_loopback() {
                    return Err(format!(
                        "{scope}: ssl tanımsız; düz HTTP yalnız loopback adreslerinde (127.0.0.1/::1) izinli"
                    ));
                }
            }
        }
        parse_upstream(&self.upstream).map_err(|e| format!("{scope}: upstream {e}"))?;
        for r in &self.routes {
            if !r.path_prefix.starts_with('/') || r.path_prefix.contains("..") || r.path_prefix.contains(['?', '#']) {
                return Err(format!("{scope}: routes.path_prefix geçersiz: '{}'", r.path_prefix));
            }
            parse_upstream(&r.upstream)
                .map_err(|e| format!("{scope}: routes('{}') upstream {e}", r.path_prefix))?;
        }
        if self.max_client_conns == 0 {
            return Err(format!("{scope}: max_client_conns 0 olamaz"));
        }
        self.proxy_ext.validate(&format!("{scope}.proxy_ext"))?;
        Ok(())
    }
}

/// Ek dinleyicileri kendi aralarında ve çekirdek dinleyicilerle (ad, ip, port) çakışmaya karşı doğrular.
pub fn validate_extra_listeners(
    extras: &[ExtraListenerConfig],
    taken: &[(String, IpAddr, u16)],
) -> Result<(), String> {
    let mut seen: Vec<(String, IpAddr, u16)> = taken.to_vec();
    let mut names: Vec<&str> = Vec::new();
    for e in extras {
        e.validate()?;
        if names.contains(&e.name.as_str()) {
            return Err(format!("listeners.extra adı tekrarlanıyor: '{}'", e.name));
        }
        names.push(e.name.as_str());
        if !e.enabled {
            continue;
        }
        let ip = e.bind_ip()?;
        for (pn, pip, pport) in &seen {
            if *pport == e.port && ips_overlap(*pip, ip) {
                return Err(format!(
                    "Dinleyici port çakışması: '{}' ({}:{}) ile ek dinleyici '{}' ({}:{}) aynı soketi kullanıyor.",
                    pn, pip, pport, e.name, ip, e.port
                ));
            }
        }
        seen.push((format!("extra:{}", e.name), ip, e.port));
    }
    Ok(())
}

/// Etkin ek dinleyicilerin TLS dosyalarının varlığını doğrular (fail-closed; dosya yoksa yapılandırma reddedilir).
pub fn validate_extra_listener_files(
    extras: &[ExtraListenerConfig],
    base_dir: &Path,
) -> Result<(), String> {
    for e in extras.iter().filter(|e| e.enabled) {
        if let Some(ssl) = &e.ssl {
            for (what, raw) in [("sertifika", &ssl.cert), ("özel anahtar", &ssl.key)] {
                let p = resolve_path(base_dir, raw.trim());
                if !p.is_file() {
                    return Err(format!(
                        "Etkin ek dinleyici '{}' TLS {} dosyası bulunamadı: {}",
                        e.name,
                        what,
                        p.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ExtraListenerConfig {
        ExtraListenerConfig {
            name: "panel".into(),
            enabled: true,
            address: "0.0.0.0".into(),
            port: 8036,
            ssl: Some(ExtraSslConfig { cert: "c.pem".into(), key: "k.pem".into() }),
            upstream: "http://127.0.0.1:8035".into(),
            routes: Vec::new(),
            preserve_host: true,
            websocket: true,
            max_client_conns: 10,
            proxy_ext: ProxyExtConfig::default(),
        }
    }

    #[test]
    fn upstream_formats() {
        assert_eq!(parse_upstream("http://127.0.0.1:8035").unwrap(), "127.0.0.1:8035");
        assert_eq!(parse_upstream("127.0.0.1:8035/").unwrap(), "127.0.0.1:8035");
        assert_eq!(parse_upstream("http://[::1]:80").unwrap(), "[::1]:80");
        assert_eq!(parse_upstream("app.internal:9000").unwrap(), "app.internal:9000");
        for bad in [
            "https://127.0.0.1:8035", "ftp://x:1", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999",
            "http://u@127.0.0.1:80", "127.0.0.1:80/x", "", "a b:80", "http://:80", "unix:/tmp/s",
        ] {
            assert!(parse_upstream(bad).is_err(), "kabul edildi: {bad}");
        }
    }

    #[test]
    fn toml_parses_and_empty_is_backward_compatible() {
        let cfg = crate::ZMaxConfig::parse_toml("[listeners.http]\nport = 80\n").unwrap();
        assert!(cfg.listeners.extra.is_empty());
        let toml = r#"
[[listeners.extra]]
name = "panel-staff"
port = 8036
upstream = "http://127.0.0.1:8035"
[listeners.extra.ssl]
cert = "/etc/zpanel/tls/fullchain.pem"
key = "/etc/zpanel/tls/privkey.pem"
[listeners.extra.proxy_ext]
init_timeout_sec = 300
max_conns = 100
[[listeners.extra.routes]]
path_prefix = "/phpmyadmin/"
upstream = "http://127.0.0.1:8091"

[[listeners.extra]]
name = "panel-local"
address = "127.0.0.1"
port = 8045
upstream = "127.0.0.1:8025"
"#;
        let cfg = crate::ZMaxConfig::parse_toml(toml).unwrap();
        assert_eq!(cfg.listeners.extra.len(), 2);
        let a = &cfg.listeners.extra[0];
        assert!(a.enabled && a.preserve_host && a.websocket);
        assert_eq!(a.proxy_ext.init_timeout_sec, 300);
        assert_eq!(a.routes[0].path_prefix, "/phpmyadmin/");
        assert!(cfg.listeners.extra[1].ssl.is_none());
        assert!(cfg.validate().is_ok());
        // zorunlu alan eksik -> ayrıştırma hatası (fail-closed)
        assert!(crate::ZMaxConfig::parse_toml("[[listeners.extra]]\nname=\"x\"\nport=1\n").is_err());
    }

    #[test]
    fn plaintext_only_on_loopback() {
        let mut c = base();
        c.ssl = None;
        assert!(c.validate().is_err());
        c.address = "127.0.0.1".into();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_bad_fields() {
        let mut c = base();
        c.name = "a b".into();
        assert!(c.validate().is_err());
        let mut c = base();
        c.port = 0;
        assert!(c.validate().is_err());
        let mut c = base();
        c.routes.push(ExtraRouteConfig { path_prefix: "pma/".into(), upstream: "127.0.0.1:1".into() });
        assert!(c.validate().is_err());
        let mut c = base();
        c.routes.push(ExtraRouteConfig { path_prefix: "/a/../b".into(), upstream: "127.0.0.1:1".into() });
        assert!(c.validate().is_err());
        let mut c = base();
        c.ssl = Some(ExtraSslConfig { cert: " ".into(), key: "k".into() });
        assert!(c.validate().is_err());
    }

    #[test]
    fn conflicts_detected() {
        let taken = vec![("https".to_string(), "0.0.0.0".parse().unwrap(), 8036u16)];
        assert!(validate_extra_listeners(&[base()], &taken).is_err());
        let mut a = base();
        a.port = 9001;
        let mut b = base();
        b.name = "b".into();
        b.port = 9001;
        assert!(validate_extra_listeners(&[a.clone(), b.clone()], &[]).is_err());
        b.enabled = false;
        assert!(validate_extra_listeners(&[a.clone(), b], &[]).is_ok());
        let mut d = a.clone();
        d.port = 9002;
        let mut dup = d.clone();
        dup.port = 9003;
        assert!(validate_extra_listeners(&[d, dup], &[]).is_err(), "aynı ad");
    }

    #[test]
    fn missing_tls_files_fail_closed() {
        let dir = std::env::temp_dir().join("zmax_extra_missing_tls_probe");
        assert!(validate_extra_listener_files(&[base()], &dir).is_err());
        let mut off = base();
        off.enabled = false;
        assert!(validate_extra_listener_files(&[off], &dir).is_ok());
    }
}
