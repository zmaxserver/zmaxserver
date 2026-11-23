//! # zmax-tls :: listener
//! Dinleyici (Listener) bazlı TLS mimarisi, sürüm (TLS 1.2 / 1.3) seçimi,
//! ALPN ve oturum yönetimi yapılandırıcısı.

use std::path::Path;
use std::sync::Arc;
use rustls::server::ResolvesServerCert;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
pub use tokio_rustls::TlsAcceptor;
use zmax_config::LoadedVHost;

use crate::alpn::AlpnConfig;
use crate::session::{SessionCacheMetrics, TlsSessionConfig};
use crate::sni::{sources_from_vhosts_filtered, CertSource, SniResolver};

/// Desteklenen TLS protokol sürümleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("1.2")
            || trimmed.eq_ignore_ascii_case("tls1.2")
            || trimmed.eq_ignore_ascii_case("tls12")
            || trimmed.eq_ignore_ascii_case("tlsv1.2")
            || trimmed.eq_ignore_ascii_case("tlsv1_2")
        {
            Some(Self::Tls12)
        } else if trimmed.eq_ignore_ascii_case("1.3")
            || trimmed.eq_ignore_ascii_case("tls1.3")
            || trimmed.eq_ignore_ascii_case("tls13")
            || trimmed.eq_ignore_ascii_case("tlsv1.3")
            || trimmed.eq_ignore_ascii_case("tlsv1_3")
        {
            Some(Self::Tls13)
        } else {
            None
        }
    }

    /// Verilen dize listesinden (örn. `["1.2", "1.3"]` veya `["1.3"]`) minimum ve maksimum sürümleri belirler.
    pub fn from_version_strings(versions: &[String]) -> (Self, Self) {
        let mut min = None;
        let mut max = None;
        for v in versions {
            if let Some(parsed) = Self::parse(v) {
                min = Some(match min {
                    None => parsed,
                    Some(m) if parsed < m => parsed,
                    Some(m) => m,
                });
                max = Some(match max {
                    None => parsed,
                    Some(m) if parsed > m => parsed,
                    Some(m) => m,
                });
            }
        }
        (min.unwrap_or(Self::Tls12), max.unwrap_or(Self::Tls13))
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        }
    }

    pub fn to_rustls(&self) -> &'static rustls::SupportedProtocolVersion {
        match self {
            Self::Tls12 => &TLS12,
            Self::Tls13 => &TLS13,
        }
    }
}

/// İstemci sertifikası doğrulama kipi (mTLS).
#[derive(Debug, Clone, Default)]
pub enum ClientAuthMode {
    #[default]
    NoClientAuth,
}

/// Tek bir Dinleyici için TLS yapılandırması.
#[derive(Debug, Clone)]
pub struct ListenerTlsConfig {
    pub name: String,
    pub min_version: TlsVersion,
    pub max_version: TlsVersion,
    pub alpn: AlpnConfig,
    pub session: TlsSessionConfig,
    pub client_auth: ClientAuthMode,
}

impl Default for ListenerTlsConfig {
    fn default() -> Self {
        Self {
            name: "default_listener".to_string(),
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            alpn: AlpnConfig::h2_and_http11(),
            session: TlsSessionConfig::default(),
            client_auth: ClientAuthMode::NoClientAuth,
        }
    }
}

impl ListenerTlsConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    pub fn with_versions(mut self, min: TlsVersion, max: TlsVersion) -> Self {
        self.min_version = min;
        self.max_version = max;
        self
    }

    pub fn with_alpn(mut self, alpn: AlpnConfig) -> Self {
        self.alpn = alpn;
        self
    }

    pub fn with_session(mut self, session: TlsSessionConfig) -> Self {
        self.session = session;
        self
    }

    /// OLS `zmax_config::ListenerConfig` modelinden TLS yapılandırması üretir.
    pub fn from_listener_config(cfg: &zmax_config::ListenerConfig) -> Self {
        let (min_v, max_v) = if cfg.tls_versions.is_empty() {
            (TlsVersion::Tls12, TlsVersion::Tls13)
        } else {
            TlsVersion::from_version_strings(&cfg.tls_versions)
        };
        let alpn = if cfg.alpn.is_empty() {
            AlpnConfig::h2_and_http11()
        } else {
            AlpnConfig::from_slice(&cfg.alpn)
        };
        let name = if !cfg.name.is_empty() {
            cfg.name.clone()
        } else if !cfg.id.is_empty() {
            cfg.id.clone()
        } else {
            format!("listener_{}", cfg.port)
        };
        Self {
            name,
            min_version: min_v,
            max_version: max_v,
            alpn,
            session: TlsSessionConfig::default(),
            client_auth: ClientAuthMode::NoClientAuth,
        }
    }
}

/// Dinleyici düzeyinde çalışan, metrikleri ve SNI çözümleyicisini içeren kabul edici.
#[derive(Clone)]
pub struct ListenerTlsAcceptor {
    name: String,
    acceptor: TlsAcceptor,
    resolver: Arc<SniResolver>,
    session_metrics: Arc<SessionCacheMetrics>,
    config: ListenerTlsConfig,
}

impl std::fmt::Debug for ListenerTlsAcceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerTlsAcceptor")
            .field("name", &self.name)
            .field("min_version", &self.config.min_version)
            .field("max_version", &self.config.max_version)
            .finish()
    }
}

impl ListenerTlsAcceptor {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn resolver(&self) -> &Arc<SniResolver> {
        &self.resolver
    }

    pub fn session_metrics(&self) -> &Arc<SessionCacheMetrics> {
        &self.session_metrics
    }

    pub fn config(&self) -> &ListenerTlsConfig {
        &self.config
    }

    pub fn tls_acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }

    /// Bir TCP/IO akışını kabul ederek TLS el sıkışmasını başlatır.
    pub async fn accept<IO>(&self, stream: IO) -> Result<TlsStream<IO>, std::io::Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.acceptor.accept(stream).await
    }
}

/// Dinleyici TLS kabul edicisi kurucu motoru (Builder).
pub struct ListenerTlsBuilder {
    config: ListenerTlsConfig,
    resolver: Option<Arc<SniResolver>>,
}

impl ListenerTlsBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            config: ListenerTlsConfig::new(name),
            resolver: None,
        }
    }

    pub fn from_config(config: ListenerTlsConfig) -> Self {
        Self {
            config,
            resolver: None,
        }
    }

    /// OLS `zmax_config::ListenerConfig` nesnesinden kurucu üretir.
    pub fn from_listener_config(cfg: &zmax_config::ListenerConfig) -> Self {
        Self::from_config(ListenerTlsConfig::from_listener_config(cfg))
    }

    /// OLS `zmax_config::ListenerConfig` ve vhost listesini kullanarak dinleyici kurucusunu hazırlar.
    pub fn from_listener_config_with_vhosts(
        cfg: &zmax_config::ListenerConfig,
        vhosts: &[LoadedVHost],
        base_dir: &Path,
    ) -> Result<Self, String> {
        let tls_cfg = ListenerTlsConfig::from_listener_config(cfg);
        let mut builder = Self::from_config(tls_cfg);

        // Dinleyiciye özel vhost eşlemelerine göre filtrelenmiş sertifikaları yükle
        let sources = sources_from_vhosts_filtered(vhosts, base_dir, &cfg.vhost_mappings);
        let resolver = Arc::new(SniResolver::new());
        if !sources.is_empty() {
            resolver.replace(&sources);
        }

        // Eğer dinleyici üzerinde özel cert_file / key_file tanımlıysa, onu da varsayılan olarak ekle
        let cert_str = cfg.cert_file.trim();
        let key_str = cfg.key_file.trim();
        if !cert_str.is_empty() && !key_str.is_empty() {
            let cert_path = zmax_config::resolve_path(base_dir, cert_str);
            let key_path = zmax_config::resolve_path(base_dir, key_str);
            let default_src = CertSource {
                label: format!("{}_default", if !cfg.id.is_empty() { &cfg.id } else { &cfg.name }),
                names: vec!["*".to_string()],
                cert_path,
                key_path,
            };
            let _ = resolver.add_certificate_source(default_src);
        }

        builder.resolver = Some(resolver);
        Ok(builder)
    }

    pub fn with_resolver(mut self, resolver: Arc<SniResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_min_version(mut self, v: TlsVersion) -> Self {
        self.config.min_version = v;
        self
    }

    pub fn with_max_version(mut self, v: TlsVersion) -> Self {
        self.config.max_version = v;
        self
    }

    pub fn with_alpn(mut self, alpn: AlpnConfig) -> Self {
        self.config.alpn = alpn;
        self
    }

    pub fn with_session_config(mut self, session: TlsSessionConfig) -> Self {
        self.config.session = session;
        self
    }

    /// Kabul ediciyi derler.
    pub fn build(self) -> Result<ListenerTlsAcceptor, String> {
        let resolver = self
            .resolver
            .unwrap_or_else(|| Arc::new(SniResolver::new()));

        let mut versions = Vec::new();
        // Sıralama: daha yüksek sürümler önce (TLS 1.3, TLS 1.2)
        if self.config.max_version >= TlsVersion::Tls13 && self.config.min_version <= TlsVersion::Tls13 {
            versions.push(&TLS13);
        }
        if self.config.max_version >= TlsVersion::Tls12 && self.config.min_version <= TlsVersion::Tls12 {
            versions.push(&TLS12);
        }
        if versions.is_empty() {
            return Err("En az bir geçerli TLS protokol sürümü seçilmelidir".to_string());
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let (storage, metrics) = self.config.session.build_storage();
        let ticketer = self
            .config
            .session
            .build_ticketer()
            .map_err(|e| format!("Bilet üreticisi başlatılamadı: {}", e))?;

        let mut cfg = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&versions)
            .map_err(|e| format!("TLS sürümleri ayarlanamadı: {}", e))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);

        cfg.session_storage = storage;
        cfg.ticketer = ticketer;
        cfg.alpn_protocols = self.config.alpn.to_wire_protocols();

        let acceptor = TlsAcceptor::from(Arc::new(cfg));

        Ok(ListenerTlsAcceptor {
            name: self.config.name.clone(),
            acceptor,
            resolver,
            session_metrics: metrics,
            config: self.config,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_version_parsing_and_ranges() {
        assert_eq!(TlsVersion::parse("1.2"), Some(TlsVersion::Tls12));
        assert_eq!(TlsVersion::parse("tls1.2"), Some(TlsVersion::Tls12));
        assert_eq!(TlsVersion::parse("TLSv1.2"), Some(TlsVersion::Tls12));
        assert_eq!(TlsVersion::parse("1.3"), Some(TlsVersion::Tls13));
        assert_eq!(TlsVersion::parse("tls1.3"), Some(TlsVersion::Tls13));
        assert_eq!(TlsVersion::parse("TLSv1.3"), Some(TlsVersion::Tls13));
        assert_eq!(TlsVersion::parse("unknown"), None);

        let versions = vec!["1.2".to_string(), "1.3".to_string()];
        let (min, max) = TlsVersion::from_version_strings(&versions);
        assert_eq!(min, TlsVersion::Tls12);
        assert_eq!(max, TlsVersion::Tls13);

        let versions_13_only = vec!["1.3".to_string()];
        let (min13, max13) = TlsVersion::from_version_strings(&versions_13_only);
        assert_eq!(min13, TlsVersion::Tls13);
        assert_eq!(max13, TlsVersion::Tls13);
    }

    #[test]
    fn test_listener_tls_config_from_zmax_config() {
        let listener_cfg = zmax_config::ListenerConfig {
            id: "ls_https".to_string(),
            name: "HTTPS Listener".to_string(),
            address: "0.0.0.0".to_string(),
            port: 443,
            secure: true,
            tls_versions: vec!["1.2".to_string(), "1.3".to_string()],
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            ..Default::default()
        };

        let tls_cfg = ListenerTlsConfig::from_listener_config(&listener_cfg);
        assert_eq!(tls_cfg.name, "HTTPS Listener");
        assert_eq!(tls_cfg.min_version, TlsVersion::Tls12);
        assert_eq!(tls_cfg.max_version, TlsVersion::Tls13);
        assert!(tls_cfg.alpn.enable_h2);
        assert!(tls_cfg.alpn.enable_http11);

        let builder = ListenerTlsBuilder::from_listener_config(&listener_cfg);
        let acceptor = builder.build().expect("Dinleyici acceptor derlenemedi");
        assert_eq!(acceptor.name(), "HTTPS Listener");
    }
}
