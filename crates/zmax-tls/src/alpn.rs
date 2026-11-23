//! # zmax-tls :: alpn
//! ALPN (Application-Layer Protocol Negotiation) protokol yönetimi ve müzakeresi.
//!
//! Desteklenen protokoller:
//! - HTTP/2 (`"h2"`)
//! - HTTP/1.1 (`"http/1.1"`)
//! - HTTP/1.0 (`"http/1.0"`)
//! - HTTP/3 (`"h3"`, `"h3-29"` - ALPN hazırlık belirteçleri)

pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP11: &[u8] = b"http/1.1";
pub const ALPN_HTTP10: &[u8] = b"http/1.0";
pub const ALPN_H3: &[u8] = b"h3";
pub const ALPN_H3_29: &[u8] = b"h3-29";

/// Tanınan ALPN protokol türleri.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    H2,
    Http11,
    Http10,
    H3,
    H3_29,
    Other(Vec<u8>),
}

impl AlpnProtocol {
    /// Bayt dizisinden ALPN protokolü türetir.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes == ALPN_H2 {
            Self::H2
        } else if bytes == ALPN_HTTP11 {
            Self::Http11
        } else if bytes == ALPN_HTTP10 {
            Self::Http10
        } else if bytes == ALPN_H3 {
            Self::H3
        } else if bytes == ALPN_H3_29 {
            Self::H3_29
        } else {
            Self::Other(bytes.to_vec())
        }
    }

    /// Protokol adının bayt temsili.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::H2 => ALPN_H2,
            Self::Http11 => ALPN_HTTP11,
            Self::Http10 => ALPN_HTTP10,
            Self::H3 => ALPN_H3,
            Self::H3_29 => ALPN_H3_29,
            Self::Other(b) => b.as_slice(),
        }
    }

    /// Protokol adının metin temsili.
    pub fn as_str(&self) -> &str {
        match self {
            Self::H2 => "h2",
            Self::Http11 => "http/1.1",
            Self::Http10 => "http/1.0",
            Self::H3 => "h3",
            Self::H3_29 => "h3-29",
            Self::Other(b) => std::str::from_utf8(b).unwrap_or("unknown"),
        }
    }

    pub fn is_h2(&self) -> bool {
        matches!(self, Self::H2)
    }

    pub fn is_http11(&self) -> bool {
        matches!(self, Self::Http11)
    }

    pub fn is_h3(&self) -> bool {
        matches!(self, Self::H3 | Self::H3_29)
    }
}

impl std::fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ALPN yapılandırma profili.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlpnConfig {
    pub enable_h2: bool,
    pub enable_http11: bool,
    pub enable_h3: bool,
    pub custom: Vec<Vec<u8>>,
}

impl Default for AlpnConfig {
    fn default() -> Self {
        Self {
            enable_h2: true,
            enable_http11: true,
            enable_h3: false,
            custom: Vec::new(),
        }
    }
}

impl AlpnConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Yalnızca HTTP/1.1 izin verir (ör. panel portları veya geriye dönük mod).
    pub fn http11_only() -> Self {
        Self {
            enable_h2: false,
            enable_http11: true,
            enable_h3: false,
            custom: Vec::new(),
        }
    }

    /// HTTP/2 ve HTTP/1.1 etkin (standart web sunucusu).
    pub fn h2_and_http11() -> Self {
        Self {
            enable_h2: true,
            enable_http11: true,
            enable_h3: false,
            custom: Vec::new(),
        }
    }

    /// HTTP/3, HTTP/2 ve HTTP/1.1 etkin (geleceğe hazır).
    pub fn full_stack() -> Self {
        Self {
            enable_h2: true,
            enable_http11: true,
            enable_h3: true,
            custom: Vec::new(),
        }
    }

    /// Verilen metin listesinden (`["h2", "http/1.1"]` vb.) ALPN yapılandırması üretir.
    pub fn from_slice(protocols: &[String]) -> Self {
        let mut cfg = Self {
            enable_h2: false,
            enable_http11: false,
            enable_h3: false,
            custom: Vec::new(),
        };
        for p in protocols {
            let t = p.trim().to_ascii_lowercase();
            if t == "h2" {
                cfg.enable_h2 = true;
            } else if t == "http/1.1" {
                cfg.enable_http11 = true;
            } else if t == "h3" || t == "h3-29" {
                cfg.enable_h3 = true;
            } else if !t.is_empty() {
                cfg.custom.push(t.into_bytes());
            }
        }
        if !cfg.enable_h2 && !cfg.enable_http11 && !cfg.enable_h3 && cfg.custom.is_empty() {
            return Self::h2_and_http11();
        }
        cfg
    }

    pub fn with_h2(mut self, enabled: bool) -> Self {
        self.enable_h2 = enabled;
        self
    }

    pub fn with_http11(mut self, enabled: bool) -> Self {
        self.enable_http11 = enabled;
        self
    }

    pub fn with_h3(mut self, enabled: bool) -> Self {
        self.enable_h3 = enabled;
        self
    }

    pub fn with_custom_protocol(mut self, proto: &[u8]) -> Self {
        if !self.custom.iter().any(|p| p.as_slice() == proto) {
            self.custom.push(proto.to_vec());
        }
        self
    }

    /// Yapılandırmayı TLS el sıkışmasında sunulacak bayt listesine dönüştürür.
    pub fn to_wire_protocols(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if self.enable_h3 {
            out.push(ALPN_H3.to_vec());
        }
        if self.enable_h2 {
            out.push(ALPN_H2.to_vec());
        }
        if self.enable_http11 {
            out.push(ALPN_HTTP11.to_vec());
        }
        for c in &self.custom {
            if !out.contains(c) {
                out.push(c.clone());
            }
        }
        out
    }
}

/// Yapılandırmadaki ALPN protokol adlarını (`"h2"`, `"http/1.1"` vb.) bayt listesine dönüştürür.
/// Boş girdileri ve yinelenen protokolleri sırayı bozmadan temizler.
pub fn parse_alpn_list(alpn: &[String]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for raw in alpn {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let bytes = if trimmed.eq_ignore_ascii_case("h2") {
            ALPN_H2.to_vec()
        } else if trimmed.eq_ignore_ascii_case("http/1.1") {
            ALPN_HTTP11.to_vec()
        } else if trimmed.eq_ignore_ascii_case("http/1.0") {
            ALPN_HTTP10.to_vec()
        } else if trimmed.eq_ignore_ascii_case("h3") {
            ALPN_H3.to_vec()
        } else if trimmed.eq_ignore_ascii_case("h3-29") {
            ALPN_H3_29.to_vec()
        } else {
            trimmed.as_bytes().to_vec()
        };
        if !out.contains(&bytes) {
            out.push(bytes);
        }
    }
    out
}

/// Varsayılan TLS ALPN listesi (`["h2", "http/1.1"]`).
pub fn default_alpn_protocols() -> Vec<Vec<u8>> {
    vec![ALPN_H2.to_vec(), ALPN_HTTP11.to_vec()]
}

/// Sunucu tarafındaki TLS akışından müzakere edilen ALPN protokolünü okur.
pub fn negotiated_alpn<T>(stream: &tokio_rustls::server::TlsStream<T>) -> Option<Vec<u8>> {
    stream.get_ref().1.alpn_protocol().map(|p| p.to_vec())
}

/// Sunucu tarafındaki TLS akışından müzakere edilen ALPN protokolünü `AlpnProtocol` türünde okur.
pub fn negotiated_alpn_enum<T>(stream: &tokio_rustls::server::TlsStream<T>) -> Option<AlpnProtocol> {
    negotiated_alpn(stream).map(|b| AlpnProtocol::from_bytes(&b))
}

/// ALPN protokolünü loglanabilir metne çevirir.
pub fn format_alpn(alpn: Option<&[u8]>) -> &'static str {
    match alpn {
        Some(b) if b == ALPN_H2 => "h2",
        Some(b) if b == ALPN_HTTP11 => "http/1.1",
        Some(b) if b == ALPN_HTTP10 => "http/1.0",
        Some(b) if b == ALPN_H3 => "h3",
        Some(b) if b == ALPN_H3_29 => "h3-29",
        Some(_) => "other",
        None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_protocol_roundtrip() {
        assert_eq!(AlpnProtocol::from_bytes(b"h2"), AlpnProtocol::H2);
        assert_eq!(AlpnProtocol::from_bytes(b"http/1.1"), AlpnProtocol::Http11);
        assert_eq!(AlpnProtocol::from_bytes(b"http/1.0"), AlpnProtocol::Http10);
        assert_eq!(AlpnProtocol::from_bytes(b"h3"), AlpnProtocol::H3);
        assert_eq!(AlpnProtocol::from_bytes(b"custom"), AlpnProtocol::Other(b"custom".to_vec()));

        assert!(AlpnProtocol::H2.is_h2());
        assert!(AlpnProtocol::Http11.is_http11());
        assert!(AlpnProtocol::H3.is_h3());
        assert_eq!(AlpnProtocol::H2.as_str(), "h2");
        assert_eq!(format_alpn(Some(b"h2")), "h2");
        assert_eq!(format_alpn(None), "none");
    }

    #[test]
    fn test_alpn_config_builder() {
        let cfg = AlpnConfig::new().with_h2(true).with_http11(true).with_h3(true);
        let wire = cfg.to_wire_protocols();
        assert_eq!(wire, vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()]);

        let h1_only = AlpnConfig::http11_only();
        assert_eq!(h1_only.to_wire_protocols(), vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn test_parse_alpn_list_deduplicates_and_trims() {
        let input = vec![
            " H2 ".to_string(),
            "".to_string(),
            "   ".to_string(),
            "HTTP/1.1".to_string(),
            "h2".to_string(),
            "h3".to_string(),
        ];
        let parsed = parse_alpn_list(&input);
        assert_eq!(parsed, vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"h3".to_vec()]);
    }
}
