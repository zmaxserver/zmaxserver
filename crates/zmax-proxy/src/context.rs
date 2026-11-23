//! # VHost URI Context Yönlendiricisi (Context Router)
//!
//! OpenLiteSpeed (OLS) mimarisine denk; URI bazlı en uzun prefix eşleşmesi (Longest Prefix Match - LPM)
//! ile Sanal Konak (vHost) isteklerini `Static`, `Proxy` ve `Redirect` hedeflerine yönlendirir.

use std::cmp::Ordering;
use std::fmt;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

/// Context türü: Statik dosya sunumu, Ters Vekil (Reverse Proxy) veya HTTP Yönlendirme (Redirect).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContextType {
    /// Belirtilen kök dizinden statik dosya sunumu
    Static {
        /// Dosya sistemindeki kök dizin
        location: PathBuf,
        /// Dizin isteklerinde aranacak varsayılan indeks dosyaları
        #[serde(default = "default_index_files")]
        index_files: Vec<String>,
        /// İndeks dosyası bulunamadığında dizin listesi (directory listing) oluşturulsun mu?
        #[serde(default)]
        autoindex: bool,
    },
    /// Belirtilen upstream hedefe (ör. `http://127.0.0.1:3000`) HTTP ters vekil yönlendirmesi
    Proxy {
        /// Upstream hedef sunucu adresi (ör. `http://127.0.0.1:3000` veya `127.0.0.1:8080`)
        upstream: String,
        /// İstemcinin `Host` başlığı korunsun mu?
        #[serde(default = "default_true")]
        preserve_host: bool,
        /// WebSocket yükseltmesi (`Upgrade: websocket`) desteklensin mi?
        #[serde(default = "default_true")]
        websocket: bool,
        /// Eşleşen prefix istek yolundan kaldırılsın mı? (`true` ise `/api/v1` -> `/v1`)
        #[serde(default)]
        strip_prefix: bool,
    },
    /// Belirtilen HTTP durum kodu ile hedef URL'e yönlendirme
    Redirect {
        /// HTTP Durum Kodu (301, 302, 303, 307, 308)
        #[serde(default = "default_redirect_status")]
        status: u16,
        /// Hedef URL veya yol (ör. `https://yeniadres.com` veya `/yeni-sayfa`)
        target_url: String,
        /// Orijinal sorgu parametreleri (`?a=1&b=2`) korunsun mu?
        #[serde(default = "default_true")]
        preserve_query: bool,
        /// Kalan alt yol hedef URL'in sonuna eklensin mi?
        #[serde(default)]
        append_remainder: bool,
    },
    /// Özel harici işleyici (FastCGI/LSAPI/CGI vb.)
    Custom {
        handler: String,
        location: String,
    },
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string(), "index.htm".to_string()]
}

fn default_redirect_status() -> u16 {
    302
}

/// Başlık (Header) manipülasyon eylemleri.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeaderAction {
    /// Başlık yoksa ekler, varsa çoklu başlık olarak listeye ekler.
    Add { name: String, value: String },
    /// Başlığı varsa üzerine yazar, yoksa ekler.
    Set { name: String, value: String },
    /// Belirtilen başlıktaki tüm kayıtları siler.
    Remove { name: String },
}

/// İstek ve yanıt başlık kuralları kümesi.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderRuleSet {
    pub request_actions: Vec<HeaderAction>,
    pub response_actions: Vec<HeaderAction>,
}

impl HeaderRuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_request_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request_actions.push(HeaderAction::Add {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn set_request_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request_actions.push(HeaderAction::Set {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn remove_request_header(mut self, name: impl Into<String>) -> Self {
        self.request_actions.push(HeaderAction::Remove {
            name: name.into(),
        });
        self
    }

    pub fn add_response_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.response_actions.push(HeaderAction::Add {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn set_response_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.response_actions.push(HeaderAction::Set {
            name: name.into(),
            value: value.into(),
        });
        self
    }

    pub fn remove_response_header(mut self, name: impl Into<String>) -> Self {
        self.response_actions.push(HeaderAction::Remove {
            name: name.into(),
        });
        self
    }

    /// Başlık listesine eylemleri uygular.
    pub fn apply_to_headers(actions: &[HeaderAction], headers: &mut Vec<(String, String)>) {
        for action in actions {
            match action {
                HeaderAction::Add { name, value } => {
                    headers.push((name.clone(), value.clone()));
                }
                HeaderAction::Set { name, value } => {
                    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                    headers.push((name.clone(), value.clone()));
                }
                HeaderAction::Remove { name } => {
                    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                }
            }
        }
    }
}

/// Tek bir URI Context yapılandırma kuralı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ContextRule {
    /// Eşleşecek URI öneki (ör. `/`, `/api`, `/static/`, `/docs`)
    pub uri: String,
    /// Context tipi ve hedefleri
    pub context_type: ContextType,
    /// Harici işleyici adı (opsiyonel)
    pub handler: String,
    /// İzin verilen IP / CIDR listesi (boşsa herkese izin)
    pub access_allowed: Vec<String>,
    /// Engellenen IP / CIDR listesi
    pub access_denied: Vec<String>,
    /// Context'e özel yeniden yazma kuralları
    pub rewrite_rules: Vec<String>,
    /// Özel başlık kuralları (Header manipülasyonu)
    pub headers: HeaderRuleSet,
    /// Context aktif mi?
    pub enabled: bool,
    /// Eşit uzunluktaki öneklerde öncelik sırası (yüksek olan önce eşleşir)
    pub priority: i32,
}

impl Default for ContextRule {
    fn default() -> Self {
        Self {
            uri: "/".to_string(),
            context_type: ContextType::Static {
                location: PathBuf::from("html"),
                index_files: default_index_files(),
                autoindex: false,
            },
            handler: String::new(),
            access_allowed: Vec::new(),
            access_denied: Vec::new(),
            rewrite_rules: Vec::new(),
            headers: HeaderRuleSet::default(),
            enabled: true,
            priority: 0,
        }
    }
}

impl ContextRule {
    /// Yeni bir genel kural oluşturur.
    pub fn new(uri: impl Into<String>, context_type: ContextType) -> Self {
        Self {
            uri: normalize_context_uri(&uri.into()),
            context_type,
            ..Default::default()
        }
    }

    /// Yeni bir Static Context kuralı oluşturur.
    pub fn new_static(uri: impl Into<String>, location: impl Into<PathBuf>) -> Self {
        Self::new(
            uri,
            ContextType::Static {
                location: location.into(),
                index_files: default_index_files(),
                autoindex: false,
            },
        )
    }

    /// Yeni bir Reverse Proxy Context kuralı oluşturur.
    pub fn new_proxy(uri: impl Into<String>, upstream: impl Into<String>) -> Self {
        Self::new(
            uri,
            ContextType::Proxy {
                upstream: upstream.into(),
                preserve_host: true,
                websocket: true,
                strip_prefix: false,
            },
        )
    }

    /// Yeni bir HTTP Redirect Context kuralı oluşturur.
    pub fn new_redirect(uri: impl Into<String>, status: u16, target_url: impl Into<String>) -> Self {
        let valid_status = match status {
            301 | 302 | 303 | 307 | 308 => status,
            _ => 302,
        };
        Self::new(
            uri,
            ContextType::Redirect {
                status: valid_status,
                target_url: target_url.into(),
                preserve_query: true,
                append_remainder: false,
            },
        )
    }

    /// İndeks dosyalarını ayarlar (Static context için).
    pub fn with_index_files(mut self, index_files: Vec<String>) -> Self {
        if let ContextType::Static { index_files: idx, .. } = &mut self.context_type {
            *idx = index_files;
        }
        self
    }

    /// Autoindex (dizin listeleme) ayarlar.
    pub fn with_autoindex(mut self, autoindex: bool) -> Self {
        if let ContextType::Static { autoindex: auto, .. } = &mut self.context_type {
            *auto = autoindex;
        }
        self
    }

    /// `strip_prefix` ayarlar (Proxy context için).
    pub fn with_strip_prefix(mut self, strip: bool) -> Self {
        if let ContextType::Proxy { strip_prefix, .. } = &mut self.context_type {
            *strip_prefix = strip;
        }
        self
    }

    /// `preserve_host` ayarlar (Proxy context için).
    pub fn with_preserve_host(mut self, preserve: bool) -> Self {
        if let ContextType::Proxy { preserve_host, .. } = &mut self.context_type {
            *preserve_host = preserve;
        }
        self
    }

    /// `append_remainder` ayarlar (Redirect context için).
    pub fn with_append_remainder(mut self, append: bool) -> Self {
        if let ContextType::Redirect { append_remainder, .. } = &mut self.context_type {
            *append_remainder = append;
        }
        self
    }

    /// `handler` alanını ayarlar.
    pub fn with_handler(mut self, handler: impl Into<String>) -> Self {
        self.handler = handler.into();
        self
    }

    /// İzin verilen IP listesini ayarlar.
    pub fn with_access_allowed(mut self, allowed: Vec<String>) -> Self {
        self.access_allowed = allowed;
        self
    }

    /// Engellenen IP listesini ayarlar.
    pub fn with_access_denied(mut self, denied: Vec<String>) -> Self {
        self.access_denied = denied;
        self
    }

    /// Yeniden yazma (rewrite) kurallarını ayarlar.
    pub fn with_rewrite_rules(mut self, rules: Vec<String>) -> Self {
        self.rewrite_rules = rules;
        self
    }

    /// Başlık manipülasyon kurallarını ayarlar.
    pub fn with_headers(mut self, headers: HeaderRuleSet) -> Self {
        self.headers = headers;
        self
    }

    /// Aktiflik durumunu ayarlar.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Öncelik değerini ayarlar.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// İstemci IP adresinin bu Context'e erişim izni olup olmadığını denetler (IP ACL).
    pub fn is_ip_allowed(&self, client_ip: &IpAddr) -> bool {
        // 1. Eğer engellenenler listesinde varsa: reddet (Açıkça yasaklanan IP engellenmeli)
        if !self.access_denied.is_empty() {
            let denied = self.access_denied.iter().any(|pattern| ip_matches_pattern(client_ip, pattern));
            if denied {
                return false;
            }
        }

        // 2. Eğer izin verilenler listesi tanımlanmışsa (ve boş değilse): eşleşmek ZORUNDA
        if !self.access_allowed.is_empty() {
            return self.access_allowed.iter().any(|pattern| ip_matches_pattern(client_ip, pattern));
        }

        // 3. Varsayılan olarak izin ver
        true
    }
}

/// Eşleşen Context sonucu ve çözümlenmiş alt yol bilgileri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedContext<'a> {
    /// Eşleşen kural referansı
    pub rule: &'a ContextRule,
    /// Eşleşen URI öneki (ör. `/api`)
    pub matched_prefix: &'a str,
    /// Kural önekinden sonra kalan alt yol (ör. `/v1/users` veya `/`)
    pub subpath: String,
    /// Orijinal sorgu dizgisi (ör. `page=1&sort=asc`)
    pub query: Option<String>,
}

/// Sanal Konak Context Yönlendiricisi.
///
/// OpenLiteSpeed standardına göre birden fazla Context kuralını tutar ve
/// gelen her URI'yi en uzun önek eşleşmesi (Longest Prefix Match) prensibiyle yönlendirir.
#[derive(Debug, Clone, Default)]
pub struct VHostContextRouter {
    rules: Vec<ContextRule>,
}

impl VHostContextRouter {
    /// Boş bir yönlendirici oluşturur.
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Yeni bir kural ekler.
    pub fn add_rule(&mut self, mut rule: ContextRule) {
        rule.uri = normalize_context_uri(&rule.uri);
        self.rules.push(rule);
        self.sort_rules();
    }

    /// Verilen kural listesi ile yönlendirici oluşturur.
    pub fn with_rules(mut self, rules: Vec<ContextRule>) -> Self {
        self.rules = rules;
        for r in &mut self.rules {
            r.uri = normalize_context_uri(&r.uri);
        }
        self.sort_rules();
        self
    }

    /// Kuralları en uzun önek (LPM) ve ardından öncelik sırasına göre dizer.
    fn sort_rules(&mut self) {
        self.rules.sort_by(|a, b| {
            // 1. Önek uzunluğu: Daha uzun olan önce gelir (Longest Prefix Match)
            let len_cmp = b.uri.len().cmp(&a.uri.len());
            if len_cmp != Ordering::Equal {
                return len_cmp;
            }
            // 2. Öncelik: Yüksek olan önce gelir
            let prio_cmp = b.priority.cmp(&a.priority);
            if prio_cmp != Ordering::Equal {
                return prio_cmp;
            }
            // 3. URI alfabetik stabil sıra
            a.uri.cmp(&b.uri)
        });
    }

    /// Kayıtlı tüm kuralları döndürür.
    pub fn rules(&self) -> &[ContextRule] {
        &self.rules
    }

    /// Kuralları temizler.
    pub fn clear(&mut self) {
        self.rules.clear();
    }

    /// Gelen istek URI'sini en uzun önek eşleşmesi (Longest Prefix Match) ile eşleştirir.
    pub fn match_uri<'a>(&'a self, req_uri: &str) -> Option<MatchedContext<'a>> {
        let (raw_path, query) = split_uri_path_and_query(req_uri);
        let normalized_path = normalize_request_path(raw_path);

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if is_prefix_match(&normalized_path, &rule.uri) {
                let subpath = compute_subpath(&normalized_path, &rule.uri);
                return Some(MatchedContext {
                    rule,
                    matched_prefix: &rule.uri,
                    subpath,
                    query: query.map(|q| q.to_string()),
                });
            }
        }

        None
    }

    /// Gelen HTTP isteğini çözümler ve kesin karara (`ContextDecision`) bağlar.
    pub fn dispatch(&self, req_uri: &str, client_ip: &IpAddr) -> ContextDecision {
        let Some(matched) = self.match_uri(req_uri) else {
            return ContextDecision::NotFound;
        };

        if !matched.rule.is_ip_allowed(client_ip) {
            return ContextDecision::Forbidden {
                matched_prefix: matched.matched_prefix.to_string(),
                reason: format!("İstemci IP ({}) erişim iznine sahip değil", client_ip),
            };
        }

        match &matched.rule.context_type {
            ContextType::Static { location, index_files, autoindex } => {
                let safe_rel = match sanitize_relative_path(&matched.subpath) {
                    Ok(p) => p,
                    Err(e) => {
                        return ContextDecision::Forbidden {
                            matched_prefix: matched.matched_prefix.to_string(),
                            reason: format!("Path traversal koruması: {}", e),
                        };
                    }
                };
                let full_path = location.join(&safe_rel);
                let mut resp_hdrs = Vec::new();
                HeaderRuleSet::apply_to_headers(&matched.rule.headers.response_actions, &mut resp_hdrs);

                ContextDecision::Static {
                    matched_prefix: matched.matched_prefix.to_string(),
                    file_path: full_path,
                    relative_path: safe_rel.to_string_lossy().to_string(),
                    autoindex: *autoindex,
                    index_files: index_files.clone(),
                    response_headers: resp_hdrs,
                }
            }
            ContextType::Proxy { upstream, preserve_host, websocket, strip_prefix } => {
                let (raw_path, _) = split_uri_path_and_query(req_uri);
                let (target_upstream, rewritten_uri) = compute_proxy_target_url(
                    upstream,
                    &matched.subpath,
                    matched.query.as_deref(),
                    *strip_prefix,
                    raw_path,
                );

                ContextDecision::Proxy {
                    matched_prefix: matched.matched_prefix.to_string(),
                    upstream: target_upstream,
                    rewritten_uri,
                    strip_prefix: *strip_prefix,
                    preserve_host: *preserve_host,
                    websocket: *websocket,
                    custom_request_headers: matched.rule.headers.request_actions.clone(),
                    custom_response_headers: matched.rule.headers.response_actions.clone(),
                }
            }
            ContextType::Redirect { status, target_url, preserve_query, append_remainder } => {
                let resp = handle_redirect_context(
                    *status,
                    target_url,
                    &matched.subpath,
                    matched.query.as_deref(),
                    *preserve_query,
                    *append_remainder,
                );
                let loc = resp.headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.clone()).unwrap_or_else(|| target_url.clone());
                let mut resp_hdrs = Vec::new();
                HeaderRuleSet::apply_to_headers(&matched.rule.headers.response_actions, &mut resp_hdrs);

                ContextDecision::Redirect {
                    matched_prefix: matched.matched_prefix.to_string(),
                    status_code: *status,
                    destination: loc,
                    headers: resp_hdrs,
                }
            }
            ContextType::Custom { .. } => ContextDecision::NotFound,
        }
    }
}

/// OLS Context motoru için genel isim (type alias).
pub type ContextEngine = VHostContextRouter;

/// Context yönlendiricisinin ürettiği kesin yönlendirme kararı.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextDecision {
    /// Statik dosya isteği.
    Static {
        matched_prefix: String,
        file_path: PathBuf,
        relative_path: String,
        autoindex: bool,
        index_files: Vec<String>,
        response_headers: Vec<(String, String)>,
    },
    /// Ters vekil isteği.
    Proxy {
        matched_prefix: String,
        upstream: String,
        rewritten_uri: String,
        strip_prefix: bool,
        preserve_host: bool,
        websocket: bool,
        custom_request_headers: Vec<HeaderAction>,
        custom_response_headers: Vec<HeaderAction>,
    },
    /// Yönlendirme yanıtı.
    Redirect {
        matched_prefix: String,
        status_code: u16,
        destination: String,
        headers: Vec<(String, String)>,
    },
    /// Erişim engellendi (403 Forbidden).
    Forbidden {
        matched_prefix: String,
        reason: String,
    },
    /// Eşleşen aktif bir context bulunamadı.
    NotFound,
}

/// HTTP Yanıt Temsili.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ContextResponse {
    /// Yeni genel HTTP yanıtı oluşturur.
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        let mut headers = Vec::new();
        headers.push(("content-type".to_string(), content_type.to_string()));
        headers.push(("content-length".to_string(), body.len().to_string()));
        headers.push(("connection".to_string(), "keep-alive".to_string()));
        Self { status, headers, body }
    }

    /// 200 OK yanıtı oluşturur.
    pub fn ok(body: Vec<u8>, content_type: &str) -> Self {
        Self::new(200, content_type, body)
    }

    /// 301 / 302 HTTP Yönlendirme yanıtı oluşturur.
    pub fn redirect(status: u16, location: &str) -> Self {
        let html_body = format!(
            "<!DOCTYPE html><html><head><title>Redirecting</title></head><body>\
            <p>Redirecting to <a href=\"{0}\">{0}</a>...</p></body></html>",
            location
        );
        let body = html_body.into_bytes();
        let headers = vec![
            ("location".to_string(), location.to_string()),
            ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
            ("content-length".to_string(), body.len().to_string()),
            ("connection".to_string(), "keep-alive".to_string()),
        ];
        Self { status, headers, body }
    }

    /// 403 Forbidden yanıtı oluşturur.
    pub fn forbidden(msg: &str) -> Self {
        let body = format!("403 Forbidden - {}\n", msg).into_bytes();
        Self::new(403, "text/plain; charset=utf-8", body)
    }

    /// 404 Not Found yanıtı oluşturur.
    pub fn not_found(msg: &str) -> Self {
        let body = format!("404 Not Found - {}\n", msg).into_bytes();
        Self::new(404, "text/plain; charset=utf-8", body)
    }

    /// 400 Bad Request yanıtı oluşturur.
    pub fn bad_request(msg: &str) -> Self {
        let body = format!("400 Bad Request - {}\n", msg).into_bytes();
        Self::new(400, "text/plain; charset=utf-8", body)
    }

    /// 500 Internal Server Error yanıtı oluşturur.
    pub fn internal_error(msg: &str) -> Self {
        let body = format!("500 Internal Server Error - {}\n", msg).into_bytes();
        Self::new(500, "text/plain; charset=utf-8", body)
    }

    /// HTTP/1.1 tel formatında bayt dizisine dönüştürür.
    pub fn to_http1_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            204 => "No Content",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            504 => "Gateway Timeout",
            _ => "Status",
        };

        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", self.status, reason).as_bytes());

        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

/// Context motorunda oluşabilecek hatalar.
#[derive(Debug)]
pub enum ContextError {
    AccessDenied(String),
    PathTraversal(String),
    NotFound(String),
    InvalidRedirectStatus(u16),
    Io(std::io::Error),
    UpstreamError(String),
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied(s) => write!(f, "Context erişim reddedildi: {}", s),
            Self::PathTraversal(s) => write!(f, "Dizin aşma (Path Traversal) engellendi: {}", s),
            Self::NotFound(s) => write!(f, "Kaynak bulunamadı: {}", s),
            Self::InvalidRedirectStatus(code) => write!(f, "Geçersiz yönlendirme durum kodu: {}", code),
            Self::Io(e) => write!(f, "Giriş/çıkış hatası: {}", e),
            Self::UpstreamError(s) => write!(f, "Upstream hatası: {}", s),
        }
    }
}

impl std::error::Error for ContextError {}

impl From<std::io::Error> for ContextError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// =========================================================================
// İŞLEYİCİLER (HANDLERS)
// =========================================================================

/// Static Context için istek işleme: Güvenli dosya yolu çözümleme, indeks dosyası ve autoindex.
pub async fn handle_static_context(
    base_location: &Path,
    subpath: &str,
    index_files: &[String],
    autoindex: bool,
    method: &str,
) -> Result<ContextResponse, ContextError> {
    // 1. Dizin aşma (Path Traversal) denetimi
    let safe_rel_path = sanitize_relative_path(subpath)?;
    let target_path = base_location.join(safe_rel_path);

    // 2. Hedef var mı kontrol et
    let meta = match tokio::fs::metadata(&target_path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ContextResponse::not_found("Dosya veya dizin mevcut değil"));
        }
        Err(e) => return Err(ContextError::Io(e)),
    };

    // 3. Hedef dizin mi yoksa dosya mı?
    if meta.is_dir() {
        // İndeks dosyalarını sırayla ara
        for idx in index_files {
            let candidate = target_path.join(idx);
            if let Ok(cand_meta) = tokio::fs::metadata(&candidate).await {
                if cand_meta.is_file() {
                    return read_and_serve_file(&candidate, method).await;
                }
            }
        }

        // İndeks bulunamadı: Autoindex açık mı?
        if autoindex {
            return generate_autoindex_html(&target_path, subpath).await;
        } else {
            return Ok(ContextResponse::forbidden("Dizin listeleme devre dışı bırakılmış (Directory listing denied)"));
        }
    } else if meta.is_file() {
        return read_and_serve_file(&target_path, method).await;
    }

    Ok(ContextResponse::not_found("Geçersiz kaynak türü"))
}

/// Redirect Context için hedef URL hesaplama ve yanıt oluşturma.
pub fn handle_redirect_context(
    status: u16,
    target_url: &str,
    subpath: &str,
    query: Option<&str>,
    preserve_query: bool,
    append_remainder: bool,
) -> ContextResponse {
    let mut final_url = target_url.to_string();

    // 1. Kalan alt yol eklenmeli mi?
    if append_remainder {
        let clean_sub = subpath.trim_start_matches('/');
        if !clean_sub.is_empty() {
            if !final_url.ends_with('/') {
                final_url.push('/');
            }
            final_url.push_str(clean_sub);
        }
    }

    // 2. Sorgu parametreleri korunmalı mı?
    if preserve_query {
        if let Some(q) = query {
            if !q.is_empty() {
                if final_url.contains('?') {
                    final_url.push('&');
                } else {
                    final_url.push('?');
                }
                final_url.push_str(q);
            }
        }
    }

    ContextResponse::redirect(status, &final_url)
}

/// Proxy Context için iletilecek hedef adres ve yolu hesaplar.
pub fn compute_proxy_target_url(
    upstream: &str,
    subpath: &str,
    query: Option<&str>,
    strip_prefix: bool,
    original_path: &str,
) -> (String, String) {
    let path_to_forward = if strip_prefix {
        if subpath.is_empty() || !subpath.starts_with('/') {
            format!("/{}", subpath)
        } else {
            subpath.to_string()
        }
    } else {
        original_path.to_string()
    };

    let target_uri = match query {
        Some(q) if !q.is_empty() => format!("{}?{}", path_to_forward, q),
        _ => path_to_forward,
    };

    // Upstream temizleme: http:// veya https:// öneklerini ayıkla
    let cleaned_upstream = upstream
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');

    (cleaned_upstream.to_string(), target_uri)
}

// =========================================================================
// YARDIMCI İŞLEVLER (HELPERS)
// =========================================================================

/// Context URI'sini normalize eder (`/api/` -> `/api`, `/` -> `/`).
pub fn normalize_context_uri(uri: &str) -> String {
    let trimmed = uri.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }

    let mut out = String::new();
    if !trimmed.starts_with('/') {
        out.push('/');
    }
    out.push_str(trimmed.trim_end_matches('/'));
    out
}

/// İstek yolunu ve sorgu dizgisini ayırır.
pub fn split_uri_path_and_query(uri: &str) -> (&str, Option<&str>) {
    let s = uri.trim();
    if let Some((path, query)) = s.split_once('?') {
        (path, Some(query))
    } else {
        (s, None)
    }
}

/// İstek yolunu normalize eder (ardışık eğik çizgileri ve yüzde kodlamasını temizler).
pub fn normalize_request_path(path: &str) -> String {
    let decoded = percent_decode(path);
    let mut clean = String::with_capacity(decoded.len() + 1);

    if !decoded.starts_with('/') {
        clean.push('/');
    }

    let mut last_was_slash = false;
    for c in decoded.chars() {
        if c == '/' {
            if !last_was_slash {
                clean.push('/');
                last_was_slash = true;
            }
        } else {
            clean.push(c);
            last_was_slash = false;
        }
    }

    if clean.is_empty() {
        "/".to_string()
    } else {
        clean
    }
}

/// Bir yolun context öneki ile eşleşip eşleşmediğini (yol sınırlarını gözeterek) kontrol eder.
fn is_prefix_match(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }

    if path == prefix {
        return true;
    }

    if path.starts_with(prefix) {
        let remainder = &path[prefix.len()..];
        // Yol sınırı: remainder '/' ile başlamalı (ör. `/api/v1` eşleşir, `/apocalypse` eşleşmez)
        return remainder.starts_with('/');
    }

    false
}

/// Eşleşen önekten sonraki alt yolu hesaplar.
fn compute_subpath(path: &str, prefix: &str) -> String {
    if prefix == "/" {
        return path.to_string();
    }

    if path == prefix {
        return "/".to_string();
    }

    if path.starts_with(prefix) {
        let remainder = &path[prefix.len()..];
        if remainder.is_empty() {
            "/".to_string()
        } else if remainder.starts_with('/') {
            remainder.to_string()
        } else {
            format!("/{}", remainder)
        }
    } else {
        "/".to_string()
    }
}

/// Basit ve güvenli yüzde kod çözücü (%20 vb.).
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte_val) = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..=i + 2]).unwrap_or(""), 16) {
                out.push(byte_val);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Göreli yolu güvenli hale getirir; `..` veya üst dizine geçiş girişimlerini reddeder.
fn sanitize_relative_path(subpath: &str) -> Result<PathBuf, ContextError> {
    let p = Path::new(subpath);
    let mut sanitized = PathBuf::new();

    for comp in p.components() {
        match comp {
            Component::Normal(c) => {
                let s = c.to_string_lossy();
                if s.contains('\0') {
                    return Err(ContextError::PathTraversal("Geçersiz boş bayt (null byte)".to_string()));
                }
                sanitized.push(c);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(ContextError::PathTraversal("Üst dizin (..) geçişi yasak".to_string()));
            }
            Component::RootDir | Component::Prefix(_) => {}
        }
    }

    Ok(sanitized)
}

/// Dosyayı okur ve HTTP yanıtı olarak sunar.
async fn read_and_serve_file(file_path: &Path, method: &str) -> Result<ContextResponse, ContextError> {
    let content_type = guess_mime_type(file_path);
    let is_head = method.eq_ignore_ascii_case("HEAD");

    let file_bytes = if is_head {
        Vec::new()
    } else {
        tokio::fs::read(file_path).await?
    };

    let file_size = if is_head {
        tokio::fs::metadata(file_path).await?.len() as usize
    } else {
        file_bytes.len()
    };

    let mut headers = Vec::new();
    headers.push(("content-type".to_string(), content_type.to_string()));
    headers.push(("content-length".to_string(), file_size.to_string()));
    headers.push(("accept-ranges".to_string(), "bytes".to_string()));
    headers.push(("connection".to_string(), "keep-alive".to_string()));

    Ok(ContextResponse {
        status: 200,
        headers,
        body: file_bytes,
    })
}

/// Dizin listesi (autoindex) HTML çıktısı üretir.
async fn generate_autoindex_html(dir_path: &Path, uri_path: &str) -> Result<ContextResponse, ContextError> {
    let mut entries = tokio::fs::read_dir(dir_path).await?;
    let mut list_items = String::new();

    // Üst dizin bağlantısı (kök değilse)
    if uri_path != "/" && !uri_path.is_empty() {
        list_items.push_str("<li><a href=\"../\">📁 ../ (Üst Dizin)</a></li>\n");
    }

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue; // Gizli dosyaları atla
        }

        let meta = entry.metadata().await;
        let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);

        if is_dir {
            list_items.push_str(&format!(
                "<li>📁 <a href=\"{0}/\">{0}/</a> [Dizin]</li>\n",
                name
            ));
        } else {
            list_items.push_str(&format!(
                "<li>📄 <a href=\"{0}\">{0}</a> ({1} bayt)</li>\n",
                name, size
            ));
        }
    }

    let html = format!(
        "<!DOCTYPE html>\n<html>\n<head><meta charset=\"utf-8\"><title>Index of {0}</title>\
        <style>body {{ font-family: monospace; padding: 20px; }} ul {{ list-style-type: none; padding-left: 0; }} li {{ margin: 6px 0; }}</style>\
        </head>\n<body>\n<h2>Index of {0}</h2><hr>\n<ul>\n{1}</ul>\n<hr>\
        <small>ZMax Server / OpenLiteSpeed Parity Context Engine</small>\n</body>\n</html>",
        uri_path, list_items
    );

    Ok(ContextResponse::ok(html.into_bytes(), "text/html; charset=utf-8"))
}

/// Dosya uzantısından MIME türünü tespit eder.
pub fn guess_mime_type(path: &Path) -> &'static str {
    let ext = match path.extension().and_then(|s| s.to_str()) {
        Some(e) => e.to_ascii_lowercase(),
        None => return "application/octet-stream",
    };

    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml",
        "txt" | "log" => "text/plain; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "eot" => "application/vnd.ms-fontobject",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "tar" => "application/gzip",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// IP adresinin verilen kalıp (IP, CIDR veya wildcard) ile eşleşip eşleşmediğini kontrol eder.
fn ip_matches_pattern(client_ip: &IpAddr, pattern: &str) -> bool {
    let pat = pattern.trim();
    if pat.is_empty() {
        return false;
    }

    if pat == "*" || pat.eq_ignore_ascii_case("all") {
        return true;
    }

    // 1. CIDR kontrolü (ör. `192.168.1.0/24`)
    if let Some((subnet_str, mask_str)) = pat.split_once('/') {
        if let (Ok(subnet_ip), Ok(mask_len)) = (subnet_str.trim().parse::<IpAddr>(), mask_str.trim().parse::<u8>()) {
            return match (client_ip, subnet_ip) {
                (IpAddr::V4(c), IpAddr::V4(s)) => {
                    if mask_len > 32 {
                        false
                    } else if mask_len == 0 {
                        true
                    } else {
                        let mask = !((1u32 << (32 - mask_len)) - 1);
                        (u32::from(*c) & mask) == (u32::from(s) & mask)
                    }
                }
                (IpAddr::V6(c), IpAddr::V6(s)) => {
                    if mask_len > 128 {
                        false
                    } else if mask_len == 0 {
                        true
                    } else {
                        let c_u128 = u128::from(*c);
                        let s_u128 = u128::from(s);
                        let shift = 128 - mask_len;
                        let mask = if shift >= 128 { 0 } else { !((1u128 << shift) - 1) };
                        (c_u128 & mask) == (s_u128 & mask)
                    }
                }
                _ => false,
            };
        }
    }

    // 2. Birebir IP eşleşmesi
    if let Ok(target_ip) = pat.parse::<IpAddr>() {
        return *client_ip == target_ip;
    }

    false
}

// =========================================================================
// BİRİM VE ENTEGRASYON TESTLERİ
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longest_prefix_match_sorting_and_routing() {
        let mut router = VHostContextRouter::new();

        // Karışık sırada ekle
        router.add_rule(ContextRule::new_static("/", "/var/www/html"));
        router.add_rule(ContextRule::new_proxy("/api", "127.0.0.1:3000"));
        router.add_rule(ContextRule::new_proxy("/api/v1/auth", "127.0.0.1:4000"));
        router.add_rule(ContextRule::new_proxy("/api/v1", "127.0.0.1:3001"));
        router.add_rule(ContextRule::new_static("/static", "/var/www/static"));

        // 1. Kök dizin eşleşmesi
        let m = router.match_uri("/index.html").expect("kök eşleşmeli");
        assert_eq!(m.matched_prefix, "/");
        assert_eq!(m.subpath, "/index.html");

        // 2. /api genel eşleşmesi
        let m = router.match_uri("/api/users").expect("/api eşleşmeli");
        assert_eq!(m.matched_prefix, "/api");
        assert_eq!(m.subpath, "/users");

        // 3. /api/v1 LPM eşleşmesi (/api yerine /api/v1 seçilmeli)
        let m = router.match_uri("/api/v1/products/123").expect("/api/v1 eşleşmeli");
        assert_eq!(m.matched_prefix, "/api/v1");
        assert_eq!(m.subpath, "/products/123");

        // 4. /api/v1/auth LPM eşleşmesi (en spesifik olan seçilmeli)
        let m = router.match_uri("/api/v1/auth/login?redirect=home").expect("auth eşleşmeli");
        assert_eq!(m.matched_prefix, "/api/v1/auth");
        assert_eq!(m.subpath, "/login");
        assert_eq!(m.query.as_deref(), Some("redirect=home"));

        // 5. Yol sınırı denetimi: `/apiservice` `/api` ile eşleşmemeli, kök `/`'a düşmeli
        let m = router.match_uri("/apiservice").expect("kök eşleşmeli");
        assert_eq!(m.matched_prefix, "/");
        assert_eq!(m.subpath, "/apiservice");
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let mut router = VHostContextRouter::new();
        router.add_rule(ContextRule::new_static("/", "/var/www/html"));
        router.add_rule(ContextRule::new_proxy("/api", "127.0.0.1:3000").with_enabled(false));

        let m = router.match_uri("/api/data").expect("kök eşleşmeli");
        assert_eq!(m.matched_prefix, "/");
    }

    #[test]
    fn test_ip_acl_matching() {
        let mut rule = ContextRule::new_static("/admin", "/var/www/admin");
        rule.access_allowed = vec!["127.0.0.1".to_string(), "192.168.1.0/24".to_string()];
        rule.access_denied = vec!["192.168.1.50".to_string()];

        let localhost: IpAddr = "127.0.0.1".parse().unwrap();
        let allowed_subnet: IpAddr = "192.168.1.15".parse().unwrap();
        let denied_ip: IpAddr = "192.168.1.50".parse().unwrap();
        let external_ip: IpAddr = "8.8.8.8".parse().unwrap();

        assert!(rule.is_ip_allowed(&localhost));
        assert!(rule.is_ip_allowed(&allowed_subnet));
        assert!(!rule.is_ip_allowed(&denied_ip), "Açıkça yasaklanan IP engellenmeli");
        assert!(!rule.is_ip_allowed(&external_ip), "İzin listesinde olmayan IP engellenmeli");
    }

    #[test]
    fn test_redirect_handler_generation() {
        let resp = handle_redirect_context(
            301,
            "https://yenisite.com/hedef",
            "/detay",
            Some("ref=mail"),
            true,
            true,
        );

        assert_eq!(resp.status, 301);
        let loc = resp.headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.as_str());
        assert_eq!(loc, Some("https://yenisite.com/hedef/detay?ref=mail"));
    }

    #[test]
    fn test_proxy_target_url_computation() {
        // Strip prefix kapalı
        let (upstream, target) = compute_proxy_target_url(
            "http://127.0.0.1:3000",
            "/users",
            Some("page=2"),
            false,
            "/api/users",
        );
        assert_eq!(upstream, "127.0.0.1:3000");
        assert_eq!(target, "/api/users?page=2");

        // Strip prefix açık
        let (upstream, target) = compute_proxy_target_url(
            "127.0.0.1:3000",
            "/users",
            None,
            true,
            "/api/users",
        );
        assert_eq!(upstream, "127.0.0.1:3000");
        assert_eq!(target, "/users");
    }

    #[tokio::test]
    async fn test_static_context_file_serving_and_traversal_protection() {
        let tmp_dir = std::env::temp_dir().join(format!("zmax_ctx_test_{}", std::process::id()));
        tokio::fs::create_dir_all(&tmp_dir).await.unwrap();

        let index_file = tmp_dir.join("index.html");
        tokio::fs::write(&index_file, b"<h1>Hos Geldiniz</h1>").await.unwrap();

        let test_css = tmp_dir.join("style.css");
        tokio::fs::write(&test_css, b"body { color: red; }").await.unwrap();

        // 1. İndeks dosyası otomatik çözümü
        let resp = handle_static_context(&tmp_dir, "/", &["index.html".to_string()], false, "GET")
            .await
            .expect("statik yanıt dönmeli");
        assert_eq!(resp.status, 200);
        assert_eq!(String::from_utf8_lossy(&resp.body), "<h1>Hos Geldiniz</h1>");
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v.contains("text/html")));

        // 2. Belirli dosya sunumu (CSS)
        let resp = handle_static_context(&tmp_dir, "/style.css", &[], false, "GET")
            .await
            .expect("css yanıt dönmeli");
        assert_eq!(resp.status, 200);
        assert_eq!(String::from_utf8_lossy(&resp.body), "body { color: red; }");
        assert!(resp.headers.iter().any(|(k, v)| k == "content-type" && v.contains("text/css")));

        // 3. Bulunamayan dosya
        let resp = handle_static_context(&tmp_dir, "/yok.txt", &[], false, "GET")
            .await
            .expect("404 dönmeli");
        assert_eq!(resp.status, 404);

        // 4. Path traversal (üst dizine geçiş) koruması
        let res = handle_static_context(&tmp_dir, "/../../secret.txt", &[], false, "GET").await;
        assert!(matches!(res, Err(ContextError::PathTraversal(_))));

        // Temizlik
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
    }

    #[test]
    fn test_context_rule_builder_methods() {
        let static_rule = ContextRule::new_static("/files", "/var/data")
            .with_index_files(vec!["app.html".to_string()])
            .with_autoindex(true);

        if let ContextType::Static { index_files, autoindex, .. } = static_rule.context_type {
            assert_eq!(index_files, vec!["app.html".to_string()]);
            assert!(autoindex);
        } else {
            panic!("Beklenen static context");
        }

        let proxy_rule = ContextRule::new_proxy("/api", "127.0.0.1:8080")
            .with_strip_prefix(true)
            .with_preserve_host(false);

        if let ContextType::Proxy { strip_prefix, preserve_host, .. } = proxy_rule.context_type {
            assert!(strip_prefix);
            assert!(!preserve_host);
        } else {
            panic!("Beklenen proxy context");
        }
    }

    #[test]
    fn test_dispatch_static_proxy_redirect_and_forbidden() {
        let client_ip: IpAddr = "192.168.1.100".parse().unwrap();
        let blocked_ip: IpAddr = "10.0.0.99".parse().unwrap();

        let mut router = VHostContextRouter::new();

        // 1. Statik Kural
        router.add_rule(ContextRule::new_static("/static", "/var/www/static"));

        // 2. Proxy Kural (strip_prefix + headers)
        let mut hdrs = HeaderRuleSet::new();
        hdrs = hdrs.add_request_header("X-Proxy-By", "ZMax");
        hdrs = hdrs.add_response_header("X-Cache", "MISS");

        router.add_rule(
            ContextRule::new_proxy("/api/v2", "http://backend.internal:5000")
                .with_strip_prefix(true)
                .with_headers(hdrs),
        );

        // 3. Redirect Kural
        router.add_rule(ContextRule::new_redirect("/old-docs", 301, "https://docs.example.com/v2"));

        // 4. Korumalı Alan (IP ACL: sadece 192.168.1.0/24 izinli)
        let mut secure_rule = ContextRule::new_static("/secure", "/var/www/secure");
        secure_rule.access_allowed = vec!["192.168.1.0/24".to_string()];
        router.add_rule(secure_rule);

        // Test 1: Statik dispatch
        match router.dispatch("/static/images/logo.png", &client_ip) {
            ContextDecision::Static { matched_prefix, file_path, relative_path, .. } => {
                assert_eq!(matched_prefix, "/static");
                assert_eq!(relative_path, "images\\logo.png".replace('\\', std::path::MAIN_SEPARATOR_STR));
                assert!(file_path.ends_with(format!("images{}logo.png", std::path::MAIN_SEPARATOR)));
            }
            other => panic!("Beklenmeyen dispatch sonucu: {:?}", other),
        }

        // Test 2: Proxy dispatch
        match router.dispatch("/api/v2/items?page=1", &client_ip) {
            ContextDecision::Proxy {
                matched_prefix,
                upstream,
                rewritten_uri,
                strip_prefix,
                custom_request_headers,
                custom_response_headers,
                ..
            } => {
                assert_eq!(matched_prefix, "/api/v2");
                assert_eq!(upstream, "backend.internal:5000");
                assert_eq!(rewritten_uri, "/items?page=1");
                assert!(strip_prefix);
                assert_eq!(custom_request_headers.len(), 1);
                assert_eq!(custom_response_headers.len(), 1);
            }
            other => panic!("Beklenmeyen proxy dispatch sonucu: {:?}", other),
        }

        // Test 3: Redirect dispatch
        match router.dispatch("/old-docs/guide", &client_ip) {
            ContextDecision::Redirect { matched_prefix, status_code, destination, .. } => {
                assert_eq!(matched_prefix, "/old-docs");
                assert_eq!(status_code, 301);
                assert_eq!(destination, "https://docs.example.com/v2");
            }
            other => panic!("Beklenmeyen redirect dispatch sonucu: {:?}", other),
        }

        // Test 4: Yetkili IP ile /secure
        match router.dispatch("/secure/dashboard", &client_ip) {
            ContextDecision::Static { matched_prefix, .. } => {
                assert_eq!(matched_prefix, "/secure");
            }
            other => panic!("Beklenmeyen secure dispatch sonucu: {:?}", other),
        }

        // Test 5: Yasaklı IP ile /secure -> Forbidden
        match router.dispatch("/secure/dashboard", &blocked_ip) {
            ContextDecision::Forbidden { matched_prefix, .. } => {
                assert_eq!(matched_prefix, "/secure");
            }
            other => panic!("Beklenen Forbidden ancak döndü: {:?}", other),
        }

        // Test 6: Eşleşmeyen URI -> NotFound
        match router.dispatch("/unmapped/path", &client_ip) {
            ContextDecision::NotFound => {}
            other => panic!("Beklenen NotFound ancak döndü: {:?}", other),
        }
    }
}
