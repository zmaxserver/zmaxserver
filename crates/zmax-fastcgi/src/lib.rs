//! # zmax-fastcgi
//! PHP-FPM / LSPHP ikili FastCGI protokol istemcisi ve soket havuzu.

use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use zmax_pool::UpstreamSocketPool;

pub const FCGI_VERSION_1: u8 = 1;
pub const FCGI_BEGIN_REQUEST: u8 = 1;
pub const FCGI_ABORT_REQUEST: u8 = 2;
pub const FCGI_END_REQUEST: u8 = 3;
pub const FCGI_PARAMS: u8 = 4;
pub const FCGI_STDIN: u8 = 5;
pub const FCGI_STDOUT: u8 = 6;
pub const FCGI_STDERR: u8 = 7;
pub const FCGI_RESPONDER: u16 = 1;
pub const FCGI_KEEP_CONN: u8 = 1;

/// Tek bir FastCGI kaydında taşınabilecek azami veri uzunluğu (65535 bayt).
pub const FCGI_MAX_RECORD_LEN: usize = u16::MAX as usize;

/// Varsayılan FastCGI istek zaman aşımı süresi (saniye).
pub const DEFAULT_FASTCGI_TIMEOUT_SECS: u64 = 60;

/// Varsayılan `SERVER_SOFTWARE` CGI değişkeni değeri.
pub const DEFAULT_SERVER_SOFTWARE: &str = "ZMax/1.0.1 (ZePanel)";

/// FastCGI istemci, protokol ve güvenlik doğrulama hataları.
#[derive(Debug)]
pub enum FastCgiError {
    /// Güvenlik politikası ihlali (path traversal, symlink kaçışı, geçersiz hedef dosya).
    SecurityViolation(String),
    /// Ağ veya dosya sistemi G/Ç hatası.
    Io(std::io::Error),
    /// Bağlantı kurulumu veya yanıt okuma zaman aşımı.
    Timeout(String),
    /// Eksik, bozuk veya beklenmeyen FastCGI protokol durumu.
    Protocol(String),
}

impl fmt::Display for FastCgiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecurityViolation(msg) => write!(f, "FastCGI guvenlik ihlali: {msg}"),
            Self::Io(err) => write!(f, "FastCGI G/C hatasi: {err}"),
            Self::Timeout(msg) => write!(f, "FastCGI zaman asimi: {msg}"),
            Self::Protocol(msg) => write!(f, "FastCGI protokol hatasi: {msg}"),
        }
    }
}

impl std::error::Error for FastCgiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for FastCgiError {
    fn from(err: std::io::Error) -> Self {
        if err.kind() == ErrorKind::TimedOut {
            Self::Timeout(err.to_string())
        } else {
            Self::Io(err)
        }
    }
}

/// FastCGI isteğinden dönen ham STDOUT ve STDERR çıktıları.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiResponse {
    /// PHP-FPM / LSPHP tarafından üretilen ham CGI başlıkları ve yanıt gövdesi (`FCGI_STDOUT`).
    pub raw_stdout: Vec<u8>,
    /// PHP hata, uyarı veya `error_log` kayıtları (`FCGI_STDERR`).
    pub stderr: Vec<u8>,
}

/// Ayrıştırılmış CGI başlıkları, gövde, STDERR ve dahili yönlendirme bilgilerini içeren detaylı yanıt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FastCgiResponseDetailed {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub raw_stdout: Vec<u8>,
    pub stderr: String,
    pub x_accel_redirect: Option<String>,
    pub x_sendfile: Option<String>,
}

impl FastCgiResponseDetailed {
    /// Ham STDOUT ve STDERR tamponlarından ayrıştırılmış yanıt oluşturur.
    pub fn from_raw(raw_stdout: Vec<u8>, raw_stderr: Vec<u8>) -> Self {
        let (status, reason, headers, body_slice) =
            FastCgiClient::split_cgi_headers_with_reason(&raw_stdout);
        let body = body_slice.to_vec();
        let x_accel_redirect = extract_safe_redirect_header(&headers, "x-accel-redirect");
        let x_sendfile = extract_safe_redirect_header(&headers, "x-sendfile");
        let stderr = String::from_utf8_lossy(&raw_stderr).into_owned();

        Self {
            status,
            reason,
            headers,
            body,
            raw_stdout,
            stderr,
            x_accel_redirect,
            x_sendfile,
        }
    }
}

/// Havuzlu FastCGI çalıştırma isteği ve meta verisi.
#[derive(Debug, Clone)]
pub struct FastCgiRequest {
    pub method: String,
    pub request_uri: String,
    pub script_name: String,
    pub script_filename: String,
    pub document_root: String,
    pub query_string: String,
    pub path_info: String,
    pub path_translated: String,
    pub host: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub server_port: u16,
    pub is_https: bool,
    pub server_software: String,
    /// HTTP protokol sürümü (`"HTTP/2.0"`, `"HTTP/1.1"` vb.; `None` ise `"HTTP/1.1"`).
    pub server_protocol: Option<String>,
    pub headers: Vec<(String, String)>,
    /// `.htaccess` `[E=...]` gibi ek CGI ortam değişkenleri (`HTTP_PROXY` engellenir).
    pub extra_env: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Default for FastCgiRequest {
    fn default() -> Self {
        Self {
            method: "GET".to_string(),
            request_uri: "/".to_string(),
            script_name: String::new(),
            script_filename: String::new(),
            document_root: String::new(),
            query_string: String::new(),
            path_info: String::new(),
            path_translated: String::new(),
            host: String::new(),
            remote_addr: String::new(),
            remote_port: 0,
            server_port: 80,
            is_https: false,
            server_software: DEFAULT_SERVER_SOFTWARE.to_string(),
            server_protocol: None,
            headers: Vec::new(),
            extra_env: Vec::new(),
            body: Vec::new(),
        }
    }
}

impl FastCgiRequest {
    /// Zorunlu istek ve betik yolu alanlarıyla yeni bir `FastCgiRequest` oluşturur.
    pub fn new(
        method: impl Into<String>,
        request_uri: impl Into<String>,
        script_name: impl Into<String>,
        script_filename: impl Into<String>,
        document_root: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            request_uri: request_uri.into(),
            script_name: script_name.into(),
            script_filename: script_filename.into(),
            document_root: document_root.into(),
            ..Self::default()
        }
    }

    pub fn query_string(mut self, query_string: impl Into<String>) -> Self {
        self.query_string = query_string.into();
        self
    }

    pub fn path_info(mut self, path_info: impl Into<String>) -> Self {
        self.path_info = path_info.into();
        self
    }

    pub fn path_translated(mut self, path_translated: impl Into<String>) -> Self {
        self.path_translated = path_translated.into();
        self
    }

    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    pub fn remote_addr(mut self, remote_addr: impl Into<String>) -> Self {
        self.remote_addr = remote_addr.into();
        self
    }

    pub fn remote_port(mut self, remote_port: u16) -> Self {
        self.remote_port = remote_port;
        self
    }

    pub fn server_port(mut self, server_port: u16) -> Self {
        self.server_port = server_port;
        self
    }

    pub fn is_https(mut self, is_https: bool) -> Self {
        self.is_https = is_https;
        self
    }

    pub fn server_software(mut self, server_software: impl Into<String>) -> Self {
        self.server_software = server_software.into();
        self
    }

    pub fn server_protocol(mut self, server_protocol: impl Into<String>) -> Self {
        self.server_protocol = Some(server_protocol.into());
        self
    }

    pub fn headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub fn extra_env(mut self, extra_env: Vec<(String, String)>) -> Self {
        self.extra_env = extra_env;
        self
    }

    pub fn env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), val.into()));
        self
    }

    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }

    /// İstekten HTTPoxy-korumalı eksiksiz CGI/1.1 FastCGI parametre haritası üretir.
    pub fn build_params(&self) -> HashMap<String, String> {
        let protocol = self
            .server_protocol
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("HTTP/1.1");

        build_cgi_params_internal(
            &self.method,
            &self.request_uri,
            &self.script_name,
            &self.script_filename,
            &self.document_root,
            &self.query_string,
            &self.path_info,
            &self.path_translated,
            &self.host,
            &self.remote_addr,
            self.remote_port,
            self.server_port,
            self.is_https,
            self.body.len(),
            &self.server_software,
            protocol,
            &self.headers,
            &self.extra_env,
        )
    }
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}

/// `cgi.fix_pathinfo` ve symlink kaçış saldırılarına karşı betik yolunun `doc_root` içinde
/// gerçek bir normal dosya olduğunu doğrular.
pub fn validate_script_within_root(
    doc_root: &Path,
    script_path: &Path,
    resolve_root_symlink: bool,
) -> Result<PathBuf, FastCgiError> {
    if doc_root.to_string_lossy().contains('\0') || script_path.to_string_lossy().contains('\0') {
        return Err(FastCgiError::SecurityViolation(
            "Yol icinde null byte tespit edildi".to_string(),
        ));
    }

    if !resolve_root_symlink {
        if let Ok(meta) = std::fs::symlink_metadata(doc_root) {
            if is_symlink_or_reparse(&meta) {
                return Err(FastCgiError::SecurityViolation(format!(
                    "Belge koku symlink olamaz: {}",
                    doc_root.display()
                )));
            }
        }
    }

    let canon_root = std::fs::canonicalize(doc_root)?;
    if !canon_root.is_dir() {
        return Err(FastCgiError::SecurityViolation(format!(
            "Belge koku gecerli bir dizin degil: {}",
            doc_root.display()
        )));
    }

    let effective_script = if script_path.is_relative() {
        doc_root.join(script_path)
    } else {
        script_path.to_path_buf()
    };

    match std::fs::canonicalize(&effective_script) {
        Ok(canon_script) => {
            if !canon_script.starts_with(&canon_root) || canon_script == canon_root {
                return Err(FastCgiError::SecurityViolation(format!(
                    "Betik yolu belge koku disina tasiyor: {}",
                    script_path.display()
                )));
            }
            let meta = std::fs::metadata(&canon_script)?;
            if !meta.is_file() {
                return Err(FastCgiError::SecurityViolation(format!(
                    "Betik yolu normal bir dosya degil: {}",
                    script_path.display()
                )));
            }
            Ok(canon_script)
        }
        Err(err) => {
            if let Ok(sym_meta) = std::fs::symlink_metadata(&effective_script) {
                if is_symlink_or_reparse(&sym_meta) {
                    return Err(FastCgiError::SecurityViolation(format!(
                        "Bozuk veya disari sarkan symlink reddedildi: {}",
                        script_path.display()
                    )));
                }
            }

            // cgi.fix_pathinfo koruması: ata bileşenlerden biri normal dosyaysa (ör. avatar.jpg/evil.php)
            let mut ancestor = effective_script.parent();
            while let Some(parent) = ancestor {
                if let Ok(meta) = std::fs::metadata(parent) {
                    if meta.is_file() {
                        return Err(FastCgiError::SecurityViolation(format!(
                            "cgi.fix_pathinfo ihlali: dosya icinden alt yol erisimi ({})",
                            script_path.display()
                        )));
                    }
                    break;
                }
                ancestor = parent.parent();
            }

            if !lexical_path_within(&effective_script, doc_root) {
                return Err(FastCgiError::SecurityViolation(format!(
                    "Path traversal girisimi reddedildi: {}",
                    script_path.display()
                )));
            }

            Err(FastCgiError::Io(err))
        }
    }
}

/// Diskte mevcut olmayan yollar için lexical `..` kaçış kontrolü yapar.
fn lexical_path_within(candidate: &Path, root: &Path) -> bool {
    fn normalize_components(path: &Path) -> Option<Vec<Component<'_>>> {
        let mut out = Vec::new();
        for comp in path.components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => match out.last() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(Component::RootDir | Component::Prefix(_)) => return None,
                    None | Some(Component::ParentDir) => return None,
                    Some(Component::CurDir) => {}
                },
                other => out.push(other),
            }
        }
        Some(out)
    }

    let Some(norm_root) = normalize_components(root) else {
        return false;
    };
    let Some(norm_cand) = normalize_components(candidate) else {
        return false;
    };
    norm_cand.len() >= norm_root.len() && norm_cand[..norm_root.len()] == norm_root[..]
}

/// `X-Accel-Redirect` ve `X-Sendfile` başlıklarını ayrıştırır; traversal veya harici şemayı reddeder.
fn extract_safe_redirect_header(headers: &[(String, String)], target_name: &str) -> Option<String> {
    let mut selected: Option<String> = None;
    for (k, v) in headers {
        if k.trim().eq_ignore_ascii_case(target_name) {
            let safe = sanitize_internal_redirect_path(v)?;
            selected = Some(safe);
        }
    }
    selected
}

fn sanitize_internal_redirect_path(raw: &str) -> Option<String> {
    if raw.contains('\0') || raw.chars().any(|c| c.is_control()) {
        return None;
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("://")
        || trimmed.starts_with("//")
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("ftp:")
        || lower.starts_with("file:")
        || lower.starts_with("data:")
        || lower.starts_with("javascript:")
    {
        return None;
    }

    if trimmed.contains("..") || lower.contains("%2e%2e") {
        return None;
    }

    Some(trimmed.to_string())
}

/// Standart CGI/1.1 ve PHP-FPM ortam değişkenlerini oluşturmak için yardımcı kurucu yapı.
#[derive(Debug, Clone)]
pub struct FastCgiParamsBuilder {
    pub method: String,
    pub request_uri: String,
    pub script_name: String,
    pub script_filename: String,
    pub document_root: String,
    pub query_string: String,
    /// İsteğe ait ek yol bilgisi (`PATH_INFO`).
    pub path_info: String,
    /// Çevrilmiş fiziksel yol bilgisi (`PATH_TRANSLATED`).
    pub path_translated: String,
    pub host: String,
    pub remote_addr: String,
    pub remote_port: u16,
    pub server_port: u16,
    pub is_https: bool,
    pub body_len: usize,
    pub server_software: String,
    pub server_protocol: String,
    pub headers: Vec<(String, String)>,
}

impl FastCgiParamsBuilder {
    /// Zorunlu istek ve dosya yolu bilgileriyle yeni bir parametre kurucu başlatır.
    pub fn new(
        method: impl Into<String>,
        request_uri: impl Into<String>,
        script_name: impl Into<String>,
        script_filename: impl Into<String>,
        document_root: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            request_uri: request_uri.into(),
            script_name: script_name.into(),
            script_filename: script_filename.into(),
            document_root: document_root.into(),
            query_string: String::new(),
            path_info: String::new(),
            path_translated: String::new(),
            host: String::new(),
            remote_addr: String::new(),
            remote_port: 0,
            server_port: 80,
            is_https: false,
            body_len: 0,
            server_software: DEFAULT_SERVER_SOFTWARE.to_string(),
            server_protocol: "HTTP/1.1".to_string(),
            headers: Vec::new(),
        }
    }

    /// Sorgu dizgesini (`QUERY_STRING`) ayarlar.
    pub fn query_string(mut self, query_string: impl Into<String>) -> Self {
        self.query_string = query_string.into();
        self
    }

    /// İsteğe ait ek yol bilgisini (`PATH_INFO`) ayarlar.
    pub fn path_info(mut self, val: impl Into<String>) -> Self {
        self.path_info = val.into();
        self
    }

    /// Çevrilmiş fiziksel yol bilgisini (`PATH_TRANSLATED`) ayarlar.
    pub fn path_translated(mut self, val: impl Into<String>) -> Self {
        self.path_translated = val.into();
        self
    }

    /// İstek `Host` değerini (`SERVER_NAME` ve varsayılan `HTTP_HOST`) ayarlar.
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    /// İstemci IP adresini (`REMOTE_ADDR`) ayarlar.
    pub fn remote_addr(mut self, remote_addr: impl Into<String>) -> Self {
        self.remote_addr = remote_addr.into();
        self
    }

    /// İstemci kaynak portunu (`REMOTE_PORT`) ayarlar.
    pub fn remote_port(mut self, remote_port: u16) -> Self {
        self.remote_port = remote_port;
        self
    }

    /// Sunucu portunu (`SERVER_PORT`) ayarlar.
    pub fn server_port(mut self, server_port: u16) -> Self {
        self.server_port = server_port;
        self
    }

    /// Bağlantının HTTPS/TLS üzerinden gelip gelmediğini (`HTTPS`, `REQUEST_SCHEME`) ayarlar.
    pub fn is_https(mut self, is_https: bool) -> Self {
        self.is_https = is_https;
        self
    }

    /// İstek gövde uzunluğunu (`CONTENT_LENGTH`) ayarlar.
    pub fn body_len(mut self, body_len: usize) -> Self {
        self.body_len = body_len;
        self
    }

    /// Sunucu yazılım bilgisini (`SERVER_SOFTWARE`) özelleştirir.
    pub fn server_software(mut self, server_software: impl Into<String>) -> Self {
        self.server_software = server_software.into();
        self
    }

    /// HTTP protokol sürümünü (`SERVER_PROTOCOL`) özelleştirir.
    pub fn server_protocol(mut self, server_protocol: impl Into<String>) -> Self {
        self.server_protocol = server_protocol.into();
        self
    }

    /// Tüm HTTP başlık listesini ayarlar.
    pub fn headers(mut self, headers: &[(String, String)]) -> Self {
        self.headers = headers.to_vec();
        self
    }

    /// Tek bir HTTP başlık çifti ekler.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Tanımlanan tüm alanlardan CGI/1.1 uyumlu FastCGI parametre haritasını üretir.
    pub fn build(&self) -> HashMap<String, String> {
        build_cgi_params_internal(
            &self.method,
            &self.request_uri,
            &self.script_name,
            &self.script_filename,
            &self.document_root,
            &self.query_string,
            &self.path_info,
            &self.path_translated,
            &self.host,
            &self.remote_addr,
            self.remote_port,
            self.server_port,
            self.is_https,
            self.body_len,
            &self.server_software,
            &self.server_protocol,
            &self.headers,
            &[],
        )
    }
}

/// HTTP isteği ve sunucu bağlamından eksiksiz CGI/1.1 + PHP FastCGI parametre haritası üretir.
#[allow(clippy::too_many_arguments)]
pub fn build_cgi_params(
    method: &str,
    request_uri: &str,
    script_name: &str,
    script_filename: &str,
    document_root: &str,
    query_string: &str,
    host: &str,
    remote_addr: &str,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    body_len: usize,
    headers: &[(String, String)],
) -> HashMap<String, String> {
    build_cgi_params_internal(
        method,
        request_uri,
        script_name,
        script_filename,
        document_root,
        query_string,
        "",
        "",
        host,
        remote_addr,
        remote_port,
        server_port,
        is_https,
        body_len,
        DEFAULT_SERVER_SOFTWARE,
        "HTTP/1.1",
        headers,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
fn build_cgi_params_internal(
    method: &str,
    request_uri: &str,
    script_name: &str,
    script_filename: &str,
    document_root: &str,
    query_string: &str,
    path_info: &str,
    path_translated: &str,
    host: &str,
    remote_addr: &str,
    remote_port: u16,
    server_port: u16,
    is_https: bool,
    body_len: usize,
    server_software: &str,
    server_protocol: &str,
    headers: &[(String, String)],
    extra_env: &[(String, String)],
) -> HashMap<String, String> {
    let mut params = HashMap::with_capacity(26 + headers.len() + extra_env.len());

    params.insert("SCRIPT_FILENAME".to_string(), script_filename.to_string());
    params.insert("DOCUMENT_ROOT".to_string(), document_root.to_string());
    params.insert("SCRIPT_NAME".to_string(), script_name.to_string());
    if !path_info.trim().is_empty() {
        params.insert("PATH_INFO".to_string(), path_info.to_string());
        params.insert("PHP_SELF".to_string(), format!("{script_name}{path_info}"));
        if !path_translated.trim().is_empty() {
            params.insert("PATH_TRANSLATED".to_string(), path_translated.to_string());
        }
    } else {
        params.insert("PHP_SELF".to_string(), script_name.to_string());
    }
    params.insert("REQUEST_METHOD".to_string(), method.to_string());
    params.insert("REQUEST_URI".to_string(), request_uri.to_string());
    params.insert("QUERY_STRING".to_string(), query_string.to_string());
    params.insert("GATEWAY_INTERFACE".to_string(), "CGI/1.1".to_string());
    params.insert("SERVER_PROTOCOL".to_string(), server_protocol.to_string());
    params.insert("REDIRECT_STATUS".to_string(), "200".to_string());
    params.insert("SERVER_SOFTWARE".to_string(), server_software.to_string());
    params.insert("SERVER_PORT".to_string(), server_port.to_string());
    params.insert("REMOTE_ADDR".to_string(), remote_addr.to_string());
    params.insert("REMOTE_PORT".to_string(), remote_port.to_string());
    params.insert("CONTENT_LENGTH".to_string(), body_len.to_string());

    if is_https {
        params.insert("HTTPS".to_string(), "on".to_string());
        params.insert("REQUEST_SCHEME".to_string(), "https".to_string());
    } else {
        params.insert("REQUEST_SCHEME".to_string(), "http".to_string());
    }

    let mut header_host: Option<&str> = None;

    for (raw_name, raw_val) in headers {
        let name = raw_name.trim();
        if name.is_empty() || name.eq_ignore_ascii_case("proxy") {
            continue;
        }
        let val = raw_val.trim();

        // CGI standardına göre Content-Type ve Content-Length HTTP_ öneki almaz.
        if name.eq_ignore_ascii_case("content-type") {
            params.insert("CONTENT_TYPE".to_string(), val.to_string());
            continue;
        }
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if name.eq_ignore_ascii_case("host") && header_host.is_none() {
            header_host = Some(val);
        }

        let Some(env_key) = header_name_to_cgi_env(name) else {
            continue;
        };
        let separator = if name.eq_ignore_ascii_case("cookie") {
            "; "
        } else {
            ", "
        };

        params
            .entry(env_key)
            .and_modify(|existing| {
                existing.push_str(separator);
                existing.push_str(val);
            })
            .or_insert_with(|| val.to_string());
    }

    let effective_host = if !host.trim().is_empty() {
        host.trim()
    } else {
        header_host.unwrap_or("")
    };

    if !effective_host.is_empty() {
        params
            .entry("HTTP_HOST".to_string())
            .or_insert_with(|| effective_host.to_string());
    }

    params.insert(
        "SERVER_NAME".to_string(),
        extract_server_name(effective_host).to_string(),
    );

    for (raw_key, raw_val) in extra_env {
        let key = raw_key.trim();
        if key.is_empty()
            || key.eq_ignore_ascii_case("HTTP_PROXY")
            || key.eq_ignore_ascii_case("PROXY")
        {
            continue;
        }
        params.insert(key.to_string(), raw_val.clone());
    }

    params
}

/// HTTP başlık adını CGI ortam değişkeni formatına (`HTTP_...`) çevirir.
/// HTTPoxy güvenlik açığını önlemek için `Proxy` başlığı `None` olarak düşürülür.
fn header_name_to_cgi_env(name: &str) -> Option<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("proxy") {
        return None;
    }

    let mut env = String::with_capacity(5 + trimmed.len());
    env.push_str("HTTP_");
    for b in trimmed.bytes() {
        if b == b'-' {
            env.push('_');
        } else {
            env.push((b as char).to_ascii_uppercase());
        }
    }
    if env == "HTTP_PROXY" {
        return None;
    }
    Some(env)
}

/// `Host` değerinden port kısmını ayırarak yalnızca sunucu adını döner (IPv4, alan adı ve IPv6 uyumlu).
fn extract_server_name(host: &str) -> &str {
    let trimmed = host.trim();
    if let Some(after_open) = trimmed.strip_prefix('[') {
        if let Some(end_bracket) = after_open.find(']') {
            return &trimmed[..=end_bracket + 1];
        }
        return trimmed;
    }
    trimmed.split(':').next().unwrap_or(trimmed)
}

/// FastCGI uzunluk kodlamasını (1 bayt veya 4 bayt MSB işaretli) yazar.
fn put_fcgi_len(buf: &mut BytesMut, len: usize) {
    if len > 127 {
        buf.put_u32((len as u32) | 0x8000_0000);
    } else {
        buf.put_u8(len as u8);
    }
}

/// CGI durum kodu için standart HTTP durum metnini döner.
fn default_reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

struct CoreAttemptError {
    error: FastCgiError,
    retryable_before_header: bool,
}

fn is_retryable_io_kind(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
    )
}

#[derive(Debug, Clone, Default)]
pub struct FastCgiClient {
    upstream: String,
    pool: Option<Arc<UpstreamSocketPool>>,
}

impl FastCgiClient {
    /// Belirtilen arka uç ve soket havuzu ile `FCGI_KEEP_CONN` destekli havuzlu istemci oluşturur.
    pub fn with_pool(upstream: &str, pool: Arc<UpstreamSocketPool>) -> Self {
        Self {
            upstream: upstream.trim().to_string(),
            pool: Some(pool),
        }
    }

    /// FastCGI Record Header (8 bayt) oluşturur
    pub fn build_header(
        type_: u8,
        request_id: u16,
        content_length: u16,
        padding_length: u8,
    ) -> [u8; 8] {
        [
            FCGI_VERSION_1,
            type_,
            (request_id >> 8) as u8,
            (request_id & 0xFF) as u8,
            (content_length >> 8) as u8,
            (content_length & 0xFF) as u8,
            padding_length,
            0, // reserved
        ]
    }

    /// FCGI_BEGIN_REQUEST kaydı oluşturur
    pub fn build_begin_request(request_id: u16, keep_conn: bool) -> BytesMut {
        let mut buf = BytesMut::with_capacity(16);
        let flags = if keep_conn { FCGI_KEEP_CONN } else { 0 };
        let header = Self::build_header(FCGI_BEGIN_REQUEST, request_id, 8, 0);

        buf.put_slice(&header);
        buf.put_u16(FCGI_RESPONDER);
        buf.put_u8(flags);
        buf.put_slice(&[0; 5]); // reserved

        buf
    }

    /// Veriyi 65535 baytlık FastCGI kayıtlarına bölerek yazar ve sonuna boş bitiş kaydı ekler.
    fn write_chunked_stream(buf: &mut BytesMut, record_type: u8, request_id: u16, data: &[u8]) {
        for chunk in data.chunks(FCGI_MAX_RECORD_LEN) {
            buf.put_slice(&Self::build_header(
                record_type,
                request_id,
                chunk.len() as u16,
                0,
            ));
            buf.put_slice(chunk);
        }
        buf.put_slice(&Self::build_header(record_type, request_id, 0, 0));
    }

    /// İkili FCGI_PARAMS anahtar-değer akışı oluşturur
    pub fn build_params(request_id: u16, params: &HashMap<&str, &str>) -> BytesMut {
        Self::build_params_map(request_id, params)
    }

    /// Sahip olunan veya ödünç alınan string haritasından 65535 bayt sınırını aşmayan FCGI_PARAMS kayıtları üretir.
    pub fn build_params_map<K, V>(request_id: u16, params: &HashMap<K, V>) -> BytesMut
    where
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        let mut content = BytesMut::new();

        for (key, val) in params {
            let k_bytes = key.as_ref().as_bytes();
            let v_bytes = val.as_ref().as_bytes();

            // Key Length & Value Length
            put_fcgi_len(&mut content, k_bytes.len());
            put_fcgi_len(&mut content, v_bytes.len());

            content.put_slice(k_bytes);
            content.put_slice(v_bytes);
        }

        let record_count = content.chunks(FCGI_MAX_RECORD_LEN).len() + 1;
        let mut buf = BytesMut::with_capacity(content.len() + record_count * 8);

        // Parametre verisini 65535 baytlık kayıtlara bölerek yaz ve sonuna boş kayıt ekle.
        Self::write_chunked_stream(&mut buf, FCGI_PARAMS, request_id, &content);

        buf
    }

    /// FCGI_STDIN gövde verisi ve bitiş kaydı oluşturur
    pub fn build_stdin(request_id: u16, body: &[u8]) -> BytesMut {
        let record_count = body.chunks(FCGI_MAX_RECORD_LEN).len() + 1;
        let mut buf = BytesMut::with_capacity(body.len() + record_count * 8);
        Self::write_chunked_stream(&mut buf, FCGI_STDIN, request_id, body);
        buf
    }

    /// Doğrudan `FastCgiClient` üzerinden standart CGI/1.1 parametre haritası üretir.
    #[allow(clippy::too_many_arguments)]
    pub fn build_cgi_params(
        method: &str,
        request_uri: &str,
        script_name: &str,
        script_filename: &str,
        document_root: &str,
        query_string: &str,
        host: &str,
        remote_addr: &str,
        remote_port: u16,
        server_port: u16,
        is_https: bool,
        body_len: usize,
        headers: &[(String, String)],
    ) -> HashMap<String, String> {
        build_cgi_params(
            method,
            request_uri,
            script_name,
            script_filename,
            document_root,
            query_string,
            host,
            remote_addr,
            remote_port,
            server_port,
            is_https,
            body_len,
            headers,
        )
    }

    /// PHP-FPM / LSPHP sunucusuna TCP veya Unix soketi üzerinden isteği gönderir
    pub async fn execute_php(
        upstream: &str,
        params: &HashMap<&str, &str>,
        stdin_body: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Self::execute_php_with_timeout(upstream, params, stdin_body, DEFAULT_FASTCGI_TIMEOUT_SECS)
            .await
    }

    /// PHP-FPM / LSPHP sunucusuna belirtilen zaman aşımıyla istek gönderir ve ham STDOUT çıktısını döner.
    pub async fn execute_php_with_timeout<K, V>(
        upstream: &str,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
        timeout_secs: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>
    where
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        let resp = Self::execute_php_detailed(upstream, params, stdin_body, timeout_secs).await?;
        Ok(resp.raw_stdout)
    }

    /// PHP-FPM / LSPHP sunucusuna saniye cinsinden zaman aşımıyla istek gönderir ve STDOUT ile STDERR çıktısını döner.
    pub async fn execute_php_detailed<K, V>(
        upstream: &str,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
        timeout_secs: u64,
    ) -> Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        Self::execute_php_detailed_duration(
            upstream,
            params,
            stdin_body,
            Duration::from_secs(timeout_secs),
        )
        .await
    }

    /// PHP-FPM / LSPHP sunucusuna `Duration` zaman aşımıyla istek gönderir ve `FastCgiResponse` döner.
    pub async fn execute_php_detailed_duration<K, V>(
        upstream: &str,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
        timeout_dur: Duration,
    ) -> Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        Self::run_with_timeout(
            timeout_dur,
            Self::execute_php_unbounded(upstream, params, stdin_body),
        )
        .await
    }

    async fn run_with_timeout<F>(
        timeout_dur: Duration,
        fut: F,
    ) -> Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        F: std::future::Future<Output = Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>>,
    {
        match tokio::time::timeout(timeout_dur, fut).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "FastCGI istegi zaman asimina ugradi ({} ms)",
                timeout_dur.as_millis()
            )
            .into()),
        }
    }

    async fn execute_php_unbounded<K, V>(
        upstream: &str,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
    ) -> Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        let trimmed = upstream.trim();
        if let Some(sock_path) = trimmed
            .strip_prefix("unix:")
            .or_else(|| if trimmed.starts_with('/') { Some(trimmed) } else { None })
        {
            #[cfg(unix)]
            {
                let stream = tokio::net::UnixStream::connect(sock_path).await?;
                return Self::execute_on_stream(stream, params, stdin_body).await;
            }
            #[cfg(not(unix))]
            {
                let _ = sock_path;
                return Err(
                    "Unix domain socket FastCGI yalnizca Unix/Linux sistemlerde desteklenir".into(),
                );
            }
        }

        let stream = tokio::net::TcpStream::connect(trimmed).await?;
        Self::execute_on_stream(stream, params, stdin_body).await
    }

    /// Önceden açılmış bir akış (`AsyncRead + AsyncWrite`) üzerinden zaman aşımıyla FastCGI isteği çalıştırır.
    pub async fn execute_on_stream_with_timeout<S, K, V>(
        stream: S,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
        timeout_dur: Duration,
    ) -> Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        Self::run_with_timeout(timeout_dur, Self::execute_on_stream(stream, params, stdin_body))
            .await
    }

    pub async fn execute_on_stream<S, K, V>(
        mut stream: S,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
    ) -> Result<FastCgiResponse, Box<dyn std::error::Error + Send + Sync>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        Self::execute_fcgi_core(&mut stream, params, stdin_body, false, false)
            .await
            .map_err(|e| Box::new(e.error) as Box<dyn std::error::Error + Send + Sync>)
    }

    /// Havuzlu ve `FCGI_KEEP_CONN = true` bayraklı FastCGI isteği yürütür.
    /// Havuzdan alınan bayat soket ilk yanıt başlığı gelmeden kapanırsa 1 kez taze bağlantıyla yeniden dener.
    pub async fn execute_php_pooled(
        &self,
        req: FastCgiRequest,
        dial_timeout: Duration,
        io_timeout: Duration,
    ) -> Result<FastCgiResponseDetailed, FastCgiError> {
        let params = req.build_params();
        let trimmed = self.upstream.trim();

        if let Some(sock_path) = trimmed
            .strip_prefix("unix:")
            .or_else(|| if trimmed.starts_with('/') { Some(trimmed) } else { None })
        {
            #[cfg(unix)]
            {
                let mut stream = tokio::time::timeout(
                    dial_timeout,
                    tokio::net::UnixStream::connect(sock_path),
                )
                .await
                .map_err(|_| {
                    FastCgiError::Timeout(format!(
                        "Unix socket baglanti zaman asimi ({} ms)",
                        dial_timeout.as_millis()
                    ))
                })??;
                let resp = Self::execute_pooled_on_stream(
                    &mut stream,
                    &params,
                    &req.body,
                    false,
                    io_timeout,
                )
                .await
                .map_err(|e| e.error)?;
                return Ok(FastCgiResponseDetailed::from_raw(
                    resp.raw_stdout,
                    resp.stderr,
                ));
            }
            #[cfg(not(unix))]
            {
                let _ = sock_path;
                return Err(FastCgiError::Protocol(
                    "Unix domain socket FastCGI yalnizca Unix/Linux sistemlerde desteklenir"
                        .to_string(),
                ));
            }
        }

        let (mut stream, from_pool) = match &self.pool {
            Some(pool) => pool
                .acquire_tagged_with_timeout(trimmed, dial_timeout)
                .await
                .map_err(FastCgiError::from)?,
            None => {
                let s = tokio::time::timeout(dial_timeout, tokio::net::TcpStream::connect(trimmed))
                    .await
                    .map_err(|_| {
                        FastCgiError::Timeout(format!(
                            "Arka uc baglanti zaman asimi ({} ms)",
                            dial_timeout.as_millis()
                        ))
                    })??;
                let _ = s.set_nodelay(true);
                (s, false)
            }
        };

        match Self::execute_pooled_on_stream(&mut stream, &params, &req.body, true, io_timeout)
            .await
        {
            Ok(resp) => {
                if let Some(pool) = &self.pool {
                    pool.release(trimmed, stream);
                }
                Ok(FastCgiResponseDetailed::from_raw(
                    resp.raw_stdout,
                    resp.stderr,
                ))
            }
            Err(first_err) => {
                if let Some(pool) = &self.pool {
                    pool.discard(stream);
                } else {
                    drop(stream);
                }

                if from_pool && first_err.retryable_before_header {
                    let mut fresh_stream = match &self.pool {
                        Some(pool) => pool
                            .dial_fresh_with_timeout(trimmed, dial_timeout)
                            .await
                            .map_err(FastCgiError::from)?,
                        None => {
                            let s = tokio::time::timeout(
                                dial_timeout,
                                tokio::net::TcpStream::connect(trimmed),
                            )
                            .await
                            .map_err(|_| {
                                FastCgiError::Timeout(format!(
                                    "Arka uc baglanti zaman asimi ({} ms)",
                                    dial_timeout.as_millis()
                                ))
                            })??;
                            let _ = s.set_nodelay(true);
                            s
                        }
                    };

                    match Self::execute_pooled_on_stream(
                        &mut fresh_stream,
                        &params,
                        &req.body,
                        true,
                        io_timeout,
                    )
                    .await
                    {
                        Ok(resp) => {
                            if let Some(pool) = &self.pool {
                                pool.release(trimmed, fresh_stream);
                            }
                            Ok(FastCgiResponseDetailed::from_raw(
                                resp.raw_stdout,
                                resp.stderr,
                            ))
                        }
                        Err(retry_err) => {
                            if let Some(pool) = &self.pool {
                                pool.discard(fresh_stream);
                            } else {
                                drop(fresh_stream);
                            }
                            Err(retry_err.error)
                        }
                    }
                } else {
                    Err(first_err.error)
                }
            }
        }
    }

    async fn execute_pooled_on_stream<S, K, V>(
        stream: &mut S,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
        keep_conn: bool,
        io_timeout: Duration,
    ) -> Result<FastCgiResponse, CoreAttemptError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        match tokio::time::timeout(
            io_timeout,
            Self::execute_fcgi_core(stream, params, stdin_body, keep_conn, true),
        )
        .await
        {
            Ok(res) => res,
            Err(_) => Err(CoreAttemptError {
                retryable_before_header: false,
                error: FastCgiError::Timeout(format!(
                    "FastCGI istegi zaman asimina ugradi ({} ms)",
                    io_timeout.as_millis()
                )),
            }),
        }
    }

    async fn execute_fcgi_core<S, K, V>(
        stream: &mut S,
        params: &HashMap<K, V>,
        stdin_body: &[u8],
        keep_conn: bool,
        require_end_request: bool,
    ) -> Result<FastCgiResponse, CoreAttemptError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        K: AsRef<str> + Eq + Hash,
        V: AsRef<str>,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let request_id = 1u16;

        let map_write_err = |e: std::io::Error| CoreAttemptError {
            retryable_before_header: is_retryable_io_kind(e.kind()),
            error: FastCgiError::from(e),
        };

        // 1. Begin Request
        let begin = Self::build_begin_request(request_id, keep_conn);
        stream.write_all(&begin).await.map_err(map_write_err)?;

        // 2. Params
        let params_data = Self::build_params_map(request_id, params);
        stream.write_all(&params_data).await.map_err(map_write_err)?;

        // 3. Stdin
        let stdin_data = Self::build_stdin(request_id, stdin_body);
        stream.write_all(&stdin_data).await.map_err(map_write_err)?;
        stream.flush().await.map_err(map_write_err)?;

        // 4. Yanıtı Oku (STDOUT, STDERR ve END_REQUEST)
        let mut raw_stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut header_buf = [0u8; 8];
        let mut received_any_record = false;
        let mut end_request_received = false;

        loop {
            match stream.read_exact(&mut header_buf).await {
                Ok(_) => {
                    received_any_record = true;
                }
                Err(e) if !received_any_record && is_retryable_io_kind(e.kind()) => {
                    return Err(CoreAttemptError {
                        retryable_before_header: true,
                        error: FastCgiError::Protocol(
                            "FastCGI sunucusu yanit gondermeden baglantiyi kapatti".to_string(),
                        ),
                    });
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                    if !require_end_request && (!raw_stdout.is_empty() || !stderr.is_empty()) {
                        break;
                    }
                    return Err(CoreAttemptError {
                        retryable_before_header: false,
                        error: FastCgiError::Protocol(if raw_stdout.is_empty() && stderr.is_empty() {
                            "FastCGI sunucusu yanit gondermeden baglantiyi kapatti".to_string()
                        } else {
                            "FastCGI yaniti FCGI_END_REQUEST gelmeden yarim kaldi".to_string()
                        }),
                    });
                }
                Err(e) => {
                    return Err(CoreAttemptError {
                        retryable_before_header: false,
                        error: FastCgiError::from(e),
                    });
                }
            }

            let type_ = header_buf[1];
            let content_len = ((header_buf[4] as usize) << 8) | (header_buf[5] as usize);
            let padding_len = header_buf[6] as usize;

            if content_len > 0 {
                let mut content = vec![0u8; content_len];
                stream
                    .read_exact(&mut content)
                    .await
                    .map_err(|e| CoreAttemptError {
                        retryable_before_header: false,
                        error: FastCgiError::from(e),
                    })?;
                match type_ {
                    FCGI_STDOUT => raw_stdout.extend_from_slice(&content),
                    FCGI_STDERR => stderr.extend_from_slice(&content),
                    FCGI_END_REQUEST
                        if require_end_request && content.len() >= 5 && content[4] != 0 =>
                    {
                        return Err(CoreAttemptError {
                            retryable_before_header: false,
                            error: FastCgiError::Protocol(format!(
                                "FastCGI protocolStatus hatasi: {}",
                                content[4]
                            )),
                        });
                    }
                    _ => {}
                }
            }

            if padding_len > 0 {
                let mut padding = vec![0u8; padding_len];
                stream
                    .read_exact(&mut padding)
                    .await
                    .map_err(|e| CoreAttemptError {
                        retryable_before_header: false,
                        error: FastCgiError::from(e),
                    })?;
            }

            if type_ == FCGI_END_REQUEST {
                end_request_received = true;
                break;
            }
        }

        if require_end_request && !end_request_received {
            return Err(CoreAttemptError {
                retryable_before_header: false,
                error: FastCgiError::Protocol(
                    "FastCGI yaniti FCGI_END_REQUEST olmadan sonlandi".to_string(),
                ),
            });
        }

        Ok(FastCgiResponse { raw_stdout, stderr })
    }

    /// FastCGI STDOUT yanıtındaki CGI başlıklarını (`Status:`, `Content-Type:`) gövdeden ayırır.
    pub fn split_cgi_headers(raw: &[u8]) -> (u16, Vec<(String, String)>, &[u8]) {
        let (status, _reason, headers, body) = Self::split_cgi_headers_with_reason(raw);
        (status, headers, body)
    }

    /// FastCGI STDOUT yanıtındaki CGI başlıklarını ayırır; `Status` koduna ek olarak durum metnini (reason phrase) de döner.
    pub fn split_cgi_headers_with_reason(
        raw: &[u8],
    ) -> (u16, String, Vec<(String, String)>, &[u8]) {
        let crlf_pos = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| (i, 4));
        let lf_pos = raw.windows(2).position(|w| w == b"\n\n").map(|i| (i, 2));
        let sep = match (crlf_pos, lf_pos) {
            (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        let Some((idx, sep_len)) = sep else {
            return (
                200,
                "OK".to_string(),
                vec![(
                    "Content-Type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                )],
                raw,
            );
        };

        let header_str = String::from_utf8_lossy(&raw[..idx]);
        let mut status = 200u16;
        let mut reason = "OK".to_string();
        let mut headers = Vec::new();
        let mut has_ct = false;

        for line in header_str.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.trim();
                let val = v.trim();
                if key.eq_ignore_ascii_case("status") {
                    let (code_str, reason_str) = match val.split_once(char::is_whitespace) {
                        Some((c, r)) => (c.trim(), r.trim()),
                        None => (val, ""),
                    };
                    if let Ok(code) = code_str.parse::<u16>() {
                        status = code;
                        reason = if reason_str.is_empty() {
                            default_reason_phrase(code).to_string()
                        } else {
                            reason_str.to_string()
                        };
                    }
                } else {
                    if key.eq_ignore_ascii_case("content-type") {
                        has_ct = true;
                    }
                    headers.push((key.to_string(), val.to_string()));
                }
            }
        }

        if !has_ct {
            headers.push((
                "Content-Type".to_string(),
                "text/html; charset=utf-8".to_string(),
            ));
        }

        (status, reason, headers, &raw[idx + sep_len..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Ham FastCGI bayt dizisini (record_type, request_id, content, padding_len) kayıtlarına ayrıştırır.
    fn parse_fcgi_records(mut data: &[u8]) -> Vec<(u8, u16, Vec<u8>, u8)> {
        let mut records = Vec::new();
        while !data.is_empty() {
            assert!(data.len() >= 8, "Eksik FastCGI kayit basligi");
            assert_eq!(data[0], FCGI_VERSION_1);
            let record_type = data[1];
            let request_id = u16::from_be_bytes([data[2], data[3]]);
            let content_len = u16::from_be_bytes([data[4], data[5]]) as usize;
            let padding_len = data[6];
            data = &data[8..];

            assert!(
                data.len() >= content_len + padding_len as usize,
                "Eksik FastCGI kayit govdesi"
            );
            let content = data[..content_len].to_vec();
            data = &data[content_len + padding_len as usize..];
            records.push((record_type, request_id, content, padding_len));
        }
        records
    }

    /// Birleştirilmiş FCGI_PARAMS akışından anahtar-değer çiftlerini çözer.
    fn decode_fcgi_nv_pairs(mut stream: &[u8]) -> HashMap<String, String> {
        fn read_len(buf: &mut &[u8]) -> usize {
            assert!(!buf.is_empty());
            if buf[0] & 0x80 != 0 {
                assert!(buf.len() >= 4);
                let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) & 0x7FFF_FFFF;
                *buf = &buf[4..];
                raw as usize
            } else {
                let len = buf[0] as usize;
                *buf = &buf[1..];
                len
            }
        }

        let mut map = HashMap::new();
        while !stream.is_empty() {
            let k_len = read_len(&mut stream);
            let v_len = read_len(&mut stream);
            assert!(stream.len() >= k_len + v_len);
            let key = String::from_utf8(stream[..k_len].to_vec()).unwrap();
            let val = String::from_utf8(stream[k_len..k_len + v_len].to_vec()).unwrap();
            stream = &stream[k_len + v_len..];
            map.insert(key, val);
        }
        map
    }

    #[test]
    fn build_stdin_splits_150kb_body_and_appends_empty_terminator() {
        let body_len = 150 * 1024; // 153_600 bayt (> 65535)
        let body: Vec<u8> = (0..body_len).map(|i| (i % 251) as u8).collect();

        let encoded = FastCgiClient::build_stdin(7, &body);
        let records = parse_fcgi_records(&encoded);

        // 153600 = 65535 + 65535 + 22530 -> 3 veri kaydı + 1 boş bitiş kaydı = 4 kayıt
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].0, FCGI_STDIN);
        assert_eq!(records[0].1, 7);
        assert_eq!(records[0].2.len(), FCGI_MAX_RECORD_LEN);

        assert_eq!(records[1].0, FCGI_STDIN);
        assert_eq!(records[1].2.len(), FCGI_MAX_RECORD_LEN);

        assert_eq!(records[2].0, FCGI_STDIN);
        assert_eq!(records[2].2.len(), body_len - 2 * FCGI_MAX_RECORD_LEN);

        // Son kayıt mutlaka boş bitiş kaydı olmalı
        let last = records.last().unwrap();
        assert_eq!(last.0, FCGI_STDIN);
        assert_eq!(last.1, 7);
        assert!(last.2.is_empty());

        // Parçalar birleştirildiğinde orijinal gövdeyle birebir eşleşmeli
        let mut reassembled = Vec::new();
        for (_, _, chunk, _) in records {
            reassembled.extend_from_slice(&chunk);
        }
        assert_eq!(reassembled, body);
    }

    #[test]
    fn build_stdin_empty_body_writes_only_terminator() {
        let encoded = FastCgiClient::build_stdin(1, &[]);
        let records = parse_fcgi_records(&encoded);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, FCGI_STDIN);
        assert!(records[0].2.is_empty());
    }

    #[test]
    fn build_params_splits_70kb_payload_into_multiple_records() {
        let big_cookie = "c=".to_string() + &"x".repeat(70 * 1024);
        let mut params = HashMap::new();
        params.insert("REQUEST_METHOD", "POST");
        params.insert("SCRIPT_NAME", "/upload.php");
        params.insert("HTTP_COOKIE", big_cookie.as_str());

        let encoded = FastCgiClient::build_params(3, &params);
        let records = parse_fcgi_records(&encoded);

        assert!(
            records.len() >= 3,
            "70 KB parametre en az 2 veri + 1 bitis kaydi uretmeli"
        );
        for (idx, (rtype, rid, content, _)) in records.iter().enumerate() {
            assert_eq!(*rtype, FCGI_PARAMS);
            assert_eq!(*rid, 3);
            assert!(content.len() <= FCGI_MAX_RECORD_LEN);
            if idx + 1 < records.len() {
                assert!(!content.is_empty());
            } else {
                assert!(content.is_empty(), "Son FCGI_PARAMS kaydi bos olmali");
            }
        }

        let mut stream = Vec::new();
        for (_, _, content, _) in records {
            stream.extend_from_slice(&content);
        }
        let decoded = decode_fcgi_nv_pairs(&stream);
        assert_eq!(decoded.get("REQUEST_METHOD").map(String::as_str), Some("POST"));
        assert_eq!(decoded.get("SCRIPT_NAME").map(String::as_str), Some("/upload.php"));
        assert_eq!(decoded.get("HTTP_COOKIE"), Some(&big_cookie));
    }

    #[test]
    fn build_cgi_params_maps_headers_and_https_correctly() {
        let headers = vec![
            ("Cookie".to_string(), "sid=abc".to_string()),
            ("cookie".to_string(), "theme=dark".to_string()),
            (
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            ("Content-Length".to_string(), "999".to_string()),
            ("X-Custom-Header".to_string(), "val-1".to_string()),
            ("x-custom-header".to_string(), "val-2".to_string()),
            ("Authorization".to_string(), "Bearer secret".to_string()),
        ];

        let https_params = build_cgi_params(
            "POST",
            "/api/test.php?foo=bar",
            "/api/test.php",
            "/var/www/site/api/test.php",
            "/var/www/site",
            "foo=bar",
            "example.com:8443",
            "203.0.113.10",
            54321,
            443,
            true,
            42,
            &headers,
        );

        assert_eq!(https_params.get("SCRIPT_FILENAME").map(String::as_str), Some("/var/www/site/api/test.php"));
        assert_eq!(https_params.get("DOCUMENT_ROOT").map(String::as_str), Some("/var/www/site"));
        assert_eq!(https_params.get("SCRIPT_NAME").map(String::as_str), Some("/api/test.php"));
        assert_eq!(https_params.get("PHP_SELF").map(String::as_str), Some("/api/test.php"));
        assert_eq!(https_params.get("REQUEST_METHOD").map(String::as_str), Some("POST"));
        assert_eq!(https_params.get("REQUEST_URI").map(String::as_str), Some("/api/test.php?foo=bar"));
        assert_eq!(https_params.get("QUERY_STRING").map(String::as_str), Some("foo=bar"));
        assert_eq!(https_params.get("GATEWAY_INTERFACE").map(String::as_str), Some("CGI/1.1"));
        assert_eq!(https_params.get("SERVER_PROTOCOL").map(String::as_str), Some("HTTP/1.1"));
        assert_eq!(https_params.get("REDIRECT_STATUS").map(String::as_str), Some("200"));
        assert_eq!(https_params.get("SERVER_NAME").map(String::as_str), Some("example.com"));
        assert_eq!(https_params.get("HTTP_HOST").map(String::as_str), Some("example.com:8443"));
        assert_eq!(https_params.get("SERVER_PORT").map(String::as_str), Some("443"));
        assert_eq!(https_params.get("REMOTE_ADDR").map(String::as_str), Some("203.0.113.10"));
        assert_eq!(https_params.get("REMOTE_PORT").map(String::as_str), Some("54321"));
        assert_eq!(https_params.get("CONTENT_LENGTH").map(String::as_str), Some("42"));
        assert_eq!(
            https_params.get("CONTENT_TYPE").map(String::as_str),
            Some("application/json; charset=utf-8")
        );
        assert!(!https_params.contains_key("HTTP_CONTENT_TYPE"));
        assert!(!https_params.contains_key("HTTP_CONTENT_LENGTH"));
        assert_eq!(
            https_params.get("HTTP_COOKIE").map(String::as_str),
            Some("sid=abc; theme=dark")
        );
        assert_eq!(
            https_params.get("HTTP_X_CUSTOM_HEADER").map(String::as_str),
            Some("val-1, val-2")
        );
        assert_eq!(
            https_params.get("HTTP_AUTHORIZATION").map(String::as_str),
            Some("Bearer secret")
        );
        assert_eq!(https_params.get("HTTPS").map(String::as_str), Some("on"));
        assert_eq!(https_params.get("REQUEST_SCHEME").map(String::as_str), Some("https"));

        // is_https = false durumunda HTTPS anahtarı bulunmamalı, REQUEST_SCHEME = http olmalı
        let http_params = FastCgiParamsBuilder::new(
            "GET",
            "/index.php",
            "/index.php",
            "/var/www/site/index.php",
            "/var/www/site",
        )
        .host("[2001:db8::1]:8080")
        .server_port(8080)
        .is_https(false)
        .build();

        assert!(!http_params.contains_key("HTTPS"));
        assert_eq!(http_params.get("REQUEST_SCHEME").map(String::as_str), Some("http"));
        assert_eq!(http_params.get("SERVER_NAME").map(String::as_str), Some("[2001:db8::1]"));
    }

    #[test]
    fn split_cgi_headers_preserves_multiple_set_cookies_and_status_reason() {
        let raw = b"Status: 302 Found\r\nLocation: /login\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; HttpOnly\r\nContent-Type: text/plain\r\n\r\nYonlendiriliyor";

        let (status, reason, headers, body) = FastCgiClient::split_cgi_headers_with_reason(raw);
        assert_eq!(status, 302);
        assert_eq!(reason, "Found");
        assert_eq!(body, b"Yonlendiriliyor");

        let cookies: Vec<&str> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(cookies, vec!["a=1; Path=/", "b=2; HttpOnly"]);

        // Geriye dönük uyumlu split_cgi_headers da aynı değerleri dönmeli
        let (compat_status, compat_headers, compat_body) = FastCgiClient::split_cgi_headers(raw);
        assert_eq!(compat_status, 302);
        assert_eq!(compat_headers, headers);
        assert_eq!(compat_body, body);
    }

    #[test]
    fn split_cgi_headers_picks_earliest_lf_or_crlf_separator() {
        let raw = b"Status: 404\nX-Test: 1\n\n<html>\r\n\r\nbody</html>";
        let (status, reason, headers, body) = FastCgiClient::split_cgi_headers_with_reason(raw);
        assert_eq!(status, 404);
        assert_eq!(reason, "Not Found");
        assert_eq!(body, b"<html>\r\n\r\nbody</html>");
        assert!(headers.iter().any(|(k, v)| k == "X-Test" && v == "1"));
    }

    #[tokio::test]
    async fn execute_on_stream_reads_stdout_stderr_and_stops_on_end_request() {
        let (client_stream, mut server_stream) = tokio::io::duplex(64 * 1024);

        let server = tokio::spawn(async move {
            let mut req_buf = Vec::new();
            let mut tmp = [0u8; 4096];
            // Boş FCGI_STDIN bitiş kaydı gelene kadar oku
            loop {
                let n = server_stream.read(&mut tmp).await.unwrap();
                assert!(n > 0);
                req_buf.extend_from_slice(&tmp[..n]);
                if req_buf.ends_with(&FastCgiClient::build_header(FCGI_STDIN, 1, 0, 0)) {
                    break;
                }
            }

            let req_records = parse_fcgi_records(&req_buf);
            assert_eq!(req_records[0].0, FCGI_BEGIN_REQUEST);
            assert!(req_records.iter().any(|r| r.0 == FCGI_PARAMS && !r.2.is_empty()));

            let mut out = BytesMut::new();
            let stdout_payload = b"Content-Type: text/plain\r\n\r\nMerhaba";
            out.put_slice(&FastCgiClient::build_header(
                FCGI_STDOUT,
                1,
                stdout_payload.len() as u16,
                0,
            ));
            out.put_slice(stdout_payload);

            let stderr_payload = b"PHP Warning: test uyarisi";
            out.put_slice(&FastCgiClient::build_header(
                FCGI_STDERR,
                1,
                stderr_payload.len() as u16,
                0,
            ));
            out.put_slice(stderr_payload);

            out.put_slice(&FastCgiClient::build_header(FCGI_STDOUT, 1, 0, 0));
            out.put_slice(&FastCgiClient::build_header(FCGI_END_REQUEST, 1, 8, 0));
            out.put_slice(&[0u8; 8]);
            // FCGI_END_REQUEST sonrası gelen veri kesinlikle okunmamalı
            out.put_slice(&FastCgiClient::build_header(FCGI_STDOUT, 1, 5, 0));
            out.put_slice(b"EXTRA");

            server_stream.write_all(&out).await.unwrap();
            server_stream.flush().await.unwrap();
        });

        let params = FastCgiParamsBuilder::new(
            "GET",
            "/index.php",
            "/index.php",
            "/var/www/index.php",
            "/var/www",
        )
        .build();

        let resp = FastCgiClient::execute_on_stream_with_timeout(
            client_stream,
            &params,
            b"",
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(resp.raw_stdout, b"Content-Type: text/plain\r\n\r\nMerhaba");
        assert_eq!(resp.stderr, b"PHP Warning: test uyarisi");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn execute_on_stream_with_timeout_aborts_stalled_upstream() {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);

        let _server = tokio::spawn(async move {
            let mut tmp = [0u8; 1024];
            let _ = server_stream.read(&mut tmp).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let params: HashMap<&str, &str> = HashMap::new();
        let err = FastCgiClient::execute_on_stream_with_timeout(
            client_stream,
            &params,
            b"",
            Duration::from_millis(80),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("zaman asimina ugradi"));
    }

    #[test]
    fn builder_sets_path_info_path_translated_and_php_self() {
        let params = FastCgiParamsBuilder::new(
            "GET",
            "/index.php/urun/42?detay=1",
            "/index.php",
            "/var/www/index.php",
            "/var/www",
        )
        .query_string("detay=1")
        .path_info("/urun/42")
        .path_translated("/var/www/urun/42")
        .build();

        assert_eq!(params.get("SCRIPT_NAME").map(String::as_str), Some("/index.php"));
        assert_eq!(params.get("PATH_INFO").map(String::as_str), Some("/urun/42"));
        assert_eq!(
            params.get("PATH_TRANSLATED").map(String::as_str),
            Some("/var/www/urun/42")
        );
        assert_eq!(
            params.get("PHP_SELF").map(String::as_str),
            Some("/index.php/urun/42")
        );
    }

    #[test]
    fn builder_omits_empty_path_info_and_path_translated() {
        let params_empty = FastCgiParamsBuilder::new(
            "GET",
            "/index.php",
            "/index.php",
            "/var/www/index.php",
            "/var/www",
        )
        .path_info("   ")
        .path_translated("/var/www/ihmal")
        .build();

        assert_eq!(
            params_empty.get("PHP_SELF").map(String::as_str),
            Some("/index.php")
        );
        assert!(!params_empty.contains_key("PATH_INFO"));
        assert!(!params_empty.contains_key("PATH_TRANSLATED"));

        let params_without_translated = FastCgiParamsBuilder::new(
            "GET",
            "/index.php/urun/42",
            "/index.php",
            "/var/www/index.php",
            "/var/www",
        )
        .path_info("/urun/42")
        .build();

        assert_eq!(
            params_without_translated.get("PATH_INFO").map(String::as_str),
            Some("/urun/42")
        );
        assert_eq!(
            params_without_translated.get("PHP_SELF").map(String::as_str),
            Some("/index.php/urun/42")
        );
        assert!(!params_without_translated.contains_key("PATH_TRANSLATED"));
    }

    /// Tek bir FastCGI isteğinin tüm kayıtlarını (`FCGI_STDIN` boş bitiş kaydına kadar) okur.
    async fn read_single_fcgi_request(
        stream: &mut tokio::net::TcpStream,
    ) -> std::io::Result<Vec<(u8, u16, Vec<u8>, u8)>> {
        let mut records = Vec::new();
        let mut header = [0u8; 8];
        loop {
            stream.read_exact(&mut header).await?;
            let rtype = header[1];
            let rid = u16::from_be_bytes([header[2], header[3]]);
            let content_len = u16::from_be_bytes([header[4], header[5]]) as usize;
            let padding_len = header[6];
            let mut content = vec![0u8; content_len];
            if content_len > 0 {
                stream.read_exact(&mut content).await?;
            }
            if padding_len > 0 {
                let mut pad = vec![0u8; padding_len as usize];
                stream.read_exact(&mut pad).await?;
            }
            let is_stdin_end = rtype == FCGI_STDIN && content_len == 0;
            records.push((rtype, rid, content, padding_len));
            if is_stdin_end {
                break;
            }
        }
        Ok(records)
    }

    fn build_fcgi_response_bytes(request_id: u16, stdout: &[u8], stderr: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        if !stdout.is_empty() {
            out.put_slice(&FastCgiClient::build_header(
                FCGI_STDOUT,
                request_id,
                stdout.len() as u16,
                0,
            ));
            out.put_slice(stdout);
        }
        if !stderr.is_empty() {
            out.put_slice(&FastCgiClient::build_header(
                FCGI_STDERR,
                request_id,
                stderr.len() as u16,
                0,
            ));
            out.put_slice(stderr);
        }
        out.put_slice(&FastCgiClient::build_header(FCGI_STDOUT, request_id, 0, 0));
        out.put_slice(&FastCgiClient::build_header(
            FCGI_END_REQUEST,
            request_id,
            8,
            0,
        ));
        out.put_slice(&[0u8; 8]);
        out.to_vec()
    }

    #[test]
    fn httpoxy_proxy_header_is_strictly_blocked() {
        assert_eq!(header_name_to_cgi_env("Proxy"), None);
        assert_eq!(header_name_to_cgi_env("proxy"), None);
        assert_eq!(header_name_to_cgi_env("  PROXY  "), None);
        assert_eq!(
            header_name_to_cgi_env("X-Proxy").as_deref(),
            Some("HTTP_X_PROXY")
        );

        let headers = vec![
            ("Proxy".to_string(), "http://attacker.invalid:8888".to_string()),
            ("proxy".to_string(), "http://evil2.invalid".to_string()),
            ("PROXY".to_string(), "http://evil3.invalid".to_string()),
            ("X-Forwarded-For".to_string(), "10.0.0.1".to_string()),
        ];

        let params = FastCgiParamsBuilder::new(
            "GET",
            "/index.php",
            "/index.php",
            "/var/www/index.php",
            "/var/www",
        )
        .headers(&headers)
        .build();

        assert!(!params.contains_key("HTTP_PROXY"));
        assert_eq!(
            params.get("HTTP_X_FORWARDED_FOR").map(String::as_str),
            Some("10.0.0.1")
        );

        let req_params = FastCgiRequest::new(
            "GET",
            "/index.php",
            "/index.php",
            "/var/www/index.php",
            "/var/www",
        )
        .header("Proxy", "http://attacker.invalid")
        .env("HTTP_PROXY", "http://override.invalid")
        .env("http_proxy", "http://override2.invalid")
        .build_params();

        assert!(!req_params.contains_key("HTTP_PROXY"));
        assert!(!req_params.contains_key("http_proxy"));
    }

    #[tokio::test]
    async fn pooled_client_sends_keep_conn_and_reuses_tcp_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let keep_conn_flags = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let accept_srv = accept_count.clone();
        let flags_srv = keep_conn_flags.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let srv = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            accept_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            for idx in 1..=2 {
                let recs = read_single_fcgi_request(&mut stream).await.unwrap();
                assert_eq!(recs[0].0, FCGI_BEGIN_REQUEST);
                // FCGI_BEGIN_REQUEST gövdesi: [role_hi, role_lo, flags, reserved...]
                flags_srv.lock().unwrap().push(recs[0].2[2]);
                let payload = format!("Content-Type: text/plain\r\n\r\nyanit-{idx}");
                let resp = build_fcgi_response_bytes(1, payload.as_bytes(), b"");
                stream.write_all(&resp).await.unwrap();
                stream.flush().await.unwrap();
            }
            let _ = done_rx.await;
        });

        let pool = Arc::new(UpstreamSocketPool::new(4));
        let client = FastCgiClient::with_pool(&addr, pool.clone());

        let r1 = client
            .execute_php_pooled(
                FastCgiRequest::new("GET", "/1.php", "/1.php", "/var/www/1.php", "/var/www"),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(r1.status, 200);
        assert_eq!(r1.body, b"yanit-1");
        assert_eq!(pool.idle_count(&addr), 1);

        let r2 = client
            .execute_php_pooled(
                FastCgiRequest::new("GET", "/2.php", "/2.php", "/var/www/2.php", "/var/www"),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(r2.status, 200);
        assert_eq!(r2.body, b"yanit-2");
        assert_eq!(pool.idle_count(&addr), 1);
        assert_eq!(accept_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(*keep_conn_flags.lock().unwrap(), vec![FCGI_KEEP_CONN, FCGI_KEEP_CONN]);

        let _ = done_tx.send(());
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn pooled_client_retries_once_on_stale_socket_eof_before_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let accept_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let accept_srv = accept_count.clone();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

        let srv = tokio::spawn(async move {
            // 1. Bağlantı: 1. isteği yanıtlar, 2. istek geldiğinde yanıt başlığı vermeden kapatır (pm.max_requests simülasyonu)
            let (mut s1, _) = listener.accept().await.unwrap();
            accept_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = read_single_fcgi_request(&mut s1).await.unwrap();
            let resp1 = build_fcgi_response_bytes(1, b"Content-Type: text/plain\r\n\r\nilk", b"");
            s1.write_all(&resp1).await.unwrap();
            s1.flush().await.unwrap();

            // Havuzdan yeniden kullanıldığında isteği al ve hemen kapat
            let _ = read_single_fcgi_request(&mut s1).await;
            drop(s1);

            // 2. Bağlantı (otomatik taze retry): isteği normal yanıtla ve keep-alive için açık tut
            let (mut s2, _) = listener.accept().await.unwrap();
            accept_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = read_single_fcgi_request(&mut s2).await.unwrap();
            let resp2 = build_fcgi_response_bytes(1, b"Content-Type: text/plain\r\n\r\ntaze", b"");
            s2.write_all(&resp2).await.unwrap();
            s2.flush().await.unwrap();
            let _ = done_rx.await;
        });

        let pool = Arc::new(UpstreamSocketPool::new(4));
        let client = FastCgiClient::with_pool(&addr, pool.clone());

        let first = client
            .execute_php_pooled(
                FastCgiRequest::new("GET", "/a.php", "/a.php", "/var/www/a.php", "/var/www"),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(first.body, b"ilk");
        assert_eq!(pool.idle_count(&addr), 1);

        // İkinci istek bayat soketi alır, anlık EOF görür, 1 kez taze bağlantıyla yeniden dener
        let second = client
            .execute_php_pooled(
                FastCgiRequest::new("GET", "/b.php", "/b.php", "/var/www/b.php", "/var/www"),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(second.body, b"taze");
        assert_eq!(accept_count.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(pool.idle_count(&addr), 1);

        let _ = done_tx.send(());
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn pooled_client_does_not_release_socket_on_incomplete_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_single_fcgi_request(&mut s).await.unwrap();
            // Kısmi STDOUT gönderip FCGI_END_REQUEST olmadan kapat -> retry yapılmamalı, havuza iade edilmemeli
            let partial = b"Content-Type: text/plain\r\n\r\nyarim";
            s.write_all(&FastCgiClient::build_header(
                FCGI_STDOUT,
                1,
                partial.len() as u16,
                0,
            ))
            .await
            .unwrap();
            s.write_all(partial).await.unwrap();
            s.flush().await.unwrap();
            drop(s);
        });

        let pool = Arc::new(UpstreamSocketPool::new(4));
        let client = FastCgiClient::with_pool(&addr, pool.clone());

        let err = client
            .execute_php_pooled(
                FastCgiRequest::new("GET", "/p.php", "/p.php", "/var/www/p.php", "/var/www"),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, FastCgiError::Protocol(_)));
        assert_eq!(pool.idle_count(&addr), 0);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn pooled_client_captures_fcgi_stderr_and_headers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_single_fcgi_request(&mut s).await.unwrap();
            let resp = build_fcgi_response_bytes(
                1,
                b"Status: 201 Created\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
                b"PHP Notice: Undefined index foo",
            );
            s.write_all(&resp).await.unwrap();
            s.flush().await.unwrap();
        });

        let pool = Arc::new(UpstreamSocketPool::new(2));
        let client = FastCgiClient::with_pool(&addr, pool);
        let res = client
            .execute_php_pooled(
                FastCgiRequest::new("POST", "/api.php", "/api.php", "/var/www/api.php", "/var/www"),
                Duration::from_secs(2),
                Duration::from_secs(2),
            )
            .await
            .unwrap();

        assert_eq!(res.status, 201);
        assert_eq!(res.reason, "Created");
        assert_eq!(res.body, br#"{"ok":true}"#);
        assert_eq!(res.stderr, "PHP Notice: Undefined index foo");
        srv.await.unwrap();
    }

    #[test]
    fn x_accel_redirect_and_x_sendfile_parse_and_block_traversal() {
        let safe_raw = b"Status: 200 OK\r\nX-Accel-Redirect: /protected/files/report.pdf\r\nX-Sendfile: /srv/files/archive.zip\r\nContent-Type: application/octet-stream\r\n\r\n";
        let safe = FastCgiResponseDetailed::from_raw(safe_raw.to_vec(), Vec::new());
        assert_eq!(
            safe.x_accel_redirect.as_deref(),
            Some("/protected/files/report.pdf")
        );
        assert_eq!(safe.x_sendfile.as_deref(), Some("/srv/files/archive.zip"));

        let traversal_raw = b"X-Accel-Redirect: /protected/../../etc/passwd\r\nX-Sendfile: ..\\secret.key\r\n\r\n";
        let traversal = FastCgiResponseDetailed::from_raw(traversal_raw.to_vec(), Vec::new());
        assert_eq!(traversal.x_accel_redirect, None);
        assert_eq!(traversal.x_sendfile, None);

        let external_scheme_raw = b"X-Accel-Redirect: https://evil.example/payload\r\nX-Sendfile: http://evil.example/x\r\n\r\n";
        let external = FastCgiResponseDetailed::from_raw(external_scheme_raw.to_vec(), Vec::new());
        assert_eq!(external.x_accel_redirect, None);
        assert_eq!(external.x_sendfile, None);

        let null_and_proto_rel_raw = b"X-Accel-Redirect: /ok\0/evil\r\nX-Sendfile: //evil.example/path\r\n\r\n";
        let bad = FastCgiResponseDetailed::from_raw(null_and_proto_rel_raw.to_vec(), Vec::new());
        assert_eq!(bad.x_accel_redirect, None);
        assert_eq!(bad.x_sendfile, None);
    }

    #[tokio::test]
    async fn request_forwards_extra_env_and_http2_server_protocol() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen_params = Arc::new(std::sync::Mutex::new(HashMap::<String, String>::new()));
        let seen_srv = seen_params.clone();

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let recs = read_single_fcgi_request(&mut s).await.unwrap();
            let mut param_bytes = Vec::new();
            for (rtype, _, content, _) in recs {
                if rtype == FCGI_PARAMS {
                    param_bytes.extend_from_slice(&content);
                }
            }
            *seen_srv.lock().unwrap() = decode_fcgi_nv_pairs(&param_bytes);

            let resp = build_fcgi_response_bytes(1, b"Content-Type: text/plain\r\n\r\nok", b"");
            s.write_all(&resp).await.unwrap();
            s.flush().await.unwrap();
        });

        let pool = Arc::new(UpstreamSocketPool::new(2));
        let client = FastCgiClient::with_pool(&addr, pool);
        let req = FastCgiRequest::new("GET", "/h2.php", "/h2.php", "/var/www/h2.php", "/var/www")
            .server_protocol("HTTP/2.0")
            .env("HTTP_AUTHORIZATION", "Bearer jwt-123")
            .env("APP_ENV", "production")
            .env("HTTP_PROXY", "http://blocked.invalid");

        let res = client
            .execute_php_pooled(req, Duration::from_secs(2), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(res.body, b"ok");
        srv.await.unwrap();

        let params = seen_params.lock().unwrap();
        assert_eq!(params.get("SERVER_PROTOCOL").map(String::as_str), Some("HTTP/2.0"));
        assert_eq!(
            params.get("HTTP_AUTHORIZATION").map(String::as_str),
            Some("Bearer jwt-123")
        );
        assert_eq!(params.get("APP_ENV").map(String::as_str), Some("production"));
        assert!(!params.contains_key("HTTP_PROXY"));
    }

    #[test]
    fn validate_script_within_root_blocks_traversal_fix_pathinfo_and_dir() {
        let base = std::env::temp_dir().join(format!("zmax_fcgi_sec_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let doc_root = base.join("public_html");
        let outside = base.join("outside");
        std::fs::create_dir_all(doc_root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let ok_script = doc_root.join("sub").join("index.php");
        let avatar_file = doc_root.join("avatar.jpg");
        let secret_file = outside.join("secret.php");
        std::fs::write(&ok_script, b"<?php echo 1;").unwrap();
        std::fs::write(&avatar_file, b"JPEGDATA").unwrap();
        std::fs::write(&secret_file, b"<?php system('id');").unwrap();

        let resolved = validate_script_within_root(&doc_root, &ok_script, false).unwrap();
        assert_eq!(resolved, std::fs::canonicalize(&ok_script).unwrap());

        // Traversal ile dışarıdaki mevcut dosyaya erişim reddedilmeli
        let traversal_existing = doc_root.join("..").join("outside").join("secret.php");
        assert!(matches!(
            validate_script_within_root(&doc_root, &traversal_existing, true),
            Err(FastCgiError::SecurityViolation(_))
        ));

        // Traversal ile mevcut olmayan dış dosyaya erişim de SecurityViolation olmalı
        let traversal_missing = doc_root.join("..").join("..").join("etc").join("passwd");
        assert!(matches!(
            validate_script_within_root(&doc_root, &traversal_missing, true),
            Err(FastCgiError::SecurityViolation(_))
        ));

        // cgi.fix_pathinfo: normal dosya altında sahte PHP yolu (/avatar.jpg/evil.php)
        let fix_pathinfo = avatar_file.join("evil.php");
        assert!(matches!(
            validate_script_within_root(&doc_root, &fix_pathinfo, true),
            Err(FastCgiError::SecurityViolation(_))
        ));

        // Dizin hedefi normal dosya olmadığından reddedilmeli
        assert!(matches!(
            validate_script_within_root(&doc_root, &doc_root.join("sub"), true),
            Err(FastCgiError::SecurityViolation(_))
        ));

        // Null bayt reddedilmeli
        assert!(matches!(
            validate_script_within_root(&doc_root, Path::new("index.php\0.jpg"), true),
            Err(FastCgiError::SecurityViolation(_))
        ));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_script_within_root_blocks_symlink_escape_and_respects_root_flag() {
        let base = std::env::temp_dir().join(format!("zmax_fcgi_sym_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let real_root = base.join("real_root");
        let outside = base.join("outside");
        std::fs::create_dir_all(&real_root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let inside_php = real_root.join("app.php");
        let outside_php = outside.join("secret.php");
        std::fs::write(&inside_php, b"<?php echo 'ok';").unwrap();
        std::fs::write(&outside_php, b"<?php echo 'secret';").unwrap();

        let escape_link = real_root.join("escape.php");
        let link_root = base.join("link_root");

        #[cfg(unix)]
        let sym_file_res = std::os::unix::fs::symlink(&outside_php, &escape_link);
        #[cfg(windows)]
        let sym_file_res = std::os::windows::fs::symlink_file(&outside_php, &escape_link);

        #[cfg(unix)]
        let sym_dir_res = std::os::unix::fs::symlink(&real_root, &link_root);
        #[cfg(windows)]
        let sym_dir_res = std::os::windows::fs::symlink_dir(&real_root, &link_root);

        match (sym_file_res, sym_dir_res) {
            (Ok(()), Ok(())) => {
                // doc_root içinden dışarı sarkan symlink kesin reddedilmeli
                assert!(matches!(
                    validate_script_within_root(&real_root, &escape_link, true),
                    Err(FastCgiError::SecurityViolation(_))
                ));

                // doc_root'un kendisi symlink ise resolve_root_symlink=false iken reddet, true iken izin ver
                let via_link_root = link_root.join("app.php");
                assert!(matches!(
                    validate_script_within_root(&link_root, &via_link_root, false),
                    Err(FastCgiError::SecurityViolation(_))
                ));
                assert!(validate_script_within_root(&link_root, &via_link_root, true).is_ok());
            }
            // Windows'ta Geliştirici Modu/Admin yetkisi yoksa (os error 1314) NTFS junction ile test et
            (Err(e), _) | (_, Err(e)) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(1314),
                    "Beklenmeyen symlink olusturma hatasi: {e}"
                );
                #[cfg(windows)]
                {
                    let escape_dir = real_root.join("escape_dir");
                    let _ = std::fs::remove_file(&escape_link);
                    let _ = std::fs::remove_dir(&link_root);
                    let st1 = std::process::Command::new("cmd")
                        .args(["/C", "mklink", "/J"])
                        .arg(&escape_dir)
                        .arg(&outside)
                        .status()
                        .unwrap();
                    assert!(st1.success());

                    let st2 = std::process::Command::new("cmd")
                        .args(["/C", "mklink", "/J"])
                        .arg(&link_root)
                        .arg(&real_root)
                        .status()
                        .unwrap();
                    assert!(st2.success());

                    assert!(matches!(
                        validate_script_within_root(
                            &real_root,
                            &escape_dir.join("secret.php"),
                            true
                        ),
                        Err(FastCgiError::SecurityViolation(_))
                    ));

                    let via_link_root = link_root.join("app.php");
                    assert!(matches!(
                        validate_script_within_root(&link_root, &via_link_root, false),
                        Err(FastCgiError::SecurityViolation(_))
                    ));
                    assert!(
                        validate_script_within_root(&link_root, &via_link_root, true).is_ok()
                    );
                    let _ = std::fs::remove_dir(&escape_dir);
                    let _ = std::fs::remove_dir(&link_root);
                }
            }
        }

        let _ = std::fs::remove_dir_all(&base);
    }
}
