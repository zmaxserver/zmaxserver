//! # zmax-static
//! Sıfır kopyalama (zero-copy) statik dosya sunumu (CSS, JS, resim, WebP, AVIF, video).

use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;

static GLOBAL_ACME_ROOT: RwLock<Option<PathBuf>> = RwLock::new(None);

/// Global ortak ACME kök dizinini ayarlar (ör. /var/www/acme).
pub fn set_global_acme_root<P: AsRef<Path>>(root: P) {
    if let Ok(mut lock) = GLOBAL_ACME_ROOT.write() {
        *lock = Some(root.as_ref().to_path_buf());
    }
}

/// Global ortak ACME kök dizinini sıfırlar / temizler.
pub fn clear_global_acme_root() {
    if let Ok(mut lock) = GLOBAL_ACME_ROOT.write() {
        *lock = None;
    }
}

/// Global ortak ACME kök dizinini döndürür.
/// Sırasıyla:
/// 1. `set_global_acme_root` ile ayarlanmış özel yol,
/// 2. `ZMAX_ACME_ROOT` çevre değişkeni (tanımlıysa),
/// 3. Standart `/var/www/acme` dizini (diskte mevcutsa).
pub fn get_global_acme_root() -> Option<PathBuf> {
    if let Ok(lock) = GLOBAL_ACME_ROOT.read() {
        if let Some(ref path) = *lock {
            return Some(path.clone());
        }
    }
    if let Ok(env_root) = std::env::var("ZMAX_ACME_ROOT") {
        let p = PathBuf::from(env_root.trim());
        if !p.as_os_str().is_empty() && p.is_dir() {
            return Some(p);
        }
    }
    #[cfg(unix)]
    {
        let default_var_acme = PathBuf::from("/var/www/acme");
        if default_var_acme.is_dir() {
            return Some(default_var_acme);
        }
    }
    None
}

/// İstek yolunun ACME HTTP-01 challenge yolu olup olmadığını kontrol eder.
pub fn is_acme_challenge_path(path: &str) -> bool {
    let clean = percent_decode_path(path).unwrap_or_else(|| path.to_string());
    clean.starts_with("/.well-known/acme-challenge/")
}

/// Özel hata belgeleri (`error_docs`) için maksimum okuma sınırı (512 KiB).
pub const MAX_ERROR_DOC_BYTES: usize = 512 * 1024;

/// Statik dosya çözümleme, hata belgesi ve dizin listeleme hataları.
#[derive(Debug)]
pub enum StaticError {
    InvalidPath,
    Forbidden,
    NotFound,
    TooLarge { size: u64, max: usize },
    Io(std::io::Error),
}

impl fmt::Display for StaticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => write!(f, "geçersiz dosya yolu"),
            Self::Forbidden => write!(f, "erişim yasak (kök dizin dışı veya yetkisiz)"),
            Self::NotFound => write!(f, "dosya veya dizin bulunamadı"),
            Self::TooLarge { size, max } => {
                write!(f, "dosya boyutu sınırı aşıyor ({size} > {max} bayt)")
            }
            Self::Io(err) => write!(f, "G/Ç hatası: {err}"),
        }
    }
}

impl std::error::Error for StaticError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StaticError {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::Forbidden,
            _ => Self::Io(err),
        }
    }
}

pub struct StaticFileHandler {
    root_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFileInfo {
    pub path: PathBuf,
    pub mime_type: &'static str,
    pub size: u64,
    pub etag: String,
    pub last_modified_secs: u64,
}

impl StaticFileInfo {
    /// `last_modified_secs` değerini RFC 7231 IMF-fixdate biçiminde döndürür.
    pub fn last_modified_http(&self) -> String {
        format_http_date(self.last_modified_secs)
    }
}

/// Önceden sıkıştırılmış sidecar (`.zst`, `.br`, `.gz`) veya orijinal dosya bilgisi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarFile {
    pub path: PathBuf,
    pub encoding: Option<&'static str>,
    pub size: u64,
    pub original_content_type: &'static str,
    pub etag: String,
    pub last_modified_secs: u64,
}

impl SidecarFile {
    /// `last_modified_secs` değerini RFC 7231 IMF-fixdate biçiminde döndürür.
    pub fn last_modified_http(&self) -> String {
        format_http_date(self.last_modified_secs)
    }
}

/// HTTP `Range` başlığı çözümleme sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteRangeResult {
    /// Range başlığı yok, desteklenmiyor veya yoksayılmalı (200 OK).
    None,
    /// Tek bayt aralığı (206 Partial Content).
    Single { start: u64, end_inclusive: u64 },
    /// Aralık dosya sınırları dışında (416 Range Not Satisfiable).
    Unsatisfiable,
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// URL yolundaki `%XX` kodlamalarını çözer (UTF-8 destekli).
/// `+` karakteri URL yolunda boşluk değildir; literal `+` olarak korunur.
/// Geçersiz `%` dizisi veya bozuk UTF-8 baytları varsa `None` döndürür.
pub fn percent_decode_path(raw_path: &str) -> Option<String> {
    let bytes = raw_path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_nibble(bytes[i + 1])?;
            let lo = hex_nibble(bytes[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Ham ve çözülmüş yol üzerinde NUL bayt, ters bölü, path traversal (`..`),
/// gizli `.` segmentleri ve ACME istisnası doğrulaması yapar.
/// Güvenliyse baştaki `/` temizlenmiş göreceli yolu (kök için `""`) döndürür.
fn validate_and_decode_relative_path(request_path: &str) -> Option<String> {
    // 1. Decode ÖNCESİ kontroller
    if request_path.contains('\0') || request_path.contains('\\') || request_path.contains("..") {
        return None;
    }
    let raw_lower = request_path.to_ascii_lowercase();
    if raw_lower.contains("%00")
        || raw_lower.contains("%5c")
        || raw_lower.contains("%2e%2e")
        || raw_lower.contains(".%2e")
        || raw_lower.contains("%2e.")
    {
        return None;
    }

    // 2. URL Percent-Decoding (+ literal kalır)
    let decoded = percent_decode_path(request_path)?;

    // 3. Decode SONRASI kontroller (çift kodlama kalıntıları dahil)
    if decoded.contains('\0') || decoded.contains('\\') || decoded.contains("..") {
        return None;
    }
    let dec_lower = decoded.to_ascii_lowercase();
    if dec_lower.contains("%00") || dec_lower.contains("%5c") || dec_lower.contains("%2e%2e") {
        return None;
    }

    let trimmed = decoded.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(String::new());
    }

    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Some(String::new());
    }

    // ACME HTTP-01 istisnası: yalnızca /.well-known/acme-challenge/<normal-dosya> izinli
    let is_acme_challenge =
        segments.len() >= 3 && segments[0] == ".well-known" && segments[1] == "acme-challenge";

    if is_acme_challenge {
        for seg in &segments[2..] {
            if seg.starts_with('.') || *seg == ".." {
                return None;
            }
        }
    } else {
        for seg in &segments {
            if seg.starts_with('.') || *seg == ".." {
                return None;
            }
        }
    }

    // Windows sürücü harfi (C:) veya kök bileşeni enjeksiyonuna karşı ekstra koruma
    let clean_rel = segments.join("/");
    let rel_path = Path::new(&clean_rel);
    if !rel_path
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return None;
    }

    Some(clean_rel)
}

fn is_safe_index_entry(entry: &str) -> bool {
    if entry.is_empty() || entry.contains('\0') || entry.contains('\\') || entry.contains("..") {
        return false;
    }
    let path = Path::new(entry);
    let mut has_normal = false;
    for comp in path.components() {
        match comp {
            Component::Normal(s) => {
                let s = s.to_str().unwrap_or("");
                if s.is_empty() || s.starts_with('.') {
                    return false;
                }
                has_normal = true;
            }
            _ => return false,
        }
    }
    has_normal
}

/// Unix epoch saniyesini RFC 7231 IMF-fixdate formatına çevirir.
/// Örnek: `Wed, 21 Oct 2015 07:28:00 GMT`
pub fn format_http_date(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let min = (rem % 3_600) / 60;
    let sec = rem % 60;

    // 1970-01-01 Perşembe (4)
    let wday = (days + 4).rem_euclid(7) as usize;

    // Howard Hinnant civil_from_days algoritması
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        DAYS[wday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        hour,
        min,
        sec
    )
}

fn normalize_etag(tag: &str) -> &str {
    let t = tag.trim();
    if let Some(rest) = t.strip_prefix("W/") {
        rest.trim()
    } else {
        t
    }
}

/// Tırnak içi virgülleri bölmeden ETag listesini ayırır.
fn split_etag_list(value: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    let mut start = 0usize;

    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                let part = value[start..idx].trim();
                if !part.is_empty() {
                    items.push(part);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let tail = value[start..].trim();
    if !tail.is_empty() {
        items.push(tail);
    }
    items
}

/// `If-None-Match` başlığı (`"..."`, `W/"..."`, virgüllü liste veya `*`) verilen `etag`
/// ile eşleşiyorsa `true` döndürür (304 Not Modified için RFC 7232 zayıf karşılaştırma).
pub fn check_if_none_match(headers: &[(String, String)], etag: &str) -> bool {
    let target = normalize_etag(etag);
    if target.is_empty() {
        return false;
    }

    for (name, val) in headers {
        if !name.eq_ignore_ascii_case("if-none-match") {
            continue;
        }
        for candidate in split_etag_list(val) {
            if candidate == "*" {
                return true;
            }
            if normalize_etag(candidate) == target {
                return true;
            }
        }
    }
    false
}

/// HTTP `Range` başlığını dosya boyutuna göre çözümler (RFC 9110).
/// Desteklenen biçimler: `bytes=0-499`, `bytes=500-`, `bytes=-200`.
pub fn parse_byte_range(range_header: &str, file_size: u64) -> ByteRangeResult {
    let trimmed = range_header.trim();
    if trimmed.len() < 6 || !trimmed[..6].eq_ignore_ascii_case("bytes=") {
        return ByteRangeResult::None;
    }
    let spec = trimmed[6..].trim();
    if spec.is_empty() || spec.contains(',') {
        // Çoklu aralık veya boş ifade: tam içerik (200) döndürmek için yoksay
        return ByteRangeResult::None;
    }

    let Some((start_raw, end_raw)) = spec.split_once('-') else {
        return ByteRangeResult::None;
    };
    let start_str = start_raw.trim();
    let end_str = end_raw.trim();

    if start_str.is_empty() && end_str.is_empty() {
        return ByteRangeResult::None;
    }

    if start_str.is_empty() {
        // Suffix byte range: bytes=-N
        let Ok(suffix_len) = end_str.parse::<u64>() else {
            return ByteRangeResult::None;
        };
        if suffix_len == 0 || file_size == 0 {
            return ByteRangeResult::Unsatisfiable;
        }
        let start = file_size.saturating_sub(suffix_len);
        return ByteRangeResult::Single {
            start,
            end_inclusive: file_size - 1,
        };
    }

    let Ok(start) = start_str.parse::<u64>() else {
        return ByteRangeResult::None;
    };

    if end_str.is_empty() {
        // Açık uçlu aralık: bytes=N-
        if file_size == 0 || start >= file_size {
            return ByteRangeResult::Unsatisfiable;
        }
        return ByteRangeResult::Single {
            start,
            end_inclusive: file_size - 1,
        };
    }

    let Ok(end) = end_str.parse::<u64>() else {
        return ByteRangeResult::None;
    };

    if start > end {
        return ByteRangeResult::None;
    }
    if file_size == 0 || start >= file_size {
        return ByteRangeResult::Unsatisfiable;
    }

    ByteRangeResult::Single {
        start,
        end_inclusive: end.min(file_size - 1),
    }
}

impl StaticFileHandler {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root_dir: root.as_ref().to_path_buf(),
        }
    }

    fn build_file_info(canonical_target: PathBuf) -> Option<StaticFileInfo> {
        let metadata = std::fs::metadata(&canonical_target).ok()?;
        let size = metadata.len();
        let last_modified_secs = metadata
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // ETag: "boyut-degisiklik_zamani"
        let etag = format!("\"{size:x}-{last_modified_secs:x}\"");
        let mime_type = Self::detect_mime(&canonical_target);

        Some(StaticFileInfo {
            path: canonical_target,
            mime_type,
            size,
            etag,
            last_modified_secs,
        })
    }

    /// İstek yolunu güvenli dosya yoluna çözümler (percent-decoding, gizli dosya ve path traversal korumalı).
    pub fn resolve(&self, request_path: &str) -> Option<StaticFileInfo> {
        let clean_rel = validate_and_decode_relative_path(request_path)?;
        if clean_rel.is_empty() {
            return None;
        }
        // Dosya isteği sonunda '/' içeremez
        if request_path.ends_with('/') {
            return None;
        }

        let target = self.root_dir.join(&clean_rel);
        if let Ok(canonical_target) = std::fs::canonicalize(&target) {
            if let Ok(canonical_root) = std::fs::canonicalize(&self.root_dir) {
                if canonical_target.starts_with(&canonical_root) && canonical_target.is_file() {
                    return Self::build_file_info(canonical_target);
                }
            }
        }

        // ACME challenge isteği ise ve vhost docroot altında bulunamadıysa ortak kökte ara
        if is_acme_challenge_path(request_path) {
            return self.resolve_acme_challenge(request_path);
        }

        None
    }

    /// ACME HTTP-01 challenge dosyasını vhost kökünde veya ortak kökte çözümler.
    pub fn resolve_acme_challenge(&self, request_path: &str) -> Option<StaticFileInfo> {
        resolve_acme_challenge(
            &self.root_dir,
            get_global_acme_root().as_deref(),
            request_path,
        )
    }

    /// ACME HTTP-01 challenge dosyasını belirtilen özel acme_root köküyle çözümler.
    pub fn resolve_acme_challenge_with_root(
        &self,
        request_path: &str,
        acme_root: Option<&Path>,
    ) -> Option<StaticFileInfo> {
        resolve_acme_challenge(&self.root_dir, acme_root, request_path)
    }

    /// İstek yolunu çözümler; hedef fiziksel bir alt dizinse `index_files` listesindeki
    /// ilk mevcut dosyayı (`index.html`, `index.htm` vb.) döndürür.
    pub fn resolve_with_index(
        &self,
        request_path: &str,
        index_files: &[String],
    ) -> Option<StaticFileInfo> {
        let clean_rel = validate_and_decode_relative_path(request_path)?;
        let canonical_root = std::fs::canonicalize(&self.root_dir).ok()?;

        let target = if clean_rel.is_empty() {
            canonical_root.clone()
        } else {
            self.root_dir.join(&clean_rel)
        };

        let canonical_target = std::fs::canonicalize(&target).ok()?;
        if !canonical_target.starts_with(&canonical_root) {
            return None;
        }

        if canonical_target.is_file() {
            if request_path.ends_with('/') {
                return None;
            }
            return Self::build_file_info(canonical_target);
        }

        if canonical_target.is_dir() {
            // ACME dizinlerinde index taraması yapılmaz
            if clean_rel == ".well-known" || clean_rel.starts_with(".well-known/acme-challenge") {
                return None;
            }
            for idx in index_files {
                if !is_safe_index_entry(idx) {
                    continue;
                }
                let candidate = canonical_target.join(idx);
                if let Ok(canon_idx) = std::fs::canonicalize(&candidate) {
                    if canon_idx.starts_with(&canonical_target) && canon_idx.is_file() {
                        return Self::build_file_info(canon_idx);
                    }
                }
            }
        }

        None
    }

    /// İstek yolunu güvenli dosya yoluna çözümler; `precompressed == true` ve istemcinin
    /// `Accept-Encoding` başlığı destekliyorsa `.zst` > `.br` > `.gz` sidecar dosyasını
    /// (varsa ve `root_dir` içinde normal bir dosyaysa) `original_content_type` değerini
    /// koruyarak ve ETag sonuna `-zst`/`-br`/`-gz` ekleyerek döndürür.
    pub fn resolve_with_sidecar(
        &self,
        url_path: &str,
        accept_encoding: Option<&str>,
        precompressed: bool,
        allow_br: bool,
        allow_gzip: bool,
    ) -> Result<SidecarFile, StaticError> {
        let clean_rel =
            validate_and_decode_relative_path(url_path).ok_or(StaticError::InvalidPath)?;
        if clean_rel.is_empty() || url_path.ends_with('/') {
            return Err(StaticError::NotFound);
        }

        let canonical_root = std::fs::canonicalize(&self.root_dir)?;
        let target = self.root_dir.join(&clean_rel);
        let canonical_target = std::fs::canonicalize(&target)?;

        if !canonical_target.starts_with(&canonical_root) {
            return Err(StaticError::Forbidden);
        }
        if !canonical_target.is_file() {
            return Err(StaticError::NotFound);
        }

        let orig = Self::build_file_info(canonical_target).ok_or(StaticError::NotFound)?;
        self.resolve_sidecar_for_resolved(
            &canonical_root,
            &target,
            orig,
            accept_encoding,
            precompressed,
            allow_br,
            allow_gzip,
        )
    }

    /// Dizin index çözümlemesiyle birlikte sidecar desteği sunar.
    pub fn resolve_with_index_and_sidecar(
        &self,
        url_path: &str,
        index_files: &[String],
        accept_encoding: Option<&str>,
        precompressed: bool,
        allow_br: bool,
        allow_gzip: bool,
    ) -> Result<SidecarFile, StaticError> {
        let orig = self
            .resolve_with_index(url_path, index_files)
            .ok_or(StaticError::NotFound)?;
        let canonical_root = std::fs::canonicalize(&self.root_dir)?;
        let target = orig.path.clone();
        self.resolve_sidecar_for_resolved(
            &canonical_root,
            &target,
            orig,
            accept_encoding,
            precompressed,
            allow_br,
            allow_gzip,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_sidecar_for_resolved(
        &self,
        canonical_root: &Path,
        logical_target: &Path,
        orig: StaticFileInfo,
        accept_encoding: Option<&str>,
        precompressed: bool,
        allow_br: bool,
        allow_gzip: bool,
    ) -> Result<SidecarFile, StaticError> {
        let already_compressed_ext =
            orig.path
                .extension()
                .and_then(|s| s.to_str())
                .is_some_and(|e| {
                    e.eq_ignore_ascii_case("zst")
                        || e.eq_ignore_ascii_case("br")
                        || e.eq_ignore_ascii_case("gz")
                });

        if !precompressed || already_compressed_ext {
            return Ok(SidecarFile {
                path: orig.path,
                encoding: None,
                size: orig.size,
                original_content_type: orig.mime_type,
                etag: orig.etag,
                last_modified_secs: orig.last_modified_secs,
            });
        }

        let candidates = negotiate_sidecar_candidates(accept_encoding, allow_br, allow_gzip);
        for (ext, encoding_name, etag_suffix) in candidates {
            let mut sidecar_os = logical_target.as_os_str().to_os_string();
            sidecar_os.push(ext);
            let sidecar_candidate = PathBuf::from(sidecar_os);

            match std::fs::canonicalize(&sidecar_candidate) {
                Ok(canon_sidecar) => {
                    if !canon_sidecar.starts_with(canonical_root) {
                        return Err(StaticError::Forbidden);
                    }
                    let Ok(meta) = std::fs::metadata(&canon_sidecar) else {
                        continue;
                    };
                    if !meta.is_file() {
                        continue;
                    }
                    let last_modified_secs = meta
                        .modified()
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    return Ok(SidecarFile {
                        path: canon_sidecar,
                        encoding: Some(encoding_name),
                        size: meta.len(),
                        original_content_type: orig.mime_type,
                        etag: append_etag_suffix(&orig.etag, etag_suffix),
                        last_modified_secs,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(StaticError::from(err)),
            }
        }

        Ok(SidecarFile {
            path: orig.path,
            encoding: None,
            size: orig.size,
            original_content_type: orig.mime_type,
            etag: orig.etag,
            last_modified_secs: orig.last_modified_secs,
        })
    }

    /// Özel `error_docs` dosyasını (`404.html`, `50x.html` vb.) güvenli şekilde okur.
    /// Mutlak veya bağıl `page_rel` içinde `..` traversal, kök kaçışı ve symlink kaçışını
    /// kesin engeller; maksimum 512 KiB sınırıyla okur.
    pub fn resolve_error_doc_file(
        &self,
        doc_root: &Path,
        custom_dir: Option<&Path>,
        page_rel: &str,
    ) -> Result<Vec<u8>, StaticError> {
        let rel_path = validate_error_doc_rel_path(page_rel)?;

        let canon_doc_root = std::fs::canonicalize(doc_root)?;
        let canon_base = match custom_dir {
            Some(dir) if !dir.as_os_str().is_empty() => {
                if dir.is_absolute() {
                    std::fs::canonicalize(dir)?
                } else {
                    let s = dir.to_str().ok_or(StaticError::InvalidPath)?;
                    if s.contains('\0') || s.contains("..") {
                        return Err(StaticError::InvalidPath);
                    }
                    let joined = doc_root.join(dir);
                    let canon = std::fs::canonicalize(&joined)?;
                    if !canon.starts_with(&canon_doc_root) {
                        return Err(StaticError::Forbidden);
                    }
                    canon
                }
            }
            _ => canon_doc_root,
        };

        let target = canon_base.join(rel_path);
        let canon_target = std::fs::canonicalize(&target)?;
        if !canon_target.starts_with(&canon_base) {
            return Err(StaticError::Forbidden);
        }

        let meta = std::fs::metadata(&canon_target)?;
        if !meta.is_file() {
            return Err(StaticError::NotFound);
        }
        if meta.len() > MAX_ERROR_DOC_BYTES as u64 {
            return Err(StaticError::TooLarge {
                size: meta.len(),
                max: MAX_ERROR_DOC_BYTES,
            });
        }

        let file = std::fs::File::open(&canon_target)?;
        let mut buf = Vec::with_capacity((meta.len() as usize).min(MAX_ERROR_DOC_BYTES));
        file.take((MAX_ERROR_DOC_BYTES + 1) as u64)
            .read_to_end(&mut buf)?;
        if buf.len() > MAX_ERROR_DOC_BYTES {
            return Err(StaticError::TooLarge {
                size: buf.len() as u64,
                max: MAX_ERROR_DOC_BYTES,
            });
        }

        Ok(buf)
    }

    /// WebP, AVIF ve tüm modern MIME türlerini algılar
    pub fn detect_mime(path: &Path) -> &'static str {
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            match ext.to_lowercase().as_str() {
                "webp" => "image/webp",
                "avif" => "image/avif",
                "svg" => "image/svg+xml",
                "wasm" => "application/wasm",
                _ => mime_guess::from_path(path)
                    .first_raw()
                    .unwrap_or("application/octet-stream"),
            }
        } else {
            "application/octet-stream"
        }
    }
}

/// ACME challenge isteklerini önce vhost belge kökü altında, yoksa ortak kök (acme_root) altında arar.
/// Başarılı olursa dosya bilgilerini döndürür. RFC 8555 standardına uygun olarak text/plain MIME tipi kullanılır.
pub fn resolve_acme_challenge(
    vhost_docroot: &Path,
    acme_root: Option<&Path>,
    request_path: &str,
) -> Option<StaticFileInfo> {
    if !is_acme_challenge_path(request_path) {
        return None;
    }

    let clean_rel = validate_and_decode_relative_path(request_path)?;
    if clean_rel.is_empty() || request_path.ends_with('/') {
        return None;
    }

    let segments: Vec<&str> = clean_rel.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 3 || segments[0] != ".well-known" || segments[1] != "acme-challenge" {
        return None;
    }

    // Token segmenti gizli dosya veya traversal içeremez
    for seg in &segments[2..] {
        if seg.starts_with('.') || *seg == ".." {
            return None;
        }
    }
    let clean_rel_path: PathBuf = segments.iter().collect();
    let token_rel_path: PathBuf = segments[2..].iter().collect();

    // 1. Önce vhost docroot/.well-known/acme-challenge/* altında ara
    let target = vhost_docroot.join(&clean_rel_path);
    if let Ok(canonical_target) = std::fs::canonicalize(&target) {
        if let Ok(canonical_docroot) = std::fs::canonicalize(vhost_docroot) {
            if canonical_target.starts_with(&canonical_docroot) && canonical_target.is_file() {
                if let Some(mut info) = StaticFileHandler::build_file_info(canonical_target) {
                    info.mime_type = "text/plain; charset=utf-8";
                    return Some(info);
                }
            }
        }
    }

    // 2. Bulunamadıysa ortak kök (açık acme_root -> global_acme_root -> otomatik tespit yedek) altında ara
    let fallback_root = acme_root
        .map(|p| p.to_path_buf())
        .or_else(get_global_acme_root)
        .or_else(|| auto_detect_acme_root(vhost_docroot));

    if let Some(common_root) = fallback_root {
        if let Ok(canonical_common) = std::fs::canonicalize(&common_root) {
            // Aday 1: common_root/.well-known/acme-challenge/<token> (certbot webroot standardı)
            let candidate1 = common_root.join(&clean_rel_path);
            if let Ok(canon_cand1) = std::fs::canonicalize(&candidate1) {
                if canon_cand1.starts_with(&canonical_common) && canon_cand1.is_file() {
                    if let Some(mut info) = StaticFileHandler::build_file_info(canon_cand1) {
                        info.mime_type = "text/plain; charset=utf-8";
                        return Some(info);
                    }
                }
            }

            // Aday 2: common_root/<token> (düz token kökü desteği)
            let candidate2 = common_root.join(&token_rel_path);
            if let Ok(canon_cand2) = std::fs::canonicalize(&candidate2) {
                if canon_cand2.starts_with(&canonical_common) && canon_cand2.is_file() {
                    if let Some(mut info) = StaticFileHandler::build_file_info(canon_cand2) {
                        info.mime_type = "text/plain; charset=utf-8";
                        return Some(info);
                    }
                }
            }
        }
    }

    None
}

/// vhost belge kökünden veya çalışma alanından ortak ACME kökünü otomatik tespit eder.
/// Yalnızca çalışma alanı düzeyindeki dizinleri (`common_acme`, `acme`, `conf/zmax.toml`) inceler;
/// başka vHost dosyalarındaki (`conf/vhosts/*.toml`) özel kökler izole tutulur.
fn auto_detect_acme_root(vhost_docroot: &Path) -> Option<PathBuf> {
    let mut curr = vhost_docroot;
    for _ in 0..4 {
        if let Some(parent) = curr.parent() {
            let cand1 = parent.join("common_acme");
            if cand1.is_dir() {
                return Some(cand1);
            }
            let cand2 = parent.join("acme");
            if cand2.is_dir() {
                return Some(cand2);
            }
            let conf_file = parent.join("conf").join("zmax.toml");
            if conf_file.is_file() {
                if let Ok(content) = std::fs::read_to_string(&conf_file) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') {
                            continue;
                        }
                        if let Some((key, val)) = trimmed.split_once('=') {
                            if key.trim() == "acme_root" {
                                let raw_val = val.split('#').next().unwrap_or("").trim();
                                let cleaned = raw_val.trim_matches('"').trim_matches('\'').trim();
                                if !cleaned.is_empty() {
                                    let p = PathBuf::from(cleaned);
                                    let resolved = if p.is_absolute() { p } else { parent.join(p) };
                                    if resolved.is_dir() {
                                        return Some(resolved);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            curr = parent;
        } else {
            break;
        }
    }
    None
}

fn append_etag_suffix(etag: &str, suffix: &str) -> String {
    if let Some(stripped) = etag.strip_suffix('"') {
        format!("{stripped}-{suffix}\"")
    } else {
        format!("{etag}-{suffix}")
    }
}

fn validate_error_doc_rel_path(page_rel: &str) -> Result<&Path, StaticError> {
    if page_rel.is_empty()
        || page_rel.contains('\0')
        || page_rel.contains('\\')
        || page_rel.contains("..")
        || page_rel.starts_with('/')
    {
        return Err(StaticError::InvalidPath);
    }

    let rel_path = Path::new(page_rel);
    if rel_path.is_absolute() || rel_path.has_root() {
        return Err(StaticError::InvalidPath);
    }

    let mut has_component = false;
    for comp in rel_path.components() {
        match comp {
            Component::Normal(seg) => {
                let s = seg.to_str().ok_or(StaticError::InvalidPath)?;
                if s.is_empty() || s.starts_with('.') {
                    return Err(StaticError::InvalidPath);
                }
                has_component = true;
            }
            _ => return Err(StaticError::InvalidPath),
        }
    }

    if !has_component {
        return Err(StaticError::InvalidPath);
    }
    Ok(rel_path)
}

fn parse_qvalue_millis(raw: &str) -> Option<u16> {
    let s = raw.trim();
    if s == "0" {
        return Some(0);
    }
    if s == "1" {
        return Some(1000);
    }
    if let Some(frac) = s.strip_prefix("0.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut val = 0u16;
        let mut mult = 100u16;
        for b in frac.bytes() {
            val += (b - b'0') as u16 * mult;
            mult /= 10;
        }
        return Some(val);
    }
    if let Some(frac) = s.strip_prefix("1.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b == b'0') {
            return None;
        }
        return Some(1000);
    }
    None
}

fn negotiate_sidecar_candidates(
    accept_encoding: Option<&str>,
    allow_br: bool,
    allow_gzip: bool,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let Some(raw) = accept_encoding else {
        return Vec::new();
    };
    if raw.trim().is_empty() {
        return Vec::new();
    }

    let mut zstd_q: Option<u16> = None;
    let mut br_q: Option<u16> = None;
    let mut gzip_q: Option<u16> = None;
    let mut x_gzip_q: Option<u16> = None;
    let mut wildcard_q: Option<u16> = None;

    for item in raw.split(',') {
        let mut parts = item.split(';');
        let coding = parts.next().unwrap_or("").trim();
        if coding.is_empty() {
            continue;
        }

        let mut q_val: Option<u16> = None;
        let mut invalid_q = false;
        for param in parts {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            if let Some((k, v)) = param.split_once('=') {
                if k.trim().eq_ignore_ascii_case("q") {
                    match parse_qvalue_millis(v) {
                        Some(q) => q_val = Some(q),
                        None => {
                            invalid_q = true;
                            break;
                        }
                    }
                }
            }
        }
        if invalid_q {
            continue;
        }

        let q = q_val.unwrap_or(1000);
        let slot = if coding.eq_ignore_ascii_case("zstd") {
            &mut zstd_q
        } else if coding.eq_ignore_ascii_case("br") {
            &mut br_q
        } else if coding.eq_ignore_ascii_case("gzip") {
            &mut gzip_q
        } else if coding.eq_ignore_ascii_case("x-gzip") {
            &mut x_gzip_q
        } else if coding == "*" {
            &mut wildcard_q
        } else {
            continue;
        };

        *slot = Some(match *slot {
            Some(prev) if prev == 0 || q == 0 => 0,
            Some(prev) => prev.max(q),
            None => q,
        });
    }

    let eff_zstd = zstd_q.or(wildcard_q).unwrap_or(0);
    let eff_br = if allow_br {
        br_q.or(wildcard_q).unwrap_or(0)
    } else {
        0
    };
    let eff_gzip = if allow_gzip {
        gzip_q.or(x_gzip_q).or(wildcard_q).unwrap_or(0)
    } else {
        0
    };

    let mut ranked: Vec<(u16, u8, &'static str, &'static str, &'static str)> =
        Vec::with_capacity(3);
    if eff_zstd > 0 {
        ranked.push((eff_zstd, 0, ".zst", "zstd", "zst"));
    }
    if eff_br > 0 {
        ranked.push((eff_br, 1, ".br", "br", "br"));
    }
    if eff_gzip > 0 {
        ranked.push((eff_gzip, 2, ".gz", "gzip", "gz"));
    }

    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    ranked
        .into_iter()
        .map(|(_, _, ext, enc, suffix)| (ext, enc, suffix))
        .collect()
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn encode_uri_segment(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let is_unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if is_unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

/// Dizin içeriğini XSS'e karşı sıkı HTML-escape edilmiş güvenli `autoindex` HTML sayfası
/// olarak üretir. Gizli `.` ile başlayan girdileri listelemez.
pub fn render_directory_listing(
    request_path: &str,
    dir_path: &Path,
) -> Result<String, StaticError> {
    let meta = std::fs::metadata(dir_path)?;
    if !meta.is_dir() {
        return Err(StaticError::NotFound);
    }

    let mut entries: Vec<(bool, String, u64)> = Vec::new();
    for entry_res in std::fs::read_dir(dir_path)? {
        let entry = entry_res?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let Ok(entry_meta) = entry.metadata() else {
            continue;
        };
        let is_dir = entry_meta.is_dir();
        let size = if is_dir { 0 } else { entry_meta.len() };
        entries.push((is_dir, name, size));
    }

    entries.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.to_ascii_lowercase().cmp(&b.1.to_ascii_lowercase()))
            .then_with(|| a.1.cmp(&b.1))
    });

    let escaped_req = escape_html(request_path);
    let mut html = String::with_capacity(512 + entries.len() * 96);
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
    html.push_str("<title>Index of ");
    html.push_str(&escaped_req);
    html.push_str("</title></head><body><h1>Index of ");
    html.push_str(&escaped_req);
    html.push_str("</h1><ul>");

    for (is_dir, name, size) in entries {
        let mut href = encode_uri_segment(&name);
        let mut display = escape_html(&name);
        if is_dir {
            href.push('/');
            display.push('/');
        }
        html.push_str("<li><a href=\"");
        html.push_str(&href);
        html.push_str("\">");
        html.push_str(&display);
        if is_dir {
            html.push_str("</a> -</li>");
        } else {
            html.push_str("</a> (");
            html.push_str(&size.to_string());
            html.push_str(" B)</li>");
        }
    }

    html.push_str("</ul></body></html>");
    Ok(html)
}

/// Bu platformda `sendfile(2)` sıfır-kopya aktarımının desteklenip desteklenmediğini döndürür.
#[inline]
pub fn is_sendfile_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Linux `sendfile(2)` sıfır-kopya dosya parçası aktarımı.
/// Başarılı aktarılan bayt sayısını döndürür ve `offset` değerini ilerletir.
#[cfg(target_os = "linux")]
pub fn try_sendfile_chunk(
    out_fd: std::os::unix::io::RawFd,
    in_fd: std::os::unix::io::RawFd,
    offset: &mut u64,
    count: usize,
) -> std::io::Result<usize> {
    if count == 0 {
        return Ok(0);
    }
    let mut off = libc::off_t::try_from(*offset).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "sendfile offset taşması")
    })?;
    // SAFETY: Geçerli dosya tanımlayıcıları ve hizalı `off_t` işaretçisi ile Linux sendfile(2) çağrısı.
    let sent = unsafe { libc::sendfile(out_fd, in_fd, &mut off, count) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    *offset = off as u64;
    Ok(sent as usize)
}

/// Linux dışındaki Unix sistemlerde temiz `Unsupported` hatası döndüren `sendfile` sarmalayıcısı.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn try_sendfile_chunk(
    _out_fd: std::os::unix::io::RawFd,
    _in_fd: std::os::unix::io::RawFd,
    _offset: &mut u64,
    _count: usize,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sendfile yalnızca Linux üzerinde desteklenir",
    ))
}

/// Windows ve Unix dışı platformlarda temiz `Unsupported` hatası döndüren çapraz-platform yardımcı.
#[cfg(not(unix))]
pub fn try_sendfile_chunk(
    _out_fd: i32,
    _in_fd: i32,
    _offset: &mut u64,
    _count: usize,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sendfile bu platformda desteklenmiyor",
    ))
}

/// `sendfile(2)` desteklenmediğinde (`ErrorKind::Unsupported`) kullanılan çapraz-platform
/// tamponlu dosya parçası aktarım yardımcısı.
pub fn copy_file_chunk_fallback(
    file: &mut std::fs::File,
    out: &mut impl Write,
    offset: &mut u64,
    count: usize,
) -> std::io::Result<usize> {
    if count == 0 {
        return Ok(0);
    }
    file.seek(SeekFrom::Start(*offset))?;
    let mut buf = vec![0u8; count.min(64 * 1024)];
    let mut total_written = 0usize;
    while total_written < count {
        let to_read = (count - total_written).min(buf.len());
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        total_written += n;
        *offset += n as u64;
    }
    Ok(total_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zmax_static_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_path_traversal_prevention() {
        let temp_dir = std::env::temp_dir().join("zmax_test_traversal");
        let _ = std::fs::create_dir_all(&temp_dir);
        let secret_file = temp_dir.parent().unwrap().join("zmax_secret.txt");
        let _ = File::create(&secret_file).and_then(|mut f| f.write_all(b"SECRET"));

        let handler = StaticFileHandler::new(&temp_dir);

        // Path traversal denemeleri - Hepsi engellenmelidir (None dönmelidir)
        assert!(handler.resolve("../zmax_secret.txt").is_none());
        assert!(handler.resolve("../../Windows/win.ini").is_none());
        assert!(handler.resolve("..\\..\\Windows\\win.ini").is_none());
        assert!(handler.resolve("/../secret").is_none());
        assert!(handler.resolve("subdir/../../etc/passwd").is_none());

        // Percent-encoded traversal, NUL bayt ve double-encoding denemeleri
        assert!(handler.resolve("/%2e%2e/zmax_secret.txt").is_none());
        assert!(handler.resolve("/%2e%2e%2fzmax_secret.txt").is_none());
        assert!(handler.resolve("/%2E%2E/zmax_secret.txt").is_none());
        assert!(handler
            .resolve("/subdir/%2e%2e/%2e%2e/zmax_secret.txt")
            .is_none());
        assert!(handler.resolve("/%252e%252e%252fzmax_secret.txt").is_none());
        assert!(handler.resolve("/dosya.txt%00.png").is_none());
        assert!(handler.resolve("/a%5cb").is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
        let _ = std::fs::remove_file(&secret_file);
    }

    #[test]
    fn test_acme_challenge_dir_allowed_other_dotfiles_blocked() {
        let root = std::env::temp_dir().join(format!("zmax_test_acme_{}", std::process::id()));
        let acme = root.join(".well-known").join("acme-challenge");
        let subdir = root.join("subdir");
        let git_dir = root.join(".git");
        let _ = std::fs::create_dir_all(&acme);
        let _ = std::fs::create_dir_all(&subdir);
        let _ = std::fs::create_dir_all(&git_dir);

        let _ = std::fs::write(acme.join("tok"), "x");
        let _ = std::fs::write(acme.join(".secret"), "no");
        let _ = std::fs::write(root.join(".env"), "SECRET");
        let _ = std::fs::write(root.join(".htaccess"), "DENY");
        let _ = std::fs::write(root.join(".htpasswd"), "HASH");
        let _ = std::fs::write(git_dir.join("config"), "GIT");
        let _ = std::fs::write(subdir.join(".htaccess"), "SUBDENY");
        let _ = std::fs::write(root.join(".well-known").join("other"), "y");

        let handler = StaticFileHandler::new(&root);
        assert!(handler.resolve("/.well-known/acme-challenge/tok").is_some());
        assert!(handler
            .resolve("/.well-known/acme-challenge/.secret")
            .is_none());
        assert!(handler.resolve("/.env").is_none());
        assert!(handler.resolve("/%2eenv").is_none());
        assert!(handler.resolve("/.htaccess").is_none());
        assert!(handler.resolve("/.htpasswd").is_none());
        assert!(handler.resolve("/.git/config").is_none());
        assert!(handler.resolve("/subdir/.htaccess").is_none());
        assert!(handler.resolve("/subdir/%2ehtaccess").is_none());
        assert!(handler.resolve("/.well-known/other").is_none());
        assert!(handler
            .resolve("/.well-known/acme-challenge/../../.env")
            .is_none());
        assert!(handler
            .resolve_with_index("/.well-known/acme-challenge/", &["tok".into()])
            .is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_percent_decode_turkish_spaces_and_literal_plus() {
        assert_eq!(
            percent_decode_path("/merhaba%20d%C3%BCnya.txt").as_deref(),
            Some("/merhaba dünya.txt")
        );
        assert_eq!(
            percent_decode_path("/g%C3%B6rsel%20(1).png").as_deref(),
            Some("/görsel (1).png")
        );
        // '+' karakteri URL path içinde boşluğa dönüşmez!
        assert_eq!(
            percent_decode_path("/c++%20notlar%C4%B1.txt").as_deref(),
            Some("/c++ notları.txt")
        );
        assert!(percent_decode_path("/bozuk%2").is_none());
        assert!(percent_decode_path("/bozuk%ZZ").is_none());
        assert!(percent_decode_path("/%FF%FE").is_none());

        let root = temp_root("tr_utf8");
        std::fs::write(root.join("örnek dosya.txt"), "merhaba").unwrap();
        std::fs::write(root.join("fotoğraf 1.webp"), "webpdata").unwrap();
        std::fs::write(root.join("c++ notları.txt"), "cpp").unwrap();

        let handler = StaticFileHandler::new(&root);
        let info1 = handler.resolve("/%C3%B6rnek%20dosya.txt").unwrap();
        assert_eq!(info1.size, 7);
        assert!(info1.last_modified_secs > 0);

        let info2 = handler.resolve("/foto%C4%9Fraf%201.webp").unwrap();
        assert_eq!(info2.mime_type, "image/webp");

        let info3 = handler.resolve("/c++%20notlar%C4%B1.txt").unwrap();
        assert_eq!(info3.size, 3);

        // Zaten çözülmüş UTF-8 yol da çalışmalı
        assert!(handler.resolve("/örnek dosya.txt").is_some());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_resolve_with_index_directory_resolution() {
        let root = temp_root("dir_index");
        let klasor = root.join("klasor");
        let bos_klasor = root.join("bos");
        std::fs::create_dir_all(&klasor).unwrap();
        std::fs::create_dir_all(&bos_klasor).unwrap();
        std::fs::write(root.join("index.htm"), "root").unwrap();
        std::fs::write(klasor.join("index.html"), "<h1>Klasor</h1>").unwrap();
        std::fs::write(klasor.join("stil.css"), "body{}").unwrap();

        let handler = StaticFileHandler::new(&root);
        let indexes = vec!["index.html".to_string(), "index.htm".to_string()];

        // Kök dizin: index.html yok, index.htm seçilir
        let root_idx = handler.resolve_with_index("/", &indexes).unwrap();
        assert!(root_idx.path.ends_with("index.htm"));

        // Eski resolve() dizinler için None dönmeye devam eder
        assert!(handler.resolve("/").is_none());
        assert!(handler.resolve("/klasor/").is_none());

        // /klasor ve /klasor/ -> /klasor/index.html
        let d1 = handler.resolve_with_index("/klasor", &indexes).unwrap();
        let d2 = handler.resolve_with_index("/klasor/", &indexes).unwrap();
        assert_eq!(d1.path, d2.path);
        assert!(d1.path.ends_with("index.html"));

        // Gerçek dosya doğrudan çözülür; sonunda '/' varsa reddedilir
        let css = handler
            .resolve_with_index("/klasor/stil.css", &indexes)
            .unwrap();
        assert_eq!(css.mime_type, "text/css");
        assert!(handler
            .resolve_with_index("/klasor/stil.css/", &indexes)
            .is_none());

        // Boş dizinde index bulunmaz -> None
        assert!(handler.resolve_with_index("/bos/", &indexes).is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_http_date_and_if_none_match() {
        assert_eq!(format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            format_http_date(1_445_412_480),
            "Wed, 21 Oct 2015 07:28:00 GMT"
        );
        // Artık yıl: 2024-02-29 12:34:56 UTC -> 1709210096
        assert_eq!(
            format_http_date(1_709_210_096),
            "Thu, 29 Feb 2024 12:34:56 GMT"
        );

        let etag = "\"a5-5f10\"";
        assert!(check_if_none_match(
            &[("If-None-Match".into(), "\"a5-5f10\"".into())],
            etag
        ));
        assert!(check_if_none_match(
            &[("if-none-match".into(), "W/\"a5-5f10\"".into())],
            etag
        ));
        assert!(check_if_none_match(
            &[(
                "If-None-Match".into(),
                "\"1-1\", W/\"a5-5f10\", \"2-2\"".into()
            )],
            etag
        ));
        assert!(check_if_none_match(
            &[("If-None-Match".into(), "*".into())],
            etag
        ));
        assert!(!check_if_none_match(
            &[("If-None-Match".into(), "\"ff-ff\"".into())],
            etag
        ));
        assert!(!check_if_none_match(&[], etag));
    }

    #[test]
    fn test_parse_byte_range() {
        // 20 baytlık dosya (geçerli indeksler 0..=19)
        assert_eq!(
            parse_byte_range("bytes=0-9", 20),
            ByteRangeResult::Single {
                start: 0,
                end_inclusive: 9
            }
        );
        assert_eq!(
            parse_byte_range("bytes=5-", 20),
            ByteRangeResult::Single {
                start: 5,
                end_inclusive: 19
            }
        );
        assert_eq!(
            parse_byte_range("bytes=-4", 20),
            ByteRangeResult::Single {
                start: 16,
                end_inclusive: 19
            }
        );
        // Suffix dosya boyutundan büyükse tüm dosya döner
        assert_eq!(
            parse_byte_range("bytes=-100", 20),
            ByteRangeResult::Single {
                start: 0,
                end_inclusive: 19
            }
        );
        // Üst sınır dosya boyutunu aşarsa son bayta kırpılır
        assert_eq!(
            parse_byte_range("bytes=10-999", 20),
            ByteRangeResult::Single {
                start: 10,
                end_inclusive: 19
            }
        );
        // Taşan aralık -> 416 Unsatisfiable
        assert_eq!(
            parse_byte_range("bytes=999999-", 20),
            ByteRangeResult::Unsatisfiable
        );
        assert_eq!(
            parse_byte_range("bytes=20-25", 20),
            ByteRangeResult::Unsatisfiable
        );
        assert_eq!(
            parse_byte_range("bytes=-0", 20),
            ByteRangeResult::Unsatisfiable
        );
        assert_eq!(
            parse_byte_range("bytes=0-0", 0),
            ByteRangeResult::Unsatisfiable
        );
        // Geçersiz veya çoklu aralık -> None
        assert_eq!(parse_byte_range("bytes=10-5", 20), ByteRangeResult::None);
        assert_eq!(
            parse_byte_range("bytes=0-1, 4-5", 20),
            ByteRangeResult::None
        );
        assert_eq!(parse_byte_range("items=0-5", 20), ByteRangeResult::None);
        assert_eq!(parse_byte_range("invalid", 20), ByteRangeResult::None);
    }

    #[test]
    fn test_sidecar_priority_zst_br_gz() {
        let root = temp_root("sidecar_prio");
        std::fs::write(root.join("app.js"), "console.log('orig');").unwrap();
        std::fs::write(root.join("app.js.zst"), "zst-bytes").unwrap();
        std::fs::write(root.join("app.js.br"), "br-bytes-123").unwrap();
        std::fs::write(root.join("app.js.gz"), "gz-bytes-12345").unwrap();

        let handler = StaticFileHandler::new(&root);

        // Üçü de kabul edilirken en yüksek öncelik .zst olmalı
        let res = handler
            .resolve_with_sidecar("/app.js", Some("gzip, br, zstd"), true, true, true)
            .unwrap();
        assert_eq!(res.encoding, Some("zstd"));
        assert!(res.path.ends_with("app.js.zst"));
        assert_eq!(res.size, 9);

        // İstemci yalnızca br ve gzip kabul ediyorsa .br seçilir
        let res_br = handler
            .resolve_with_sidecar("/app.js", Some("gzip, br"), true, true, true)
            .unwrap();
        assert_eq!(res_br.encoding, Some("br"));
        assert!(res_br.path.ends_with("app.js.br"));

        // allow_br = false ise .br atlanıp .gz seçilir
        let res_no_br = handler
            .resolve_with_sidecar("/app.js", Some("br, gzip"), true, false, true)
            .unwrap();
        assert_eq!(res_no_br.encoding, Some("gzip"));
        assert!(res_no_br.path.ends_with("app.js.gz"));

        // İstemci q ağırlığında gzip > br ise .gz seçilir
        let res_q = handler
            .resolve_with_sidecar("/app.js", Some("br;q=0.5, gzip;q=0.9"), true, true, true)
            .unwrap();
        assert_eq!(res_q.encoding, Some("gzip"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_sidecar_fallback_when_missing_or_disabled() {
        let root = temp_root("sidecar_fallback");
        std::fs::write(root.join("page.html"), "<h1>Merhaba</h1>").unwrap();
        std::fs::write(root.join("with_gz.css"), "body{color:red}").unwrap();
        std::fs::write(root.join("with_gz.css.gz"), "gz").unwrap();

        let handler = StaticFileHandler::new(&root);

        // Sidecar yoksa orijinal dosya (encoding = None) döner
        let plain = handler
            .resolve_with_sidecar("/page.html", Some("zstd, br, gzip"), true, true, true)
            .unwrap();
        assert_eq!(plain.encoding, None);
        assert!(plain.path.ends_with("page.html"));
        assert_eq!(plain.original_content_type, "text/html");

        // precompressed = false iken sidecar olsa bile orijinal dosya döner
        let disabled = handler
            .resolve_with_sidecar("/with_gz.css", Some("gzip"), false, true, true)
            .unwrap();
        assert_eq!(disabled.encoding, None);
        assert!(disabled.path.ends_with("with_gz.css"));

        // Accept-Encoding yoksa orijinal dosya döner
        let no_hdr = handler
            .resolve_with_sidecar("/with_gz.css", None, true, true, true)
            .unwrap();
        assert_eq!(no_hdr.encoding, None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_sidecar_preserves_original_content_type_and_etag() {
        let root = temp_root("sidecar_mime_etag");
        std::fs::write(root.join("style.css"), "body{margin:0;padding:0}").unwrap();
        std::fs::write(root.join("style.css.gz"), "gz").unwrap();
        std::fs::write(root.join("icon.svg"), "<svg></svg>").unwrap();
        std::fs::write(root.join("icon.svg.br"), "br").unwrap();
        std::fs::write(root.join("data.json"), "{\"ok\":true}").unwrap();
        std::fs::write(root.join("data.json.zst"), "zst").unwrap();

        let handler = StaticFileHandler::new(&root);
        let orig_css = handler.resolve("/style.css").unwrap();

        let gz_css = handler
            .resolve_with_sidecar("/style.css", Some("gzip"), true, true, true)
            .unwrap();
        assert_eq!(gz_css.original_content_type, "text/css");
        assert_ne!(gz_css.original_content_type, "application/x-gzip");
        assert_ne!(gz_css.etag, orig_css.etag);
        assert!(gz_css.etag.ends_with("-gz\""));

        let br_svg = handler
            .resolve_with_sidecar("/icon.svg", Some("br"), true, true, true)
            .unwrap();
        assert_eq!(br_svg.original_content_type, "image/svg+xml");
        assert!(br_svg.etag.ends_with("-br\""));

        let zst_json = handler
            .resolve_with_sidecar("/data.json", Some("zstd"), true, true, true)
            .unwrap();
        assert_eq!(zst_json.original_content_type, "application/json");
        assert!(zst_json.etag.ends_with("-zst\""));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_sidecar_security_traversal_and_directory_skip() {
        let root = temp_root("sidecar_sec");
        std::fs::write(root.join("safe.txt"), "ok").unwrap();
        // Sidecar yerine aynı adda bir dizin varsa atlanıp orijinale düşmeli
        std::fs::create_dir_all(root.join("safe.txt.br")).unwrap();

        let handler = StaticFileHandler::new(&root);
        assert!(matches!(
            handler.resolve_with_sidecar("/../secret.txt", Some("br"), true, true, true),
            Err(StaticError::InvalidPath)
        ));

        let safe = handler
            .resolve_with_sidecar("/safe.txt", Some("br"), true, true, true)
            .unwrap();
        assert_eq!(safe.encoding, None);
        assert!(safe.path.ends_with("safe.txt"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_error_doc_resolver_traversal_and_size_limit() {
        let base = temp_root("error_docs");
        let doc_root = base.join("public");
        let custom_err = doc_root.join("errors");
        let outside_err = base.join("outside_secret.html");
        std::fs::create_dir_all(&custom_err).unwrap();
        std::fs::write(doc_root.join("404.html"), b"<h1>Bulunamadi</h1>").unwrap();
        std::fs::write(custom_err.join("502.html"), b"<h1>Ag Gecidi Hatasi</h1>").unwrap();
        std::fs::write(&outside_err, b"GIZLI_ICERIK").unwrap();
        std::fs::write(doc_root.join(".env"), b"DB_PASS=123").unwrap();

        // 512 KiB sınırında ve sınırı aşan dosyalar
        std::fs::write(
            doc_root.join("exact_limit.html"),
            vec![b'a'; MAX_ERROR_DOC_BYTES],
        )
        .unwrap();
        std::fs::write(
            doc_root.join("too_big.html"),
            vec![b'b'; MAX_ERROR_DOC_BYTES + 1],
        )
        .unwrap();

        let handler = StaticFileHandler::new(&doc_root);

        assert_eq!(
            handler
                .resolve_error_doc_file(&doc_root, None, "404.html")
                .unwrap(),
            b"<h1>Bulunamadi</h1>"
        );
        assert_eq!(
            handler
                .resolve_error_doc_file(&doc_root, Some(Path::new("errors")), "502.html")
                .unwrap(),
            b"<h1>Ag Gecidi Hatasi</h1>"
        );
        assert_eq!(
            handler
                .resolve_error_doc_file(&doc_root, None, "exact_limit.html")
                .unwrap()
                .len(),
            MAX_ERROR_DOC_BYTES
        );

        // Boyut aşımı engellenmeli
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, None, "too_big.html"),
            Err(StaticError::TooLarge { .. })
        ));

        // Bağıl ve mutlak traversal denemeleri kesin engellenmeli
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, None, "../outside_secret.html"),
            Err(StaticError::InvalidPath)
        ));
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, None, "errors/../../outside_secret.html"),
            Err(StaticError::InvalidPath)
        ));
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, None, "/etc/passwd"),
            Err(StaticError::InvalidPath)
        ));
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, None, outside_err.to_str().unwrap()),
            Err(StaticError::InvalidPath)
        ));
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, None, ".env"),
            Err(StaticError::InvalidPath)
        ));
        assert!(matches!(
            handler.resolve_error_doc_file(&doc_root, Some(Path::new("..")), "outside_secret.html"),
            Err(StaticError::InvalidPath)
        ));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_render_directory_listing_xss_escape_and_dotfiles() {
        let root = temp_root("autoindex_xss");
        std::fs::create_dir_all(root.join("alt_klasor")).unwrap();
        std::fs::write(root.join("normal.txt"), b"merhaba").unwrap();
        std::fs::write(root.join(".env"), b"SECRET").unwrap();

        // Windows dosya adlarında `<`, `>`, `"` yasak olduğundan `&` ve `'` ile gerçek dosya oluşturup
        // ek olarak `request_path` içinde tüm 5 XSS karakterini (`<`, `>`, `&`, `"`, `'`) test ediyoruz;
        // Unix'te tüm özel karakterli dosya adı da oluşturulur.
        std::fs::write(root.join("rapor'2026&ozet.txt"), b"veri").unwrap();
        #[cfg(unix)]
        std::fs::write(root.join("<script>alert(\"xss\")</script>.txt"), b"x").unwrap();

        let html = render_directory_listing("/klasor/<script>\"'&test/", &root).unwrap();

        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;&quot;&#x27;&amp;test/"));
        assert!(html.contains("rapor&#x27;2026&amp;ozet.txt"));
        assert!(html.contains("href=\"rapor%272026%26ozet.txt\""));
        assert!(html.contains("alt_klasor/"));
        assert!(html.contains("normal.txt"));
        assert!(!html.contains(".env"));

        #[cfg(unix)]
        {
            assert!(html.contains("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;.txt"));
            assert!(!html.contains("alert(\"xss\")"));
        }

        assert_eq!(
            escape_html("<div class=\"x\" data-a='y'>a&b</div>"),
            "&lt;div class=&quot;x&quot; data-a=&#x27;y&#x27;&gt;a&amp;b&lt;/div&gt;"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_sendfile_and_cross_platform_fallback() {
        let root = temp_root("sendfile_fallback");
        let file_path = root.join("payload.bin");
        std::fs::write(&file_path, b"0123456789ABCDEF").unwrap();

        #[cfg(not(target_os = "linux"))]
        {
            assert!(!is_sendfile_supported());
            let mut off = 0u64;
            let err = try_sendfile_chunk(0, 0, &mut off, 10).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        }

        let mut file = std::fs::File::open(&file_path).unwrap();
        let mut out = Vec::new();
        let mut offset = 4u64;
        let copied = copy_file_chunk_fallback(&mut file, &mut out, &mut offset, 6).unwrap();
        assert_eq!(copied, 6);
        assert_eq!(offset, 10);
        assert_eq!(&out, b"456789");

        let _ = std::fs::remove_dir_all(&root);
    }

    static GLOBAL_ACME_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct ClearGlobalAcmeOnDrop;
    impl Drop for ClearGlobalAcmeOnDrop {
        fn drop(&mut self) {
            clear_global_acme_root();
        }
    }

    #[test]
    fn test_acme_common_root_and_vhost_docroot_resolution() {
        let _guard = GLOBAL_ACME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _reset = ClearGlobalAcmeOnDrop;
        let base = temp_root("acme_res_test");
        let vhost_docroot = base.join("vhost_docroot");
        let common_acme = base.join("common_acme");

        let vhost_acme_dir = vhost_docroot.join(".well-known").join("acme-challenge");
        let common_acme_dir = common_acme.join(".well-known").join("acme-challenge");

        std::fs::create_dir_all(&vhost_acme_dir).unwrap();
        std::fs::create_dir_all(&common_acme_dir).unwrap();

        // 1. Sadece vhost docroot altında olan token
        let vhost_token_content = "vhost-challenge-token-content-12345";
        std::fs::write(vhost_acme_dir.join("vhost-only-token"), vhost_token_content).unwrap();

        // 2. Sadece ortak kök (.well-known/acme-challenge) altında olan token
        let common_token_content = "common-challenge-token-content-67890";
        std::fs::write(
            common_acme_dir.join("common-only-token"),
            common_token_content,
        )
        .unwrap();

        // 3. Ortak kökün doğrudan altında (düz kök) olan token
        let flat_token_content = "flat-common-token-abcde";
        std::fs::write(common_acme.join("flat-only-token"), flat_token_content).unwrap();

        // 4. Hem vhost docroot hem ortak kökte olan token (öncelik vhost docroot olmalı)
        std::fs::write(vhost_acme_dir.join("both-token"), "vhost-version").unwrap();
        std::fs::write(common_acme_dir.join("both-token"), "common-version").unwrap();

        // 5. Gizli dosya ve traversal denemesi
        std::fs::write(vhost_acme_dir.join(".secret"), "gizli").unwrap();
        std::fs::write(base.join("outside.txt"), "disari").unwrap();

        let handler = StaticFileHandler::new(&vhost_docroot);

        // Test 1: vhost docroot'tan okuma
        let res1 = handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/vhost-only-token",
                Some(&common_acme),
            )
            .expect("vhost-only-token bulunmalı");
        assert_eq!(res1.mime_type, "text/plain; charset=utf-8");
        let c1 = std::fs::read_to_string(&res1.path).unwrap();
        assert_eq!(c1, vhost_token_content);

        // Test 2: Ortak kökten okuma (.well-known altı)
        let res2 = handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/common-only-token",
                Some(&common_acme),
            )
            .expect("common-only-token bulunmalı");
        assert_eq!(res2.mime_type, "text/plain; charset=utf-8");
        let c2 = std::fs::read_to_string(&res2.path).unwrap();
        assert_eq!(c2, common_token_content);

        // Test 3: Ortak kökten okuma (düz kök altı)
        let res3 = handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/flat-only-token",
                Some(&common_acme),
            )
            .expect("flat-only-token bulunmalı");
        assert_eq!(res3.mime_type, "text/plain; charset=utf-8");
        let c3 = std::fs::read_to_string(&res3.path).unwrap();
        assert_eq!(c3, flat_token_content);

        // Test 4: Öncelik kontrolü (vhost versiyonu dönmeli)
        let res4 = handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/both-token",
                Some(&common_acme),
            )
            .expect("both-token bulunmalı");
        let c4 = std::fs::read_to_string(&res4.path).unwrap();
        assert_eq!(c4, "vhost-version");

        // Test 5: Global ACME root ile resolve() ve resolve_acme_challenge()
        set_global_acme_root(&common_acme);
        let res5 = handler
            .resolve("/.well-known/acme-challenge/common-only-token")
            .expect("global_acme_root ile resolve() common-only-token bulmalı");
        assert_eq!(
            std::fs::read_to_string(&res5.path).unwrap(),
            common_token_content
        );

        let res5_direct = handler
            .resolve_acme_challenge("/.well-known/acme-challenge/common-only-token")
            .expect("resolve_acme_challenge bulmalı");
        assert_eq!(
            std::fs::read_to_string(&res5_direct.path).unwrap(),
            common_token_content
        );
        clear_global_acme_root();

        // Test 6: Güvenlik denetimleri (traversal, gizli dosya, geçersiz yollar)
        assert!(handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/../outside.txt",
                Some(&common_acme),
            )
            .is_none());
        assert!(handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/.secret",
                Some(&common_acme),
            )
            .is_none());
        assert!(handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/%2e%2e/outside.txt",
                Some(&common_acme),
            )
            .is_none());
        assert!(handler
            .resolve_acme_challenge_with_root("/.well-known/acme-challenge/", Some(&common_acme),)
            .is_none());
        assert!(handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/non-existent-token",
                Some(&common_acme),
            )
            .is_none());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_acme_root_precedence_and_no_cross_vhost_leak() {
        let _guard = GLOBAL_ACME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _reset = ClearGlobalAcmeOnDrop;

        let base = temp_root("acme_precedence");
        let docroot_a = base.join("www").join("site_a");
        let auto_common = base.join("common_acme");
        let explicit_global = base.join("explicit_global");
        let vhost_acme = base.join("vhost_a_acme");
        let other_vhost_acme = base.join("other_vhost_acme");

        for dir in [
            &docroot_a,
            &auto_common,
            &explicit_global,
            &vhost_acme,
            &other_vhost_acme,
        ] {
            std::fs::create_dir_all(dir.join(".well-known").join("acme-challenge")).unwrap();
        }
        std::fs::create_dir_all(base.join("conf").join("vhosts")).unwrap();

        // Komsu vhost dosyasi: baska vhost'un acme_root ayari auto_detect tarafindan sizdirilmamali
        std::fs::write(
            base.join("conf").join("vhosts").join("other.toml"),
            format!(
                "[vhost]\nname = \"other.test\"\n[vhost.acme]\nacme_root = \"{}\"\n",
                other_vhost_acme.display().to_string().replace('\\', "/")
            ),
        )
        .unwrap();
        std::fs::write(
            other_vhost_acme
                .join(".well-known")
                .join("acme-challenge")
                .join("other-only-token"),
            "OTHER_VHOST_SECRET_TOKEN",
        )
        .unwrap();

        std::fs::write(
            auto_common
                .join(".well-known")
                .join("acme-challenge")
                .join("shared-token"),
            "AUTO_DETECT_LOSER",
        )
        .unwrap();
        std::fs::write(
            explicit_global
                .join(".well-known")
                .join("acme-challenge")
                .join("shared-token"),
            "GLOBAL_ACME_WINNER",
        )
        .unwrap();
        std::fs::write(
            vhost_acme
                .join(".well-known")
                .join("acme-challenge")
                .join("shared-token"),
            "VHOST_ACME_WINNER",
        )
        .unwrap();

        let handler = StaticFileHandler::new(&docroot_a);

        // 1. Komsu vhost dosyasi uzerinden token sizmamali
        clear_global_acme_root();
        assert!(
            handler
                .resolve_acme_challenge("/.well-known/acme-challenge/other-only-token")
                .is_none(),
            "Baska vhost acme_root degeri otomatik tespit ile diger vhosta sizmamali"
        );

        // 2. set_global_acme_root() tanimliysa auto_detect common_acme yerine global kullanilmali
        set_global_acme_root(&explicit_global);
        let res_global = handler
            .resolve_acme_challenge("/.well-known/acme-challenge/shared-token")
            .expect("Global ACME root uzerinden bulunmali");
        assert_eq!(
            std::fs::read_to_string(&res_global.path).unwrap(),
            "GLOBAL_ACME_WINNER"
        );

        // 3. vhost acme_root tanimliysa global acme_root yerine vhost acme_root kullanilmali
        let res_vhost = handler
            .resolve_acme_challenge_with_root(
                "/.well-known/acme-challenge/shared-token",
                Some(&vhost_acme),
            )
            .expect("vHost ACME root uzerinden bulunmali");
        assert_eq!(
            std::fs::read_to_string(&res_vhost.path).unwrap(),
            "VHOST_ACME_WINNER"
        );

        clear_global_acme_root();
        let _ = std::fs::remove_dir_all(&base);
    }
}
