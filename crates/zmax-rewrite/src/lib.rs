//! # zmax-rewrite
//! WordPress, OpenCart, XenForo ve Laravel uyumlu URL yeniden yazma (rewrite), `.htaccess` ve `try_files` motoru.

pub mod htaccess;

use dashmap::DashMap;
use htaccess::{absolutize_location, expand_request_vars, HtAccess, Outcome, RequestCtx};
use regex::RegexBuilder;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

const DEFAULT_INDEX_FILES: &[&str] = &["index.php", "index.html", "index.htm"];

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
/// `+` karakteri URL yolunda literal `+` olarak korunur.
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

/// Ham ve decode edilmiş yolu traversal, NUL bayt ve gizli `.` segmentlerine karşı doğrular.
/// Güvenliyse başında `/` bulunan (ve gerekiyorsa sondaki `/` korunan) temiz yolu döndürür.
pub fn sanitize_and_decode_route_path(raw_path: &str) -> Option<String> {
    if raw_path.contains('\0') || raw_path.contains('\\') || raw_path.contains("..") {
        return None;
    }
    let raw_lower = raw_path.to_ascii_lowercase();
    if raw_lower.contains("%00")
        || raw_lower.contains("%5c")
        || raw_lower.contains("%2e%2e")
        || raw_lower.contains(".%2e")
        || raw_lower.contains("%2e.")
    {
        return None;
    }

    let decoded = percent_decode_path(raw_path)?;
    if decoded.contains('\0') || decoded.contains('\\') || decoded.contains("..") {
        return None;
    }
    let dec_lower = decoded.to_ascii_lowercase();
    if dec_lower.contains("%00") || dec_lower.contains("%5c") || dec_lower.contains("%2e%2e") {
        return None;
    }

    let trailing_slash = decoded.ends_with('/');
    let trimmed = decoded.trim_start_matches('/');
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if segments.is_empty() {
        return Some("/".to_string());
    }

    let is_acme_file =
        segments.len() >= 3 && segments[0] == ".well-known" && segments[1] == "acme-challenge";
    if is_acme_file {
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

    let rel = segments.join("/");
    if !Path::new(&rel)
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return None;
    }

    let mut clean = format!("/{rel}");
    if trailing_slash {
        clean.push('/');
    }
    Some(clean)
}

fn is_safe_index_entry(entry: &str) -> bool {
    if entry.is_empty() || entry.contains('\0') || entry.contains('\\') || entry.contains("..") {
        return false;
    }
    let mut has_normal = false;
    for comp in Path::new(entry).components() {
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

fn is_php_path(path: &str) -> bool {
    path.len() >= 4 && path[path.len() - 4..].eq_ignore_ascii_case(".php")
}

/// Verilen `doc_root` altındaki `.htaccess` dosyasını okur ve ayrıştırır.
/// Dosya yoksa veya okunamazsa `None` döndürür.
pub fn load_htaccess_for_root(doc_root: &Path) -> Option<HtAccess> {
    let ht_path = doc_root.join(".htaccess");
    let content = std::fs::read_to_string(ht_path).ok()?;
    Some(HtAccess::parse(&content))
}

/// Birleşik route çözümleyici için istek bağlamı.
#[derive(Debug, Clone)]
pub struct RouteRequest<'a> {
    pub doc_root: &'a Path,
    pub path: &'a str,
    pub query: &'a str,
    pub host: &'a str,
    pub https: bool,
    pub method: &'a str,
    pub remote_addr: &'a str,
    pub server_port: u16,
    pub headers: &'a [(String, String)],
    pub index_files: &'a [String],
    pub php_enabled: bool,
    pub try_files_enabled: bool,
}

impl<'a> RouteRequest<'a> {
    /// Varsayılan ayarlarla yeni bir yönlendirme isteği oluşturur.
    pub fn new(doc_root: &'a Path, path: &'a str) -> Self {
        Self {
            doc_root,
            path,
            query: "",
            host: "localhost",
            https: false,
            method: "GET",
            remote_addr: "127.0.0.1",
            server_port: 80,
            headers: &[],
            index_files: &[],
            php_enabled: true,
            try_files_enabled: true,
        }
    }
}

/// `.htaccess` + `try_files` birleşik çözümleme sonucu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    StaticFile { path: String, query: String },
    PhpScript { path: String, query: String },
    Redirect { status: u16, location: String },
    Forbidden,
    Gone,
    NotFound,
}

/// Birleşik route çözümleme sonucu ve varsa PHP `PATH_INFO`, ortam değişkenleri, dizin listeleme ve hata sayfası bilgileri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResolution {
    /// İsteğin nihai yönlendirme sonucu.
    pub outcome: RouteOutcome,
    /// Varsa `.php/...` sonrasındaki ek yol bilgisi (`PATH_INFO`), yoksa boş string.
    pub path_info: String,
    /// `[E=KEY:VAL]` bayraklarından toplanan ortam değişkenleri.
    pub env_vars: Vec<(String, String)>,
    /// `Options -Indexes` -> `Some(true)`, `Options +Indexes` -> `Some(false)`.
    pub disable_indexes: Option<bool>,
    /// `ErrorDocument <kod> <hedef>` eşlemeleri.
    pub error_documents: BTreeMap<u16, String>,
}

impl Default for RouteResolution {
    fn default() -> Self {
        Self {
            outcome: RouteOutcome::NotFound,
            path_info: String::new(),
            env_vars: Vec::new(),
            disable_indexes: None,
            error_documents: BTreeMap::new(),
        }
    }
}

impl RouteResolution {
    fn from_outcome(outcome: RouteOutcome) -> Self {
        Self {
            outcome,
            ..Self::default()
        }
    }

    fn with_metadata(
        mut self,
        env_vars: Vec<(String, String)>,
        disable_indexes: Option<bool>,
        error_documents: BTreeMap<u16, String>,
    ) -> Self {
        self.env_vars = env_vars;
        self.disable_indexes = disable_indexes;
        self.error_documents = error_documents;
        self
    }
}

/// VHost yapılandırmasından (`[[vhost.rewrite.rules]]`) gelen deklaratif yönlendirme kuralı.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclarativeRewriteRule {
    pub pattern: String,
    pub target: String,
    pub status: u16,
    pub flags: Vec<String>,
    pub last: bool,
}

#[derive(Debug, Clone)]
struct CachedHtAccess {
    modified: Option<SystemTime>,
    file_len: u64,
    htaccess: Arc<HtAccess>,
}

fn load_cached_htaccess(
    cache: &DashMap<PathBuf, CachedHtAccess>,
    dir: &Path,
) -> Option<Arc<HtAccess>> {
    let ht_path = dir.join(".htaccess");
    let Ok(meta) = std::fs::metadata(&ht_path) else {
        cache.remove(&ht_path);
        return None;
    };
    if !meta.is_file() {
        cache.remove(&ht_path);
        return None;
    }
    let modified = meta.modified().ok();
    let file_len = meta.len();

    if let Some(entry) = cache.get(&ht_path) {
        if entry.modified.is_some() && entry.modified == modified && entry.file_len == file_len {
            return Some(Arc::clone(&entry.htaccess));
        }
    }

    let content = std::fs::read_to_string(&ht_path).ok()?;
    let ht = Arc::new(HtAccess::parse(&content));
    cache.insert(
        ht_path,
        CachedHtAccess {
            modified,
            file_len,
            htaccess: Arc::clone(&ht),
        },
    );
    Some(ht)
}

/// `<doc_root>/.htaccess` ve alt dizin `.htaccess` kurallarını (`mtime` önbelleği ile) ve `try_files` çözümlemesini birleştiren yardımcı.
#[derive(Debug, Default)]
pub struct HtAccessResolver {
    htaccess: Option<HtAccess>,
    explicit_override: bool,
    cache: DashMap<PathBuf, CachedHtAccess>,
}

impl HtAccessResolver {
    /// Boş `mtime` önbellekli yeni bir çözümleyici oluşturur.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verilen `doc_root` dizininden `.htaccess` dosyasını yükleyip önbelleğe alarak çözümleyici oluşturur.
    pub fn from_doc_root(doc_root: &Path) -> Self {
        let cache = DashMap::new();
        let root_dir = std::fs::canonicalize(doc_root).unwrap_or_else(|_| doc_root.to_path_buf());
        let htaccess = load_cached_htaccess(&cache, &root_dir).map(|arc| (*arc).clone());
        Self {
            htaccess,
            explicit_override: false,
            cache,
        }
    }

    /// Önceden ayrıştırılmış bir `HtAccess` örneğiyle çözümleyici oluşturur.
    pub fn from_htaccess(htaccess: Option<HtAccess>) -> Self {
        Self {
            htaccess,
            explicit_override: true,
            cache: DashMap::new(),
        }
    }

    pub fn htaccess(&self) -> Option<&HtAccess> {
        self.htaccess.as_ref()
    }

    /// Önbelleğe alınmış tüm `.htaccess` kayıtlarını temizler.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Şu anda önbellekte tutulan `.htaccess` dosya sayısını döndürür.
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    pub fn resolve(&self, req: &RouteRequest<'_>) -> RouteOutcome {
        self.resolve_with_info(req).outcome
    }

    /// İsteği `.htaccess` (`mtime` önbelleği + hiyerarşik alt dizin taraması) ve `try_files` ile tam `RouteResolution` olarak çözümler.
    pub fn resolve_with_info(&self, req: &RouteRequest<'_>) -> RouteResolution {
        if self.explicit_override {
            resolve_with_optional_htaccess_info(req, self.htaccess.as_ref())
        } else {
            resolve_hierarchical_with_cache(req, &self.cache)
        }
    }
}

/// `<doc_root>/.htaccess` (ve varsa alt dizin `.htaccess`) dosyalarını okuyarak isteği uçtan uca çözümler.
pub fn resolve_request_route(req: &RouteRequest<'_>) -> RouteOutcome {
    HtAccessResolver::from_doc_root(req.doc_root).resolve(req)
}

fn has_hidden_segment(path: &str) -> bool {
    path.split('/')
        .filter(|s| !s.is_empty())
        .any(|seg| seg.starts_with('.') || seg == "..")
}

fn resolve_php_path_info(
    doc_root: &Path,
    canonical_root: &Path,
    clean_path: &str,
    query: &str,
    php_enabled: bool,
) -> Option<RouteResolution> {
    if !clean_path.starts_with('/') {
        return None;
    }

    for (idx, _) in clean_path.match_indices('/') {
        if idx == 0 {
            continue;
        }
        let prefix = &clean_path[..idx];
        if !is_php_path(prefix) {
            continue;
        }
        let last_seg = prefix.rsplit('/').next().unwrap_or("");
        if last_seg.len() <= 4 || last_seg.starts_with('.') {
            continue;
        }

        let script_rel_fs = prefix.trim_start_matches('/');
        let cand = doc_root.join(script_rel_fs);
        let Ok(canon_cand) = std::fs::canonicalize(&cand) else {
            continue;
        };
        if !canon_cand.starts_with(canonical_root) || !canon_cand.is_file() {
            continue;
        }

        let remaining = &clean_path[idx..];
        let Some(clean_info) = sanitize_and_decode_route_path(remaining) else {
            return Some(RouteResolution::from_outcome(RouteOutcome::Forbidden));
        };
        if has_hidden_segment(&clean_info) {
            return Some(RouteResolution::from_outcome(RouteOutcome::Forbidden));
        }

        if !php_enabled {
            return Some(RouteResolution::from_outcome(RouteOutcome::Forbidden));
        }

        return Some(RouteResolution {
            outcome: RouteOutcome::PhpScript {
                path: prefix.to_string(),
                query: query.to_string(),
            },
            path_info: clean_info,
            ..RouteResolution::default()
        });
    }

    None
}

fn resolve_filesystem_target_with_info(
    doc_root: &Path,
    canonical_root: &Path,
    clean_path: &str,
    query: &str,
    index_files: &[&str],
    php_enabled: bool,
) -> Option<RouteResolution> {
    if let Some(outcome) = resolve_filesystem_target(
        doc_root,
        canonical_root,
        clean_path,
        query,
        index_files,
        php_enabled,
    ) {
        return Some(RouteResolution::from_outcome(outcome));
    }

    resolve_php_path_info(doc_root, canonical_root, clean_path, query, php_enabled)
}

fn resolve_filesystem_target(
    doc_root: &Path,
    canonical_root: &Path,
    clean_path: &str,
    query: &str,
    index_files: &[&str],
    php_enabled: bool,
) -> Option<RouteOutcome> {
    let rel = clean_path.trim_matches('/');
    let target: PathBuf = if rel.is_empty() {
        canonical_root.to_path_buf()
    } else {
        doc_root.join(rel)
    };

    let canonical_target = std::fs::canonicalize(&target).ok()?;
    if !canonical_target.starts_with(canonical_root) {
        return None;
    }

    if canonical_target.is_file() {
        if clean_path.ends_with('/') && clean_path != "/" {
            return None;
        }
        if is_php_path(clean_path) {
            return Some(if php_enabled {
                RouteOutcome::PhpScript {
                    path: clean_path.to_string(),
                    query: query.to_string(),
                }
            } else {
                RouteOutcome::Forbidden
            });
        }
        return Some(RouteOutcome::StaticFile {
            path: clean_path.to_string(),
            query: query.to_string(),
        });
    }

    if canonical_target.is_dir() {
        // ACME dizinleri index aramasına kapalıdır
        if rel == ".well-known" || rel.starts_with(".well-known/acme-challenge") {
            return None;
        }
        for idx in index_files {
            if !is_safe_index_entry(idx) {
                continue;
            }
            let cand = canonical_target.join(idx);
            if let Ok(canon_cand) = std::fs::canonicalize(&cand) {
                if canon_cand.starts_with(&canonical_target) && canon_cand.is_file() {
                    let joined = if rel.is_empty() {
                        format!("/{idx}")
                    } else {
                        format!("/{rel}/{idx}")
                    };
                    if is_php_path(&joined) {
                        return Some(if php_enabled {
                            RouteOutcome::PhpScript {
                                path: joined,
                                query: query.to_string(),
                            }
                        } else {
                            RouteOutcome::Forbidden
                        });
                    }
                    return Some(RouteOutcome::StaticFile {
                        path: joined,
                        query: query.to_string(),
                    });
                }
            }
        }
    }

    None
}

fn merge_env_vars(dst: &mut Vec<(String, String)>, src: Vec<(String, String)>) {
    for (k, v) in src {
        if !dst.iter().any(|(ek, _)| *ek == k) {
            dst.push((k, v));
        }
    }
}

fn collect_hierarchical_htaccess(
    canonical_root: &Path,
    decoded_path: &str,
    cache: &DashMap<PathBuf, CachedHtAccess>,
) -> Vec<(Arc<HtAccess>, String)> {
    let mut chain = Vec::new();
    if let Some(root_ht) = load_cached_htaccess(cache, canonical_root) {
        chain.push((root_ht, "/".to_string()));
    }

    let mut cur_dir = canonical_root.to_path_buf();
    let mut cur_prefix = String::from("/");
    for seg in decoded_path
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
    {
        if seg.starts_with('.') || seg == ".." {
            break;
        }
        cur_dir.push(seg);
        let Ok(canon_sub) = std::fs::canonicalize(&cur_dir) else {
            break;
        };
        if !canon_sub.starts_with(canonical_root) || !canon_sub.is_dir() {
            break;
        }
        cur_prefix.push_str(seg);
        cur_prefix.push('/');
        if let Some(sub_ht) = load_cached_htaccess(cache, &canon_sub) {
            chain.push((sub_ht, cur_prefix.clone()));
        }
    }

    chain
}

fn resolve_chain_with_info(
    req: &RouteRequest<'_>,
    decoded_path: &str,
    canonical_root: &Path,
    chain: &[(&HtAccess, &str)],
) -> RouteResolution {
    // Üst dizinden alt dizine yapılandırma mirası (DirectoryIndex, Options -Indexes, ErrorDocument)
    let mut custom_indexes: Vec<&str> = if !req.index_files.is_empty() {
        req.index_files.iter().map(String::as_str).collect()
    } else {
        DEFAULT_INDEX_FILES.to_vec()
    };
    let mut disable_indexes: Option<bool> = None;
    let mut error_documents: BTreeMap<u16, String> = BTreeMap::new();

    for (ht, _) in chain {
        if !ht.directory_index.is_empty() {
            custom_indexes = ht.directory_index.iter().map(String::as_str).collect();
        }
        if ht.disable_indexes.is_some() {
            disable_indexes = ht.disable_indexes;
        }
        for (code, target) in &ht.error_documents {
            error_documents.insert(*code, target.clone());
        }
    }

    let mut collected_env: Vec<(String, String)> = Vec::new();
    let ctx = RequestCtx {
        path: decoded_path,
        query: req.query,
        host: req.host,
        https: req.https,
        method: req.method,
        doc_root: req.doc_root,
        remote_addr: req.remote_addr,
        server_port: req.server_port,
        headers: req.headers,
    };

    // <FilesMatch> ve <Files> kuralları (RewriteEngine Off olsa dahi hiyerarşik uygulanır)
    let filename = decoded_path.rsplit('/').next().unwrap_or("");
    if !filename.is_empty() {
        for (ht, _) in chain {
            for rule in &ht.files_matches {
                if rule.pattern.is_match(filename) && rule.denied {
                    return RouteResolution::from_outcome(RouteOutcome::Forbidden).with_metadata(
                        collected_env,
                        disable_indexes,
                        error_documents,
                    );
                }
            }
        }
    }

    // 2. En derin alt dizinden köke doğru `.htaccess` kurallarını değerlendir (alt dizin baskınlığı)
    for (ht, dir_prefix) in chain.iter().rev() {
        let eval = ht.evaluate_in_dir(&ctx, dir_prefix);
        merge_env_vars(&mut collected_env, eval.env_vars);
        match eval.outcome {
            Outcome::Redirect { status, location } => {
                return RouteResolution::from_outcome(RouteOutcome::Redirect { status, location })
                    .with_metadata(collected_env, disable_indexes, error_documents);
            }
            Outcome::Forbidden => {
                return RouteResolution::from_outcome(RouteOutcome::Forbidden).with_metadata(
                    collected_env,
                    disable_indexes,
                    error_documents,
                );
            }
            Outcome::Gone => {
                return RouteResolution::from_outcome(RouteOutcome::Gone).with_metadata(
                    collected_env,
                    disable_indexes,
                    error_documents,
                );
            }
            Outcome::Rewritten { path, query } => {
                let Some(safe_rewritten) = sanitize_and_decode_route_path(&path) else {
                    return RouteResolution::from_outcome(RouteOutcome::Forbidden).with_metadata(
                        collected_env,
                        disable_indexes,
                        error_documents,
                    );
                };
                if let Some(found) = resolve_filesystem_target_with_info(
                    req.doc_root,
                    canonical_root,
                    &safe_rewritten,
                    &query,
                    &custom_indexes,
                    req.php_enabled,
                ) {
                    return found.with_metadata(collected_env, disable_indexes, error_documents);
                }
                return RouteResolution::from_outcome(RouteOutcome::NotFound).with_metadata(
                    collected_env,
                    disable_indexes,
                    error_documents,
                );
            }
            Outcome::None => {
                if eval.matched_last || eval.engine_explicit_off {
                    break;
                }
            }
        }
    }

    // 3. Gerçek dosya, dizin index veya `.php/...` PATH_INFO kontrolü
    if let Some(found) = resolve_filesystem_target_with_info(
        req.doc_root,
        canonical_root,
        decoded_path,
        req.query,
        &custom_indexes,
        req.php_enabled,
    ) {
        return found.with_metadata(collected_env, disable_indexes, error_documents);
    }

    // 4. try_files fallback (/index.php)
    if req.try_files_enabled && req.php_enabled {
        let fallback = canonical_root.join("index.php");
        if let Ok(canon_fb) = std::fs::canonicalize(&fallback) {
            if canon_fb.starts_with(canonical_root) && canon_fb.is_file() {
                return RouteResolution::from_outcome(RouteOutcome::PhpScript {
                    path: "/index.php".to_string(),
                    query: req.query.to_string(),
                })
                .with_metadata(collected_env, disable_indexes, error_documents);
            }
        }
    }

    RouteResolution::from_outcome(RouteOutcome::NotFound).with_metadata(
        collected_env,
        disable_indexes,
        error_documents,
    )
}

fn resolve_hierarchical_with_cache(
    req: &RouteRequest<'_>,
    cache: &DashMap<PathBuf, CachedHtAccess>,
) -> RouteResolution {
    let Some(decoded_path) = sanitize_and_decode_route_path(req.path) else {
        return RouteResolution::from_outcome(RouteOutcome::Forbidden);
    };
    let Ok(canonical_root) = std::fs::canonicalize(req.doc_root) else {
        return RouteResolution::from_outcome(RouteOutcome::NotFound);
    };
    let owned_chain = collect_hierarchical_htaccess(&canonical_root, &decoded_path, cache);
    let borrowed: Vec<(&HtAccess, &str)> = owned_chain
        .iter()
        .map(|(ht, prefix)| (ht.as_ref(), prefix.as_str()))
        .collect();
    resolve_chain_with_info(req, &decoded_path, &canonical_root, &borrowed)
}

fn resolve_with_optional_htaccess_info(
    req: &RouteRequest<'_>,
    htaccess: Option<&HtAccess>,
) -> RouteResolution {
    // 1. Ham ve çözülmüş yol üzerinde traversal + gizli dosya koruması
    let Some(decoded_path) = sanitize_and_decode_route_path(req.path) else {
        return RouteResolution::from_outcome(RouteOutcome::Forbidden);
    };

    let Ok(canonical_root) = std::fs::canonicalize(req.doc_root) else {
        return RouteResolution::from_outcome(RouteOutcome::NotFound);
    };

    let chain: Vec<(&HtAccess, &str)> = match htaccess {
        Some(ht) => vec![(ht, "/")],
        None => Vec::new(),
    };
    resolve_chain_with_info(req, &decoded_path, &canonical_root, &chain)
}

/// VHost yapılandırmasındaki deklaratif `[[vhost.rewrite.rules]]` kurallarını sırayla değerlendirir.
/// Eşleşen bir yeniden yazma, yönlendirme veya erişim engeli varsa `Some(RouteResolution)` döner.
pub fn evaluate_declarative_rules(
    req: &RouteRequest<'_>,
    rules: &[DeclarativeRewriteRule],
) -> Option<RouteResolution> {
    if rules.is_empty() {
        return None;
    }
    let Some(decoded_path) = sanitize_and_decode_route_path(req.path) else {
        return Some(RouteResolution::from_outcome(RouteOutcome::Forbidden));
    };

    let mut path = decoded_path;
    let mut query = req.query.to_string();
    let mut changed = false;
    let mut matched_last = false;
    let mut env_vars: Vec<(String, String)> = Vec::new();

    for rule in rules {
        let mut nc = false;
        let mut qsa = false;
        let mut qsd = false;
        let mut flag_last = false;
        let mut flag_forbidden = false;
        let mut flag_gone = false;
        let mut flag_redirect: Option<u16> = None;
        let mut rule_envs: Vec<(String, String)> = Vec::new();

        for raw in &rule.flags {
            let inner = raw.trim().trim_start_matches('[').trim_end_matches(']');
            for part in inner.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                let (k, v) = match p.split_once('=') {
                    Some((k, v)) => (k.trim().to_ascii_lowercase(), Some(v.trim())),
                    None => (p.to_ascii_lowercase(), None),
                };
                match k.as_str() {
                    "l" | "last" | "end" => flag_last = true,
                    "nc" | "nocase" => nc = true,
                    "qsa" | "qsappend" => qsa = true,
                    "qsd" | "qsdiscard" => qsd = true,
                    "f" | "forbidden" => flag_forbidden = true,
                    "g" | "gone" => flag_gone = true,
                    "r" | "redirect" => {
                        flag_redirect = Some(match v {
                            Some("permanent") => 301,
                            Some("temp") => 302,
                            Some("seeother") => 303,
                            Some(n) => n.parse().unwrap_or(302),
                            None => 302,
                        });
                    }
                    "e" | "env" => {
                        if let Some(raw_env) = v {
                            if let Some((ek, ev)) = raw_env.split_once(':') {
                                let key = ek.trim();
                                if !key.is_empty() && !key.starts_with('!') {
                                    rule_envs.push((key.to_string(), ev.to_string()));
                                }
                            } else if !raw_env.is_empty() && !raw_env.starts_with('!') {
                                rule_envs.push((raw_env.to_string(), String::new()));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let Ok(re) = RegexBuilder::new(&rule.pattern)
            .case_insensitive(nc)
            .build()
        else {
            continue;
        };

        let caps_opt = re.captures(&path).or_else(|| {
            if !rule.pattern.starts_with("^/") && !rule.pattern.starts_with('/') {
                re.captures(path.trim_start_matches('/'))
            } else {
                None
            }
        });
        let Some(caps) = caps_opt else {
            continue;
        };

        let rule_caps: Vec<String> = caps
            .iter()
            .map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default())
            .collect();

        let ctx = RequestCtx {
            path: &path,
            query: &query,
            host: req.host,
            https: req.https,
            method: req.method,
            doc_root: req.doc_root,
            remote_addr: req.remote_addr,
            server_port: req.server_port,
            headers: req.headers,
        };

        for (ek, ev) in &rule_envs {
            let expanded_val = expand_request_vars(ev, Some(&rule_caps), None, &ctx, &path, &query);
            if let Some((_, existing)) = env_vars.iter_mut().find(|(k, _)| *k == *ek) {
                *existing = expanded_val;
            } else {
                env_vars.push((ek.clone(), expanded_val));
            }
        }

        if rule.status == 403 || flag_forbidden {
            return Some(
                RouteResolution::from_outcome(RouteOutcome::Forbidden).with_metadata(
                    env_vars,
                    None,
                    BTreeMap::new(),
                ),
            );
        }
        if rule.status == 410 || flag_gone {
            return Some(
                RouteResolution::from_outcome(RouteOutcome::Gone).with_metadata(
                    env_vars,
                    None,
                    BTreeMap::new(),
                ),
            );
        }

        let redirect_status = if (300..400).contains(&rule.status) {
            Some(rule.status)
        } else {
            flag_redirect
        };

        let expanded =
            expand_request_vars(&rule.target, Some(&rule_caps), None, &ctx, &path, &query);
        let mut new_path = path.clone();
        let mut new_query = query.clone();
        let external = expanded.starts_with("http://") || expanded.starts_with("https://");

        if expanded != "-" && !expanded.is_empty() {
            let (p_part, q_part) = match expanded.split_once('?') {
                Some((p, q)) => (p.to_string(), Some(q.to_string())),
                None => (expanded.clone(), None),
            };
            if external {
                let mut loc = p_part;
                let q = match (q_part, qsa, query.is_empty()) {
                    (Some(q), true, false) => format!("{q}&{query}"),
                    (Some(q), _, _) => q,
                    (None, _, _) if qsd => String::new(),
                    (None, _, _) => query.clone(),
                };
                if !q.is_empty() {
                    loc.push('?');
                    loc.push_str(&q);
                }
                return Some(
                    RouteResolution::from_outcome(RouteOutcome::Redirect {
                        status: redirect_status.unwrap_or(302),
                        location: loc,
                    })
                    .with_metadata(env_vars, None, BTreeMap::new()),
                );
            }
            new_path = if p_part.starts_with('/') {
                p_part
            } else {
                format!("/{p_part}")
            };
            new_query = match (q_part, qsa, query.is_empty()) {
                (Some(q), true, false) => format!("{q}&{query}"),
                (Some(q), _, _) => q,
                (None, _, _) if qsd => String::new(),
                (None, _, _) => query.clone(),
            };
        }

        if let Some(code) = redirect_status {
            let mut loc = new_path.clone();
            if !new_query.is_empty() {
                loc.push('?');
                loc.push_str(&new_query);
            }
            return Some(
                RouteResolution::from_outcome(RouteOutcome::Redirect {
                    status: code,
                    location: absolutize_location(&loc, &ctx),
                })
                .with_metadata(env_vars, None, BTreeMap::new()),
            );
        }

        if new_path != path || new_query != query {
            path = new_path;
            query = new_query;
            changed = true;
        }

        if rule.last || flag_last {
            matched_last = true;
            break;
        }
    }

    if !changed && !matched_last {
        return None;
    }

    let Some(safe_path) = sanitize_and_decode_route_path(&path) else {
        return Some(
            RouteResolution::from_outcome(RouteOutcome::Forbidden).with_metadata(
                env_vars,
                None,
                BTreeMap::new(),
            ),
        );
    };

    let Ok(canonical_root) = std::fs::canonicalize(req.doc_root) else {
        return Some(
            RouteResolution::from_outcome(RouteOutcome::NotFound).with_metadata(
                env_vars,
                None,
                BTreeMap::new(),
            ),
        );
    };
    let custom_indexes: Vec<&str> = if !req.index_files.is_empty() {
        req.index_files.iter().map(String::as_str).collect()
    } else {
        DEFAULT_INDEX_FILES.to_vec()
    };

    if let Some(found) = resolve_filesystem_target_with_info(
        req.doc_root,
        &canonical_root,
        &safe_path,
        &query,
        &custom_indexes,
        req.php_enabled,
    ) {
        return Some(found.with_metadata(env_vars, None, BTreeMap::new()));
    }

    Some(
        RouteResolution::from_outcome(RouteOutcome::NotFound).with_metadata(
            env_vars,
            None,
            BTreeMap::new(),
        ),
    )
}

pub struct RewriteEngine;

impl Default for RewriteEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RewriteEngine {
    pub fn new() -> Self {
        Self
    }

    /// `.htaccess` kuralları + `try_files` fallback ile isteği çözümler.
    pub fn resolve_request(&self, req: &RouteRequest<'_>) -> RouteOutcome {
        self.resolve_request_with_info(req).outcome
    }

    /// `.htaccess` kuralları + `try_files` fallback ile isteği çözümler ve varsa `PATH_INFO` bilgisini döndürür.
    pub fn resolve_request_with_info(&self, req: &RouteRequest<'_>) -> RouteResolution {
        HtAccessResolver::from_doc_root(req.doc_root).resolve_with_info(req)
    }

    /// Önceden yüklenmiş opsiyonel `HtAccess` kullanarak isteği çözümler.
    pub fn resolve_with_htaccess(
        &self,
        req: &RouteRequest<'_>,
        htaccess: Option<&HtAccess>,
    ) -> RouteOutcome {
        self.resolve_with_htaccess_info(req, htaccess).outcome
    }

    /// Önceden yüklenmiş opsiyonel `HtAccess` kullanarak isteği çözümler ve varsa `PATH_INFO` bilgisini döndürür.
    pub fn resolve_with_htaccess_info(
        &self,
        req: &RouteRequest<'_>,
        htaccess: Option<&HtAccess>,
    ) -> RouteResolution {
        resolve_with_optional_htaccess_info(req, htaccess)
    }

    /// WordPress, OpenCart, XenForo standart try_files $uri $uri/ /index.php?$args davranışı
    pub fn resolve_try_files<'a>(
        &self,
        doc_root: &Path,
        request_path: &'a str,
    ) -> ResolvedRoute<'a> {
        let clean_path = request_path.trim_start_matches('/');

        // Boş veya kök istek
        if clean_path.is_empty() {
            let index_php = doc_root.join("index.php");
            let index_html = doc_root.join("index.html");
            if index_php.is_file() {
                return ResolvedRoute::PhpScript("/index.php");
            } else if index_html.is_file() {
                return ResolvedRoute::StaticFile("/index.html");
            }
        }

        let target = doc_root.join(clean_path);

        // 1. Gerçek fiziksel bir dosya mı? (CSS, JS, resim, pdf vb.)
        if target.is_file() {
            return ResolvedRoute::StaticFile(request_path);
        }

        // 2. Fiziksel bir alt dizin mi?
        if target.is_dir() {
            let index_php = target.join("index.php");
            let index_html = target.join("index.html");
            if index_php.is_file() {
                return ResolvedRoute::PhpScript("/index.php");
            } else if index_html.is_file() {
                return ResolvedRoute::StaticFile("/index.html");
            }
        }

        // 3. Dosya yoksa: OpenCart, XenForo, WordPress veya Laravel ana yönlendiricisine aktar
        ResolvedRoute::PhpScript("/index.php")
    }
}

#[derive(Debug, PartialEq)]
pub enum ResolvedRoute<'a> {
    StaticFile(&'a str),
    PhpScript(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn temp_site(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zmax_rw_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const WP_HTACCESS: &str = r#"# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
"#;

    const LARAVEL_HTACCESS: &str = r#"<IfModule mod_rewrite.c>
    <IfModule mod_negotiation.c>
        Options -MultiViews -Indexes
    </IfModule>

    RewriteEngine On

    RewriteCond %{HTTP:Authorization} .
    RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]

    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} (.+)/$
    RewriteRule ^ %1 [L,R=301]

    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^ index.php [L]
</IfModule>
"#;

    #[test]
    fn test_cms_rewrite_resolution() {
        let temp_dir = std::env::temp_dir().join("zmax_rewrite_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let _ = File::create(temp_dir.join("index.php"));
        let _ = File::create(temp_dir.join("style.css"));

        let engine = RewriteEngine::new();

        // 1. Gerçek dosya isteği -> Statik dosya olarak çözülmeli
        let res_static = engine.resolve_try_files(&temp_dir, "/style.css");
        assert_eq!(res_static, ResolvedRoute::StaticFile("/style.css"));

        // 2. WordPress kalıcı bağlantı (/ornek-yazi/) -> /index.php'ye yönlenmeli
        let res_wp = engine.resolve_try_files(&temp_dir, "/ornek-yazi/");
        assert_eq!(res_wp, ResolvedRoute::PhpScript("/index.php"));

        // 3. OpenCart SEO URL (/kategori/urun-123) -> /index.php'ye yönlenmeli
        let res_oc = engine.resolve_try_files(&temp_dir, "/kategori/urun-123");
        assert_eq!(res_oc, ResolvedRoute::PhpScript("/index.php"));

        // 4. XenForo forum konusu (/threads/baslik.102/) -> /index.php'ye yönlenmeli
        let res_xf = engine.resolve_try_files(&temp_dir, "/threads/baslik.102/");
        assert_eq!(res_xf, ResolvedRoute::PhpScript("/index.php"));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wordpress_htaccess_permalinks_and_encoded_media() {
        let root = temp_site("wp_full");
        let uploads = root.join("wp-content").join("uploads");
        let wp_admin = root.join("wp-admin");
        std::fs::create_dir_all(&uploads).unwrap();
        std::fs::create_dir_all(&wp_admin).unwrap();
        std::fs::write(root.join(".htaccess"), WP_HTACCESS).unwrap();
        std::fs::write(root.join("index.php"), "<?php // wp").unwrap();
        std::fs::write(wp_admin.join("index.php"), "<?php // admin").unwrap();
        std::fs::write(uploads.join("resim 1.jpg"), b"jpeg").unwrap();
        std::fs::write(uploads.join("çiçek bahçesi.webp"), b"webp").unwrap();
        std::fs::write(root.join(".env"), "DB_PASS=123").unwrap();

        assert!(load_htaccess_for_root(&root).is_some());

        // WordPress kalıcı bağlantıları /index.php'ye çözülmeli
        for permalink in [
            "/merhaba-dunya/",
            "/2026/11/yazi/",
            "/wp-json/wp/v2/posts",
            "/t%C3%BCrk%C3%A7e-yaz%C4%B1/",
        ] {
            let mut req = RouteRequest::new(&root, permalink);
            req.query = "page=2";
            assert_eq!(
                resolve_request_route(&req),
                RouteOutcome::PhpScript {
                    path: "/index.php".into(),
                    query: "page=2".into()
                },
                "Başarısız permalink: {permalink}"
            );
        }

        // Kök istek ve fiziksel alt dizin (wp-admin)
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/")),
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: String::new()
            }
        );
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/wp-admin/")),
            RouteOutcome::PhpScript {
                path: "/wp-admin/index.php".into(),
                query: String::new()
            }
        );

        // Yüzde kodlamalı gerçek medya dosyaları statik dosya olarak çözülmeli
        assert_eq!(
            resolve_request_route(&RouteRequest::new(
                &root,
                "/wp-content/uploads/resim%201.jpg"
            )),
            RouteOutcome::StaticFile {
                path: "/wp-content/uploads/resim 1.jpg".into(),
                query: String::new()
            }
        );
        assert_eq!(
            resolve_request_route(&RouteRequest::new(
                &root,
                "/wp-content/uploads/%C3%A7i%C3%A7ek%20bah%C3%A7esi.webp"
            )),
            RouteOutcome::StaticFile {
                path: "/wp-content/uploads/çiçek bahçesi.webp".into(),
                query: String::new()
            }
        );

        // Gizli dosyalar ve path traversal kesin engellenmeli
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/.htaccess")),
            RouteOutcome::Forbidden
        );
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/.env")),
            RouteOutcome::Forbidden
        );
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/wp-content/%2e%2e/.env")),
            RouteOutcome::Forbidden
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_laravel_htaccess_and_turkish_routes() {
        let root = temp_site("laravel");
        let assets = root.join("assets");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(root.join(".htaccess"), LARAVEL_HTACCESS).unwrap();
        std::fs::write(root.join("index.php"), "<?php // laravel").unwrap();
        std::fs::write(assets.join("app+v2.js"), "console.log(1);").unwrap();

        let resolver = HtAccessResolver::from_doc_root(&root);

        // Laravel trailing slash -> 301 yönlendirme (sorgu varken bile çalışmalı)
        let mut req_slash = RouteRequest::new(&root, "/%C3%BCr%C3%BCnler/");
        req_slash.host = "app.test";
        req_slash.https = true;
        req_slash.query = "sayfa=3";
        assert_eq!(
            resolver.resolve(&req_slash),
            RouteOutcome::Redirect {
                status: 301,
                location: "https://app.test/ürünler?sayfa=3".into()
            }
        );

        // Trailing slash olmadan front controller (/index.php)
        let mut req_api = RouteRequest::new(&root, "/api/kullan%C4%B1c%C4%B1lar");
        req_api.query = "aktif=1";
        assert_eq!(
            resolver.resolve(&req_api),
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: "aktif=1".into()
            }
        );

        // '+' karakteri dosya yolunda literal kalır
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/assets/app+v2.js")),
            RouteOutcome::StaticFile {
                path: "/assets/app+v2.js".into(),
                query: String::new()
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_try_files_without_htaccess_and_acme_exception() {
        let root = temp_site("no_ht");
        let subdir = root.join("docs");
        let acme = root.join(".well-known").join("acme-challenge");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::create_dir_all(&acme).unwrap();
        std::fs::write(root.join("index.php"), "<?php").unwrap();
        std::fs::write(subdir.join("index.html"), "<h1>Docs</h1>").unwrap();
        std::fs::write(acme.join("token123"), "acme-ok").unwrap();

        assert!(load_htaccess_for_root(&root).is_none());

        let engine = RewriteEngine::new();

        // Alt dizin index.html çözümü
        assert_eq!(
            engine.resolve_request(&RouteRequest::new(&root, "/docs/")),
            RouteOutcome::StaticFile {
                path: "/docs/index.html".into(),
                query: String::new()
            }
        );

        // ACME doğrulama dosyası izinli
        assert_eq!(
            engine.resolve_request(&RouteRequest::new(
                &root,
                "/.well-known/acme-challenge/token123"
            )),
            RouteOutcome::StaticFile {
                path: "/.well-known/acme-challenge/token123".into(),
                query: String::new()
            }
        );

        // try_files açıkken olmayan yol -> /index.php
        assert_eq!(
            engine.resolve_request(&RouteRequest::new(&root, "/kategori/yaz%C4%B1m")),
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: String::new()
            }
        );

        // try_files kapalıyken olmayan yol -> NotFound
        let mut req_no_try = RouteRequest::new(&root, "/olmayan-sayfa");
        req_no_try.try_files_enabled = false;
        assert_eq!(engine.resolve_request(&req_no_try), RouteOutcome::NotFound);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_htaccess_redirect_forbidden_gone_and_directory_index() {
        let root = temp_site("ht_actions");
        std::fs::write(root.join("ozel.php"), "<?php // ozel").unwrap();
        std::fs::write(root.join("sayfa.php"), "<?php // sayfa").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "DirectoryIndex ozel.php index.html\n",
                "RewriteEngine On\n",
                "RewriteCond %{HTTP_USER_AGENT} kotu-bot [NC]\n",
                "RewriteRule ^ - [F]\n",
                "RewriteRule ^silinen-urun$ - [G]\n",
                "RewriteRule ^eski-kampanya$ /yeni-kampanya [R=301,L]\n",
                "RewriteRule ^u/(\\d+)$ /sayfa.php?id=$1 [QSA,L]\n",
            ),
        )
        .unwrap();

        // DirectoryIndex -> /ozel.php
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/")),
            RouteOutcome::PhpScript {
                path: "/ozel.php".into(),
                query: String::new()
            }
        );

        // [F] Forbidden
        let ua = vec![("User-Agent".into(), "KOTU-BOT/1.0".into())];
        let mut req_f = RouteRequest::new(&root, "/");
        req_f.headers = &ua;
        assert_eq!(resolve_request_route(&req_f), RouteOutcome::Forbidden);

        // [G] Gone
        assert_eq!(
            resolve_request_route(&RouteRequest::new(&root, "/silinen-urun")),
            RouteOutcome::Gone
        );

        // [R=301] Redirect
        let mut req_r = RouteRequest::new(&root, "/eski-kampanya");
        req_r.host = "magaza.test";
        req_r.https = true;
        assert_eq!(
            resolve_request_route(&req_r),
            RouteOutcome::Redirect {
                status: 301,
                location: "https://magaza.test/yeni-kampanya".into()
            }
        );

        // [QSA,L] Rewritten -> /sayfa.php + birleştirilmiş sorgu
        let mut req_qsa = RouteRequest::new(&root, "/u/77");
        req_qsa.query = "ref=anasayfa";
        assert_eq!(
            resolve_request_route(&req_qsa),
            RouteOutcome::PhpScript {
                path: "/sayfa.php".into(),
                query: "id=77&ref=anasayfa".into()
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_php_path_info_resolution_and_security() {
        let root = temp_site("path_info");
        let alt_dir = root.join("alt");
        std::fs::create_dir_all(&alt_dir).unwrap();
        std::fs::write(root.join("index.php"), "<?php // root").unwrap();
        std::fs::write(alt_dir.join("info.php"), "<?php // info").unwrap();
        std::fs::write(alt_dir.join("Api.PHP"), "<?php // api").unwrap();
        std::fs::write(root.join(".env"), "SECRET=1").unwrap();

        let engine = RewriteEngine::new();

        // 1. /index.php/urun/42?a=1 -> PhpScript { path: "/index.php", query: "a=1" } + path_info: "/urun/42"
        let mut req_urun = RouteRequest::new(&root, "/index.php/urun/42");
        req_urun.query = "a=1";
        assert_eq!(
            engine.resolve_request_with_info(&req_urun),
            RouteResolution {
                outcome: RouteOutcome::PhpScript {
                    path: "/index.php".into(),
                    query: "a=1".into(),
                },
                path_info: "/urun/42".into(),
                ..RouteResolution::default()
            }
        );
        // Geriye dönük uyumlu resolve_request aynı sonucu döndürmeli
        assert_eq!(
            engine.resolve_request(&req_urun),
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: "a=1".into(),
            }
        );

        // 2. /alt/info.php/v1/users/ -> trailing slash korunmalı
        assert_eq!(
            engine.resolve_request_with_info(&RouteRequest::new(&root, "/alt/info.php/v1/users/")),
            RouteResolution {
                outcome: RouteOutcome::PhpScript {
                    path: "/alt/info.php".into(),
                    query: String::new(),
                },
                path_info: "/v1/users/".into(),
                ..RouteResolution::default()
            }
        );

        // 3. Büyük/küçük harf duyarsız .PHP/ segment sınırı
        assert_eq!(
            engine.resolve_request_with_info(&RouteRequest::new(&root, "/alt/Api.PHP/v2/")),
            RouteResolution {
                outcome: RouteOutcome::PhpScript {
                    path: "/alt/Api.PHP".into(),
                    query: String::new(),
                },
                path_info: "/v2/".into(),
                ..RouteResolution::default()
            }
        );

        // 4. Gizli segment / traversal içeren PATH_INFO -> Forbidden (path_info: "")
        for bad_path in [
            "/index.php/../.env",
            "/index.php/.htaccess",
            "/index.php/%2e%2e/.env",
            "/index.php/.git/config",
        ] {
            assert_eq!(
                engine.resolve_request_with_info(&RouteRequest::new(&root, bad_path)),
                RouteResolution {
                    outcome: RouteOutcome::Forbidden,
                    path_info: String::new(),
                    ..RouteResolution::default()
                },
                "Engellenmesi gereken yol: {bad_path}"
            );
        }

        // Doğrudan resolve_filesystem_target_with_info çağrısında da gizli segment engellenmeli
        let canonical_root = std::fs::canonicalize(&root).unwrap();
        assert_eq!(
            resolve_filesystem_target_with_info(
                &root,
                &canonical_root,
                "/index.php/.well-known/acme-challenge/token",
                "",
                DEFAULT_INDEX_FILES,
                true,
            ),
            Some(RouteResolution {
                outcome: RouteOutcome::Forbidden,
                path_info: String::new(),
                ..RouteResolution::default()
            })
        );

        // 5. php_enabled = false iken /index.php/foo -> Forbidden
        let mut req_no_php = RouteRequest::new(&root, "/index.php/foo");
        req_no_php.php_enabled = false;
        assert_eq!(
            engine.resolve_request_with_info(&req_no_php),
            RouteResolution {
                outcome: RouteOutcome::Forbidden,
                path_info: String::new(),
                ..RouteResolution::default()
            }
        );

        // 6. Var olmayan /yok.php/foo (try_files_enabled = true) -> /index.php fallback (path_info: "")
        assert_eq!(
            engine.resolve_request_with_info(&RouteRequest::new(&root, "/yok.php/foo")),
            RouteResolution {
                outcome: RouteOutcome::PhpScript {
                    path: "/index.php".into(),
                    query: String::new(),
                },
                path_info: String::new(),
                ..RouteResolution::default()
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_htaccess_rewrite_preserves_php_path_info() {
        let root = temp_site("ht_path_info");
        let alt_dir = root.join("alt");
        std::fs::create_dir_all(&alt_dir).unwrap();
        std::fs::write(root.join("index.php"), "<?php // root").unwrap();
        std::fs::write(alt_dir.join("info.php"), "<?php // info").unwrap();

        let ht = HtAccess::parse(concat!(
            "RewriteEngine On\n",
            "RewriteRule ^api/(.*)$ /alt/info.php/$1 [QSA,L]\n",
        ));

        let engine = RewriteEngine::new();
        let mut req = RouteRequest::new(&root, "/api/v1/users/");
        req.query = "detay=1";

        let expected = RouteResolution {
            outcome: RouteOutcome::PhpScript {
                path: "/alt/info.php".into(),
                query: "detay=1".into(),
            },
            path_info: "/v1/users/".into(),
            ..RouteResolution::default()
        };

        assert_eq!(engine.resolve_with_htaccess_info(&req, Some(&ht)), expected);
        assert_eq!(
            engine.resolve_with_htaccess(&req, Some(&ht)),
            expected.outcome
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_htaccess_wp_front_controller_keeps_existing_php_path_info() {
        let root = temp_site("ht_wp_path_info");
        std::fs::write(root.join("index.php"), "<?php // front").unwrap();
        std::fs::write(root.join("php_test.php"), "<?php // endpoint").unwrap();

        let ht = HtAccess::parse(concat!(
            "RewriteEngine On\n",
            "RewriteCond %{REQUEST_FILENAME} !-f\n",
            "RewriteCond %{REQUEST_FILENAME} !-d\n",
            "RewriteRule ^ /index.php [L]\n",
        ));

        let engine = RewriteEngine::new();
        let mut req_info = RouteRequest::new(&root, "/php_test.php/urun/42");
        req_info.query = "a=1";
        assert_eq!(
            engine.resolve_with_htaccess_info(&req_info, Some(&ht)),
            RouteResolution {
                outcome: RouteOutcome::PhpScript {
                    path: "/php_test.php".into(),
                    query: "a=1".into(),
                },
                path_info: "/urun/42".into(),
                ..RouteResolution::default()
            }
        );

        let req_missing = RouteRequest::new(&root, "/olmayan-yazi");
        assert_eq!(
            engine.resolve_with_htaccess_info(&req_missing, Some(&ht)),
            RouteResolution {
                outcome: RouteOutcome::PhpScript {
                    path: "/index.php".into(),
                    query: String::new(),
                },
                path_info: String::new(),
                ..RouteResolution::default()
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_hierarchical_subdirectory_htaccess_dominance() {
        let root = temp_site("hier_sub");
        let sub = root.join("sub");
        let deep = sub.join("ozel");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(root.join("index.php"), "<?php // root").unwrap();
        std::fs::write(sub.join("detay.php"), "<?php // sub detay").unwrap();

        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "Options -Indexes\n",
                "ErrorDocument 404 /404.html\n",
                "ErrorDocument 500 /500.html\n",
                "RewriteEngine On\n",
                "RewriteCond %{REQUEST_FILENAME} !-f\n",
                "RewriteCond %{REQUEST_FILENAME} !-d\n",
                "RewriteRule . /index.php [L]\n",
            ),
        )
        .unwrap();

        std::fs::write(
            sub.join(".htaccess"),
            concat!(
                "ErrorDocument 404 /sub/404.html\n",
                "RewriteEngine On\n",
                "RewriteRule ^urun/(\\d+)$ detay.php?id=$1 [L]\n",
                "RewriteRule ^yonlendir$ /sub/hedef [R=302,L]\n",
            ),
        )
        .unwrap();

        std::fs::write(
            deep.join(".htaccess"),
            concat!("RewriteEngine On\n", "RewriteRule ^yasak$ - [F]\n",),
        )
        .unwrap();

        let resolver = HtAccessResolver::new();

        // Alt dizin kuralı kök WordPress yakalayıcısından baskın olmalı ve göreceli hedef `/sub/` ile çözülmeli
        let res_sub = resolver.resolve_with_info(&RouteRequest::new(&root, "/sub/urun/42"));
        assert_eq!(
            res_sub.outcome,
            RouteOutcome::PhpScript {
                path: "/sub/detay.php".into(),
                query: "id=42".into(),
            }
        );
        assert_eq!(res_sub.disable_indexes, Some(true));
        assert_eq!(
            res_sub.error_documents.get(&404).map(String::as_str),
            Some("/sub/404.html")
        );
        assert_eq!(
            res_sub.error_documents.get(&500).map(String::as_str),
            Some("/500.html")
        );

        // Alt dizinde [R=302,L] baskın olmalı
        let mut req_redir = RouteRequest::new(&root, "/sub/yonlendir");
        req_redir.host = "ornek.test";
        assert_eq!(
            resolver.resolve(&req_redir),
            RouteOutcome::Redirect {
                status: 302,
                location: "http://ornek.test/sub/hedef".into(),
            }
        );

        // En derin alt dizinde [F] baskın olmalı
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/sub/ozel/yasak")),
            RouteOutcome::Forbidden
        );

        // Alt dizinde eşleşmeyen yol kök kuralına düşebilmeli
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/sub/genel-yazi")),
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: String::new(),
            }
        );

        assert_eq!(resolver.cache_len(), 3);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_htaccess_mtime_cache_hit_and_invalidation() {
        let root = temp_site("mtime_cache");
        std::fs::write(root.join("a.php"), "<?php // a").unwrap();
        std::fs::write(root.join("b.php"), "<?php // b").unwrap();
        let ht_path = root.join(".htaccess");
        std::fs::write(&ht_path, "RewriteEngine On\nRewriteRule ^go$ /a.php [L]\n").unwrap();

        let resolver = HtAccessResolver::from_doc_root(&root);
        assert_eq!(resolver.cache_len(), 1);

        let canon_ht = std::fs::canonicalize(&ht_path).unwrap();
        let first_ptr = Arc::clone(&resolver.cache.get(&canon_ht).unwrap().htaccess);

        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/go")),
            RouteOutcome::PhpScript {
                path: "/a.php".into(),
                query: String::new(),
            }
        );

        // İkinci çağrıda dosya değişmediği için önbellek isabeti (aynı Arc örneği) korunmalı
        let second_ptr = Arc::clone(&resolver.cache.get(&canon_ht).unwrap().htaccess);
        assert!(Arc::ptr_eq(&first_ptr, &second_ptr));
        assert_eq!(resolver.cache_len(), 1);

        // Dosya güncellenince (mtime/uzunluk değişince) önbellek geçersiz kılınmalı
        std::thread::sleep(std::time::Duration::from_millis(30));
        std::fs::write(
            &ht_path,
            "RewriteEngine On\nRewriteRule ^go$ /b.php?from=updated [L]\n",
        )
        .unwrap();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&ht_path)
            .unwrap();
        let _ = f.set_modified(SystemTime::now() + std::time::Duration::from_secs(2));
        drop(f);

        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/go")),
            RouteOutcome::PhpScript {
                path: "/b.php".into(),
                query: "from=updated".into(),
            }
        );
        let third_ptr = Arc::clone(&resolver.cache.get(&canon_ht).unwrap().htaccess);
        assert!(!Arc::ptr_eq(&first_ptr, &third_ptr));

        // clear_cache sonrası cache_len() sıfırlanmalı ve sonraki resolve yeniden doldurmalı
        resolver.clear_cache();
        assert_eq!(resolver.cache_len(), 0);
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/go")),
            RouteOutcome::PhpScript {
                path: "/b.php".into(),
                query: "from=updated".into(),
            }
        );
        assert_eq!(resolver.cache_len(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_env_flag_http_authorization_and_forwarded_proto() {
        let root = temp_site("env_vars");
        std::fs::write(root.join("index.php"), "<?php // api").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "RewriteEngine On\n",
                "RewriteCond %{HTTP:Authorization} .\n",
                "RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]\n",
                "RewriteCond %{HTTP:X-Forwarded-Proto} ^https$ [NC]\n",
                "RewriteRule .* - [E=PROXY_HTTPS:on,E=REQ_TLS:%{HTTPS}]\n",
                "RewriteCond %{REQUEST_FILENAME} !-f\n",
                "RewriteRule ^ /index.php [L]\n",
            ),
        )
        .unwrap();

        let headers = vec![
            (
                "Authorization".to_string(),
                "Bearer gizli-token".to_string(),
            ),
            ("X-Forwarded-Proto".to_string(), "https".to_string()),
        ];
        let mut req = RouteRequest::new(&root, "/api/profil");
        req.headers = &headers;
        req.https = false;

        let resolver = HtAccessResolver::from_doc_root(&root);
        let res = resolver.resolve_with_info(&req);
        assert_eq!(
            res.outcome,
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: String::new(),
            }
        );
        assert!(res
            .env_vars
            .contains(&("HTTP_AUTHORIZATION".into(), "Bearer gizli-token".into())));
        assert!(res.env_vars.contains(&("PROXY_HTTPS".into(), "on".into())));
        assert!(res.env_vars.contains(&("REQ_TLS".into(), "off".into())));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_options_indexes_directive() {
        let root = temp_site("opt_indexes");
        let sub = root.join("public-files");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(root.join("index.php"), "<?php").unwrap();
        std::fs::write(root.join(".htaccess"), LARAVEL_HTACCESS).unwrap();
        std::fs::write(sub.join(".htaccess"), "Options +Indexes\n").unwrap();

        let resolver = HtAccessResolver::new();

        let res_root = resolver.resolve_with_info(&RouteRequest::new(&root, "/api/test"));
        assert_eq!(res_root.disable_indexes, Some(true));

        let res_sub = resolver.resolve_with_info(&RouteRequest::new(&root, "/public-files/"));
        assert_eq!(res_sub.disable_indexes, Some(false));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_error_document_directive() {
        let root = temp_site("err_doc");
        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "ErrorDocument 404 /custom404.html\n",
                "ErrorDocument 403 /errors/403.html\n",
            ),
        )
        .unwrap();

        let resolver = HtAccessResolver::from_doc_root(&root);
        let mut req = RouteRequest::new(&root, "/olmayan-sayfa");
        req.try_files_enabled = false;

        let res = resolver.resolve_with_info(&req);
        assert_eq!(res.outcome, RouteOutcome::NotFound);
        assert_eq!(
            res.error_documents.get(&404).map(String::as_str),
            Some("/custom404.html")
        );
        assert_eq!(
            res.error_documents.get(&403).map(String::as_str),
            Some("/errors/403.html")
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_ifmodule_blocks_and_unclosed_safety() {
        let root = temp_site("ifmodule");
        std::fs::write(root.join("ok.php"), "<?php // ok").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "<IfModule mod_unknown.c>\n",
                "RewriteRule .* - [F]\n",
                "</IfModule>\n",
                "<IfModule !mod_rewrite.c>\n",
                "RewriteRule .* - [F]\n",
                "</IfModule>\n",
                "<IfModule mod_rewrite.c>\n",
                "RewriteEngine On\n",
                "RewriteRule ^merhaba$ /ok.php [L]\n",
                // kasıtlı olarak kapatılmamış IfModule bloğu da güvenle işlenebilmeli
            ),
        )
        .unwrap();

        let resolver = HtAccessResolver::from_doc_root(&root);
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/merhaba")),
            RouteOutcome::PhpScript {
                path: "/ok.php".into(),
                query: String::new(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_htaccess_forbidden_and_flags_comprehensive() {
        let root = temp_site("flags_f");
        std::fs::write(root.join("hedef.php"), "<?php").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "RewriteEngine On\n",
                "RewriteRule ^gizli-panel$ - [F]\n",
                "RewriteRule ^eski-sayfa$ - [G]\n",
                "RewriteRule ^Gecici$ /hedef.php [NC,R,L]\n",
                "RewriteRule ^kalici/(.*)$ /yeni/$1 [R=301,L]\n",
                "RewriteRule ^urun/([0-9]+)$ /hedef.php?id=$1 [QSA,NC,L]\n",
            ),
        )
        .unwrap();

        let resolver = HtAccessResolver::from_doc_root(&root);
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/gizli-panel")),
            RouteOutcome::Forbidden
        );
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/eski-sayfa")),
            RouteOutcome::Gone
        );

        let mut req_r302 = RouteRequest::new(&root, "/gecici");
        req_r302.host = "site.test";
        assert_eq!(
            resolver.resolve(&req_r302),
            RouteOutcome::Redirect {
                status: 302,
                location: "http://site.test/hedef.php".into(),
            }
        );

        let mut req_r301 = RouteRequest::new(&root, "/kalici/yazi");
        req_r301.host = "site.test";
        req_r301.https = true;
        assert_eq!(
            resolver.resolve(&req_r301),
            RouteOutcome::Redirect {
                status: 301,
                location: "https://site.test/yeni/yazi".into(),
            }
        );

        let mut req_qsa = RouteRequest::new(&root, "/URUN/99");
        req_qsa.query = "sayfa=2";
        assert_eq!(
            resolver.resolve(&req_qsa),
            RouteOutcome::PhpScript {
                path: "/hedef.php".into(),
                query: "id=99&sayfa=2".into(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_declarative_vhost_rewrite_rules() {
        let root = temp_site("decl_rules");
        std::fs::write(root.join("urun.php"), "<?php // urun").unwrap();

        let rules = vec![
            DeclarativeRewriteRule {
                pattern: "^/yasakli/.*".into(),
                target: "-".into(),
                status: 403,
                flags: vec!["L".into()],
                last: true,
            },
            DeclarativeRewriteRule {
                pattern: "^/eski/(.*)$".into(),
                target: "/yeni/$1".into(),
                status: 301,
                flags: vec!["QSA".into()],
                last: true,
            },
            DeclarativeRewriteRule {
                pattern: "^/Urun/(\\d+)$".into(),
                target: "/urun.php?id=$1".into(),
                status: 0,
                flags: vec![
                    "NC".into(),
                    "QSA".into(),
                    "E=REWRITE_SRC:declarative".into(),
                ],
                last: true,
            },
        ];

        // 1. 403 Forbidden kuralı
        let res_f = evaluate_declarative_rules(&RouteRequest::new(&root, "/yasakli/panel"), &rules)
            .expect("403 kurali eslesmeli");
        assert_eq!(res_f.outcome, RouteOutcome::Forbidden);

        // 2. 301 Redirect + QSA
        let mut req_r = RouteRequest::new(&root, "/eski/kampanya");
        req_r.host = "shop.test";
        req_r.https = true;
        req_r.query = "ref=1";
        let res_r = evaluate_declarative_rules(&req_r, &rules).expect("301 kurali eslesmeli");
        assert_eq!(
            res_r.outcome,
            RouteOutcome::Redirect {
                status: 301,
                location: "https://shop.test/yeni/kampanya?ref=1".into(),
            }
        );

        // 3. İç PHP yönlendirmesi + [NC, QSA, E=...]
        let mut req_int = RouteRequest::new(&root, "/urun/55");
        req_int.query = "kur=TRY";
        let res_int = evaluate_declarative_rules(&req_int, &rules).expect("ic rewrite eslesmeli");
        assert_eq!(
            res_int.outcome,
            RouteOutcome::PhpScript {
                path: "/urun.php".into(),
                query: "id=55&kur=TRY".into(),
            }
        );
        assert_eq!(
            res_int.env_vars,
            vec![("REWRITE_SRC".into(), "declarative".into())]
        );

        // 4. Eşleşmeyen yol -> None
        assert!(
            evaluate_declarative_rules(&RouteRequest::new(&root, "/normal-sayfa"), &rules)
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_hierarchical_rewrite_engine_off_stops_parent_rules() {
        let root = temp_site("hier_off");
        let static_sub = root.join("raw");
        std::fs::create_dir_all(&static_sub).unwrap();
        std::fs::write(root.join("index.php"), "<?php").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            "RewriteEngine On\nRewriteRule . /index.php [L]\n",
        )
        .unwrap();
        std::fs::write(static_sub.join(".htaccess"), "RewriteEngine Off\n").unwrap();

        let resolver = HtAccessResolver::new();
        let mut req = RouteRequest::new(&root, "/raw/missing");
        req.try_files_enabled = false;
        assert_eq!(resolver.resolve(&req), RouteOutcome::NotFound);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_hierarchical_files_match_protection() {
        let root = temp_site("hier_fm");
        let sub = root.join("yedekler");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(root.join("index.php"), "<?php").unwrap();
        std::fs::write(sub.join("dump.sql"), "SQL DATA").unwrap();
        std::fs::write(sub.join("rapor.pdf"), "PDF DATA").unwrap();

        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "<FilesMatch \"\\.(env|sql|bak|ini)$\">\n",
                "    Require all denied\n",
                "</FilesMatch>\n",
                "RewriteEngine On\n",
                "RewriteCond %{REQUEST_FILENAME} !-f\n",
                "RewriteCond %{REQUEST_FILENAME} !-d\n",
                "RewriteRule . /index.php [L]\n",
            ),
        )
        .unwrap();

        let resolver = HtAccessResolver::new();

        // Kök seviyesindeki .env engellenmeli
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/.env")),
            RouteOutcome::Forbidden
        );

        // Alt dizindeki dump.sql kök <FilesMatch> kuralı nedeniyle engellenmeli
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/yedekler/dump.sql")),
            RouteOutcome::Forbidden
        );

        // Alt dizindeki rapor.pdf statik dosya olarak başarıyla sunulmalı
        assert_eq!(
            resolver.resolve(&RouteRequest::new(&root, "/yedekler/rapor.pdf")),
            RouteOutcome::StaticFile {
                path: "/yedekler/rapor.pdf".into(),
                query: String::new(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_zpanel_redirects_full_route_resolution() {
        let root = temp_site("zpanel_route");
        std::fs::write(root.join("index.php"), "<?php // WP").unwrap();
        std::fs::write(
            root.join(".htaccess"),
            concat!(
                "# BEGIN zPanel Redirects\n",
                "<IfModule mod_rewrite.c>\n",
                "RewriteEngine On\n\n",
                "# Force HTTPS\n",
                "RewriteCond %{HTTPS} off\n",
                "RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n",
                "# Enforce non-WWW\n",
                "RewriteCond %{HTTP_HOST} ^www\\.(.+)$ [NC]\n",
                "RewriteRule ^(.*)$ https://%1%{REQUEST_URI} [L,R=301]\n",
                "</IfModule>\n",
                "# BEGIN WordPress\n",
                "<IfModule mod_rewrite.c>\n",
                "RewriteEngine On\n",
                "RewriteBase /\n",
                "RewriteRule ^index\\.php$ - [L]\n",
                "RewriteCond %{REQUEST_FILENAME} !-f\n",
                "RewriteCond %{REQUEST_FILENAME} !-d\n",
                "RewriteRule . /index.php [L]\n",
                "</IfModule>\n",
                "# END WordPress\n",
            ),
        )
        .unwrap();

        let resolver = HtAccessResolver::from_doc_root(&root);

        // 1. HTTP isteği -> HTTPS'e 301 yönlenmeli
        let mut req_http = RouteRequest::new(&root, "/ornek-yazi/");
        req_http.host = "site.test";
        req_http.https = false;
        req_http.query = "sayfa=1";
        assert_eq!(
            resolver.resolve(&req_http),
            RouteOutcome::Redirect {
                status: 301,
                location: "https://site.test/ornek-yazi/?sayfa=1".into(),
            }
        );

        // 2. HTTPS www isteği -> non-WWW (%1) 301 yönlenmeli
        let mut req_www = RouteRequest::new(&root, "/ornek-yazi/");
        req_www.host = "www.site.test";
        req_www.https = true;
        req_www.query = "sayfa=1";
        assert_eq!(
            resolver.resolve(&req_www),
            RouteOutcome::Redirect {
                status: 301,
                location: "https://site.test/ornek-yazi/?sayfa=1".into(),
            }
        );

        // 3. Normal HTTPS isteği -> WordPress permalink /index.php'ye çözülmeli
        let mut req_https = RouteRequest::new(&root, "/ornek-yazi/");
        req_https.host = "site.test";
        req_https.https = true;
        req_https.query = "sayfa=1";
        assert_eq!(
            resolver.resolve(&req_https),
            RouteOutcome::PhpScript {
                path: "/index.php".into(),
                query: "sayfa=1".into(),
            }
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
