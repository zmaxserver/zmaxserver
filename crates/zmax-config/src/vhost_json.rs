//! # vhost_json
//! Sanal konak (vHost) yapılandırmalarının JSON REST API üzerinden tam alan
//! ayrıştırılması, doğrulanması, serileştirilmesi ve TOML turu (round-trip) eşitliği.

use std::collections::BTreeMap;
use std::path::Path;
use serde_json::{Map, Value};

use crate::{LoadedVHost, VHostEntry, VHostRewriteRule};

/// Bir JSON değerini metin (String) olarak doğrular ve döndürür.
pub fn val_as_str(v: &Value, field: &str) -> Result<String, String> {
    v.as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("'{}' alanı metin (string) olmalıdır", field))
}

/// Bir JSON değerini mantıksal (bool) olarak doğrular ve döndürür.
pub fn val_as_bool(v: &Value, field: &str) -> Result<bool, String> {
    v.as_bool()
        .ok_or_else(|| format!("'{}' alanı mantıksal (bool) olmalıdır", field))
}

/// Bir JSON değerini pozitif tamsayı (u64) olarak doğrular ve döndürür.
pub fn val_as_u64(v: &Value, field: &str) -> Result<u64, String> {
    v.as_u64()
        .ok_or_else(|| format!("'{}' alanı negatif olmayan tamsayı olmalıdır", field))
}

/// Bir JSON değerini usize olarak doğrular ve döndürür.
pub fn val_as_usize(v: &Value, field: &str) -> Result<usize, String> {
    let n = val_as_u64(v, field)?;
    usize::try_from(n).map_err(|_| format!("'{}' değeri taşma sınırını aşıyor", field))
}

/// Bir JSON değerini metin dizisi (Vec<String>) olarak doğrular ve döndürür.
pub fn val_as_string_list(v: &Value, field: &str) -> Result<Vec<String>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| format!("'{}' alanı dizi ([...]) olmalıdır", field))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| format!("'{}' dizisi yalnızca metin içermelidir", field))?;
        out.push(s.to_string());
    }
    Ok(out)
}

/// Bir JSON değerini `BTreeMap<u16, String>` (HTTP durum kodu -> sayfa yolu) olarak doğrular.
pub fn val_as_status_pages(v: &Value, field: &str) -> Result<BTreeMap<u16, String>, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| format!("'{}' alanı durum kodu eşleme nesnesi ({{...}}) olmalıdır", field))?;
    let mut pages = BTreeMap::new();
    for (k, val) in obj {
        let code: u16 = k
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("'{}' içinde geçersiz HTTP durum kodu: '{}'", field, k))?;
        if !(100..=599).contains(&code) {
            return Err(format!(
                "'{}' içinde HTTP durum kodu 100-599 aralığında olmalıdır: {}",
                field, code
            ));
        }
        let page = val
            .as_str()
            .ok_or_else(|| format!("'{}' sayfa yolu metin olmalıdır (kod {})", field, code))?;
        if has_parent_dir_traversal(page) {
            return Err(format!(
                "'{}' sayfa yolunda geçersiz dizin geçişi ('..'): '{}'",
                field, page
            ));
        }
        pages.insert(code, page.to_string());
    }
    Ok(pages)
}

/// Bir JSON değerini `Vec<VHostRewriteRule>` olarak doğrular.
pub fn val_as_rewrite_rules(v: &Value, field: &str) -> Result<Vec<VHostRewriteRule>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| format!("'{}' alanı kural dizisi ([...]) olmalıdır", field))?;
    let mut rules = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let obj = item.as_object().ok_or_else(|| {
            format!("'{}' içindeki {}. kural nesne ({{...}}) olmalıdır", field, idx)
        })?;
        let pattern = obj
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target = obj
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let status = if let Some(st_val) = obj.get("status") {
            let n = st_val.as_u64().ok_or_else(|| {
                format!("'{}' içindeki {}. kural status değeri sayı olmalıdır", field, idx)
            })?;
            u16::try_from(n).map_err(|_| {
                format!("'{}' içindeki {}. kural status değeri u16 sınırını aşıyor", field, idx)
            })?
        } else {
            0
        };
        if status != 0 && !(100..=599).contains(&status) {
            return Err(format!(
                "'{}' içindeki {}. kural status kodu 100-599 aralığında veya 0 olmalıdır: {}",
                field, idx, status
            ));
        }
        let flags = if let Some(flags_val) = obj.get("flags") {
            val_as_string_list(flags_val, &format!("{}[{}].flags", field, idx))?
        } else {
            Vec::new()
        };
        let last = if let Some(last_val) = obj.get("last") {
            last_val.as_bool().unwrap_or(false)
        } else {
            false
        };
        rules.push(VHostRewriteRule {
            pattern,
            target,
            status,
            flags,
            last,
        });
    }
    Ok(rules)
}

/// Yol enjeksiyonu (`..` veya `\0`) kontrolü yapar.
pub fn has_parent_dir_traversal(path: &str) -> bool {
    path.contains('\0') || path.split(['/', '\\']).any(|seg| seg == "..")
}

/// Alt nesneleri temel yapılandırma haritasına derinlemesine birleştirir.
pub fn merge_section_object(
    root: &mut Map<String, Value>,
    section_key: &str,
    patch: &Value,
) -> Result<(), String> {
    let patch_obj = patch.as_object().ok_or_else(|| {
        format!("'{}' alanı bir JSON nesnesi ({{...}}) olmalıdır", section_key)
    })?;
    let target_entry = root
        .entry(section_key.to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if !target_entry.is_object() {
        *target_entry = Value::Object(Map::new());
    }
    if let Some(target_map) = target_entry.as_object_mut() {
        for (k, v) in patch_obj {
            target_map.insert(k.clone(), v.clone());
        }
    }
    Ok(())
}

/// Gelen JSON gövdesini (bayt dizisi) temel `VHostEntry` üzerine uygular (patch),
/// tüm vHost alanlarını doğrular ve güncel `VHostEntry` nesnesini döndürür.
pub fn merge_vhost_json_patch(
    base: &VHostEntry,
    domain: &str,
    body: &[u8],
) -> Result<VHostEntry, String> {
    let parsed: Value = if body.iter().all(|b| b.is_ascii_whitespace()) {
        Value::Object(Map::new())
    } else {
        serde_json::from_slice(body).map_err(|e| format!("Geçersiz JSON gövdesi: {}", e))?
    };
    let obj = parsed
        .as_object()
        .ok_or_else(|| "JSON gövdesi nesne ({...}) olmalıdır".to_string())?;

    let mut base_map = match serde_json::to_value(base) {
        Ok(Value::Object(m)) => m,
        Ok(_) => return Err("Temel vHost serileştirme biçimi hatalı".to_string()),
        Err(e) => return Err(format!("Temel vHost serileştirilemedi: {}", e)),
    };

    // 1. Temel Üst Düzey Alanlar
    if let Some(v) = obj.get("aliases") {
        base_map.insert("aliases".to_string(), v.clone());
    }
    if let Some(v) = obj.get("document_root") {
        base_map.insert("document_root".to_string(), v.clone());
    }
    if let Some(v) = obj.get("index_files") {
        base_map.insert("index_files".to_string(), v.clone());
    }

    // 2. Yapılandırılmış Bölüm Nesneleri
    for section in [
        "cache",
        "php",
        "ssl",
        "security",
        "rewrite",
        "proxy",
        "headers",
        "logging",
        "error_docs",
        "tls",
        "static",
    ] {
        if let Some(patch) = obj.get(section) {
            merge_section_object(&mut base_map, section, patch)?;
        }
    }
    if let Some(patch) = obj.get("static_files") {
        merge_section_object(&mut base_map, "static", patch)?;
    }

    // Serde ile ara nesneye dönüştür
    let mut entry: VHostEntry = serde_json::from_value(Value::Object(base_map))
        .map_err(|e| format!("vHost alanları ayrıştırılamadı: {}", e))?;
    entry.name = domain.to_string();

    // 3. Geriye Dönük & Düz (Flat) Kısayol Alanlarını Uygula ve Doğrula

    // Cache
    if let Some(v) = obj.get("cache_enabled") {
        entry.cache.enabled = val_as_bool(v, "cache_enabled")?;
    }
    if let Some(v) = obj.get("cache_expire") {
        entry.cache.expire = val_as_u64(v, "cache_expire")?;
    }

    // PHP
    if let Some(v) = obj.get("php_enabled") {
        entry.php.enabled = val_as_bool(v, "php_enabled")?;
    }
    if let Some(v) = obj.get("php_sapi") {
        entry.php.sapi = val_as_str(v, "php_sapi")?;
    }
    if let Some(v) = obj.get("php_upstream") {
        entry.php.upstream = val_as_str(v, "php_upstream")?;
    }
    if let Some(v) = obj.get("php_timeout") {
        entry.php.timeout = val_as_u64(v, "php_timeout")?;
    }
    if let Some(v) = obj.get("php_upstreams").or_else(|| obj.get("upstreams")) {
        entry.php.upstreams = val_as_string_list(v, "upstreams")?;
    }
    if let Some(v) = obj.get("lb_policy") {
        entry.php.lb_policy = val_as_str(v, "lb_policy")?;
    }
    if let Some(v) = obj.get("dial_timeout_ms") {
        entry.php.dial_timeout_ms = val_as_u64(v, "dial_timeout_ms")?;
    }
    if let Some(v) = obj.get("io_timeout_secs") {
        entry.php.io_timeout_secs = val_as_u64(v, "io_timeout_secs")?;
    }
    if let Some(v) = obj.get("keep_conn") {
        entry.php.keep_conn = val_as_bool(v, "keep_conn")?;
    }
    if let Some(v) = obj.get("max_idle_conns") {
        entry.php.max_idle_conns = val_as_usize(v, "max_idle_conns")?;
    }
    if let Some(v) = obj.get("resolve_root_symlink") {
        entry.php.resolve_root_symlink = val_as_bool(v, "resolve_root_symlink")?;
    }
    if let Some(v) = obj.get("allow_x_accel_redirect") {
        entry.php.allow_x_accel_redirect = val_as_bool(v, "allow_x_accel_redirect")?;
    }
    if let Some(v) = obj.get("x_accel_prefix") {
        entry.php.x_accel_prefix = val_as_str(v, "x_accel_prefix")?;
    }

    // SSL
    if let Some(v) = obj.get("ssl_cert") {
        entry.ssl.certificate = val_as_str(v, "ssl_cert")?;
    }
    if let Some(v) = obj.get("ssl_key") {
        entry.ssl.key = val_as_str(v, "ssl_key")?;
    }

    // Security (WAF, Hotlink, IP ACL)
    if let Some(v) = obj.get("hotlink_protection") {
        entry.security.hotlink_protection = val_as_bool(v, "hotlink_protection")?;
    }
    if let Some(v) = obj.get("force_https") {
        entry.security.force_https = val_as_bool(v, "force_https")?;
    }
    if let Some(v) = obj.get("allow_ips") {
        entry.security.allow_ips = val_as_string_list(v, "allow_ips")?;
    }
    if let Some(v) = obj.get("deny_ips") {
        entry.security.deny_ips = val_as_string_list(v, "deny_ips")?;
    }
    if let Some(v) = obj.get("waf_enabled").or_else(|| obj.get("security_waf_enabled")) {
        entry.security.waf_enabled = match v {
            Value::Null => None,
            Value::Bool(b) => Some(*b),
            _ => return Err("'waf_enabled' alanı mantıksal (bool) veya null olmalıdır".to_string()),
        };
    }
    if let Some(v) = obj.get("wp_brute_force").or_else(|| obj.get("security_wp_brute_force")) {
        entry.security.wp_brute_force = val_as_bool(v, "wp_brute_force")?;
    }
    if let Some(v) = obj.get("waf_exclude_paths").or_else(|| obj.get("security_waf_exclude_paths")) {
        entry.security.waf_exclude_paths = val_as_string_list(v, "waf_exclude_paths")?;
    }

    // Rewrite (rules, enabled, try_files, htaccess)
    if let Some(v) = obj.get("rewrite_enabled") {
        entry.rewrite.enabled = val_as_bool(v, "rewrite_enabled")?;
    }
    if let Some(v) = obj.get("try_files") {
        entry.rewrite.try_files = val_as_bool(v, "try_files")?;
    }
    if let Some(v) = obj.get("htaccess") {
        entry.rewrite.htaccess = val_as_bool(v, "htaccess")?;
    }
    if let Some(v) = obj.get("rewrite_rules").or_else(|| obj.get("rules")) {
        entry.rewrite.rules = val_as_rewrite_rules(v, "rewrite_rules")?;
    }

    // Headers (security_headers, hsts)
    if let Some(v) = obj.get("security_headers").or_else(|| obj.get("headers_security_headers")) {
        entry.headers.security_headers = val_as_bool(v, "security_headers")?;
    }
    if let Some(v) = obj.get("hsts").or_else(|| obj.get("headers_hsts")) {
        entry.headers.hsts = val_as_bool(v, "hsts")?;
    }

    // Logging (enabled, access_log, error_log, log_format, max_log_size_mb, also_write_global)
    if let Some(v) = obj.get("logging_enabled") {
        entry.logging.enabled = val_as_bool(v, "logging_enabled")?;
    }
    if let Some(v) = obj.get("access_log") {
        entry.logging.access_log = val_as_str(v, "access_log")?;
    }
    if let Some(v) = obj.get("error_log") {
        entry.logging.error_log = val_as_str(v, "error_log")?;
    }
    if let Some(v) = obj.get("log_format").or_else(|| obj.get("format")) {
        entry.logging.format = val_as_str(v, "log_format")?;
    }
    if let Some(v) = obj.get("max_log_size_mb") {
        entry.logging.max_log_size_mb = val_as_u64(v, "max_log_size_mb")?;
    }
    if let Some(v) = obj.get("also_write_global") {
        entry.logging.also_write_global = val_as_bool(v, "also_write_global")?;
    }

    // Error Docs (enabled, dir, pages)
    if let Some(v) = obj.get("error_docs_enabled") {
        entry.error_docs.enabled = val_as_bool(v, "error_docs_enabled")?;
    }
    if let Some(v) = obj.get("error_docs_dir") {
        entry.error_docs.dir = val_as_str(v, "error_docs_dir")?;
    }
    if let Some(v) = obj.get("error_docs_pages").or_else(|| obj.get("pages")) {
        entry.error_docs.pages = val_as_status_pages(v, "error_docs_pages")?;
    }

    // TLS
    if let Some(v) = obj.get("http2") {
        entry.tls.http2 = val_as_bool(v, "http2")?;
    }
    if let Some(v) = obj.get("strict_sni") {
        entry.tls.strict_sni = val_as_bool(v, "strict_sni")?;
    }
    if let Some(v) = obj.get("tls_min_version") {
        entry.tls.min_version = val_as_str(v, "tls_min_version")?;
    }

    // Static Files
    if let Some(v) = obj.get("precompressed") {
        entry.static_files.precompressed = val_as_bool(v, "precompressed")?;
    }
    if let Some(v) = obj.get("brotli") {
        entry.static_files.brotli = val_as_bool(v, "brotli")?;
    }
    if let Some(v) = obj.get("gzip") {
        entry.static_files.gzip = val_as_bool(v, "gzip")?;
    }
    if let Some(v) = obj.get("autoindex") {
        entry.static_files.autoindex = val_as_bool(v, "autoindex")?;
    }
    if let Some(v) = obj.get("sendfile") {
        entry.static_files.sendfile = val_as_bool(v, "sendfile")?;
    }

    // Proxy
    if let Some(v) = obj.get("proxy_enabled") {
        entry.proxy.enabled = val_as_bool(v, "proxy_enabled")?;
    }
    if let Some(v) = obj.get("proxy_upstream") {
        entry.proxy.upstream = val_as_str(v, "proxy_upstream")?;
    }
    if let Some(v) = obj.get("proxy_path_prefix") {
        entry.proxy.path_prefix = val_as_str(v, "proxy_path_prefix")?;
    }
    if let Some(v) = obj.get("preserve_host") {
        entry.proxy.preserve_host = val_as_bool(v, "preserve_host")?;
    }
    if let Some(v) = obj.get("websocket") {
        entry.proxy.websocket = val_as_bool(v, "websocket")?;
    }

    // 4. Doğrulamalar (Validation)
    if entry.document_root.contains("..")
        || entry.document_root.contains('\0')
        || entry.document_root.trim().is_empty()
    {
        return Err("Geçersiz document_root yolu".to_string());
    }

    for (label, path_val) in [
        ("logging.access_log", entry.logging.access_log.as_str()),
        ("logging.error_log", entry.logging.error_log.as_str()),
        ("error_docs.dir", entry.error_docs.dir.as_str()),
        ("ssl.certificate", entry.ssl.certificate.as_str()),
        ("ssl.key", entry.ssl.key.as_str()),
    ] {
        if has_parent_dir_traversal(path_val) {
            return Err(format!("Geçersiz {} dosya yolu: '{}'", label, path_val));
        }
    }

    for (code, page_path) in &entry.error_docs.pages {
        if !(100..=599).contains(code) {
            return Err(format!("Geçersiz HTTP durum kodu: {}", code));
        }
        if has_parent_dir_traversal(page_path) {
            return Err(format!(
                "Geçersiz error_docs.pages dosya yolu (kod {}): '{}'",
                code, page_path
            ));
        }
    }

    // Standart VHostEntry doğrulaması (domain, IP ACL, logging, tls, php)
    entry.validate()?;

    if entry.php.enabled && entry.effective_php_upstreams().is_empty() {
        return Err("PHP etkin ancak upstream boş olamaz".to_string());
    }
    if entry.proxy.enabled && entry.proxy.upstream.trim().is_empty() {
        return Err("Proxy etkin ancak upstream boş olamaz".to_string());
    }

    Ok(entry)
}

/// `VHostEntry` nesnesini hem tüm yapılandırılmış bölümleri hem de geriye dönük
/// düz (flat) alanları içeren tam JSON nesnesine serileştirir.
pub fn format_vhost_entry_json(
    entry: &VHostEntry,
    file_name: &str,
    resolved_doc_root: &Path,
) -> Value {
    let mut root = match serde_json::to_value(entry) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    };
    let has_ssl = !entry.ssl.certificate.trim().is_empty();
    let effective_upstreams = entry.effective_php_upstreams();

    root.insert("domain".to_string(), Value::String(entry.name.clone()));
    root.insert(
        "resolved_root".to_string(),
        Value::String(resolved_doc_root.to_string_lossy().into_owned()),
    );
    root.insert("file".to_string(), Value::String(file_name.to_string()));

    // Geriye dönük uyumlu ve açık düz kısayol alanları
    root.insert("php_enabled".to_string(), Value::Bool(entry.php.enabled));
    root.insert("php_sapi".to_string(), Value::String(entry.php.sapi.clone()));
    root.insert(
        "php_upstream".to_string(),
        Value::String(entry.php.upstream.clone()),
    );
    root.insert("php_timeout".to_string(), Value::from(entry.php.timeout));
    root.insert("php_upstreams".to_string(), serde_json::json!(effective_upstreams));
    root.insert("upstreams".to_string(), serde_json::json!(entry.php.upstreams));
    root.insert("lb_policy".to_string(), Value::String(entry.php.lb_policy.clone()));
    root.insert("dial_timeout_ms".to_string(), Value::from(entry.php.dial_timeout_ms));
    root.insert("io_timeout_secs".to_string(), Value::from(entry.php.io_timeout_secs));
    root.insert("keep_conn".to_string(), Value::Bool(entry.php.keep_conn));
    root.insert(
        "max_idle_conns".to_string(),
        Value::from(entry.php.max_idle_conns as u64),
    );
    root.insert(
        "resolve_root_symlink".to_string(),
        Value::Bool(entry.php.resolve_root_symlink),
    );
    root.insert(
        "allow_x_accel_redirect".to_string(),
        Value::Bool(entry.php.allow_x_accel_redirect),
    );
    root.insert(
        "x_accel_prefix".to_string(),
        Value::String(entry.php.x_accel_prefix.clone()),
    );

    root.insert("cache_enabled".to_string(), Value::Bool(entry.cache.enabled));
    root.insert("cache_expire".to_string(), Value::from(entry.cache.expire));

    root.insert("ssl_enabled".to_string(), Value::Bool(has_ssl));
    root.insert("ssl_cert".to_string(), Value::String(entry.ssl.certificate.clone()));
    root.insert("ssl_key".to_string(), Value::String(entry.ssl.key.clone()));

    root.insert("force_https".to_string(), Value::Bool(entry.security.force_https));
    root.insert(
        "hotlink_protection".to_string(),
        Value::Bool(entry.security.hotlink_protection),
    );
    root.insert("allow_ips".to_string(), serde_json::json!(entry.security.allow_ips));
    root.insert("deny_ips".to_string(), serde_json::json!(entry.security.deny_ips));
    root.insert("waf_enabled".to_string(), serde_json::json!(entry.security.waf_enabled));
    root.insert("wp_brute_force".to_string(), Value::Bool(entry.security.wp_brute_force));
    root.insert(
        "waf_exclude_paths".to_string(),
        serde_json::json!(entry.security.waf_exclude_paths),
    );

    root.insert("proxy_enabled".to_string(), Value::Bool(entry.proxy.enabled));
    root.insert(
        "proxy_upstream".to_string(),
        Value::String(entry.proxy.upstream.clone()),
    );
    root.insert(
        "proxy_path_prefix".to_string(),
        Value::String(entry.proxy.path_prefix.clone()),
    );
    root.insert("preserve_host".to_string(), Value::Bool(entry.proxy.preserve_host));
    root.insert("websocket".to_string(), Value::Bool(entry.proxy.websocket));

    root.insert("rewrite_enabled".to_string(), Value::Bool(entry.rewrite.enabled));
    root.insert("try_files".to_string(), Value::Bool(entry.rewrite.try_files));
    root.insert("htaccess".to_string(), Value::Bool(entry.rewrite.htaccess));
    root.insert("rewrite_rules".to_string(), serde_json::json!(entry.rewrite.rules));
    root.insert("rules".to_string(), serde_json::json!(entry.rewrite.rules));

    root.insert(
        "security_headers".to_string(),
        Value::Bool(entry.headers.security_headers),
    );
    root.insert("hsts".to_string(), Value::Bool(entry.headers.hsts));

    root.insert("logging_enabled".to_string(), Value::Bool(entry.logging.enabled));
    root.insert(
        "access_log".to_string(),
        Value::String(entry.logging.access_log.clone()),
    );
    root.insert(
        "error_log".to_string(),
        Value::String(entry.logging.error_log.clone()),
    );
    root.insert("log_format".to_string(), Value::String(entry.logging.format.clone()));
    root.insert(
        "max_log_size_mb".to_string(),
        Value::from(entry.logging.max_log_size_mb),
    );
    root.insert(
        "also_write_global".to_string(),
        Value::Bool(entry.logging.also_write_global),
    );

    root.insert("error_docs_enabled".to_string(), Value::Bool(entry.error_docs.enabled));
    root.insert(
        "error_docs_dir".to_string(),
        Value::String(entry.error_docs.dir.clone()),
    );
    root.insert(
        "error_docs_pages".to_string(),
        serde_json::json!(entry.error_docs.pages),
    );

    root.insert("http2".to_string(), Value::Bool(entry.tls.http2));
    root.insert("strict_sni".to_string(), Value::Bool(entry.tls.strict_sni));
    root.insert(
        "tls_min_version".to_string(),
        Value::String(entry.tls.min_version.clone()),
    );

    root.insert(
        "precompressed".to_string(),
        Value::Bool(entry.static_files.precompressed),
    );
    root.insert("brotli".to_string(), Value::Bool(entry.static_files.brotli));
    root.insert("gzip".to_string(), Value::Bool(entry.static_files.gzip));
    root.insert("autoindex".to_string(), Value::Bool(entry.static_files.autoindex));
    root.insert("sendfile".to_string(), Value::Bool(entry.static_files.sendfile));

    Value::Object(root)
}

/// `LoadedVHost` nesnesini tam JSON metnine dönüştürür.
pub fn format_loaded_vhost_json(v: &LoadedVHost) -> String {
    let val = format_vhost_entry_json(&v.entry, &v.file_name, &v.resolved_doc_root);
    serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string())
}

/// İki `VHostEntry` nesnesinin tüm alanlarının birebir eşit olup olmadığını denetler.
pub fn vhost_entry_eq(a: &VHostEntry, b: &VHostEntry) -> bool {
    vhost_entry_diff(a, b).is_none()
}

/// İki `VHostEntry` arasındaki ilk farklı alanın adını döndürür (varsa).
pub fn vhost_entry_diff(a: &VHostEntry, b: &VHostEntry) -> Option<String> {
    if a.name != b.name {
        return Some(format!("name: '{}' != '{}'", a.name, b.name));
    }
    if a.aliases != b.aliases {
        return Some(format!("aliases: '{:?}' != '{:?}'", a.aliases, b.aliases));
    }
    if a.document_root != b.document_root {
        return Some(format!("document_root: '{}' != '{}'", a.document_root, b.document_root));
    }
    if a.index_files != b.index_files {
        return Some(format!("index_files: '{:?}' != '{:?}'", a.index_files, b.index_files));
    }
    if a.cache.enabled != b.cache.enabled || a.cache.expire != b.cache.expire {
        return Some(format!("cache: '{:?}' != '{:?}'", a.cache, b.cache));
    }
    if a.php.enabled != b.php.enabled
        || a.php.sapi != b.php.sapi
        || a.php.upstream != b.php.upstream
        || a.php.timeout != b.php.timeout
        || a.php.upstreams != b.php.upstreams
        || a.php.lb_policy != b.php.lb_policy
        || a.php.dial_timeout_ms != b.php.dial_timeout_ms
        || a.php.io_timeout_secs != b.php.io_timeout_secs
        || a.php.keep_conn != b.php.keep_conn
        || a.php.max_idle_conns != b.php.max_idle_conns
        || a.php.resolve_root_symlink != b.php.resolve_root_symlink
        || a.php.allow_x_accel_redirect != b.php.allow_x_accel_redirect
        || a.php.x_accel_prefix != b.php.x_accel_prefix
    {
        return Some(format!("php: '{:?}' != '{:?}'", a.php, b.php));
    }
    if a.ssl.certificate != b.ssl.certificate || a.ssl.key != b.ssl.key {
        return Some(format!("ssl: '{:?}' != '{:?}'", a.ssl, b.ssl));
    }
    if a.security.hotlink_protection != b.security.hotlink_protection
        || a.security.force_https != b.security.force_https
        || a.security.allow_ips != b.security.allow_ips
        || a.security.deny_ips != b.security.deny_ips
        || a.security.waf_enabled != b.security.waf_enabled
        || a.security.wp_brute_force != b.security.wp_brute_force
        || a.security.waf_exclude_paths != b.security.waf_exclude_paths
    {
        return Some(format!("security: '{:?}' != '{:?}'", a.security, b.security));
    }
    if a.rewrite.enabled != b.rewrite.enabled
        || a.rewrite.try_files != b.rewrite.try_files
        || a.rewrite.htaccess != b.rewrite.htaccess
        || a.rewrite.rules != b.rewrite.rules
    {
        return Some(format!("rewrite: '{:?}' != '{:?}'", a.rewrite, b.rewrite));
    }
    if a.proxy.enabled != b.proxy.enabled
        || a.proxy.upstream != b.proxy.upstream
        || a.proxy.path_prefix != b.proxy.path_prefix
        || a.proxy.preserve_host != b.proxy.preserve_host
        || a.proxy.websocket != b.proxy.websocket
    {
        return Some(format!("proxy: '{:?}' != '{:?}'", a.proxy, b.proxy));
    }
    if a.headers.security_headers != b.headers.security_headers
        || a.headers.hsts != b.headers.hsts
    {
        return Some(format!("headers: '{:?}' != '{:?}'", a.headers, b.headers));
    }
    if a.logging.enabled != b.logging.enabled
        || a.logging.access_log != b.logging.access_log
        || a.logging.error_log != b.logging.error_log
        || a.logging.format != b.logging.format
        || a.logging.max_log_size_mb != b.logging.max_log_size_mb
        || a.logging.also_write_global != b.logging.also_write_global
    {
        return Some(format!("logging: '{:?}' != '{:?}'", a.logging, b.logging));
    }
    if a.error_docs.enabled != b.error_docs.enabled
        || a.error_docs.dir != b.error_docs.dir
        || a.error_docs.pages != b.error_docs.pages
    {
        return Some(format!("error_docs: '{:?}' != '{:?}'", a.error_docs, b.error_docs));
    }
    if a.tls.http2 != b.tls.http2
        || a.tls.strict_sni != b.tls.strict_sni
        || a.tls.min_version != b.tls.min_version
    {
        return Some(format!("tls: '{:?}' != '{:?}'", a.tls, b.tls));
    }
    if a.static_files.precompressed != b.static_files.precompressed
        || a.static_files.brotli != b.static_files.brotli
        || a.static_files.gzip != b.static_files.gzip
        || a.static_files.autoindex != b.static_files.autoindex
        || a.static_files.sendfile != b.static_files.sendfile
    {
        return Some(format!("static_files: '{:?}' != '{:?}'", a.static_files, b.static_files));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize_vhost_toml;

    #[test]
    fn test_merge_vhost_json_full_fields_and_roundtrip_equality() {
        let base = VHostEntry::default();
        let payload = r#"{
            "domain": "tamalan.test",
            "document_root": "www/tamalan",
            "aliases": ["www.tamalan.test", "cdn.tamalan.test"],
            "hotlink_protection": true,
            "allow_ips": ["192.168.1.0/24", "10.0.0.1"],
            "deny_ips": ["198.51.100.5"],
            "waf_enabled": true,
            "wp_brute_force": false,
            "waf_exclude_paths": ["/api/webhook", "/health"],
            "security_headers": true,
            "hsts": true,
            "logging_enabled": true,
            "access_log": "logs/tamalan_access.log",
            "error_log": "logs/tamalan_error.log",
            "log_format": "%h %l %u %t \"%r\" %>s %b",
            "max_log_size_mb": 50,
            "also_write_global": false,
            "error_docs_enabled": true,
            "error_docs_dir": "errors/custom",
            "error_docs_pages": {
                "404": "404.html",
                "403": "forbidden.html",
                "500": "500.html"
            },
            "rewrite_enabled": true,
            "try_files": true,
            "htaccess": false,
            "rewrite_rules": [
                {
                    "pattern": "^/eski/(.*)$",
                    "target": "/yeni/$1",
                    "status": 301,
                    "flags": ["L", "R"],
                    "last": true
                }
            ],
            "http2": true,
            "strict_sni": true,
            "tls_min_version": "1.3"
        }"#;

        let entry = merge_vhost_json_patch(&base, "tamalan.test", payload.as_bytes())
            .expect("Tam alan birleştirmesi başarılı olmalıdır");

        // Alan kontrolleri
        assert_eq!(entry.name, "tamalan.test");
        assert_eq!(entry.document_root, "www/tamalan");
        assert_eq!(entry.aliases, vec!["www.tamalan.test", "cdn.tamalan.test"]);
        assert!(entry.security.hotlink_protection);
        assert_eq!(entry.security.allow_ips, vec!["192.168.1.0/24", "10.0.0.1"]);
        assert_eq!(entry.security.deny_ips, vec!["198.51.100.5"]);
        assert_eq!(entry.security.waf_enabled, Some(true));
        assert!(!entry.security.wp_brute_force);
        assert_eq!(entry.security.waf_exclude_paths, vec!["/api/webhook", "/health"]);
        assert!(entry.headers.security_headers);
        assert!(entry.headers.hsts);
        assert!(entry.logging.enabled);
        assert_eq!(entry.logging.access_log, "logs/tamalan_access.log");
        assert_eq!(entry.logging.error_log, "logs/tamalan_error.log");
        assert_eq!(entry.logging.format, "%h %l %u %t \"%r\" %>s %b");
        assert_eq!(entry.logging.max_log_size_mb, 50);
        assert!(!entry.logging.also_write_global);
        assert!(entry.error_docs.enabled);
        assert_eq!(entry.error_docs.dir, "errors/custom");
        assert_eq!(entry.error_docs.pages.get(&404).map(String::as_str), Some("404.html"));
        assert_eq!(entry.error_docs.pages.get(&403).map(String::as_str), Some("forbidden.html"));
        assert_eq!(entry.error_docs.pages.get(&500).map(String::as_str), Some("500.html"));
        assert!(entry.rewrite.enabled);
        assert!(entry.rewrite.try_files);
        assert!(!entry.rewrite.htaccess);
        assert_eq!(entry.rewrite.rules.len(), 1);
        assert_eq!(entry.rewrite.rules[0].pattern, "^/eski/(.*)$");
        assert_eq!(entry.rewrite.rules[0].target, "/yeni/$1");
        assert_eq!(entry.rewrite.rules[0].status, 301);
        assert!(entry.rewrite.rules[0].last);
        assert!(entry.tls.http2);
        assert!(entry.tls.strict_sni);
        assert_eq!(entry.tls.min_version, "1.3");

        // TOML Turu (Round-trip Equality) Doğrulaması
        let toml_str = serialize_vhost_toml(&entry).expect("TOML serileştirme başarılı olmalıdır");
        let reloaded_doc: crate::VHostFileDocument =
            toml::from_str(&toml_str).expect("TOML ayrıştırma başarılı olmalıdır");
        let reloaded_entry = reloaded_doc.vhost;

        if let Some(diff) = vhost_entry_diff(&entry, &reloaded_entry) {
            panic!("TOML round-trip sonrasında fark tespit edildi: {}", diff);
        }
        assert!(vhost_entry_eq(&entry, &reloaded_entry));
    }

    #[test]
    fn test_merge_vhost_json_nested_sections() {
        let base = VHostEntry::default();
        let payload = r#"{
            "security": {
                "hotlink_protection": true,
                "allow_ips": ["10.1.2.3"],
                "deny_ips": ["172.16.0.0/16"],
                "waf_enabled": false
            },
            "headers": {
                "security_headers": true,
                "hsts": false
            },
            "logging": {
                "enabled": true,
                "access_log": "logs/ozel.log",
                "format": "%h %t \"%r\" %>s"
            },
            "error_docs": {
                "enabled": true,
                "dir": "hatalar",
                "pages": { "404": "bulunamadi.html" }
            },
            "rewrite": {
                "enabled": true,
                "rules": [
                    { "pattern": "/test", "target": "/hedef", "status": 302, "flags": ["L"], "last": true }
                ]
            }
        }"#;

        let entry = merge_vhost_json_patch(&base, "nested.test", payload.as_bytes())
            .expect("İç içe nesne birleştirmesi başarılı olmalıdır");

        assert!(entry.security.hotlink_protection);
        assert_eq!(entry.security.allow_ips, vec!["10.1.2.3"]);
        assert_eq!(entry.security.deny_ips, vec!["172.16.0.0/16"]);
        assert_eq!(entry.security.waf_enabled, Some(false));
        assert!(entry.headers.security_headers);
        assert!(!entry.headers.hsts);
        assert!(entry.logging.enabled);
        assert_eq!(entry.logging.access_log, "logs/ozel.log");
        assert_eq!(entry.error_docs.pages.get(&404).map(String::as_str), Some("bulunamadi.html"));
        assert_eq!(entry.rewrite.rules.len(), 1);
    }

    #[test]
    fn test_merge_vhost_json_invalid_inputs_rejected() {
        let base = VHostEntry::default();

        // 1. Bozuk JSON
        let err = merge_vhost_json_patch(&base, "test.local", b"{bozuk_json:").unwrap_err();
        assert!(err.contains("Geçersiz JSON") || err.contains("JSON"));

        // 2. Dizi kökü (nesne bekleniyor)
        let err = merge_vhost_json_patch(&base, "test.local", b"[1, 2, 3]").unwrap_err();
        assert!(err.contains("nesne"));

        // 3. Geçersiz IP CIDR
        let payload = r#"{"allow_ips": ["gecersiz_ip_degeri"]}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("security.allow_ips") || err.contains("geçersiz"));

        // 4. Path traversal (document_root)
        let payload = r#"{"document_root": "../../../etc/passwd"}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("document_root"));

        // 5. Path traversal (logging.access_log)
        let payload = r#"{"access_log": "../gizli.log"}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("access_log"));

        // 6. Path traversal (error_docs_pages)
        let payload = r#"{"error_docs_pages": {"404": "../../etc/shadow"}}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("error_docs"));

        // 7. Geçersiz HTTP durum kodu
        let payload = r#"{"error_docs_pages": {"999": "hata.html"}}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("durum kodu"));

        // 8. Geçersiz log formatı
        let payload = r#"{"log_format": "bilinmeyen_ve_yuzdesiz_format"}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("log_format") || err.contains("logging"));

        // 9. Geçersiz TLS min version
        let payload = r#"{"tls_min_version": "1.0"}"#;
        let err = merge_vhost_json_patch(&base, "test.local", payload.as_bytes()).unwrap_err();
        assert!(err.contains("tls.min_version") || err.contains("min_version"));
    }
}
