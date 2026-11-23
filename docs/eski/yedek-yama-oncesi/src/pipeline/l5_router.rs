//! L5 Yonlendirme: vhost cozumleme, force_https/ACME karari, ters vekil karari ve hotlink denetimi.
//! HTTP/1.1 (`pipeline_h1`) ve HTTP/2 (`pipeline_h2`) ayni islevleri cagirir.

use crate::api::ServerState;
use crate::modules_runtime::CompiledPolicies;
use crate::pipeline::l8_response::resolve_vhost_security_headers;
use crate::web_engine::DEFAULT_LOG_MAX_BYTES;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zmax_config::match_vhost;
use zmax_header::SecurityHeadersPolicy;
use zmax_security::IpAccessList;
use zmax_static::percent_decode_path;

#[derive(Debug, Clone, Default)]
pub struct LogMeta {
    pub domain: Option<String>,
    pub custom_log_path: Option<PathBuf>,
    pub json_format: bool,
    pub also_write_global: bool,
    pub max_log_size_bytes: u64,
}

#[derive(Clone)]
pub struct ResolvedVHostContext {
    pub doc_root: PathBuf,
    pub index_files: Vec<String>,
    pub php_enabled: bool,
    pub php_upstream: String,
    pub php_upstreams: Vec<String>,
    pub php_lb_policy: String,
    pub php_timeout: u64,
    pub cache_enabled: bool,
    pub cache_expire: u64,
    pub cache_stale_sec: u64,
    pub vhost_name: String,
    pub vhost_aliases: Vec<String>,
    pub force_https: bool,
    pub hotlink_protection: bool,
    pub hotlink_config: zmax_config::HotlinkConfig,
    pub global_acl: IpAccessList,
    pub vhost_acl: IpAccessList,
    pub vhost_acl_engine: zmax_security::VhostAcl,
    pub rewrite_enabled: bool,
    pub rewrite_try_files: bool,
    pub rewrite_htaccess: bool,
    pub rewrite_rules: Vec<zmax_config::VHostRewriteRule>,
    pub proxy_enabled: bool,
    pub proxy_upstream: String,
    pub proxy_path_prefix: String,
    pub proxy_preserve_host: bool,
    pub proxy_websocket: bool,
    // [kart-10] Ters vekil genisletilmis ayarları (initTimeout, keep-alive, respBuffer)
    pub proxy_ext: zmax_config::ProxyExtConfig,
    pub(crate) auto_webp: bool,
    pub(crate) auto_avif: bool,
    pub(crate) etag_enabled: bool,
    pub(crate) last_modified_header: bool,
    pub max_log_size_bytes: u64,
    pub(crate) headers_policy: Option<SecurityHeadersPolicy>,
    // 8-Madde Alanlari
    pub waf_enabled: Option<bool>,
    pub waf_exclude_paths: Vec<String>,
    pub error_docs: zmax_config::VHostErrorDocsSection,
    pub logging: zmax_config::VHostLoggingSection,
    pub tls_http2: bool,
    pub acme_root: Option<PathBuf>,
    pub auth: zmax_config::VHostAuthSection, // [kart-9]
    // [kart-8] FastCGI bağlantı zaman aşımı (milisaniye)
    pub php_dial_timeout_ms: u64,
    pub autoindex: bool,
    pub block_dangerous_files: bool,
}

/// FastCGI bağlantı zaman aşımı (ms): vhost değeri verilmişse (ve 0 değilse) o; yoksa `mod_fastcgi`
/// politika değeri (en az 1 ms). vhost varsayılanı `None` olduğundan politika gerçekten kullanılır.
#[inline]
pub(crate) fn resolve_php_dial_timeout_ms(vhost_dial_ms: Option<u64>, policy_dial_ms: u64) -> u64 {
    match vhost_dial_ms {
        Some(ms) if ms > 0 => ms,
        _ => policy_dial_ms.max(1),
    }
}

/// ACME HTTP-01 dogrulama yolu (force_https yonlendirmesinden muaf).
pub fn is_acme_challenge(path: &str) -> bool {
    percent_decode_path(path)
        .map(|p| p.starts_with("/.well-known/acme-challenge/"))
        .unwrap_or_else(|| path.starts_with("/.well-known/acme-challenge/"))
}

/// `https://ayni-host/ayni-yol?sorgu` adresini uretir. HTTPS portu 443 degilse porta eklenir.
pub fn https_redirect_location(
    host_header: &str,
    path: &str,
    query: &str,
    https_port: u16,
) -> Option<String> {
    let host = host_header.trim();
    let hostname = if host.starts_with('[') {
        &host[..=host.find(']')?]
    } else {
        host.split(':').next().unwrap_or("")
    };
    if hostname.is_empty()
        || !hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':' | '_'))
    {
        return None;
    }
    let authority = if https_port == 443 {
        hostname.to_string()
    } else {
        format!("{}:{}", hostname, https_port)
    };
    let path = if path.is_empty() { "/" } else { path };
    Some(if query.is_empty() {
        format!("https://{}{}", authority, path)
    } else {
        format!("https://{}{}?{}", authority, path, query)
    })
}

const HOTLINK_PROTECTED_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "webp", "avif", "svg", "ico", "bmp", "mp4", "webm", "ogg", "mp3",
    "wav", "woff", "woff2", "ttf", "eot", "pdf", "zip",
];

/// Dosya adı veya yolunun hotlink koruması kapsamındaki statik medya/varlık uzantısına sahip olup olmadığını kontrol eder.
#[allow(dead_code)]
pub fn is_hotlink_protected_extension(file_name_or_path: &str) -> bool {
    let path_only = file_name_or_path
        .split(['?', '#'])
        .next()
        .unwrap_or(file_name_or_path)
        .trim();
    let Some(ext) = Path::new(path_only).extension().and_then(|e| e.to_str()) else {
        return false;
    };
    HOTLINK_PROTECTED_EXTENSIONS
        .iter()
        .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

fn is_valid_port(port_str: &str) -> bool {
    !port_str.is_empty()
        && port_str.bytes().all(|b| b.is_ascii_digit())
        && port_str.parse::<u16>().is_ok()
}

fn normalize_host_without_port(raw: &str, allow_bare_ipv6: bool) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    if let Some(after_open) = s.strip_prefix('[') {
        let end = after_open.find(']')?;
        let inner = &after_open[..end];
        let after = &after_open[end + 1..];
        if !after.is_empty() {
            let port_str = after.strip_prefix(':')?;
            if !is_valid_port(port_str) {
                return None;
            }
        }
        let ip = inner.parse::<std::net::Ipv6Addr>().ok()?;
        return Some(format!("[{ip}]"));
    }

    if allow_bare_ipv6 {
        if let Ok(ip) = s.parse::<std::net::Ipv6Addr>() {
            return Some(format!("[{ip}]"));
        }
    }

    let host = if let Some((h, port_str)) = s.split_once(':') {
        if !is_valid_port(port_str) {
            return None;
        }
        h
    } else {
        s
    };

    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return None;
    }

    Some(host.to_ascii_lowercase())
}

fn is_subdomain_match_eligible(domain: &str) -> bool {
    let is_ip = domain
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok();
    domain != "default" && domain.contains('.') && !is_ip
}

fn host_matches_allowed_domain(ref_host: &str, candidate: &str) -> bool {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return false;
    }

    if let Some(wild_base) = trimmed.strip_prefix("*.") {
        let Some(domain) = normalize_host_without_port(wild_base, false) else {
            return false;
        };
        if is_subdomain_match_eligible(&domain) {
            let suffix = format!(".{domain}");
            return ref_host.ends_with(&suffix);
        }
        return false;
    }

    let Some(domain) = normalize_host_without_port(trimmed, true) else {
        return false;
    };
    if ref_host == domain {
        return true;
    }
    if is_subdomain_match_eligible(&domain) {
        let suffix = format!(".{domain}");
        return ref_host.ends_with(&suffix);
    }
    false
}

/// HTTP `Referer` başlığından şemayı, yolu, kimlik bilgisini ve portu soyarak küçük harfli ana makine adını çıkarır.
#[allow(dead_code)]
pub fn extract_referer_host(referer: &str) -> Option<String> {
    let raw = referer.trim();
    let rest = if raw
        .as_bytes()
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"http://"))
    {
        &raw[7..]
    } else if raw
        .as_bytes()
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"https://"))
    {
        &raw[8..]
    } else {
        return None;
    };

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("").trim();
    if authority.is_empty() || authority.contains('\\') {
        return None;
    }

    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .trim();

    normalize_host_without_port(host_port, false)
}

/// Statik medya/varlık isteğinin dış kaynaklı (hotlink) olup olmadığını değerlendirir; engellenmeliyse `true` döner.
pub fn is_hotlink_blocked(
    referer_header: Option<&str>,
    request_host: &str,
    vhost_name: &str,
    vhost_aliases: &[String],
    file_path: &str,
) -> bool {
    if !is_hotlink_protected_extension(file_path) {
        return false;
    }

    let Some(raw_referer) = referer_header.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };

    let Some(ref_host) = extract_referer_host(raw_referer) else {
        return false;
    };

    let allowed = host_matches_allowed_domain(&ref_host, request_host)
        || host_matches_allowed_domain(&ref_host, vhost_name)
        || vhost_aliases
            .iter()
            .any(|alias| host_matches_allowed_domain(&ref_host, alias));

    !allowed
}

/// Hem HTTP/1.1 hem HTTP/2 boru hattında statik dosya sunumundan önce çağrılan birleştirilmiş Hotlink koruma denetimi.
pub fn is_request_hotlink_blocked(
    vhost_ctx: &ResolvedVHostContext,
    referer: Option<&str>,
    request_host: &str,
    request_path: &str,
) -> bool {
    let hl = &vhost_ctx.hotlink_config;
    let is_enabled = hl.enabled || vhost_ctx.hotlink_protection;
    if !is_enabled {
        return false;
    }

    zmax_security::is_hotlink_blocked(
        true,
        &hl.allowed_referers,
        &hl.extensions,
        referer,
        request_host,
        &vhost_ctx.vhost_name,
        &vhost_ctx.vhost_aliases,
        request_path,
    )
}

/// `resolve_vhost_context` icin protokol ayrimi (onceki H1/H2 farklarini aynen korur).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum VhostProto {
    Http1,
    Http2,
}

/// HTTP/1.1 ve HTTP/2 boru hattinin paylastigi vhost cozumleme adimi (Host -> `ResolvedVHostContext`).
/// `proto` yalniz iki protokolun onceki farklarini korur (varsayilan indeks listesi, gunluk boyutu, baslik politikasi).
pub(crate) async fn resolve_vhost_context(
    state: &Arc<ServerState>,
    host: &str,
    proto: VhostProto,
) -> (
    CompiledPolicies,
    Option<zmax_redis::ZMaxRedisClient>,
    ResolvedVHostContext,
    bool,
) {
    let rt = state.runtime.read().await;
    let policies = rt.policies.clone();
    let redis_client = rt.redis_client.clone();
    let vh_opt = match_vhost(&rt.vhosts, host);
    let is_unknown_host =
        !rt.vhosts.is_empty() && !host.trim().is_empty() && vh_opt.is_none();
    let global_acl = IpAccessList::new(
        rt.config.security.allow_ips.clone(),
        rt.config.security.deny_ips.clone(),
    );
    let max_log_size_bytes = rt
        .config
        .logging
        .max_log_size_mb
        .saturating_mul(1024 * 1024);
    let max_log_size_bytes = if proto == VhostProto::Http2 || max_log_size_bytes == 0 {
        DEFAULT_LOG_MAX_BYTES
    } else {
        max_log_size_bytes
    };
    let cache_stale_sec = rt.config.cache.stale_while_revalidate_sec;
    let ctx = match vh_opt {
        Some(vh) => {
            let sec_headers = if proto == VhostProto::Http2 {
                None
            } else {
                resolve_vhost_security_headers(
                    policies.headers_enabled,
                    &policies.security_headers,
                    Some(&vh.entry),
                )
            };
            ResolvedVHostContext {
                doc_root: vh.resolved_doc_root.clone(),
                index_files: vh.entry.index_files.clone(),
                php_enabled: vh.entry.php.enabled && policies.fastcgi.enabled,
                php_upstream: if vh.entry.php.upstream.trim().is_empty() {
                    policies.fastcgi.default_upstream.clone()
                } else {
                    vh.entry.php.upstream.clone()
                },
                php_timeout: vh
                    .entry
                    .php
                    .timeout
                    .max(policies.fastcgi.timeout_sec)
                    .max(5),
                cache_enabled: vh.entry.cache.enabled && rt.config.cache.enabled,
                cache_expire: vh.entry.cache.expire.max(1),
                cache_stale_sec,
                vhost_name: vh.entry.name.clone(),
                vhost_aliases: vh.entry.aliases.clone(),
                force_https: vh.entry.security.force_https,
                hotlink_protection: vh.entry.effective_hotlink().enabled,
                hotlink_config: vh.entry.effective_hotlink(),
                global_acl: global_acl.clone(),
                vhost_acl: IpAccessList::new(
                    vh.entry.security.allow_ips.clone(),
                    vh.entry.security.deny_ips.clone(),
                ),
                // [v1-1b] [vhost.security] ve [vhost.acl] kurallari tutarli birlestirilir
                vhost_acl_engine: crate::security_pipeline::build_merged_vhost_acl(
                    &vh.entry.security,
                    &vh.entry.acl,
                ),
                rewrite_enabled: vh.entry.rewrite.enabled && policies.rewrite_enabled,
                rewrite_try_files: vh.entry.rewrite.try_files,
                rewrite_htaccess: vh.entry.rewrite.htaccess && policies.rewrite_htaccess,
                proxy_enabled: vh.entry.proxy.enabled && policies.proxy.enabled,
                proxy_upstream: vh.entry.proxy.upstream.clone(),
                proxy_path_prefix: if vh.entry.proxy.path_prefix.trim().is_empty() {
                    "/".to_string()
                } else {
                    vh.entry.proxy.path_prefix.clone()
                },
                proxy_preserve_host: vh.entry.proxy.preserve_host
                    && policies.proxy.preserve_host,
                proxy_websocket: vh.entry.proxy.websocket && policies.proxy.websocket_upgrade,
                // [kart-10]
                proxy_ext: vh.entry.proxy_ext.clone(),
                auto_webp: policies.static_policy.auto_webp,
                auto_avif: policies.static_policy.auto_avif,
                etag_enabled: policies.static_policy.etag_enabled,
                last_modified_header: policies.static_policy.last_modified_header,
                max_log_size_bytes,
                headers_policy: sec_headers,
                php_upstreams: vh.entry.php.upstreams.clone(),
                php_lb_policy: vh.entry.php.lb_policy.clone(),
                rewrite_rules: vh.entry.rewrite.rules.clone(),
                waf_enabled: vh.entry.security.waf_enabled,
                waf_exclude_paths: vh.entry.security.waf_exclude_paths.clone(),
                error_docs: vh.entry.error_docs.clone(),
                logging: vh.entry.logging.clone(),
                tls_http2: vh.entry.tls.http2,
                acme_root: crate::acme_runtime::resolve_vhost_acme_root(
                    Some(&vh.entry),
                    &state.base_dir,
                ),
                auth: vh.entry.auth.clone(),
                php_dial_timeout_ms: resolve_php_dial_timeout_ms(
                    vh.entry.php.dial_timeout_ms,
                    policies.fastcgi.dial_timeout_ms,
                ),
                autoindex: vh.entry.static_files.autoindex,
                block_dangerous_files: vh.entry.security.block_dangerous_files,
            }
        }
        None => ResolvedVHostContext {
            doc_root: state.base_dir.join("www").join("html"),
            index_files: if proto == VhostProto::Http2 {
                vec!["index.html".to_string(), "index.php".to_string()]
            } else {
                vec![
                    "index.html".to_string(),
                    "index.htm".to_string(),
                    "index.php".to_string(),
                ]
            },
            php_enabled: false,
            php_upstream: policies.fastcgi.default_upstream.clone(),
            php_timeout: policies.fastcgi.timeout_sec.max(5),
            cache_enabled: rt.config.cache.enabled,
            cache_expire: rt.config.cache.default_ttl_seconds.max(1),
            cache_stale_sec,
            vhost_name: "default".to_string(),
            vhost_aliases: Vec::new(),
            force_https: false,
            hotlink_protection: false,
            hotlink_config: zmax_config::HotlinkConfig::default(),
            global_acl,
            vhost_acl: IpAccessList::default(),
            vhost_acl_engine: zmax_security::VhostAcl::default(),
            rewrite_enabled: policies.rewrite_enabled,
            rewrite_try_files: true,
            rewrite_htaccess: policies.rewrite_htaccess,
            proxy_enabled: false,
            proxy_upstream: String::new(),
            proxy_path_prefix: "/".to_string(),
            proxy_preserve_host: true,
            proxy_websocket: true,
            // [kart-10]
            proxy_ext: zmax_config::ProxyExtConfig::default(),
            auto_webp: policies.static_policy.auto_webp,
            auto_avif: policies.static_policy.auto_avif,
            etag_enabled: policies.static_policy.etag_enabled,
            last_modified_header: policies.static_policy.last_modified_header,
            max_log_size_bytes,
            headers_policy: if proto == VhostProto::Http2 {
                None
            } else {
                resolve_vhost_security_headers(
                    policies.headers_enabled,
                    &policies.security_headers,
                    None,
                )
            },
            php_upstreams: Vec::new(),
            php_lb_policy: "least_conn".to_string(),
            rewrite_rules: Vec::new(),
            waf_enabled: None,
            waf_exclude_paths: Vec::new(),
            error_docs: zmax_config::VHostErrorDocsSection::default(),
            logging: zmax_config::VHostLoggingSection::default(),
            tls_http2: true,
            acme_root: None,
            auth: zmax_config::VHostAuthSection::default(),
            php_dial_timeout_ms: resolve_php_dial_timeout_ms(
                None,
                policies.fastcgi.dial_timeout_ms,
            ),
            autoindex: policies.static_policy.directory_browsing,
            block_dangerous_files: false,
        },
    };
    (policies, redis_client, ctx, is_unknown_host)
}

/// Ters vekil karari: vhost vekili aciksa ve yol onekiyle eslesiyorsa istek upstream'e gider (H1 ve H2 ortak).
#[inline]
pub(crate) fn proxy_route_matches(vhost_ctx: &ResolvedVHostContext, path: &str) -> bool {
    vhost_ctx.proxy_enabled
        && !vhost_ctx.proxy_upstream.trim().is_empty()
        && path.starts_with(&vhost_ctx.proxy_path_prefix)
}
