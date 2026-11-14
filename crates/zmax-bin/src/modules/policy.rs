//! Modül politikaları (RealIp, Gzip, WAF, Proxy, FastCGI, Static) ve derleme.

use zmax_config::{LoadedModules, ZMaxConfig};
use zmax_header::SecurityHeadersPolicy;
use zmax_security::WafInspector;

#[derive(Debug, Clone)]
pub struct RealIpPolicy {
    pub enabled: bool,
    pub header_name: String,
    pub recursive: bool,
    pub trusted_proxies: Vec<String>,
}

impl Default for RealIpPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            header_name: "X-Forwarded-For".to_string(),
            recursive: true,
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GzipPolicy {
    pub enabled: bool,
    pub brotli_enabled: bool,
    pub min_length: usize,
    pub mime_types: Vec<String>,
    pub vary_header: bool,
}

impl Default for GzipPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            brotli_enabled: true,
            min_length: 512,
            mime_types: vec![
                "text/html".to_string(),
                "text/css".to_string(),
                "application/javascript".to_string(),
                "application/json".to_string(),
                "text/plain".to_string(),
                "text/xml".to_string(),
            ],
            vary_header: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WafPolicy {
    pub enabled: bool,
    pub inspector: WafInspector,
    pub wp_brute_force_enabled: bool,
}

impl Default for WafPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            inspector: WafInspector::default(),
            wp_brute_force_enabled: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyModulePolicy {
    pub enabled: bool,
    pub preserve_host: bool,
    pub websocket_upgrade: bool,
    pub connect_timeout_sec: u64,
}

impl Default for ProxyModulePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            preserve_host: true,
            websocket_upgrade: true,
            connect_timeout_sec: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FastCgiModulePolicy {
    pub enabled: bool,
    pub default_upstream: String,
    pub timeout_sec: u64,
    pub pool_size: usize,
    pub dial_timeout_ms: u64,
    pub keep_conn: bool,
}

impl Default for FastCgiModulePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            default_upstream: "127.0.0.1:9000".to_string(),
            timeout_sec: 60,
            pool_size: 64,
            dial_timeout_ms: 5000,
            keep_conn: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticModulePolicy {
    pub etag_enabled: bool,
    pub last_modified_header: bool,
    pub auto_webp: bool,
    pub auto_avif: bool,
    #[allow(dead_code)]
    pub directory_browsing: bool,
}

impl Default for StaticModulePolicy {
    fn default() -> Self {
        Self {
            etag_enabled: true,
            last_modified_header: true,
            auto_webp: true,
            auto_avif: true,
            directory_browsing: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledPolicies {
    pub realip: RealIpPolicy,
    pub gzip: GzipPolicy,
    pub waf: WafPolicy,
    pub headers_enabled: bool,
    pub security_headers: SecurityHeadersPolicy,
    pub rewrite_enabled: bool,
    pub rewrite_htaccess: bool,
    pub proxy: ProxyModulePolicy,
    pub fastcgi: FastCgiModulePolicy,
    pub cache_max_object_bytes: usize,
    pub effective_rate_limit: u32,
    pub static_policy: StaticModulePolicy,
}

/// Yüklenen `modules/mod_*.toml` ve `conf/zmax.toml` ayarlarından aktif politikaları derler.
pub fn compile_policies(config: &ZMaxConfig, modules: &LoadedModules) -> CompiledPolicies {
    let realip = match modules.get("mod_realip") {
        Some(m) if m.is_enabled() => RealIpPolicy {
            enabled: true,
            header_name: m
                .get_str("header_name")
                .unwrap_or("X-Forwarded-For")
                .to_string(),
            recursive: m.get_bool("recursive").unwrap_or(true),
            trusted_proxies: m.get_string_list("trusted_proxies").unwrap_or_default(),
        },
        _ => RealIpPolicy::default(),
    };

    let brotli_mod = modules.get("mod_brotli");
    let brotli_enabled = brotli_mod.map(|m| m.is_enabled()).unwrap_or(true);
    let gzip = match modules.get("mod_gzip") {
        Some(m) => GzipPolicy {
            enabled: m.is_enabled(),
            brotli_enabled,
            min_length: m.get_u64("min_length").unwrap_or(512) as usize,
            mime_types: m
                .get_string_list("mime_types")
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| GzipPolicy::default().mime_types),
            vary_header: m.get_bool("vary_header").unwrap_or(true),
        },
        None => {
            let mut def = GzipPolicy::default();
            def.brotli_enabled = brotli_enabled;
            if let Some(bm) = brotli_mod {
                if let Some(min_len) = bm.get_u64("min_length") {
                    def.min_length = min_len as usize;
                }
                if let Some(mimes) = bm.get_string_list("mime_types").filter(|v| !v.is_empty()) {
                    def.mime_types = mimes;
                }
            }
            def
        }
    };

    let mod_sec = modules.get("mod_security");
    let mod_crs = modules.get("mod_coreruleset");
    let sec_enabled = mod_sec.map(|m| m.is_enabled()).unwrap_or(true);
    let crs_enabled = mod_crs.map(|m| m.is_enabled()).unwrap_or(false);

    let block_traversal = mod_sec
        .and_then(|m| m.get_bool("path_traversal_shield"))
        .unwrap_or(config.security.block_path_traversal);
    let block_hidden = mod_sec
        .and_then(|m| m.get_bool("block_hidden_files"))
        .unwrap_or(true);

    let block_sqli = if crs_enabled {
        mod_crs.and_then(|m| m.get_bool("block_sql_injection")).unwrap_or(true)
    } else {
        mod_sec
            .and_then(|m| m.get_bool("sql_injection_inspection"))
            .unwrap_or(false)
    };
    let block_xss = if crs_enabled {
        mod_crs
            .and_then(|m| m.get_bool("block_cross_site_scripting"))
            .unwrap_or(true)
    } else {
        false
    };
    let block_cmdi = if crs_enabled {
        mod_crs
            .and_then(|m| m.get_bool("block_remote_code_execution"))
            .unwrap_or(true)
    } else {
        false
    };

    let waf = WafPolicy {
        enabled: sec_enabled || crs_enabled,
        inspector: WafInspector {
            block_traversal,
            block_sensitive_files: block_hidden,
            block_sqli,
            block_xss,
            block_cmdi,
        },
        wp_brute_force_enabled: sec_enabled,
    };

    let (headers_enabled, security_headers) = match modules.get("mod_headers") {
        Some(m) => {
            let p = SecurityHeadersPolicy {
                hsts_enabled: m.get_bool("hsts_enabled").unwrap_or(true),
                hsts_max_age: m.get_u64("hsts_max_age").unwrap_or(31_536_000),
                hsts_include_subdomains: m.get_bool("hsts_include_subdomains").unwrap_or(false),
                x_frame_options: m
                    .get_str("x_frame_options")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                x_content_type_options: m
                    .get_str("x_content_type_options")
                    .map(|s| !s.eq_ignore_ascii_case("off") && !s.is_empty())
                    .unwrap_or(true),
                referrer_policy: m
                    .get_str("referrer_policy")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                content_security_policy: m
                    .get_str("content_security_policy")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                permissions_policy: m
                    .get_str("permissions_policy")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
                hide_server_tokens: m.get_bool("server_token_hidden").unwrap_or(true),
            };
            (m.is_enabled(), p)
        }
        None => (true, SecurityHeadersPolicy::default()),
    };

    let (rewrite_enabled, rewrite_htaccess) = match modules.get("mod_rewrite") {
        Some(m) => (
            m.is_enabled(),
            m.get_bool("enable_htaccess").unwrap_or(true),
        ),
        None => (true, true),
    };

    let proxy = match modules.get("mod_proxy") {
        Some(m) => ProxyModulePolicy {
            enabled: m.is_enabled(),
            preserve_host: m.get_bool("preserve_host").unwrap_or(true),
            websocket_upgrade: m.get_bool("websocket_upgrade").unwrap_or(true),
            connect_timeout_sec: m.get_u64("connect_timeout_sec").unwrap_or(10),
        },
        None => ProxyModulePolicy::default(),
    };

    let fastcgi = match modules.get("mod_fastcgi") {
        Some(m) => FastCgiModulePolicy {
            enabled: m.is_enabled(),
            default_upstream: m
                .get_str("default_upstream")
                .unwrap_or("127.0.0.1:9000")
                .to_string(),
            timeout_sec: m.get_u64("connection_timeout_sec").unwrap_or(60),
            pool_size: m.get_u64("keep_alive_pool_size").unwrap_or(64) as usize,
            dial_timeout_ms: m.get_u64("dial_timeout_ms").unwrap_or(5000),
            keep_conn: m.get_bool("keep_conn").unwrap_or(true),
        },
        None => FastCgiModulePolicy::default(),
    };

    let cache_max_object_bytes = modules
        .get("mod_cache")
        .and_then(|m| m.get_u64("max_object_size_kb"))
        .map(|kb| (kb as usize).saturating_mul(1024))
        .unwrap_or(4 * 1024 * 1024);

    let effective_rate_limit = if config.security.rate_limit_enabled && sec_enabled {
        let base_limit = config.security.rate_limit_per_minute.max(1);
        if base_limit != 2000 {
            base_limit
        } else {
            mod_sec
                .and_then(|m| m.get_u64("token_bucket_rate_limit"))
                .map(|v| (v as u32).max(1))
                .unwrap_or(base_limit)
        }
    } else {
        u32::MAX
    };

    let static_policy = match modules.get("mod_static") {
        Some(m) if m.is_enabled() => StaticModulePolicy {
            etag_enabled: m.get_bool("etag_enabled").unwrap_or(true),
            last_modified_header: m.get_bool("last_modified_header").unwrap_or(true),
            auto_webp: m.get_bool("auto_webp").unwrap_or(true),
            auto_avif: m.get_bool("auto_avif").unwrap_or(true),
            directory_browsing: m.get_bool("directory_browsing").unwrap_or(false),
        },
        _ => StaticModulePolicy {
            auto_webp: false,
            auto_avif: false,
            directory_browsing: false,
            ..StaticModulePolicy::default()
        },
    };

    CompiledPolicies {
        realip,
        gzip,
        waf,
        headers_enabled,
        security_headers,
        rewrite_enabled,
        rewrite_htaccess,
        proxy,
        fastcgi,
        cache_max_object_bytes,
        effective_rate_limit,
        static_policy,
    }
}
