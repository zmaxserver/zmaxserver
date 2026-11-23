//! # zmax-header
//! HTTP başlık haritası, normalizasyon ve kurumsal güvenlik başlıkları (HSTS, CSP, X-Frame).

use http::header::{HeaderMap, HeaderName, HeaderValue};
use std::collections::HashSet;

pub struct SecurityHeaders;

impl SecurityHeaders {
    /// Kurumsal standart güvenlik başlıklarını yanıta enjekte eder
    pub fn apply(headers: &mut HeaderMap) {
        headers.insert(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("SAMEORIGIN"),
        );
        headers.insert(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        );
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("zmaxserver"),
        );
    }
}

/// Yapılandırılabilir HTTP güvenlik başlığı politikası.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeadersPolicy {
    pub hsts_enabled: bool,
    pub hsts_max_age: u64,
    pub hsts_include_subdomains: bool,
    pub x_frame_options: Option<String>,
    pub x_content_type_options: bool,
    pub referrer_policy: Option<String>,
    pub content_security_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub hide_server_tokens: bool,
}

impl Default for SecurityHeadersPolicy {
    fn default() -> Self {
        Self {
            hsts_enabled: true,
            hsts_max_age: 31_536_000,
            hsts_include_subdomains: false,
            x_frame_options: Some("SAMEORIGIN".to_string()),
            x_content_type_options: true,
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            content_security_policy: None,
            permissions_policy: None,
            hide_server_tokens: true,
        }
    }
}

impl SecurityHeadersPolicy {
    /// Ham HTTP yanıt başlık bloğuna (`out`) politika başlıklarını enjekte eder.
    /// Halihazırda bulunan başlıkları ezmez ve mükerrer yazmaz.
    pub fn append_headers(&self, out: &mut String, is_https: bool) {
        let had_terminator = out.ends_with("\r\n\r\n");
        if had_terminator {
            out.truncate(out.len() - 2);
        } else if !out.is_empty() && !out.ends_with("\r\n") {
            out.push_str("\r\n");
        }

        if self.hide_server_tokens {
            strip_leaky_tokens(out);
        }

        let existing = collect_existing_header_names(out);

        if is_https && self.hsts_enabled && !existing.contains("strict-transport-security") {
            if self.hsts_include_subdomains {
                out.push_str(&format!(
                    "Strict-Transport-Security: max-age={}; includeSubDomains\r\n",
                    self.hsts_max_age
                ));
            } else {
                out.push_str(&format!(
                    "Strict-Transport-Security: max-age={}\r\n",
                    self.hsts_max_age
                ));
            }
        }

        if self.x_content_type_options && !existing.contains("x-content-type-options") {
            out.push_str("X-Content-Type-Options: nosniff\r\n");
        }

        if let Some(ref val) = self.x_frame_options {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !existing.contains("x-frame-options") {
                out.push_str(&format!("X-Frame-Options: {}\r\n", trimmed));
            }
        }

        if let Some(ref val) = self.referrer_policy {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !existing.contains("referrer-policy") {
                out.push_str(&format!("Referrer-Policy: {}\r\n", trimmed));
            }
        }

        if let Some(ref val) = self.content_security_policy {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !existing.contains("content-security-policy") {
                out.push_str(&format!("Content-Security-Policy: {}\r\n", trimmed));
            }
        }

        if let Some(ref val) = self.permissions_policy {
            let trimmed = val.trim();
            if !trimmed.is_empty() && !existing.contains("permissions-policy") {
                out.push_str(&format!("Permissions-Policy: {}\r\n", trimmed));
            }
        }

        if self.hide_server_tokens && !existing.contains("server") {
            out.push_str("Server: zmaxserver\r\n");
        }

        if had_terminator {
            out.push_str("\r\n");
        }
    }
}

fn collect_existing_header_names(raw: &str) -> HashSet<String> {
    let mut names = HashSet::new();
    for (idx, line) in raw.split("\r\n").enumerate() {
        // İlk satır durum satırıdır (HTTP/1.1 200 OK)
        if idx == 0 && line.starts_with("HTTP/") {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let lower = name.trim().to_ascii_lowercase();
            if !lower.is_empty() {
                names.insert(lower);
            }
        }
    }
    names
}

fn strip_leaky_tokens(raw: &mut String) {
    let mut filtered = String::with_capacity(raw.len());
    let trailing_crlf = raw.ends_with("\r\n");
    for (idx, line) in raw.split("\r\n").enumerate() {
        if line.is_empty() {
            continue;
        }
        if idx > 0 {
            if let Some((name, _)) = line.split_once(':') {
                let lower = name.trim().to_ascii_lowercase();
                if matches!(
                    lower.as_str(),
                    "x-powered-by" | "x-aspnet-version" | "x-aspnetmvc-version"
                ) {
                    continue;
                }
            }
        }
        filtered.push_str(line);
        filtered.push_str("\r\n");
    }
    if !trailing_crlf && filtered.ends_with("\r\n") {
        filtered.truncate(filtered.len() - 2);
    }
    *raw = filtered;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_legacy_security_headers_apply() {
        let mut map = HeaderMap::new();
        SecurityHeaders::apply(&mut map);
        assert_eq!(map.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(map.get("x-frame-options").unwrap(), "SAMEORIGIN");
        assert_eq!(map.get("x-xss-protection").unwrap(), "1; mode=block");
        assert_eq!(map.get("server").unwrap(), "zmaxserver");
    }

    #[test]
    fn test_policy_append_headers_http_vs_https() {
        let policy = SecurityHeadersPolicy {
            hsts_enabled: true,
            hsts_max_age: 63_072_000,
            hsts_include_subdomains: true,
            content_security_policy: Some("default-src 'self'".to_string()),
            permissions_policy: Some("geolocation=()".to_string()),
            ..Default::default()
        };

        let mut http_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".to_string();
        policy.append_headers(&mut http_resp, false);
        assert!(!http_resp.contains("Strict-Transport-Security"));
        assert!(http_resp.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(http_resp.contains("X-Frame-Options: SAMEORIGIN\r\n"));
        assert!(http_resp.contains("Referrer-Policy: strict-origin-when-cross-origin\r\n"));
        assert!(http_resp.contains("Content-Security-Policy: default-src 'self'\r\n"));
        assert!(http_resp.contains("Permissions-Policy: geolocation=()\r\n"));
        assert!(http_resp.contains("Server: zmaxserver\r\n"));
        assert!(http_resp.ends_with("\r\n\r\n"));

        let mut https_resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".to_string();
        policy.append_headers(&mut https_resp, true);
        assert!(https_resp.contains(
            "Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n"
        ));
        assert!(https_resp.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_policy_does_not_overwrite_or_duplicate_existing_headers() {
        let policy = SecurityHeadersPolicy::default();
        let mut resp = concat!(
            "HTTP/1.1 200 OK\r\n",
            "server: custom-app\r\n",
            "x-frame-options: DENY\r\n",
            "X-Powered-By: PHP/8.3\r\n",
            "\r\n"
        )
        .to_string();

        policy.append_headers(&mut resp, true);
        assert!(resp.contains("x-frame-options: DENY\r\n"));
        assert!(!resp.contains("SAMEORIGIN"));
        assert_eq!(resp.to_ascii_lowercase().matches("x-frame-options:").count(), 1);
        assert_eq!(resp.to_ascii_lowercase().matches("server:").count(), 1);
        assert!(resp.contains("server: custom-app\r\n"));
        assert!(!resp.contains("X-Powered-By"));
        assert!(resp.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_policy_appends_to_open_header_block() {
        let policy = SecurityHeadersPolicy {
            hide_server_tokens: false,
            ..Default::default()
        };
        let mut partial = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n".to_string();
        policy.append_headers(&mut partial, false);
        assert!(partial.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(!partial.contains("Server: zmaxserver"));
        assert!(!partial.ends_with("\r\n\r\n"));
        assert!(partial.ends_with("\r\n"));
    }
}
