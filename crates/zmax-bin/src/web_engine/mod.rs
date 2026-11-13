//! # ZMax Web Trafik Motoru
//! HTTP/1.1 Keep-Alive döngüsü, WAF/Rate-Limit/WP Kalkanı, Rewrite/`.htaccess`,
//! Reverse Proxy + WebSocket, FastCGI (PHP), Range/ETag/Gzip Statik Sunum ve L1/L2 Önbellek.

mod cache_policy;
mod cached_response;
mod context;
mod extra_listeners;
mod http_write;
#[cfg(test)]
mod kart8_tests;
mod logging;
mod php;
mod pipeline_h1;
mod pipeline_h2;
mod proxy_h1;
mod proxy_h2;
mod purge;
mod request_util;
mod static_files;
mod static_stream;

pub use crate::api::ParsedHttpRequest;
pub use context::ResolvedVHostContext;
pub use extra_listeners::reconcile as reconcile_extra_listeners;
pub use http_write::write_http_response;
pub use pipeline_h1::handle_web_connection;
pub use pipeline_h2::handle_h2_dispatched_request;
pub use proxy_h2::H2BodyReceiver;
pub use request_util::{https_redirect_location, is_acme_challenge};

const MAX_STATIC_CACHE_BYTES: usize = 2 * 1024 * 1024;
const MAX_GZIP_IN_MEMORY_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_LOG_MAX_BYTES: u64 = 100 * 1024 * 1024;
