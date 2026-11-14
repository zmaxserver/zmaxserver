//! # ZMax Web Trafik Boru Hattı (8 Katman Mimarisi)
//!
//! L1 Bağlantı -> L2 Protokol/TLS -> L3 Gerçek IP -> L4 Güvenlik ->
//! L5 Yönlendirme -> L6 Önbellek -> L7 İşleyiciler -> L8 Yanıt

pub mod l1_connection;
pub mod l2_protocol;

use bytes::Bytes;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Instant;

use crate::core::state::{ParsedHttpRequest, ServerState};

/// İstek protokol şeması (HTTP veya HTTPS)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn is_https(&self) -> bool {
        matches!(self, Scheme::Https)
    }
}

/// Katman yürütme sonucu: boru hattında ilerle veya erken yanıt dön
pub enum Outcome {
    Continue(RequestContext),
    Respond(ResponseContext),
}

/// Boru hattı katman sözleşmesi trait'i
pub trait PipelineLayer: Send + Sync {
    fn run<'a>(
        &'a self,
        ctx: RequestContext,
        st: &'a ServerState,
    ) -> Pin<Box<dyn Future<Output = Outcome> + Send + 'a>>;
}

/// Katmanlar arası istek bağlamı (RequestContext)
pub struct RequestContext {
    pub peer: SocketAddr,
    pub real_ip: IpAddr,
    pub scheme: Scheme,
    pub tls_sni: Option<String>,
    pub req: ParsedHttpRequest,
    pub started: Instant,
    pub req_id: String,
}

/// Erken yanıt bağlamı (ResponseContext)
pub struct ResponseContext {
    pub status: u16,
    pub reason: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

impl ResponseContext {
    pub fn simple(status: u16, reason: &'static str, body: Bytes, content_type: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: vec![("Content-Type", content_type.to_string())],
            body,
        }
    }
}

/// Yanıt aktarım hedefi trait'i (HTTP/1 veya HTTP/2 için ortak soyutlama)
pub trait ResponseSink: Send + Sync {
    fn send_response(&mut self, resp: ResponseContext) -> Pin<Box<dyn Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + '_>>;
}
