//! # L2 — Protokol ve TLS Katmanı (`pipeline/l2_protocol/mod.rs`)
//!
//! TLS el sıkışması, ALPN, HTTP/1.1 ve HTTP/2 protokol doğrulamaları,
//! RFC 7230 Host başlığı denetimi, Strict SNI doğrulaması ve sınır kontrolleri.

pub mod h2;

use std::future::Future;
use std::pin::Pin;
use bytes::Bytes;

use crate::core::state::ServerState;
use zmax_config::match_vhost;

use super::{
    Outcome, PipelineLayer, RequestContext, ResponseContext,
};

/// Host adını port ve köşeli parantezlerden arındırarak normalize eder.
pub fn normalize_host_name(host: &str) -> String {
    let trimmed = host.trim();
    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_ascii_lowercase();
        }
    }
    trimmed
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// L2 Protokol Katmanı
pub struct L2ProtocolLayer;

impl L2ProtocolLayer {
    /// L2 Protokol ve RFC 7230 doğrulamalarını yürütür.
    pub async fn run_validations(&self, ctx: RequestContext, st: &ServerState) -> Outcome {
        let req = &ctx.req;

        // 1. RFC 7230 Bölüm 5.4: HTTP/1.1 isteklerinde Host başlığı zorunludur.
        if req.version == 1 && req.host.trim().is_empty() {
            return Outcome::Respond(ResponseContext::simple(
                400,
                "Bad Request",
                Bytes::from_static(b"400 Bad Request - Missing Host Header\n"),
                "text/plain; charset=utf-8",
            ));
        }

        // Birden fazla Host başlığı denetimi (RFC 7230)
        let host_count = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("host"))
            .count();
        if host_count > 1 {
            return Outcome::Respond(ResponseContext::simple(
                400,
                "Bad Request",
                Bytes::from_static(b"400 Bad Request - Multiple Host Headers\n"),
                "text/plain; charset=utf-8",
            ));
        }

        // VHost ve TLS ayarlarını incele
        let (global_strict_sni, vhost_strict_sni, tls_http2) = {
            let rt = st.runtime.read().await;
            let vh_opt = match_vhost(&rt.vhosts, &req.host);
            let global_sni = rt.config.listeners.https.strict_sni;
            if let Some(vh) = vh_opt {
                (global_sni, vh.entry.tls.strict_sni, vh.entry.tls.http2)
            } else {
                (global_sni, false, true)
            }
        };

        // 2. Strict SNI Denetimi (E1 / E7)
        if ctx.scheme.is_https() && (global_strict_sni || vhost_strict_sni) {
            let host_norm = normalize_host_name(&req.host);
            let sni_norm = ctx.tls_sni.as_deref().map(normalize_host_name);
            let mismatch = match sni_norm {
                Some(ref s) => s.is_empty() || s != &host_norm,
                None => true,
            };
            if mismatch {
                return Outcome::Respond(ResponseContext::simple(
                    421,
                    "Misdirected Request",
                    Bytes::from_static(b"421 Misdirected Request - Strict SNI Mismatch\n"),
                    "text/plain; charset=utf-8",
                ));
            }
        }

        // 3. HTTP/2 Etkinlik Denetimi
        if req.version >= 2 && !tls_http2 {
            return Outcome::Respond(ResponseContext::simple(
                421,
                "Misdirected Request",
                Bytes::from_static(b"421 Misdirected Request - HTTP/2 Disabled on Host\n"),
                "text/plain; charset=utf-8",
            ));
        }

        Outcome::Continue(ctx)
    }
}

impl PipelineLayer for L2ProtocolLayer {
    fn run<'a>(
        &'a self,
        ctx: RequestContext,
        st: &'a ServerState,
    ) -> Pin<Box<dyn Future<Output = Outcome> + Send + 'a>> {
        Box::pin(async move {
            self.run_validations(ctx, st).await
        })
    }
}
