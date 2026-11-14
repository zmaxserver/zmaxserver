//! Web Trafik Boru Hattı — Katmanlı istek boru hattı (L3 gerçek IP, L4 güvenlik, L7 işleyiciler, L8 yanıt).

pub mod l3_realip;
pub mod l4_security;
pub mod l7_handlers;
pub mod l8_response;
