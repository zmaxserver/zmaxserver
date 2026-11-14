//! Web Trafik Boru Hattı — katmanlı istek boru hattı (L3 gerçek IP, L4 güvenlik, L5 yönlendirme, L6 önbellek, L7 işleyiciler, L8 yanıt).

pub mod l3_realip;
pub mod l4_security;
pub mod l5_router;
pub mod l6_cache;
pub mod l7_handlers;
pub mod l8_response;
