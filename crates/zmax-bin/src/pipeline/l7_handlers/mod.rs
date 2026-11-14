//! L7 — İşleyiciler Katmanı (Handlers Layer)
//! Statik dosya sunumu (`static_files`), FastCGI/PHP (`fastcgi`), Ters Vekil (`proxy`) ve Upstream havuzu (`upstream`).

pub mod fastcgi;
pub mod proxy;
pub mod static_files;
pub mod upstream;

pub use fastcgi::*;
pub use proxy::*;
pub use static_files::*;
pub use upstream::*;
