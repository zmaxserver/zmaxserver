// Surum tek kaynaktan (depo kokundeki VERSION) okunur ve ZMAX_VERSION olarak derlemeye gomulur.
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let version_file = manifest.join("..").join("..").join("VERSION");
    println!("cargo:rerun-if-changed={}", version_file.display());
    let fallback = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let version = match std::fs::read_to_string(&version_file) {
        Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            println!(
                "cargo:warning=VERSION dosyasi okunamadi veya bos, CARGO_PKG_VERSION kullaniliyor"
            );
            fallback
        }
    };
    println!("cargo:rustc-env=ZMAX_VERSION={version}");
}
