//! # zmax-bin :: acme_runtime
//! ACME HTTP-01 küresel (`server.acme.acme_root`) ve sanal konak (`vhost.acme.acme_root`)
//! kök dizin yapılandırmasını çalışma zamanına ve sıcak yenileme (`reload`/`SIGHUP`) döngüsüne bağlar.

use std::path::{Path, PathBuf};
use zmax_config::{resolve_path, VHostEntry, ZMaxConfig};

fn resolve_non_empty_acme_path(raw: Option<&Path>, base_dir: &Path) -> Option<PathBuf> {
    let raw_path = raw?;
    let text = raw_path.to_string_lossy();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(resolve_path(base_dir, trimmed))
}

/// Yapılandırmada (`server.acme.acme_root` veya yedek `acme.acme_root`) boş olmayan bir ACME kökü
/// tanımlıysa `zmax_static::set_global_acme_root` ile küresel kökü ayarlar.
/// Alan tanımsız veya boşsa mevcut küresel ACME köküne dokunmaz (`clear_global_acme_root` çağrılmaz).
pub fn apply_global_acme_root(config: &ZMaxConfig, base_dir: &Path) {
    let configured = resolve_non_empty_acme_path(config.server.acme.acme_root.as_deref(), base_dir)
        .or_else(|| resolve_non_empty_acme_path(config.acme.acme_root.as_deref(), base_dir));

    if let Some(resolved_root) = configured {
        zmax_static::set_global_acme_root(&resolved_root);
    }
}

/// Sanal konak yapılandırmasında `[vhost.acme] acme_root` boş olmayan biçimde tanımlıysa
/// `base_dir` üzerinden mutlak/göreceli yolu çözümleyerek döndürür.
pub fn resolve_vhost_acme_root(vhost: Option<&VHostEntry>, base_dir: &Path) -> Option<PathBuf> {
    let entry = vhost?;
    resolve_non_empty_acme_path(entry.acme.acme_root.as_deref(), base_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_GLOBAL_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn apply_global_acme_root_sets_only_when_non_empty() {
        let _guard = TEST_GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        zmax_static::clear_global_acme_root();

        let base = std::env::temp_dir().join("zmax_acme_runtime_unit");
        let _ = std::fs::create_dir_all(base.join("shared_acme"));

        // Başlangıçta bir küresel kök ayarla; boş config geldiğinde sıfırlanmamalı
        let initial_dir = base.join("initial_acme");
        let _ = std::fs::create_dir_all(&initial_dir);
        zmax_static::set_global_acme_root(&initial_dir);

        let empty_cfg = ZMaxConfig::default();
        apply_global_acme_root(&empty_cfg, &base);
        assert_eq!(
            zmax_static::get_global_acme_root(),
            Some(initial_dir.clone())
        );

        // Whitespace değerli config de mevcut küresel kökü sıfırlamamalı
        let mut ws_cfg = ZMaxConfig::default();
        ws_cfg.server.acme.acme_root = Some(PathBuf::from("   "));
        apply_global_acme_root(&ws_cfg, &base);
        assert_eq!(zmax_static::get_global_acme_root(), Some(initial_dir));

        // Dolu göreceli acme_root geldiğinde base_dir ile çözülüp güncellenmeli
        let mut configured_cfg = ZMaxConfig::default();
        configured_cfg.server.acme.acme_root = Some(PathBuf::from("shared_acme"));
        apply_global_acme_root(&configured_cfg, &base);
        assert_eq!(
            zmax_static::get_global_acme_root(),
            Some(base.join("shared_acme"))
        );

        zmax_static::clear_global_acme_root();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_vhost_acme_root_handles_relative_empty_and_absolute() {
        let base = std::env::temp_dir().join("zmax_vhost_acme_unit");

        assert!(resolve_vhost_acme_root(None, &base).is_none());

        let mut vh = VHostEntry::default();
        assert!(resolve_vhost_acme_root(Some(&vh), &base).is_none());

        vh.acme.acme_root = Some(PathBuf::from("  "));
        assert!(resolve_vhost_acme_root(Some(&vh), &base).is_none());

        vh.acme.acme_root = Some(PathBuf::from("custom/acme"));
        assert_eq!(
            resolve_vhost_acme_root(Some(&vh), &base),
            Some(base.join("custom/acme"))
        );
    }
}
