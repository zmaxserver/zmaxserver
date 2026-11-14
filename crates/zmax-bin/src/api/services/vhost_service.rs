use super::super::*;

pub(crate) fn format_vhost_json(v: &LoadedVHost) -> String {
    zmax_config::vhost_json::format_loaded_vhost_json(v)
}

pub(crate) async fn write_vhost_atomic_with_rollback(
    vhosts_dir: &Path,
    domain: &str,
    entry: &VHostEntry,
    state: &Arc<ServerState>,
) -> Result<usize, String> {
    tokio::fs::create_dir_all(vhosts_dir)
        .await
        .map_err(|e| format!("vhosts dizini oluşturulamadı: {}", e))?;

    let file_name = format!("{}.toml", domain);
    let target = vhosts_dir.join(&file_name);
    let tmp_path = vhosts_dir.join(format!(".{}.tmp", file_name));

    // Var olan dosyanın içeriğini belleğe yedekle (varsa)
    let backup_bytes: Option<Vec<u8>> = if target.exists() {
        match tokio::fs::read(&target).await {
            Ok(bytes) => Some(bytes),
            Err(e) => return Err(format!("Mevcut vHost dosyası yedeklenemedi: {}", e)),
        }
    } else {
        None
    };

    let toml_text =
        serialize_vhost_toml(entry).map_err(|e| format!("TOML serileştirme hatası: {}", e))?;
    let content = format!(
        "# ZMax Server API tarafından otomatik yönetilen Sanal Konak ({})\n{}",
        domain, toml_text
    );

    // 1. Önce geçici dosyaya yaz
    if let Err(e) = tokio::fs::write(&tmp_path, content.as_bytes()).await {
        return Err(format!("Geçici vHost dosyası yazılamadı: {}", e));
    }

    // 2. Atomik rename ile asıl dosyanın üzerine taşı
    if let Err(e) = tokio::fs::rename(&tmp_path, &target).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(format!("vHost dosyası taşınamadı: {}", e));
    }

    // 3. Çalışma zamanı durumunu (runtime) reload et
    match reload_runtime_state(state).await {
        Ok(count) => {
            // Aktif çalışma zamanındaki vHost ile yazılanın birebir eşit olduğunu doğrula
            let rt = state.runtime.read().await;
            if let Some(loaded) = rt
                .vhosts
                .iter()
                .find(|v| v.entry.name.eq_ignore_ascii_case(domain))
            {
                if let Some(diff) = zmax_config::vhost_entry_diff(entry, &loaded.entry) {
                    drop(rt);
                    rollback_vhost_file(&target, backup_bytes.as_deref()).await;
                    let _ = reload_runtime_state(state).await;
                    return Err(format!(
                        "Aktif çalışma zamanı yapılandırması yazılanla eşleşmiyor: {}",
                        diff
                    ));
                }
            }
            Ok(count)
        }
        Err(err) => {
            // RELOAD HATASI: Çalışan eski TOML dosyasına geri dön (ROLLBACK)
            rollback_vhost_file(&target, backup_bytes.as_deref()).await;
            let _ = reload_runtime_state(state).await;
            Err(format!(
                "vHost uygulanamadı, çalışan TOML geri yüklendi: {}",
                err
            ))
        }
    }
}

pub(crate) async fn rollback_vhost_file(target: &Path, backup: Option<&[u8]>) {
    match backup {
        Some(old_content) => {
            let _ = tokio::fs::write(target, old_content).await;
        }
        None => {
            let _ = tokio::fs::remove_file(target).await;
        }
    }
}

pub(crate) fn merge_vhost_json_patch(
    base: &VHostEntry,
    domain: &str,
    body: &[u8],
) -> Result<VHostEntry, String> {
    zmax_config::vhost_json::merge_vhost_json_patch(base, domain, body)
}

