//! Günlük döndürme (`.1` yedek).

use std::path::{Path, PathBuf};

pub(super) async fn rotate_log_file(log_file: &Path) {
    let mut backup_os = log_file.as_os_str().to_os_string();
    backup_os.push(".1");
    let backup_file = PathBuf::from(backup_os);
    if tokio::fs::rename(log_file, &backup_file).await.is_err() {
        let _ = tokio::fs::remove_file(&backup_file).await;
        let _ = tokio::fs::rename(log_file, &backup_file).await;
    }
}


pub(crate) const DEFAULT_LOG_ROTATION_MAX_BYTES: u64 = 100 * 1024 * 1024;

/// Belirtilen günlük dosyasına satır ekler; boyut `max_bytes` eşiğine ulaştığında `.1` yedeğine döndürür.
pub async fn append_line_with_rotation(log_file: &Path, line: &str, max_bytes: u64) {
    use tokio::io::AsyncWriteExt;

    if let Some(parent) = log_file.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
    }

    if max_bytes > 0 {
        if let Ok(meta) = tokio::fs::metadata(log_file).await {
            if meta.is_file() && meta.len() >= max_bytes {
                let mut backup_os = log_file.as_os_str().to_os_string();
                backup_os.push(".1");
                let backup_file = PathBuf::from(backup_os);
                if tokio::fs::rename(log_file, &backup_file).await.is_err() {
                    let _ = tokio::fs::remove_file(&backup_file).await;
                    let _ = tokio::fs::rename(log_file, &backup_file).await;
                }
            }
        }
    }

    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .await
    {
        if line.ends_with('\n') {
            let _ = f.write_all(line.as_bytes()).await;
        } else {
            let _ = f.write_all(format!("{line}\n").as_bytes()).await;
        }
        let _ = f.flush().await;
    }
}

/// Hata/uyarı günlüklerini `logs/error.log` dosyasına boyut sınırı ile güvenli şekilde yazar.
pub async fn append_error_log_limit(base_dir: &Path, line: &str, max_bytes: u64) {
    let log_file = base_dir.join("logs").join("error.log");
    append_line_with_rotation(&log_file, line, max_bytes).await;
}

/// Erişim günlüklerini `logs/access.log` dosyasına boyut sınırı ile güvenli şekilde yazar.
pub async fn append_access_log_limit(base_dir: &Path, line: &str, max_bytes: u64) {
    let log_file = base_dir.join("logs").join("access.log");
    append_line_with_rotation(&log_file, line, max_bytes).await;
}

/// Hata/uyarı günlüklerini `logs/error.log` dosyasına güvenli şekilde yazar.
pub async fn append_error_log(base_dir: &Path, line: &str) {
    append_error_log_limit(base_dir, line, DEFAULT_LOG_ROTATION_MAX_BYTES).await;
}
