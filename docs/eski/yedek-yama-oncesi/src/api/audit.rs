//! A9 — Denetim kaydı: yazma işlemleri `logs/audit.log` dosyasına tek satır olarak yazılır.
//! Token, parola ve gizli değer ASLA yazılmaz; yalnız işlem adı ve hedef (domain/ip/kapsam) girer.

use crate::core::state::ServerState;
use crate::logger::rotate::{append_line_with_rotation, DEFAULT_LOG_ROTATION_MAX_BYTES};
use std::time::{SystemTime, UNIX_EPOCH};

/// Satır alanlarındaki ayraç/satır sonu karakterlerini temizler (kayıt enjeksiyonu önlemi).
fn temiz(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() || c == '|' { ' ' } else { c })
        .take(200)
        .collect()
}

/// Unix saniyesinden UTC `YYYY-MM-DDTHH:MM:SSZ`.
fn utc_zaman() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60
    )
}

/// Tek satır üretir: `zaman | kanal | rol | işlem | hedef | sonuç`.
pub(crate) fn satir(kanal: &str, rol: &str, islem: &str, hedef: &str, ok: bool) -> String {
    format!(
        "{} | {} | {} | {} | {} | {}",
        utc_zaman(),
        temiz(kanal),
        temiz(rol),
        temiz(islem),
        temiz(hedef),
        if ok { "ok" } else { "hata" }
    )
}

/// Yazma işlemini `logs/audit.log` dosyasına ekler (mevcut rotasyon altyapısıyla).
/// Rol henüz bilinmiyorsa (M13 auth rolü yok) "bilinmiyor" yazılır.
pub(crate) async fn kayit(state: &ServerState, kanal: &str, islem: &str, hedef: &str, ok: bool) {
    let line = satir(kanal, "bilinmiyor", islem, hedef, ok);
    let file = state.base_dir.join("logs").join("audit.log");
    append_line_with_rotation(&file, &line, DEFAULT_LOG_ROTATION_MAX_BYTES).await;
}
