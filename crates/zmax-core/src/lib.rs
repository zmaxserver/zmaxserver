//! # zmax-core
//! ZMax Server asenkron ağ ve worker yaşam döngüsü çekirdeği.

use std::time::{SystemTime, UNIX_EPOCH};

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 80,
            workers: num_cpus_estimate(),
        }
    }
}

pub fn num_cpus_estimate() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Sistemde kullanılabilir CPU çekirdeği sayısını döndürür (en az 1).
#[cfg(unix)]
pub fn available_cpu_cores() -> usize {
    if let Ok(n) = std::thread::available_parallelism() {
        return n.get().max(1);
    }
    let count = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if count > 0 {
        count as usize
    } else {
        1
    }
}

/// Sistemde kullanılabilir CPU çekirdeği sayısını döndürür (en az 1).
#[cfg(not(unix))]
pub fn available_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().max(1))
        .unwrap_or(1)
}

/// Geçerli iş parçacığını belirtilen CPU çekirdeğine sabitler (`sched_setaffinity`).
#[cfg(all(unix, target_os = "linux"))]
pub fn pin_current_thread_to_core(core_id: usize) -> Result<(), String> {
    if core_id >= libc::CPU_SETSIZE as usize {
        return Err(format!(
            "CPU çekirdek numarası CPU_SETSIZE sınırını aşıyor: {} (üst sınır: {})",
            core_id,
            libc::CPU_SETSIZE
        ));
    }
    let cores = available_cpu_cores();
    if core_id >= cores {
        return Err(format!(
            "Geçersiz CPU çekirdek numarası: {} (mevcut: 0..{})",
            core_id, cores
        ));
    }
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core_id, &mut set);
    }
    let rc = unsafe {
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "İş parçacığı {} numaralı çekirdeğe sabitlenemedi: {}",
            core_id,
            std::io::Error::last_os_error()
        ))
    }
}

/// Linux dışı Unix türevlerinde CPU sabitleme için güvenli uyarı yedeklemesi.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn pin_current_thread_to_core(core_id: usize) -> Result<(), String> {
    let cores = available_cpu_cores();
    if core_id >= cores {
        return Err(format!(
            "Geçersiz CPU çekirdek numarası: {} (mevcut: 0..{})",
            core_id, cores
        ));
    }
    tracing::warn!(
        "Bu Unix platformunda sched_setaffinity desteklenmiyor; CPU sabitleme atlandı (core_id={})",
        core_id
    );
    Ok(())
}

/// Windows ortamında CPU çekirdeği sabitleme için güvenli uyarı yedeklemesi.
#[cfg(not(unix))]
pub fn pin_current_thread_to_core(core_id: usize) -> Result<(), String> {
    let cores = available_cpu_cores();
    if core_id >= cores {
        return Err(format!(
            "Geçersiz CPU çekirdek numarası: {} (mevcut: 0..{})",
            core_id, cores
        ));
    }
    tracing::warn!(
        "Windows ortamında POSIX sched_setaffinity desteklenmiyor; CPU sabitleme atlandı (core_id={})",
        core_id
    );
    Ok(())
}

fn validate_account_name<'a>(label: &str, raw: &'a str) -> Result<&'a str, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{} adı boş olamaz", label));
    }
    if trimmed.contains('\0')
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '/' || c == '\\' || c == ':')
    {
        return Err(format!("Geçersiz {} adı: '{}'", label, trimmed));
    }
    Ok(trimmed)
}

#[cfg(unix)]
fn lookup_gid_by_name(c_group: &std::ffi::CString) -> Result<libc::gid_t, String> {
    let mut buf_len = 4096usize;
    loop {
        let mut grp = std::mem::MaybeUninit::<libc::group>::zeroed();
        let mut buf = vec![0u8; buf_len];
        let mut result: *mut libc::group = std::ptr::null_mut();
        let rc = unsafe {
            libc::getgrnam_r(
                c_group.as_ptr(),
                grp.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return Err(format!("Grup bulunamadı: '{}'", c_group.to_string_lossy()));
            }
            let grp_ref = unsafe { grp.assume_init_ref() };
            let _name = unsafe { std::ffi::CStr::from_ptr(grp_ref.gr_name) };
            return Ok(grp_ref.gr_gid);
        }
        if rc == libc::ERANGE && buf_len < 1024 * 1024 {
            buf_len *= 2;
            continue;
        }
        return Err(format!(
            "Grup bilgisi okunamadı ('{}'): {}",
            c_group.to_string_lossy(),
            std::io::Error::from_raw_os_error(rc)
        ));
    }
}

#[cfg(unix)]
fn lookup_uid_by_name(c_user: &std::ffi::CString) -> Result<libc::uid_t, String> {
    let mut buf_len = 4096usize;
    loop {
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::zeroed();
        let mut buf = vec![0u8; buf_len];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == 0 {
            if result.is_null() {
                return Err(format!("Kullanıcı bulunamadı: '{}'", c_user.to_string_lossy()));
            }
            let pwd_ref = unsafe { pwd.assume_init_ref() };
            let _name = unsafe { std::ffi::CStr::from_ptr(pwd_ref.pw_name) };
            return Ok(pwd_ref.pw_uid);
        }
        if rc == libc::ERANGE && buf_len < 1024 * 1024 {
            buf_len *= 2;
            continue;
        }
        return Err(format!(
            "Kullanıcı bilgisi okunamadı ('{}'): {}",
            c_user.to_string_lossy(),
            std::io::Error::from_raw_os_error(rc)
        ));
    }
}

/// POSIX ortamında kök yetkilerini belirtilen kullanıcı ve gruba düşürür (`setgid` -> `setuid`).
#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> Result<(), String> {
    let user = validate_account_name("Kullanıcı", user)?;
    let group = validate_account_name("Grup", group)?;

    let c_user = std::ffi::CString::new(user)
        .map_err(|_| "Kullanıcı adında NUL karakteri bulunamaz".to_string())?;
    let c_group = std::ffi::CString::new(group)
        .map_err(|_| "Grup adında NUL karakteri bulunamaz".to_string())?;

    let gid = lookup_gid_by_name(&c_group)?;
    let uid = lookup_uid_by_name(&c_user)?;

    // Önce grup yetkisi düşürülür; kullanıcı yetkisi düştükten sonra setgid yapılamaz.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(format!(
            "setgid({}) başarısız ({}): {}",
            gid,
            group,
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(format!(
            "setuid({}) başarısız ({}): {}",
            uid,
            user,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Windows ortamında POSIX yetki düşürme için güvenli uyarı yedeklemesi.
#[cfg(not(unix))]
pub fn drop_privileges(user: &str, group: &str) -> Result<(), String> {
    let user = validate_account_name("Kullanıcı", user)?;
    let group = validate_account_name("Grup", group)?;
    tracing::warn!(
        "Windows ortamında POSIX drop_privileges desteklenmiyor; atlandı (user='{}', group='{}')",
        user,
        group
    );
    Ok(())
}

/// Howard Hinnant sivil takvim algoritması ile UNIX gün sayısını `(yıl, ay, gün)` üçlüsüne çevirir.
#[inline]
const fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m as u32, d as u32)
}

#[inline]
fn system_time_to_utc_parts(t: SystemTime) -> (u16, u32, u32, u32, u32, u32) {
    let epoch_secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(err) => {
            let d = err.duration();
            let secs = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
            if d.subsec_nanos() > 0 {
                secs.saturating_neg().saturating_sub(1)
            } else {
                secs.saturating_neg()
            }
        }
    };
    let days = epoch_secs.div_euclid(86_400);
    let rem = epoch_secs.rem_euclid(86_400) as u32;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (year, month, day) = civil_from_days(days);
    let clamped_year = year.clamp(0, 9999) as u16;
    (clamped_year, month, day, hour, minute, second)
}

#[inline]
const fn write_2digits(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset] = b'0' + ((val / 10) % 10) as u8;
    buf[offset + 1] = b'0' + (val % 10) as u8;
}

#[inline]
const fn write_4digits(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset] = b'0' + ((val / 1000) % 10) as u8;
    buf[offset + 1] = b'0' + ((val / 100) % 10) as u8;
    buf[offset + 2] = b'0' + ((val / 10) % 10) as u8;
    buf[offset + 3] = b'0' + (val % 10) as u8;
}

/// NCSA Combined Log Format zaman damgasını sabit 26 baytlık yığın tamponuna sıfır ek tahsisle yazar.
pub fn write_clf_timestamp_buf(buf: &mut [u8; 26], t: SystemTime) {
    const MONTHS: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun",
        b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
    ];
    let (year, month, day, hour, minute, second) = system_time_to_utc_parts(t);
    let mon = MONTHS[(month.saturating_sub(1) as usize).min(11)];

    write_2digits(buf, 0, day);
    buf[2] = b'/';
    buf[3] = mon[0];
    buf[4] = mon[1];
    buf[5] = mon[2];
    buf[6] = b'/';
    write_4digits(buf, 7, year);
    buf[11] = b':';
    write_2digits(buf, 12, hour);
    buf[14] = b':';
    write_2digits(buf, 15, minute);
    buf[17] = b':';
    write_2digits(buf, 18, second);
    buf[20..26].copy_from_slice(b" +0000");
}

/// Sistem zamanını NCSA Combined Log Formatında (`11/Nov/2026:21:00:00 +0000`) döndürür.
pub fn format_clf_timestamp(t: SystemTime) -> String {
    let mut buf = [0u8; 26];
    write_clf_timestamp_buf(&mut buf, t);
    String::from_utf8(buf.to_vec()).expect("ASCII zaman damgası her zaman geçerli UTF-8'dir")
}

/// ISO-8601 UTC zaman damgasını sabit 20 baytlık yığın tamponuna sıfır ek tahsisle yazar.
pub fn write_iso8601_utc_buf(buf: &mut [u8; 20], t: SystemTime) {
    let (year, month, day, hour, minute, second) = system_time_to_utc_parts(t);

    write_4digits(buf, 0, year);
    buf[4] = b'-';
    write_2digits(buf, 5, month);
    buf[7] = b'-';
    write_2digits(buf, 8, day);
    buf[10] = b'T';
    write_2digits(buf, 11, hour);
    buf[13] = b':';
    write_2digits(buf, 14, minute);
    buf[16] = b':';
    write_2digits(buf, 17, second);
    buf[19] = b'Z';
}

/// Sistem zamanını ISO-8601 UTC biçiminde (`2026-11-11T21:00:00Z`) döndürür.
pub fn format_iso8601_utc(t: SystemTime) -> String {
    let mut buf = [0u8; 20];
    write_iso8601_utc_buf(&mut buf, t);
    String::from_utf8(buf.to_vec()).expect("ASCII zaman damgası her zaman geçerli UTF-8'dir")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn utc_time(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn test_timestamps_unix_epoch() {
        assert_eq!(format_clf_timestamp(UNIX_EPOCH), "01/Jan/1970:00:00:00 +0000");
        assert_eq!(format_iso8601_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn test_timestamps_leap_years_and_century_rule() {
        // 2000-02-29T12:34:56Z (400'e bölünen artık yıl)
        let y2000_leap = utc_time(951_827_696);
        assert_eq!(format_clf_timestamp(y2000_leap), "29/Feb/2000:12:34:56 +0000");
        assert_eq!(format_iso8601_utc(y2000_leap), "2000-02-29T12:34:56Z");

        // 2024-02-29T23:59:59Z (4'e bölünen artık yıl)
        let y2024_leap = utc_time(1_709_251_199);
        assert_eq!(format_clf_timestamp(y2024_leap), "29/Feb/2024:23:59:59 +0000");
        assert_eq!(format_iso8601_utc(y2024_leap), "2024-02-29T23:59:59Z");

        // 2100 yılı 100'e bölünüp 400'e bölünmediği için artık yıl değildir: 28 Şub -> 1 Mar
        let y2100_feb28_end = utc_time(4_107_542_399);
        let y2100_mar01 = utc_time(4_107_542_400);
        assert_eq!(format_iso8601_utc(y2100_feb28_end), "2100-02-28T23:59:59Z");
        assert_eq!(format_iso8601_utc(y2100_mar01), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn test_timestamps_2026_reference_date() {
        // 2026-11-11T21:00:00Z = 1_794_430_800
        let t = utc_time(1_794_430_800);
        assert_eq!(format_clf_timestamp(t), "11/Nov/2026:21:00:00 +0000");
        assert_eq!(format_iso8601_utc(t), "2026-11-11T21:00:00Z");
    }

    #[test]
    fn test_zero_alloc_stack_buffer_writers() {
        let t = utc_time(1_794_430_800);
        let mut clf_buf = [0u8; 26];
        let mut iso_buf = [0u8; 20];
        write_clf_timestamp_buf(&mut clf_buf, t);
        write_iso8601_utc_buf(&mut iso_buf, t);
        assert_eq!(&clf_buf, b"11/Nov/2026:21:00:00 +0000");
        assert_eq!(&iso_buf, b"2026-11-11T21:00:00Z");
    }

    #[test]
    fn test_available_cpu_cores_and_pin_bounds() {
        let cores = available_cpu_cores();
        assert!(cores >= 1);
        assert!(num_cpus_estimate() >= 1);

        // Geçerli 0 numaralı çekirdeğe sabitleme temiz geçmeli (Windows'ta uyarı ile Ok döner)
        assert!(pin_current_thread_to_core(0).is_ok());

        // Çekirdek sayısı dışındaki kimlik reddedilmeli
        assert!(pin_current_thread_to_core(cores.saturating_add(1000)).is_err());
    }

    #[test]
    fn test_drop_privileges_empty_and_invalid_validation() {
        assert!(drop_privileges("", "nobody").is_err());
        assert!(drop_privileges("nobody", "").is_err());
        assert!(drop_privileges("   ", "   ").is_err());
        assert!(drop_privileges("bad\0user", "nobody").is_err());
        assert!(drop_privileges("bad user", "nobody").is_err());
        assert!(drop_privileges("nobody", "bad/group").is_err());

        #[cfg(unix)]
        {
            assert!(drop_privileges("zmax_nonexistent_user_99999", "nobody").is_err());
            assert!(drop_privileges("nobody", "zmax_nonexistent_group_99999").is_err());
        }

        #[cfg(not(unix))]
        {
            // Windows ortamında geçerli biçimli kullanıcı/grup adı temiz uyarı ile Ok döner
            assert!(drop_privileges("nobody", "nobody").is_ok());
        }
    }
}

