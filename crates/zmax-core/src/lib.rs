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
    // SAFETY: sysconf(_SC_NPROCESSORS_ONLN) güvenli bir POSIX sistem konfigürasyonu sorgusudur.
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
    // SAFETY: `cpu_set_t` C POD yapısıdır; tüm baytlarının sıfırlanması geçerli boş küme durumudur.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: `set` geçerli `cpu_set_t` nesnesidir; `core_id` < CPU_SETSIZE doğrulanmıştır.
    unsafe {
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core_id, &mut set);
    }
    // SAFETY: `set` bellek boyutu ve işaretçisi geçerlidir; `0` geçerli iş parçacığını hedefler.
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
        // SAFETY: `getgrnam_r` re-entrant bir POSIX fonksiyonudur; `c_group`, `grp` ve `buf` geçerli işaretçilerdir.
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
            // SAFETY: `result` null olmadığında ve `rc == 0` iken `grp` libc tarafından başarıyla başlatılmıştır.
            let grp_ref = unsafe { grp.assume_init_ref() };
            // SAFETY: `grp_ref.gr_name` libc tarafından ayrılmış ve null ile sonlandırılmış geçerli C dizesidir.
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
        // SAFETY: `getpwnam_r` re-entrant bir POSIX fonksiyonudur; `c_user`, `pwd` ve `buf` geçerli işaretçilerdir.
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
            // SAFETY: `result` null olmadığında ve `rc == 0` iken `pwd` libc tarafından başarıyla başlatılmıştır.
            let pwd_ref = unsafe { pwd.assume_init_ref() };
            // SAFETY: `pwd_ref.pw_name` libc tarafından ayrılmış ve null ile sonlandırılmış geçerli C dizesidir.
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

/// Geçerli sürecin Unix üzerinde etkin kök yetkisiyle (`euid == 0`) çalışıp çalışmadığını döndürür.
/// Windows ve Unix dışı platformlarda `false` döner.
#[cfg(unix)]
pub fn is_running_as_root() -> bool {
    // SAFETY: `geteuid` iş parçacığı güvenli, salt-okunur bir POSIX kimlik sorgusudur.
    unsafe { libc::geteuid() == 0 }
}

/// Geçerli sürecin etkin kök yetkisiyle (`euid == 0`) çalışıp çalışmadığını döndürür.
/// Windows ve Unix dışı platformlarda `false` döner.
#[cfg(not(unix))]
pub fn is_running_as_root() -> bool {
    false
}

/// POSIX ortamında kök yetkilerini belirtilen kullanıcı ve gruba düşürür
/// (`setgroups(0, null)` -> `initgroups` -> `setgid` -> `setuid`) ve geri yükselmenin kapalı olduğunu doğrular.
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

    // Kök yetkisi olmayan ortamlarda (geliştirici testi vb.) kullanıcı/grup varlığı doğrulandıktan sonra güvenle atla
    if !is_running_as_root() {
        tracing::info!(
            "Kök (root/euid=0) yetkisi bulunmadığından drop_privileges atlandı (user='{}', group='{}')",
            user,
            group
        );
        return Ok(());
    }

    // 1. Önce root'tan miras kalan tüm ek grupları (supplementary groups) sıfırla.
    // SAFETY: Kök yetkisi (euid == 0) altındayken `setgroups(0, null)` ek grup listesini boşaltır.
    if unsafe { libc::setgroups(0 as _, std::ptr::null()) } != 0 {
        return Err(format!(
            "setgroups(0) başarısız: {}",
            std::io::Error::last_os_error()
        ));
    }

    // 2. Yalnız hedef kullanıcının izin verilen ek gruplarını ve hedef birincil `gid` grubunu yükle.
    // SAFETY: `c_user` geçerli NUL-sonlandırmalı C dizesidir ve `gid` sistemden doğrulanmıştır.
    if unsafe { libc::initgroups(c_user.as_ptr(), gid as _) } != 0 {
        return Err(format!(
            "initgroups('{}', {}) başarısız: {}",
            user,
            gid,
            std::io::Error::last_os_error()
        ));
    }

    // 3. Birincil grup yetkisi düşürülür; `setuid` sonrasında `setgid` yapılamaz.
    // SAFETY: `gid` sistem grup tablosundan doğrulanmış geçerli bir grup kimliğidir.
    if unsafe { libc::setgid(gid) } != 0 {
        return Err(format!(
            "setgid({}) başarısız ({}): {}",
            gid,
            group,
            std::io::Error::last_os_error()
        ));
    }

    // 4. Kullanıcı yetkisi kalıcı olarak düşürülür.
    // SAFETY: `uid` sistem kullanıcı tablosundan doğrulanmıştır; öncesinde gruplar düşürülmüştür.
    if unsafe { libc::setuid(uid) } != 0 {
        return Err(format!(
            "setuid({}) başarısız ({}): {}",
            uid,
            user,
            std::io::Error::last_os_error()
        ));
    }

    // 5. Yetkisiz hedef kullanıcı için gerçekten root kalmadığını ve gid=0 ek grubu olmadığını doğrula.
    if uid != 0 {
        // SAFETY: `getuid`/`geteuid`/`getgid`/`getegid` yan etkisiz salt-okunur POSIX sorgularıdır.
        let (ruid, euid, rgid, egid) = unsafe {
            (
                libc::getuid(),
                libc::geteuid(),
                libc::getgid(),
                libc::getegid(),
            )
        };
        if ruid != uid || euid != uid || rgid != gid || egid != gid || euid == 0 || ruid == 0 {
            return Err(format!(
                "Yetki düşürme doğrulaması başarısız: beklenen uid={}/gid={}, mevcut uid={}/euid={}, gid={}/egid={}",
                uid, gid, ruid, euid, rgid, egid
            ));
        }
        if gid != 0 {
            verify_no_root_supplementary_group()?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn verify_no_root_supplementary_group() -> Result<(), String> {
    // SAFETY: `getgroups(0, null)` yalnızca ek grup sayısını okur, bellek yazmaz.
    let ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if ngroups < 0 {
        return Err(format!(
            "getgroups(0) başarısız: {}",
            std::io::Error::last_os_error()
        ));
    }
    if ngroups == 0 {
        return Ok(());
    }
    let mut supp = vec![0 as libc::gid_t; ngroups as usize];
    // SAFETY: `supp` uzunluğu `ngroups` öğe alacak kadar ayrılmıştır ve işaretçisi hizalıdır.
    let read_n = unsafe { libc::getgroups(ngroups, supp.as_mut_ptr()) };
    if read_n < 0 {
        return Err(format!(
            "getgroups({}) başarısız: {}",
            ngroups,
            std::io::Error::last_os_error()
        ));
    }
    let count = (read_n as usize).min(supp.len());
    if supp[..count].contains(&0) {
        return Err(
            "Yetki düşürme sonrası ek gruplarda root (gid=0) bulundu; güvenlik nedeniyle durduruluyor"
                .to_string(),
        );
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

#[cfg(unix)]
fn chown_single_non_symlink(
    p: &std::path::Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
    depth: u8,
) -> Result<(), String> {
    let meta = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(format!(
                "Yol meta verisi okunamadı ('{}'): {}",
                p.display(),
                err
            ))
        }
    };

    // Sembolik bağ üzerinden root-yetkili chown istismarını (symlink attack) önle
    if meta.file_type().is_symlink() {
        tracing::warn!(
            "Sembolik bağ sahiplik devrinden güvenlik nedeniyle atlandı: {}",
            p.display()
        );
        return Ok(());
    }

    let c_path = std::ffi::CString::new(p.to_string_lossy().as_bytes()).map_err(|_| {
        format!(
            "Yol NUL karakteri içerdiğinden sahiplik değiştirilemedi: '{}'",
            p.display()
        )
    })?;
    // SAFETY: `c_path` geçerli NUL-sonlandırmalı dosya yoludur. `libc::lchown` sembolik bağları takip etmez (TOCTOU engellenir).
    if unsafe { libc::lchown(c_path.as_ptr(), uid, gid) } != 0 {
        let err = std::io::Error::last_os_error();
        return Err(format!(
            "Yol sahipliği değiştirilemedi ('{}' -> uid={}, gid={}): {}",
            p.display(),
            uid,
            gid,
            err
        ));
    }

    if meta.is_dir() && depth > 0 {
        let entries = std::fs::read_dir(p)
            .map_err(|e| format!("Dizin içeriği okunamadı ('{}'): {}", p.display(), e))?;
        for entry_res in entries {
            let entry = entry_res
                .map_err(|e| format!("Dizin girdisi okunamadı ('{}'): {}", p.display(), e))?;
            chown_single_non_symlink(&entry.path(), uid, gid, depth - 1)?;
        }
    }

    Ok(())
}

/// POSIX ortamında belirtilen dosya veya dizinlerin sahipliğini kullanıcı ve gruba devreder.
/// Kök (`euid == 0`) iken herhangi bir `chown` hatasında sessizce devam etmek yerine `Err` döner.
#[cfg(unix)]
pub fn ensure_paths_ownership<P: AsRef<std::path::Path>>(
    user: &str,
    group: &str,
    paths: &[P],
) -> Result<(), String> {
    let user = validate_account_name("Kullanıcı", user)?;
    let group = validate_account_name("Grup", group)?;
    let c_user = std::ffi::CString::new(user)
        .map_err(|_| "Kullanıcı adında NUL karakteri bulunamaz".to_string())?;
    let c_group = std::ffi::CString::new(group)
        .map_err(|_| "Grup adında NUL karakteri bulunamaz".to_string())?;

    let gid = lookup_gid_by_name(&c_group)?;
    let uid = lookup_uid_by_name(&c_user)?;

    if !is_running_as_root() {
        tracing::debug!(
            "Kök (root) yetkisi olmadığından ensure_paths_ownership atlandı (user='{}', group='{}')",
            user,
            group
        );
        return Ok(());
    }

    for path in paths {
        let p = path.as_ref();
        if !p.exists() {
            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        format!("Üst dizin oluşturulamadı ('{}'): {}", parent.display(), e)
                    })?;
                    chown_single_non_symlink(parent, uid, gid, 0)?;
                }
            }
        }
        chown_single_non_symlink(p, uid, gid, 2)?;
    }
    Ok(())
}

/// Windows ortamında dosya ve dizin sahipliği denetimi ve güvenli doğrulama.
#[cfg(not(unix))]
pub fn ensure_paths_ownership<P: AsRef<std::path::Path>>(
    user: &str,
    group: &str,
    paths: &[P],
) -> Result<(), String> {
    let _ = (
        validate_account_name("Kullanıcı", user)?,
        validate_account_name("Grup", group)?,
    );
    for path in paths {
        let p = path.as_ref();
        if p.exists() {
            tracing::trace!("Windows ortamında dosya yolu doğrulandı: {}", p.display());
        }
    }
    Ok(())
}

/// Günlük, önbellek ve geçici dosya yollarının sahipliğini ayarlayıp ardından yetkiyi düşürür.
pub fn drop_privileges_with_paths<P: AsRef<std::path::Path>>(
    user: &str,
    group: &str,
    paths: &[P],
) -> Result<(), String> {
    ensure_paths_ownership(user, group, paths)?;
    drop_privileges(user, group)
}

/// POSIX ortamında kök yetkisi altındayken TLS özel anahtarlarını ve sertifikalarını
/// yetki düşürme sonrasında SIGHUP/API reload sırasında servis kullanıcısının okuyabilmesi için
/// hedef gruba (gid) devreder ve 0640 (sahip rw, grup r) izni verir.
#[cfg(unix)]
pub fn ensure_tls_keys_readable_by_group<P: AsRef<std::path::Path>>(
    group: &str,
    paths: &[P],
) -> Result<(), String> {
    if !is_running_as_root() {
        return Ok(());
    }
    let group = validate_account_name("Grup", group)?;
    let c_group = std::ffi::CString::new(group)
        .map_err(|_| "Grup adında NUL karakteri bulunamaz".to_string())?;
    let gid = lookup_gid_by_name(&c_group)?;

    for p in paths {
        let path = p.as_ref();
        if !path.exists() {
            continue;
        }
        let c_path = match std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        // SAFETY: `c_path` geçerli NUL-sonlandırmalı dosya yoludur. lchown sembolik bağları takip etmez.
        let _ = unsafe { libc::lchown(c_path.as_ptr(), 0 as _, gid) };
        // İzinleri 0640 (S_IRUSR | S_IWUSR | S_IRGRP) olarak ayarla; genele açılmaz (others=0).
        // SAFETY: `chmod` geçerli POSIX dosya izinlerini ayarlar; 0o640 ile anahtar genele açılmaz.
        let _ = unsafe {
            libc::chmod(
                c_path.as_ptr(),
                (libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP) as _,
            )
        };
    }
    Ok(())
}

/// Windows ortamında TLS anahtar izni yedeklemesi.
#[cfg(not(unix))]
pub fn ensure_tls_keys_readable_by_group<P: AsRef<std::path::Path>>(
    _group: &str,
    _paths: &[P],
) -> Result<(), String> {
    Ok(())
}

/// Günlük, önbellek ve geçici dosya yollarının sahipliğini ayarlayıp, TLS anahtarlarını grupça okunabilir kılıp yetkiyi düşürür.
pub fn drop_privileges_with_paths_and_tls<P: AsRef<std::path::Path>, Q: AsRef<std::path::Path>>(
    user: &str,
    group: &str,
    paths: &[P],
    tls_paths: &[Q],
) -> Result<(), String> {
    ensure_paths_ownership(user, group, paths)?;
    ensure_tls_keys_readable_by_group(group, tls_paths)?;
    drop_privileges(user, group)
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

    #[test]
    fn test_drop_privileges_with_paths() {
        let temp_dir = std::env::temp_dir().join(format!("zmax_core_privs_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let log_file = temp_dir.join("access.log");
        let cache_dir = temp_dir.join("cache");
        let _ = std::fs::write(&log_file, b"test");

        let group = {
            #[cfg(unix)]
            {
                let c_nobody = std::ffi::CString::new("nobody").expect("sabit ASCII");
                if lookup_gid_by_name(&c_nobody).is_ok() {
                    "nobody"
                } else {
                    "nogroup"
                }
            }
            #[cfg(not(unix))]
            {
                "nobody"
            }
        };

        assert!(ensure_paths_ownership("nobody", group, &[&log_file, &cache_dir]).is_ok());
        assert!(drop_privileges_with_paths("nobody", group, &[&log_file, &cache_dir]).is_ok());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_is_running_as_root_consistent_with_platform() {
        let running_as_root = is_running_as_root();
        #[cfg(not(unix))]
        assert!(!running_as_root);
        #[cfg(unix)]
        {
            // SAFETY: `geteuid` salt-okunur POSIX kimlik sorgusudur.
            let euid_is_zero = unsafe { libc::geteuid() == 0 };
            assert_eq!(running_as_root, euid_is_zero);
        }
    }

    /// Kök (`euid == 0`) yetkisi altında ek grupların temizlendiğini (`setgroups`/`initgroups`),
    /// sahipliğin devredildiğini ve düşürme sonrasında `setuid(0)` çağrısının `EPERM` ile
    /// başarısız olduğunu (geri yükselme imkansızlığı) kanıtlar.
    /// VM'de kök olarak çalıştırma:
    /// `cargo test -p zmax-core test_drop_privileges_blocks_setuid_zero_and_drops_groups -- --ignored --nocapture`
    #[cfg(unix)]
    #[test]
    #[ignore = "Kök (root / euid == 0) yetkisi gerektirir; --ignored ile root ortamında çalıştırın"]
    fn test_drop_privileges_blocks_setuid_zero_and_drops_groups() {
        assert!(
            is_running_as_root(),
            "Bu test root (euid == 0) olarak çalıştırılmalıdır"
        );

        let c_nobody_user = std::ffi::CString::new("nobody").expect("sabit ASCII");
        let _uid = lookup_uid_by_name(&c_nobody_user).expect("'nobody' kullanıcısı bulunmalı");
        let group = {
            let c_nobody_grp = std::ffi::CString::new("nobody").expect("sabit ASCII");
            if lookup_gid_by_name(&c_nobody_grp).is_ok() {
                "nobody"
            } else {
                "nogroup"
            }
        };

        let temp_dir =
            std::env::temp_dir().join(format!("zmax_core_root_drop_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let logs_dir = temp_dir.join("logs");
        std::fs::create_dir_all(&logs_dir).unwrap();
        let pre_log = logs_dir.join("pre_drop.log");
        std::fs::write(&pre_log, b"root-opened\n").unwrap();

        drop_privileges_with_paths("nobody", group, &[&logs_dir])
            .expect("Kök yetkiden 'nobody' kullanıcısına düşürme başarılı olmalı");

        assert!(
            !is_running_as_root(),
            "drop_privileges sonrası euid artık 0 (root) olmamalı"
        );
        // SAFETY: `getuid`/`getgid` salt-okunur POSIX sorgularıdır.
        let (ruid, rgid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert_ne!(ruid, 0, "Gerçek uid root kalmamalı");
        assert_ne!(rgid, 0, "Gerçek gid root kalmamalı");

        // Ek gruplarda gid=0 bulunmamalı
        verify_no_root_supplementary_group().expect("Ek gruplar arasında root (gid=0) bulunmamalı");

        // Düşürme sonrası tekrar kök yetkisi alma denemesi KESİN başarısız (EPERM) olmalıdır
        // SAFETY: Yetkisiz süreçte `setuid(0)` çağrısının çekirdek tarafından reddedildiğini doğrular.
        let rc = unsafe { libc::setuid(0) };
        let err = std::io::Error::last_os_error();
        assert_ne!(
            rc, 0,
            "Yetki düşürüldükten sonra setuid(0) asla başarılı olmamalı!"
        );
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EPERM),
            "setuid(0) başarısızlık nedeni EPERM olmalıdır (alınan: {:?})",
            err
        );

        // Sahipliği devredilen dizindeki dosyaya yetkisiz kullanıcı da yazabilmeli
        std::fs::OpenOptions::new()
            .append(true)
            .open(&pre_log)
            .expect("Sahipliği devredilen log dosyası yetki düşümü sonrası açılabilmeli");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

