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

/// Debian/Ubuntu'da `nobody` grubu yoktur (`nogroup` vardır); RHEL/Alma'da `nobody` vardır.
#[cfg(any(unix, test))]
const NOBODY_GROUP_FALLBACK: &str = "nogroup";

/// Grup adını çözer; ad `nobody` ise ve yoksa `nogroup` yedeğini dener.
/// İkisi de yoksa açık hata ve yönerge döner (sessiz geçme yok).
#[cfg(any(unix, test))]
fn resolve_group_gid<G>(group: &str, lookup_gid: G) -> Result<u32, String>
where
    G: Fn(&str) -> Result<u32, String>,
{
    match lookup_gid(group) {
        Ok(gid) => Ok(gid),
        Err(first) => {
            if group == "nobody" {
                if let Ok(gid) = lookup_gid(NOBODY_GROUP_FALLBACK) {
                    tracing::info!(
                        "'nobody' grubu bulunamadı; '{}' yedek grubu kullanılıyor",
                        NOBODY_GROUP_FALLBACK
                    );
                    return Ok(gid);
                }
                return Err(format!(
                    "{first} ('{NOBODY_GROUP_FALLBACK}' yedeği de yok): sistemde var olan bir hizmet grubunu                      server.group değerine yazın (Debian/Ubuntu: nogroup, RHEL/Alma: nobody)                      veya ayrı bir grup oluşturun (groupadd zmax)"
                ));
            }
            Err(format!(
                "{first}: server.group değerine sistemde var olan bir grup yazın veya grubu oluşturun (groupadd)"
            ))
        }
    }
}

/// Yetki düşürme / sahiplik devri için hedef `(uid, gid)` çiftini çözer.
///
/// - kök değil: düşürülecek yetki yok; arama yapılmaz, `Ok(None)` (atla)
/// - kök: kullanıcı ve grup mutlaka çözülmeli (`nobody` grubu yoksa `nogroup` yedeği);
///   çözülemezse `Err` (fail-closed)
///
/// # Errors
/// Kök iken kullanıcı veya grup sistemde bulunamazsa.
#[cfg(any(unix, test))]
fn resolve_service_ids<U, G>(
    user: &str,
    group: &str,
    running_as_root: bool,
    lookup_uid: U,
    lookup_gid: G,
) -> Result<Option<(u32, u32)>, String>
where
    U: Fn(&str) -> Result<u32, String>,
    G: Fn(&str) -> Result<u32, String>,
{
    if !running_as_root {
        return Ok(None);
    }
    let gid = resolve_group_gid(group, lookup_gid)?;
    let uid = lookup_uid(user).map_err(|e| {
        format!("{e}: server.user değerine sistemde var olan bir hizmet kullanıcısı yazın")
    })?;
    Ok(Some((uid, gid)))
}

#[cfg(unix)]
fn lookup_gid_str(name: &str) -> Result<u32, String> {
    let c = std::ffi::CString::new(name)
        .map_err(|_| "Grup adında NUL karakteri bulunamaz".to_string())?;
    lookup_gid_by_name(&c)
}

#[cfg(unix)]
fn lookup_uid_str(name: &str) -> Result<u32, String> {
    let c = std::ffi::CString::new(name)
        .map_err(|_| "Kullanıcı adında NUL karakteri bulunamaz".to_string())?;
    lookup_uid_by_name(&c)
}

/// `server.user` / `server.group` değerlerine göre yetki düşürme kararı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeDropPlan {
    /// Kök olmayan süreçte kullanıcı/grup verilmemiş: düşürülecek yetki yok, atla.
    Skip,
    /// Kullanıcı ve grup verilmiş: sahiplik devri ve `drop_privileges` uygulanır.
    Drop,
}

/// Yetki düşürme kararını verir (saf fonksiyon; platformdan bağımsız).
///
/// - kullanıcı ve grup dolu: `Drop`
/// - boş (kök değil): `Skip` (geliştirici/yerel başlatma; gönderilen `conf/zmax.toml` böyledir)
/// - boş (kök): `Err` (fail-closed; kök olarak yetkisiz kullanıcıya düşmeden hizmet verilmez)
///
/// # Errors
/// Kök (`euid == 0`) iken kullanıcı veya grup boşsa.
pub fn plan_privilege_drop(
    user: &str,
    group: &str,
    running_as_root: bool,
) -> Result<PrivilegeDropPlan, String> {
    let missing = user.trim().is_empty() || group.trim().is_empty();
    match (missing, running_as_root) {
        (false, _) => Ok(PrivilegeDropPlan::Drop),
        (true, false) => Ok(PrivilegeDropPlan::Skip),
        (true, true) => Err(
            "root olarak çalışırken server.user ve server.group boş olamaz (fail-closed):              yapılandırmaya yetkisiz bir hizmet kullanıcısı ve grubu yazın"
                .to_string(),
        ),
    }
}

/// POSIX ortamında kök yetkilerini belirtilen kullanıcı ve gruba düşürür
/// (`setgroups(0, null)` -> `initgroups` -> `setgid` -> `setuid`) ve geri yükselmenin kapalı olduğunu doğrular.
#[cfg(unix)]
pub fn drop_privileges(user: &str, group: &str) -> Result<(), String> {
    let user = validate_account_name("Kullanıcı", user)?;
    let group = validate_account_name("Grup", group)?;

    let c_user = std::ffi::CString::new(user)
        .map_err(|_| "Kullanıcı adında NUL karakteri bulunamaz".to_string())?;

    // Kök değilse düşürülecek yetki yok: hesap araması yapılmaz (ör. Debian'da 'nobody' grubu yok) ve atlanır.
    let Some((uid, gid)) = resolve_service_ids(
        user,
        group,
        is_running_as_root(),
        lookup_uid_str,
        lookup_gid_str,
    )?
    else {
        tracing::info!(
            "Kök (root/euid=0) yetkisi bulunmadığından drop_privileges atlandı (user='{}', group='{}')",
            user,
            group
        );
        return Ok(());
    };

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

/// Tek bir girdinin (ve `depth` kadar alt seviyenin) sahipliğini TOCTOU'suz devreder.
///
/// Çalışma yöntemi: girdi `openat(O_DIRECTORY | O_NOFOLLOW)` ile açılıp `fchown` ile devredilir
/// (dizin sonradan sembolik bağla değiştirilse bile işlem açık dosya tanıtıcısına uygulanır);
/// çocuklar bu dizin tanıtıcısına GÖRE (`openat` / `fchownat(AT_SYMLINK_NOFOLLOW)`) işlenir.
/// Dizin olmayan girdiler `fchownat(AT_SYMLINK_NOFOLLOW)` ile devredilir; sembolik bağlar atlanır.
/// `parent_fd` = `libc::AT_FDCWD` ya da açık bir dizin tanıtıcısıdır. En üst yolun ara bileşenleri
/// çekirdek tarafından normal şekilde çözülür (kök sahibi, güvenilir dizin varsayımı).
#[cfg(unix)]
fn chown_entry_nofollow(
    parent_fd: libc::c_int,
    name: &std::ffi::CStr,
    shown: &std::path::Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
    depth: u8,
) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: `name` geçerli NUL-sonlandırmalı C dizesidir; `parent_fd` AT_FDCWD ya da bu çağrı
    // zincirinin açık tuttuğu dizin tanıtıcısıdır. O_NOFOLLOW sembolik bağın izlenmesini engeller.
    let raw = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw >= 0 {
        // SAFETY: `openat` başarılı döndü; `raw` bu sürece ait yeni ve açık bir tanıtıcıdır, tek sahibi `dir`.
        let dir = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: `dir` açık bir dizin tanıtıcısıdır.
        if unsafe { libc::fchown(dir.as_raw_fd(), uid, gid) } != 0 {
            return Err(format!(
                "Dizin sahipliği değiştirilemedi ('{}' -> uid={}, gid={}): {}",
                shown.display(),
                uid,
                gid,
                std::io::Error::last_os_error()
            ));
        }
        if depth > 0 {
            let entries = std::fs::read_dir(shown)
                .map_err(|e| format!("Dizin içeriği okunamadı ('{}'): {}", shown.display(), e))?;
            for entry_res in entries {
                let entry = entry_res.map_err(|e| {
                    format!("Dizin girdisi okunamadı ('{}'): {}", shown.display(), e)
                })?;
                let child = std::ffi::CString::new(entry.file_name().as_bytes()).map_err(|_| {
                    format!(
                        "Dosya adı NUL karakteri içerdiğinden sahiplik değiştirilemedi: '{}'",
                        entry.path().display()
                    )
                })?;
                chown_entry_nofollow(dir.as_raw_fd(), &child, &entry.path(), uid, gid, depth - 1)?;
            }
        }
        return Ok(());
    }

    let open_err = std::io::Error::last_os_error();
    match open_err.raw_os_error() {
        // Girdi (artık) yok: devredilecek bir şey kalmadı.
        Some(libc::ENOENT) => return Ok(()),
        // Dizin değil ya da sembolik bağ: aşağıda ayrı ele alınır.
        Some(libc::ENOTDIR) | Some(libc::ELOOP) => {}
        _ => {
            return Err(format!(
                "Yol açılamadı ('{}'): {}",
                shown.display(),
                open_err
            ))
        }
    }

    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `name` geçerli C dizesi, `st` yazılabilir `stat` belleğidir; AT_SYMLINK_NOFOLLOW bağı izlemez.
    let rc = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(format!(
            "Yol meta verisi okunamadı ('{}'): {}",
            shown.display(),
            err
        ));
    }
    // SAFETY: `fstatat` başarılı (rc == 0) olduğundan `st` libc tarafından doldurulmuştur.
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        // Sembolik bağ üzerinden root-yetkili chown istismarını (symlink attack) önle
        tracing::warn!(
            "Sembolik bağ sahiplik devrinden güvenlik nedeniyle atlandı: {}",
            shown.display()
        );
        return Ok(());
    }
    // SAFETY: `name` geçerli C dizesi; AT_SYMLINK_NOFOLLOW son bileşen bağsa bağın hedefine DEĞİL bağın kendisine uygulanır.
    if unsafe {
        libc::fchownat(
            parent_fd,
            name.as_ptr(),
            uid,
            gid,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(format!(
            "Yol sahipliği değiştirilemedi ('{}' -> uid={}, gid={}): {}",
            shown.display(),
            uid,
            gid,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// En üst düzey yol için `chown_entry_nofollow` çağrısı (yol yoksa `Ok`).
#[cfg(unix)]
fn chown_single_non_symlink(
    p: &std::path::Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
    depth: u8,
) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "Yol NUL karakteri içerdiğinden sahiplik değiştirilemedi: '{}'",
            p.display()
        )
    })?;
    chown_entry_nofollow(libc::AT_FDCWD, &c_path, p, uid, gid, depth)
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

    let Some((uid, gid)) = resolve_service_ids(
        user,
        group,
        is_running_as_root(),
        lookup_uid_str,
        lookup_gid_str,
    )?
    else {
        tracing::debug!(
            "Kök (root) yetkisi olmadığından ensure_paths_ownership atlandı (user='{}', group='{}')",
            user,
            group
        );
        return Ok(());
    };

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

/// Anahtar/sertifika dosya kipine "grup okuyabilir" biti (0o040) eklenmiş hâlini döndürür.
/// Diğer izin bitlerine (sahip/diğerleri, özel bitler) DOKUNMAZ: 0600 -> 0640, 0640 -> 0640, 0644 -> 0644.
#[inline]
pub const fn group_read_mode(mode: u32) -> u32 {
    (mode & 0o7777) | 0o040
}

/// `path` (varsa sembolik bağları çözülmüş gerçek dosya) için grubu `gid` yapar ve grup okuma bitini ekler.
///
/// Yol yoksa `Ok(false)` (sonradan oluşacak dosya; bir sonraki çağrıda ele alınır). Hedef normal dosya
/// değilse, açılamıyorsa ya da `fchown`/`fchmod` başarısızsa `Err` döner (sessizce yutulmaz).
/// Sembolik bağlar (ör. certbot `live/ -> archive/`) `canonicalize` ile çözülür; gerçek hedef
/// `O_NOFOLLOW` ile açılıp açık tanıtıcı üzerinde `fchown`/`fchmod` uygulanır (`chmod(path)` yarışı yok).
/// Sahip (uid) değiştirilmez. Değişiklik yapıldıysa `Ok(true)`.
#[cfg(unix)]
fn grant_group_read(path: &std::path::Path, gid: libc::gid_t) -> Result<bool, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let real = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => {
            return Err(format!(
                "TLS anahtar yolu çözümlenemedi ('{}'): {}",
                path.display(),
                e
            ))
        }
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(&real)
        .map_err(|e| {
            format!(
                "TLS anahtar dosyası açılamadı ('{}'): {}",
                real.display(),
                e
            )
        })?;
    let meta = file.metadata().map_err(|e| {
        format!(
            "TLS anahtar meta verisi okunamadı ('{}'): {}",
            real.display(),
            e
        )
    })?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "TLS anahtar yolu normal dosya değil: '{}'",
            real.display()
        ));
    }

    let mut changed = false;
    if meta.gid() != gid {
        // SAFETY: `file` açık bir dosyanın geçerli tanıtıcısıdır; `uid_t::MAX` = (uid_t)-1 sahibi değiştirmez.
        if unsafe { libc::fchown(file.as_raw_fd(), libc::uid_t::MAX, gid) } != 0 {
            return Err(format!(
                "TLS anahtar grubu değiştirilemedi ('{}' -> gid={}): {}",
                real.display(),
                gid,
                std::io::Error::last_os_error()
            ));
        }
        changed = true;
    }
    let cur = meta.mode() & 0o7777;
    let want = group_read_mode(cur);
    if want != cur {
        file.set_permissions(std::fs::Permissions::from_mode(want))
            .map_err(|e| {
                format!(
                    "TLS anahtar izni değiştirilemedi ('{}' -> {:o}): {}",
                    real.display(),
                    want,
                    e
                )
            })?;
        changed = true;
    }
    Ok(changed)
}

/// Kök kontrolü OLMADAN, verilen yolların hepsine `grant_group_read` uygular; tüm hataları toplar.
/// Dönen sayı değiştirilen dosya sayısıdır.
#[cfg(unix)]
fn apply_tls_group_read<P: AsRef<std::path::Path>>(
    gid: libc::gid_t,
    paths: &[P],
) -> Result<usize, String> {
    let mut changed = 0usize;
    let mut errors: Vec<String> = Vec::new();
    for p in paths {
        match grant_group_read(p.as_ref(), gid) {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        Ok(changed)
    } else {
        Err(errors.join("; "))
    }
}

/// POSIX ortamında kök yetkisi altındayken TLS özel anahtarlarını ve sertifikalarını
/// yetki düşürme sonrasında servis kullanıcısının okuyabilmesi için hedef gruba (gid) devreder ve
/// grup okuma biti (0640) verir. Hata sessizce yutulmaz: herhangi bir yol için gereken değişiklik
/// yapılamazsa `Err` döner. Dönen sayı değiştirilen dosya sayısıdır (kök değilse 0).
///
/// **Güvenlik ödünü:** anahtar `root:<grup>` 0640 olur; aynı gruptaki her süreç (ör. PHP-FPM aynı grupta
/// çalışıyorsa) anahtarı okuyabilir. Servis grubunu yalnız ZMax'a ayırın. Alternatif (anahtarı düşürme
/// öncesi belleğe alıp ayrıcalıklı yardımcıyla yenilemek) bu sürümde YOK.
///
/// **Sınır:** düşürmeden SONRA oluşan/yenilenen (ör. certbot, root 0600) anahtarı süreç kendisi
/// düzeltemez (artık root değil). Yenileme sonrası `zmax --fix-tls-perms` (root, certbot
/// `--deploy-hook`) bu fonksiyonu yeniden çalıştırır.
#[cfg(unix)]
pub fn ensure_tls_keys_readable_by_group<P: AsRef<std::path::Path>>(
    group: &str,
    paths: &[P],
) -> Result<usize, String> {
    if !is_running_as_root() {
        return Ok(0);
    }
    let group = validate_account_name("Grup", group)?;
    let gid = resolve_group_gid(group, lookup_gid_str)?;
    apply_tls_group_read(gid, paths)
}

/// Windows ortamında TLS anahtar izni yedeklemesi.
#[cfg(not(unix))]
pub fn ensure_tls_keys_readable_by_group<P: AsRef<std::path::Path>>(
    _group: &str,
    _paths: &[P],
) -> Result<usize, String> {
    Ok(0)
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

/// Yetki düşürme sonrasında bu sürecin okuyamadığı yolları `(yol, hata)` olarak döndürür
/// (var olmayan yollar atlanır). TLS anahtar izin planının gerçekten işlediğini doğrulamak için kullanılır.
pub fn unreadable_paths<P: AsRef<std::path::Path>>(
    paths: &[P],
) -> Vec<(std::path::PathBuf, String)> {
    let mut out = Vec::new();
    for p in paths {
        let path = p.as_ref();
        match std::fs::File::open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => out.push((path.to_path_buf(), e.to_string())),
        }
    }
    out
}

/// Geçici dosya dizinini yalnız sahibine açık (0700) ve doğrulanmış sahipli hazırlar.
///
/// Dizin yoksa `0700` kipiyle oluşturulur (üst dizinler normal kiple). Varsa: sembolik bağ olmamalı
/// (`O_NOFOLLOW | O_DIRECTORY` ile açılır), sahibi bu sürecin etkin kullanıcısı ya da `service_user`
/// olmalı ve kip `0700`'e çekilir (başkasının dizini kabul edilmez). Unix dışında yalnız oluşturur.
///
/// # Errors
/// Oluşturma/açma/sahiplik doğrulama/kip ayarlama başarısızsa.
pub fn prepare_private_tmp_dir(path: &std::path::Path, service_user: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Geçici dizinin üst dizini oluşturulamadı ('{}'): {}",
                    parent.display(),
                    e
                )
            })?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = service_user;
        std::fs::create_dir_all(path)
            .map_err(|e| format!("Geçici dizin oluşturulamadı ('{}'): {}", path.display(), e))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(format!(
                    "Geçici dizin oluşturulamadı ('{}'): {}",
                    path.display(),
                    e
                ))
            }
        }
        let dir = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                format!(
                    "Geçici yol dizin değil ya da sembolik bağ, güvenlik nedeniyle reddedildi ('{}'): {}",
                    path.display(),
                    e
                )
            })?;
        let meta = dir.metadata().map_err(|e| {
            format!(
                "Geçici dizin meta verisi okunamadı ('{}'): {}",
                path.display(),
                e
            )
        })?;
        // SAFETY: `geteuid` salt-okunur POSIX kimlik sorgusudur.
        let euid = unsafe { libc::geteuid() };
        let svc_uid = {
            let name = service_user.trim();
            if name.is_empty() {
                None
            } else {
                let c = std::ffi::CString::new(validate_account_name("Kullanıcı", name)?)
                    .map_err(|_| "Kullanıcı adında NUL karakteri bulunamaz".to_string())?;
                lookup_uid_by_name(&c).ok()
            }
        };
        if meta.uid() != euid && Some(meta.uid()) != svc_uid {
            return Err(format!(
                "Geçici dizin sahibi güvenilir değil ('{}': uid={}, beklenen {} ya da hizmet kullanıcısı)",
                path.display(),
                meta.uid(),
                euid
            ));
        }
        if meta.mode() & 0o777 != 0o700 {
            dir.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| {
                    format!(
                        "Geçici dizin izni 0700 yapılamadı ('{}'): {}",
                        path.display(),
                        e
                    )
                })?;
        }
        Ok(())
    }
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
            // Kök değilse düşürülecek yetki yok: hesap aranmaz, atlanır; kökken eksik hesap fail-closed hatadır.
            let missing_is_err = is_running_as_root();
            assert_eq!(
                drop_privileges("zmax_nonexistent_user_99999", "nobody").is_err(),
                missing_is_err
            );
            assert_eq!(
                drop_privileges("nobody", "zmax_nonexistent_group_99999").is_err(),
                missing_is_err
            );
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
    fn plan_privilege_drop_empty_nonroot_skips() {
        for (u, g) in [("", ""), ("", "nobody"), ("nobody", ""), ("  ", "	")] {
            assert_eq!(
                plan_privilege_drop(u, g, false),
                Ok(PrivilegeDropPlan::Skip),
                "root değilken boş user/group atlanmalı ({u:?}/{g:?})"
            );
        }
    }

    #[test]
    fn plan_privilege_drop_empty_root_is_error() {
        for (u, g) in [("", ""), ("", "nobody"), ("nobody", ""), (" ", " ")] {
            let err = plan_privilege_drop(u, g, true)
                .expect_err("root + boş user/group fail-closed olmalı");
            assert!(err.contains("fail-closed"), "hata metni: {err}");
        }
    }

    #[test]
    fn plan_privilege_drop_filled_always_drops() {
        assert_eq!(
            plan_privilege_drop("nobody", "nobody", true),
            Ok(PrivilegeDropPlan::Drop)
        );
        assert_eq!(
            plan_privilege_drop("nobody", "nobody", false),
            Ok(PrivilegeDropPlan::Drop)
        );
    }

    /// Debian/Ubuntu benzeri: `nobody` grubu yok, `nogroup` var; `nobody` kullanıcısı var.
    fn debian_uid(name: &str) -> Result<u32, String> {
        if name == "nobody" {
            Ok(65534)
        } else {
            Err(format!("Kullanıcı bulunamadı: '{name}'"))
        }
    }

    fn debian_gid(name: &str) -> Result<u32, String> {
        if name == "nogroup" {
            Ok(65533)
        } else {
            Err(format!("Grup bulunamadı: '{name}'"))
        }
    }

    #[test]
    fn resolve_ids_non_root_missing_group_is_skipped() {
        let none = |n: &str| Err::<u32, String>(format!("Grup bulunamadı: '{n}'"));
        assert_eq!(
            resolve_service_ids("nobody", "nobody", false, debian_uid, none),
            Ok(None)
        );
        assert_eq!(
            resolve_service_ids("yok", "yok", false, debian_uid, debian_gid),
            Ok(None)
        );
    }

    #[test]
    fn resolve_ids_root_nobody_missing_falls_back_to_nogroup() {
        assert_eq!(
            resolve_service_ids("nobody", "nobody", true, debian_uid, debian_gid),
            Ok(Some((65534, 65533)))
        );
    }

    #[test]
    fn resolve_ids_root_prefers_nobody_group_when_present() {
        let gid = |n: &str| match n {
            "nobody" => Ok(65534),
            "nogroup" => Ok(65533),
            _ => Err(format!("Grup bulunamadı: '{n}'")),
        };
        assert_eq!(
            resolve_service_ids("nobody", "nobody", true, debian_uid, gid),
            Ok(Some((65534, 65534)))
        );
    }

    #[test]
    fn resolve_ids_root_no_nobody_no_nogroup_is_error_with_guidance() {
        let none = |n: &str| Err::<u32, String>(format!("Grup bulunamadı: '{n}'"));
        let err = resolve_service_ids("nobody", "nobody", true, debian_uid, none)
            .expect_err("kökken grup yoksa fail-closed olmalı");
        assert!(err.contains("nobody") && err.contains("nogroup"), "{err}");
        assert!(err.contains("server.group"), "{err}");
    }

    #[test]
    fn resolve_ids_root_other_missing_group_or_user_is_error_with_guidance() {
        let err = resolve_service_ids("nobody", "zmax", true, debian_uid, debian_gid)
            .expect_err("nobody dışı eksik grup yedeksiz hata olmalı");
        assert!(
            err.contains("zmax") && err.contains("server.group"),
            "{err}"
        );
        let err = resolve_service_ids("zmaxu", "nobody", true, debian_uid, debian_gid)
            .expect_err("eksik kullanıcı kökken hata olmalı");
        assert!(
            err.contains("zmaxu") && err.contains("server.user"),
            "{err}"
        );
    }

    #[test]
    fn resolve_group_gid_falls_back_for_tls_path_too() {
        assert_eq!(resolve_group_gid("nobody", debian_gid), Ok(65533));
        assert!(resolve_group_gid("", debian_gid).is_err());
    }

    #[test]
    fn group_read_mode_adds_only_group_read_bit() {
        assert_eq!(group_read_mode(0o600), 0o640);
        assert_eq!(group_read_mode(0o640), 0o640);
        assert_eq!(group_read_mode(0o644), 0o644);
        assert_eq!(group_read_mode(0o400), 0o440);
        assert_eq!(
            group_read_mode(0o100600),
            0o640,
            "dosya türü bitleri atılmalı"
        );
    }

    fn k8_unique_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "zmax_core_k8_{}_{}_{}",
            tag,
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("geçici dizin oluşturulamadı");
        d
    }

    #[test]
    fn unreadable_paths_skips_missing_and_accepts_readable() {
        let d = k8_unique_dir("unread");
        let ok = d.join("ok.key");
        std::fs::write(&ok, b"k").unwrap();
        let missing = d.join("yok.key");
        assert!(unreadable_paths(&[&ok, &missing]).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    fn own_gid() -> libc::gid_t {
        // SAFETY: `getgid` salt-okunur POSIX sorgusudur.
        unsafe { libc::getgid() }
    }

    #[cfg(unix)]
    fn mode_of(p: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn set_mode(p: &std::path::Path, m: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn grant_group_read_sets_group_read_and_is_idempotent() {
        let d = k8_unique_dir("grant");
        let key = d.join("a.key");
        std::fs::write(&key, b"gizli").unwrap();
        set_mode(&key, 0o600);

        assert_eq!(grant_group_read(&key, own_gid()), Ok(true));
        assert_eq!(mode_of(&key), 0o640);
        assert_eq!(
            grant_group_read(&key, own_gid()),
            Ok(false),
            "ikinci çağrı değişiklik yapmaz"
        );

        // Sonradan oluşan (yenilenen) anahtar da aynı çağrıyla okunabilir yapılır.
        let renewed = d.join("renewed.key");
        std::fs::write(&renewed, b"yeni").unwrap();
        set_mode(&renewed, 0o600);
        assert_eq!(
            apply_tls_group_read(own_gid(), &[&key, &renewed]),
            Ok(1),
            "yalnız yeni dosya değişmeli"
        );
        assert_eq!(mode_of(&renewed), 0o640);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn grant_group_read_missing_path_is_ok_but_directory_is_error() {
        let d = k8_unique_dir("grant_err");
        assert_eq!(grant_group_read(&d.join("yok.pem"), own_gid()), Ok(false));
        let err = grant_group_read(&d, own_gid()).expect_err("dizin anahtar sayılmamalı");
        assert!(err.contains("normal dosya değil"), "hata: {err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn apply_tls_group_read_reports_errors_instead_of_swallowing() {
        let d = k8_unique_dir("apply_err");
        let good = d.join("good.key");
        std::fs::write(&good, b"k").unwrap();
        set_mode(&good, 0o600);
        // Dizin yolu hata üretir; iyi dosya yine de işlenir ve hata toplanıp döndürülür.
        let err = apply_tls_group_read(own_gid(), &[d.clone(), good.clone()])
            .expect_err("hata yutulmamalı");
        assert!(err.contains("normal dosya değil"), "hata: {err}");
        assert_eq!(
            mode_of(&good),
            0o640,
            "hata sonrası kalan yollar da işlenmeli"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn grant_group_read_follows_certbot_style_symlink_to_real_file() {
        let d = k8_unique_dir("grant_link");
        let archive = d.join("archive");
        let live = d.join("live");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        let real = archive.join("privkey1.pem");
        std::fs::write(&real, b"k").unwrap();
        set_mode(&real, 0o600);
        let link = live.join("privkey.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(grant_group_read(&link, own_gid()), Ok(true));
        assert_eq!(mode_of(&real), 0o640, "gerçek hedef dosya düzeltilmeli");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn chown_nofollow_skips_symlink_and_handles_missing_and_tree() {
        let d = k8_unique_dir("chown");
        // SAFETY: `getuid` salt-okunur POSIX sorgusudur.
        let uid = unsafe { libc::getuid() };
        let gid = own_gid();
        let sub = d.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("f.log"), b"x").unwrap();
        let outside = k8_unique_dir("chown_outside");
        let target = outside.join("hedef.txt");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, d.join("link")).unwrap();
        std::os::unix::fs::symlink(&outside, d.join("dirlink")).unwrap();

        assert_eq!(chown_single_non_symlink(&d, uid, gid, 2), Ok(()));
        assert_eq!(
            chown_single_non_symlink(&d.join("yok"), uid, gid, 2),
            Ok(())
        );
        // Üst yol sembolik bağsa (dizin bağı) izlenmez ve hata vermez.
        assert_eq!(
            chown_single_non_symlink(&d.join("dirlink"), uid, gid, 2),
            Ok(())
        );
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_private_tmp_dir_creates_0700_and_rejects_symlink() {
        use std::os::unix::fs::MetadataExt;
        let d = k8_unique_dir("tmpdir");
        let t = d.join("zmax-tmp");
        assert_eq!(prepare_private_tmp_dir(&t, ""), Ok(()));
        assert_eq!(mode_of(&t), 0o700);
        // geniş izinle önceden var olan kendi dizini 0700'e çekilir
        set_mode(&t, 0o755);
        assert_eq!(prepare_private_tmp_dir(&t, ""), Ok(()));
        assert_eq!(mode_of(&t), 0o700);
        // sahip doğrulama: kendi dizinimiz (euid) kabul edilir
        // SAFETY: `geteuid` salt-okunur POSIX sorgusudur.
        assert_eq!(std::fs::metadata(&t).unwrap().uid(), unsafe {
            libc::geteuid()
        });
        // sembolik bağ reddedilir
        let real = d.join("gercek");
        std::fs::create_dir_all(&real).unwrap();
        let link = d.join("baglanti");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = prepare_private_tmp_dir(&link, "").expect_err("sembolik bağ reddedilmeli");
        assert!(err.contains("sembolik"), "hata: {err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn prepare_private_tmp_dir_creates_missing_parents() {
        let d = k8_unique_dir("tmpdir_parent");
        let t = d.join("a").join("b").join("tmp");
        assert_eq!(prepare_private_tmp_dir(&t, ""), Ok(()));
        assert!(t.is_dir());
        let _ = std::fs::remove_dir_all(&d);
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

