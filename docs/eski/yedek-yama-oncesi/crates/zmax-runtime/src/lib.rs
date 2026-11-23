//! # zmax-runtime
//! ZMax Server asenkron worker yaşam döngüsü ve işletim sistemi sinyal yöneticisi.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// SIGUSR2 yerinde ikili (zero-downtime) yükseltmede aktarılan dosya tanıtıcılarını tutan ortam değişkeni.
pub const INHERITED_FDS_ENV: &str = "ZMAX_INHERITED_FDS";

/// Sistemdeki uygun CPU çekirdeği sayısını hesaplar
pub fn detect_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// Yapılandırılan worker sayısına göre etkin worker sayısını belirler (`0` ise otomatik çekirdek sayısı).
pub fn determine_worker_count(configured: usize) -> usize {
    if configured > 0 {
        configured
    } else {
        detect_worker_threads().max(1)
    }
}

/// Sunucu yaşam döngüsü boyunca alınabilecek işletim sistemi sinyalleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSignal {
    Reload,
    ReopenLogs,
    UpgradeBinary,
    Shutdown,
}

/// Devam eden istek/bağlantı takibi için RAII koruyucu; bırakıldığında sayacı düşürür.
#[derive(Debug)]
pub struct InFlightGuard {
    in_flight: Arc<AtomicUsize>,
    drained_notify: Arc<tokio::sync::Notify>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.drained_notify.notify_waiters();
        }
    }
}

/// `tokio::sync::watch` tabanlı zarif kapanma ve aktif görev boşaltma (drain) koordinatörü.
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    tx: tokio::sync::watch::Sender<bool>,
    rx: tokio::sync::watch::Receiver<bool>,
    in_flight: Arc<AtomicUsize>,
    drained_notify: Arc<tokio::sync::Notify>,
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownCoordinator {
    /// Yeni bir kapatma koordinatörü oluşturur.
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        Self {
            tx,
            rx,
            in_flight: Arc::new(AtomicUsize::new(0)),
            drained_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Worker görevlerinin dinleyebileceği `watch` alıcı kopyasını döndürür.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.rx.clone()
    }

    /// Kapatma sürecinin başlatılıp başlatılmadığını bildirir.
    pub fn is_shutting_down(&self) -> bool {
        *self.rx.borrow()
    }

    /// Kapatma sinyalini tüm dinleyicilere yayınlar.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// Kapatma sinyali gelene kadar asenkron olarak bekler.
    pub async fn wait(&self) {
        let mut rx = self.subscribe();
        if *rx.borrow_and_update() {
            return;
        }
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                return;
            }
        }
    }

    /// Şu anda tamamlanmayı bekleyen aktif görev sayısını döndürür.
    pub fn active_tasks(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Kapatma başlamadıysa bir aktif görev koruyucusu (`InFlightGuard`) tahsis eder.
    pub fn acquire_guard(&self) -> Option<InFlightGuard> {
        if self.is_shutting_down() {
            return None;
        }
        self.in_flight.fetch_add(1, Ordering::AcqRel);
        let guard = InFlightGuard {
            in_flight: Arc::clone(&self.in_flight),
            drained_notify: Arc::clone(&self.drained_notify),
        };
        if self.is_shutting_down() {
            drop(guard);
            return None;
        }
        Some(guard)
    }

    /// Aktif görevlerin sıfırlanmasını belirtilen zaman aşımı boyunca bekler.
    /// Tüm görevler temiz sonlanırsa `true`, süre dolarsa `false` döner.
    pub async fn wait_for_drain(&self, timeout: Duration) -> bool {
        if self.active_tasks() == 0 {
            return true;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let notified = self.drained_notify.notified();
            if self.active_tasks() == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.active_tasks() == 0;
            }
        }
    }

    /// Kapatmayı tetikler ve aktif görevlerin boşalmasını bekler.
    pub async fn shutdown_and_drain(&self, timeout: Duration) -> bool {
        self.trigger();
        self.wait_for_drain(timeout).await
    }
}

/// Miras alınan `(isim, fd)` çiftlerini `ZMAX_INHERITED_FDS` ortam değişkeni biçimine kodlar.
pub fn encode_inherited_fds_env(fds: &[(String, i64)]) -> String {
    fds.iter()
        .filter_map(|(name, fd)| {
            let clean = name.trim();
            if clean.is_empty() || *fd < 0 || clean.contains('=') || clean.contains(',') {
                None
            } else {
                Some(format!("{}={}", clean, fd))
            }
        })
        .collect::<Vec<String>>()
        .join(",")
}

/// `ZMAX_INHERITED_FDS` ortam değişkeninden miras alınan `(isim, fd)` çiftlerini çözer.
pub fn decode_inherited_fds_env(raw: &str) -> Vec<(String, i64)> {
    raw.split(',')
        .filter_map(|segment| {
            let (name, fd_str) = segment.trim().split_once('=')?;
            let clean_name = name.trim();
            if clean_name.is_empty() {
                return None;
            }
            let fd = fd_str.trim().parse::<i64>().ok()?;
            if fd < 0 {
                return None;
            }
            Some((clean_name.to_string(), fd))
        })
        .collect()
}

/// Geçerli sürecin ortamından `ZMAX_INHERITED_FDS` değerini okur ve ayrıştırır.
pub fn read_inherited_fds_from_env() -> Vec<(String, i64)> {
    match std::env::var(INHERITED_FDS_ENV) {
        Ok(raw) => decode_inherited_fds_env(&raw),
        Err(_) => Vec::new(),
    }
}

/// POSIX dosya tanıtıcısı üzerinde `FD_CLOEXEC` bayrağını `libc::fcntl` ile ayarlar veya kaldırır.
#[cfg(unix)]
pub fn set_fd_cloexec(fd: std::os::unix::io::RawFd, cloexec: bool) -> std::io::Result<()> {
    if fd < 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EBADF));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let next_flags = if cloexec {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, next_flags) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `SIGUSR2` kesintisiz ikili yükseltmesi için dinleme soketlerini miras bırakarak yeni sunucu sürecini başlatır.
#[cfg(unix)]
pub fn spawn_reexec_binary(
    binary_path: Option<&std::path::Path>,
    args: Option<&[String]>,
    inherited_fds: &[(String, std::os::unix::io::RawFd)],
) -> std::io::Result<u32> {
    let exe = match binary_path {
        Some(path) => path.to_path_buf(),
        None => std::env::current_exe()?,
    };

    let mut env_pairs = Vec::with_capacity(inherited_fds.len());
    for (name, fd) in inherited_fds {
        set_fd_cloexec(*fd, false)?;
        env_pairs.push((name.clone(), i64::from(*fd)));
    }
    let encoded = encode_inherited_fds_env(&env_pairs);

    let mut cmd = std::process::Command::new(exe);
    match args {
        Some(custom_args) => {
            cmd.args(custom_args);
        }
        None => {
            cmd.args(std::env::args_os().skip(1));
        }
    }

    if encoded.is_empty() {
        cmd.env_remove(INHERITED_FDS_ENV);
    } else {
        cmd.env(INHERITED_FDS_ENV, encoded);
    }

    let child = cmd.spawn()?;
    Ok(child.id())
}

/// Bir sonraki işletim sistemi çalışma zamanı sinyalini (`Reload`, `ReopenLogs`, `UpgradeBinary`, `Shutdown`) bekler.
pub async fn wait_for_runtime_signal() -> RuntimeSignal {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt())
            .expect("SIGINT sinyal dinleyicisi kurulamadi");
        let mut sigterm = signal(SignalKind::terminate())
            .expect("SIGTERM sinyal dinleyicisi kurulamadi");
        let mut sighup = signal(SignalKind::hangup())
            .expect("SIGHUP sinyal dinleyicisi kurulamadi");
        let mut sigusr1 = signal(SignalKind::user_defined1())
            .expect("SIGUSR1 sinyal dinleyicisi kurulamadi");
        let mut sigusr2 = signal(SignalKind::user_defined2())
            .expect("SIGUSR2 sinyal dinleyicisi kurulamadi");

        tokio::select! {
            _ = sigint.recv() => RuntimeSignal::Shutdown,
            _ = sigterm.recv() => RuntimeSignal::Shutdown,
            _ = sighup.recv() => RuntimeSignal::Reload,
            _ = sigusr1.recv() => RuntimeSignal::ReopenLogs,
            _ = sigusr2.recv() => RuntimeSignal::UpgradeBinary,
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Ctrl+C sinyal dinleyicisi kurulamadi");
        RuntimeSignal::Shutdown
    }
}

/// Windows ve Linux için zarif kapanma (graceful shutdown) sinyali dinleyicisi
pub async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Ctrl+C sinyal dinleyicisi kurulamadi");
    };

    #[cfg(unix)]
    let terminate = async {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM sinyal dinleyicisi kurulamadi");
        sigterm.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Kapatma sinyali alindi (Ctrl+C). Sunucu durduruluyor...");
        },
        _ = terminate => {
            tracing::info!("Kapatma sinyali alindi (SIGTERM). Sunucu durduruluyor...");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_worker_count() {
        let auto = determine_worker_count(0);
        assert!(auto >= 1);
        assert_eq!(auto, detect_worker_threads().max(1));
        assert_eq!(determine_worker_count(1), 1);
        assert_eq!(determine_worker_count(16), 16);
    }

    #[test]
    fn test_inherited_fds_encode_decode_roundtrip() {
        let input = vec![
            ("http".to_string(), 3),
            ("https".to_string(), 4),
            ("admin".to_string(), 7),
        ];
        let encoded = encode_inherited_fds_env(&input);
        assert_eq!(encoded, "http=3,https=4,admin=7");
        assert_eq!(decode_inherited_fds_env(&encoded), input);

        // Geçersiz girdiler filtrelenmeli
        let filtered = encode_inherited_fds_env(&[
            ("".to_string(), 3),
            ("bad=name".to_string(), 4),
            ("bad,name".to_string(), 5),
            ("neg".to_string(), -1),
            ("api".to_string(), 9),
        ]);
        assert_eq!(filtered, "api=9");

        // Bozuk segmentler decode sırasında atlanmalı
        let decoded = decode_inherited_fds_env(" , http = 10 , broken , x=abc , neg=-2 , https=11 ");
        assert_eq!(
            decoded,
            vec![("http".to_string(), 10), ("https".to_string(), 11)]
        );
    }

    #[test]
    fn test_runtime_signal_enum_traits() {
        let signals = [
            RuntimeSignal::Reload,
            RuntimeSignal::ReopenLogs,
            RuntimeSignal::UpgradeBinary,
            RuntimeSignal::Shutdown,
        ];
        assert_ne!(signals[0], signals[1]);
        assert_ne!(signals[2], signals[3]);
        assert_eq!(signals[0], RuntimeSignal::Reload);
        assert!(format!("{:?}", RuntimeSignal::UpgradeBinary).contains("UpgradeBinary"));
    }

    #[tokio::test]
    async fn test_shutdown_coordinator_trigger_and_wait() {
        let coord = ShutdownCoordinator::new();
        assert!(!coord.is_shutting_down());
        let mut rx = coord.subscribe();
        assert!(!*rx.borrow());

        let waiter_coord = coord.clone();
        let handle = tokio::spawn(async move {
            waiter_coord.wait().await;
        });

        tokio::task::yield_now().await;
        coord.trigger();

        handle.await.expect("Wait görevi temiz bitmeli");
        assert!(coord.is_shutting_down());
        rx.changed().await.ok();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn test_shutdown_coordinator_drain_completes_when_guards_drop() {
        let coord = ShutdownCoordinator::new();
        let g1 = coord.acquire_guard().expect("İlk guard alınmalı");
        let g2 = coord.acquire_guard().expect("İkinci guard alınmalı");
        assert_eq!(coord.active_tasks(), 2);

        let drain_coord = coord.clone();
        let drain_task = tokio::spawn(async move {
            drain_coord.shutdown_and_drain(Duration::from_millis(500)).await
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(coord.is_shutting_down());
        assert!(coord.acquire_guard().is_none(), "Kapatma sonrası yeni guard reddedilmeli");

        drop(g1);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(coord.active_tasks(), 1);
        drop(g2);

        let drained = drain_task.await.unwrap();
        assert!(drained, "Tüm guard'lar bırakılınca drain true dönmeli");
        assert_eq!(coord.active_tasks(), 0);
    }

    #[tokio::test]
    async fn test_shutdown_coordinator_drain_timeout_when_task_remains_active() {
        let coord = ShutdownCoordinator::new();
        let _stuck_guard = coord.acquire_guard().expect("Guard alınmalı");
        assert_eq!(coord.active_tasks(), 1);

        let drained = coord.shutdown_and_drain(Duration::from_millis(30)).await;
        assert!(!drained, "Açık guard varken drain zaman aşımı false dönmeli");
        assert_eq!(coord.active_tasks(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_set_fd_cloexec_toggle() {
        use std::os::unix::io::AsRawFd;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fd = listener.as_raw_fd();

        set_fd_cloexec(fd, false).unwrap();
        let flags_clear = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(flags_clear & libc::FD_CLOEXEC, 0);

        set_fd_cloexec(fd, true).unwrap();
        let flags_set = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags_set & libc::FD_CLOEXEC, 0);

        assert!(set_fd_cloexec(-1, true).is_err());
    }
}
