//! # zmax-timeout
//! Slowloris ve yavaş istemci saldırılarına karşı zaman aşımı koruma kalkanı.
//! Matris Standartları: Header 10 sn, Body 30 sn, Keep-Alive 65 sn.

use std::future::Future;
use std::time::Duration;
use thiserror::Error;

/// Varsayılan zaman aşımı sabitleri (Matris §1 / §8)
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
pub const DEFAULT_BODY_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(65);

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutError {
    #[error("Baslik okuma zaman asimina ugradi (Slowloris engellendi)")]
    HeaderTimeout,
    #[error("Govde (Body) veri aktarimi zaman asimina ugradi")]
    BodyTimeout,
    #[error("Bosta bekleme (Keep-Alive) suresi doldu")]
    IdleTimeout,
}

impl TimeoutError {
    /// Zaman aşımı hatasının karşılık geldiği HTTP durum kodunu döner (varsa).
    /// Başlık ve Gövde aşımı 408 dönerken, boştaki Keep-Alive bağlantının sessizce
    /// kapatılması gerektiğinden None döner.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::HeaderTimeout => Some(408),
            Self::BodyTimeout => Some(408),
            Self::IdleTimeout => None,
        }
    }

    /// Hatanın Slowloris veya yavaş veri iletim saldırısı olup olmadığını belirtir.
    pub fn is_slowloris(&self) -> bool {
        matches!(self, Self::HeaderTimeout | Self::BodyTimeout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutConfig {
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub keep_alive_timeout: Duration,
}

impl TimeoutConfig {
    pub const fn new(
        header_timeout: Duration,
        body_timeout: Duration,
        keep_alive_timeout: Duration,
    ) -> Self {
        Self {
            header_timeout,
            body_timeout,
            keep_alive_timeout,
        }
    }

    pub fn with_header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }

    pub fn with_body_timeout(mut self, timeout: Duration) -> Self {
        self.body_timeout = timeout;
        self
    }

    pub fn with_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.keep_alive_timeout = timeout;
        self
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            body_timeout: DEFAULT_BODY_TIMEOUT,
            keep_alive_timeout: DEFAULT_KEEP_ALIVE_TIMEOUT,
        }
    }
}

/// HTTP başlık okuma işlemini Slowloris kalkanıyla sarar.
pub async fn with_header_timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutError::HeaderTimeout)
}

/// HTTP gövde okuma işlemini zaman aşımıyla sarar.
pub async fn with_body_timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutError::BodyTimeout)
}

/// Boşta bekleme (Keep-Alive) işlemini zaman aşımıyla sarar.
pub async fn with_idle_timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutError::IdleTimeout)
}

/// Belirtilen mutlak son tarihe (deadline) kadar işlemi tamamlamasını bekler.
pub async fn with_deadline<F, T>(
    deadline: tokio::time::Instant,
    future: F,
    error: TimeoutError,
) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_timeout_helpers_return_expected_variants() {
        let ok_res = with_header_timeout(Duration::from_millis(50), async { 42 }).await;
        assert_eq!(ok_res, Ok(42));

        let hdr_err = with_header_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(80)).await;
        })
        .await;
        assert_eq!(hdr_err, Err(TimeoutError::HeaderTimeout));

        let body_err = with_body_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(80)).await;
        })
        .await;
        assert_eq!(body_err, Err(TimeoutError::BodyTimeout));

        let idle_ok = with_idle_timeout(Duration::from_millis(50), async { "alive" }).await;
        assert_eq!(idle_ok, Ok("alive"));

        let idle_err = with_idle_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_millis(80)).await;
        })
        .await;
        assert_eq!(idle_err, Err(TimeoutError::IdleTimeout));
    }

    #[tokio::test]
    async fn test_timeout_error_status_codes_and_classification() {
        assert_eq!(TimeoutError::HeaderTimeout.status_code(), Some(408));
        assert_eq!(TimeoutError::BodyTimeout.status_code(), Some(408));
        assert_eq!(TimeoutError::IdleTimeout.status_code(), None);

        assert!(TimeoutError::HeaderTimeout.is_slowloris());
        assert!(TimeoutError::BodyTimeout.is_slowloris());
        assert!(!TimeoutError::IdleTimeout.is_slowloris());
    }

    #[tokio::test]
    async fn test_timeout_config_builder_and_default_matrix_bounds() {
        let defaults = TimeoutConfig::default();
        assert_eq!(defaults.header_timeout, Duration::from_secs(10));
        assert_eq!(defaults.body_timeout, Duration::from_secs(30));
        assert_eq!(defaults.keep_alive_timeout, Duration::from_secs(65));

        let custom = TimeoutConfig::new(
            Duration::from_secs(5),
            Duration::from_secs(15),
            Duration::from_secs(30),
        )
        .with_header_timeout(Duration::from_secs(8))
        .with_body_timeout(Duration::from_secs(20))
        .with_keep_alive_timeout(Duration::from_secs(45));

        assert_eq!(custom.header_timeout, Duration::from_secs(8));
        assert_eq!(custom.body_timeout, Duration::from_secs(20));
        assert_eq!(custom.keep_alive_timeout, Duration::from_secs(45));
    }

    #[tokio::test]
    async fn test_slowloris_byte_drip_and_default_config_bounds() {
        // Slowloris simülasyonu: saldırgan her 15 ms'de 1 bayt yolluyor, toplam başlık 120 ms sürecek;
        // 35 ms'lik header_timeout erken kesmeli ve HeaderTimeout üretmelidir.
        let received = Arc::new(AtomicUsize::new(0));
        let received_clone = Arc::clone(&received);
        let slowloris_future = async move {
            for _ in 0..8 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                received_clone.fetch_add(1, Ordering::Relaxed);
            }
            "GET / HTTP/1.1\r\n"
        };
        let verdict = with_header_timeout(Duration::from_millis(35), slowloris_future).await;
        assert_eq!(verdict, Err(TimeoutError::HeaderTimeout));
        assert!(received.load(Ordering::Relaxed) < 8);
    }

    #[tokio::test]
    async fn test_slowloris_body_drip_timeout_mitigation() {
        // Yavaş gövde (body) aktarımı simülasyonu: istemci her 15 ms'de 1 bayt gönderiyor,
        // gövde için tanınan süre dolunca BodyTimeout almalı ve akış kesilmelidir.
        let body_received = Arc::new(AtomicUsize::new(0));
        let body_clone = Arc::clone(&body_received);
        let slow_body_future = async move {
            for _ in 0..10 {
                tokio::time::sleep(Duration::from_millis(15)).await;
                body_clone.fetch_add(1, Ordering::Relaxed);
            }
            vec![b'A'; 10]
        };

        let verdict = with_body_timeout(Duration::from_millis(40), slow_body_future).await;
        assert_eq!(verdict, Err(TimeoutError::BodyTimeout));
        assert!(body_received.load(Ordering::Relaxed) < 10);
    }

    #[tokio::test]
    async fn test_concurrent_body_and_idle_deadlines_isolated() {
        let mut handles = Vec::new();
        for idx in 0..16usize {
            handles.push(tokio::spawn(async move {
                if idx % 2 == 0 {
                    with_body_timeout(Duration::from_millis(40), async {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        idx
                    })
                    .await
                } else {
                    with_body_timeout(Duration::from_millis(15), async {
                        tokio::time::sleep(Duration::from_millis(70)).await;
                        idx
                    })
                    .await
                }
            }));
        }
        let mut ok_count = 0usize;
        let mut timeout_count = 0usize;
        for h in handles {
            match h.await.unwrap() {
                Ok(_) => ok_count += 1,
                Err(TimeoutError::BodyTimeout) => timeout_count += 1,
                Err(other) => panic!("Beklenmeyen hata türü: {other:?}"),
            }
        }
        assert_eq!(ok_count, 8);
        assert_eq!(timeout_count, 8);
    }

    #[tokio::test]
    async fn test_matrix_bounds_and_ratio_simulation() {
        // Matris §1 / §8 oranlarının simülasyonu: Header 10ms (10s), Body 30ms (30s), Keep-Alive 65ms (65s).
        let config = TimeoutConfig::new(
            Duration::from_millis(10),
            Duration::from_millis(30),
            Duration::from_millis(65),
        );

        // 1. Header aşımı
        let h_res = with_header_timeout(config.header_timeout, async {
            tokio::time::sleep(Duration::from_millis(35)).await;
            "tamam"
        })
        .await;
        assert_eq!(h_res, Err(TimeoutError::HeaderTimeout));

        // 2. Body aşımı
        let b_res = with_body_timeout(config.body_timeout, async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            "tamam"
        })
        .await;
        assert_eq!(b_res, Err(TimeoutError::BodyTimeout));

        // 3. Keep-Alive idle aşımı
        let idle_res = with_idle_timeout(config.keep_alive_timeout, async {
            tokio::time::sleep(Duration::from_millis(95)).await;
            "tamam"
        })
        .await;
        assert_eq!(idle_res, Err(TimeoutError::IdleTimeout));
    }
}
