//! # zmax-timeout
//! Slowloris ve yavaş istemci saldırılarına karşı zaman aşımı koruma kalkanı.

use std::future::Future;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum TimeoutError {
    #[error("Baslik okuma zaman asimina ugradi (Slowloris engellendi)")]
    HeaderTimeout,
    #[error("Govde (Body) veri aktarimi zaman asimina ugradi")]
    BodyTimeout,
    #[error("Bosta bekleme (Keep-Alive) suresi doldu")]
    IdleTimeout,
}

pub struct TimeoutConfig {
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub keep_alive_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(65),
        }
    }
}

/// HTTP başlık okuma işlemini 10 saniyelik Slowloris kalkanıyla sarar
pub async fn with_header_timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutError::HeaderTimeout)
}

/// HTTP gövde okuma işlemini zaman aşımıyla sarar
pub async fn with_body_timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutError::BodyTimeout)
}

/// Boşta bekleme (Keep-Alive) işlemini zaman aşımıyla sarar
pub async fn with_idle_timeout<F, T>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| TimeoutError::IdleTimeout)
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
    async fn test_slowloris_byte_drip_and_default_config_bounds() {
        let defaults = TimeoutConfig::default();
        assert_eq!(defaults.header_timeout, Duration::from_secs(10));
        assert_eq!(defaults.body_timeout, Duration::from_secs(30));
        assert_eq!(defaults.keep_alive_timeout, Duration::from_secs(65));

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
}
