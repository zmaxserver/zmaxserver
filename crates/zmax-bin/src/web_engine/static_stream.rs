use crate::api::ServerState;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use tokio::io::AsyncSeekExt;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zmax_static::is_sendfile_supported;

#[cfg(target_os = "linux")]
async fn try_stream_tcp_sendfile(
    tcp_stream: &mut TcpStream,
    file: &tokio::fs::File,
    offset: &mut u64,
    remaining: &mut u64,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::io::AsRawFd;

    tcp_stream.flush().await?;
    let out_fd = tcp_stream.as_raw_fd();
    let in_fd = file.as_raw_fd();
    let sendfile_write_timeout = Duration::from_secs(30);

    while *remaining > 0 {
        tokio::time::timeout(sendfile_write_timeout, tcp_stream.writable())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "sendfile soket yazma zaman aşımı",
                )
            })??;
        let chunk_cap = usize::try_from(*remaining)
            .unwrap_or(usize::MAX)
            .min(1024 * 1024);
        match tcp_stream.try_io(tokio::io::Interest::WRITABLE, || {
            zmax_static::try_sendfile_chunk(out_fd, in_fd, offset, chunk_cap)
        }) {
            Ok(0) => {
                // Beklenmeyen EOF durumunda kalanı tamponlu yedek akışla tamamla
                return Ok(false);
            }
            Ok(n) => {
                let n_u64 = u64::try_from(n).unwrap_or(*remaining);
                *remaining = remaining.saturating_sub(n_u64);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
                ) || matches!(
                    err.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSOCK | libc::EOPNOTSUPP)
                ) =>
            {
                return Ok(false);
            }
            Err(err) => return Err(Box::new(err)),
        }
    }

    Ok(true)
}

pub(super) async fn stream_file_range_pooled<S>(
    socket: &mut S,
    state: &Arc<ServerState>,
    file: &mut tokio::fs::File,
    file_offset: u64,
    mut remaining: u64,
    is_https: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin + 'static,
{
    // [kart-8] Linux düz TCP (!is_https) statik aktarımında gerçek `sendfile(2)` sıfır-kopya yolu.
    // TLS bağlantılarında (`TlsStream<TcpStream>`) baytlar rustls ile kullanıcı alanında
    // şifrelendiği için çekirdek içi sendfile(2) kullanılamaz; doğrudan BufferPool tamponlu
    // okuma/yazma yedek yoluna düşülür.
    if !is_https && is_sendfile_supported() {
        if let Some(_tcp_stream) = (socket as &mut dyn std::any::Any).downcast_mut::<TcpStream>() {
            #[cfg(target_os = "linux")]
            {
                let mut cur_offset = file_offset;
                if try_stream_tcp_sendfile(_tcp_stream, file, &mut cur_offset, &mut remaining)
                    .await?
                {
                    return Ok(());
                }
                file.seek(std::io::SeekFrom::Start(cur_offset)).await?;
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = file_offset;

    let mut buf = state.buffer_pool.acquire();
    let target_cap = 64 * 1024;
    if buf.capacity() < target_cap {
        buf.reserve(target_cap - buf.capacity());
    }
    buf.resize(target_cap, 0);

    let res = async {
        while remaining > 0 {
            let to_read = (remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read]).await?;
            if n == 0 {
                break;
            }
            socket.write_all(&buf[..n]).await?;
            remaining -= n as u64;
        }
        Ok(())
    }
    .await;

    state.buffer_pool.release(buf);
    res
}
