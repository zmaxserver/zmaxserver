//! # zmax-proxy
//! Node.js, Python WSGI/ASGI, Go backend ters proxy, tamponsuz akış (SSE `respBuffer 0`)
//! ve WebSocket çift yönlü tünel motoru.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const STREAM_BUF_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct ProxyRewriteOptions<'a> {
    /// `true` ise istemcinin `Host` başlığı korunur; `false` ve `upstream_host` doluysa arka uç adresi yazılır.
    pub preserve_host: bool,
    /// `preserve_host == false` olduğunda kullanılacak hedef `Host` değeri.
    pub upstream_host: Option<&'a str>,
}

impl Default for ProxyRewriteOptions<'_> {
    fn default() -> Self {
        Self {
            preserve_host: true,
            upstream_host: None,
        }
    }
}

/// Tamponsuz/akışlı proxy iletiminin başarı sonucu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamForwardResult {
    pub status: u16,
    pub body_bytes: usize,
    pub upstream_reusable: bool,
    pub client_keep_alive: bool,
    pub is_sse: bool,
}

/// Akışlı proxy iletiminde hata ayrıntısı (`headers_sent` ile 502/504 yazılıp yazılamayacağını ayırır).
#[derive(Debug)]
pub struct StreamForwardError {
    pub error: ProxyError,
    pub headers_sent: bool,
    pub status: Option<u16>,
    pub body_bytes_sent: usize,
}

impl fmt::Display for StreamForwardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for StreamForwardError {}

pub struct ReverseProxy {
    upstream_addr: String,
    connect_timeout: Duration,
    read_timeout: Duration,
    init_timeout: Duration,
    keep_alive_timeout: Duration,
    resp_buffer: bool,
    preserve_host: bool,
    https: bool,
}

impl ReverseProxy {
    pub fn new(upstream: &str) -> Self {
        Self {
            upstream_addr: upstream.to_string(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            read_timeout: DEFAULT_READ_TIMEOUT,
            init_timeout: DEFAULT_READ_TIMEOUT,
            keep_alive_timeout: DEFAULT_KEEP_ALIVE_TIMEOUT,
            resp_buffer: false,
            preserve_host: true,
            https: false,
        }
    }

    pub fn with_timeouts(mut self, connect_timeout: Duration, read_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self.read_timeout = read_timeout;
        self.init_timeout = read_timeout;
        self
    }

    pub fn with_init_timeout(mut self, init_timeout: Duration) -> Self {
        self.init_timeout = init_timeout;
        self
    }

    pub fn with_keep_alive_timeout(mut self, keep_alive_timeout: Duration) -> Self {
        self.keep_alive_timeout = keep_alive_timeout;
        self
    }

    /// `false` = OLS `respBuffer 0` tamponsuz anında akış (varsayılan); `true` = tamponlu yanıt.
    pub fn with_resp_buffer(mut self, resp_buffer: bool) -> Self {
        self.resp_buffer = resp_buffer;
        self
    }

    pub fn with_preserve_host(mut self, preserve_host: bool) -> Self {
        self.preserve_host = preserve_host;
        self
    }

    pub fn with_https(mut self, https: bool) -> Self {
        self.https = https;
        self
    }

    pub fn init_timeout(&self) -> Duration {
        self.init_timeout
    }

    pub fn keep_alive_timeout(&self) -> Duration {
        self.keep_alive_timeout
    }

    pub fn resp_buffer(&self) -> bool {
        self.resp_buffer
    }

    fn rewrite_options(&self) -> ProxyRewriteOptions<'_> {
        ProxyRewriteOptions {
            preserve_host: self.preserve_host,
            upstream_host: if self.preserve_host {
                None
            } else {
                Some(self.upstream_addr.as_str())
            },
        }
    }

    /// Gelen HTTP isteğini arka uç sunucusuna yönlendirir, gerçek istemci IP başlıklarını ekler ve tam yanıtı döndürür.
    pub async fn forward_http(
        &self,
        request_raw: &[u8],
        client_ip: SocketAddr,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let opts = self.rewrite_options();
        let (is_head, rewritten_req) =
            rewrite_full_request(request_raw, client_ip.ip(), self.https, &opts, false)
                .ok_or(ProxyError::BadRequest)?;

        let mut upstream_stream = match tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect(&self.upstream_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(Box::new(ProxyError::Connect(e.to_string()))),
            Err(_) => return Err(Box::new(ProxyError::Connect("baglanti zaman asimi".into()))),
        };

        let _ = upstream_stream.set_nodelay(true);
        upstream_stream.write_all(&rewritten_req).await?;

        Ok(read_http_response(&mut upstream_stream, is_head, self.read_timeout).await?)
    }

    /// Önceden alınmış (ör. `UpstreamSocketPool`) bir `TcpStream` üzerinden HTTP isteğini
    /// iletir; `(yanıt_baytları, soket_yeniden_kullanılabilir_mi)` çiftini döndürür.
    pub async fn forward_http_on_stream(
        &self,
        upstream_stream: &mut TcpStream,
        request_raw: &[u8],
        client_ip: SocketAddr,
    ) -> Result<(Vec<u8>, bool), Box<dyn std::error::Error + Send + Sync>> {
        let opts = self.rewrite_options();
        let (is_head, rewritten_req) =
            rewrite_full_request(request_raw, client_ip.ip(), self.https, &opts, true)
                .ok_or(ProxyError::BadRequest)?;

        let _ = upstream_stream.set_nodelay(true);
        upstream_stream.write_all(&rewritten_req).await?;

        Ok(
            read_http_response_with_reusability(upstream_stream, is_head, self.read_timeout)
                .await?,
        )
    }

    /// Önceden alınmış (`UpstreamSocketPool`) bir `TcpStream` üzerinden isteği iletir ve yanıtı
    /// tamponsuz olarak (`resp_buffer == false` veya `text/event-stream` SSE ise) doğrudan istemciye
    /// parça parça `flush` ile aktarır. Keep-alive soket yeniden kullanımını korur.
    pub async fn forward_streaming_on_stream<W>(
        &self,
        upstream_stream: &mut TcpStream,
        client_writer: &mut W,
        request_head: &[u8],
        request_body: &[u8],
        client_ip: SocketAddr,
        client_wants_keep_alive: bool,
    ) -> Result<StreamForwardResult, StreamForwardError>
    where
        W: AsyncWrite + Unpin,
    {
        let opts = self.rewrite_options();
        let (is_head, rewritten_head) =
            rewrite_head_with_method(request_head, client_ip.ip(), self.https, &opts, true).ok_or(
                StreamForwardError {
                    error: ProxyError::BadRequest,
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                },
            )?;

        let _ = upstream_stream.set_nodelay(true);
        if let Err(e) = upstream_stream.write_all(&rewritten_head).await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: false,
                status: None,
                body_bytes_sent: 0,
            });
        }
        if !request_body.is_empty() {
            if let Err(e) = upstream_stream.write_all(request_body).await {
                return Err(StreamForwardError {
                    error: ProxyError::Io(e),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                });
            }
        }
        if let Err(e) = upstream_stream.flush().await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: false,
                status: None,
                body_bytes_sent: 0,
            });
        }

        let mut head_buf = Vec::with_capacity(4096);
        let mut buf = [0u8; STREAM_BUF_BYTES];
        let header_deadline = tokio::time::Instant::now() + self.init_timeout;

        let (header_end, head_info) = loop {
            if let Some(end) = find_header_end(&head_buf) {
                let info = inspect_response_framing(&head_buf[..end], is_head).map_err(|err| {
                    StreamForwardError {
                        error: err,
                        headers_sent: false,
                        status: None,
                        body_bytes_sent: 0,
                    }
                })?;
                if info.status == 100 && head_buf.len() >= end {
                    head_buf.drain(..end);
                    continue;
                }
                break (end, info);
            }

            if head_buf.len() >= MAX_RESPONSE_HEADER_BYTES {
                return Err(StreamForwardError {
                    error: ProxyError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Arka uc yanit basligi maksimum boyutu asti",
                    )),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                });
            }

            let n = read_with_deadline(
                upstream_stream,
                &mut buf,
                header_deadline,
                "Arka uc yanit okuma zaman asimina ugradi",
            )
            .await
            .map_err(|err| StreamForwardError {
                error: err,
                headers_sent: false,
                status: None,
                body_bytes_sent: 0,
            })?;

            if n == 0 {
                if head_buf.is_empty() {
                    return Err(StreamForwardError {
                        error: ProxyError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "Arka uc yanit gondermeden baglantiyi kapatti",
                        )),
                        headers_sent: false,
                        status: None,
                        body_bytes_sent: 0,
                    });
                }
                // Başlık tamamlanmadan EOF: kalan ham baytı doğrudan ilet ve bağlantıyı kapat
                let write_res = async {
                    client_writer.write_all(&head_buf).await?;
                    client_writer.flush().await
                }
                .await;
                if let Err(e) = write_res {
                    return Err(StreamForwardError {
                        error: ProxyError::Io(e),
                        headers_sent: true,
                        status: Some(502),
                        body_bytes_sent: 0,
                    });
                }
                return Ok(StreamForwardResult {
                    status: 200,
                    body_bytes: 0,
                    upstream_reusable: false,
                    client_keep_alive: false,
                    is_sse: false,
                });
            }
            head_buf.extend_from_slice(&buf[..n]);
        };

        let should_stream_unbuffered = !self.resp_buffer || head_info.is_sse;
        let idle_timeout = self.init_timeout;
        let mut can_keep_alive = head_info.header_allows_keep_alive;
        let body_allowed = !(is_head || head_info.status == 204 || head_info.status == 304);

        if !should_stream_unbuffered {
            // Tamponlu mod: gövdenin tamamını bekle, tek seferde yaz
            let full_res = finish_buffered_body(
                upstream_stream,
                head_buf,
                header_end,
                &head_info,
                idle_timeout,
            )
            .await;
            match full_res {
                Ok((full_bytes, upstream_ok)) => {
                    let body_len = if body_allowed {
                        full_bytes.len().saturating_sub(header_end)
                    } else {
                        0
                    };
                    if let Err(e) = client_writer.write_all(&full_bytes).await {
                        return Err(StreamForwardError {
                            error: ProxyError::Io(e),
                            headers_sent: true,
                            status: Some(head_info.status),
                            body_bytes_sent: 0,
                        });
                    }
                    if let Err(e) = client_writer.flush().await {
                        return Err(StreamForwardError {
                            error: ProxyError::Io(e),
                            headers_sent: true,
                            status: Some(head_info.status),
                            body_bytes_sent: body_len,
                        });
                    }
                    let client_keep = client_wants_keep_alive && upstream_ok;
                    return Ok(StreamForwardResult {
                        status: head_info.status,
                        body_bytes: body_len,
                        upstream_reusable: upstream_ok,
                        client_keep_alive: client_keep,
                        is_sse: head_info.is_sse,
                    });
                }
                Err(err) => {
                    return Err(StreamForwardError {
                        error: err,
                        headers_sent: false,
                        status: None,
                        body_bytes_sent: 0,
                    });
                }
            }
        }

        // Tamponsuz akış (respBuffer 0 / SSE): başlığı hemen istemciye yaz ve flush et
        if let Err(e) = client_writer.write_all(&head_buf[..header_end]).await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: false,
                status: Some(head_info.status),
                body_bytes_sent: 0,
            });
        }
        if let Err(e) = client_writer.flush().await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: true,
                status: Some(head_info.status),
                body_bytes_sent: 0,
            });
        }

        let initial_body = &head_buf[header_end..];
        let mut body_bytes_sent = 0usize;

        match head_info.framing {
            ResponseFraming::NoBody => {
                if !initial_body.is_empty() {
                    can_keep_alive = false;
                }
            }
            ResponseFraming::ContentLength(total_len) => {
                let mut remaining = total_len;
                if !initial_body.is_empty() {
                    if initial_body.len() > total_len {
                        can_keep_alive = false;
                    }
                    let take = remaining.min(initial_body.len());
                    if take > 0 {
                        write_and_flush_client(
                            client_writer,
                            &initial_body[..take],
                            head_info.status,
                            body_bytes_sent,
                        )
                        .await?;
                        if body_allowed {
                            body_bytes_sent += take;
                        }
                        remaining -= take;
                    }
                }

                while remaining > 0 {
                    let n = read_with_idle_timeout(
                        upstream_stream,
                        &mut buf,
                        idle_timeout,
                        "Arka uc govde okuma zaman asimina ugradi",
                    )
                    .await
                    .map_err(|err| StreamForwardError {
                        error: err,
                        headers_sent: true,
                        status: Some(head_info.status),
                        body_bytes_sent,
                    })?;

                    if n == 0 {
                        return Err(StreamForwardError {
                            error: ProxyError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Content-Length tamamlanmadan baglanti kapandi",
                            )),
                            headers_sent: true,
                            status: Some(head_info.status),
                            body_bytes_sent,
                        });
                    }

                    if n > remaining {
                        can_keep_alive = false;
                    }
                    let take = remaining.min(n);
                    write_and_flush_client(
                        client_writer,
                        &buf[..take],
                        head_info.status,
                        body_bytes_sent,
                    )
                    .await?;
                    if body_allowed {
                        body_bytes_sent += take;
                    }
                    remaining -= take;
                }
            }
            ResponseFraming::Chunked => {
                let mut tracker = ChunkedStreamTracker::new();
                let mut done = false;

                if !initial_body.is_empty() {
                    let (consumed, finished) =
                        tracker
                            .feed(initial_body)
                            .map_err(|err| StreamForwardError {
                                error: err,
                                headers_sent: true,
                                status: Some(head_info.status),
                                body_bytes_sent,
                            })?;
                    if consumed > 0 {
                        write_and_flush_client(
                            client_writer,
                            &initial_body[..consumed],
                            head_info.status,
                            body_bytes_sent,
                        )
                        .await?;
                        if body_allowed {
                            body_bytes_sent += consumed;
                        }
                    }
                    if finished {
                        if consumed < initial_body.len() {
                            can_keep_alive = false;
                        }
                        done = true;
                    }
                }

                while !done {
                    let n = read_with_idle_timeout(
                        upstream_stream,
                        &mut buf,
                        idle_timeout,
                        "Arka uc chunked yanit zaman asimina ugradi",
                    )
                    .await
                    .map_err(|err| StreamForwardError {
                        error: err,
                        headers_sent: true,
                        status: Some(head_info.status),
                        body_bytes_sent,
                    })?;

                    if n == 0 {
                        return Err(StreamForwardError {
                            error: ProxyError::Io(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Chunked yanit bitmeden baglanti kapandi",
                            )),
                            headers_sent: true,
                            status: Some(head_info.status),
                            body_bytes_sent,
                        });
                    }

                    let slice = &buf[..n];
                    let (consumed, finished) =
                        tracker.feed(slice).map_err(|err| StreamForwardError {
                            error: err,
                            headers_sent: true,
                            status: Some(head_info.status),
                            body_bytes_sent,
                        })?;

                    if consumed > 0 {
                        write_and_flush_client(
                            client_writer,
                            &slice[..consumed],
                            head_info.status,
                            body_bytes_sent,
                        )
                        .await?;
                        if body_allowed {
                            body_bytes_sent += consumed;
                        }
                    }
                    if finished {
                        if consumed < slice.len() {
                            can_keep_alive = false;
                        }
                        done = true;
                    }
                }
            }
            ResponseFraming::UntilEof => {
                can_keep_alive = false;
                if !initial_body.is_empty() {
                    write_and_flush_client(
                        client_writer,
                        initial_body,
                        head_info.status,
                        body_bytes_sent,
                    )
                    .await?;
                    if body_allowed {
                        body_bytes_sent += initial_body.len();
                    }
                }
                loop {
                    let n = read_with_idle_timeout(
                        upstream_stream,
                        &mut buf,
                        idle_timeout,
                        "Arka uc EOF yanit zaman asimina ugradi",
                    )
                    .await
                    .map_err(|err| StreamForwardError {
                        error: err,
                        headers_sent: true,
                        status: Some(head_info.status),
                        body_bytes_sent,
                    })?;
                    if n == 0 {
                        break;
                    }
                    write_and_flush_client(
                        client_writer,
                        &buf[..n],
                        head_info.status,
                        body_bytes_sent,
                    )
                    .await?;
                    if body_allowed {
                        body_bytes_sent += n;
                    }
                }
            }
        }

        let client_keep = client_wants_keep_alive && can_keep_alive;
        Ok(StreamForwardResult {
            status: head_info.status,
            body_bytes: body_bytes_sent,
            upstream_reusable: can_keep_alive,
            client_keep_alive: client_keep,
            is_sse: head_info.is_sse,
        })
    }

    /// WebSocket `Upgrade` isteğini `X-Forwarded-*` başlıklarıyla arka uca iletir, ilk el sıkışma
    /// (`101 Switching Protocols` vb.) yanıtını `init_timeout` içinde bekler ve çift yönlü tünel kurar.
    pub async fn tunnel_websocket_request<S>(
        &self,
        client: &mut S,
        request_head: &[u8],
        request_body: &[u8],
        client_ip: SocketAddr,
    ) -> Result<(u16, usize), StreamForwardError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let opts = self.rewrite_options();
        let rewritten_head =
            rewrite_request_head_with_options(request_head, client_ip.ip(), self.https, &opts)
                .ok_or(StreamForwardError {
                    error: ProxyError::BadRequest,
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                })?;

        let mut upstream = match tokio::time::timeout(
            self.connect_timeout,
            TcpStream::connect(&self.upstream_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return Err(StreamForwardError {
                    error: ProxyError::Connect(e.to_string()),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                })
            }
            Err(_) => {
                return Err(StreamForwardError {
                    error: ProxyError::Connect("baglanti zaman asimi".into()),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                })
            }
        };

        let _ = upstream.set_nodelay(true);
        if let Err(e) = upstream.write_all(&rewritten_head).await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: false,
                status: None,
                body_bytes_sent: 0,
            });
        }
        if !request_body.is_empty() {
            if let Err(e) = upstream.write_all(request_body).await {
                return Err(StreamForwardError {
                    error: ProxyError::Io(e),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                });
            }
        }
        if let Err(e) = upstream.flush().await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: false,
                status: None,
                body_bytes_sent: 0,
            });
        }

        // İlk el sıkışma yanıtını (ör. 101 Switching Protocols) `init_timeout` içinde oku
        let mut head_buf = Vec::with_capacity(2048);
        let mut buf = [0u8; 4096];
        let deadline = tokio::time::Instant::now() + self.init_timeout;

        let (header_end, head_info) = loop {
            if let Some(end) = find_header_end(&head_buf) {
                let info = inspect_response_framing(&head_buf[..end], false).map_err(|err| {
                    StreamForwardError {
                        error: err,
                        headers_sent: false,
                        status: None,
                        body_bytes_sent: 0,
                    }
                })?;
                break (end, info);
            }

            if head_buf.len() >= MAX_RESPONSE_HEADER_BYTES {
                return Err(StreamForwardError {
                    error: ProxyError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WebSocket yanit basligi maksimum boyutu asti",
                    )),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                });
            }

            let n = read_with_deadline(
                &mut upstream,
                &mut buf,
                deadline,
                "WebSocket el sikisma yaniti zaman asimina ugradi",
            )
            .await
            .map_err(|err| StreamForwardError {
                error: err,
                headers_sent: false,
                status: None,
                body_bytes_sent: 0,
            })?;

            if n == 0 {
                return Err(StreamForwardError {
                    error: ProxyError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "WebSocket el sikismasi tamamlanmadan arka uc kapandi",
                    )),
                    headers_sent: false,
                    status: None,
                    body_bytes_sent: 0,
                });
            }
            head_buf.extend_from_slice(&buf[..n]);
        };

        if let Err(e) = client.write_all(&head_buf).await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: false,
                status: Some(head_info.status),
                body_bytes_sent: 0,
            });
        }
        if let Err(e) = client.flush().await {
            return Err(StreamForwardError {
                error: ProxyError::Io(e),
                headers_sent: true,
                status: Some(head_info.status),
                body_bytes_sent: 0,
            });
        }
        let initial_extra_len = head_buf.len().saturating_sub(header_end);

        if head_info.status == 101 {
            let copied = tokio::io::copy_bidirectional(client, &mut upstream).await;
            let tunneled_bytes = match copied {
                Ok((_, u2c)) => initial_extra_len.saturating_add(u2c as usize),
                Err(_) => initial_extra_len,
            };
            return Ok((101, tunneled_bytes));
        }

        // 101 dışı ret yanıtında kalan gövde varsa kapatılana dek ilet
        let mut total_body = initial_extra_len;
        if let Ok(extra) = tokio::io::copy(&mut upstream, client).await {
            total_body = total_body.saturating_add(extra as usize);
        }
        if let Err(e) = client.flush().await {
            tracing::debug!(error = %e, "websocket ret yaniti flush hatasi");
        }
        Ok((head_info.status, total_body))
    }

    /// WebSocket ve uzun ömürlü bağlantılar için tam çift yönlü (Full-Duplex) tünel.
    pub async fn tunnel_websocket(
        &self,
        mut client_stream: TcpStream,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut upstream_stream = TcpStream::connect(&self.upstream_addr).await?;
        let _ = upstream_stream.set_nodelay(true);
        let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut upstream_stream).await;
        Ok(())
    }
}

#[derive(Debug)]
pub enum ProxyError {
    /// İstek başı ayrıştırılamadı (henüz hiçbir bayt arka uca gitmedi).
    BadRequest,
    /// Arka uca bağlanılamadı (henüz hiçbir bayt istemciye yazılmadı).
    Connect(String),
    Io(io::Error),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::BadRequest => write!(f, "Gecersiz HTTP istek basligi"),
            ProxyError::Connect(msg) => write!(f, "Arka uc baglanti hatasi: {}", msg),
            ProxyError::Io(e) => write!(f, "Proxy G/C hatasi: {}", e),
        }
    }
}

impl std::error::Error for ProxyError {}

/// İstek başını arka uç için yeniden yazar: mevcut `X-Forwarded-For` değerlerini koruyup
/// gerçek istemci IP adresini **sonuna** ekler (yoksa doğrudan yazar), `X-Real-IP` ve
/// `X-Forwarded-Proto` (`http`/`https`) ile `X-Forwarded-Host` başlıklarını ekler;
/// WebSocket (`Upgrade`) dışında `Connection: close` zorlar.
pub fn rewrite_request_head(head: &[u8], client_ip: IpAddr, https: bool) -> Option<Vec<u8>> {
    rewrite_request_head_with_options(head, client_ip, https, &ProxyRewriteOptions::default())
}

/// `ProxyRewriteOptions` (ör. `preserve_host`) desteğiyle istek başını yeniden yazar.
pub fn rewrite_request_head_with_options(
    head: &[u8],
    client_ip: IpAddr,
    https: bool,
    options: &ProxyRewriteOptions<'_>,
) -> Option<Vec<u8>> {
    let mut hs = [httparse::EMPTY_HEADER; 96];
    let mut req = httparse::Request::new(&mut hs);
    match req.parse(head).ok()? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return None,
    }
    Some(build_rewritten_head(&req, client_ip, https, options))
}

fn rewrite_head_with_method(
    head: &[u8],
    client_ip: IpAddr,
    https: bool,
    options: &ProxyRewriteOptions<'_>,
    keep_upstream_alive: bool,
) -> Option<(bool, Vec<u8>)> {
    let mut hs = [httparse::EMPTY_HEADER; 96];
    let mut req = httparse::Request::new(&mut hs);
    match req.parse(head).ok()? {
        httparse::Status::Complete(_) => {}
        httparse::Status::Partial => return None,
    }
    let is_head = req
        .method
        .map(|m| m.eq_ignore_ascii_case("HEAD"))
        .unwrap_or(false);
    let out = build_rewritten_head_internal(&req, client_ip, https, options, keep_upstream_alive);
    Some((is_head, out))
}

fn rewrite_full_request(
    raw: &[u8],
    client_ip: IpAddr,
    https: bool,
    options: &ProxyRewriteOptions<'_>,
    keep_upstream_alive: bool,
) -> Option<(bool, Vec<u8>)> {
    let mut hs = [httparse::EMPTY_HEADER; 96];
    let mut req = httparse::Request::new(&mut hs);
    let body_offset = match req.parse(raw).ok()? {
        httparse::Status::Complete(offset) => offset,
        httparse::Status::Partial => return None,
    };
    let is_head = req
        .method
        .map(|m| m.eq_ignore_ascii_case("HEAD"))
        .unwrap_or(false);
    let mut out =
        build_rewritten_head_internal(&req, client_ip, https, options, keep_upstream_alive);
    if body_offset < raw.len() {
        out.extend_from_slice(&raw[body_offset..]);
    }
    Some((is_head, out))
}

fn build_rewritten_head(
    req: &httparse::Request<'_, '_>,
    client_ip: IpAddr,
    https: bool,
    options: &ProxyRewriteOptions<'_>,
) -> Vec<u8> {
    build_rewritten_head_internal(req, client_ip, https, options, false)
}

fn sanitize_header_value(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|&c| c != '\r' && c != '\n' && c != '\0')
        .collect()
}

fn build_rewritten_head_internal(
    req: &httparse::Request<'_, '_>,
    client_ip: IpAddr,
    https: bool,
    options: &ProxyRewriteOptions<'_>,
    keep_upstream_alive: bool,
) -> Vec<u8> {
    let method = req.method.unwrap_or("GET");
    let path = req.path.unwrap_or("/");
    let ver = req.version.unwrap_or(1);
    let upgrade = req
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("upgrade"));

    let mut orig_host: Option<&[u8]> = None;
    let mut has_connection = false;
    let mut forwarded_for_parts: Vec<String> = Vec::new();

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(format!("{} {} HTTP/1.{}\r\n", method, path, ver).as_bytes());

    for h in req.headers.iter() {
        let n = h.name.to_ascii_lowercase();
        if n == "host" {
            orig_host = Some(h.value);
            if !options.preserve_host && options.upstream_host.is_some() {
                continue;
            }
        }
        if n == "x-forwarded-for" {
            let cleaned = sanitize_header_value(h.value);
            for part in cleaned.split(',') {
                let p = part.trim();
                if !p.is_empty() {
                    forwarded_for_parts.push(p.to_string());
                }
            }
            continue;
        }
        let drop = matches!(
            n.as_str(),
            "x-forwarded-proto"
                | "x-forwarded-host"
                | "x-real-ip"
                | "keep-alive"
                | "proxy-connection"
        ) || (n == "connection" && !upgrade);
        if drop {
            continue;
        }
        if n == "connection" {
            has_connection = true;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }

    if !options.preserve_host {
        if let Some(up_host) = options.upstream_host {
            out.extend_from_slice(format!("Host: {}\r\n", up_host).as_bytes());
        }
    }
    if let Some(host_val) = orig_host {
        let clean_host = sanitize_header_value(host_val);
        out.extend_from_slice(b"X-Forwarded-Host: ");
        out.extend_from_slice(clean_host.trim().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    let client_ip_str = client_ip.to_string();
    forwarded_for_parts.push(client_ip_str.clone());
    out.extend_from_slice(
        format!("X-Forwarded-For: {}\r\n", forwarded_for_parts.join(", ")).as_bytes(),
    );
    out.extend_from_slice(format!("X-Real-IP: {}\r\n", client_ip_str).as_bytes());
    out.extend_from_slice(
        format!(
            "X-Forwarded-Proto: {}\r\n",
            if https { "https" } else { "http" }
        )
        .as_bytes(),
    );
    if upgrade {
        if !has_connection {
            out.extend_from_slice(b"Connection: Upgrade\r\n");
        }
    } else if keep_upstream_alive {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
    } else {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

enum ResponseFraming {
    NoBody,
    ContentLength(usize),
    Chunked,
    UntilEof,
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some(pos + 2);
    }
    None
}

struct ResponseHeadInfo {
    status: u16,
    framing: ResponseFraming,
    header_allows_keep_alive: bool,
    is_sse: bool,
}

fn inspect_response_framing(
    header_bytes: &[u8],
    is_head_request: bool,
) -> Result<ResponseHeadInfo, ProxyError> {
    let mut hs = [httparse::EMPTY_HEADER; 128];
    let mut resp = httparse::Response::new(&mut hs);
    match resp.parse(header_bytes) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => {
            return Err(ProxyError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Arka uc gecersiz HTTP yanit basligi dondu",
            )))
        }
    }

    let status = resp.code.unwrap_or(200);
    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;
    let mut has_conn_close = false;
    let mut has_conn_keep_alive = false;
    let mut is_sse = false;

    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("transfer-encoding") {
            let val = String::from_utf8_lossy(h.value).to_ascii_lowercase();
            if val.split(',').any(|p| p.trim() == "chunked") {
                is_chunked = true;
            }
        } else if h.name.eq_ignore_ascii_case("content-length") {
            let val = String::from_utf8_lossy(h.value);
            if let Ok(len) = val.trim().parse::<usize>() {
                content_length = Some(len);
            }
        } else if h.name.eq_ignore_ascii_case("content-type") {
            let val = String::from_utf8_lossy(h.value).to_ascii_lowercase();
            if val.contains("text/event-stream") {
                is_sse = true;
            }
        } else if h.name.eq_ignore_ascii_case("connection") {
            let val = String::from_utf8_lossy(h.value);
            for token in val.split(',') {
                let t = token.trim();
                if t.eq_ignore_ascii_case("close") {
                    has_conn_close = true;
                } else if t.eq_ignore_ascii_case("keep-alive") {
                    has_conn_keep_alive = true;
                }
            }
        }
    }

    let framing =
        if is_head_request || status == 204 || status == 304 || (100..200).contains(&status) {
            ResponseFraming::NoBody
        } else if is_chunked {
            ResponseFraming::Chunked
        } else if let Some(len) = content_length {
            ResponseFraming::ContentLength(len)
        } else {
            ResponseFraming::UntilEof
        };

    let framing_allows = !matches!(framing, ResponseFraming::UntilEof);
    let version_allows = match resp.version {
        Some(1) => !has_conn_close,
        Some(0) => has_conn_keep_alive && !has_conn_close,
        _ => false,
    };
    let header_allows_keep_alive = framing_allows && status != 101 && version_allows;

    Ok(ResponseHeadInfo {
        status,
        framing,
        header_allows_keep_alive,
        is_sse,
    })
}

fn is_chunked_complete(body: &[u8]) -> Result<Option<usize>, ProxyError> {
    let mut pos = 0usize;
    loop {
        let Some(rel_crlf) = body[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&body[pos..pos + rel_crlf]).map_err(|_| {
            ProxyError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Gecersiz chunked boyut satiri",
            ))
        })?;
        let hex_part = size_line.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(hex_part, 16).map_err(|_| {
            ProxyError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Gecersiz chunked hex uzunlugu",
            ))
        })?;

        let after_line = pos + rel_crlf + 2;
        if chunk_size == 0 {
            if body[after_line..].starts_with(b"\r\n") {
                return Ok(Some(after_line + 2));
            }
            if let Some(trailer_end) = body[after_line..].windows(4).position(|w| w == b"\r\n\r\n")
            {
                return Ok(Some(after_line + trailer_end + 4));
            }
            return Ok(None);
        }

        let next_pos = after_line
            .checked_add(chunk_size)
            .and_then(|v| v.checked_add(2))
            .ok_or_else(|| {
                ProxyError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Chunk boyutu tasmasi",
                ))
            })?;
        if body.len() < next_pos {
            return Ok(None);
        }
        pos = next_pos;
    }
}

/// Parça parça gelen HTTP chunked akışını bellekte tamponlamadan tarayarak
/// son chunk (`0\r\n\r\n`) sınırını tespit eder.
struct ChunkedStreamTracker {
    state: ChunkTrackState,
    line_buf: Vec<u8>,
}

enum ChunkTrackState {
    SizeLine,
    ChunkData(usize),
    ChunkCrlf(u8),
    TrailerLineStart,
    TrailerLineRest,
    TrailerEndLf,
    Done,
}

impl ChunkedStreamTracker {
    fn new() -> Self {
        Self {
            state: ChunkTrackState::SizeLine,
            line_buf: Vec::with_capacity(64),
        }
    }

    fn feed(&mut self, data: &[u8]) -> Result<(usize, bool), ProxyError> {
        let mut i = 0usize;
        while i < data.len() {
            match self.state {
                ChunkTrackState::Done => {
                    return Ok((i, true));
                }
                ChunkTrackState::SizeLine => {
                    let b = data[i];
                    i += 1;
                    if b == b'\n' {
                        let line_str = std::str::from_utf8(&self.line_buf).map_err(|_| {
                            ProxyError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Gecersiz chunked boyut satiri",
                            ))
                        })?;
                        let trimmed = line_str.trim_end_matches('\r');
                        let hex_part = trimmed.split(';').next().unwrap_or("").trim();
                        let chunk_size = usize::from_str_radix(hex_part, 16).map_err(|_| {
                            ProxyError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Gecersiz chunked hex uzunlugu",
                            ))
                        })?;
                        self.line_buf.clear();
                        if chunk_size == 0 {
                            self.state = ChunkTrackState::TrailerLineStart;
                        } else {
                            self.state = ChunkTrackState::ChunkData(chunk_size);
                        }
                    } else {
                        if self.line_buf.len() >= 4096 {
                            return Err(ProxyError::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Chunked boyut satiri cok uzun",
                            )));
                        }
                        self.line_buf.push(b);
                    }
                }
                ChunkTrackState::ChunkData(rem) => {
                    let avail = data.len() - i;
                    let take = rem.min(avail);
                    i += take;
                    let left = rem - take;
                    if left == 0 {
                        self.state = ChunkTrackState::ChunkCrlf(0);
                    } else {
                        self.state = ChunkTrackState::ChunkData(left);
                    }
                }
                ChunkTrackState::ChunkCrlf(step) => {
                    let b = data[i];
                    i += 1;
                    if step == 0 && b == b'\r' {
                        self.state = ChunkTrackState::ChunkCrlf(1);
                    } else if b == b'\n' {
                        self.state = ChunkTrackState::SizeLine;
                    } else {
                        return Err(ProxyError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Chunk govdesi sonrasinda CRLF bekleniyordu",
                        )));
                    }
                }
                ChunkTrackState::TrailerLineStart => {
                    let b = data[i];
                    i += 1;
                    if b == b'\r' {
                        self.state = ChunkTrackState::TrailerEndLf;
                    } else if b == b'\n' {
                        self.state = ChunkTrackState::Done;
                        return Ok((i, true));
                    } else {
                        self.state = ChunkTrackState::TrailerLineRest;
                    }
                }
                ChunkTrackState::TrailerLineRest => {
                    let b = data[i];
                    i += 1;
                    if b == b'\n' {
                        self.state = ChunkTrackState::TrailerLineStart;
                    }
                }
                ChunkTrackState::TrailerEndLf => {
                    let b = data[i];
                    i += 1;
                    if b == b'\n' {
                        self.state = ChunkTrackState::Done;
                        return Ok((i, true));
                    } else {
                        return Err(ProxyError::Io(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Chunked trailer bitiminde LF bekleniyordu",
                        )));
                    }
                }
            }
        }
        Ok((i, matches!(self.state, ChunkTrackState::Done)))
    }
}

async fn write_and_flush_client<W>(
    client_writer: &mut W,
    data: &[u8],
    status: u16,
    body_bytes_sent: usize,
) -> Result<(), StreamForwardError>
where
    W: AsyncWrite + Unpin,
{
    if let Err(e) = client_writer.write_all(data).await {
        return Err(StreamForwardError {
            error: ProxyError::Io(e),
            headers_sent: true,
            status: Some(status),
            body_bytes_sent,
        });
    }
    if let Err(e) = client_writer.flush().await {
        return Err(StreamForwardError {
            error: ProxyError::Io(e),
            headers_sent: true,
            status: Some(status),
            body_bytes_sent,
        });
    }
    Ok(())
}

async fn read_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
    timeout_msg: &'static str,
) -> Result<usize, ProxyError> {
    let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
    if rem.is_zero() {
        return Err(ProxyError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            timeout_msg,
        )));
    }
    tokio::time::timeout(rem, stream.read(buf))
        .await
        .map_err(|_| ProxyError::Io(io::Error::new(io::ErrorKind::TimedOut, timeout_msg)))?
        .map_err(ProxyError::Io)
}

async fn read_with_idle_timeout(
    stream: &mut TcpStream,
    buf: &mut [u8],
    idle_timeout: Duration,
    timeout_msg: &'static str,
) -> Result<usize, ProxyError> {
    tokio::time::timeout(idle_timeout, stream.read(buf))
        .await
        .map_err(|_| ProxyError::Io(io::Error::new(io::ErrorKind::TimedOut, timeout_msg)))?
        .map_err(ProxyError::Io)
}

async fn finish_buffered_body(
    stream: &mut TcpStream,
    mut response: Vec<u8>,
    header_end: usize,
    head_info: &ResponseHeadInfo,
    read_timeout: Duration,
) -> Result<(Vec<u8>, bool), ProxyError> {
    let mut buf = [0u8; STREAM_BUF_BYTES];
    let mut can_keep_alive = head_info.header_allows_keep_alive;
    match head_info.framing {
        ResponseFraming::NoBody => {
            if response.len() > header_end {
                can_keep_alive = false;
            }
            response.truncate(header_end);
        }
        ResponseFraming::ContentLength(len) => {
            let expected_total = header_end.saturating_add(len);
            while response.len() < expected_total {
                let n = read_with_idle_timeout(
                    stream,
                    &mut buf,
                    read_timeout,
                    "Arka uc govde okuma zaman asimina ugradi",
                )
                .await?;
                if n == 0 {
                    return Err(ProxyError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Content-Length tamamlanmadan baglanti kapandi",
                    )));
                }
                response.extend_from_slice(&buf[..n]);
            }
            if response.len() > expected_total {
                can_keep_alive = false;
            }
            response.truncate(expected_total);
        }
        ResponseFraming::Chunked => loop {
            if let Some(chunk_end) = is_chunked_complete(&response[header_end..])? {
                let expected_total = header_end + chunk_end;
                if response.len() > expected_total {
                    can_keep_alive = false;
                }
                response.truncate(expected_total);
                break;
            }
            let n = read_with_idle_timeout(
                stream,
                &mut buf,
                read_timeout,
                "Arka uc chunked yanit zaman asimina ugradi",
            )
            .await?;
            if n == 0 {
                return Err(ProxyError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Chunked yanit bitmeden baglanti kapandi",
                )));
            }
            response.extend_from_slice(&buf[..n]);
        },
        ResponseFraming::UntilEof => {
            can_keep_alive = false;
            loop {
                let n = read_with_idle_timeout(
                    stream,
                    &mut buf,
                    read_timeout,
                    "Arka uc EOF yanit zaman asimina ugradi",
                )
                .await?;
                if n == 0 {
                    break;
                }
                response.extend_from_slice(&buf[..n]);
            }
        }
    }
    Ok((response, can_keep_alive))
}

async fn read_http_response(
    stream: &mut TcpStream,
    is_head_request: bool,
    read_timeout: Duration,
) -> Result<Vec<u8>, ProxyError> {
    Ok(
        read_http_response_with_reusability(stream, is_head_request, read_timeout)
            .await?
            .0,
    )
}

async fn read_http_response_with_reusability(
    stream: &mut TcpStream,
    is_head_request: bool,
    read_timeout: Duration,
) -> Result<(Vec<u8>, bool), ProxyError> {
    let mut response = Vec::with_capacity(4096);
    let mut buf = [0u8; 8192];
    let deadline = tokio::time::Instant::now() + read_timeout;

    // 1. Önce HTTP yanıt başlıklarının sonunu oku (100 Continue ara yanıtlarını atlayarak)
    let (header_end, head_info) = loop {
        if let Some(end) = find_header_end(&response) {
            let info = inspect_response_framing(&response[..end], is_head_request)?;
            if info.status == 100 && response.len() >= end {
                response.drain(..end);
                continue;
            }
            break (end, info);
        }

        if response.len() >= MAX_RESPONSE_HEADER_BYTES {
            return Err(ProxyError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "Arka uc yanit basligi maksimum boyutu asti",
            )));
        }

        let n = read_with_deadline(
            stream,
            &mut buf,
            deadline,
            "Arka uc yanit okuma zaman asimina ugradi",
        )
        .await?;

        if n == 0 {
            if response.is_empty() {
                return Err(ProxyError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Arka uc yanit gondermeden baglantiyi kapatti",
                )));
            }
            return Ok((response, false));
        }
        response.extend_from_slice(&buf[..n]);
    };

    // 2. Çerçevelemeye göre gövdenin tamamını oku
    let mut can_keep_alive = head_info.header_allows_keep_alive;
    match head_info.framing {
        ResponseFraming::NoBody => {
            if response.len() > header_end {
                can_keep_alive = false;
            }
            response.truncate(header_end);
        }
        ResponseFraming::ContentLength(len) => {
            let expected_total = header_end.saturating_add(len);
            while response.len() < expected_total {
                let n = read_with_deadline(
                    stream,
                    &mut buf,
                    deadline,
                    "Arka uc govde okuma zaman asimina ugradi",
                )
                .await?;
                if n == 0 {
                    return Err(ProxyError::Io(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Content-Length tamamlanmadan baglanti kapandi",
                    )));
                }
                response.extend_from_slice(&buf[..n]);
            }
            if response.len() > expected_total {
                can_keep_alive = false;
            }
            response.truncate(expected_total);
        }
        ResponseFraming::Chunked => loop {
            if let Some(chunk_end) = is_chunked_complete(&response[header_end..])? {
                let expected_total = header_end + chunk_end;
                if response.len() > expected_total {
                    can_keep_alive = false;
                }
                response.truncate(expected_total);
                break;
            }
            let n = read_with_deadline(
                stream,
                &mut buf,
                deadline,
                "Arka uc chunked yanit zaman asimina ugradi",
            )
            .await?;
            if n == 0 {
                return Err(ProxyError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Chunked yanit bitmeden baglanti kapandi",
                )));
            }
            response.extend_from_slice(&buf[..n]);
        },
        ResponseFraming::UntilEof => {
            can_keep_alive = false;
            loop {
                let n = read_with_deadline(
                    stream,
                    &mut buf,
                    deadline,
                    "Arka uc EOF yanit zaman asimina ugradi",
                )
                .await?;
                if n == 0 {
                    break;
                }
                response.extend_from_slice(&buf[..n]);
            }
        }
    }

    Ok((response, can_keep_alive))
}

/// İstemci akışını (düz ya da TLS) arka uca bağlar: yeniden yazılmış başı + önceden okunmuş gövde
/// baytlarını gönderir, sonra iki yönlü kopyalar (büyük gövde, akış ve WebSocket dahil).
pub async fn proxy_connection<C>(
    client: &mut C,
    head: &[u8],
    extra: &[u8],
    upstream: &str,
    client_ip: IpAddr,
    https: bool,
) -> Result<(), ProxyError>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let new_head = rewrite_request_head(head, client_ip, https).ok_or(ProxyError::BadRequest)?;
    let mut up =
        match tokio::time::timeout(DEFAULT_CONNECT_TIMEOUT, TcpStream::connect(upstream)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(ProxyError::Connect(e.to_string())),
            Err(_) => return Err(ProxyError::Connect("zaman asimi".into())),
        };
    let _ = up.set_nodelay(true);
    up.write_all(&new_head).await.map_err(ProxyError::Io)?;
    if !extra.is_empty() {
        up.write_all(extra).await.map_err(ProxyError::Io)?;
    }
    // Yanıt (arka uç -> istemci) bitince bağlantı biter; istemci yarım kapatmadıysa beklenmez.
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = up.into_split();
    let c2u = async {
        let _ = tokio::io::copy(&mut cr, &mut uw).await;
        if let Err(e) = uw.shutdown().await {
            tracing::trace!(error = %e, "proxy_connection upstream shutdown");
        }
    };
    let u2c = async {
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
        if let Err(e) = cw.shutdown().await {
            tracing::trace!(error = %e, "proxy_connection client shutdown");
        }
    };
    tokio::pin!(c2u, u2c);
    tokio::select! {
        _ = &mut u2c => {}
        _ = &mut c2u => { u2c.await; }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_node_reverse_proxy_forwarding() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let n = socket.read(&mut buf).await.unwrap();
                let req_str = String::from_utf8_lossy(&buf[..n]);
                assert!(req_str.contains("GET /api/users HTTP/1.1\r\n"));
                assert!(req_str.contains("X-Forwarded-For: 127.0.0.1\r\n"));
                assert!(req_str.contains("X-Real-IP: 127.0.0.1\r\n"));

                let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"node\":\"active\"}";
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });

        let proxy = ReverseProxy::new(&local_addr.to_string());
        let request = b"GET /api/users HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let client_ip = "127.0.0.1:54321".parse().unwrap();

        let resp = proxy.forward_http(request, client_ip).await.unwrap();
        let resp_str = String::from_utf8_lossy(&resp);

        assert!(resp_str.contains("200 OK"));
        assert!(resp_str.contains("{\"node\":\"active\"}"));
    }

    #[tokio::test]
    async fn forward_http_reads_fragmented_content_length_and_appends_client_ip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap();
            let req_str = String::from_utf8_lossy(&buf[..n]);
            assert!(
                req_str.contains("X-Forwarded-For: 1.2.3.4, 203.0.113.42\r\n"),
                "gercek baslik: {req_str}"
            );
            assert!(req_str.contains("X-Real-IP: 203.0.113.42\r\n"));

            // Parçalı TCP gönderimi simülasyonu (küçük parça + gecikmeli ikinci parça)
            let part1 =
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello";
            socket.write_all(part1).await.unwrap();
            socket.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(25)).await;
            socket.write_all(b" world").await.unwrap();
            socket.flush().await.unwrap();
            // Sunucu keep-alive açık bıraksa dahi Content-Length tamamlanınca istemci bitirmeli
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let proxy = ReverseProxy::new(&local_addr.to_string());
        let request =
            b"GET /frag HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n";
        let client_ip: SocketAddr = "203.0.113.42:40000".parse().unwrap();

        let resp = proxy.forward_http(request, client_ip).await.unwrap();
        let resp_str = String::from_utf8(resp).unwrap();
        assert!(
            resp_str.ends_with("\r\n\r\nhello world"),
            "yanit: {resp_str}"
        );
    }

    #[tokio::test]
    async fn forward_http_reads_fragmented_chunked_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await.unwrap();

            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket.write_all(b"alpha\r\n4\r\nbeta\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            socket.write_all(b"0\r\n\r\n").await.unwrap();
        });

        let proxy = ReverseProxy::new(&local_addr.to_string());
        let request = b"GET /chunked HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let client_ip: SocketAddr = "198.51.100.7:12345".parse().unwrap();

        let resp = proxy.forward_http(request, client_ip).await.unwrap();
        let resp_str = String::from_utf8(resp).unwrap();
        assert!(resp_str.contains("5\r\nalpha\r\n4\r\nbeta\r\n0\r\n\r\n"));
    }

    #[test]
    fn head_rewrite_appends_xff_and_sets_real_ip_proto_and_host_with_crlf() {
        let head = concat!(
            "GET /x?y=1 HTTP/1.1\r\n",
            "Host: p.test\r\n",
            "X-Forwarded-For: 6.6.6.6\r\n",
            "X-Forwarded-Host: evil.test\r\n",
            "X-Forwarded-Proto: http\r\n",
            "X-Real-IP: 6.6.6.6\r\n",
            "Connection: keep-alive\r\n",
            "Cookie: a=b\r\n",
            "\r\n",
        )
        .as_bytes();
        let out = rewrite_request_head(head, "9.9.9.9".parse().unwrap(), true).unwrap();
        let t = String::from_utf8(out).unwrap();
        assert!(t.starts_with("GET /x?y=1 HTTP/1.1\r\n"));
        assert!(!t.contains("evil.test"));
        assert!(t.contains("Host: p.test\r\n"));
        assert!(t.contains("X-Forwarded-Host: p.test\r\n"));
        assert!(t.contains("X-Forwarded-For: 6.6.6.6, 9.9.9.9\r\n"), "{t}");
        assert!(t.contains("X-Real-IP: 9.9.9.9\r\n"));
        assert!(t.contains("X-Forwarded-Proto: https\r\n"));
        assert!(t.contains("Cookie: a=b\r\n"));
        assert!(t.contains("Connection: close\r\n"));
        assert!(!t.contains("keep-alive"));
        assert!(t.ends_with("\r\n\r\n"));
        // Hiçbir çıplak LF olmamalı
        assert!(t.split("\r\n").all(|line| !line.contains('\n')));
    }

    #[test]
    fn head_rewrite_merges_multiple_xff_headers_and_preserves_order() {
        let head = concat!(
            "GET /chain HTTP/1.1\r\n",
            "Host: app.example\r\n",
            "X-Forwarded-For: 10.0.0.1, 10.0.0.2\r\n",
            "X-Forwarded-For: 172.16.0.5\r\n",
            "\r\n",
        )
        .as_bytes();
        let out = rewrite_request_head(head, "198.51.100.8".parse().unwrap(), true).unwrap();
        let t = String::from_utf8(out).unwrap();
        assert!(
            t.contains("X-Forwarded-For: 10.0.0.1, 10.0.0.2, 172.16.0.5, 198.51.100.8\r\n"),
            "{t}"
        );
        assert!(t.contains("X-Forwarded-Proto: https\r\n"));
        assert!(t.contains("X-Forwarded-Host: app.example\r\n"));
    }

    #[test]
    fn head_rewrite_can_override_host_when_preserve_host_disabled() {
        let head = b"GET /app HTTP/1.1\r\nHost: public.example.com\r\n\r\n";
        let opts = ProxyRewriteOptions {
            preserve_host: false,
            upstream_host: Some("127.0.0.1:3000"),
        };
        let out =
            rewrite_request_head_with_options(head, "10.0.0.5".parse().unwrap(), false, &opts)
                .unwrap();
        let t = String::from_utf8(out).unwrap();
        assert!(t.contains("Host: 127.0.0.1:3000\r\n"));
        assert!(t.contains("X-Forwarded-Host: public.example.com\r\n"));
    }

    #[test]
    fn head_rewrite_keeps_websocket_upgrade() {
        let head = concat!(
            "GET /ws HTTP/1.1\r\n",
            "Host: p.test\r\n",
            "Upgrade: websocket\r\n",
            "Connection: Upgrade\r\n",
            "\r\n",
        )
        .as_bytes();
        let t = String::from_utf8(
            rewrite_request_head(head, "1.1.1.1".parse().unwrap(), false).unwrap(),
        )
        .unwrap();
        assert!(t.contains("Connection: Upgrade\r\n"));
        assert!(!t.contains("Connection: close"));
        assert!(t.contains("X-Forwarded-Proto: http\r\n"));
    }

    #[tokio::test]
    async fn proxy_connection_streams_body_and_response_and_websocket_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let mut got = Vec::new();
            while !(got.windows(4).any(|w| w == b"\r\n\r\n") && got.len() > 5000) {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            let txt = String::from_utf8_lossy(&got).into_owned();
            assert!(txt.contains("X-Forwarded-For: 7.7.7.7\r\n"));
            let body = format!("bodylen={}", got.len() - txt.find("\r\n\r\n").unwrap() - 4);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            s.write_all(resp.as_bytes()).await.unwrap();
        });
        let (mut client, mut server_side) = tokio::io::duplex(64 * 1024);
        let up = addr.to_string();
        let task = tokio::spawn(async move {
            let head = b"POST /u HTTP/1.1\r\nHost: p.test\r\nContent-Length: 5000\r\n\r\n";
            let extra = vec![b'x'; 2000];
            proxy_connection(
                &mut server_side,
                head,
                &extra,
                &up,
                "7.7.7.7".parse().unwrap(),
                false,
            )
            .await
            .unwrap();
        });
        client.write_all(&vec![b'y'; 3000]).await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        task.await.unwrap();
        let t = String::from_utf8_lossy(&out);
        assert!(t.starts_with("HTTP/1.1 200 OK"), "{t}");
        assert!(t.ends_with("bodylen=5000"), "{t}");
    }

    #[tokio::test]
    async fn forward_http_times_out_when_upstream_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        });

        let proxy = ReverseProxy::new(&local_addr.to_string())
            .with_timeouts(Duration::from_secs(1), Duration::from_millis(40));
        let request = b"GET /slow HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let client_ip: SocketAddr = "127.0.0.1:50000".parse().unwrap();

        let err = proxy.forward_http(request, client_ip).await.unwrap_err();
        assert!(err.to_string().contains("zaman asimi"));
    }

    #[tokio::test]
    async fn proxy_connection_supports_websocket_upgrade_duplex() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("Upgrade: websocket\r\n"));
            assert!(req.contains("Connection: Upgrade\r\n"));

            s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();

            let mut msg = [0u8; 4];
            s.read_exact(&mut msg).await.unwrap();
            assert_eq!(&msg, b"ping");
            s.write_all(b"pong").await.unwrap();
        });

        let (mut client, mut server_side) = tokio::io::duplex(4096);
        let up = addr.to_string();
        let task = tokio::spawn(async move {
            let head = b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
            proxy_connection(
                &mut server_side,
                head,
                &[],
                &up,
                "8.8.8.8".parse().unwrap(),
                true,
            )
            .await
            .unwrap();
        });

        let mut resp_buf = [0u8; 128];
        let n = client.read(&mut resp_buf).await.unwrap();
        assert!(String::from_utf8_lossy(&resp_buf[..n]).starts_with("HTTP/1.1 101"));

        client.write_all(b"ping").await.unwrap();
        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
        drop(client);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_connection_reports_unreachable_upstream() {
        let (_c, mut s) = tokio::io::duplex(1024);
        let head = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let r = proxy_connection(
            &mut s,
            head,
            &[],
            "127.0.0.1:1",
            "1.1.1.1".parse().unwrap(),
            false,
        )
        .await;
        assert!(matches!(r, Err(ProxyError::Connect(_))));
    }

    async fn read_test_request(socket: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut tmp).await.unwrap();
            assert!(n > 0, "istemci istek basligini tamamlamadan kapatti");
            buf.extend_from_slice(&tmp[..n]);
        }
        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn test_forward_http_on_stream_keepalive_reuse() {
        // 1. Keep-alive sunucu: aynı TCP bağlantısı üzerinden ardışık 2 HTTP isteğini yanıtlar
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let keepalive_srv = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            let req1 = read_test_request(&mut socket).await;
            assert!(req1.contains("GET /bir HTTP/1.1\r\n"));
            assert!(req1.contains("Connection: keep-alive\r\n"));
            assert!(!req1.contains("Connection: close"));

            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nbirinc")
                .await
                .unwrap();
            socket.flush().await.unwrap();

            let req2 = read_test_request(&mut socket).await;
            assert!(req2.contains("GET /iki HTTP/1.1\r\n"));
            assert!(req2.contains("Connection: keep-alive\r\n"));

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\niki\r\n0\r\n\r\n",
                )
                .await
                .unwrap();
            socket.flush().await.unwrap();
        });

        let proxy = ReverseProxy::new(&addr.to_string());
        let client_ip: SocketAddr = "198.51.100.10:55555".parse().unwrap();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        let (resp1, can_reuse1) = proxy
            .forward_http_on_stream(
                &mut stream,
                b"GET /bir HTTP/1.1\r\nHost: pool.test\r\nConnection: close\r\n\r\n",
                client_ip,
            )
            .await
            .unwrap();
        assert!(can_reuse1);
        let resp1_str = String::from_utf8(resp1).unwrap();
        assert!(resp1_str.ends_with("\r\n\r\nbirinc"));

        let (resp2, can_reuse2) = proxy
            .forward_http_on_stream(
                &mut stream,
                b"GET /iki HTTP/1.1\r\nHost: pool.test\r\n\r\n",
                client_ip,
            )
            .await
            .unwrap();
        assert!(can_reuse2);
        let resp2_str = String::from_utf8(resp2).unwrap();
        assert!(resp2_str.contains("3\r\niki\r\n0\r\n\r\n"));

        drop(stream);
        keepalive_srv.await.unwrap();

        // 2. Connection: close dönen sunucu: soket yeniden kullanılabilir olmamalı
        let close_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let close_addr = close_listener.local_addr().unwrap();

        let close_srv = tokio::spawn(async move {
            let (mut socket, _) = close_listener.accept().await.unwrap();
            let req = read_test_request(&mut socket).await;
            assert!(req.contains("Connection: keep-alive\r\n"));

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\nkapal",
                )
                .await
                .unwrap();
            socket.flush().await.unwrap();
        });

        let close_proxy = ReverseProxy::new(&close_addr.to_string());
        let mut close_stream = TcpStream::connect(close_addr).await.unwrap();
        let (resp_close, can_reuse_close) = close_proxy
            .forward_http_on_stream(
                &mut close_stream,
                b"GET /kapat HTTP/1.1\r\nHost: pool.test\r\n\r\n",
                client_ip,
            )
            .await
            .unwrap();
        assert!(!can_reuse_close);
        assert!(String::from_utf8(resp_close).unwrap().ends_with("kapal"));

        close_srv.await.unwrap();
    }

    #[tokio::test]
    async fn test_forward_http_on_stream_framing_and_http10_reusability() {
        type ReusabilityCase<'a> = (&'a [u8], &'a [u8], bool, &'a str);
        let cases: &[ReusabilityCase<'_>] = &[
            (
                b"GET /eof HTTP/1.1\r\nHost: h.test\r\n\r\n",
                b"HTTP/1.1 200 OK\r\n\r\neof-govde",
                false,
                "UntilEof yanit tekrar kullanilmamali",
            ),
            (
                b"GET /h10-ka HTTP/1.0\r\nHost: h.test\r\n\r\n",
                b"HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 2\r\n\r\nok",
                true,
                "HTTP/1.0 acik Connection: keep-alive ile tekrar kullanilabilmeli",
            ),
            (
                b"GET /h10-def HTTP/1.0\r\nHost: h.test\r\n\r\n",
                b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
                false,
                "HTTP/1.0 Connection basligi yoksa tekrar kullanilmamali",
            ),
            (
                b"GET /no-content HTTP/1.1\r\nHost: h.test\r\n\r\n",
                b"HTTP/1.1 204 No Content\r\n\r\n",
                true,
                "HTTP/1.1 204 No Content tekrar kullanilabilmeli",
            ),
            (
                b"HEAD /head-close HTTP/1.1\r\nHost: h.test\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 10\r\n\r\n",
                false,
                "HEAD yanitinda Connection: close varsa tekrar kullanilmamali",
            ),
        ];

        for &(req_bytes, resp_bytes, expected_reuse, msg) in cases {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let raw_resp = resp_bytes.to_vec();

            let srv = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let _ = read_test_request(&mut socket).await;
                socket.write_all(&raw_resp).await.unwrap();
                socket.flush().await.unwrap();
                drop(socket);
            });

            let proxy = ReverseProxy::new(&addr.to_string());
            let client_ip: SocketAddr = "127.0.0.1:40001".parse().unwrap();
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let (_resp, can_reuse) = proxy
                .forward_http_on_stream(&mut stream, req_bytes, client_ip)
                .await
                .unwrap();
            assert_eq!(can_reuse, expected_reuse, "{msg}");
            srv.await.unwrap();
        }
    }

    #[test]
    fn chunked_tracker_handles_byte_by_byte_and_trailers() {
        let payload = b"5;ext=1\r\nhello\r\n4\r\n\r\nab\r\n0\r\nX-Checksum: ok\r\n\r\nTRAILING";
        let mut tracker = ChunkedStreamTracker::new();
        let mut total_consumed = 0usize;
        let mut finished = false;
        for byte in payload.iter() {
            let (c, done) = tracker.feed(std::slice::from_ref(byte)).unwrap();
            total_consumed += c;
            if done {
                finished = true;
                break;
            }
        }
        assert!(finished);
        assert_eq!(
            &payload[..total_consumed],
            b"5;ext=1\r\nhello\r\n4\r\n\r\nab\r\n0\r\nX-Checksum: ok\r\n\r\n"
        );
    }

    #[tokio::test]
    async fn streaming_sse_delivers_first_heartbeat_immediately_before_backend_finishes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client_got_first = std::sync::Arc::new(tokio::sync::Notify::new());
        let srv_wait = std::sync::Arc::clone(&client_got_first);

        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let req = read_test_request(&mut sock).await;
            assert!(req.contains("X-Forwarded-For: 203.0.113.1, 10.0.0.9\r\n"));
            assert!(req.contains("X-Forwarded-Proto: https\r\n"));

            let part1 = concat!(
                "HTTP/1.1 200 OK\r\n",
                "Content-Type: text/event-stream; charset=utf-8\r\n",
                "Cache-Control: no-cache\r\n",
                "Transfer-Encoding: chunked\r\n\r\n",
                "d\r\n: heartbeat\n\n\r\n"
            );
            sock.write_all(part1.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();

            // İstemci 1. parçayı okuyup onaylayana dek akışı açık tut (tamponsuz akış kanıtı!)
            srv_wait.notified().await;

            let part2 = "e\r\ndata: bitis\n\n\r\n0\r\n\r\n";
            sock.write_all(part2.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        });

        let (mut client_read, mut client_write) = tokio::io::duplex(8192);
        let proxy = ReverseProxy::new(&addr.to_string())
            .with_https(true)
            .with_resp_buffer(false);
        let mut upstream_stream = TcpStream::connect(addr).await.unwrap();

        let forward_task = tokio::spawn(async move {
            proxy
                .forward_streaming_on_stream(
                    &mut upstream_stream,
                    &mut client_write,
                    b"GET /events HTTP/1.1\r\nHost: panel.test\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n",
                    b"",
                    "10.0.0.9:5000".parse().unwrap(),
                    true,
                )
                .await
                .unwrap()
        });

        // Arka uç henüz part2 ve 0\r\n\r\n göndermediği halde istemci : heartbeat\n\n parçasını almalı!
        let mut received = Vec::new();
        let mut tmp = [0u8; 512];
        while !String::from_utf8_lossy(&received).contains(": heartbeat") {
            let n = tokio::time::timeout(Duration::from_secs(1), client_read.read(&mut tmp))
                .await
                .expect("SSE ilk parcasi 1 sn icinde ulasmali")
                .unwrap();
            assert!(n > 0);
            received.extend_from_slice(&tmp[..n]);
        }

        // İlk parça ulaştı -> arka uca 2. parçayı göndermesi için işaret ver
        client_got_first.notify_one();

        let mut rest = Vec::new();
        while !String::from_utf8_lossy(&rest).contains("0\r\n\r\n") {
            let n = tokio::time::timeout(Duration::from_secs(1), client_read.read(&mut tmp))
                .await
                .expect("SSE ikinci parcasi da gelmeli")
                .unwrap();
            if n == 0 {
                break;
            }
            rest.extend_from_slice(&tmp[..n]);
        }
        let rest_str = String::from_utf8_lossy(&rest);
        assert!(rest_str.contains("data: bitis"), "{rest_str}");

        let res = forward_task.await.unwrap();
        assert_eq!(res.status, 200);
        assert!(res.is_sse);
        assert!(res.upstream_reusable);
        assert!(res.client_keep_alive);

        drop(client_read);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn tunnel_websocket_with_head_respects_xff_append_and_echoes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let req = read_test_request(&mut s).await;
            assert!(req.contains("Upgrade: websocket\r\n"), "{req}");
            assert!(req.contains("Connection: Upgrade\r\n"), "{req}");
            assert!(
                req.contains("X-Forwarded-For: 192.0.2.5, 198.51.100.2\r\n"),
                "{req}"
            );
            assert!(req.contains("X-Forwarded-Proto: https\r\n"), "{req}");
            assert!(
                req.contains("X-Forwarded-Host: ws.zpanel.test\r\n"),
                "{req}"
            );

            s.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();
            s.flush().await.unwrap();

            let mut echo_buf = [0u8; 10];
            s.read_exact(&mut echo_buf).await.unwrap();
            s.write_all(&echo_buf).await.unwrap();
            s.flush().await.unwrap();
        });

        let (mut client, mut server_side) = tokio::io::duplex(4096);
        let proxy = ReverseProxy::new(&addr.to_string()).with_https(true);

        let ws_task = tokio::spawn(async move {
            let head = concat!(
                "GET /ws/term HTTP/1.1\r\n",
                "Host: ws.zpanel.test\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
                "Sec-WebSocket-Version: 13\r\n",
                "X-Forwarded-For: 192.0.2.5\r\n\r\n",
            )
            .as_bytes()
            .to_vec();
            proxy
                .tunnel_websocket_request(
                    &mut server_side,
                    &head,
                    &[],
                    "198.51.100.2:443".parse().unwrap(),
                )
                .await
                .unwrap()
        });

        let mut resp = [0u8; 256];
        let n = client.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).starts_with("HTTP/1.1 101"));

        client.write_all(b"merhaba-ws").await.unwrap();
        let mut back = [0u8; 10];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"merhaba-ws");
        drop(client);

        let (status, _) = ws_task.await.unwrap();
        assert_eq!(status, 101);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn streaming_init_timeout_aborts_stalled_upstream_before_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let close_gate = std::sync::Arc::new(tokio::sync::Notify::new());
        let srv_gate = std::sync::Arc::clone(&close_gate);

        let srv = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            srv_gate.notified().await;
        });

        let (_cr, mut cw) = tokio::io::duplex(4096);
        let proxy =
            ReverseProxy::new(&addr.to_string()).with_init_timeout(Duration::from_millis(50));
        let mut upstream = TcpStream::connect(addr).await.unwrap();

        let err = proxy
            .forward_streaming_on_stream(
                &mut upstream,
                &mut cw,
                b"GET /stall HTTP/1.1\r\nHost: slow.test\r\n\r\n",
                b"",
                "127.0.0.1:1000".parse().unwrap(),
                true,
            )
            .await
            .unwrap_err();
        assert!(!err.headers_sent);
        assert!(err.to_string().contains("zaman asimina ugradi"), "{err}");

        close_gate.notify_one();
        srv.await.unwrap();
    }
}
