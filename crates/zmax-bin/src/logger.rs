//! # ZMax Asenkron Toplu Günlük Motoru (`AsyncLogManager`)
//! İstek yolunu (hot-path) disk G/Ç ile bloklamadan `tokio::sync::mpsc` kanalı üzerinden
//! NCSA Combined ve JSON erişim/hata günlüklerini toplu tamponlayarak yazar, döndürür (`.1`)
//! ve `reopen_all` / `read_tail_lines` işlemlerini yönetir.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufWriter};
use tokio::sync::{mpsc, oneshot};

const LOG_CHANNEL_CAPACITY: usize = 16_384;
const MIN_FLUSH_MS: u64 = 50;
const TAIL_CHUNK_SIZE: usize = 64 * 1024;
const MAX_TAIL_SCAN_BYTES: u64 = 32 * 1024 * 1024;

/// Tek bir HTTP/HTTPS isteği için erişim günlüğü kaydı.
#[derive(Debug, Clone)]
pub struct AccessLogEntry {
    pub timestamp: SystemTime,
    pub client_ip: String,
    pub method: String,
    pub target: String,
    pub protocol: String,
    pub status: u16,
    pub bytes_sent: usize,
    pub referer: String,
    pub user_agent: String,
    pub request_id: String,
    pub duration_ms: f64,
    pub domain: String,
    pub target_path: Option<PathBuf>,
    pub json_format: bool,
    pub also_write_global: bool,
    pub max_size_bytes: u64,
}

impl Default for AccessLogEntry {
    fn default() -> Self {
        Self {
            timestamp: SystemTime::now(),
            client_ip: "-".to_string(),
            method: "GET".to_string(),
            target: "/".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes_sent: 0,
            referer: String::new(),
            user_agent: String::new(),
            request_id: String::new(),
            duration_ms: 0.0,
            domain: String::new(),
            target_path: None,
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        }
    }
}

enum LogCommand {
    Access(AccessLogEntry),
    Error {
        path_override: Option<PathBuf>,
        message: String,
        max_size_bytes: u64,
        also_global: bool,
    },
    Flush(oneshot::Sender<()>),
    ReopenAll(oneshot::Sender<()>),
    UpdateGlobalPaths {
        access_log: PathBuf,
        error_log: PathBuf,
        ack: oneshot::Sender<()>,
    },
}

struct OpenLogFile {
    writer: BufWriter<tokio::fs::File>,
    current_size: u64,
    pending_bytes: usize,
}

struct LogWorkerState {
    base_dir: PathBuf,
    global_access_log: PathBuf,
    global_error_log: PathBuf,
    writers: HashMap<PathBuf, OpenLogFile>,
    total_pending_bytes: usize,
    batch_threshold_bytes: usize,
    writer_capacity: usize,
}

impl LogWorkerState {
    fn resolve(&self, path: &Path) -> PathBuf {
        resolve_log_path(&self.base_dir, path)
    }

    async fn flush_all(&mut self) {
        for open in self.writers.values_mut() {
            if open.pending_bytes > 0 {
                let _ = open.writer.flush().await;
                open.pending_bytes = 0;
            }
        }
        self.total_pending_bytes = 0;
    }

    async fn close_all(&mut self) {
        for (_, mut open) in self.writers.drain() {
            let _ = open.writer.flush().await;
            let _ = open.writer.shutdown().await;
        }
        self.total_pending_bytes = 0;
    }

    async fn close_path(&mut self, path: &Path) {
        if let Some(mut open) = self.writers.remove(path) {
            self.total_pending_bytes = self.total_pending_bytes.saturating_sub(open.pending_bytes);
            let _ = open.writer.flush().await;
            let _ = open.writer.shutdown().await;
        }
    }

    async fn open_writer(&mut self, path: &Path) -> bool {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
        }
        let Ok(file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
        else {
            return false;
        };
        let initial_size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
        let writer = BufWriter::with_capacity(self.writer_capacity, file);
        self.writers.insert(
            path.to_path_buf(),
            OpenLogFile {
                writer,
                current_size: initial_size,
                pending_bytes: 0,
            },
        );
        true
    }

    async fn ensure_ready_and_write(&mut self, path: &Path, line: &str, max_size_bytes: u64) {
        if path.as_os_str().is_empty() {
            return;
        }
        let line_len = line.len() as u64;

        if !self.writers.contains_key(path) {
            if max_size_bytes > 0 {
                if let Ok(meta) = tokio::fs::metadata(path).await {
                    let cur = meta.len();
                    if meta.is_file()
                        && (cur >= max_size_bytes
                            || (cur > 0 && cur.saturating_add(line_len) > max_size_bytes))
                    {
                        rotate_log_file(path).await;
                    }
                }
            }
            if !self.open_writer(path).await {
                return;
            }
        } else if max_size_bytes > 0 {
            let need_rotate = self.writers.get(path).is_some_and(|open| {
                open.current_size >= max_size_bytes
                    || (open.current_size > 0
                        && open.current_size.saturating_add(line_len) > max_size_bytes)
            });
            if need_rotate {
                self.close_path(path).await;
                rotate_log_file(path).await;
                if !self.open_writer(path).await {
                    return;
                }
            }
        }

        let Some(open) = self.writers.get_mut(path) else {
            return;
        };
        if open.writer.write_all(line.as_bytes()).await.is_err() {
            self.close_path(path).await;
            return;
        }
        open.current_size = open.current_size.saturating_add(line_len);
        open.pending_bytes = open.pending_bytes.saturating_add(line.len());
        self.total_pending_bytes = self.total_pending_bytes.saturating_add(line.len());

        if self.total_pending_bytes >= self.batch_threshold_bytes {
            self.flush_all().await;
        }
    }

    async fn handle_command(&mut self, cmd: LogCommand) {
        match cmd {
            LogCommand::Access(entry) => {
                let line = if entry.json_format {
                    format_json_line(&entry)
                } else {
                    format_combined_line(&entry)
                };
                let max_bytes = entry.max_size_bytes;
                let custom = entry
                    .target_path
                    .as_deref()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| self.resolve(p));

                match custom {
                    Some(target) => {
                        self.ensure_ready_and_write(&target, &line, max_bytes).await;
                        if entry.also_write_global && target != self.global_access_log {
                            let global = self.global_access_log.clone();
                            self.ensure_ready_and_write(&global, &line, max_bytes).await;
                        }
                    }
                    None => {
                        let global = self.global_access_log.clone();
                        self.ensure_ready_and_write(&global, &line, max_bytes).await;
                    }
                }
            }
            LogCommand::Error {
                path_override,
                message,
                max_size_bytes,
                also_global,
            } => {
                let mut line = sanitize_log_line(&message);
                line.push('\n');
                let custom = path_override
                    .as_deref()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| self.resolve(p));

                match custom {
                    Some(target) => {
                        self.ensure_ready_and_write(&target, &line, max_size_bytes)
                            .await;
                        if also_global && target != self.global_error_log {
                            let global = self.global_error_log.clone();
                            self.ensure_ready_and_write(&global, &line, max_size_bytes)
                                .await;
                        }
                    }
                    None => {
                        let global = self.global_error_log.clone();
                        self.ensure_ready_and_write(&global, &line, max_size_bytes)
                            .await;
                    }
                }
            }
            LogCommand::Flush(ack) => {
                self.flush_all().await;
                let _ = ack.send(());
            }
            LogCommand::ReopenAll(ack) => {
                self.close_all().await;
                let _ = ack.send(());
            }
            LogCommand::UpdateGlobalPaths {
                access_log,
                error_log,
                ack,
            } => {
                let new_access = self.resolve(&access_log);
                let new_error = self.resolve(&error_log);
                if new_access != self.global_access_log {
                    let old_access = self.global_access_log.clone();
                    self.close_path(&old_access).await;
                    self.global_access_log = new_access;
                }
                if new_error != self.global_error_log {
                    let old_error = self.global_error_log.clone();
                    self.close_path(&old_error).await;
                    self.global_error_log = new_error;
                }
                let _ = ack.send(());
            }
        }
    }
}

/// Arka plan görevinde açık dosya tanıtıcılarıyla toplu ve kilitlenmesiz günlük yazımı yönetir.
#[derive(Debug)]
pub struct AsyncLogManager {
    base_dir: PathBuf,
    tx: mpsc::Sender<LogCommand>,
    dropped: Arc<AtomicU64>,
}

impl AsyncLogManager {
    /// Yeni bir asenkron günlük yöneticisi başlatır ve arka plan yazıcı görevini doğurur.
    pub fn new(
        base_dir: PathBuf,
        global_access_log: PathBuf,
        global_error_log: PathBuf,
        batch_flush_ms: u64,
        batch_buffer_kb: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel(LOG_CHANNEL_CAPACITY);
        let dropped = Arc::new(AtomicU64::new(0));

        let resolved_access = resolve_log_path(&base_dir, &global_access_log);
        let resolved_error = resolve_log_path(&base_dir, &global_error_log);
        let batch_threshold_bytes = batch_buffer_kb.saturating_mul(1024);
        let writer_capacity = batch_threshold_bytes.clamp(8 * 1024, 256 * 1024);

        let worker_state = LogWorkerState {
            base_dir: base_dir.clone(),
            global_access_log: resolved_access,
            global_error_log: resolved_error,
            writers: HashMap::new(),
            total_pending_bytes: 0,
            batch_threshold_bytes,
            writer_capacity,
        };
        let flush_ms = batch_flush_ms.max(MIN_FLUSH_MS);

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(run_log_worker(rx, worker_state, flush_ms));
        } else {
            let _ = std::thread::Builder::new()
                .name("zmax-async-logger".to_string())
                .spawn(move || {
                    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    {
                        rt.block_on(run_log_worker(rx, worker_state, flush_ms));
                    }
                });
        }

        Self {
            base_dir,
            tx,
            dropped,
        }
    }

    /// Erişim günlüğü kaydını beklemesiz (`try_send`) olarak kuyruğa ekler; kanal doluysa sayacı artırır.
    pub fn log_access(&self, entry: AccessLogEntry) {
        if self.tx.try_send(LogCommand::Access(entry)).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Hata günlüğü satırını beklemesiz (`try_send`) olarak kuyruğa ekler; kanal doluysa sayacı artırır.
    pub fn log_error(
        &self,
        path_override: Option<PathBuf>,
        message: String,
        max_size_bytes: u64,
        also_global: bool,
    ) {
        if self
            .tx
            .try_send(LogCommand::Error {
                path_override,
                message,
                max_size_bytes,
                also_global,
            })
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Açık tüm `BufWriter`ları diske boşaltır ve kapatır (`SIGUSR1`/logrotate sonrası yeniden açılış için).
    pub async fn reopen_all(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(LogCommand::ReopenAll(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    /// Kuyrukta bekleyen tüm günlükleri diske topluca boşaltır.
    pub async fn flush(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.tx.send(LogCommand::Flush(ack_tx)).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    /// Küresel erişim ve hata günlüğü dosya yollarını sıcak yenilemede günceller.
    pub async fn update_global_paths(&self, access_log: PathBuf, error_log: PathBuf) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .tx
            .send(LogCommand::UpdateGlobalPaths {
                access_log,
                error_log,
                ack: ack_tx,
            })
            .await
            .is_ok()
        {
            let _ = ack_rx.await;
        }
    }

    /// Büyük günlük dosyalarında bellek dostu biçimde sondan en fazla `limit` satır okur.
    pub async fn read_tail_lines(&self, path: &Path, limit: usize) -> std::io::Result<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        self.flush().await;

        let resolved = resolve_log_path(&self.base_dir, path);
        let mut file = tokio::fs::File::open(&resolved).await?;
        let file_len = file.metadata().await?.len();
        if file_len == 0 {
            return Ok(Vec::new());
        }

        let mut pos = file_len;
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut total_read: u64 = 0;
        let mut newline_count: usize = 0;
        let mut skipped_trailing_nl = false;

        while pos > 0 && total_read < MAX_TAIL_SCAN_BYTES && newline_count < limit {
            let start = pos.saturating_sub(TAIL_CHUNK_SIZE as u64);
            let len = (pos - start) as usize;
            file.seek(std::io::SeekFrom::Start(start)).await?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await?;

            let mut scan_end = buf.len();
            if !skipped_trailing_nl {
                skipped_trailing_nl = true;
                if scan_end > 0 && buf[scan_end - 1] == b'\n' {
                    scan_end -= 1;
                }
            }
            for &b in buf[..scan_end].iter().rev() {
                if b == b'\n' {
                    newline_count += 1;
                    if newline_count >= limit {
                        break;
                    }
                }
            }

            chunks.push(buf);
            total_read = total_read.saturating_add(len as u64);
            pos = start;
        }

        chunks.reverse();
        let total_bytes: usize = chunks.iter().map(|c| c.len()).sum();
        let mut merged = Vec::with_capacity(total_bytes);
        for chunk in chunks {
            merged.extend_from_slice(&chunk);
        }

        let slice = if pos > 0 {
            match merged.iter().position(|&b| b == b'\n') {
                Some(idx) => &merged[idx + 1..],
                None => &merged[..],
            }
        } else {
            &merged[..]
        };

        let text = String::from_utf8_lossy(slice);
        let trimmed = text.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Ok(Vec::new());
        }
        let mut lines: Vec<String> = trimmed
            .split('\n')
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect();
        if lines.len() > limit {
            let drop_count = lines.len() - limit;
            lines.drain(..drop_count);
        }
        Ok(lines)
    }

    /// Kanal doluluğu nedeniyle güvenli şekilde düşürülen günlük kaydı sayısını döndürür.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

async fn run_log_worker(
    mut rx: mpsc::Receiver<LogCommand>,
    mut state: LogWorkerState,
    flush_ms: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_millis(flush_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            maybe_cmd = rx.recv() => {
                match maybe_cmd {
                    Some(cmd) => {
                        state.handle_command(cmd).await;
                        for _ in 0..256 {
                            match rx.try_recv() {
                                Ok(next_cmd) => state.handle_command(next_cmd).await,
                                Err(_) => break,
                            }
                        }
                    }
                    None => {
                        state.close_all().await;
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if state.total_pending_bytes > 0 {
                    state.flush_all().await;
                }
            }
        }
    }
}

fn resolve_log_path(base_dir: &Path, raw: &Path) -> PathBuf {
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        base_dir.join(raw)
    }
}

async fn rotate_log_file(log_file: &Path) {
    let mut backup_os = log_file.as_os_str().to_os_string();
    backup_os.push(".1");
    let backup_file = PathBuf::from(backup_os);
    if tokio::fs::rename(log_file, &backup_file).await.is_err() {
        let _ = tokio::fs::remove_file(&backup_file).await;
        let _ = tokio::fs::rename(log_file, &backup_file).await;
    }
}

fn sanitize_log_line(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch == '\0' {
            continue;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn sanitize_log_token(raw: &str, empty_fallback: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch == '\0' {
            continue;
        }
        if ch.is_control() {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        empty_fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn escape_clf_quoted(raw: &str, empty_fallback: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return empty_fallback.to_string();
    }
    let mut out = String::with_capacity(trimmed.len() + 4);
    for ch in trimmed.chars() {
        match ch {
            '\0' => {}
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    if out.trim().is_empty() {
        empty_fallback.to_string()
    } else {
        out
    }
}

fn format_combined_line(entry: &AccessLogEntry) -> String {
    let ts = zmax_core::format_clf_timestamp(entry.timestamp);
    let ip = sanitize_log_token(&entry.client_ip, "-");
    let method = sanitize_log_token(&entry.method, "GET");
    let target = sanitize_log_token(&entry.target, "/");
    let proto = sanitize_log_token(&entry.protocol, "HTTP/1.1");
    let referer = escape_clf_quoted(&entry.referer, "-");
    let ua = escape_clf_quoted(&entry.user_agent, "-");
    format!(
        "{} - - [{}] \"{} {} {}\" {} {} \"{}\" \"{}\"\n",
        ip, ts, method, target, proto, entry.status, entry.bytes_sent, referer, ua
    )
}

fn format_json_line(entry: &AccessLogEntry) -> String {
    let ts = zmax_core::format_iso8601_utc(entry.timestamp);
    let latency_ms = if entry.duration_ms.is_finite() {
        entry.duration_ms
    } else {
        0.0
    };
    let val = serde_json::json!({
        "ts": ts,
        "request_id": sanitize_log_token(&entry.request_id, ""),
        "domain": sanitize_log_token(&entry.domain, ""),
        "ip": sanitize_log_token(&entry.client_ip, ""),
        "method": sanitize_log_token(&entry.method, "GET"),
        "target": sanitize_log_token(&entry.target, "/"),
        "proto": sanitize_log_token(&entry.protocol, "HTTP/1.1"),
        "status": entry.status,
        "bytes": entry.bytes_sent,
        "latency_ms": latency_ms,
        "referer": sanitize_log_token(&entry.referer, ""),
        "user_agent": sanitize_log_token(&entry.user_agent, ""),
    });
    let mut line = serde_json::to_string(&val).unwrap_or_else(|_| "{}".to_string());
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn make_temp_dir(label: &str) -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "zmax_logger_{}_{}_{}",
            label,
            std::process::id(),
            id
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn ncsa_combined_formats_timestamp_numeric_bytes_and_escapes() {
        let dir = make_temp_dir("combined");
        let access = dir.join("logs").join("access.log");
        let error = dir.join("logs").join("error.log");
        let mgr = AsyncLogManager::new(dir.clone(), access.clone(), error, 50, 64);

        // 2026-11-11T21:00:00Z = 1_794_430_800
        let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);
        mgr.log_access(AccessLogEntry {
            timestamp: ts,
            client_ip: "203.0.113.5".to_string(),
            method: "GET".to_string(),
            target: "/urunler?sayfa=2".to_string(),
            protocol: "HTTP/2.0".to_string(),
            status: 200,
            bytes_sent: 0,
            referer: String::new(),
            user_agent: "ZMaxAgent/1.0 \"test\"\r\nline".to_string(),
            request_id: "zmx-1".to_string(),
            duration_ms: 1.25,
            domain: "site.test".to_string(),
            target_path: None,
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        });
        mgr.log_access(AccessLogEntry {
            timestamp: ts,
            client_ip: "198.51.100.7".to_string(),
            method: "POST".to_string(),
            target: "/api/submit".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 201,
            bytes_sent: 4096,
            referer: "https://site.test/form".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            request_id: "zmx-2".to_string(),
            duration_ms: 4.5,
            domain: "site.test".to_string(),
            target_path: None,
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        });
        mgr.flush().await;

        let content = tokio::fs::read_to_string(&access).await.unwrap();
        assert!(!content.contains('\r'), "LF sonu beklenir: {content}");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "203.0.113.5 - - [11/Nov/2026:21:00:00 +0000] \"GET /urunler?sayfa=2 HTTP/2.0\" 200 0 \"-\" \"ZMaxAgent/1.0 \\\"test\\\"  line\""
        );
        assert_eq!(
            lines[1],
            "198.51.100.7 - - [11/Nov/2026:21:00:00 +0000] \"POST /api/submit HTTP/1.1\" 201 4096 \"https://site.test/form\" \"Mozilla/5.0\""
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn json_format_writes_valid_single_line_json_and_tails() {
        let dir = make_temp_dir("json");
        let access = dir.join("logs").join("access.log");
        let error = dir.join("logs").join("error.log");
        let mgr = AsyncLogManager::new(dir.clone(), access.clone(), error, 50, 64);

        let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);
        for idx in 0..5usize {
            mgr.log_access(AccessLogEntry {
                timestamp: ts,
                client_ip: "127.0.0.1".to_string(),
                method: "GET".to_string(),
                target: format!("/p/{idx}"),
                protocol: "HTTP/2.0".to_string(),
                status: 200,
                bytes_sent: 100 + idx,
                referer: "https://example.com/".to_string(),
                user_agent: "curl/8.0".to_string(),
                request_id: format!("req-{idx}"),
                duration_ms: 2.5,
                domain: "ornek.test".to_string(),
                target_path: None,
                json_format: true,
                also_write_global: true,
                max_size_bytes: 0,
            });
        }
        mgr.flush().await;

        let tail = mgr.read_tail_lines(&access, 3).await.unwrap();
        assert_eq!(tail.len(), 3);
        let parsed: serde_json::Value = serde_json::from_str(&tail[2]).unwrap();
        assert_eq!(parsed["ts"], "2026-11-11T21:00:00Z");
        assert_eq!(parsed["request_id"], "req-4");
        assert_eq!(parsed["domain"], "ornek.test");
        assert_eq!(parsed["ip"], "127.0.0.1");
        assert_eq!(parsed["method"], "GET");
        assert_eq!(parsed["target"], "/p/4");
        assert_eq!(parsed["proto"], "HTTP/2.0");
        assert_eq!(parsed["status"], 200);
        assert_eq!(parsed["bytes"], 104);
        assert_eq!(parsed["latency_ms"], 2.5);
        assert_eq!(parsed["referer"], "https://example.com/");
        assert_eq!(parsed["user_agent"], "curl/8.0");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn per_vhost_target_rotation_and_reopen_all_writes_to_new_file() {
        let dir = make_temp_dir("reopen");
        let global_access = dir.join("logs").join("global_access.log");
        let global_error = dir.join("logs").join("global_error.log");
        let vhost_rel = PathBuf::from("logs/vhosts/site.access.log");
        let vhost_abs = dir.join(&vhost_rel);
        let rotated_archive = dir.join("logs/vhosts/site.access.log.rotated");

        let mgr = AsyncLogManager::new(
            dir.clone(),
            global_access.clone(),
            global_error.clone(),
            50,
            64,
        );
        let ts = UNIX_EPOCH + Duration::from_secs(1_794_430_800);

        mgr.log_access(AccessLogEntry {
            timestamp: ts,
            client_ip: "10.0.0.1".to_string(),
            method: "GET".to_string(),
            target: "/once".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes_sent: 512,
            referer: String::new(),
            user_agent: "TestUA".to_string(),
            request_id: "r1".to_string(),
            duration_ms: 1.0,
            domain: "site.test".to_string(),
            target_path: Some(vhost_rel.clone()),
            json_format: false,
            also_write_global: true,
            max_size_bytes: 0,
        });
        mgr.flush().await;

        assert!(vhost_abs.is_file());
        assert!(global_access.is_file());

        // Açık dosya tanıtıcılarını bırak, eski dosyayı taşı, sonra reopen_all sonrası yeni dosyaya yaz
        mgr.reopen_all().await;
        tokio::fs::rename(&vhost_abs, &rotated_archive).await.unwrap();

        mgr.log_access(AccessLogEntry {
            timestamp: ts,
            client_ip: "10.0.0.2".to_string(),
            method: "GET".to_string(),
            target: "/sonra".to_string(),
            protocol: "HTTP/1.1".to_string(),
            status: 200,
            bytes_sent: 1024,
            referer: String::new(),
            user_agent: "TestUA".to_string(),
            request_id: "r2".to_string(),
            duration_ms: 1.5,
            domain: "site.test".to_string(),
            target_path: Some(vhost_rel.clone()),
            json_format: false,
            also_write_global: false,
            max_size_bytes: 0,
        });
        mgr.flush().await;

        let new_body = tokio::fs::read_to_string(&vhost_abs).await.unwrap();
        assert!(new_body.contains("/sonra") && !new_body.contains("/once"));
        let old_body = tokio::fs::read_to_string(&rotated_archive).await.unwrap();
        assert!(old_body.contains("/once") && !old_body.contains("/sonra"));
        let global_body = tokio::fs::read_to_string(&global_access).await.unwrap();
        assert!(global_body.contains("/once") && !global_body.contains("/sonra"));

        // Boyut sınırı ile .1 rotasyonu
        let err_override = PathBuf::from("logs/vhosts/site.error.log");
        mgr.log_error(
            Some(err_override.clone()),
            "birinci-uzun-hata-mesaji-0123456789abcdef".to_string(),
            48,
            false,
        );
        mgr.log_error(
            Some(err_override.clone()),
            "ikinci-hata".to_string(),
            48,
            false,
        );
        mgr.flush().await;
        let err_abs = dir.join(&err_override);
        let err_dot_one = dir.join("logs/vhosts/site.error.log.1");
        assert!(err_dot_one.is_file());
        assert_eq!(tokio::fs::read_to_string(&err_abs).await.unwrap(), "ikinci-hata\n");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
