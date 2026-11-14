//! Arka plan günlük yazıcı görevi.

use super::*;

pub(super) enum LogCommand {
    Access(AccessLogEntry),
    Error {
        path_override: Option<PathBuf>,
        message: String,
        max_size_bytes: u64,
        also_global: bool,
    },
    Waf {
        path_override: Option<PathBuf>,
        record: zmax_security::waf_events::WafEventRecord,
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

pub(super) struct OpenLogFile {
    pub(super) writer: BufWriter<tokio::fs::File>,
    pub(super) current_size: u64,
    pub(super) pending_bytes: usize,
}

pub(super) struct LogWorkerState {
    pub(super) base_dir: PathBuf,
    pub(super) global_access_log: PathBuf,
    pub(super) global_error_log: PathBuf,
    pub(super) global_waf_log: PathBuf,
    pub(super) writers: HashMap<PathBuf, OpenLogFile>,
    pub(super) total_pending_bytes: usize,
    pub(super) batch_threshold_bytes: usize,
    pub(super) writer_capacity: usize,
}

impl LogWorkerState {
    pub(super) fn resolve(&self, path: &Path) -> PathBuf {
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

    async fn flush_path(&mut self, path: &Path) {
        if let Some(open) = self.writers.get_mut(path) {
            if open.pending_bytes > 0 {
                self.total_pending_bytes =
                    self.total_pending_bytes.saturating_sub(open.pending_bytes);
                let _ = open.writer.flush().await;
                open.pending_bytes = 0;
            }
        }
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
            LogCommand::Waf {
                path_override,
                record,
                max_size_bytes,
                also_global,
            } => {
                let line = record.to_json_line();
                let custom = path_override
                    .as_deref()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| self.resolve(p));

                match custom {
                    Some(target) => {
                        self.ensure_ready_and_write(&target, &line, max_size_bytes)
                            .await;
                        self.flush_path(&target).await;
                        if also_global && target != self.global_waf_log {
                            let global = self.global_waf_log.clone();
                            self.ensure_ready_and_write(&global, &line, max_size_bytes)
                                .await;
                            self.flush_path(&global).await;
                        }
                    }
                    None => {
                        let global = self.global_waf_log.clone();
                        self.ensure_ready_and_write(&global, &line, max_size_bytes)
                            .await;
                        self.flush_path(&global).await;
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

pub(super) async fn run_log_worker(
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

pub(super) fn resolve_log_path(base_dir: &Path, raw: &Path) -> PathBuf {
    if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        base_dir.join(raw)
    }
}
