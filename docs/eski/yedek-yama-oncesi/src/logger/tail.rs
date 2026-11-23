//! Dosya sonundan satır okuma.

use super::*;

impl AsyncLogManager {
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

}
