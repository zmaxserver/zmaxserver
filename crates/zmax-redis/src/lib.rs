//! # zmax-redis
//! ZMax Server Redis entegrasyon modülü.
//! Dağıtık önbellek, Pub/Sub senkronizasyonu, RESP2 protokolü ve merkezi IP engelleme.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const MAX_RESP_LINE_BYTES: usize = 64 * 1024;
const MAX_RESP_BULK_BYTES: usize = 64 * 1024 * 1024;
const MAX_RESP_ARRAY_ITEMS: usize = 100_000;
const MAX_RESP_DEPTH: usize = 32;

fn default_redis_addr() -> String {
    "127.0.0.1:6379".to_string()
}

fn default_redis_host() -> String {
    "127.0.0.1".to_string()
}

fn default_redis_port() -> u16 {
    6379
}

fn default_timeout_ms() -> u64 {
    100
}

fn default_pubsub_channel() -> String {
    "zmax:cache:purge".to_string()
}

fn default_channel_prefix() -> String {
    "zmax".to_string()
}

fn default_reconnect_backoff_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedisConfig {
    #[serde(default = "default_redis_host")]
    pub host: String,
    #[serde(default = "default_redis_port")]
    pub port: u16,
    #[serde(default = "default_redis_addr")]
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub database: u8,
    #[serde(default)]
    pub db: u8,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_pubsub_channel")]
    pub pubsub_channel: String,
    #[serde(default = "default_channel_prefix")]
    pub channel_prefix: String,
    #[serde(default = "default_reconnect_backoff_ms")]
    pub reconnect_backoff_ms: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            host: default_redis_host(),
            port: default_redis_port(),
            addr: default_redis_addr(),
            username: None,
            password: None,
            database: 0,
            db: 0,
            timeout_ms: default_timeout_ms(),
            pubsub_channel: default_pubsub_channel(),
            channel_prefix: default_channel_prefix(),
            reconnect_backoff_ms: default_reconnect_backoff_ms(),
        }
    }
}

impl RedisConfig {
    /// Etkin Redis sunucu adresini (`host:port` veya açıkça belirtilen `addr`) döndürür.
    pub fn effective_addr(&self) -> String {
        let addr_trimmed = self.addr.trim();
        if !addr_trimmed.is_empty() && addr_trimmed != "127.0.0.1:6379" {
            return addr_trimmed.to_string();
        }
        if self.host.trim() != "127.0.0.1" || self.port != 6379 {
            return format!("{}:{}", self.host.trim(), self.port);
        }
        if !addr_trimmed.is_empty() {
            addr_trimmed.to_string()
        } else {
            format!("{}:{}", self.host.trim(), self.port)
        }
    }

    /// Etkin veritabanı indeksini döndürür (`db` sıfırdan farklıysa onu, değilse `database` alanını kullanır).
    pub fn effective_db(&self) -> u8 {
        if self.db != 0 {
            self.db
        } else {
            self.database
        }
    }

    /// Küme olayları için kullanılacak Pub/Sub kanal adını döndürür.
    pub fn effective_events_channel(&self) -> String {
        let prefix = self.channel_prefix.trim().trim_end_matches(':');
        if !prefix.is_empty() && prefix != "zmax" {
            return format!("{}:events", prefix);
        }
        let legacy = self.pubsub_channel.trim();
        if !legacy.is_empty() && legacy != "zmax:cache:purge" {
            return legacy.to_string();
        }
        if !prefix.is_empty() {
            format!("{}:events", prefix)
        } else {
            "zmax:events".to_string()
        }
    }
}

/// Çoklu sunucu kümesi (Cluster) senkronizasyon olayları.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterSyncEvent {
    BanIp { ip: String, ttl_secs: u64 },
    UnbanIp { ip: String },
    PurgeDomain { domain: String },
    PurgeTag { domain: String, tag: String },
    PurgeAll,
    ReloadConfig,
}

impl ClusterSyncEvent {
    /// Olayı Redis Pub/Sub tel biçimine serileştirir.
    pub fn to_wire_string(&self) -> String {
        match self {
            Self::BanIp { ip, ttl_secs } => format!("ban:{}:{}", ip, ttl_secs),
            Self::UnbanIp { ip } => format!("unban:{}", ip),
            Self::PurgeDomain { domain } => format!("purge:{}", domain),
            Self::PurgeTag { domain, tag } => format!("purge-tag:{}:{}", domain, tag),
            Self::PurgeAll => "purge:*".to_string(),
            Self::ReloadConfig => "reload".to_string(),
        }
    }

    /// Olayı gönderen düğüm kimliğiyle sarar: `@<node>|<olay>` (eski düğümler sarmalsız biçimi de okunur).
    pub fn to_wire_with_node(&self, node_id: &str) -> String {
        let clean: String = node_id.chars().filter(|c| *c != '|' && *c != '@' && !c.is_whitespace()).collect();
        if clean.is_empty() {
            self.to_wire_string()
        } else {
            format!("@{}|{}", clean, self.to_wire_string())
        }
    }

    /// Sarmalı (varsa) çözer; düğüm kimliği ve olayı döndürür.
    pub fn parse_wire_with_node(raw: &str) -> Result<(Option<String>, Self), String> {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_prefix('@') {
            if let Some((node, inner)) = rest.split_once('|') {
                let node = node.trim();
                let node = if node.is_empty() { None } else { Some(node.to_string()) };
                return Ok((node, Self::parse_inner(inner)?));
            }
        }
        Ok((None, Self::parse_inner(trimmed)?))
    }

    /// Tel biçimindeki Redis Pub/Sub mesajını `ClusterSyncEvent` değerine ayrıştırır.
    pub fn parse_wire(raw: &str) -> Result<Self, String> {
        Self::parse_wire_with_node(raw).map(|(_, ev)| ev)
    }

    fn parse_inner(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed == "reload" {
            return Ok(Self::ReloadConfig);
        }
        if trimmed == "purge:*" {
            return Ok(Self::PurgeAll);
        }
        if let Some(rest) = trimmed.strip_prefix("ban:") {
            // IPv6 adresleri ':' içerdiği için son ':' ayırıcısını kullanırız.
            let (ip, ttl_str) = rest
                .rsplit_once(':')
                .ok_or_else(|| format!("Geçersiz ban olayı biçimi: '{}'", raw))?;
            let ip_clean = ip.trim();
            if ip_clean.is_empty() {
                return Err(format!("ban olayında IP boş olamaz: '{}'", raw));
            }
            let ttl_secs = ttl_str
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("Geçersiz ban TTL değeri: '{}'", raw))?;
            return Ok(Self::BanIp {
                ip: ip_clean.to_string(),
                ttl_secs,
            });
        }
        if let Some(ip) = trimmed.strip_prefix("unban:") {
            let ip_clean = ip.trim();
            if ip_clean.is_empty() {
                return Err(format!("unban olayında IP boş olamaz: '{}'", raw));
            }
            return Ok(Self::UnbanIp {
                ip: ip_clean.to_string(),
            });
        }
        if let Some(rest) = trimmed.strip_prefix("purge-tag:") {
            let (domain, tag) = rest
                .split_once(':')
                .ok_or_else(|| format!("Geçersiz purge-tag olayı biçimi: '{}'", raw))?;
            let domain_clean = domain.trim();
            let tag_clean = tag.trim();
            if domain_clean.is_empty() || tag_clean.is_empty() {
                return Err(format!("purge-tag olayında domain veya tag boş olamaz: '{}'", raw));
            }
            return Ok(Self::PurgeTag {
                domain: domain_clean.to_string(),
                tag: tag_clean.to_string(),
            });
        }
        if let Some(domain) = trimmed.strip_prefix("purge:") {
            let domain_clean = domain.trim();
            if domain_clean.is_empty() {
                return Err(format!("purge olayında domain boş olamaz: '{}'", raw));
            }
            return Ok(Self::PurgeDomain {
                domain: domain_clean.to_string(),
            });
        }
        Err(format!("Bilinmeyen ClusterSyncEvent mesajı: '{}'", raw))
    }
}

impl fmt::Display for ClusterSyncEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire_string())
    }
}

impl FromStr for ClusterSyncEvent {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_wire(s)
    }
}

/// RESP2 protokol çerçeve türleri.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespFrame {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Option<Vec<RespFrame>>),
}

impl RespFrame {
    /// Çerçeveyi mümkünse UTF-8 metin dilimi olarak döndürür.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::SimpleString(s) | Self::Error(s) => Some(s.as_str()),
            Self::BulkString(Some(bytes)) => std::str::from_utf8(bytes).ok(),
            _ => None,
        }
    }

    /// Çerçevenin `"OK"` basit dizgisi olup olmadığını denetler.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::SimpleString(s) if s.eq_ignore_ascii_case("OK"))
    }
}

/// Verilen komut argümanlarını RESP2 dizi (`*N\r\n$len\r\narg\r\n`) biçiminde kodlar.
pub fn encode_resp_command(args: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + args.iter().map(|a| a.len() + 12).sum::<usize>());
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for arg in args {
        out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
        out.extend_from_slice(arg.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Bellek içi bayt diliminden tek bir RESP2 çerçevesini ayrıştırır ve `(çerçeve, tüketilen_bayt)` döner.
pub fn parse_resp_frame(input: &[u8]) -> Result<(RespFrame, usize), String> {
    parse_resp_frame_inner(input, 0)
}

fn parse_resp_frame_inner(input: &[u8], depth: usize) -> Result<(RespFrame, usize), String> {
    if depth > MAX_RESP_DEPTH {
        return Err("RESP2 dizi derinlik sınırı aşıldı".to_string());
    }
    if input.is_empty() {
        return Err("RESP2 çerçevesi boş".to_string());
    }
    let crlf_pos = input
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or_else(|| "Eksik RESP2 satır sonu (CRLF)".to_string())?;
    if crlf_pos > MAX_RESP_LINE_BYTES {
        return Err("RESP2 başlık satırı izin verilen uzunluğu aşıyor".to_string());
    }

    let prefix = input[0];
    let payload = &input[1..crlf_pos];
    let mut cursor = crlf_pos + 2;

    match prefix {
        b'+' => {
            let s = String::from_utf8(payload.to_vec())
                .map_err(|_| "RESP2 SimpleString geçersiz UTF-8 içeriyor".to_string())?;
            Ok((RespFrame::SimpleString(s), cursor))
        }
        b'-' => {
            let s = String::from_utf8(payload.to_vec())
                .map_err(|_| "RESP2 Error geçersiz UTF-8 içeriyor".to_string())?;
            Ok((RespFrame::Error(s), cursor))
        }
        b':' => {
            let s = std::str::from_utf8(payload)
                .map_err(|_| "RESP2 Integer geçersiz UTF-8".to_string())?;
            let n = s
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("Geçersiz RESP2 tamsayı: '{}'", s))?;
            Ok((RespFrame::Integer(n), cursor))
        }
        b'$' => {
            let s = std::str::from_utf8(payload)
                .map_err(|_| "RESP2 BulkString uzunluğu geçersiz UTF-8".to_string())?;
            let len = s
                .trim()
                .parse::<isize>()
                .map_err(|_| format!("Geçersiz RESP2 BulkString uzunluğu: '{}'", s))?;
            if len == -1 {
                return Ok((RespFrame::BulkString(None), cursor));
            }
            if len < 0 || (len as usize) > MAX_RESP_BULK_BYTES {
                return Err(format!("Geçersiz RESP2 BulkString uzunluğu: {}", len));
            }
            let ulen = len as usize;
            if input.len() < cursor + ulen + 2 {
                return Err("Eksik RESP2 BulkString verisi".to_string());
            }
            let data = input[cursor..cursor + ulen].to_vec();
            if &input[cursor + ulen..cursor + ulen + 2] != b"\r\n" {
                return Err("RESP2 BulkString sonunda CRLF bekleniyordu".to_string());
            }
            cursor += ulen + 2;
            Ok((RespFrame::BulkString(Some(data)), cursor))
        }
        b'*' => {
            let s = std::str::from_utf8(payload)
                .map_err(|_| "RESP2 Array uzunluğu geçersiz UTF-8".to_string())?;
            let count = s
                .trim()
                .parse::<isize>()
                .map_err(|_| format!("Geçersiz RESP2 Array uzunluğu: '{}'", s))?;
            if count == -1 {
                return Ok((RespFrame::Array(None), cursor));
            }
            if count < 0 || (count as usize) > MAX_RESP_ARRAY_ITEMS {
                return Err(format!("Geçersiz RESP2 Array eleman sayısı: {}", count));
            }
            let mut items = Vec::with_capacity(count as usize);
            for _ in 0..(count as usize) {
                let (item, consumed) = parse_resp_frame_inner(&input[cursor..], depth + 1)?;
                cursor += consumed;
                items.push(item);
            }
            Ok((RespFrame::Array(Some(items)), cursor))
        }
        other => Err(format!("Desteklenmeyen RESP2 önek baytı: 0x{:02x}", other)),
    }
}

/// Asenkron tamponlu okuyucu üzerinden RESP2 çerçevelerini çözen okuyucu.
#[derive(Debug)]
pub struct RespReader<R> {
    inner: R,
}

impl<R> RespReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &R {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncBufRead + Unpin + Send> RespReader<R> {
    /// Akıştan bir sonraki RESP2 çerçevesini asenkron olarak okur.
    pub async fn read_frame(&mut self) -> Result<RespFrame, String> {
        read_resp_frame(&mut self.inner).await
    }
}

async fn read_crlf_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut line = Vec::with_capacity(64);
    let n = reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|e| format!("Redis akış okuma hatası: {}", e))?;
    if n == 0 {
        return Err("Redis bağlantısı kapandı (EOF)".to_string());
    }
    if line.len() > MAX_RESP_LINE_BYTES {
        return Err("RESP2 satır uzunluk sınırı aşıldı".to_string());
    }
    if !line.ends_with(b"\r\n") {
        return Err("RESP2 satırı CRLF ile sonlanmadı".to_string());
    }
    line.truncate(line.len() - 2);
    Ok(line)
}

/// Tamponlu asenkron okuyucudan tek bir RESP2 çerçevesi okur (`+`, `-`, `:`, `$`, `*`).
pub async fn read_resp_frame<R: AsyncBufRead + Unpin + Send>(
    reader: &mut R,
) -> Result<RespFrame, String> {
    read_resp_frame_inner(reader, 0).await
}

fn read_resp_frame_inner<'a, R: AsyncBufRead + Unpin + Send>(
    reader: &'a mut R,
    depth: usize,
) -> Pin<Box<dyn Future<Output = Result<RespFrame, String>> + Send + 'a>> {
    Box::pin(async move {
        if depth > MAX_RESP_DEPTH {
            return Err("RESP2 dizi derinlik sınırı aşıldı".to_string());
        }
        let line = read_crlf_line(reader).await?;
        if line.is_empty() {
            return Err("Boş RESP2 başlık satırı".to_string());
        }
        let prefix = line[0];
        let payload = &line[1..];

        match prefix {
            b'+' => {
                let s = String::from_utf8(payload.to_vec())
                    .map_err(|_| "RESP2 SimpleString geçersiz UTF-8".to_string())?;
                Ok(RespFrame::SimpleString(s))
            }
            b'-' => {
                let s = String::from_utf8(payload.to_vec())
                    .map_err(|_| "RESP2 Error geçersiz UTF-8".to_string())?;
                Ok(RespFrame::Error(s))
            }
            b':' => {
                let s = std::str::from_utf8(payload)
                    .map_err(|_| "RESP2 Integer geçersiz UTF-8".to_string())?;
                let n = s
                    .trim()
                    .parse::<i64>()
                    .map_err(|_| format!("Geçersiz RESP2 tamsayı: '{}'", s))?;
                Ok(RespFrame::Integer(n))
            }
            b'$' => {
                let s = std::str::from_utf8(payload)
                    .map_err(|_| "RESP2 BulkString uzunluğu geçersiz UTF-8".to_string())?;
                let len = s
                    .trim()
                    .parse::<isize>()
                    .map_err(|_| format!("Geçersiz RESP2 BulkString uzunluğu: '{}'", s))?;
                if len == -1 {
                    return Ok(RespFrame::BulkString(None));
                }
                if len < 0 || (len as usize) > MAX_RESP_BULK_BYTES {
                    return Err(format!("Geçersiz RESP2 BulkString uzunluğu: {}", len));
                }
                let mut data = vec![0u8; len as usize];
                reader
                    .read_exact(&mut data)
                    .await
                    .map_err(|e| format!("RESP2 BulkString gövdesi okunamadı: {}", e))?;
                let mut crlf = [0u8; 2];
                reader
                    .read_exact(&mut crlf)
                    .await
                    .map_err(|e| format!("RESP2 BulkString CRLF okunamadı: {}", e))?;
                if &crlf != b"\r\n" {
                    return Err("RESP2 BulkString sonunda CRLF bekleniyordu".to_string());
                }
                Ok(RespFrame::BulkString(Some(data)))
            }
            b'*' => {
                let s = std::str::from_utf8(payload)
                    .map_err(|_| "RESP2 Array uzunluğu geçersiz UTF-8".to_string())?;
                let count = s
                    .trim()
                    .parse::<isize>()
                    .map_err(|_| format!("Geçersiz RESP2 Array uzunluğu: '{}'", s))?;
                if count == -1 {
                    return Ok(RespFrame::Array(None));
                }
                if count < 0 || (count as usize) > MAX_RESP_ARRAY_ITEMS {
                    return Err(format!("Geçersiz RESP2 Array eleman sayısı: {}", count));
                }
                let mut items = Vec::with_capacity(count as usize);
                for _ in 0..(count as usize) {
                    let frame = read_resp_frame_inner(reader, depth + 1).await?;
                    items.push(frame);
                }
                Ok(RespFrame::Array(Some(items)))
            }
            other => Err(format!("Desteklenmeyen RESP2 önek baytı: 0x{:02x}", other)),
        }
    })
}

async fn send_command_expect_ok(
    reader: &mut BufReader<TcpStream>,
    args: &[&str],
    op_name: &str,
) -> Result<(), String> {
    let cmd = encode_resp_command(args);
    reader
        .get_mut()
        .write_all(&cmd)
        .await
        .map_err(|e| format!("Redis {} komutu gönderilemedi: {}", op_name, e))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|e| format!("Redis {} komutu boşaltılamadı: {}", op_name, e))?;

    match read_resp_frame(reader).await? {
        RespFrame::SimpleString(s) if s.eq_ignore_ascii_case("OK") => Ok(()),
        RespFrame::Error(err) => Err(format!("Redis {} hatası: {}", op_name, err)),
        other => Err(format!("Redis {} için beklenmeyen yanıt: {:?}", op_name, other)),
    }
}

/// Redis sunucusuna bağlanır; yapılandırılmışsa `AUTH [user] pass`, `SELECT db` ve `PING` adımlarını doğrular.
pub async fn connect_and_auth(config: &RedisConfig) -> Result<BufReader<TcpStream>, String> {
    let addr = config.effective_addr();
    let timeout_dur = Duration::from_millis(if config.timeout_ms == 0 { 3000 } else { config.timeout_ms });

    let stream = tokio::time::timeout(timeout_dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Redis bağlantısı zaman aşımına uğradı ({})", addr))?
        .map_err(|e| format!("Redis bağlantısı kurulamadı ({}): {}", addr, e))?;

    let mut reader = BufReader::new(stream);

    if let Some(password) = config.password.as_deref() {
        match config.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            Some(user) => send_command_expect_ok(&mut reader, &["AUTH", user, password], "AUTH").await?,
            None => send_command_expect_ok(&mut reader, &["AUTH", password], "AUTH").await?,
        }
    }

    let db = config.effective_db();
    if db > 0 {
        let db_str = db.to_string();
        send_command_expect_ok(&mut reader, &["SELECT", &db_str], "SELECT").await?;
    }

    let ping_cmd = encode_resp_command(&["PING"]);
    reader
        .get_mut()
        .write_all(&ping_cmd)
        .await
        .map_err(|e| format!("Redis PING gönderilemedi: {}", e))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|e| format!("Redis PING boşaltılamadı: {}", e))?;

    match read_resp_frame(&mut reader).await? {
        RespFrame::SimpleString(s) if s.eq_ignore_ascii_case("PONG") => Ok(reader),
        RespFrame::BulkString(Some(b)) if b.eq_ignore_ascii_case(b"PONG") => Ok(reader),
        RespFrame::Error(err) => Err(format!("Redis PING hatası: {}", err)),
        other => Err(format!("Redis PING için beklenmeyen yanıt: {:?}", other)),
    }
}

/// Küme senkronizasyon olayını Redis Pub/Sub kanalına yayınlar (`PUBLISH`) ve alıcı sayısını döner.
pub async fn publish_event(config: &RedisConfig, event: &ClusterSyncEvent) -> Result<i64, String> {
    publish_event_from(config, "", event).await
}

/// Olayı düğüm kimliğiyle yayınlar (`node_id` boşsa sarmalsız eski biçim).
pub async fn publish_event_from(
    config: &RedisConfig,
    node_id: &str,
    event: &ClusterSyncEvent,
) -> Result<i64, String> {
    let mut reader = connect_and_auth(config).await?;
    let channel = config.effective_events_channel();
    let payload = event.to_wire_with_node(node_id);
    let cmd = encode_resp_command(&["PUBLISH", &channel, &payload]);

    reader
        .get_mut()
        .write_all(&cmd)
        .await
        .map_err(|e| format!("Redis PUBLISH gönderilemedi: {}", e))?;
    reader
        .get_mut()
        .flush()
        .await
        .map_err(|e| format!("Redis PUBLISH boşaltılamadı: {}", e))?;

    match read_resp_frame(&mut reader).await? {
        RespFrame::Integer(subscribers) => Ok(subscribers),
        RespFrame::Error(err) => Err(format!("Redis PUBLISH hatası: {}", err)),
        other => Err(format!("Redis PUBLISH için beklenmeyen yanıt: {:?}", other)),
    }
}

fn extract_pubsub_event(items: &[RespFrame]) -> Option<(Option<String>, ClusterSyncEvent)> {
    let kind = items.first()?.as_str()?;
    let payload_str = if kind.eq_ignore_ascii_case("message") && items.len() >= 3 {
        items[2].as_str()?
    } else if kind.eq_ignore_ascii_case("pmessage") && items.len() >= 4 {
        items[3].as_str()?
    } else {
        return None;
    };

    match ClusterSyncEvent::parse_wire_with_node(payload_str) {
        Ok(pair) => Some(pair),
        Err(err) => {
            tracing::warn!("Geçersiz küme Pub/Sub mesajı yoksayıldı: {}", err);
            None
        }
    }
}

/// Redis Pub/Sub kanalına abone olur; kopmalarda üstel geri çekilme (backoff) ile yeniden bağlanır.
pub async fn subscribe_events<F>(
    config: &RedisConfig,
    shutdown: tokio::sync::watch::Receiver<bool>,
    mut on_event: F,
) -> Result<(), String>
where
    F: FnMut(ClusterSyncEvent) + Send,
{
    subscribe_events_origin(config, shutdown, move |_, ev| on_event(ev)).await
}

/// `subscribe_events` ile aynı; olayı gönderen düğüm kimliğini de verir.
pub async fn subscribe_events_origin<F>(
    config: &RedisConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut on_event: F,
) -> Result<(), String>
where
    F: FnMut(Option<String>, ClusterSyncEvent) + Send,
{
    let channel = config.effective_events_channel();
    let base_backoff = config.reconnect_backoff_ms.max(10);
    let mut attempt: u32 = 0;

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        match connect_and_auth(config).await {
            Ok(mut reader) => {
                attempt = 0;
                let sub_cmd = encode_resp_command(&["SUBSCRIBE", &channel]);
                if let Err(e) = reader.get_mut().write_all(&sub_cmd).await {
                    tracing::warn!("Redis SUBSCRIBE gönderilemedi: {}", e);
                } else if let Err(e) = reader.get_mut().flush().await {
                    tracing::warn!("Redis SUBSCRIBE boşaltılamadı: {}", e);
                } else {
                    loop {
                        tokio::select! {
                            changed = shutdown.changed() => {
                                if changed.is_err() || *shutdown.borrow() {
                                    return Ok(());
                                }
                            }
                            frame_res = read_resp_frame(&mut reader) => {
                                match frame_res {
                                    Ok(RespFrame::Array(Some(items))) => {
                                        if let Some((node, event)) = extract_pubsub_event(&items) {
                                            on_event(node, event);
                                        }
                                    }
                                    Ok(RespFrame::Error(err)) => {
                                        tracing::warn!("Redis Pub/Sub sunucu hatası: {}", err);
                                        break;
                                    }
                                    Ok(_) => {}
                                    Err(err) => {
                                        tracing::warn!("Redis Pub/Sub akışı kesildi: {}", err);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(
                    "Redis Pub/Sub bağlantısı kurulamadı ({}): {}",
                    config.effective_addr(),
                    err
                );
            }
        }

        if *shutdown.borrow() {
            return Ok(());
        }

        let shift = attempt.min(6);
        let delay_ms = base_backoff.saturating_mul(1u64 << shift).min(30_000);
        attempt = attempt.saturating_add(1);

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZMaxRedisClient {
    config: RedisConfig,
}

impl ZMaxRedisClient {
    pub fn new(config: RedisConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &RedisConfig {
        &self.config
    }

    /// Redis sunucusuna hızlı bağlantı testi yapar (AUTH/SELECT/PING -> PONG)
    pub async fn ping(&self) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        connect_and_auth(&self.config)
            .await
            .map(|_| true)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e).into())
    }

    /// Çoklu sunucu kümesine (Cluster) önbellek temizleme mesajı yayınlar (PUBLISH)
    pub async fn publish_purge(&self, tag_or_url: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = connect_and_auth(&self.config)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let cmd = encode_resp_command(&["PUBLISH", &self.config.pubsub_channel, tag_or_url]);
        reader.get_mut().write_all(&cmd).await?;
        reader.get_mut().flush().await?;
        match read_resp_frame(&mut reader).await {
            Ok(RespFrame::Integer(_)) => Ok(()),
            Ok(RespFrame::Error(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e).into()),
            Ok(other) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Beklenmeyen PUBLISH yanıtı: {:?}", other),
            )
            .into()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e).into()),
        }
    }

    /// Engellenen bir saldırgan IP'sini merkezi Redis havuzuna kaydeder (SETEX)
    pub async fn ban_ip(&self, ip: &str, ttl_secs: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut reader = connect_and_auth(&self.config)
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let key = format!("zmax:banned:{}", ip);
        let ttl_str = ttl_secs.to_string();
        let cmd = encode_resp_command(&["SETEX", &key, &ttl_str, "1"]);
        reader.get_mut().write_all(&cmd).await?;
        reader.get_mut().flush().await?;
        match read_resp_frame(&mut reader).await {
            Ok(frame) if frame.is_ok() => Ok(()),
            Ok(RespFrame::Error(e)) => Err(std::io::Error::new(std::io::ErrorKind::Other, e).into()),
            Ok(other) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Beklenmeyen SETEX yanıtı: {:?}", other),
            )
            .into()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e).into()),
        }
    }

    /// Küme olayını düğüm kimliğiyle yayınlar.
    pub async fn publish_event_from(&self, node_id: &str, event: &ClusterSyncEvent) -> Result<i64, String> {
        publish_event_from(&self.config, node_id, event).await
    }

    /// Düğüm kimliğini veren abonelik.
    pub async fn subscribe_events_origin<F>(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
        on_event: F,
    ) -> Result<(), String>
    where
        F: FnMut(Option<String>, ClusterSyncEvent) + Send,
    {
        subscribe_events_origin(&self.config, shutdown, on_event).await
    }

    /// Yapılandırılmış küme olayını yayınlar.
    pub async fn publish_event(&self, event: &ClusterSyncEvent) -> Result<i64, String> {
        publish_event(&self.config, event).await
    }

    /// Küme olaylarını yeniden bağlanma desteğiyle dinler.
    pub async fn subscribe_events<F>(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
        on_event: F,
    ) -> Result<(), String>
    where
        F: FnMut(ClusterSyncEvent) + Send,
    {
        subscribe_events(&self.config, shutdown, on_event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn read_mock_resp_command(reader: &mut BufReader<TcpStream>) -> Result<Vec<String>, String> {
        let frame = read_resp_frame(reader).await?;
        match frame {
            RespFrame::Array(Some(items)) => items
                .into_iter()
                .map(|it| match it {
                    RespFrame::BulkString(Some(b)) => String::from_utf8(b)
                        .map_err(|_| "Komut argümanı geçersiz UTF-8".to_string()),
                    RespFrame::SimpleString(s) => Ok(s),
                    other => Err(format!("Beklenmeyen komut argümanı: {:?}", other)),
                })
                .collect(),
            other => Err(format!("Beklenmeyen komut çerçevesi: {:?}", other)),
        }
    }

    #[test]
    fn test_cluster_sync_event_wire_roundtrip_and_ipv6() {
        let cases = [
            (
                ClusterSyncEvent::BanIp {
                    ip: "192.0.2.44".to_string(),
                    ttl_secs: 600,
                },
                "ban:192.0.2.44:600",
            ),
            (
                ClusterSyncEvent::BanIp {
                    ip: "2001:db8::1".to_string(),
                    ttl_secs: 120,
                },
                "ban:2001:db8::1:120",
            ),
            (
                ClusterSyncEvent::UnbanIp {
                    ip: "::1".to_string(),
                },
                "unban:::1",
            ),
            (
                ClusterSyncEvent::PurgeDomain {
                    domain: "example.com".to_string(),
                },
                "purge:example.com",
            ),
            (
                ClusterSyncEvent::PurgeTag {
                    domain: "example.com".to_string(),
                    tag: "post:42".to_string(),
                },
                "purge-tag:example.com:post:42",
            ),
            (ClusterSyncEvent::PurgeAll, "purge:*"),
            (ClusterSyncEvent::ReloadConfig, "reload"),
        ];

        for (event, expected_wire) in cases {
            assert_eq!(event.to_wire_string(), expected_wire);
            let parsed = ClusterSyncEvent::parse_wire(expected_wire).unwrap();
            assert_eq!(parsed, event);
            let via_from_str: ClusterSyncEvent = expected_wire.parse().unwrap();
            assert_eq!(via_from_str, event);
        }

        for invalid in ["", "unknown", "ban:", "ban:1.2.3.4:notanumber", "unban:", "purge:", "purge-tag:onlydomain"] {
            assert!(
                ClusterSyncEvent::parse_wire(invalid).is_err(),
                "Geçersiz wire olayı reddedilmeli: '{}'",
                invalid
            );
        }
    }

    #[tokio::test]
    async fn test_resp_reader_slice_and_async_all_frame_types() {
        let raw = b"+OK\r\n-ERR wrongpass\r\n:42\r\n$5\r\nhello\r\n$-1\r\n*2\r\n$3\r\nfoo\r\n:7\r\n*-1\r\n";
        let mut offset = 0usize;
        let mut frames = Vec::new();
        while offset < raw.len() {
            let (frame, consumed) = parse_resp_frame(&raw[offset..]).unwrap();
            offset += consumed;
            frames.push(frame);
        }

        let mut async_reader = RespReader::new(BufReader::new(std::io::Cursor::new(&raw[..])));
        let mut async_frames = Vec::new();
        for _ in 0..frames.len() {
            async_frames.push(async_reader.read_frame().await.unwrap());
        }
        assert_eq!(async_frames, frames);

        assert_eq!(
            frames,
            vec![
                RespFrame::SimpleString("OK".to_string()),
                RespFrame::Error("ERR wrongpass".to_string()),
                RespFrame::Integer(42),
                RespFrame::BulkString(Some(b"hello".to_vec())),
                RespFrame::BulkString(None),
                RespFrame::Array(Some(vec![
                    RespFrame::BulkString(Some(b"foo".to_vec())),
                    RespFrame::Integer(7),
                ])),
                RespFrame::Array(None),
            ]
        );
    }

    #[tokio::test]
    async fn test_connect_and_auth_with_acl_select_and_ping() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);

            let cmd1 = read_mock_resp_command(&mut reader).await.unwrap();
            assert_eq!(cmd1, vec!["AUTH", "zmax_user", "secret123"]);
            reader.get_mut().write_all(b"+OK\r\n").await.unwrap();

            let cmd2 = read_mock_resp_command(&mut reader).await.unwrap();
            assert_eq!(cmd2, vec!["SELECT", "3"]);
            reader.get_mut().write_all(b"+OK\r\n").await.unwrap();

            let cmd3 = read_mock_resp_command(&mut reader).await.unwrap();
            assert_eq!(cmd3, vec!["PING"]);
            reader.get_mut().write_all(b"+PONG\r\n").await.unwrap();
            reader.get_mut().flush().await.unwrap();
        });

        let cfg = RedisConfig {
            addr: addr.to_string(),
            username: Some("zmax_user".to_string()),
            password: Some("secret123".to_string()),
            db: 3,
            timeout_ms: 2000,
            ..Default::default()
        };

        let conn = connect_and_auth(&cfg).await;
        assert!(conn.is_ok(), "AUTH+SELECT+PING başarılı olmalı: {:?}", conn.err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_and_auth_handles_err_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(socket);
            let cmd = read_mock_resp_command(&mut reader).await.unwrap();
            assert_eq!(cmd, vec!["AUTH", "wrongpass"]);
            reader
                .get_mut()
                .write_all(b"-ERR invalid password\r\n")
                .await
                .unwrap();
            reader.get_mut().flush().await.unwrap();
        });

        let cfg = RedisConfig {
            addr: addr.to_string(),
            password: Some("wrongpass".to_string()),
            timeout_ms: 2000,
            ..Default::default()
        };

        let err = connect_and_auth(&cfg).await.unwrap_err();
        assert!(err.contains("ERR invalid password"), "Hata mesajı iletilmeli: {}", err);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_publish_event_and_legacy_client_methods() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // 1. bağlantı: publish_event (PING + PUBLISH)
            let (socket1, _) = listener.accept().await.unwrap();
            let mut r1 = BufReader::new(socket1);
            assert_eq!(read_mock_resp_command(&mut r1).await.unwrap(), vec!["PING"]);
            r1.get_mut().write_all(b"+PONG\r\n").await.unwrap();
            let pub_cmd = read_mock_resp_command(&mut r1).await.unwrap();
            assert_eq!(pub_cmd, vec!["PUBLISH", "prod:events", "purge-tag:site.com:home"]);
            r1.get_mut().write_all(b":3\r\n").await.unwrap();
            r1.get_mut().flush().await.unwrap();

            // 2. bağlantı: legacy ban_ip (PING + SETEX)
            let (socket2, _) = listener.accept().await.unwrap();
            let mut r2 = BufReader::new(socket2);
            assert_eq!(read_mock_resp_command(&mut r2).await.unwrap(), vec!["PING"]);
            r2.get_mut().write_all(b"+PONG\r\n").await.unwrap();
            let ban_cmd = read_mock_resp_command(&mut r2).await.unwrap();
            assert_eq!(ban_cmd, vec!["SETEX", "zmax:banned:203.0.113.9", "120", "1"]);
            r2.get_mut().write_all(b"+OK\r\n").await.unwrap();
            r2.get_mut().flush().await.unwrap();
        });

        let cfg = RedisConfig {
            addr: addr.to_string(),
            channel_prefix: "prod".to_string(),
            timeout_ms: 2000,
            ..Default::default()
        };

        let subs = publish_event(
            &cfg,
            &ClusterSyncEvent::PurgeTag {
                domain: "site.com".to_string(),
                tag: "home".to_string(),
            },
        )
        .await
        .unwrap();
        assert_eq!(subs, 3);

        let client = ZMaxRedisClient::new(cfg);
        client.ban_ip("203.0.113.9", 120).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_subscribe_events_receives_messages_and_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // 1. bağlantı: PING -> PONG, SUBSCRIBE -> onay + 1 mesaj, sonra bağlantıyı kes (reconnect testi)
            let (s1, _) = listener.accept().await.unwrap();
            let mut r1 = BufReader::new(s1);
            assert_eq!(read_mock_resp_command(&mut r1).await.unwrap(), vec!["PING"]);
            r1.get_mut().write_all(b"+PONG\r\n").await.unwrap();
            let sub1 = read_mock_resp_command(&mut r1).await.unwrap();
            assert_eq!(sub1, vec!["SUBSCRIBE", "cluster:events"]);
            r1.get_mut()
                .write_all(b"*3\r\n$9\r\nsubscribe\r\n$14\r\ncluster:events\r\n:1\r\n")
                .await
                .unwrap();
            r1.get_mut()
                .write_all(b"*3\r\n$7\r\nmessage\r\n$14\r\ncluster:events\r\n$17\r\npurge:example.com\r\n")
                .await
                .unwrap();
            r1.get_mut().flush().await.unwrap();
            drop(r1);

            // 2. bağlantı: yeniden bağlanınca ikinci mesajı gönder
            let (s2, _) = listener.accept().await.unwrap();
            let mut r2 = BufReader::new(s2);
            assert_eq!(read_mock_resp_command(&mut r2).await.unwrap(), vec!["PING"]);
            r2.get_mut().write_all(b"+PONG\r\n").await.unwrap();
            let sub2 = read_mock_resp_command(&mut r2).await.unwrap();
            assert_eq!(sub2, vec!["SUBSCRIBE", "cluster:events"]);
            r2.get_mut()
                .write_all(b"*3\r\n$9\r\nsubscribe\r\n$14\r\ncluster:events\r\n:1\r\n")
                .await
                .unwrap();
            r2.get_mut()
                .write_all(b"*3\r\n$7\r\nmessage\r\n$14\r\ncluster:events\r\n$19\r\nban:198.51.100.7:60\r\n")
                .await
                .unwrap();
            r2.get_mut().flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let cfg = RedisConfig {
            addr: addr.to_string(),
            channel_prefix: "cluster".to_string(),
            reconnect_backoff_ms: 20,
            timeout_ms: 2000,
            ..Default::default()
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (ev_tx, mut ev_rx) = tokio::sync::mpsc::channel(8);

        let sub_task = tokio::spawn(async move {
            subscribe_events(&cfg, shutdown_rx, move |ev| {
                let _ = ev_tx.try_send(ev);
            })
            .await
        });

        let first = tokio::time::timeout(Duration::from_secs(3), ev_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            first,
            ClusterSyncEvent::PurgeDomain {
                domain: "example.com".to_string()
            }
        );

        let second = tokio::time::timeout(Duration::from_secs(3), ev_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second,
            ClusterSyncEvent::BanIp {
                ip: "198.51.100.7".to_string(),
                ttl_secs: 60
            }
        );

        let _ = shutdown_tx.send(true);
        sub_task.await.unwrap().unwrap();
        server.await.unwrap();
    }
}

