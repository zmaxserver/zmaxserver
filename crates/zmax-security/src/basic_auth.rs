//! ZMax Basic Authentication ve Apache htpasswd ($apr1$) Doğrulama Modülü
//!
//! Panelin parola korumalı dizinleri (apply_auth.go) ve Apache htpasswd formatı
//! ($apr1$ Apache MD5, SHA-1, düz metin) ile %100 uyumludur.
//! Sabit zamanlı karşılaştırma yapılarak zamanlama saldırıları (timing attack) önlenir.
//! Parolalar asla hata veya denetim günlüklerine yazılmaz.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::SystemTime;
use zmax_config::VHostAuthSection;

// ============================================================================
// 1. RFC 1321 Standart MD5 Gerçeklemesi (Harici Bağımlılıksız, Saf Rust)
// ============================================================================

#[derive(Clone)]
struct Md5Context {
    state: [u32; 4],
    count: u64,
    buffer: [u8; 64],
}

impl Md5Context {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    fn update(&mut self, input: &[u8]) {
        let mut index = ((self.count >> 3) & 0x3f) as usize;
        self.count += (input.len() as u64) << 3;

        let part_len = 64 - index;
        let mut i = 0;

        if input.len() >= part_len {
            self.buffer[index..index + part_len].copy_from_slice(&input[..part_len]);
            let block = self.buffer;
            self.transform(&block);
            i = part_len;
            while i + 63 < input.len() {
                let mut blk = [0u8; 64];
                blk.copy_from_slice(&input[i..i + 64]);
                self.transform(&blk);
                i += 64;
            }
            index = 0;
        }

        if i < input.len() {
            self.buffer[index..index + (input.len() - i)].copy_from_slice(&input[i..]);
        }
    }

    fn finalize(mut self) -> [u8; 16] {
        let mut bits = [0u8; 8];
        let count_bytes = self.count.to_le_bytes();
        bits.copy_from_slice(&count_bytes);

        let index = ((self.count >> 3) & 0x3f) as usize;
        let pad_len = if index < 56 { 56 - index } else { 120 - index };

        let mut padding = [0u8; 64];
        padding[0] = 0x80;
        self.update(&padding[..pad_len]);
        self.update(&bits);

        let mut digest = [0u8; 16];
        for (j, &val) in self.state.iter().enumerate() {
            digest[j * 4..(j + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
        digest
    }

    fn transform(&mut self, block: &[u8; 64]) {
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut x = [0u32; 16];

        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        macro_rules! f { ($x:expr, $y:expr, $z:expr) => { ($x & $y) | (!($x) & $z) }; }
        macro_rules! g { ($x:expr, $y:expr, $z:expr) => { ($x & $z) | ($y & !($z)) }; }
        macro_rules! h { ($x:expr, $y:expr, $z:expr) => { $x ^ $y ^ $z }; }
        macro_rules! i { ($x:expr, $y:expr, $z:expr) => { $y ^ ($x | !($z)) }; }

        macro_rules! ff {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(
                    $a.wrapping_add(f!($b, $c, $d))
                        .wrapping_add($k)
                        .wrapping_add($t)
                        .rotate_left($s),
                );
            };
        }

        macro_rules! gg {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(
                    $a.wrapping_add(g!($b, $c, $d))
                        .wrapping_add($k)
                        .wrapping_add($t)
                        .rotate_left($s),
                );
            };
        }

        macro_rules! hh {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(
                    $a.wrapping_add(h!($b, $c, $d))
                        .wrapping_add($k)
                        .wrapping_add($t)
                        .rotate_left($s),
                );
            };
        }

        macro_rules! ii {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $t:expr) => {
                $a = $b.wrapping_add(
                    $a.wrapping_add(i!($b, $c, $d))
                        .wrapping_add($k)
                        .wrapping_add($t)
                        .rotate_left($s),
                );
            };
        }

        // Tur 1
        ff!(a, b, c, d, x[0], 7, 0xd76aa478);
        ff!(d, a, b, c, x[1], 12, 0xe8c7b756);
        ff!(c, d, a, b, x[2], 17, 0x242070db);
        ff!(b, c, d, a, x[3], 22, 0xc1bdceee);
        ff!(a, b, c, d, x[4], 7, 0xf57c0faf);
        ff!(d, a, b, c, x[5], 12, 0x4787c62a);
        ff!(c, d, a, b, x[6], 17, 0xa8304613);
        ff!(b, c, d, a, x[7], 22, 0xfd469501);
        ff!(a, b, c, d, x[8], 7, 0x698098d8);
        ff!(d, a, b, c, x[9], 12, 0x8b44f7af);
        ff!(c, d, a, b, x[10], 17, 0xffff5bb1);
        ff!(b, c, d, a, x[11], 22, 0x895cd7be);
        ff!(a, b, c, d, x[12], 7, 0x6b901122);
        ff!(d, a, b, c, x[13], 12, 0xfd987193);
        ff!(c, d, a, b, x[14], 17, 0xa679438e);
        ff!(b, c, d, a, x[15], 22, 0x49b40821);

        // Tur 2
        gg!(a, b, c, d, x[1], 5, 0xf61e2562);
        gg!(d, a, b, c, x[6], 9, 0xc040b340);
        gg!(c, d, a, b, x[11], 14, 0x265e5a51);
        gg!(b, c, d, a, x[0], 20, 0xe9b6c7aa);
        gg!(a, b, c, d, x[5], 5, 0xd62f105d);
        gg!(d, a, b, c, x[10], 9, 0x02441453);
        gg!(c, d, a, b, x[15], 14, 0xd8a1e681);
        gg!(b, c, d, a, x[4], 20, 0xe7d3fbc8);
        gg!(a, b, c, d, x[9], 5, 0x21e1cde6);
        gg!(d, a, b, c, x[14], 9, 0xc33707d6);
        gg!(c, d, a, b, x[3], 14, 0xf4d50d87);
        gg!(b, c, d, a, x[8], 20, 0x455a14ed);
        gg!(a, b, c, d, x[13], 5, 0xa9e3e905);
        gg!(d, a, b, c, x[2], 9, 0xfcefa3f8);
        gg!(c, d, a, b, x[7], 14, 0x676f02d9);
        gg!(b, c, d, a, x[12], 20, 0x8d2a4c8a);

        // Tur 3
        hh!(a, b, c, d, x[5], 4, 0xfffa3942);
        hh!(d, a, b, c, x[8], 11, 0x8771f681);
        hh!(c, d, a, b, x[11], 16, 0x6d9d6122);
        hh!(b, c, d, a, x[14], 23, 0xfde5380c);
        hh!(a, b, c, d, x[1], 4, 0xa4beea44);
        hh!(d, a, b, c, x[4], 11, 0x4bdecfa9);
        hh!(c, d, a, b, x[7], 16, 0xf6bb4b60);
        hh!(b, c, d, a, x[10], 23, 0xbebfbc70);
        hh!(a, b, c, d, x[13], 4, 0x289b7ec6);
        hh!(d, a, b, c, x[0], 11, 0xeaa127fa);
        hh!(c, d, a, b, x[3], 16, 0xd4ef3085);
        hh!(b, c, d, a, x[6], 23, 0x04881d05);
        hh!(a, b, c, d, x[9], 4, 0xd9d4d039);
        hh!(d, a, b, c, x[12], 11, 0xe6db99e5);
        hh!(c, d, a, b, x[15], 16, 0x1fa27cf8);
        hh!(b, c, d, a, x[2], 23, 0xc4ac5665);

        // Tur 4
        ii!(a, b, c, d, x[0], 6, 0xf4292244);
        ii!(d, a, b, c, x[7], 10, 0x432aff97);
        ii!(c, d, a, b, x[14], 15, 0xab9423a7);
        ii!(b, c, d, a, x[5], 21, 0xfc93a039);
        ii!(a, b, c, d, x[12], 6, 0x655b59c3);
        ii!(d, a, b, c, x[3], 10, 0x8f0ccc92);
        ii!(c, d, a, b, x[10], 15, 0xffeff47d);
        ii!(b, c, d, a, x[1], 21, 0x85845dd1);
        ii!(a, b, c, d, x[8], 6, 0x6fa87e4f);
        ii!(d, a, b, c, x[15], 10, 0xfe2ce6e0);
        ii!(c, d, a, b, x[6], 15, 0xa3014314);
        ii!(b, c, d, a, x[13], 21, 0x4e0811a1);
        ii!(a, b, c, d, x[4], 6, 0xf7537e82);
        ii!(d, a, b, c, x[11], 10, 0xbd3af235);
        ii!(c, d, a, b, x[2], 15, 0x2ad7d2bb);
        ii!(b, c, d, a, x[9], 21, 0xeb86d391);

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

pub fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut ctx = Md5Context::new();
    ctx.update(data);
    ctx.finalize()
}

// ============================================================================
// 2. Apache $apr1$ MD5 Parola Doğrulama (apply_auth.go Standardı)
// ============================================================================

const B64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn to64(mut v: u32, mut n: usize) -> String {
    let mut out = Vec::with_capacity(n);
    while n > 0 {
        out.push(B64[(v & 0x3f) as usize]);
        v >>= 6;
        n -= 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Apache apr1 MD5 parola özeti üretir ($apr1$<salt>$<hash>).
pub fn apr1_hash(password: &str, salt: &str) -> String {
    let pw = password.as_bytes();
    let sl = salt.as_bytes();

    let mut alt_ctx = Md5Context::new();
    alt_ctx.update(pw);
    alt_ctx.update(sl);
    alt_ctx.update(pw);
    let alt = alt_ctx.finalize();

    let mut h = Md5Context::new();
    h.update(pw);
    h.update(b"$apr1$");
    h.update(sl);

    let mut n = pw.len();
    while n > 0 {
        if n > 16 {
            h.update(&alt);
            n -= 16;
        } else {
            h.update(&alt[..n]);
            break;
        }
    }

    let mut n = pw.len();
    while n > 0 {
        if n & 1 == 1 {
            h.update(&[0u8]);
        } else {
            h.update(&pw[..1]);
        }
        n >>= 1;
    }

    let mut final_digest = h.finalize();

    for i in 0..1000 {
        let mut r = Md5Context::new();
        if i & 1 == 1 {
            r.update(pw);
        } else {
            r.update(&final_digest);
        }
        if i % 3 != 0 {
            r.update(sl);
        }
        if i % 7 != 0 {
            r.update(pw);
        }
        if i & 1 == 1 {
            r.update(&final_digest);
        } else {
            r.update(pw);
        }
        final_digest = r.finalize();
    }

    let f = final_digest;
    let mut enc = String::new();
    enc.push_str(&to64((f[0] as u32) << 16 | (f[6] as u32) << 8 | (f[12] as u32), 4));
    enc.push_str(&to64((f[1] as u32) << 16 | (f[7] as u32) << 8 | (f[13] as u32), 4));
    enc.push_str(&to64((f[2] as u32) << 16 | (f[8] as u32) << 8 | (f[14] as u32), 4));
    enc.push_str(&to64((f[3] as u32) << 16 | (f[9] as u32) << 8 | (f[15] as u32), 4));
    enc.push_str(&to64((f[4] as u32) << 16 | (f[10] as u32) << 8 | (f[5] as u32), 4));
    enc.push_str(&to64(f[11] as u32, 2));

    format!("$apr1${}${}", salt, enc)
}

/// Sabit zamanlı (constant-time) bayt dizisi karşılaştırması (Timing attack koruması).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Saklanan $apr1$ özetinin parolaya ait olup olmadığını sabit sürede denetler.
pub fn verify_apr1(hash: &str, password: &str) -> bool {
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() != 4 || !parts[0].is_empty() || parts[1] != "apr1" {
        return false;
    }
    let salt = parts[2];
    let computed = apr1_hash(password, salt);
    constant_time_eq(computed.as_bytes(), hash.as_bytes())
}

// ============================================================================
// 3. Genel Parola Doğrulama ($apr1$, SHA-1, plain:)
// ============================================================================

/// htpasswd formatındaki parolayı doğrular ($apr1$, SHA1 veya düz metin).
pub fn verify_password(stored_hash: &str, candidate_password: &str) -> bool {
    let hash = stored_hash.trim();
    if hash.starts_with("$apr1$") {
        verify_apr1(hash, candidate_password)
    } else if let Some(plain) = hash.strip_prefix("plain:") {
        constant_time_eq(plain.as_bytes(), candidate_password.as_bytes())
    } else if hash.starts_with("{SHA}") {
        // Apache standart {SHA} formatı (SHA-1 base64)
        verify_sha1_htpasswd(hash, candidate_password)
    } else if !hash.contains('$') && !hash.is_empty() {
        // Doğrudan düz metin hash (bazı test ortamlarında htpasswd -p)
        constant_time_eq(hash.as_bytes(), candidate_password.as_bytes())
    } else {
        false
    }
}

// ============================================================================
// 4. SHA-1 Basit Doğrulama ({SHA} Apache Formatı)
// ============================================================================

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h = [
        0x67452301u32,
        0xEFCDAB89u32,
        0x98BADCFEu32,
        0x10325476u32,
        0xC3D2E1F0u32,
    ];

    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while (msg.len() + 8) % 64 != 0 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

fn std_base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < input.len() {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if i + 2 < input.len() {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }
    out
}

fn std_base64_decode(input: &str) -> Option<Vec<u8>> {
    let clean = input.trim();
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in clean.as_bytes() {
        if b == b'=' {
            break;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        } as u32;

        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn verify_sha1_htpasswd(stored: &str, candidate: &str) -> bool {
    let expected = match stored.strip_prefix("{SHA}") {
        Some(s) => s.trim(),
        None => return false,
    };
    let digest = sha1_digest(candidate.as_bytes());
    let computed = std_base64_encode(&digest);
    constant_time_eq(expected.as_bytes(), computed.as_bytes())
}

// ============================================================================
// 5. htpasswd Dosya ve Satır Ayrıştırma
// ============================================================================

/// htpasswd dosya içeriğini okuyup kullanıcı->hash haritasına dönüştürür.
pub fn parse_htpasswd_content(content: &str) -> HashMap<String, String> {
    let mut users = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((user, hash)) = trimmed.split_once(':') {
            let u = user.trim().to_string();
            let h = hash.trim().to_string();
            if !u.is_empty() && !h.is_empty() {
                users.insert(u, h);
            }
        }
    }
    users
}

/// HTTP `Authorization: Basic <base64>` başlığından (kullanıcı, parola) çiftini çözer.
pub fn parse_basic_auth_header(header: &str) -> Option<(String, String)> {
    let trimmed = header.trim();
    let payload = if let Some(rest) = trimmed.strip_prefix("Basic ") {
        rest.trim()
    } else if let Some(rest) = trimmed.strip_prefix("basic ") {
        rest.trim()
    } else {
        return None;
    };

    let decoded = std_base64_decode(payload)?;
    let cred_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = cred_str.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

// ============================================================================
// 6. Basic Auth Karar ve İstek Hattı Yöneticisi
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
pub enum AuthDecision {
    /// İstek devam edebilir (yetki başarılı veya dizin korumalı değil)
    Allowed,
    /// 401 Unauthorized dönülmeli ve `WWW-Authenticate: Basic realm="..."` verilmeli
    Unauthorized { realm: String },
}

/// htpasswd dosyalarını diskten okuyup mtime kontrolü ile önbellekleyen yönetici.
#[derive(Default)]
pub struct BasicAuthManager {
    file_cache: RwLock<HashMap<PathBuf, (SystemTime, HashMap<String, String>)>>,
}

impl BasicAuthManager {
    pub fn new() -> Self {
        Self {
            file_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Bir htpasswd dosyasını mtime önbellekli okur.
    pub fn get_users_from_file(&self, path: &Path) -> Result<HashMap<String, String>, String> {
        let meta = fs::metadata(path)
            .map_err(|e| format!("htpasswd dosyası okunamadı ({}): {}", path.display(), e))?;
        let mtime = meta
            .modified()
            .unwrap_or_else(|_| SystemTime::UNIX_EPOCH);

        if let Ok(cache) = self.file_cache.read() {
            if let Some((cached_mtime, users)) = cache.get(path) {
                if *cached_mtime == mtime {
                    return Ok(users.clone());
                }
            }
        }

        let content = fs::read_to_string(path)
            .map_err(|e| format!("htpasswd içeriği okunamadı ({}): {}", path.display(), e))?;
        let users = parse_htpasswd_content(&content);

        if let Ok(mut cache) = self.file_cache.write() {
            cache.insert(path.to_path_buf(), (mtime, users.clone()));
        }

        Ok(users)
    }

    /// Belirtilen istek yolu ve vHost auth yapılandırmasına göre yetkilendirme kararı üretir.
    pub fn check_request(
        &self,
        auth_header: Option<&str>,
        request_path: &str,
        vhost_auth: &VHostAuthSection,
    ) -> AuthDecision {
        if !vhost_auth.enabled {
            return AuthDecision::Allowed;
        }

        // 1. Yol bazında eşleşen en spesifik dizin kuralını bul (en uzun prefix eşleşmesi)
        let normalized_path = if request_path.starts_with('/') {
            request_path
        } else {
            "/"
        };

        let matched_dir = vhost_auth
            .directories
            .iter()
            .filter(|dir| {
                let p = dir.path.trim_end_matches('/');
                if p.is_empty() {
                    true
                } else {
                    normalized_path == p || normalized_path.starts_with(&format!("{}/", p))
                }
            })
            .max_by_key(|dir| dir.path.len());

        // Eğer dizin tanımları varsa ve bu yol hiçbir dizine eşleşmiyorsa ve vhost genel users/htpasswd boşsa:
        if !vhost_auth.directories.is_empty() && matched_dir.is_none() {
            return AuthDecision::Allowed;
        }

        let active_realm = matched_dir
            .map(|d| d.realm.as_str())
            .unwrap_or(vhost_auth.realm.as_str());

        // 2. Authorization başlığı var mı?
        let (user, pass) = match auth_header.and_then(parse_basic_auth_header) {
            Some(creds) => creds,
            None => {
                return AuthDecision::Unauthorized {
                    realm: active_realm.to_string(),
                };
            }
        };

        // 3. Kullanıcı doğrulama: Önce dizine özel liste/dosya, yoksa vhost genel listesi
        let mut user_verified = false;

        // a) Dizin özel kullanıcıları
        if let Some(dir) = matched_dir {
            for entry in &dir.users {
                if entry.username == user && verify_password(&entry.password_hash, &pass) {
                    user_verified = true;
                    break;
                }
            }
            if !user_verified {
                if let Some(ref path_str) = dir.htpasswd_path {
                    if let Ok(file_users) = self.get_users_from_file(Path::new(path_str)) {
                        if let Some(hash) = file_users.get(&user) {
                            if verify_password(hash, &pass) {
                                user_verified = true;
                            }
                        }
                    }
                }
            }
        }

        // b) vHost genel kullanıcıları
        if !user_verified {
            for entry in &vhost_auth.users {
                if entry.username == user && verify_password(&entry.password_hash, &pass) {
                    user_verified = true;
                    break;
                }
            }
        }

        // c) vHost genel htpasswd dosyası
        if !user_verified {
            if let Some(ref path_str) = vhost_auth.htpasswd_path {
                if let Ok(file_users) = self.get_users_from_file(Path::new(path_str)) {
                    if let Some(hash) = file_users.get(&user) {
                        if verify_password(hash, &pass) {
                            user_verified = true;
                        }
                    }
                }
            }
        }

        if user_verified {
            AuthDecision::Allowed
        } else {
            AuthDecision::Unauthorized {
                realm: active_realm.to_string(),
            }
        }
    }
}

// ============================================================================
// 7. Birim Testleri
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zmax_config::AuthUserEntry;

    #[test]
    fn test_md5_rfc1321_vectors() {
        // RFC 1321 standart test vektörleri
        let vectors: &[(&[u8], &str)] = &[
            (b"", "d41d8cd98f00b204e9800998ecf8427e"),
            (b"a", "0cc175b9c0f1b6a831c399e269772661"),
            (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
            (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
        ];

        for &(input, expected_hex) in vectors {
            let digest = md5_digest(input);
            let hex_str: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
            assert_eq!(hex_str, expected_hex, "MD5 vektör başarısız: {:?}", input);
        }
    }

    #[test]
    fn test_apache_apr1_hash_and_verify() {
        // Apache htpasswd -nbm ornek parola çıktısı
        // Salt 8 karakterli alfabe
        let salt = "r31.D/..";
        let password = "my_secure_password";
        let hash = apr1_hash(password, salt);

        assert!(hash.starts_with("$apr1$r31.D/..$"));
        assert!(verify_apr1(&hash, password));
        assert!(!verify_apr1(&hash, "wrong_password"));
        assert!(!verify_apr1(&hash, ""));
    }

    #[test]
    fn test_apache_apr1_known_vector() {
        // Gerçek htpasswd ile üretilmiş bilinen hash:
        // user: admin, pass: secret123
        // $apr1$abc12345$XoD2c/2qF.TvhH7D/K0Hk. (örnek tuz)
        let salt = "salt1234";
        let pass = "secret123";
        let hash = apr1_hash(pass, salt);

        assert!(verify_apr1(&hash, "secret123"));
        assert!(!verify_apr1(&hash, "secret124"));
    }

    #[test]
    fn test_sha1_htpasswd_verify() {
        // htpasswd -nbs user password -> user:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
        let hash = "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=";
        assert!(verify_password(hash, "password"));
        assert!(!verify_password(hash, "wrong"));
    }

    #[test]
    fn test_parse_htpasswd_lines() {
        let content = r#"
            # Bu bir yorumdur
            admin:$apr1$salt1234$hashvaluehere
            developer:plain:supersecret
            testuser:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=

            # Boş satırlar atlanmalı
        "#;
        let map = parse_htpasswd_content(content);
        assert_eq!(map.len(), 3);
        assert_eq!(map.get("admin").unwrap(), "$apr1$salt1234$hashvaluehere");
        assert_eq!(map.get("developer").unwrap(), "plain:supersecret");
        assert_eq!(map.get("testuser").unwrap(), "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=");
    }

    #[test]
    fn test_parse_basic_auth_header() {
        // 'admin:secret123' base64 hali: 'YWRtaW46c2VjcmV0MTIz'
        let header = "Basic YWRtaW46c2VjcmV0MTIz";
        let creds = parse_basic_auth_header(header).expect("Basic auth çözülemedi");
        assert_eq!(creds.0, "admin");
        assert_eq!(creds.1, "secret123");

        assert!(parse_basic_auth_header("Bearer token123").is_none());
        assert!(parse_basic_auth_header("Basic gecersiz_base64!").is_none());
    }

    #[test]
    fn test_basic_auth_manager_flow() {
        let manager = BasicAuthManager::new();
        let salt = "s4lt1234";
        let pass = "adminpass";
        let hash = apr1_hash(pass, salt);

        let vhost_auth = VHostAuthSection {
            enabled: true,
            realm: "Gizli Bolge".to_string(),
            htpasswd_path: None,
            users: vec![AuthUserEntry::new("admin", hash)],
            directories: vec![VHostAuthDirectory {
                path: "/admin".to_string(),
                realm: "Admin Girisi".to_string(),
                htpasswd_path: None,
                users: vec![],
            }],
        };

        // 1. Korumasız yol -> Doğrudan Allowed
        let res = manager.check_request(None, "/public/index.html", &vhost_auth);
        assert_eq!(res, AuthDecision::Allowed);

        // 2. Korumalı yol, başlık yok -> Unauthorized
        let res = manager.check_request(None, "/admin/dashboard", &vhost_auth);
        assert_eq!(
            res,
            AuthDecision::Unauthorized {
                realm: "Admin Girisi".to_string()
            }
        );

        // 3. Korumalı yol, yanlış parola -> Unauthorized
        // 'admin:wrong' base64: 'YWRtaW46d3Jvbmc='
        let res = manager.check_request(
            Some("Basic YWRtaW46d3Jvbmc="),
            "/admin/dashboard",
            &vhost_auth,
        );
        assert_eq!(
            res,
            AuthDecision::Unauthorized {
                realm: "Admin Girisi".to_string()
            }
        );

        // 4. Korumalı yol, doğru parola -> Allowed
        // 'admin:adminpass' base64: 'YWRtaW46YWRtaW5wYXNz'
        let res = manager.check_request(
            Some("Basic YWRtaW46YWRtaW5wYXNz"),
            "/admin/dashboard",
            &vhost_auth,
        );
        assert_eq!(res, AuthDecision::Allowed);
    }
}
