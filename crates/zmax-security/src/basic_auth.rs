//! ZMax Basic Authentication, Apache htpasswd ($apr1$) ve Argon2id Doğrulama Modülü
//!
//! Apache htpasswd formatı (`$apr1$` Apache MD5, `{SHA}` SHA-1, `plain:`) ve
//! modern PHC `$argon2id$` (RFC 9106) özetlerini saf Rust ile çevrimdışı doğrular.
//! Sabit zamanlı karşılaştırma (constant-time) uygulanır; parolalar ve kimlik
//! başlıkları asla günlük veya hata çıktılarına yazılmaz.

use dashmap::DashMap;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};
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

        macro_rules! f {
            ($x:expr, $y:expr, $z:expr) => {
                ($x & $y) | (!($x) & $z)
            };
        }
        macro_rules! g {
            ($x:expr, $y:expr, $z:expr) => {
                ($x & $z) | ($y & !($z))
            };
        }
        macro_rules! h {
            ($x:expr, $y:expr, $z:expr) => {
                $x ^ $y ^ $z
            };
        }
        macro_rules! i {
            ($x:expr, $y:expr, $z:expr) => {
                $y ^ ($x | !($z))
            };
        }

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

/// Apache apr1 MD5 parola özeti üretir (`$apr1$<salt>$<hash>`).
pub fn apr1_hash(password: &str, salt: &str) -> String {
    let pw = password.as_bytes();
    let salt_len = salt.len().min(8);
    let sl = &salt.as_bytes()[..salt_len];
    let effective_salt = std::str::from_utf8(sl).unwrap_or("");

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
    enc.push_str(&to64(
        (f[0] as u32) << 16 | (f[6] as u32) << 8 | (f[12] as u32),
        4,
    ));
    enc.push_str(&to64(
        (f[1] as u32) << 16 | (f[7] as u32) << 8 | (f[13] as u32),
        4,
    ));
    enc.push_str(&to64(
        (f[2] as u32) << 16 | (f[8] as u32) << 8 | (f[14] as u32),
        4,
    ));
    enc.push_str(&to64(
        (f[3] as u32) << 16 | (f[9] as u32) << 8 | (f[15] as u32),
        4,
    ));
    enc.push_str(&to64(
        (f[4] as u32) << 16 | (f[10] as u32) << 8 | (f[5] as u32),
        4,
    ));
    enc.push_str(&to64(f[11] as u32, 2));

    format!("$apr1${}${}", effective_salt, enc)
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

/// Saklanan `$apr1$` özetinin parolaya ait olup olmadığını sabit sürede denetler.
pub fn verify_apr1(hash: &str, password: &str) -> bool {
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() != 4 || !parts[0].is_empty() || parts[1] != "apr1" {
        return false;
    }
    let salt = parts[2];
    let digest = parts[3];
    if salt.is_empty() || salt.len() > 8 || digest.len() != 22 {
        return false;
    }
    if !salt.bytes().all(|b| B64.contains(&b)) || !digest.bytes().all(|b| B64.contains(&b)) {
        return false;
    }
    let computed = apr1_hash(password, salt);
    constant_time_eq(computed.as_bytes(), hash.as_bytes())
}

// ============================================================================
// 3. RFC 7693 BLAKE2b ve RFC 9106 Argon2id Gerçeklemesi (Saf Rust)
// ============================================================================

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t_lo: u64, t_hi: u64, is_last: bool) {
    let mut m = [0u64; 16];
    for (i, slot) in m.iter_mut().enumerate() {
        let off = i * 8;
        *slot = u64::from_le_bytes([
            block[off],
            block[off + 1],
            block[off + 2],
            block[off + 3],
            block[off + 4],
            block[off + 5],
            block[off + 6],
            block[off + 7],
        ]);
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t_lo;
    v[13] ^= t_hi;
    if is_last {
        v[14] = !v[14];
    }

    for s in &BLAKE2B_SIGMA {
        blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

        blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// RFC 7693 BLAKE2b özet fonksiyonu (`1 <= outlen <= 64`).
pub fn blake2b(outlen: usize, key: &[u8], data: &[u8]) -> Vec<u8> {
    let outlen = outlen.clamp(1, 64);
    let keylen = key.len().min(64);
    let mut h = BLAKE2B_IV;
    h[0] ^= 0x0101_0000 ^ ((keylen as u64) << 8) ^ (outlen as u64);

    let mut total: u128 = 0;
    let mut blocks: Vec<[u8; 128]> = Vec::new();
    if keylen > 0 {
        let mut kb = [0u8; 128];
        kb[..keylen].copy_from_slice(&key[..keylen]);
        blocks.push(kb);
    }

    if data.is_empty() && blocks.is_empty() {
        blake2b_compress(&mut h, &[0u8; 128], 0, 0, true);
    } else {
        let mut off = 0usize;
        if blocks.is_empty() {
            while off + 128 < data.len() {
                let mut blk = [0u8; 128];
                blk.copy_from_slice(&data[off..off + 128]);
                total += 128;
                blake2b_compress(&mut h, &blk, total as u64, (total >> 64) as u64, false);
                off += 128;
            }
            let rem = data.len() - off;
            let mut last = [0u8; 128];
            last[..rem].copy_from_slice(&data[off..]);
            total += rem as u128;
            blake2b_compress(&mut h, &last, total as u64, (total >> 64) as u64, true);
        } else {
            let kb = blocks[0];
            total += 128;
            if data.is_empty() {
                blake2b_compress(&mut h, &kb, total as u64, (total >> 64) as u64, true);
            } else {
                blake2b_compress(&mut h, &kb, total as u64, (total >> 64) as u64, false);
                while off + 128 < data.len() {
                    let mut blk = [0u8; 128];
                    blk.copy_from_slice(&data[off..off + 128]);
                    total += 128;
                    blake2b_compress(&mut h, &blk, total as u64, (total >> 64) as u64, false);
                    off += 128;
                }
                let rem = data.len() - off;
                let mut last = [0u8; 128];
                last[..rem].copy_from_slice(&data[off..]);
                total += rem as u128;
                blake2b_compress(&mut h, &last, total as u64, (total >> 64) as u64, true);
            }
        }
    }

    let mut out = Vec::with_capacity(outlen);
    for word in &h {
        let bytes = word.to_le_bytes();
        let take = (outlen - out.len()).min(8);
        out.extend_from_slice(&bytes[..take]);
        if out.len() >= outlen {
            break;
        }
    }
    out
}

/// RFC 9106 Bölüm 3.3 değişken uzunluklu H' (BLAKE2b-long) fonksiyonu.
fn blake2b_long(outlen: usize, input: &[u8]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(4 + input.len());
    seed.extend_from_slice(&(outlen as u32).to_le_bytes());
    seed.extend_from_slice(input);

    if outlen <= 64 {
        return blake2b(outlen, &[], &seed);
    }

    let mut out = Vec::with_capacity(outlen);
    let mut v = blake2b(64, &[], &seed);
    out.extend_from_slice(&v[..32]);
    let mut remaining = outlen - 32;

    while remaining > 64 {
        v = blake2b(64, &[], &v);
        out.extend_from_slice(&v[..32]);
        remaining -= 32;
    }

    let last = blake2b(remaining, &[], &v);
    out.extend_from_slice(&last);
    out
}

#[inline]
fn fblamka(x: u64, y: u64) -> u64 {
    let xy = (x as u32 as u64).wrapping_mul(y as u32 as u64);
    x.wrapping_add(y).wrapping_add(xy.wrapping_shl(1))
}

#[inline]
fn argon2_gb(v: &mut [u64; 128], i0: usize, i1: usize, i2: usize, i3: usize) {
    v[i0] = fblamka(v[i0], v[i1]);
    v[i3] = (v[i3] ^ v[i0]).rotate_right(32);
    v[i2] = fblamka(v[i2], v[i3]);
    v[i1] = (v[i1] ^ v[i2]).rotate_right(24);
    v[i0] = fblamka(v[i0], v[i1]);
    v[i3] = (v[i3] ^ v[i0]).rotate_right(16);
    v[i2] = fblamka(v[i2], v[i3]);
    v[i1] = (v[i1] ^ v[i2]).rotate_right(63);
}

#[inline]
fn argon2_p(v: &mut [u64; 128], idx: [usize; 16]) {
    argon2_gb(v, idx[0], idx[4], idx[8], idx[12]);
    argon2_gb(v, idx[1], idx[5], idx[9], idx[13]);
    argon2_gb(v, idx[2], idx[6], idx[10], idx[14]);
    argon2_gb(v, idx[3], idx[7], idx[11], idx[15]);

    argon2_gb(v, idx[0], idx[5], idx[10], idx[15]);
    argon2_gb(v, idx[1], idx[6], idx[11], idx[12]);
    argon2_gb(v, idx[2], idx[7], idx[8], idx[13]);
    argon2_gb(v, idx[3], idx[4], idx[9], idx[14]);
}

/// RFC 9106 Bölüm 3.5 Argon2 `G(X, Y)` sıkıştırma fonksiyonu.
fn argon2_compress_g(x: &[u64; 128], y: &[u64; 128]) -> [u64; 128] {
    let mut r = [0u64; 128];
    for i in 0..128 {
        r[i] = x[i] ^ y[i];
    }
    let mut z = r;

    // 8 satır (her biri 16 u64)
    for row in 0..8 {
        let base = row * 16;
        argon2_p(
            &mut z,
            [
                base,
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9,
                base + 10,
                base + 11,
                base + 12,
                base + 13,
                base + 14,
                base + 15,
            ],
        );
    }

    // 8 sütun (her biri 2'şer u64 x 8 satır)
    for col in 0..8 {
        let b = col * 2;
        argon2_p(
            &mut z,
            [
                b,
                b + 1,
                16 + b,
                16 + b + 1,
                32 + b,
                32 + b + 1,
                48 + b,
                48 + b + 1,
                64 + b,
                64 + b + 1,
                80 + b,
                80 + b + 1,
                96 + b,
                96 + b + 1,
                112 + b,
                112 + b + 1,
            ],
        );
    }

    for i in 0..128 {
        z[i] ^= r[i];
    }
    z
}

fn le_bytes_to_block(bytes: &[u8]) -> [u64; 128] {
    let mut blk = [0u64; 128];
    for (i, slot) in blk.iter_mut().enumerate() {
        let off = i * 8;
        *slot = u64::from_le_bytes([
            bytes[off],
            bytes[off + 1],
            bytes[off + 2],
            bytes[off + 3],
            bytes[off + 4],
            bytes[off + 5],
            bytes[off + 6],
            bytes[off + 7],
        ]);
    }
    blk
}

fn block_to_le_bytes(blk: &[u64; 128]) -> [u8; 1024] {
    let mut out = [0u8; 1024];
    for (i, word) in blk.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

const ARGON2_TYPE_ID: u32 = 2;
const ARGON2_VERSION: u32 = 0x13;
const MAX_ARGON2_MEMORY_KIB: u32 = 262_144; // 256 MiB DoS koruma sınırı
const MAX_ARGON2_TIME_COST: u32 = 32;
const MAX_ARGON2_PARALLELISM: u32 = 16;

/// RFC 9106 Argon2id ham anahtar türetme fonksiyonu.
#[allow(clippy::too_many_arguments)]
pub fn argon2id_raw(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    t_cost: u32,
    m_cost_kib: u32,
    parallelism: u32,
    tag_len: usize,
) -> Result<Vec<u8>, &'static str> {
    if parallelism == 0 || parallelism > MAX_ARGON2_PARALLELISM {
        return Err("Argon2id paralellik değeri sınır dışında");
    }
    if t_cost == 0 || t_cost > MAX_ARGON2_TIME_COST {
        return Err("Argon2id yineleme sayısı sınır dışında");
    }
    if m_cost_kib < 8 * parallelism || m_cost_kib > MAX_ARGON2_MEMORY_KIB {
        return Err("Argon2id bellek maliyeti sınır dışında");
    }
    if salt.len() < 4 || salt.len() > 64 {
        return Err("Argon2id tuz uzunluğu sınır dışında");
    }
    if !(4..=128).contains(&tag_len) {
        return Err("Argon2id çıktı uzunluğu sınır dışında");
    }

    let lanes = parallelism as usize;
    let memory_blocks = 4 * lanes * ((m_cost_kib as usize) / (4 * lanes));
    let lane_len = memory_blocks / lanes;
    let segment_len = lane_len / 4;

    // H_0 hesabı (RFC 9106 Bölüm 3.2)
    let mut h0_in =
        Vec::with_capacity(40 + password.len() + salt.len() + secret.len() + associated_data.len());
    h0_in.extend_from_slice(&parallelism.to_le_bytes());
    h0_in.extend_from_slice(&(tag_len as u32).to_le_bytes());
    h0_in.extend_from_slice(&m_cost_kib.to_le_bytes());
    h0_in.extend_from_slice(&t_cost.to_le_bytes());
    h0_in.extend_from_slice(&ARGON2_VERSION.to_le_bytes());
    h0_in.extend_from_slice(&ARGON2_TYPE_ID.to_le_bytes());
    h0_in.extend_from_slice(&(password.len() as u32).to_le_bytes());
    h0_in.extend_from_slice(password);
    h0_in.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    h0_in.extend_from_slice(salt);
    h0_in.extend_from_slice(&(secret.len() as u32).to_le_bytes());
    h0_in.extend_from_slice(secret);
    h0_in.extend_from_slice(&(associated_data.len() as u32).to_le_bytes());
    h0_in.extend_from_slice(associated_data);
    let h0 = blake2b(64, &[], &h0_in);

    let mut mem = vec![[0u64; 128]; memory_blocks];
    let mut init_buf = [0u8; 72];
    init_buf[..64].copy_from_slice(&h0);

    for lane in 0..lanes {
        init_buf[64..68].copy_from_slice(&0u32.to_le_bytes());
        init_buf[68..72].copy_from_slice(&(lane as u32).to_le_bytes());
        mem[lane * lane_len] = le_bytes_to_block(&blake2b_long(1024, &init_buf));

        init_buf[64..68].copy_from_slice(&1u32.to_le_bytes());
        init_buf[68..72].copy_from_slice(&(lane as u32).to_le_bytes());
        mem[lane * lane_len + 1] = le_bytes_to_block(&blake2b_long(1024, &init_buf));
    }

    let zero_block = [0u64; 128];

    for pass in 0..t_cost {
        for slice in 0..4usize {
            let data_independent = pass == 0 && slice < 2;
            let starting_index = if pass == 0 && slice == 0 { 2 } else { 0 };

            for lane in 0..lanes {
                let mut addr_block = [0u64; 128];
                let mut pseudo_rand_block = [0u64; 128];
                if data_independent {
                    addr_block[0] = pass as u64;
                    addr_block[1] = lane as u64;
                    addr_block[2] = slice as u64;
                    addr_block[3] = memory_blocks as u64;
                    addr_block[4] = t_cost as u64;
                    addr_block[5] = ARGON2_TYPE_ID as u64;
                }

                for index in starting_index..segment_len {
                    if data_independent && (index == starting_index || index % 128 == 0) {
                        addr_block[6] += 1;
                        let tmp = argon2_compress_g(&zero_block, &addr_block);
                        pseudo_rand_block = argon2_compress_g(&zero_block, &tmp);
                    }

                    let curr_offset = slice * segment_len + index;
                    let prev_offset = if curr_offset == 0 {
                        lane_len - 1
                    } else {
                        curr_offset - 1
                    };

                    let pseudo_rand = if data_independent {
                        pseudo_rand_block[index % 128]
                    } else {
                        mem[lane * lane_len + prev_offset][0]
                    };

                    let j1 = (pseudo_rand & 0xFFFF_FFFF) as u64;
                    let j2 = (pseudo_rand >> 32) as u64;

                    let ref_lane = if pass == 0 && slice == 0 {
                        lane
                    } else {
                        (j2 as usize) % lanes
                    };

                    let w = if pass == 0 {
                        if slice == 0 || ref_lane == lane {
                            slice * segment_len + index - 1
                        } else if index == 0 {
                            slice * segment_len - 1
                        } else {
                            slice * segment_len
                        }
                    } else if ref_lane == lane {
                        lane_len - segment_len + index - 1
                    } else if index == 0 {
                        lane_len - segment_len - 1
                    } else {
                        lane_len - segment_len
                    };

                    let x = (j1 * j1) >> 32;
                    let y = ((w as u64) * x) >> 32;
                    let rel_pos = (w as u64) - 1 - y;
                    let start_pos = if pass == 0 || slice == 3 {
                        0
                    } else {
                        (slice + 1) * segment_len
                    };
                    let ref_index = (start_pos + (rel_pos as usize)) % lane_len;

                    let prev_blk = &mem[lane * lane_len + prev_offset];
                    let ref_blk = &mem[ref_lane * lane_len + ref_index];
                    let next_blk = argon2_compress_g(prev_blk, ref_blk);

                    let curr_slot = &mut mem[lane * lane_len + curr_offset];
                    if pass == 0 {
                        *curr_slot = next_blk;
                    } else {
                        for k in 0..128 {
                            curr_slot[k] ^= next_blk[k];
                        }
                    }
                }
            }
        }
    }

    let mut final_blk = mem[lane_len - 1];
    for lane in 1..lanes {
        let last = &mem[lane * lane_len + lane_len - 1];
        for k in 0..128 {
            final_blk[k] ^= last[k];
        }
    }

    let final_bytes = block_to_le_bytes(&final_blk);
    Ok(blake2b_long(tag_len, &final_bytes))
}

fn std_base64_encode_nopad(input: &[u8]) -> String {
    std_base64_encode(input).trim_end_matches('=').to_string()
}

/// PHC biçiminde `$argon2id$v=19$m=...,t=...,p=...$<salt>$<tag>` özeti üretir.
pub fn argon2id_hash(
    password: &str,
    salt: &[u8],
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
) -> Result<String, &'static str> {
    let tag = argon2id_raw(
        password.as_bytes(),
        salt,
        &[],
        &[],
        t_cost,
        m_cost_kib,
        parallelism,
        32,
    )?;
    Ok(format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        m_cost_kib,
        t_cost,
        parallelism,
        std_base64_encode_nopad(salt),
        std_base64_encode_nopad(&tag)
    ))
}

/// PHC `$argon2id$...` özetini sabit zamanlı olarak doğrular.
pub fn verify_argon2id(phc_hash: &str, candidate_password: &str) -> bool {
    let parts: Vec<&str> = phc_hash.split('$').collect();
    // Beklenen yapı: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt_b64>", "<tag_b64>"]
    if parts.len() != 6 || !parts[0].is_empty() || parts[1] != "argon2id" || parts[2] != "v=19" {
        return false;
    }

    let mut m_cost: Option<u32> = None;
    let mut t_cost: Option<u32> = None;
    let mut p_cost: Option<u32> = None;

    for kv in parts[3].split(',') {
        let Some((k, v)) = kv.split_once('=') else {
            return false;
        };
        let Ok(num) = v.parse::<u32>() else {
            return false;
        };
        match k {
            "m" if m_cost.is_none() => m_cost = Some(num),
            "t" if t_cost.is_none() => t_cost = Some(num),
            "p" if p_cost.is_none() => p_cost = Some(num),
            _ => return false,
        }
    }

    let (Some(m), Some(t), Some(p)) = (m_cost, t_cost, p_cost) else {
        return false;
    };

    let Some(salt) = decode_base64_flexible(parts[4]) else {
        return false;
    };
    let Some(expected_tag) = decode_base64_flexible(parts[5]) else {
        return false;
    };
    if !(12..=128).contains(&expected_tag.len()) {
        return false;
    }

    let Ok(computed) = argon2id_raw(
        candidate_password.as_bytes(),
        &salt,
        &[],
        &[],
        t,
        m,
        p,
        expected_tag.len(),
    ) else {
        return false;
    };

    constant_time_eq(&computed, &expected_tag)
}

// ============================================================================
// 4. Genel Parola Doğrulama ($argon2id$, $apr1$, SHA-1, plain:)
// ============================================================================

/// htpasswd veya config formatındaki parolayı doğrular (`$argon2id$`, `$apr1$`, `{SHA}`, `{PLAIN}` veya `plain:`).
///
/// GÜVENLİK (P2): DES crypt hash'leri (`abJnggxhB/yWI`) veya işaretsiz düz metinler
/// ASLA parola olarak kabul edilmez; düz metin parolalar yalnızca `{PLAIN}` veya `plain:`
/// öneki açıkça belirtildiğinde kabul edilir.
pub fn verify_password(stored_hash: &str, candidate_password: &str) -> bool {
    let hash = stored_hash.trim();
    if hash.starts_with("$argon2id$") {
        verify_argon2id(hash, candidate_password)
    } else if hash.starts_with("$apr1$") {
        verify_apr1(hash, candidate_password)
    } else if let Some(plain) = hash.strip_prefix("{PLAIN}") {
        constant_time_eq(plain.as_bytes(), candidate_password.as_bytes())
    } else if let Some(plain) = hash.strip_prefix("plain:") {
        constant_time_eq(plain.as_bytes(), candidate_password.as_bytes())
    } else if hash.starts_with("{SHA}") {
        // Apache standart {SHA} formatı (SHA-1 base64)
        verify_sha1_htpasswd(hash, candidate_password)
    } else {
        // GÜVENLİK (P2): DES crypt hash'i (örn: abJnggxhB/yWI) veya öneksiz metinler reddedilir
        false
    }
}

// ============================================================================
// 5. SHA-1 ve Katı Base64 Yardımcıları ({SHA} Apache Formatı)
// ============================================================================

#[allow(
    clippy::manual_is_multiple_of,
    clippy::chunks_exact_to_as_chunks,
    clippy::needless_range_loop
)]
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
        let b1 = if i + 1 < input.len() {
            input[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as u32
        } else {
            0
        };

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

/// Standart veya padding'siz RFC 4648 Base64 dizgesini katı kurallarla çözer.
#[allow(clippy::manual_is_multiple_of)]
fn decode_base64_flexible(input: &str) -> Option<Vec<u8>> {
    let clean = input.trim();
    if clean.is_empty() {
        return Some(Vec::new());
    }
    let bytes = clean.as_bytes();
    if bytes.iter().any(|&b| b.is_ascii_whitespace()) {
        return None;
    }

    let mut pad_count = 0usize;
    for &b in bytes.iter().rev() {
        if b == b'=' {
            pad_count += 1;
        } else {
            break;
        }
    }
    if pad_count > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - pad_count];
    if body.contains(&b'=') {
        return None;
    }
    if pad_count > 0 && bytes.len() % 4 != 0 {
        return None;
    }
    if body.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity((body.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in body {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
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
// 6. htpasswd Dosya ve Başlık Ayrıştırma
// ============================================================================

/// htpasswd dosya içeriğini okuyup `kullanıcı -> parola_özeti` haritasına dönüştürür.
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
    let (scheme, rest) = trimmed.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let payload = rest.trim();
    if payload.is_empty() {
        return None;
    }

    let decoded = decode_base64_flexible(payload)?;
    let cred_str = String::from_utf8(decoded).ok()?;
    let (user, pass) = cred_str.split_once(':')?;
    if user.is_empty() || user.chars().any(|c| c.is_control()) {
        return None;
    }
    if pass.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return None;
    }
    Some((user.to_string(), pass.to_string()))
}

/// `WWW-Authenticate: Basic realm="..."` değeri için başlık enjeksiyonundan arındırılmış realm üretir.
pub fn sanitize_realm(realm: &str) -> String {
    let cleaned: String = realm
        .chars()
        .filter(|&c| !c.is_control() && c != '"' && c != '\\')
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "Restricted Area".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Güvenli `Basic realm="..."` başlık değeri biçimlendirir.
pub fn format_www_authenticate_header(realm: &str) -> String {
    format!("Basic realm=\"{}\"", sanitize_realm(realm))
}

// ============================================================================
// 7. Yol Normalizasyonu, Önek Eşleştirme ve Basic Auth Yöneticisi
// ============================================================================

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_for_auth(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                let decoded = (h << 4) | l;
                if decoded != 0 {
                    out.push(decoded);
                }
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Yol karşılaştırması için büyük/küçük harfi tek tipe indirger (büyük/küçük harf duyarsız dosya
/// sistemlerinde `/GIZLI/` ile `/gizli/` aynı korumaya girer). Türkçe `ı`/`İ` de `i`ye katlanır:
/// bu yalnız eşleştirme içindir ve korumayı genişletir (fail-closed), sunulan yolu değiştirmez.
fn fold_case_for_auth(s: &str) -> String {
    s.to_lowercase().replace('ı', "i").replace('\u{307}', "")
}

/// Percent-encoding, ters bölü, `.` / `..` ve çift eğik çizgi atlatma girişimlerini tek tip yola indirger.
pub fn normalize_auth_path(raw_path: &str) -> String {
    let path_only = raw_path.split(['?', '#']).next().unwrap_or("/");
    let decoded = fold_case_for_auth(&percent_decode_for_auth(path_only).replace('\\', "/"));
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => {
                // Windows dosya sistemi segment sonundaki nokta ve boşlukları yok sayar
                // (`/gizli./` ile `/gizli/` aynı dizin): eşleştirme için aynı şekilde atılır.
                let trimmed = s.trim_end_matches(['.', ' ']);
                if !trimmed.is_empty() {
                    segments.push(trimmed);
                }
            }
        }
    }
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

/// `seg` bir Windows 8.3 kısa adı kalıbıysa (`GIZLI~1`, `GIZLI~1.HTM`) `~` öncesi gövdeyi döndürür.
fn short_name_base(seg: &str) -> Option<&str> {
    let (base, rest) = seg.split_once('~')?;
    let (digits, ext) = match rest.split_once('.') {
        Some((d, e)) => (d, Some(e)),
        None => (rest, None),
    };
    let base_ok = !base.is_empty() && base.chars().count() <= 6;
    let digits_ok = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());
    let ext_ok = ext.is_none_or(|e| e.chars().count() <= 3);
    (base_ok && digits_ok && ext_ok).then_some(base)
}

/// Yol segmenti, öneki oluşturan `prefix_seg` ile eşleşir mi? Birebir eşitlik ya da (fail-closed)
/// `prefix_seg` için üretilebilecek 8.3 kısa ad kalıbı (`GIZLI~1` ~ `gizli`): kısa ad gövdesi uzun
/// adın başıyla örtüşüyorsa korumalı sayılır (gerçek eşleşme dosya sistemine bağlı olduğundan
/// belirsizlikte kimlik doğrulaması istenir).
fn segment_matches(path_seg: &str, prefix_seg: &str) -> bool {
    if path_seg == prefix_seg {
        return true;
    }
    let Some(base) = short_name_base(path_seg) else {
        return false;
    };
    let squash = |s: &str| -> String { s.chars().filter(|c| *c != '.' && *c != ' ').collect() };
    let base = squash(base);
    !base.is_empty() && squash(prefix_seg).starts_with(&base)
}

/// Normalize edilmiş yolun verilen dizin önekiyle eşleşip eşleşmediğini denetler.
pub fn matches_path_prefix(normalized_path: &str, raw_prefix: &str) -> bool {
    let norm_prefix = normalize_auth_path(raw_prefix);
    if norm_prefix == "/" {
        return true;
    }
    let mut path_segs = normalized_path.split('/').filter(|s| !s.is_empty());
    norm_prefix
        .split('/')
        .filter(|s| !s.is_empty())
        .all(|p| path_segs.next().is_some_and(|s| segment_matches(s, p)))
}

/// ACME HTTP-01 muafiyeti (`/.well-known/acme-challenge/...`) yalnız yol, normalleştirildikten sonra
/// da bu dizinin altında kalıyorsa ve `..` (veya yalnız nokta/boşluktan oluşan) segment içermiyorsa
/// geçerlidir. Ham yola bakmak `/.well-known/acme-challenge/../../gizli/` ile korumayı atlatır.
pub fn is_acme_challenge_exempt(raw_path: &str) -> bool {
    let path_only = raw_path.split(['?', '#']).next().unwrap_or("");
    let decoded = percent_decode_for_auth(path_only).replace('\\', "/");
    let has_dot_segment = decoded
        .split('/')
        .any(|seg| seg != "." && !seg.is_empty() && seg.chars().all(|c| c == '.' || c == ' '));
    if has_dot_segment {
        return false;
    }
    normalize_auth_path(raw_path).starts_with("/.well-known/acme-challenge/")
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthDecision {
    /// İstek devam edebilir (yetki başarılı veya dizin korumalı değil)
    Allowed,
    /// 401 Unauthorized dönülmeli ve `WWW-Authenticate: Basic realm="..."` verilmeli
    Unauthorized { realm: String },
    /// Başarısız deneme eşiği aşıldı; IP banlandı (403, Argon2 hesaplanmadı)
    Banned,
    /// IP başına eşzamanlı doğrulama sınırı aşıldı (429 + Retry-After)
    TooManyRequests { retry_after_secs: u64 },
    /// Doğrulama kuyruğu zaman aşımı (503 + Retry-After)
    Unavailable { retry_after_secs: u64 },
}

// ============================================================================
// 6.5. Basic Auth Brute-Force Kalkanı ve Sahte Özet (Zamanlama Saldırısı Koruması)
// ============================================================================

/// `[vhost.auth]` bölümünden okunan kaba kuvvet / kuyruk / süre sınırları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthLimits {
    pub max_failed_attempts: u32,
    pub fail_window_secs: u64,
    pub ban_secs: u64,
    pub fail_min_ms: u64,
    pub queue_timeout_ms: u64,
    pub max_concurrent_per_ip: u32,
}

impl From<&VHostAuthSection> for AuthLimits {
    fn from(a: &VHostAuthSection) -> Self {
        Self {
            max_failed_attempts: a.max_failed_attempts.max(1),
            fail_window_secs: a.fail_window_secs.max(1),
            ban_secs: a.ban_secs.max(1),
            fail_min_ms: a.fail_min_ms,
            queue_timeout_ms: a.queue_timeout_ms,
            max_concurrent_per_ip: a.max_concurrent_per_ip.max(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AttemptEntry {
    count: u32,
    start: Instant,
    window_secs: u64,
}

/// `attempts` tablosunun süresi dolmuş kayıtlarının en geç bu aralıkla temizlenmesi.
const ATTEMPTS_PURGE_INTERVAL_SECS: u64 = 30;

/// IP başına eşzamanlı doğrulama sınırı koruyucusu; düşünce sayacı geri azaltır ve yuva
/// bekleyenleri uyandırır.
pub struct InflightGuard<'a> {
    map: &'a DashMap<IpAddr, AtomicU32>,
    released: &'a tokio::sync::Notify,
    ip: IpAddr,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.map.get(&self.ip) {
            c.fetch_sub(1, Ordering::AcqRel);
        }
        self.map
            .remove_if(&self.ip, |_, c| c.load(Ordering::Acquire) == 0);
        self.released.notify_waiters();
    }
}

/// Basic Authentication denemelerini IP bazında sayıp kaba kuvvet eşiğinde IP'yi banlayan,
/// IP başına eşzamanlı doğrulama sayısını sınırlayan koruma kalkanı.
///
/// Sayaç doğrulamadan ÖNCE artırılır (`begin_attempt`): eşik aşıldıysa Argon2 hiç hesaplanmaz.
pub struct BasicAuthBruteForceGuard {
    attempts: DashMap<IpAddr, AttemptEntry>,
    inflight: DashMap<IpAddr, AtomicU32>,
    /// Bir IP yuvası boşaldığında bekleyenleri uyandırır (`enter_with_wait`).
    slot_released: tokio::sync::Notify,
    base: Instant,
    last_purge_secs: AtomicU64,
}

impl Default for BasicAuthBruteForceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl BasicAuthBruteForceGuard {
    pub fn new() -> Self {
        Self {
            attempts: DashMap::new(),
            inflight: DashMap::new(),
            slot_released: tokio::sync::Notify::new(),
            base: Instant::now(),
            last_purge_secs: AtomicU64::new(0),
        }
    }

    /// IP başına eşzamanlı doğrulama yuvası alır; sınır doluysa `None` (429).
    pub fn try_enter(&self, ip: IpAddr, max_concurrent: u32) -> Option<InflightGuard<'_>> {
        let entry = self.inflight.entry(ip).or_insert_with(|| AtomicU32::new(0));
        let prev = entry.fetch_add(1, Ordering::AcqRel);
        if prev >= max_concurrent {
            entry.fetch_sub(1, Ordering::AcqRel);
            drop(entry);
            self.inflight
                .remove_if(&ip, |_, c| c.load(Ordering::Acquire) == 0);
            return None;
        }
        Some(InflightGuard {
            map: &self.inflight,
            released: &self.slot_released,
            ip,
        })
    }

    /// `try_enter` ile aynı, ancak yuva doluysa en çok `wait` süre boşalmasını bekler (sınırlı kuyruk).
    /// Doğru parolalı tarayıcının paralel bağlantıları anında 429 yerine sırayla doğrulanır;
    /// süre dolunca yine `None` (429) döner, bekleme asla sınırsız değildir.
    pub async fn enter_with_wait(
        &self,
        ip: IpAddr,
        max_concurrent: u32,
        wait: Duration,
    ) -> Option<InflightGuard<'_>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            // Önce kaydol, sonra dene: yuva ikisi arasında boşalırsa uyandırma kaçmaz.
            let notified = self.slot_released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(guard) = self.try_enter(ip, max_concurrent) {
                return Some(guard);
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.try_enter(ip, max_concurrent);
            }
        }
    }

    /// Doğrulamadan ÖNCE çağrılır: denemeyi sayar. Eşik aşıldıysa IP banlanır ve `false` döner
    /// (çağıran Argon2/apr1 hesaplamadan 403 verir).
    pub fn begin_attempt(
        &self,
        ip: IpAddr,
        limits: &AuthLimits,
        ban_manager: &crate::IpBanManager,
    ) -> bool {
        let now = Instant::now();
        self.maybe_purge(now);
        let count = {
            let mut e = self.attempts.entry(ip).or_insert(AttemptEntry {
                count: 0,
                start: now,
                window_secs: limits.fail_window_secs,
            });
            if now.duration_since(e.start).as_secs() >= limits.fail_window_secs {
                e.count = 0;
                e.start = now;
            }
            e.window_secs = limits.fail_window_secs;
            e.count = e.count.saturating_add(1);
            e.count
        };
        if count > limits.max_failed_attempts {
            ban_manager.ban(
                ip,
                format!("Basic Auth brute-force engellendi ({count} deneme)"),
                limits.ban_secs,
            );
            return false;
        }
        true
    }

    /// Doğrulama hiç yapılamadıysa (503) denemeyi sayaçtan geri alır.
    pub fn cancel_attempt(&self, ip: IpAddr) {
        if let Some(mut e) = self.attempts.get_mut(&ip) {
            e.count = e.count.saturating_sub(1);
        }
    }

    /// Başarılı girişte IP'nin sayacını sıfırlar.
    pub fn record_success(&self, ip: IpAddr) {
        self.attempts.remove(&ip);
    }

    /// Penceresi dolmuş kayıtları siler (TTL temizliği).
    pub fn purge_expired_at(&self, now: Instant) {
        self.attempts
            .retain(|_, e| now.saturating_duration_since(e.start).as_secs() < e.window_secs);
    }

    /// En fazla `ATTEMPTS_PURGE_INTERVAL_SECS` aralıkla `purge_expired_at` çalıştırır.
    fn maybe_purge(&self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.base).as_secs();
        let last = self.last_purge_secs.load(Ordering::Relaxed);
        if elapsed.saturating_sub(last) >= ATTEMPTS_PURGE_INTERVAL_SECS
            && self
                .last_purge_secs
                .compare_exchange(last, elapsed, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            self.purge_expired_at(now);
        }
    }

    /// Tabloda tutulan IP kayıt sayısı (sızıntı denetimi için).
    pub fn tracked_ips(&self) -> usize {
        self.attempts.len()
    }
}

/// Eşzamanlı Argon2/apr1 doğrulama sayısı için varsayılan üst sınır (`[security] auth_max_concurrent_hashes`).
pub const DEFAULT_MAX_CONCURRENT_HASHES: usize = 4;

#[derive(Clone)]
struct CachedUsersEntry {
    mtime: SystemTime,
    len: u64,
    last_checked: std::time::Instant,
    users: HashMap<String, String>,
}

/// Başarılı doğrulamaların önbellekte tutulma süresi.
const SUCCESS_CACHE_TTL: Duration = Duration::from_secs(30);
/// Önbellekteki en çok kayıt sayısı (dolunca yeni başarı önbelleğe alınmaz, doğrulama yine yapılır).
const SUCCESS_CACHE_MAX_ENTRIES: usize = 1024;

/// Başarılı (kullanıcı, parola, kayıtlı özet) doğrulamalarının kısa ömürlü önbelleği.
///
/// Tarayıcı aynı sayfa için onlarca paralel istek gönderir; her birinde Argon2'yi yeniden hesaplamak
/// hem gereksizdir hem de IP başına eşzamanlı doğrulama sınırına takılır. Parola düz saklanmaz:
/// anahtar, süreç başına rastgele tuzlu BLAKE2b özetidir (uzunluk önekli kullanıcı, parola ve kayıtlı
/// özet). Kayıtlı özet anahtarın parçası olduğundan htpasswd/yapılandırmada parola değişince
/// eski başarı kendiliğinden geçersizdir. Yalnızca BAŞARILI doğrulamalar eklenir; yanlış parola
/// ASLA önbelleğe girmez.
struct SuccessCache {
    salt: [u8; 32],
    entries: DashMap<[u8; 32], Instant>,
}

impl SuccessCache {
    fn new() -> Self {
        use std::hash::{BuildHasher, Hasher};
        let mut salt = [0u8; 32];
        for (i, chunk) in salt.chunks_mut(8).enumerate() {
            let mut h = std::collections::hash_map::RandomState::new().build_hasher();
            h.write_usize(i);
            if let Ok(d) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                h.write_u128(d.as_nanos());
            }
            chunk.copy_from_slice(&h.finish().to_le_bytes());
        }
        Self {
            salt,
            entries: DashMap::new(),
        }
    }

    fn key(&self, user: &str, pass: &str, stored_hash: &str) -> [u8; 32] {
        let mut data = Vec::with_capacity(user.len() + pass.len() + stored_hash.len() + 24);
        for part in [user, pass, stored_hash] {
            data.extend_from_slice(&(part.len() as u64).to_le_bytes());
            data.extend_from_slice(part.as_bytes());
        }
        let digest = blake2b(32, &self.salt, &data);
        data.fill(0);
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        key
    }

    fn is_fresh(&self, key: &[u8; 32], now: Instant) -> bool {
        self.entries.get(key).is_some_and(|exp| *exp > now)
    }

    fn insert(&self, key: [u8; 32], now: Instant) {
        if self.entries.len() >= SUCCESS_CACHE_MAX_ENTRIES {
            self.entries.retain(|_, exp| *exp > now);
        }
        if self.entries.len() < SUCCESS_CACHE_MAX_ENTRIES {
            self.entries.insert(key, now + SUCCESS_CACHE_TTL);
        }
    }
}

/// htpasswd dosyalarını diskten okuyup `(mtime, boyut, TTL)` denetimi ile önbellekleyen yönetici.
pub struct BasicAuthManager {
    file_cache: RwLock<HashMap<PathBuf, CachedUsersEntry>>,
    pub semaphore: Arc<tokio::sync::Semaphore>,
    pub brute_force_guard: BasicAuthBruteForceGuard,
    success_cache: SuccessCache,
}

impl Default for BasicAuthManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BasicAuthManager {
    pub fn new() -> Self {
        Self::with_max_concurrent_hashes(DEFAULT_MAX_CONCURRENT_HASHES)
    }

    pub fn with_max_concurrent_hashes(max_concurrent: usize) -> Self {
        Self {
            file_cache: RwLock::new(HashMap::new()),
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1))),
            brute_force_guard: BasicAuthBruteForceGuard::default(),
            success_cache: SuccessCache::new(),
        }
    }

    /// `verify_password` + başarı önbelleği: önbellekte taze kayıt varsa hash hesaplanmaz.
    /// Yanlış parola ne önbelleğe girer ne de önbellekten geçer.
    fn verify_password_cached(&self, user: &str, stored_hash: &str, candidate: &str) -> bool {
        let key = self.success_cache.key(user, candidate, stored_hash);
        if self.success_cache.is_fresh(&key, Instant::now()) {
            return true;
        }
        let ok = verify_password(stored_hash, candidate);
        if ok {
            self.success_cache.insert(key, Instant::now());
        }
        ok
    }

    fn resolve_htpasswd_path(base_dir: Option<&Path>, raw: &str) -> PathBuf {
        let p = Path::new(raw.trim());
        if p.is_absolute() {
            p.to_path_buf()
        } else if let Some(base) = base_dir {
            base.join(p)
        } else {
            p.to_path_buf()
        }
    }

    /// Bir htpasswd dosyasını `(mtime, boyut, TTL)` önbellekli okur.
    /// Saniyede 1 kereden fazla disk metadata sorgusu yapmaz.
    pub fn get_users_from_file(&self, path: &Path) -> Result<HashMap<String, String>, String> {
        let now = std::time::Instant::now();
        if let Ok(cache) = self.file_cache.read() {
            if let Some(entry) = cache.get(path) {
                if now.duration_since(entry.last_checked) < Duration::from_millis(1000) {
                    return Ok(entry.users.clone());
                }
            }
        }

        let meta = fs::metadata(path)
            .map_err(|e| format!("htpasswd dosyası okunamadı ({}): {}", path.display(), e))?;
        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let len = meta.len();

        if let Ok(mut cache) = self.file_cache.write() {
            if let Some(entry) = cache.get_mut(path) {
                if entry.mtime == mtime && entry.len == len {
                    entry.last_checked = now;
                    return Ok(entry.users.clone());
                }
            }
        }

        let content = fs::read_to_string(path)
            .map_err(|e| format!("htpasswd içeriği okunamadı ({}): {}", path.display(), e))?;
        let users = parse_htpasswd_content(&content);

        if let Ok(mut cache) = self.file_cache.write() {
            cache.insert(
                path.to_path_buf(),
                CachedUsersEntry {
                    mtime,
                    len,
                    last_checked: now,
                    users: users.clone(),
                },
            );
        }

        Ok(users)
    }

    fn resolve_user_hash<'a>(
        &'a self,
        matched_dir: Option<&'a zmax_config::VHostAuthDirectory>,
        vhost_auth: &'a VHostAuthSection,
        base_dir: Option<&Path>,
        user: &str,
    ) -> (Option<String>, bool) {
        if let Some(dir) = matched_dir {
            let has_own_users = !dir.users.is_empty();
            let has_own_file = dir
                .htpasswd_path
                .as_deref()
                .is_some_and(|p| !p.trim().is_empty());

            if has_own_users {
                for entry in &dir.users {
                    if constant_time_eq(entry.username.as_bytes(), user.as_bytes()) {
                        return (Some(entry.password_hash.clone()), false);
                    }
                }
            }
            if has_own_file {
                if let Some(ref path_str) = dir.htpasswd_path {
                    let resolved = Self::resolve_htpasswd_path(base_dir, path_str);
                    match self.get_users_from_file(&resolved) {
                        Ok(file_users) => {
                            for (uname, hash) in file_users {
                                if constant_time_eq(uname.as_bytes(), user.as_bytes()) {
                                    return (Some(hash), false);
                                }
                            }
                        }
                        Err(_) => return (None, true),
                    }
                }
            }
            if has_own_users || has_own_file {
                return (None, false);
            }
        }

        if !vhost_auth.users.is_empty() {
            for entry in &vhost_auth.users {
                if constant_time_eq(entry.username.as_bytes(), user.as_bytes()) {
                    return (Some(entry.password_hash.clone()), false);
                }
            }
        }
        if let Some(ref path_str) = vhost_auth.htpasswd_path {
            if !path_str.trim().is_empty() {
                let resolved = Self::resolve_htpasswd_path(base_dir, path_str);
                match self.get_users_from_file(&resolved) {
                    Ok(file_users) => {
                        for (uname, hash) in file_users {
                            if constant_time_eq(uname.as_bytes(), user.as_bytes()) {
                                return (Some(hash), false);
                            }
                        }
                    }
                    Err(_) => return (None, true),
                }
            }
        }

        (None, false)
    }

    /// Göreceli `htpasswd_path` çözümlemesi destekli yetkilendirme kararı üretir.
    pub fn check_request_with_base(
        &self,
        auth_header: Option<&str>,
        request_path: &str,
        vhost_auth: &VHostAuthSection,
        base_dir: Option<&Path>,
    ) -> AuthDecision {
        if !vhost_auth.enabled {
            return AuthDecision::Allowed;
        }

        let normalized_path = normalize_auth_path(request_path);

        // 1. Dizin kurallarında en uzun normalleştirilmiş önek eşleşmesini bul
        let matched_dir = vhost_auth
            .directories
            .iter()
            .filter(|dir| matches_path_prefix(&normalized_path, &dir.path))
            .max_by_key(|dir| normalize_auth_path(&dir.path).len());

        if matched_dir.is_none() {
            if let Some(ref prefix) = vhost_auth.path_prefix {
                if !prefix.trim().is_empty() && !matches_path_prefix(&normalized_path, prefix) {
                    return AuthDecision::Allowed;
                }
            } else if !vhost_auth.directories.is_empty() {
                return AuthDecision::Allowed;
            }
        }

        let raw_realm = matched_dir
            .map(|d| {
                if d.realm.trim().is_empty() {
                    vhost_auth.realm.as_str()
                } else {
                    d.realm.as_str()
                }
            })
            .unwrap_or(vhost_auth.realm.as_str());
        let active_realm = sanitize_realm(raw_realm);

        // 2. Authorization: Basic başlığını ayrıştır
        let Some((user, pass)) = auth_header.and_then(parse_basic_auth_header) else {
            return AuthDecision::Unauthorized {
                realm: active_realm,
            };
        };

        // 3. Kullanıcı doğrulama ve Zamanlama Saldırısı (Timing Attack) Koruması
        let (found_hash, file_err) =
            self.resolve_user_hash(matched_dir, vhost_auth, base_dir, &user);
        // Süre eşitleme `check_request_async` içinde `fail_min_ms` tabanıyla yapılır.
        let user_verified = match found_hash {
            Some(hash) if !file_err => self.verify_password_cached(&user, &hash, &pass),
            _ => false,
        };

        if user_verified {
            AuthDecision::Allowed
        } else {
            AuthDecision::Unauthorized {
                realm: active_realm,
            }
        }
    }

    /// Belirtilen istek yolu ve vHost auth yapılandırmasına göre yetkilendirme kararı üretir.
    pub fn check_request(
        &self,
        auth_header: Option<&str>,
        request_path: &str,
        vhost_auth: &VHostAuthSection,
    ) -> AuthDecision {
        self.check_request_with_base(auth_header, request_path, vhost_auth, None)
    }

    /// Asenkron tokio işleyicilerini bloklamamak için CPU-yoğun hash hesaplamalarını
    /// `spawn_blocking` ve eşzamanlı `Semaphore` koruması altında yürütür.
    ///
    /// Sıra: IP başına eşzamanlı sınır (429) -> sayaç doğrulamadan ÖNCE (403, ban) ->
    /// `queue_timeout_ms` süreli semafor (503) -> doğrulama -> başarısızsa en az `fail_min_ms`
    /// süre (kullanıcı var/yok ve şemadan bağımsız).
    pub async fn check_request_async(
        self: &Arc<Self>,
        client_ip: IpAddr,
        auth_header: Option<&str>,
        request_path: &str,
        vhost_auth: &VHostAuthSection,
        base_dir: Option<&Path>,
        ban_manager: &crate::IpBanManager,
    ) -> AuthDecision {
        if !vhost_auth.enabled {
            return AuthDecision::Allowed;
        }
        let started = tokio::time::Instant::now();
        let limits = AuthLimits::from(vhost_auth);

        let normalized_path = normalize_auth_path(request_path);

        let matched_dir = vhost_auth
            .directories
            .iter()
            .filter(|dir| matches_path_prefix(&normalized_path, &dir.path))
            .max_by_key(|dir| normalize_auth_path(&dir.path).len());

        if matched_dir.is_none() {
            if let Some(ref prefix) = vhost_auth.path_prefix {
                if !prefix.trim().is_empty() && !matches_path_prefix(&normalized_path, prefix) {
                    return AuthDecision::Allowed;
                }
            } else if !vhost_auth.directories.is_empty() {
                return AuthDecision::Allowed;
            }
        }

        let raw_realm = matched_dir
            .map(|d| {
                if d.realm.trim().is_empty() {
                    vhost_auth.realm.as_str()
                } else {
                    d.realm.as_str()
                }
            })
            .unwrap_or(vhost_auth.realm.as_str());
        let active_realm = sanitize_realm(raw_realm);

        let Some(auth_str) = auth_header else {
            return AuthDecision::Unauthorized {
                realm: active_realm,
            };
        };

        // 1. IP başına eşzamanlı doğrulama sınırı (yuva, yanıt sonuna kadar tutulur)
        let Some(_slot) = self
            .brute_force_guard
            .enter_with_wait(
                client_ip,
                limits.max_concurrent_per_ip,
                Duration::from_millis(limits.queue_timeout_ms),
            )
            .await
        else {
            return AuthDecision::TooManyRequests {
                retry_after_secs: 1,
            };
        };

        // 2. Sayaç doğrulamadan ÖNCE: eşik aşıldıysa hash hesaplanmadan 403
        if !self
            .brute_force_guard
            .begin_attempt(client_ip, &limits, ban_manager)
        {
            return AuthDecision::Banned;
        }

        let deadline = started + Duration::from_millis(limits.fail_min_ms);

        if parse_basic_auth_header(auth_str).is_none() {
            tokio::time::sleep_until(deadline).await;
            return AuthDecision::Unauthorized {
                realm: active_realm,
            };
        }

        // 3. Sınırlı kuyruk: semafor beklemesi zaman aşımına uğrarsa 503 + Retry-After
        let permit = match tokio::time::timeout(
            Duration::from_millis(limits.queue_timeout_ms),
            self.semaphore.clone().acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => {
                self.brute_force_guard.cancel_attempt(client_ip);
                return AuthDecision::Unavailable {
                    retry_after_secs: 1,
                };
            }
        };

        // 4. CPU-yoğun hash hesaplaması tokio worker thread'lerinden izole edilir
        let this = self.clone();
        let auth_hdr_owned = auth_str.to_string();
        let path_owned = request_path.to_string();
        let vhost_auth_owned = vhost_auth.clone();
        let base_dir_owned = base_dir.map(|p| p.to_path_buf());

        let decision = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            this.check_request_with_base(
                Some(&auth_hdr_owned),
                &path_owned,
                &vhost_auth_owned,
                base_dir_owned.as_deref(),
            )
        })
        .await
        .unwrap_or_else(|_| AuthDecision::Unauthorized {
            realm: active_realm.clone(),
        });

        match &decision {
            AuthDecision::Allowed => self.brute_force_guard.record_success(client_ip),
            _ => tokio::time::sleep_until(deadline).await,
        }
        decision
    }
}

// ============================================================================
// 8. Birim Testleri
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use zmax_config::{AuthUserEntry, VHostAuthDirectory};

    #[test]
    fn test_md5_rfc1321_vectors() {
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
    fn test_blake2b_rfc7693_vectors() {
        let empty = blake2b(64, &[], b"");
        let empty_hex: String = empty.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            empty_hex,
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );

        let abc = blake2b(64, &[], b"abc");
        let abc_hex: String = abc.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            abc_hex,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    #[test]
    fn test_argon2id_rfc9106_vector_and_php_compatibility() {
        // RFC 9106 Bölüm 5.3 resmi Argon2id test vektörü (p=4, m=32 KiB, t=3)
        let tag = argon2id_raw(
            &[0x01u8; 32],
            &[0x02u8; 16],
            &[0x03u8; 8],
            &[0x04u8; 12],
            3,
            32,
            4,
            32,
        )
        .expect("RFC 9106 Argon2id başarısız olmamalı");
        let hex_tag: String = tag.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex_tag,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );

        // Gerçek PHP 8.3 password_hash(..., PASSWORD_ARGON2ID) çıktıları
        let php_hash_p1 = "$argon2id$v=19$m=65536,t=3,p=1$aDVMNW9MV3FjUE5xY3h4Lw$VC9wtT1yZVDrE7wkPALDM3Mupw+dSW/ACmdVxL8uuro";
        assert!(verify_password(php_hash_p1, "parola123"));
        assert!(!verify_password(php_hash_p1, "parola124"));
        assert!(!verify_password(php_hash_p1, ""));

        let php_hash_p2 = "$argon2id$v=19$m=16384,t=2,p=2$UnFzbno4NzVKNC9FVE4vRA$+O1YP9rLyU3ZXlopheksJ03SwhyyAjgBpocKoV8usmE";
        assert!(verify_password(php_hash_p2, "zmaxAdmin!2026"));
        assert!(!verify_password(php_hash_p2, "zmaxAdmin!2025"));

        // DoS / geçersiz parametre korumaları reddedilmeli
        let huge_m = "$argon2id$v=19$m=999999999,t=3,p=1$aDVMNW9MV3FjUE5xY3h4Lw$VC9wtT1yZVDrE7wkPALDM3Mupw+dSW/ACmdVxL8uuro";
        assert!(!verify_password(huge_m, "parola123"));
        let bad_ver = "$argon2id$v=16$m=16384,t=2,p=1$aDVMNW9MV3FjUE5xY3h4Lw$VC9wtT1yZVDrE7wkPALDM3Mupw+dSW/ACmdVxL8uuro";
        assert!(!verify_password(bad_ver, "parola123"));
    }

    #[test]
    fn test_apache_apr1_hash_and_verify() {
        let salt = "r31.D/..";
        let password = "my_secure_password";
        let hash = apr1_hash(password, salt);

        assert!(hash.starts_with("$apr1$r31.D/..$"));
        assert!(verify_apr1(&hash, password));
        assert!(verify_password(&hash, password));
        assert!(!verify_apr1(&hash, "wrong_password"));
        assert!(!verify_apr1(&hash, ""));
        // Geçersiz apr1 karakter/uzunluk reddi
        assert!(!verify_apr1("$apr1$salt1234$kisa", "secret"));
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
        assert_eq!(
            map.get("testuser").unwrap(),
            "{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g="
        );
    }

    #[test]
    fn test_parse_basic_auth_header_strict_and_case_insensitive() {
        // 'admin:secret123' base64 hali: 'YWRtaW46c2VjcmV0MTIz'
        let creds =
            parse_basic_auth_header("Basic YWRtaW46c2VjcmV0MTIz").expect("Basic auth çözülemedi");
        assert_eq!(creds.0, "admin");
        assert_eq!(creds.1, "secret123");

        // Büyük/küçük harf duyarsız scheme (RFC 7235/7617)
        let creds2 = parse_basic_auth_header("basic YWRtaW46c2VjcmV0MTIz")
            .expect("Küçük harfli scheme kabul edilmeli");
        assert_eq!(creds2.0, "admin");

        // Şifrede ':' olabilir ('user:pa:ss' -> 'dXNlcjpwYTpzcw==')
        let creds3 = parse_basic_auth_header("BASIC dXNlcjpwYTpzcw==").unwrap();
        assert_eq!(creds3.0, "user");
        assert_eq!(creds3.1, "pa:ss");

        assert!(parse_basic_auth_header("Bearer token123").is_none());
        assert!(parse_basic_auth_header("Basic gecersiz_base64!").is_none());
        assert!(parse_basic_auth_header("Basic ").is_none());
    }

    #[test]
    fn test_path_normalization_prefix_and_bypass_prevention() {
        assert_eq!(
            normalize_auth_path("/%61dmin/index.html"),
            "/admin/index.html"
        );
        assert_eq!(
            normalize_auth_path("//admin/../admin/panel?a=1"),
            "/admin/panel"
        );
        assert!(matches_path_prefix("/admin/index.html", "/admin"));
        assert!(matches_path_prefix("/admin", "/admin/"));
        assert!(!matches_path_prefix("/administrator", "/admin"));

        let manager = BasicAuthManager::new();
        let hash = apr1_hash("gizli123", "s4lt9999");
        let auth_cfg = VHostAuthSection {
            enabled: true,
            realm: "Gizli\"Alan\r\nBad:1".to_string(),
            path_prefix: Some("/gizli".to_string()),
            htpasswd_path: None,
            users: vec![AuthUserEntry::new("panelci", hash)],
            directories: vec![],
            ..Default::default()
        };

        // Korumasız yol Allowed
        assert_eq!(
            manager.check_request(None, "/acik/sayfa.html", &auth_cfg),
            AuthDecision::Allowed
        );
        assert_eq!(
            manager.check_request(None, "/gizli2/sayfa.html", &auth_cfg),
            AuthDecision::Allowed
        );

        // Percent-encoded veya çift slash ile atlatma girişimi 401 dönmeli ve realm temizlenmeli
        let res = manager.check_request(None, "//%67izli/panel.php?ok=1", &auth_cfg);
        assert_eq!(
            res,
            AuthDecision::Unauthorized {
                realm: "GizliAlanBad:1".to_string()
            }
        );
        assert_eq!(
            format_www_authenticate_header("Gizli\"Alan\r\nBad:1"),
            "Basic realm=\"GizliAlanBad:1\""
        );
    }

    #[test]
    fn test_basic_auth_manager_flow_and_relative_htpasswd_reload() {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base_dir =
            std::env::temp_dir().join(format!("zmax_basic_auth_{}_{}", std::process::id(), nanos));
        let auth_dir = base_dir.join("conf");
        std::fs::create_dir_all(&auth_dir).unwrap();

        let ht_rel = "conf/test.htpasswd";
        let apr_hash = apr1_hash("adminpass", "s4lt1234");
        let argon_hash = argon2id_hash("argonpass", b"saltsalt1234", 1024, 1, 1).unwrap();
        std::fs::write(
            base_dir.join(ht_rel),
            format!("admin:{}\nmodern:{}\n", apr_hash, argon_hash),
        )
        .unwrap();

        let manager = BasicAuthManager::new();
        let vhost_auth = VHostAuthSection {
            enabled: true,
            realm: "Gizli Bolge".to_string(),
            path_prefix: None,
            htpasswd_path: Some(ht_rel.to_string()),
            users: vec![],
            directories: vec![
                VHostAuthDirectory {
                    path: "/admin".to_string(),
                    realm: "Admin Girisi".to_string(),
                    htpasswd_path: None,
                    users: vec![],
                },
                VHostAuthDirectory {
                    path: "/admin/super".to_string(),
                    realm: "Super Admin".to_string(),
                    htpasswd_path: None,
                    users: vec![AuthUserEntry::new(
                        "rootuser",
                        apr1_hash("rootpw", "rt123456"),
                    )],
                },
            ],
            ..Default::default()
        };

        // 1. Korumasız yol -> Doğrudan Allowed
        assert_eq!(
            manager.check_request_with_base(
                None,
                "/public/index.html",
                &vhost_auth,
                Some(&base_dir)
            ),
            AuthDecision::Allowed
        );

        // 2. Korumalı yol, başlık yok -> Unauthorized
        assert_eq!(
            manager.check_request_with_base(None, "/admin/dashboard", &vhost_auth, Some(&base_dir)),
            AuthDecision::Unauthorized {
                realm: "Admin Girisi".to_string()
            }
        );

        // 3. Yanlış parola -> Unauthorized
        // 'admin:wrong' -> 'YWRtaW46d3Jvbmc='
        assert_eq!(
            manager.check_request_with_base(
                Some("Basic YWRtaW46d3Jvbmc="),
                "/admin/dashboard",
                &vhost_auth,
                Some(&base_dir),
            ),
            AuthDecision::Unauthorized {
                realm: "Admin Girisi".to_string()
            }
        );

        // 4. Doğru $apr1$ parola (göreceli htpasswd_path üzerinden) -> Allowed
        // 'admin:adminpass' -> 'YWRtaW46YWRtaW5wYXNz'
        assert_eq!(
            manager.check_request_with_base(
                Some("Basic YWRtaW46YWRtaW5wYXNz"),
                "/admin/dashboard",
                &vhost_auth,
                Some(&base_dir),
            ),
            AuthDecision::Allowed
        );

        // 5. Doğru Argon2id parola -> Allowed ('modern:argonpass' -> 'bW9kZXJuOmFyZ29ucGFzcw==')
        assert_eq!(
            manager.check_request_with_base(
                Some("Basic bW9kZXJuOmFyZ29ucGFzcw=="),
                "/admin/dashboard",
                &vhost_auth,
                Some(&base_dir),
            ),
            AuthDecision::Allowed
        );

        // 6. En uzun dizin öneki (/admin/super) sadece kendi rootuser'ını kabul etmeli
        assert_eq!(
            manager.check_request_with_base(
                Some("Basic YWRtaW46YWRtaW5wYXNz"),
                "/admin/super/ayar",
                &vhost_auth,
                Some(&base_dir),
            ),
            AuthDecision::Unauthorized {
                realm: "Super Admin".to_string()
            }
        );
        // 'rootuser:rootpw' -> 'cm9vdHVzZXI6cm9vdHB3'
        assert_eq!(
            manager.check_request_with_base(
                Some("Basic cm9vdHVzZXI6cm9vdHB3"),
                "/admin/super/ayar",
                &vhost_auth,
                Some(&base_dir),
            ),
            AuthDecision::Allowed
        );

        let _ = std::fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn test_des_crypt_hash_rejected_as_password_and_plain_prefix() {
        // GÜVENLİK (P2): htpasswd -d ile üretilen DES crypt hash'i (örn: abJnggxhB/yWI)
        // ASLA parola olarak kabul edilmemelidir.
        let des_hash = "abJnggxhB/yWI";
        assert!(
            !verify_password(des_hash, des_hash),
            "DES crypt hash'i asla parola olarak kabul edilmemeli!"
        );
        assert!(!verify_password(des_hash, "password"));
        assert!(!verify_password(des_hash, "gizli"));

        // Düz metin parolalar yalnızca açıkça {PLAIN} veya plain: önekiyle kabul edilir
        assert!(verify_password("{PLAIN}acikparola", "acikparola"));
        assert!(verify_password("plain:acikparola", "acikparola"));
        assert!(!verify_password("{PLAIN}acikparola", "yanlis"));
        assert!(!verify_password("plain:acikparola", "yanlis"));

        // Öneksiz düz metinler güvenlik gereği reddedilir
        assert!(!verify_password("rastgeleparola", "rastgeleparola"));
    }

    fn limits(max: u32, window: u64) -> AuthLimits {
        AuthLimits {
            max_failed_attempts: max,
            fail_window_secs: window,
            ban_secs: 300,
            fail_min_ms: 0,
            queue_timeout_ms: 500,
            max_concurrent_per_ip: 2,
        }
    }

    #[test]
    fn test_brute_force_guard_counts_before_verification_and_bans_over_threshold() {
        use std::net::IpAddr;
        let ban_mgr = crate::IpBanManager::new();
        let guard = BasicAuthBruteForceGuard::new();
        let lim = limits(3, 60);
        let ip: IpAddr = "192.168.10.50".parse().unwrap();

        // İlk 3 deneme doğrulanabilir, 4. deneme doğrulamadan ÖNCE reddedilir ve IP banlanır
        for _ in 0..3 {
            assert!(guard.begin_attempt(ip, &lim, &ban_mgr));
            assert!(!ban_mgr.is_banned(ip));
        }
        assert!(!guard.begin_attempt(ip, &lim, &ban_mgr));
        assert!(ban_mgr.is_banned(ip));

        // Başarılı giriş sayacı sıfırlar
        let other: IpAddr = "192.168.10.51".parse().unwrap();
        for _ in 0..3 {
            assert!(guard.begin_attempt(other, &lim, &ban_mgr));
        }
        guard.record_success(other);
        assert!(guard.begin_attempt(other, &lim, &ban_mgr));
        assert!(!ban_mgr.is_banned(other));

        // 503 ile iptal edilen deneme sayılmaz
        let third: IpAddr = "192.168.10.52".parse().unwrap();
        for _ in 0..10 {
            assert!(guard.begin_attempt(third, &lim, &ban_mgr));
            guard.cancel_attempt(third);
        }
        assert!(!ban_mgr.is_banned(third));
    }

    #[test]
    fn test_attempts_table_is_purged_after_window_ttl() {
        let ban_mgr = crate::IpBanManager::new();
        let guard = BasicAuthBruteForceGuard::new();
        let lim = limits(5, 60);
        for n in 1..=200u32 {
            let ip: std::net::IpAddr = std::net::IpAddr::from([10, 1, (n >> 8) as u8, n as u8]);
            assert!(guard.begin_attempt(ip, &lim, &ban_mgr));
        }
        assert_eq!(guard.tracked_ips(), 200);
        // Pencere dolmadan temizlik kayıt silmez
        guard.purge_expired_at(Instant::now() + Duration::from_secs(30));
        assert_eq!(guard.tracked_ips(), 200);
        // Pencere (60 sn) dolunca tablo boşalır
        guard.purge_expired_at(Instant::now() + Duration::from_secs(61));
        assert_eq!(
            guard.tracked_ips(),
            0,
            "attempts tablosu TTL ile temizlenmeli"
        );
    }

    #[test]
    fn test_per_ip_inflight_limit_and_release() {
        let guard = BasicAuthBruteForceGuard::new();
        let ip: std::net::IpAddr = "10.9.9.9".parse().unwrap();
        let g1 = guard.try_enter(ip, 2).expect("1. yuva");
        let g2 = guard.try_enter(ip, 2).expect("2. yuva");
        assert!(
            guard.try_enter(ip, 2).is_none(),
            "3. yuva reddedilmeli (429)"
        );
        drop(g1);
        let g3 = guard
            .try_enter(ip, 2)
            .expect("yuva serbest kalinca yeniden alinabilir");
        drop((g2, g3));
        assert!(guard.inflight.is_empty(), "yuva tablosu sizdirmamali");
    }

    #[test]
    fn test_auth_limits_come_from_vhost_auth_section_with_documented_defaults() {
        let d = AuthLimits::from(&VHostAuthSection::default());
        assert_eq!(
            (d.max_failed_attempts, d.fail_window_secs, d.ban_secs),
            (5, 60, 300)
        );
        assert_eq!(
            (d.fail_min_ms, d.queue_timeout_ms, d.max_concurrent_per_ip),
            (500, 500, 2)
        );
        let cfg = VHostAuthSection {
            max_failed_attempts: 9,
            fail_window_secs: 11,
            ban_secs: 13,
            fail_min_ms: 17,
            queue_timeout_ms: 19,
            max_concurrent_per_ip: 23,
            ..Default::default()
        };
        let l = AuthLimits::from(&cfg);
        assert_eq!(
            (l.max_failed_attempts, l.fail_window_secs, l.ban_secs),
            (9, 11, 13)
        );
        assert_eq!(
            (l.fail_min_ms, l.queue_timeout_ms, l.max_concurrent_per_ip),
            (17, 19, 23)
        );
    }

    #[test]
    fn test_normalize_auth_path_is_case_insensitive() {
        assert_eq!(
            normalize_auth_path("/GIZLI/"),
            normalize_auth_path("/gizli")
        );
        assert_eq!(
            normalize_auth_path("/Gizli/IndeX.HTML"),
            "/gizli/index.html"
        );
        assert_eq!(
            normalize_auth_path("/G%C4%B0ZL%C4%B0"),
            normalize_auth_path("/gizli")
        );
        assert!(matches_path_prefix(
            &normalize_auth_path("/GiZLi/x"),
            "/gizli"
        ));
        assert!(matches_path_prefix(
            &normalize_auth_path("/gizli/x"),
            "/GIZLI/"
        ));
        assert!(!matches_path_prefix(
            &normalize_auth_path("/gizlix"),
            "/gizli"
        ));
    }

    #[tokio::test]
    async fn test_check_request_async_with_spawn_blocking_and_semaphore() {
        use std::net::IpAddr;
        let manager = Arc::new(BasicAuthManager::new());
        let ban_mgr = crate::IpBanManager::new();
        let test_ip: IpAddr = "10.0.5.5".parse().unwrap();

        let mut vhost_auth = VHostAuthSection {
            enabled: true,
            realm: "Test Async".to_string(),
            ..Default::default()
        };
        let hash = apr1_hash("testpass", "salt1234");
        vhost_auth.users.push(AuthUserEntry {
            username: "asyncuser".to_string(),
            password_hash: hash,
        });

        // 1. Başlıksız -> 401 Unauthorized
        let res = manager
            .check_request_async(test_ip, None, "/guvenli", &vhost_auth, None, &ban_mgr)
            .await;
        assert_eq!(
            res,
            AuthDecision::Unauthorized {
                realm: "Test Async".to_string()
            }
        );
        assert!(!ban_mgr.is_banned(test_ip));

        // 2. Doğru parola -> Allowed (ve IP banlanmaz)
        let token = "Basic ".to_string() + &std_base64_encode(b"asyncuser:testpass");
        let res = manager
            .check_request_async(
                test_ip,
                Some(&token),
                "/guvenli",
                &vhost_auth,
                None,
                &ban_mgr,
            )
            .await;
        assert_eq!(res, AuthDecision::Allowed);

        // 3. Bilinmeyen kullanıcı adı (Timing attack sahte hash testi) -> 401
        let bad_user_token = "Basic ".to_string() + &std_base64_encode(b"bilinmeyen:parola");
        let res = manager
            .check_request_async(
                test_ip,
                Some(&bad_user_token),
                "/guvenli",
                &vhost_auth,
                None,
                &ban_mgr,
            )
            .await;
        assert_eq!(
            res,
            AuthDecision::Unauthorized {
                realm: "Test Async".to_string()
            }
        );
    }

    #[test]
    fn des_crypt_hash_not_accepted_as_password() {
        let des_hash = "abJnggxhB/yWI";
        assert!(
            !verify_password(des_hash, des_hash),
            "DES crypt hash'i asla parola olarak kabul edilmemeli"
        );
        assert!(!verify_password(des_hash, "password"));
        assert!(!verify_password(des_hash, "gizli"));
        assert!(!verify_password("duzmetin", "duzmetin"));
        assert!(verify_password("{PLAIN}duzmetin", "duzmetin"));
        assert!(verify_password("plain:duzmetin", "duzmetin"));
    }

    #[tokio::test]
    async fn failure_time_is_equalized_between_known_apr1_user_and_unknown_user() {
        let manager = Arc::new(BasicAuthManager::new());
        let ban_mgr = crate::IpBanManager::new();
        let mut vhost_auth = VHostAuthSection {
            enabled: true,
            realm: "Timing Test".to_string(),
            fail_min_ms: 150,
            max_failed_attempts: 1000,
            ..Default::default()
        };
        vhost_auth.users.push(AuthUserEntry {
            username: "knownuser".to_string(),
            password_hash: apr1_hash("Dogru", "salt1234"),
        });
        let known = "Basic ".to_string() + &std_base64_encode(b"knownuser:Yanlis");
        let unknown = "Basic ".to_string() + &std_base64_encode(b"nonexistent:Yanlis");
        let ip: std::net::IpAddr = "10.0.9.9".parse().unwrap();

        let (mut sum_known, mut sum_unknown) = (Duration::ZERO, Duration::ZERO);
        for _ in 0..6 {
            let t = Instant::now();
            let r = manager
                .check_request_async(ip, Some(&known), "/t", &vhost_auth, None, &ban_mgr)
                .await;
            sum_known += t.elapsed();
            assert!(matches!(r, AuthDecision::Unauthorized { .. }));
            let t = Instant::now();
            let r = manager
                .check_request_async(ip, Some(&unknown), "/t", &vhost_auth, None, &ban_mgr)
                .await;
            sum_unknown += t.elapsed();
            assert!(matches!(r, AuthDecision::Unauthorized { .. }));
        }
        let (k, u) = (sum_known / 6, sum_unknown / 6);
        let diff = if k > u { k - u } else { u - k };
        assert!(
            diff < Duration::from_millis(50),
            "bilinen {k:?} / bilinmeyen {u:?} farki {diff:?}"
        );
        assert!(k >= Duration::from_millis(140) && u >= Duration::from_millis(140));
    }

    #[tokio::test]
    async fn queue_timeout_yields_unavailable_and_per_ip_limit_yields_too_many_requests() {
        let manager = Arc::new(BasicAuthManager::with_max_concurrent_hashes(1));
        let ban_mgr = crate::IpBanManager::new();
        let ip: std::net::IpAddr = "10.0.9.10".parse().unwrap();
        let mut vhost_auth = VHostAuthSection {
            enabled: true,
            queue_timeout_ms: 50,
            fail_min_ms: 0,
            max_failed_attempts: 1000,
            max_concurrent_per_ip: 1,
            ..Default::default()
        };
        vhost_auth.users.push(AuthUserEntry {
            username: "u".to_string(),
            password_hash: apr1_hash("p", "salt1234"),
        });
        let tok = "Basic ".to_string() + &std_base64_encode(b"u:x");

        // Semaforun tek yuvasını tut: kuyruk 50 ms sonra 503 olmalı
        let _held = manager.semaphore.clone().acquire_owned().await.unwrap();
        let t = Instant::now();
        let r = manager
            .check_request_async(ip, Some(&tok), "/q", &vhost_auth, None, &ban_mgr)
            .await;
        assert!(matches!(r, AuthDecision::Unavailable { .. }), "{r:?}");
        assert!(t.elapsed() < Duration::from_millis(1000));

        // IP yuvası doluyken ikinci istek 429
        let slot = manager.brute_force_guard.try_enter(ip, 1).unwrap();
        let r = manager
            .check_request_async(ip, Some(&tok), "/q", &vhost_auth, None, &ban_mgr)
            .await;
        assert!(matches!(r, AuthDecision::TooManyRequests { .. }), "{r:?}");
        drop(slot);
    }

    #[test]
    fn r9b_normalize_folds_windows_trailing_dot_and_space() {
        for raw in [
            "/gizli./index.html",
            "/gizli../index.html",
            "/gizli.../index.html",
            "/gizli%20/index.html",
            "/gizli%2e/index.html",
            "/gizli. ./index.html",
            "/GIZLI./index.html",
        ] {
            assert_eq!(normalize_auth_path(raw), "/gizli/index.html", "{raw}");
        }
        assert_eq!(normalize_auth_path("/a/b/../c"), "/a/c");
        assert_eq!(normalize_auth_path("/dosya.txt"), "/dosya.txt");
        assert_eq!(normalize_auth_path("/.well-known/x"), "/.well-known/x");
    }

    #[test]
    fn r9b_short_name_83_is_protected_fail_closed() {
        assert!(matches_path_prefix("/gizli~1/index.html", "/gizli"));
        assert!(matches_path_prefix(
            &normalize_auth_path("/GIZLI~1/a"),
            "/gizli"
        ));
        assert!(matches_path_prefix("/gizli~2", "/gizli"));
        assert!(matches_path_prefix("/gizli~1/x", "/gizliayarlari"));
        assert!(matches_path_prefix("/gizli~1.htm", "/gizli.html"));
        assert!(matches_path_prefix("/panel/gizli~1/x", "/panel/gizli"));
        // 8.3 kalıbına uymayan veya başka adlı yollar eşleşmez
        assert!(!matches_path_prefix("/baska~1/x", "/gizli"));
        assert!(!matches_path_prefix("/gizlix~1/x", "/gizli"));
        assert!(!matches_path_prefix("/gizli~/x", "/gizli"));
        assert!(!matches_path_prefix("/gizli~a/x", "/gizli"));
        assert!(!matches_path_prefix("/gizlix/x", "/gizli"));
        // Eski davranış korunur
        assert!(matches_path_prefix("/admin/index.html", "/admin"));
        assert!(!matches_path_prefix("/administrator", "/admin"));
        assert!(matches_path_prefix("/x/y", "/"));
    }

    #[test]
    fn r9b_acme_exemption_requires_normalized_path_under_challenge_dir() {
        assert!(is_acme_challenge_exempt(
            "/.well-known/acme-challenge/tok123"
        ));
        assert!(is_acme_challenge_exempt(
            "/.well-known/acme-challenge/tok?x=1"
        ));
        for raw in [
            "/.well-known/acme-challenge/../../gizli/index.html",
            "/.well-known/acme-challenge/%2e%2e/%2e%2e/gizli/index.html",
            "/.well-known/acme-challenge/%2E%2E/gizli",
            "/.well-known/acme-challenge/..%2fgizli",
            "/.well-known/acme-challenge/..\\gizli",
            "/.well-known/acme-challenge/.../gizli",
            "/.well-known/acme-challenge/.. /gizli",
            "/gizli/index.html",
            "/.well-known/security.txt",
            "/.well-known/acme-challenge",
        ] {
            assert!(!is_acme_challenge_exempt(raw), "{raw}");
        }
    }

    #[tokio::test]
    async fn r9b_enter_with_wait_waits_for_release_then_times_out() {
        let guard = Arc::new(BasicAuthBruteForceGuard::new());
        let ip: std::net::IpAddr = "10.0.9.20".parse().unwrap();
        let held = guard.try_enter(ip, 1).expect("ilk yuva");

        // Yuva 80 ms sonra bırakılır: bekleyen, süre dolmadan yuvayı alır.
        let g2 = Arc::clone(&guard);
        let waiter = tokio::spawn(async move {
            g2.enter_with_wait(ip, 1, Duration::from_secs(5))
                .await
                .is_some()
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        drop(held);
        assert!(waiter.await.unwrap(), "yuva bosalinca bekleyen girmeli");

        // Yuva dolu kalırsa bekleme sınırlıdır ve None döner.
        let _held2 = guard.try_enter(ip, 1).expect("yuva");
        let t = Instant::now();
        let r = guard
            .enter_with_wait(ip, 1, Duration::from_millis(60))
            .await;
        assert!(r.is_none());
        assert!(t.elapsed() >= Duration::from_millis(50));
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn r9b_success_cache_only_stores_successes_and_follows_stored_hash() {
        let manager = BasicAuthManager::new();
        let h1 = apr1_hash("dogru", "salt1111");
        assert!(!manager.verify_password_cached("u", &h1, "yanlis"));
        assert_eq!(
            manager.success_cache.entries.len(),
            0,
            "yanlis parola onbellege girmez"
        );
        assert!(manager.verify_password_cached("u", &h1, "dogru"));
        assert_eq!(manager.success_cache.entries.len(), 1);
        assert!(manager.verify_password_cached("u", &h1, "dogru"));
        assert_eq!(manager.success_cache.entries.len(), 1);
        // Başka kullanıcı veya yanlış parola önbellekten geçmez
        assert!(!manager.verify_password_cached("v", &h1, "yanlis"));
        assert!(!manager.verify_password_cached("u", &h1, "dogru2"));
        // Kayıtlı özet değişince eski başarı geçersiz (yeni özet başka parola ister)
        let h2 = apr1_hash("yeni", "salt2222");
        assert!(!manager.verify_password_cached("u", &h2, "dogru"));
        assert!(manager.verify_password_cached("u", &h2, "yeni"));
    }

    #[test]
    fn r9b_success_cache_is_bounded_and_expires() {
        let cache = SuccessCache::new();
        let now = Instant::now();
        let k = cache.key("u", "p", "h");
        assert!(!cache.is_fresh(&k, now));
        cache.insert(k, now);
        assert!(cache.is_fresh(&k, now + Duration::from_secs(29)));
        assert!(!cache.is_fresh(&k, now + SUCCESS_CACHE_TTL + Duration::from_secs(1)));
        // Alan sınırı: uzunluk önekli anahtar ("ab","c") ile ("a","bc") çakışmaz
        assert_ne!(cache.key("ab", "c", "h"), cache.key("a", "bc", "h"));
        for i in 0..(SUCCESS_CACHE_MAX_ENTRIES + 50) {
            cache.insert(cache.key("u", &format!("p{i}"), "h"), now);
        }
        assert!(cache.entries.len() <= SUCCESS_CACHE_MAX_ENTRIES);
        // Süresi dolmuş kayıtlar dolu tabloda temizlenir
        let later = now + SUCCESS_CACHE_TTL + Duration::from_secs(5);
        cache.insert(cache.key("yeni", "p", "h"), later);
        assert!(cache.entries.len() < SUCCESS_CACHE_MAX_ENTRIES);
    }
}
