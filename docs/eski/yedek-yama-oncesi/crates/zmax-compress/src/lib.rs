//! # zmax-compress
//! Saf Rust (sıfır harici bağımlılık) RFC 1951 (DEFLATE Fixed Huffman + LZ77) ve RFC 1952 (GZIP)
//! uçuş anı HTTP sıkıştırma motoru.

use std::io::{self, Write};

/// Varsayılan hızlı sunucu Brotli sıkıştırma kalitesi.
pub const DEFAULT_BROTLI_QUALITY: u32 = 4;
/// Brotli pencere boyutu (`lgwin = 20`, 1 MiB pencere).
pub const BROTLI_LGWIN: u32 = 20;
/// Dinamik sıkıştırma için minimum gövde eşiği (bayt).
pub const MIN_COMPRESS_BODY_SIZE: usize = 256;

/// İstemcinin `Accept-Encoding` başlığını analiz eder ve desteklenen en uygun kodlamayı seçer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentEncoding {
    Identity,
    Gzip,
}

/// Dinamik sıkıştırma motoru için desteklenen HTTP içerik kodlamaları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionEncoding {
    Identity,
    Gzip,
    Brotli,
}

impl CompressionEncoding {
    /// HTTP `Content-Encoding` başlık değerini döndürür (`Identity` için `None`).
    pub fn as_header_value(&self) -> Option<&'static str> {
        match self {
            Self::Identity => None,
            Self::Gzip => Some("gzip"),
            Self::Brotli => Some("br"),
        }
    }
}

/// `Accept-Encoding` başlığına göre `gzip` desteği olup olmadığını belirler.
pub fn negotiate_encoding(accept_encoding: Option<&str>) -> ContentEncoding {
    let Some(raw) = accept_encoding else {
        return ContentEncoding::Identity;
    };
    for part in raw.split(',') {
        let token = part.split(';').next().unwrap_or("").trim();
        if token.eq_ignore_ascii_case("gzip") || token == "*" {
            // q=0 kontrolü
            let q_zero = part
                .split(';')
                .skip(1)
                .any(|p| p.trim().eq_ignore_ascii_case("q=0") || p.trim().eq_ignore_ascii_case("q=0.0"));
            if !q_zero {
                return ContentEncoding::Gzip;
            }
        }
    }
    ContentEncoding::Identity
}

/// RFC 9110 `qvalue` değerini `0..=1000` aralığında binde bir tam sayıya dönüştürür.
fn parse_qvalue(raw: &str) -> Option<u16> {
    let s = raw.trim();
    if s == "0" {
        return Some(0);
    }
    if s == "1" {
        return Some(1000);
    }
    if let Some(frac) = s.strip_prefix("0.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut val = 0u16;
        let mut mult = 100u16;
        for b in frac.bytes() {
            val += (b - b'0') as u16 * mult;
            mult /= 10;
        }
        return Some(val);
    }
    if let Some(frac) = s.strip_prefix("1.") {
        if frac.len() > 3 || !frac.bytes().all(|b| b == b'0') {
            return None;
        }
        return Some(1000);
    }
    None
}

#[derive(Default)]
struct AcceptEncodingWeights {
    zstd: Option<u16>,
    br: Option<u16>,
    gzip: Option<u16>,
    x_gzip: Option<u16>,
    identity: Option<u16>,
    wildcard: Option<u16>,
}

impl AcceptEncodingWeights {
    fn parse(raw: &str) -> Self {
        let mut w = Self::default();
        for item in raw.split(',') {
            let mut parts = item.split(';');
            let coding = parts.next().unwrap_or("").trim();
            if coding.is_empty() {
                continue;
            }

            let mut q_val: Option<u16> = None;
            let mut invalid_q = false;
            for param in parts {
                let param = param.trim();
                if param.is_empty() {
                    continue;
                }
                if let Some((k, v)) = param.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("q") {
                        match parse_qvalue(v) {
                            Some(q) => q_val = Some(q),
                            None => {
                                invalid_q = true;
                                break;
                            }
                        }
                    }
                }
            }
            if invalid_q {
                continue;
            }

            let q = q_val.unwrap_or(1000);
            let slot = if coding.eq_ignore_ascii_case("zstd") {
                &mut w.zstd
            } else if coding.eq_ignore_ascii_case("br") {
                &mut w.br
            } else if coding.eq_ignore_ascii_case("gzip") {
                &mut w.gzip
            } else if coding.eq_ignore_ascii_case("x-gzip") {
                &mut w.x_gzip
            } else if coding.eq_ignore_ascii_case("identity") {
                &mut w.identity
            } else if coding == "*" {
                &mut w.wildcard
            } else {
                continue;
            };

            *slot = Some(match *slot {
                Some(prev) if prev == 0 || q == 0 => 0,
                Some(prev) => prev.max(q),
                None => q,
            });
        }
        w
    }

    fn effective_gzip(&self) -> u16 {
        self.gzip.or(self.x_gzip).or(self.wildcard).unwrap_or(0)
    }

    fn effective_br(&self) -> u16 {
        self.br.or(self.wildcard).unwrap_or(0)
    }

    fn effective_zstd(&self) -> u16 {
        self.zstd.or(self.wildcard).unwrap_or(0)
    }
}

/// RFC 9110 `Accept-Encoding` kalitelerine (`q=...`, `q=0`, `*`) göre dinamik sıkıştırma
/// kodlamasını seçer (`br` > `gzip` sunucu önceliğiyle).
pub fn negotiate_dynamic_encoding(
    accept_encoding: Option<&str>,
    allow_br: bool,
    allow_gzip: bool,
) -> CompressionEncoding {
    let Some(raw) = accept_encoding else {
        return CompressionEncoding::Identity;
    };
    if raw.trim().is_empty() || (!allow_br && !allow_gzip) {
        return CompressionEncoding::Identity;
    }

    let weights = AcceptEncodingWeights::parse(raw);
    let br_q = if allow_br { weights.effective_br() } else { 0 };
    let gzip_q = if allow_gzip {
        weights.effective_gzip()
    } else {
        0
    };

    let best_compressed = br_q.max(gzip_q);
    if best_compressed == 0 {
        return CompressionEncoding::Identity;
    }

    if let Some(id_q) = weights.identity {
        if id_q > best_compressed {
            return CompressionEncoding::Identity;
        }
    }

    if br_q >= gzip_q {
        CompressionEncoding::Brotli
    } else {
        CompressionEncoding::Gzip
    }
}

/// Önceden sıkıştırılmış statik sidecar dosyalar için kabul edilen `(uzantı, kodlama)` çiftlerini
/// RFC 9110 `q`-ağırlığına göre (eşitlikte `.zst` > `.br` > `.gz` önceliğiyle) döndürür.
pub fn negotiate_sidecar_extensions(
    accept_encoding: Option<&str>,
) -> Vec<(&'static str, &'static str)> {
    let Some(raw) = accept_encoding else {
        return Vec::new();
    };
    if raw.trim().is_empty() {
        return Vec::new();
    }

    let weights = AcceptEncodingWeights::parse(raw);
    let mut candidates: Vec<(u16, u8, &'static str, &'static str)> = Vec::with_capacity(3);

    let zstd_q = weights.effective_zstd();
    if zstd_q > 0 {
        candidates.push((zstd_q, 0, ".zst", "zstd"));
    }
    let br_q = weights.effective_br();
    if br_q > 0 {
        candidates.push((br_q, 1, ".br", "br"));
    }
    let gzip_q = weights.effective_gzip();
    if gzip_q > 0 {
        candidates.push((gzip_q, 2, ".gz", "gzip"));
    }

    // Yüksek q değeri önce; eşitlikte sunucu önceliği (zstd=0 < br=1 < gzip=2)
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    candidates
        .into_iter()
        .map(|(_, _, ext, enc)| (ext, enc))
        .collect()
}

/// Gövde boyutunun minimum sıkıştırma eşiğini (`>= 256` bayt) karşılayıp karşılamadığını kontrol eder.
#[inline]
pub fn is_compressible_body_size(body_len: usize) -> bool {
    body_len >= MIN_COMPRESS_BODY_SIZE
}

/// Yanıtın hem boyut eşiği (`>= 256` bayt) hem MIME türü açısından sıkıştırmaya uygunluğunu kontrol eder.
pub fn should_compress(mime: &str, body_len: usize, allowed_prefixes: &[String]) -> bool {
    is_compressible_body_size(body_len) && is_compressible_mime(mime, allowed_prefixes)
}

/// Yanıtın MIME türüne göre sıkıştırılmaya uygun olup olmadığını kontrol eder.
pub fn is_compressible_mime(mime: &str, allowed_prefixes: &[String]) -> bool {
    let base = mime.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    if base.is_empty() {
        return false;
    }
    if allowed_prefixes.is_empty() {
        if base == "text/event-stream" {
            return false;
        }
        return base.starts_with("text/")
            || base.ends_with("+json")
            || base.ends_with("+xml")
            || matches!(
                base.as_str(),
                "application/javascript"
                    | "application/x-javascript"
                    | "application/json"
                    | "application/xml"
                    | "application/xhtml+xml"
                    | "application/wasm"
                    | "application/manifest+json"
                    | "application/rss+xml"
                    | "application/atom+xml"
                    | "image/svg+xml"
            );
    }
    allowed_prefixes
        .iter()
        .any(|p| base == p.to_ascii_lowercase() || base.starts_with(&p.to_ascii_lowercase()))
}

/// IEEE 802.3 CRC-32 hesaplar (GZIP alt bilgisi için zorunlu).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

struct BitWriter {
    out: Vec<u8>,
    bit_buf: u32,
    bit_cnt: u8,
}

impl BitWriter {
    fn with_capacity(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap),
            bit_buf: 0,
            bit_cnt: 0,
        }
    }

    #[inline]
    fn write_bits_lsb(&mut self, val: u32, count: u8) {
        self.bit_buf |= val << self.bit_cnt;
        self.bit_cnt += count;
        while self.bit_cnt >= 8 {
            self.out.push((self.bit_buf & 0xFF) as u8);
            self.bit_buf >>= 8;
            self.bit_cnt -= 8;
        }
    }

    /// Huffman kodları MSB-first olduğu için bit sırasını tersleyip LSB akışına yazar.
    #[inline]
    fn write_huffman_msb(&mut self, code: u16, len: u8) {
        let mut rev = 0u32;
        for i in 0..len {
            if (code >> (len - 1 - i)) & 1 != 0 {
                rev |= 1 << i;
            }
        }
        self.write_bits_lsb(rev, len);
    }

    fn flush_to_byte(mut self) -> Vec<u8> {
        if self.bit_cnt > 0 {
            self.out.push((self.bit_buf & 0xFF) as u8);
        }
        self.out
    }
}

#[inline]
fn encode_fixed_literal(bw: &mut BitWriter, sym: u16) {
    match sym {
        0..=143 => bw.write_huffman_msb(0b0011_0000 + sym, 8),
        144..=255 => bw.write_huffman_msb(0b1_1001_0000 + (sym - 144), 9),
        256..=279 => bw.write_huffman_msb(sym - 256, 7),
        280..=287 => bw.write_huffman_msb(0b1100_0000 + (sym - 280), 8),
        _ => {}
    }
}

fn encode_length(bw: &mut BitWriter, len: usize) {
    const LENGTH_BASES: [(u16, u16, u8); 29] = [
        (3, 257, 0),   (4, 258, 0),   (5, 259, 0),   (6, 260, 0),
        (7, 261, 0),   (8, 262, 0),   (9, 263, 0),   (10, 264, 0),
        (11, 265, 1),  (13, 266, 1),  (15, 267, 1),  (17, 268, 1),
        (19, 269, 2),  (23, 270, 2),  (27, 271, 2),  (31, 272, 2),
        (35, 273, 3),  (43, 274, 3),  (51, 275, 3),  (59, 276, 3),
        (67, 277, 4),  (83, 278, 4),  (99, 279, 4),  (115, 280, 4),
        (131, 281, 5), (163, 282, 5), (195, 283, 5), (227, 284, 5),
        (258, 285, 0),
    ];
    for (idx, &(base, sym, extra_bits)) in LENGTH_BASES.iter().enumerate() {
        let next_base = if idx + 1 < LENGTH_BASES.len() {
            LENGTH_BASES[idx + 1].0 as usize
        } else {
            259
        };
        if len >= base as usize && len < next_base {
            encode_fixed_literal(bw, sym);
            if extra_bits > 0 {
                bw.write_bits_lsb((len - base as usize) as u32, extra_bits);
            }
            return;
        }
    }
}

fn encode_distance(bw: &mut BitWriter, dist: usize) {
    const DIST_BASES: [(u16, u16, u8); 30] = [
        (1, 0, 0),     (2, 1, 0),     (3, 2, 0),     (4, 3, 0),
        (5, 4, 1),     (7, 5, 1),     (9, 6, 2),     (13, 7, 2),
        (17, 8, 3),    (25, 9, 3),    (33, 10, 4),   (49, 11, 4),
        (65, 12, 5),   (97, 13, 5),   (129, 14, 6),  (193, 15, 6),
        (257, 16, 7),  (385, 17, 7),  (513, 18, 8),  (769, 19, 8),
        (1025, 20, 9), (1537, 21, 9), (2049, 22, 10),(3073, 23, 10),
        (4097, 24, 11),(6145, 25, 11),(8193, 26, 12),(12289, 27, 12),
        (16385, 28, 13),(24577, 29, 13),
    ];
    for (idx, &(base, sym, extra_bits)) in DIST_BASES.iter().enumerate() {
        let next_base = if idx + 1 < DIST_BASES.len() {
            DIST_BASES[idx + 1].0 as usize
        } else {
            32769
        };
        if dist >= base as usize && dist < next_base {
            bw.write_huffman_msb(sym, 5);
            if extra_bits > 0 {
                bw.write_bits_lsb((dist - base as usize) as u32, extra_bits);
            }
            return;
        }
    }
}

/// Verilen veriyi RFC 1951 Fixed-Huffman + LZ77 ile DEFLATE akışına sıkıştırır.
pub fn deflate_fixed_lz77(input: &[u8]) -> Vec<u8> {
    let mut bw = BitWriter::with_capacity(input.len() / 2 + 16);
    bw.write_bits_lsb(1, 1); // BFINAL = 1
    bw.write_bits_lsb(1, 2); // BTYPE = 01 (Fixed Huffman)

    const HASH_SIZE: usize = 4096;
    let mut head = [u32::MAX; HASH_SIZE];
    let mut pos = 0usize;

    while pos < input.len() {
        if pos + 3 <= input.len() {
            let h = (((input[pos] as usize) << 8)
                ^ ((input[pos + 1] as usize) << 4)
                ^ (input[pos + 2] as usize))
                & (HASH_SIZE - 1);
            let prev = head[h];
            head[h] = pos as u32;

            if prev != u32::MAX {
                let p = prev as usize;
                let dist = pos - p;
                if dist > 0 && dist <= 32768 {
                    let max_len = (input.len() - pos).min(258);
                    let mut mlen = 0usize;
                    while mlen < max_len && input[p + mlen] == input[pos + mlen] {
                        mlen += 1;
                    }
                    if mlen >= 3 {
                        encode_length(&mut bw, mlen);
                        encode_distance(&mut bw, dist);
                        // Aradaki 3-byte hash'leri güncelle
                        let end_update = (pos + mlen).min(input.len().saturating_sub(2));
                        for k in (pos + 1)..end_update {
                            let hk = (((input[k] as usize) << 8)
                                ^ ((input[k + 1] as usize) << 4)
                                ^ (input[k + 2] as usize))
                                & (HASH_SIZE - 1);
                            head[hk] = k as u32;
                        }
                        pos += mlen;
                        continue;
                    }
                }
            }
        }
        encode_fixed_literal(&mut bw, input[pos] as u16);
        pos += 1;
    }

    encode_fixed_literal(&mut bw, 256); // EOB
    bw.flush_to_byte()
}

/// Veriyi RFC 1952 uyumlu tam GZIP formatında sıkıştırır.
pub fn gzip_compress(input: &[u8]) -> Vec<u8> {
    let compressed = deflate_fixed_lz77(input);
    let mut out = Vec::with_capacity(10 + compressed.len() + 8);
    // RFC 1952 GZIP Header (10 bayt)
    out.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0xFF]);
    out.extend_from_slice(&compressed);
    let sum = crc32(input);
    let isize = (input.len() as u32).to_le_bytes();
    out.extend_from_slice(&sum.to_le_bytes());
    out.extend_from_slice(&isize);
    out
}

/// Veriyi gerçek Brotli (RFC 7932) formatında sıkıştırır.
/// `quality` güvenli sunucu aralığına (`1..=9`) sıkıştırılır (`lgwin = 20`).
pub fn compress_brotli(data: &[u8], quality: u32) -> io::Result<Vec<u8>> {
    let clamped_quality = quality.clamp(1, 9);
    let mut out = Vec::new();
    {
        let mut writer =
            brotli::CompressorWriter::new(&mut out, 4096, clamped_quality, BROTLI_LGWIN);
        writer.write_all(data)?;
        writer.flush()?;
    }
    Ok(out)
}

/// Veriyi varsayılan hızlı sunucu kalitesiyle (`quality = 4`, `lgwin = 20`) Brotli ile sıkıştırır.
pub fn compress_brotli_default(data: &[u8]) -> io::Result<Vec<u8>> {
    compress_brotli(data, DEFAULT_BROTLI_QUALITY)
}

/// Seçilen dinamik kodlamaya göre veriyi sıkıştırır (`Identity` için ham kopya).
pub fn compress_dynamic(data: &[u8], encoding: CompressionEncoding) -> io::Result<Vec<u8>> {
    match encoding {
        CompressionEncoding::Identity => Ok(data.to_vec()),
        CompressionEncoding::Gzip => Ok(gzip_compress(data)),
        CompressionEncoding::Brotli => compress_brotli(data, DEFAULT_BROTLI_QUALITY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_gzip_compresses_repetitive_html_effectively() {
        let html = b"<html><body><h1>ZMax Server Test Sayfasi</h1><p>Hizli HTTP sunumu ve gzip sikistirma denemesi.</p></body></html>".repeat(12);
        let gz = gzip_compress(&html);
        assert_eq!(&gz[..3], &[0x1F, 0x8B, 0x08]);
        assert!(gz.len() < html.len() / 2, "Yeterli sıkıştırma sağlanamadı: {} vs {}", gz.len(), html.len());
        let len_trailer = u32::from_le_bytes(gz[gz.len() - 4..].try_into().unwrap()) as usize;
        assert_eq!(len_trailer, html.len());
    }

    #[test]
    fn test_negotiate_encoding() {
        assert_eq!(negotiate_encoding(Some("br, gzip, deflate")), ContentEncoding::Gzip);
        assert_eq!(negotiate_encoding(Some("identity")), ContentEncoding::Identity);
        assert_eq!(negotiate_encoding(Some("gzip;q=0")), ContentEncoding::Identity);
        assert_eq!(negotiate_encoding(None), ContentEncoding::Identity);
    }

    #[test]
    fn test_brotli_roundtrip_and_quality_clamp() {
        let html = b"<html><body><h1>ZMax Brotli</h1><p>Tekrarli icerik sikistirma testi.</p></body></html>".repeat(16);

        // Kalite 0 -> 1 ve 99 -> 9 clamp edilerek sorunsuz çalışmalı
        for q in [0, 1, DEFAULT_BROTLI_QUALITY, 9, 99] {
            let compressed = compress_brotli(&html, q).expect("Brotli sıkıştırma hatası");
            assert!(
                compressed.len() < html.len() / 3,
                "Yetersiz Brotli oranı (q={q}): {} vs {}",
                compressed.len(),
                html.len()
            );

            let mut decompressed = Vec::new();
            let mut reader = brotli::Decompressor::new(compressed.as_slice(), 4096);
            reader.read_to_end(&mut decompressed).expect("Brotli açma hatası");
            assert_eq!(decompressed, html);
        }

        // Boş girdi gidiş-dönüş testi
        let empty_br = compress_brotli(b"", DEFAULT_BROTLI_QUALITY).unwrap();
        let mut empty_out = Vec::new();
        brotli::Decompressor::new(empty_br.as_slice(), 4096)
            .read_to_end(&mut empty_out)
            .unwrap();
        assert!(empty_out.is_empty());
    }

    #[test]
    fn test_negotiate_dynamic_encoding_rfc9110() {
        // Eşit q'da br > gzip önceliği
        assert_eq!(
            negotiate_dynamic_encoding(Some("gzip, deflate, br"), true, true),
            CompressionEncoding::Brotli
        );
        // Sunucu br kapattıysa gzip seçilir
        assert_eq!(
            negotiate_dynamic_encoding(Some("gzip, deflate, br"), false, true),
            CompressionEncoding::Gzip
        );
        // q-ağırlık sıralaması: gzip;q=0.9 > br;q=0.5
        assert_eq!(
            negotiate_dynamic_encoding(Some("br;q=0.5, gzip;q=0.9"), true, true),
            CompressionEncoding::Gzip
        );
        // q=0 reddi: br;q=0 olsa bile wildcard br'yi geri açamaz
        assert_eq!(
            negotiate_dynamic_encoding(Some("br;q=0, *;q=0.8"), true, true),
            CompressionEncoding::Gzip
        );
        // gzip;q=0 ile sadece br kalır
        assert_eq!(
            negotiate_dynamic_encoding(Some("br;q=0.3, gzip;q=0"), true, true),
            CompressionEncoding::Brotli
        );
        // *;q=0 tüm belirtilmeyenleri reddeder
        assert_eq!(
            negotiate_dynamic_encoding(Some("*;q=0"), true, true),
            CompressionEncoding::Identity
        );
        // Açık br, *;q=0'ı geçersiz kılar
        assert_eq!(
            negotiate_dynamic_encoding(Some("br;q=0.4, *;q=0"), true, true),
            CompressionEncoding::Brotli
        );
        // Açık identity ağırlığı daha yüksekse Identity seçilir
        assert_eq!(
            negotiate_dynamic_encoding(Some("br;q=0.5, identity;q=0.9"), true, true),
            CompressionEncoding::Identity
        );
        // x-gzip ve geçersiz q değerleri
        assert_eq!(
            negotiate_dynamic_encoding(Some("x-gzip;q=0.8, br;q=2.0"), true, true),
            CompressionEncoding::Gzip
        );
        // Yok veya boş
        assert_eq!(negotiate_dynamic_encoding(None, true, true), CompressionEncoding::Identity);
        assert_eq!(negotiate_dynamic_encoding(Some(""), true, true), CompressionEncoding::Identity);
    }

    #[test]
    fn test_negotiate_sidecar_extensions() {
        // Eşit ağırlıkta sunucu sırası: .zst > .br > .gz
        assert_eq!(
            negotiate_sidecar_extensions(Some("gzip, br, zstd")),
            vec![(".zst", "zstd"), (".br", "br"), (".gz", "gzip")]
        );
        // q ağırlığına göre sıralama
        assert_eq!(
            negotiate_sidecar_extensions(Some("br;q=0.5, gzip;q=0.9, zstd;q=0.7")),
            vec![(".gz", "gzip"), (".zst", "zstd"), (".br", "br")]
        );
        // zstd;q=0 hariç bırakılır
        assert_eq!(
            negotiate_sidecar_extensions(Some("zstd;q=0, br, gzip")),
            vec![(".br", "br"), (".gz", "gzip")]
        );
        // br;q=0 + wildcard
        assert_eq!(
            negotiate_sidecar_extensions(Some("br;q=0, *")),
            vec![(".zst", "zstd"), (".gz", "gzip")]
        );
        // *;q=0 ve None boş döner
        assert!(negotiate_sidecar_extensions(Some("*;q=0")).is_empty());
        assert!(negotiate_sidecar_extensions(None).is_empty());
    }

    #[test]
    fn test_min_body_size_and_mime_eligibility() {
        assert!(!is_compressible_body_size(255));
        assert!(is_compressible_body_size(256));

        assert!(!should_compress("text/html; charset=utf-8", 255, &[]));
        assert!(should_compress("text/html; charset=utf-8", 256, &[]));
        assert!(should_compress("application/javascript", 512, &[]));
        assert!(should_compress("image/svg+xml", 300, &[]));
        assert!(!should_compress("image/png", 4096, &[]));
        assert!(!should_compress("text/event-stream", 1024, &[]));
    }
}

