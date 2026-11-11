//! ZMax Server - Compile-Time Polymorphic String Encryption Motoru (ZMax PolyCrypt)
//!
//! Bu modül, ikili dosyaların (binary) tersine mühendisliğe (IDA Pro, Ghidra, radare2, strings)
//! karşı en üst düzeyde korunmasını sağlar.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
extern crate std;

/// Derleme anında 64-bit FNV-1a tabanlı benzersiz entropi tohumu üretir.
pub const fn derive_seed(file: &str, line: u32, col: u32, len: usize) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let bytes = file.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        i += 1;
    }
    hash ^= (line as u64).wrapping_mul(0x9E3779B97F4A7C15);
    hash ^= (col as u64).rotate_left(17);
    hash ^= (len as u64).rotate_left(31);
    hash
}

/// Derleme anında string baytlarını çok katmanlı polimorfik şifreler.
pub const fn poly_encrypt<const N: usize>(input: &[u8; N], seed: u64) -> [u8; N] {
    let mut encrypted = [0u8; N];
    let mut state = seed ^ 0xA5A55A5AA55AA5A5;
    let mut prev: u8 = (seed & 0xFF) as u8;
    
    let mut i = 0;
    while i < N {
        // XorShift64* PRNG adımı
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let keystream = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as u8;
        
        let rot = (((i ^ (seed as usize)) % 7) + 1) as u32;
        let mut byte = input[i];
        
        // 1. Avalanche: Önceki şifreli bayt ile XOR
        byte ^= prev;
        // 2. Non-linear rotasyon
        byte = byte.rotate_left(rot);
        // 3. Keystream ve değişken indis ile harmanlama
        byte = byte.wrapping_add(keystream).wrapping_add(i as u8);
        
        encrypted[i] = byte;
        prev = byte;
        i += 1;
    }
    encrypted
}

/// Çalışma anında (runtime) stack üzerinde şifreyi çözer.
/// `#[inline(always)]` ile her çağrıldığı yere doğrudan assembly olarak gömülür.
#[inline(always)]
pub fn poly_decrypt<const N: usize>(encrypted: &[u8; N], seed: u64, out: &mut [u8; N]) {
    let mut state = seed ^ 0xA5A55A5AA55AA5A5;
    let mut prev: u8 = (seed & 0xFF) as u8;

    for i in 0..N {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let keystream = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as u8;
        
        let rot = (((i ^ (seed as usize)) % 7) + 1) as u32;
        let enc_byte = encrypted[i];
        
        // Şifreleme işlemlerinin tam tersi (Inversion)
        let mut byte = enc_byte.wrapping_sub(i as u8).wrapping_sub(keystream);
        byte = byte.rotate_right(rot);
        byte ^= prev;
        
        out[i] = byte;
        prev = enc_byte;
    }
}

/// Çözülen metni güvenli bir şekilde stack buffer içinde tutan ve &str olarak sunan sarmalayıcı.
pub struct ZPolyStr<const N: usize> {
    pub buffer: [u8; N],
}

impl<const N: usize> ZPolyStr<N> {
    #[inline(always)]
    pub fn as_str(&self) -> &str {
        #[cfg(feature = "std")]
        let slice = std::hint::black_box(&self.buffer);
        #[cfg(not(feature = "std"))]
        let slice = &self.buffer;
        
        core::str::from_utf8(slice).unwrap_or("")
    }
}

/// Temel Kullanıcı Makrosu: `zpoly!("Korumalı Metin")`
///
/// Derleme anında metni polimorfik olarak şifreler, binary içine yalnızca
/// anlamsız rastgele baytlar bırakır. Çalışma anında stack üzerinde anlık çözer.
#[macro_export]
macro_rules! zpoly {
    ($text:expr) => {{
        const RAW_STR: &str = $text;
        const RAW_BYTES: &[u8] = RAW_STR.as_bytes();
        const LEN: usize = RAW_BYTES.len();

        // 1. Derleme Anı Tohum Üretimi
        const SEED: u64 = $crate::derive_seed(file!(), line!(), column!(), LEN);

        // 2. Derleme Anı Diziye Dönüştürme
        const fn to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
            let mut arr = [0u8; N];
            let mut idx = 0;
            while idx < N {
                arr[idx] = slice[idx];
                idx += 1;
            }
            arr
        }

        // 3. Derleme Anı Kriptografisi
        const ENCRYPTED: [u8; LEN] = $crate::poly_encrypt(&to_array::<LEN>(RAW_BYTES), SEED);

        // 4. Çalışma Anında Stack Üzerinde Çözümleme
        let mut decrypted = [0u8; LEN];
        $crate::poly_decrypt(&ENCRYPTED, SEED, &mut decrypted);
        
        $crate::ZPolyStr { buffer: decrypted }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_encryption_decryption() {
        let original = "ZePanel ZMax High-Performance Engine 2026!";
        let decrypted = zpoly!("ZePanel ZMax High-Performance Engine 2026!");
        assert_eq!(decrypted.as_str(), original);
    }

    #[test]
    fn test_empty_and_special_characters() {
        let special = "⚡ WAF Korumalı & Özel Karakterler: öçşığü 100% Güvenlik!";
        let decrypted = zpoly!("⚡ WAF Korumalı & Özel Karakterler: öçşığü 100% Güvenlik!");
        assert_eq!(decrypted.as_str(), special);
    }

    #[test]
    fn test_different_seeds_produce_different_ciphertexts() {
        const RAW: &[u8; 11] = b"HELLO WORLD";
        let c1 = poly_encrypt(RAW, 12345);
        let c2 = poly_encrypt(RAW, 67890);
        assert_ne!(c1, c2, "Farklı tohumlar tamamen farklı şifreli metin üretmelidir (Polimorfizm)");
        assert_ne!(c1, *RAW, "Şifreli metin açık metinle aynı olamaz");
    }
}

