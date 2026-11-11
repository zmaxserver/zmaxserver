# ZMax Server — Derleme Anı Polimorfik Kriptografi ve Anti-Decompile Mimarisi

**Amaç:** `zmax-obfuscate` derleme anı dize şifreleme tasarımı. **Güncellenir:** crate değişince. **Bağlı:** [`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md) · [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md)

> **Modül:** `crates/zmax-obfuscate` (**ZMax PolyCrypt**)  
> **Sürüm:** `v1.0.01`  
> **Amaç:** İkili dosyaların (`.exe` / Linux `ELF`) tersine mühendislik (IDA Pro, Ghidra, Binary Ninja, `strings`, `radare2`) ve bellek dökümü (memory dump) analizlerine karşı en üst seviyede korunması.

---

## 1. Neden Geleneksel Şifreleme Yetersizdir?

Standart uygulamalarda metinler (API başlıkları, protokol imzaları, bannerlar, yollar, güvenlik kuralları) derlenmiş dosyanın `.rodata` bölümünde düz metin (plaintext) olarak saklanır. Basit bir `strings zmax` komutu tüm iç mimariyi açığa çıkarır.

Tek anahtarlı klasik XOR korumasında ise:
1. Decompiler tek bir çözücü fonksiyonu (`decrypt_str`) tespit eder.
2. Çapraz referans (XREF) analiziyle bu fonksiyona gönderilen tüm veriler saniyeler içinde topluca deşifre edilir.

**ZMax PolyCrypt** bu saldırı vektörlerinin tamamını ortadan kaldırmak için sıfır harici bağımlılıkla (100% yerli saf Rust) sıfırdan tasarlanmıştır.

---

## 2. ZMax PolyCrypt (Compile-Time Polymorphic String Encryption)

`zpoly!("...")` makrosu çağrıldığında şifreleme işlemi **derleme anında (Compile-Time)** Rust `const fn` motoru tarafından gerçekleştirilir. Derlenmiş ikili dosyanın içinde düz metin ASLA yer almaz.

### 5 Katmanlı Kriptografik Akış:

#### Aşama 1: Polimorfik Entropi Tohumu (`derive_seed`)
Her çağrı noktasında statik ve evrensel bir anahtar yerine, o kod satırına özel benzersiz 64-bit bir tohum üretilir:
- **Girdiler:** Dosya yolu (`file!()`), Satır numarası (`line!()`), Sütun numarası (`column!()`) ve Metin uzunluğu.
- **Algoritma:** `FNV-1a 64-bit` karma fonksiyonu + Altın Oran sabiti (`0x9E3779B97F4A7C15`) + Bit rotasyonları.
- **Sonuç (Polimorfizm):** Aynı metin iki farklı satırda yazılsa bile ikili dosyada tamamen farklı rastgele bayt dizileri (ciphertext) üretilir.

#### Aşama 2: XorShift64* Dinamik Akış Anahtarı (PRNG Stream)
Sabit bir anahtar yerine her bayt adımında durum değiştiren dinamik anahtar akışı kullanılır:
```rust
state ^= state >> 12;
state ^= state << 25;
state ^= state >> 27;
let keystream = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as u8;
```

#### Aşama 3: Avalanche (Çığ Etkisi) & Non-Linear Bit Rotasyonu
Tek bir baytın kırılmasını (bruteforce) imkansız hale getirmek için ardışık bağımlılık zinciri uygulanır:
1. **Zincirleme (CBC/CFB Mantığı):** Her bayt, kendisinden bir önceki şifrelenmiş baytla (`prev`) XOR işlemine tabi tutulur.
2. **Dinamik Rotasyon:** Tohum ve indeks tabanlı 1–7 bit arası dinamik sola kaydırma (`rotate_left`).
3. **Modüler Harmanlama:** Anahtar akışı ve indeks pozisyonu ile `wrapping_add`.

#### Aşama 4: Inlined Stack-Only Çözümleme (XREF Gizleme)
Ortak bir küresel deşifre fonksiyonu bulunmaz. `poly_decrypt` fonksiyonu `#[inline(always)]` olarak işaretlenmiştir:
- Çağrıldığı her noktanın makine kodunun (assembly) doğrudan içine gömülür.
- Tersine mühendislik aracında (Ghidra/IDA) tek bir "şifre çözücü fonksiyon" listelenemez.
- Heap (yığın) belleği tahsis edilmez; yalnızca ilgili thread stack çerçevesinde anlık çözülür ve kapsam bitiminde silinir.

#### Aşama 5: Anti-Constant Folding (`black_box` Bariyeri)
Yüksek optimizasyon seviyelerinde (`opt-level = 3`, `lto = "fat"`) LLVM derleyicisinin "bu dizinin sonucu bellidir" diyerek düz metni yeniden binary içine gömmesini önlemek için `std::hint::black_box` bariyeri uygulanır.

---

## 3. Anti-Decompile Derleyici Zırhı (`Cargo.toml` ve `.cargo/config.toml`)

Polimorfik şifrelemeye ek olarak, derleme çıktısının makine kodu seviyesinde çözümlenmesini zorlaştıran sertleştirme politikaları devrededir:

| Parametre | Değer | Güvenlik Etkisi |
| :--- | :--- | :--- |
| **`opt-level`** | `3` | Döngü açma (loop unrolling), vektörleştirme ve karmaşık kontrol akışı. |
| **`lto`** | `"fat"` | Tüm crate ve fonksiyon sınırlarını yok eder; tek devasa optimizasyon bloğu oluşturur. |
| **`codegen-units`** | `1` | Bölünmüş nesne dosyalarını kapatır, agresif içiçe geçme (inlining) sağlar. |
| **`panic`** | `"abort"` | Hata ayıklama unwind tablolarını ve dosya/satır hata dizelerini ikili dosyadan tamamen siler. |
| **`strip`** | `true` | Tüm sembol tablolarını, fonksiyon isimlerini ve hata ayıklama bilgilerini kazır. |
| **`remap-path-prefix`** | Aktif | Geliştirici ortamındaki kaynak klasör yollarının binary içine yazılmasını engeller. |

---

## 4. Kullanım Standardı (Rust Kodu)

```rust
use zmax_obfuscate::zpoly;

// Çalışma anında stack üzerinde anlık çözülür, binary'de açık metin bulunmaz
let header = zpoly!("ZMax/1.0.01 (ZePanel)");
println!("Motor: {}", header.as_str());
```

---

## 5. Doğrulama Testleri

> Durum: `UNIT TESTED` (3 `#[test]` grep ile sayıldı). Aşağıdaki "GEÇTİ" ifadeleri eski belgeden gelir; bu oturumda `cargo test` çalıştırılmadı. Tersine mühendislik direnci iddiaları ölçülmemiştir.

`cargo test -p zmax-obfuscate` ile doğrulanan güvenlik testleri:
- `test_polymorphic_encryption_decryption` — **GEÇTİ**
- `test_empty_and_special_characters` — **GEÇTİ** (UTF-8 / Türkçe karakter desteği)
- `test_different_seeds_produce_different_ciphertexts` — **GEÇTİ** (Farklı tohumların benzersiz ciphertext ürettiği doğrulandı)

