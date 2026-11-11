# ⚡ ZMax Server — Derleme, Paketleme ve Doğrulama Rehberi

Bu rehber; **ZMax Server (`v1.0.01` / Workspace `1.0.1`)** projesinin Windows yerel ortamında derlenmesini, `Zig` + `rust-lld` ile Linux x64/ARM64 statik `musl` hedeflerine çapraz derlenmesini, birim/entegrasyon testlerinin çalıştırılmasını, kurumsal dağıtım paketlerinin (`.zip`, `.tar.gz`, `.deb`, `.rpm`, `SHA256SUMS.txt`) üretilmesini ve canlı sistem doğrulamalarını adım adım açıklar.

---

## 1. Ön Koşullar ve Araç Zinciri

### 1.1. Gerekli Araçlar

| Araç | Doğrulanan Sürüm / Konum | Görevi ve Kurulum Yöntemi |
| :--- | :--- | :--- |
| **`rustc` & `cargo`** | `1.99.1` (`~/.cargo/bin`) | Rust derleyicisi ve paket yöneticisi. Kurulum için `doc\tools\rustup-init.exe` veya `doc\tools\rust_kurulum.bat` çalıştırılabilir. |
| **`rustup` & Hedefler** | `1.29.3` (Toolchain: `stable-x86_64-pc-windows-msvc`) | Hedef mimari yönetimi (`x86_64-pc-windows-msvc`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`). |
| **MSVC Build Tools** | Visual Studio 2022 Build Tools (`C++` + Windows SDK) | Yerel Windows Release (`x86_64-pc-windows-msvc`) derlemelerinde `link.exe` bağlayıcısı ve Windows SDK kütüphaneleri için gereklidir. |
| **`zig`** | `0.17.1` (`%LOCALAPPDATA%\Microsoft\WinGet\Links\zig.exe`) | Linux `musl` çapraz derlemelerinde C/Assembly bağımlılıkları (`ring`) için `zig cc` ve `zig ar` sağlar. Kurulum: `winget install zig.zig`. |
| **`python`** | `3.13+` (`%LOCALAPPDATA%\Programs\Python\Python313\python.exe`) | `.cargo\zig-cc-*.cmd` sarmalayıcıları ve `doc\tools\*.py` paketleme/doğrulama araçları için gereklidir. |
| **`nfpm`** | `2.48.0` (`D:\lunixpanel\zpanel-tam\araclar\nfpm\nfpm.exe` veya `PATH`) | Linux `.rpm` paketlerinin üretimi için gereklidir (`winget install goreleaser.nfpm` veya `doc\tools\nfpm.exe`). |

### 1.2. Rust Hedeflerini Kurma ve Doğrulama

```powershell
rustup target add x86_64-pc-windows-msvc x86_64-unknown-linux-musl aarch64-unknown-linux-musl
rustup target list --installed
```

Yeni kurulum sonrası `zig` mevcut oturumun `PATH` listesinde görünmüyorsa PowerShell oturumuna geçici olarak ekleyin:

```powershell
$env:PATH = "$env:LOCALAPPDATA\Microsoft\WinGet\Links;$env:PATH"
zig version
python --version
```

### 1.3. `.cargo/config.toml` ve `zig-cc-*.py` Sarmalayıcılarının Çalışma Mantığı

Proje kökündeki [`.cargo/config.toml`](file:///D:/zmaxserver/.cargo/config.toml) dosyası, tüm hedefler için bağlayıcı ve yol güvenliği kurallarını otomatik uygular:

1. **Tam Statik Linux `musl` Bağlama:**
   `[target.x86_64-unknown-linux-musl]` ve `[target.aarch64-unknown-linux-musl]` hedeflerinde `linker = "rust-lld"` ile `target-feature = "+crt-static"` bayrakları tanımlıdır. Böylece üretilen `zmax` ikili dosyası hedef Linux sunucuda `glibc` sürümünden bağımsız olarak çalışır.
2. **Yol Gizliliği (`--remap-path-prefix`):**
   Hem Windows hem Linux hedeflerinde `--remap-path-prefix=D:\zmaxserver=ZMAX_CORE` uygulanır; ikili dosyaların hata/sembol metinlerine yerel geliştirici dizin yolları sızmaz.
3. **C/Assembly Bağımlılıkları için `zig-cc` Sarmalayıcısı:**
   `zmax-tls` crate'i (`rustls` + `tokio-rustls` üzerinden `ring`) derlenirken `cc-rs` aracı C derleyicisine `--target=x86_64-unknown-linux-musl` biçiminde parametre gönderir. `zig cc` bu `--target=...` eşittir sözdizimini doğrudan desteklemediği (`-target <hedef>` beklediği) için `.cargo/config.toml` içindeki `[env]` bölümü derlemeyi sarmalayıcılara yönlendirir:
   - `CC_x86_64_unknown_linux_musl` → [`.cargo/zig-cc-x64.cmd`](file:///D:/zmaxserver/.cargo/zig-cc-x64.cmd) → [`.cargo/zig-cc-x64.py`](file:///D:/zmaxserver/.cargo/zig-cc-x64.py) (`--target=` argümanlarını süzer ve `zig cc -target x86_64-linux-musl` çağırır).
   - `CC_aarch64_unknown_linux_musl` → [`.cargo/zig-cc-arm64.cmd`](file:///D:/zmaxserver/.cargo/zig-cc-arm64.cmd) → [`.cargo/zig-cc-arm64.py`](file:///D:/zmaxserver/.cargo/zig-cc-arm64.py) (`--target=` argümanlarını süzer ve `zig cc -target aarch64-linux-musl` çağırır).
   - `AR_*` → [`.cargo/zig-ar.cmd`](file:///D:/zmaxserver/.cargo/zig-ar.cmd) (`zig ar %*`).
4. **Release Profili ve Bellek Ayırıcı:**
   [`Cargo.toml`](file:///D:/zmaxserver/Cargo.toml) içindeki `[profile.release]` bloğu `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` ve `strip = true` ayarlarıyla maksimum boyut/hız optimizasyonu uygular. [`crates/zmax-bin/Cargo.toml`](file:///D:/zmaxserver/crates/zmax-bin/Cargo.toml) üzerinde `mimalloc` yalnızca `not(target_env = "musl")` hedeflerinde (ör. Windows MSVC) global ayırıcı olarak etkinleştirilir; statik `musl` derlemelerinde standart `musl` ayırıcı kullanılır.

---

## 2. Derleme Adımları

Tüm derleme komutları proje kök dizininden (`D:\zmaxserver`) çalıştırılır.

### 2.1. Windows Yerel Release Derleme (`x86_64-pc-windows-msvc`)

```powershell
cd D:\zmaxserver
cargo build --release
```

- **Çıktı:** `D:\zmaxserver\target\release\zmax.exe`
- **Hızlı CLI Doğrulaması:**
  ```powershell
  .\target\release\zmax.exe -v
  .\target\release\zmax.exe -t
  ```
  - `-v` / `--version`: Sunucu sürüm bilgisini yazdırır.
  - `-t` / `--check` / `--test`: `conf/zmax.toml` ve `conf/vhosts/*.toml` yapılandırmalarını doğrulayıp çıkış kodu döner.
  - `-c <yol>` / `--config <yol>`: Özel yapılandırma dosyası yolu belirtir.

### 2.2. Linux x64 Statik `musl` Çapraz Derleme

```powershell
cd D:\zmaxserver
$env:PATH = "$env:LOCALAPPDATA\Microsoft\WinGet\Links;$env:PATH"
cargo build --release --target x86_64-unknown-linux-musl
```

- **Çıktı:** `D:\zmaxserver\target\x86_64-unknown-linux-musl\release\zmax`

### 2.3. Linux ARM64 (`aarch64`) Statik `musl` Çapraz Derleme

```powershell
cd D:\zmaxserver
$env:PATH = "$env:LOCALAPPDATA\Microsoft\WinGet\Links;$env:PATH"
cargo build --release --target aarch64-unknown-linux-musl
```

- **Çıktı:** `D:\zmaxserver\target\aarch64-unknown-linux-musl\release\zmax`

---

## 3. Workspace Birim ve Entegrasyon Testleri

Workspace altındaki tüm 18 crate (`zmax-runtime`, `zmax-httpparser`, `zmax-header`, `zmax-pool`, `zmax-tls`, `zmax-timeout`, `zmax-proxy`, `zmax-fastcgi`, `zmax-static`, `zmax-cache`, `zmax-compress`, `zmax-rewrite`, `zmax-security`, `zmax-config`, `zmax-redis`, `zmax-obfuscate`, `zmax-core`, `zmax-bin`) testlerini ve statik kod analizini çalıştırmak için:

```powershell
cd D:\zmaxserver
cargo clippy --workspace --all-targets --locked --offline
cargo test --workspace --locked --offline
```

> Bu komutlar; sıfır Clippy uyarısını, **131/131** birim + entegrasyon testini, `.htaccess` + `PATH_INFO`, IP ACL CIDR, SWR/Stampede, TLS panel dinleyicisi ve `19480–19486` port çakışmazlık doğrulamalarını çevrimdışı kilitli bağımlılıklarla yürütür. Mimari ve rakip modül durumu için ayrıca [FERRON_VE_LITESPEED_KARSILASTIRMA.md](file:///D:/zmaxserver/doc/FERRON_VE_LITESPEED_KARSILASTIRMA.md) dosyasına bakınız.

---

## 4. Tüm Dağıtım Paketlerinin Üretimi

### 4.1. Tek Tıkla Derleme + Paketleme (`package_all.bat`)

[`doc\tools\package_all.bat`](file:///D:/zmaxserver/doc/tools/package_all.bat) betiği; önce Windows Release'i, ardından sistemde `zig` + `python` ve ilgili `rustup` hedefleri kuruluysa Linux x64 ve ARM64 `musl` hedeflerini derler; sonrasında `pack_zmax.py` ile paketleri üretir ve `verify_packages.py` ile doğrular:

```cmd
cd /d D:\zmaxserver\doc\tools
package_all.bat
```

Desteklenen bayraklar:
- `package_all.bat win`: Yalnızca Windows x64 derlemesi ve `.zip` paketi üretir.
- `package_all.bat --skip-build`: `cargo build` adımlarını atlayıp mevcut ikili dosyalarla paketleri yeniler.
- `package_all.bat --nopause`: İşlem sonunda bekleme (`pause`) yapmadan çıkar.

### 4.2. Python Paketleyicisi ile Doğrudan Üretim (`pack_zmax.py`)

Derlenmiş ikili dosyalar hazır olduğunda [`doc\tools\pack_zmax.py`](file:///D:/zmaxserver/doc/tools/pack_zmax.py) doğrudan çalıştırılabilir:

```powershell
cd D:\zmaxserver
python doc\tools\pack_zmax.py
```

**Üretilen Dağıtım Çıktıları (`D:\zmaxserver\packed\`):**

| Platform / Format | Çıktı Yolu | İçerik ve Özellikler |
| :--- | :--- | :--- |
| **Windows x64 (`.zip`)** | `packed\zmax-server-v1.0.01-windows-x64.zip` | `win\bin\zmax.exe`, `win\bin\zmaxctrl.bat`, `conf`, `modules` (18 adet), `admin`, `fcgi-bin`, `www`, boş `logs\` ve `cachedata\`. |
| **Linux x64 (`.tar.gz`)** | `packed\zmax-server-v1.0.01-linux-x64.tar.gz` | Statik `zmax`, `zmaxctrl` (`0755`), `install.sh` (`0755`), `systemd\zmax.service`, LF satır sonu dönüşümlü config/web dosyaları. |
| **Linux ARM64 (`.tar.gz`)** | `packed\zmax-server-v1.0.01-linux-arm64.tar.gz` | `aarch64` statik `zmax` ve tüm ortak Linux paket yapısı. |
| **Debian/Ubuntu (`.deb`)** | `packed\deb\zmax-server_1.0.01_amd64.deb`<br>`packed\deb\zmax-server_1.0.01_arm64.deb` | Saf Python `ar` + `tar.gz` paketi; `/usr/local/zmax`, `/etc/systemd/system/zmax.service`, `/usr/local/bin/zmax{,ctrl}` sembolik bağları, `conffiles`, `md5sums`, `postinst`/`prerm`/`postrm`. |
| **AlmaLinux/RHEL/Rocky (`.rpm`)** | `packed\rpm\zmax-server-1.0.01-1.x86_64.rpm`<br>`packed\rpm\zmax-server-1.0.01-1.aarch64.rpm` | `nfpm` ile üretilir; `/usr/lib/systemd/system/zmax.service`, `config|noreplace` yapılandırma koruması, `/usr/local/bin/zmax{,ctrl}` sembolik bağları. |
| **Bütünlük Özeti** | `packed\SHA256SUMS.txt` | Üretilen tüm paketlerin SHA-256 özetleri ve bayt boyutları. |

**Kullanışlı `pack_zmax.py` Parametreleri:**
- `--target {all,win,linux-x64,linux-arm64}`: Yalnızca seçilen hedefi paketler.
- `--nfpm <yol>`: `nfpm.exe` konumunu elle belirtir (belirtilmezse `NFPM_EXE`, `doc\tools\nfpm.exe`, `PATH`, `D:\lunixpanel\zpanel-tam\araclar\nfpm\nfpm.exe`, WinGet/Scoop/Chocolatey yolları taranır).
- `--skip-rpm`: `.rpm` üretimini atlayarak yalnızca `.zip`, `.tar.gz` ve `.deb` üretir.
- `--require-all`: `--target all` modunda eksik derleme ikilisi varsa hata ile durur.

> **Not:** `pack_zmax.py`, paketlenen `admin/` kopyalarında eski `css/admin.css` ve `js/app.js` kalıntılarını temizler ve Linux hedeflerindeki `.toml`, `.types`, `.conf`, `.html`, `.php`, `.sh`, `.service`, `.js`, `.css`, `.svg`, `zmaxctrl` dosyalarını otomatik olarak LF (`\n`) satır sonuna normalize eder.

---

## 5. Paket Doğrulama ve Canlı Test Yöntemleri

### 5.1. Statik Paket Bütünlük Doğrulaması (`verify_packages.py`)

```powershell
python doc\tools\verify_packages.py
```

*(Yalnızca mevcut platform paketlerini doğrulamak için `--allow-missing` bayrağını ekleyin.)*

Bu araç her paketin içinde şunları denetler:
- Zorunlu `admin/`, `conf/`, `fcgi-bin/`, `modules/`, `www/` dosya listesi (`REQUIRED_COMMON`) ve tam `18` adet `modules/mod_*.toml` dosyası.
- Hiçbir test `.log` artığının pakete sızmamış olması.
- Linux paketlerinde `zmax.toml`, `zmaxctrl`, `install.sh`, `zmax.service` dosyalarının CRLF (`\r\n`) içermemesi ve ikili/betik izinlerinin `0755` olması.
- `conf/zmax.toml` içinde `19480`, `19485`, `19486` portlarının yer alması.
- WebAdmin dosyalarında (`admin/index.html`, `admin/js/core.js`) mutlak `/css/...` veya `/api/...` yerine tam göreli yolların bulunması.

### 5.2. Paket İçerik İnceleme (`inspect_packages.py`)

```powershell
python doc\tools\inspect_packages.py
python doc\tools\inspect_packages.py --format rpm
python doc\tools\inspect_packages.py --file D:\zmaxserver\packed\deb\zmax-server_1.0.01_amd64.deb
```

ZIP, TAR.GZ, DEB (`control` + `data`) ve RPM (gzip CPIO yükü) içindeki tüm dosya, dizin, sembolik bağ, izin modu ve bayt boyutlarını listeler.

### 5.3. Canlı Uçtan Uca Smoke Testi (`live_smoke.py`)

Önce ZMax Server'ı başlatın (ör. `.\target\release\zmax.exe` veya `.\bin\zmaxctrl.bat start`), ardından:

```powershell
python doc\tools\live_smoke.py
```

*(API token etkinse `--token <gizli_token>` veya `$env:ZMAX_API_TOKEN` kullanın.)*

Doğrular:
1. **Web `19480`:** `GET /` → `200 OK` ve ardışık istekte L1 Cache `X-Cache: HIT`.
2. **WebAdmin `19485` + Ters Vekil Simülasyonu:** Doğrudan ve yerel `/v1/zmax/console/` ters vekili arkasından `index.html`, `css/core.css`, `js/core.js`, `assets/zmax_white.svg` ve `api/status` çağrılarının `200 OK` dönmesi.
3. **Kontrol API `19486`:** `/api/v1/health`, `/api/v1/status`, `/api/v1/ports` (`collision_detected: false`), `PUT`/`GET`/`DELETE /api/v1/vhosts/...`, `../evil.local` path traversal talebinin `400` ile reddedilmesi, `/api/v1/cache/purge` ve `/api/v1/reload`.

### 5.4. Güvenlik ve Yük Testi Araçları

- **Slowloris Kalkan Testi:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\doc\tools\slowloris_test.ps1
  ```
  `127.0.0.1:19480` üzerinde tamamlanmamış HTTP başlığı göndererek 10 saniyelik Slowloris zaman aşımında bağlantının sunucu tarafından kesildiğini doğrular.
- **Rate Limiting (Token Bucket) Testi:**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\doc\tools\rate_limit_test.ps1
  ```
  `127.0.0.1:19480/index.html` adresine 2100 istek göndererek `rate_limit_per_minute = 2000` sınırında `429 Too Many Requests` kalkanını doğrular.
- **HTTP Yük ve Performans Benchmark (`bombardier.exe`):**
  ```cmd
  doc\tools\benchmark_test.bat
  ```
  125 eşzamanlı bağlantıyla 10 saniyelik HTTP yük testi (`http://127.0.0.1:19480/index.html`) uygular.
- **Kendinden İmzalı SSL Sertifikası (Yerel HTTPS Testi):**
  ```cmd
  doc\tools\generate_ssl_cert.bat
  ```
  `conf\ssl_localhost.cer` üretir (`[listeners.https]` testi için).

---

## 6. Sürüm, Çakışmasız Port (`19480–19486`) ve Proxy/Token Notları

### 6.1. Sürüm Bilgisi

- **Workspace Crate Sürümü (`Cargo.toml`):** `1.0.1`
- **Sunucu & Dağıtım Paket Etiketi (`zmax -v`, `zmax.toml`, `packed/`):** `v1.0.01` (`1.0.01`)

### 6.2. Çakışmasız Port Bloğu (`19480–19486`) ve Ortam Değişkenleri

Popüler kontrol panelleri (`cPanel`, `Plesk`, `DirectAdmin`, `CyberPanel/OLS`, `HestiaCP`, `aaPanel`, `CloudPanel`, `ISPConfig`, `zPanel`) ve OS ephemeral port havuzları (Linux `32768–60999`, Windows `49152–65535`) ile sıfır çakışma için ZMax Server varsayılan olarak IANA Unassigned **`19480–19486`** aralığını kullanır:

| Bileşen | Varsayılan Adres:Port | Yapılandırma (`conf/zmax.toml`) | Ortam Değişkenleri |
| :--- | :--- | :--- | :--- |
| **Web HTTP** | `0.0.0.0:19480` | `[listeners.http]` (`enabled = true`) | `ZMAX_HTTP_ADDR`, `ZMAX_HTTP_PORT` |
| **HTTPS & HTTP/3 QUIC** | `0.0.0.0:19483` | `[listeners.https]` (`enabled = false`, `ssl = true`) | `ZMAX_HTTPS_ADDR`, `ZMAX_HTTPS_PORT` |
| **WebAdmin UI** | `127.0.0.1:19485` | `[listeners.admin]` (`enabled = true`) | `ZMAX_ADMIN_ADDR`, `ZMAX_ADMIN_PORT` |
| **Evrensel Kontrol API** | `127.0.0.1:19486` | `[listeners.api]` (`enabled = true`, opsiyonel `unix_socket`) | `ZMAX_API_ADDR`, `ZMAX_API_PORT`, `ZMAX_API_TOKEN` |

Diğer çalışma zamanı ortam değişkenleri: `ZMAX_HOME` (kök dizin), `ZMAX_CONF` (yapılandırma yolu), `ZMAX_VHOSTS_DIR` (vHost dizini), `ZMAX_WORKERS` (worker sayısı).

### 6.3. Ters Vekil (Reverse Proxy) ve API Token Güvenlik Notları

1. **Tam Göreli WebAdmin Yolları:**
   [`admin/index.html`](file:///D:/zmaxserver/admin/index.html) ve [`admin/js/core.js`](file:///D:/zmaxserver/admin/js/core.js) içindeki tüm CSS/JS/SVG ve API çağrıları (`apiFetch('api/status')`, `apiFetch('api/v1/vhosts')` vb.) mutlak `/` yerine göreli yol kullanır. Böylece WebAdmin konsolu bir kontrol paneli ters vekili arkasından (ör. `/v1/zmax/console/`) HTML/JS yeniden yazımı olmadan sunulabilir.
2. **Sondaki `/` (Trailing Slash) ve Önek Soyma:**
   Panel vekilinden WebAdmin açılırken `/v1/zmax/console/` şeklinde sondaki `/` korunmalıdır (`/v1/zmax/console` gelirse `301`/`302` ile `/v1/zmax/console/` adresine yönlendirilmelidir). İstek yukarı akışa (`http://127.0.0.1:19485`) aktarılırken `/v1/zmax/console` öneki sıyrılmalıdır.
3. **API Token Koruma Davranışı (`crates/zmax-bin/src/api.rs`):**
   - `[listeners.api]` altında `token = "..."` tanımlıysa (veya `ZMAX_API_TOKEN` ortam değişkeni ayarlıysa, `require_token` otomatik etkinleşir) ya da `require_token = true` ise, **yalnızca `/api/v1/health`** ucu herkese açık kalır.
   - Diğer tüm `/api/*` uçları (hem `19486` hem `19485` üzerinden gelenler) sabit zamanlı (`constant_time_eq`) doğrulamayla `Authorization: Bearer <token>` veya `X-ZMax-Token: <token>` başlığını zorunlu kılar; eksik veya geçersiz token durumunda `401 Unauthorized` döner.
   - **Panel Proxy Önerisi:** Üretimde panel ters vekili oturum doğrulaması yaptıktan sonra `127.0.0.1:19485` / `19486` hedefine ilettiği `/api/*` isteklerine `X-ZMax-Token` veya `Authorization: Bearer` başlığını sunucu tarafında enjekte etmelidir; böylece API gizli anahtarı tarayıcıya sızdırılmaz. (Doğrudan WebAdmin kullanımında ise `core.js`, `localStorage.getItem('zmax_api_token')` tanımlıysa isteklere `X-ZMax-Token` başlığını ekler.)
