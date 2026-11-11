# ⚡ ZMax Server - Geliştirme, Test ve Üretim Araçları Kataloğu

Bu dizin (`D:\zmaxserver\doc\tools`), ZMax Server geliştirme döngüsü, çapraz derleme, kurumsal paketleme, paket doğrulama, performans testleri ve güvenlik denetimleri için gereken tüm bağımsız araçları ve belgeleri içerir.

> 📘 **Detaylı Derleme ve Dağıtım Rehberi:** Windows yerel derleme, Linux x64/ARM64 statik musl çapraz derleme, `.deb`/`.rpm`/`.tar.gz`/`.zip` paket üretimi ve doğrulama adımları için [`derleme.md`](./derleme.md) dosyasına bakın.

---

## 🛠️ Araçlar Listesi ve Kullanımı

| Dosya | Tür | Açıklama |
| :--- | :--- | :--- |
| `derleme.md` | Belge (Markdown) | Ön koşullar, Windows/Linux musl derleme, `cargo test`, paket üretimi, port ve proxy/token notları için tam rehber. |
| `package_all.bat` | Betik (CMD) | Windows + (kuruluysa) Linux x64/ARM64 musl hedeflerini derler, `pack_zmax.py` ile paketler ve `verify_packages.py` ile doğrular (`win`, `full`, `--skip-build`, `--nopause`). |
| `pack_zmax.py` | Python Aracı | Windows `.zip`, Linux x64/ARM64 `.tar.gz`, `.deb`, `.rpm` (`nfpm` ile) paketlerini ve `SHA256SUMS.txt` dosyasını üretir. |
| `verify_packages.py` | Python Aracı | Üretilen `.zip`, `.tar.gz`, `.deb` ve `.rpm` arşivlerinin dosya ağacı, LF satır sonu, 18 modül, port bloğu ve göreli WebAdmin yollarını doğrular. |
| `inspect_packages.py` | Python Aracı | Paketlerin iç dosya listelerini, izin modlarını, DEB `control`/`data` ve RPM CPIO yük içeriklerini ayrıntılı inceler. |
| `live_smoke.py` | Python Aracı | Çalışan ZMax Server (`19480`, `19485`, `19486`) üzerinde L1 Cache (`MISS -> HIT`), `/v1/zmax/console/` ters vekil simülasyonu ve vHost CRUD + traversal korumasını canlı test eder. |
| `bombardier.exe` | 9.7 MB (x64 Binary) | Yüksek eşzamanlı HTTP/1.1 ve HTTP/2 yük ve benchmark aracı. |
| `benchmark_test.bat` | Betik (CMD) | 125 eşzamanlı bağlantıyla 10 saniyelik HTTP yük testini (`127.0.0.1:19480`) tek tıkla başlatır. |
| `slowloris_test.ps1` | PowerShell Betiği | Slowloris DoS saldırı simülasyonu yapar; 10s zaman aşımında soket kapatmayı doğrular. |
| `rate_limit_test.ps1` | PowerShell Betiği | Token Bucket algoritmasını test eder; 2000+ istekte `429 Too Many Requests` kalkanını doğrular. |
| `rustup-init.exe` | 12.8 MB (Kurucu) | Rust ve Cargo derleme ortamı resmi kurucusu. |
| `rust_kurulum.bat` | Betik (CMD) | Tek tıkla Rust geliştirme ortamını kuran betik. |
| `generate_ssl_cert.bat` | Betik (CMD) | Yerel HTTPS (Port `19483`) testi için kendinden imzalı SSL sertifikası üretir. |

---

## 🚀 Hızlı Başlangıç

### 1. Tek Tıkla Tam Derleme ve Paketleme:
```cmd
package_all.bat
```
*(Sadece Windows paketi için: `package_all.bat win`; derlemeyi atlayıp mevcut ikili dosyaları paketlemek için: `package_all.bat --skip-build`)*

### 2. Python ile Paket Üretimi, Doğrulama ve İnceleme:
```cmd
python pack_zmax.py
python verify_packages.py
python inspect_packages.py --format rpm
```

### 3. Canlı Uçtan Uca Smoke Testi (Sunucu Çalışırken):
```cmd
python live_smoke.py
```

### 4. Performans ve Güvenlik Testleri:
```cmd
benchmark_test.bat
powershell -ExecutionPolicy Bypass -File .\slowloris_test.ps1
powershell -ExecutionPolicy Bypass -File .\rate_limit_test.ps1
```
