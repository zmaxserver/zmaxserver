# ZMax Server - Adım Adım Geliştirme ve İlerleme Takibi

Bu dosya, ZMax Server geliştirme sürecindeki her bir adımı sırasıyla listeler. Tamamlanan her adımın başına anında **`[x]`** işareti konulacaktır.

---

### [x] Adım 1: Proje Altyapısı ve Geliştirici Ortamı Kurulumu
- [x] Rust 1.99.1 (`cargo` ve `rustc`) araç takımının Windows ortamına kurulması ve doğrulanması
- [x] `D:\zmaxserver` proje ana dizininin ve workspace yapısının oluşturulması
- [x] 14 modüllü kurumsal `Cargo.toml` çalışma alanı (workspace) dosyasının tanımlanması
- [x] Mimari belgeleri, modül matrisi ve işletim sistemi (Windows/Linux) hesaplamalarının tamamlanması

---

### [x] Adım 2: Temel Altyapı Katmanı (Runtime, Pool, Timeout)
- [x] **`zmax-runtime`:** CPU çekirdeği başına asenkron worker döngüsü, Tokio çalışma alanı ve Ctrl+C / SIGTERM ile kesintisiz kapanma (graceful shutdown) mekanizması
- [x] **`zmax-pool`:** Sıfır kopyalama bellek havuzlama (`BytesMut` buffer reuse) ve arka uç Keep-Alive bağlantı havuzu
- [x] **`zmax-timeout`:** Slowloris saldırılarına karşı Header (10s), Body (30s) ve Keep-Alive (65s) zaman aşımı kontrolcüsü

---

### [x] Adım 3: HTTP Protokolü, Başlık & Güvenlik Katmanı (`v1.0.01`)
- [x] **`zmax-httpparser`:** Soketten gelen baytları doğrudan okuyan (`&[u8]` slice) sıfır kopyalama streaming HTTP/1.1 ayrıştırıcısı *(HTTP/2 -> Adım 10)*
- [x] **`zmax-header`:** HTTP başlık haritası, başlık normalizasyonu ve kurumsal güvenlik başlıkları (HSTS, CSP, X-Frame-Options)
- [x] **`zmax-tls`:** TLS 1.3 ve TLS 1.2 şifreleme, çoklu alan adı SNI *(ALPN `h2`, OCSP Stapling ve Session Resumption -> Adım 10)*

---

### [x] Adım 4: İçerik Sunumu, PHP ve Ters Proxy (Static, FastCGI, Proxy — `v1.0.01`)
- [x] **`zmax-static`:** `BufferPool` 64 KiB akışlı statik dosya sunumu, ETag/`304`, `Range` ve WebP/AVIF içerik müzakeresi *(OS `TransmitFile`/`sendfile(2)` ve sidecar -> Adım 10)*
- [x] **`zmax-fastcgi`:** PHP-FPM / LSPHP ikili protokol istemcisi (Linux Unix Domain Socket ve Windows/Linux TCP; *Windows Named Pipe ve `FCGI_KEEP_CONN` havuzu -> Adım 9*)
- [x] **`zmax-proxy`:** Node.js, Python ve WebSocket (`Upgrade: websocket`) ters proxy geçişi + `UpstreamSocketPool`

---

### [x] Adım 5: Hızlandırma, Önbellek ve Güvenlik (Cache, Rewrite, Security — `v1.0.01`)
- [x] **`zmax-cache`:** Moka L1/L2 sayfa önbelleği, etiketli Purge motoru, Stampede kalkanı ve SWR *(LSCache `X-LiteSpeed-*` başlık köprüsü -> Adım 10)*
- [x] **`zmax-rewrite`:** WordPress permalinkleri (`try_files`), kök `.htaccess` regex yönlendirme motoru ve PHP `PATH_INFO` *(alt-dizin `.htaccess` -> Adım 8)*
- [x] **`zmax-security`:** Token Bucket IP hız sınırlama, WordPress `wp-login.php` kaba kuvvet kalkanı, WAF, Hotlink ve CIDR IP ACL *(alan adına özel WAF -> Adım 8)*
- [x] **`zmax-compress`:** Uçuş anında saf Rust Gzip sıkıştırma katmanı *(Brotli/Zstd -> Adım 10)*

---

### [x] Adım 6: Yapılandırma, Çekirdek Derleme ve Canlı Doğrulama
- [x] **`zmax-config`:** TOML tabanlı sanal konak (vHost) yöneticisi ve canlı reload
- [x] **`zmax-bin`:** Tüm 18 workspace crate'i entegre edildi; 3 hedef Release ikilisi derlendi (`zmax.exe`: 4.464.640 B, `linux-x64`: 5.264.008 B, `linux-arm64`: 4.204.888 B)
- [x] **Canlı Test:** `cargo clippy --workspace --all-targets --locked --offline` (0 uyarı/hata) + `cargo test --workspace --locked --offline` (131/131 test, 0 başarısız, 0 yoksayılan) + gerçek `php-cgi.exe` FastCGI (`PATH_INFO`, `.htaccess` `!-f`, WebP/AVIF `Accept`/`Vary`, Hotlink, IP ACL CIDR, Ters Proxy `UpstreamSocketPool`, Web + Panel/API HTTPS TLS, `live_smoke.py`, port çakışma kilidi, `0.0.0.0` Admin token `401` koruması) canlıda doğrulandı! *(Not: Linux `musl` ikilileri ve systemd betikleri çapraz derlenip statik paket olarak doğrulandı; canlı Linux VM çalıştırması bu aşamada yapılmamıştır.)*

---

### [x] Adım 7: Dahili WebAdmin & Evrensel Kontrol REST API (Portlar 19480 / 19483 / 19485 / 19486 - Sıfır Çakışma)
- [x] Port **`19485`** (`127.0.0.1:19485`) üzerinden çalışan Bootstrap 5 + Vue 3 WebAdmin arayüzü
- [x] Port **`19486`** (`127.0.0.1:19486`) üzerinden izole Evrensel Panel Kontrol REST API'si (`/api/v1/health`, `/api/v1/status`, `/api/v1/ports`, `/api/v1/config`, `/api/v1/reload`, `/api/v1/vhosts` CRUD)
- [x] Web HTTP **`19480`** (ve HTTPS/QUIC **`19483`**) ile cPanel, Plesk, DirectAdmin, CyberPanel, HestiaCP, aaPanel, CloudPanel, ISPConfig ve zPanel dahil tüm popüler panellerle %100 sıfır port çakışması
- [x] Tek tıkla L1 RAM önbellek temizleme (`POST /api/v1/cache/purge` & `/api/purge`) ve çalışma zamanı hot-reload (`POST /api/v1/reload`)
- [x] Windows (`.zip`), Linux x64/ARM64 (`.tar.gz`), Debian/Ubuntu (`.deb`) ve AlmaLinux/RHEL/Rocky (`.rpm`) paketlerinin eksiksiz üretimi

---

## 📋 Hedef Fazlar (`v1.1+`: Az CPU · Sıfır Güvenlik Zafiyeti · Çoklu İşlem · Evrensel Uyum)

### [ ] Adım 8: Linux Bağımsız Çalışma & Panel Kritik Eksikleri (Faz 1)
- [ ] **`zmax-log` / Per-VHost Günlükler:** `[vhost.logging]` (`access_log`, `error_log`), kanallı toplu asenkron yazıcı, `X-Request-Id` Trace ID ve `GET /api/v1/logs?domain=...`
- [ ] **Alan Adına Özel WAF & Tam Control API CRUD:** `waf_enabled`/`waf_exclude_paths`, `PUT /api/v1/vhosts` tam security JSON desteği ve WebAdmin IP ACL/Hotlink ekranı
- [ ] **Alt-Dizin `.htaccess` & Canlı Linux VM Doğrulaması:** `mtime` önbellekli alt-dizin `.htaccess` + `systemd` / `php-fpm` canlı Linux WordPress/HTTPS testi

---

### [ ] Adım 9: FastCGI Güvenlik ve Hız Sertleştirmesi (Faz 2)
- [ ] **HTTPoxy (`CVE-2016-5385`) & Yol Güvenliği:** `Proxy:` -> `HTTP_PROXY` mutlak soyma, `resolve_root_symlink`, `X-Accel-Redirect` / `X-Sendfile` iç yol korumalı devir
- [ ] **FastCGI Havuzlama, Streaming & Çoklu Upstream:** `FCGI_KEEP_CONN` kalıcı soket havuzu, streaming `FCGI_STDOUT`, ayrık `dial_timeout`/`io_timeout`, `least_conn` LB ve `suEXEC` site bazlı UDS

---

### [ ] Adım 10: Tam Protokol, Zero-Copy, Çoklu Süreç & Otomasyon (Faz 3)
- [ ] **Çoklu İşlem & OS Sertleştirme:** `setuid`/`nobody` yetki düşürme, `core_affinity`, Linux `SO_REUSEPORT`, `SIGUSR2` FD devri ile 0 ms ikili yükseltme, `tikv-jemallocator` değerlendirmesi
- [ ] **Protokoller & Otomasyon:** HTTP/2 (`h2`), HTTP/3 (`zmax-quic`), `PROXY Protocol v1/v2`, dahili `zmax-acme` + OCSP Stapling + Session Resumption
- [ ] **Hız & Ekosistem:** LSCache `X-LiteSpeed-*` başlık köprüsü, Brotli/Zstd + sidecar (`.zst`/`.br`/`.gz`), `sendfile(2)`/`TransmitFile`, `zmax-appserver` (`max_jobs`/TTL supervisor), `zmax-auth`, `zmax-botshield`, `zmax-redis` kablolaması

---

## 📊 Genel İlerleme Özeti: Çekirdek Sürüm (`v1.0.01`) Tamamlandı ve Doğrulandı
- Çalışan 18 crate'li çekirdek motor, 3 hedef Release derlemesi (`win-x64`, `linux-x64`, `linux-arm64`), Windows canlı E2E testleri ve 7 dağıtım paketi tamamlandı; kalan `v1.1+` mimari tasarımı [mimari/EKLENECEK_MIMARI.md](file:///D:/zmaxserver/doc/mimari/EKLENECEK_MIMARI.md), [TAM_MODUL_VE_OZELLIK_MATRISI.md](file:///D:/zmaxserver/doc/TAM_MODUL_VE_OZELLIK_MATRISI.md) ve [FERRON_VE_LITESPEED_KARSILASTIRMA.md](file:///D:/zmaxserver/doc/FERRON_VE_LITESPEED_KARSILASTIRMA.md) belgelerinde detaylandırılmıştır.
