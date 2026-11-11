# ZMax Server — Ferron (`ferronweb/ferron`) ve LiteSpeed / OpenLiteSpeed Teknik Karşılaştırma Raporu

**Amaç:** Ferron ve LiteSpeed/OLS ile genel özellik kıyası (bilgi amaçlı; hedef belgesi değil). **Güncellenir:** yeni kıyas verisi gelince; ZMax durumu için matris geçerlidir. **Bağlı:** [`OLS_DENKLIK.md`](OLS_DENKLIK.md) (hedef: OLS denkliği) · [`../TAM_MODUL_VE_OZELLIK_MATRISI.md`](../TAM_MODUL_VE_OZELLIK_MATRISI.md)

Bu doküman; **ZMax Server (`v1.0.01` / Workspace `1.0.1`)** kod tabanının, referans alınan **OpenLiteSpeed (`doc/ornekmimariler/openlitespeed`) / LiteSpeed Enterprise** mimarisinin ve modern Rust tabanlı **Ferron Web Server (`ferronweb/ferron`, `2.8.1` / `3.0.0-rc.11`)** projesinin **doğrudan kaynak kodları, `Cargo.toml` bağımlılıkları ve resmî belgeleri incelenerek** hazırlanmış gerçekçi fark ve kazanım raporudur.

> **Güncelleme (2026-11-12):** ZMax sütunu `v1.0.01` ilk yazım anındaydı; ZMax satırlarındaki "Yok/pasif" ifadelerinin bir kısmı sonradan kütüphane düzeyinde kodlandı (HTTP/2 motoru, Brotli, `sendfile`, sidecar, LSCache köprüsü, FastCGI havuzu, vhost WAF/günlük). Bunların hatta bağlılığı ve gerçek istekle doğrulanması için `TAM_MODUL_VE_OZELLIK_MATRISI.md` esas alınır; çelişkide matris geçerlidir. Rakip (Ferron/LiteSpeed) bilgileri 2026-11 başı kaynak incelemesidir, yeniden doğrulanmadı.`n>`n> **Doğrulama İlkesi:** Bu belgedeki tüm özellikler çalışır durum (**✅ Var / Çalışıyor**), kısmi / yapılandırma düzeyinde (**🟡 Kısmi / Yer Tutucu**) veya hiç bulunmayan (**❌ Yok**) biçiminde ayrılmıştır; yalnızca kodda veya testlerde doğrulanmış yetenekler "var" olarak işaretlenmiştir.

---

## 1. Ferron (`ferronweb/ferron`) Araştırma Raporu

### 1.1. Genel Profil ve Mimari (`develop-3.x` / `3.0.0-rc.11`, MIT Lisansı)
- **Dil & Çekirdek:** Tamamen **Rust** ile geliştirilmiş modüler web sunucusu ve ters vekil (`ferron`, `core`, `entrypoint`, `modules/*`, `types/*`, `utils/*`).
- **Ağ & G/Ç Motoru (`zincio`, `zincio-http`, `quinn`):** Özel `zincio` katmanı üzerinden sıfır kopyalamalı HTTP/1.1 (`h1-zerocopy`), HTTP/2 (`h2`) ve QUIC tabanlı HTTP/3 (`h3-quinn`) sunar.
- **Bellek Ayırıcı:** Windows'ta **`mimalloc`**, Unix/Linux hedeflerinde ise **`tikv-jemallocator`** (background threads) kullanır.
- **Yapılandırma Modeli:** KDL tabanlı kompakt `ferron.conf` (`modules/config-ferronconf`) ve JSON (`modules/config-json`) destekler. **Önemli not:** Ferron kasıtlı olarak `.htaccess` dosyalarını **okumaz**; tüm yönlendirme kurallarının merkezî yapılandırmaya taşınmasını ister.

### 1.2. Ferron'da Neler Var? (Doğrudan Modül Envanteri)
1. **Tam Protokol Yığını (`http-server`):** HTTP/1.1, **HTTP/2**, **HTTP/3 (QUIC / UDP)** ve **PROXY Protocol v1/v2 (`ppp`)** desteği.
2. **Otomatik TLS & OCSP (`tls-acme`, `ocsp-stapler`, `dns-*`):** `instant-acme` ile Let's Encrypt **HTTP-01**, **TLS-ALPN-01** ve **DNS-01** (`dns-stalwartlite`, `dns-command`) otomatik sertifika alma/yenileme ile yerleşik OCSP Stapling.
3. **Sıkıştırma (`http-compression`, `http-static`):** **Gzip**, **Deflate**, **Brotli** ve **Zstd** (`async-compression`) + statik dosyalar için önceden sıkıştırılmış sidecar (`.zst`, `.br`, `.gz`) sunumu.
4. **LSCache Uyumlu Önbellek (`http-cache`):** `quick_cache` + CRC32 doğrulamalı disk kalıcılığı (`PersistManager`) yanında WordPress **LSCache başlık protokolünü** (`X-LiteSpeed-Cache-Control`, `X-LiteSpeed-Tag`, `X-LiteSpeed-Purge`, `X-LiteSpeed-Vary`, `_lscache_vary` çerez ayrımı, `LSC-Cookie`) doğrudan anlar.
5. **Üretim Hata Ayıklama ve Gözlemlenebilirlik (`http-traceid`, `observability-*`):** İstek başına benzersiz **`Trace ID`** üretip tüm aşamalara yayar; **OpenTelemetry (`otlp`/gRPC)**, **Prometheus**, **StatsD**, JSON/metin logları ile satır-Trace ID korelasyonu kurar.
6. **Gelişmiş Ters Vekil (`http-proxy`, `http-fproxy`, `http-canary`):** HTTP/1.1 + HTTP/2 upstream, WebSocket, gRPC, **`hickory-resolver`** ile asenkron DNS çözümleme, sağlık kontrolü, devre kesici (circuit breaker), ileri vekil (`fproxy`), haricî auth (`fauth`) ve **Canary ağırlıklı trafik bölme (`http-canary`)**.
7. **Uygulama Geçitleri (`http-fcgi`, `http-cgi`, `http-scgi`):** `cegla-fcgi` + `connpool` ile havuzlanmış FastCGI (PHP-FPM), CGI ve SCGI desteği.
8. **Yönetim & Erişim (`admin-api`, `http-basicauth`, `http-abuseban`, `http-ratelimit`):** `/health`, `/status`, `/config`, `/reload` HTTP JSON Yönetim API'si, argon2/pbkdf2/scrypt şifreli Basic Auth, CIDR tabanlı `http-abuseban` ve bölge bazlı `http-ratelimit`.

### 1.3. Ferron'da Neler Yok? (ZMax ve LiteSpeed Karşısında Eksikleri)
- ❌ **`.htaccess` desteği yok:** Paylaşımlı hosting ve WordPress/Laravel/OpenCart kullanıcılarının yüklediği `.htaccess` kurallarını doğrudan çalıştırmaz.
- ❌ **Dahili WebAdmin GUI konsolu yok:** Web tabanlı görsel vHost CRUD, canlı modül aç/kapa, yasaklı IP unban ve log izleme arayüzü bulunmaz (yalnızca CLI + JSON Admin API vardır).
- ❌ **WordPress odaklı WAF & Hotlink koruması yok:** `wp-login.php` / `xmlrpc.php` brute-force kural seti, OWASP SQLi/XSS/CMDi inceleme filtresi ve yerleşik Hotlink Referer koruma modülü yoktur.
- ❌ **WebP/AVIF içerik müzakeresi yok:** `Accept: image/avif,image/webp` başlığına göre otomatik görsel seçimi + `Vary: Accept` modülü yerleşik değildir.
- ❌ **Kontrol Paneli Ekosistemi yok:** cPanel/Plesk/ZePanel benzeri port çakışmasız panel köprüsü, vHost TOML API CRUD ve panel `proxy_prefix` WebUI yönetimi yoktur.

### 1.4. ZMax Server İçin Ferron'dan Alınabilecek Yararlı Fikirler ve Modüller
| Öncelik | Özellik / Mimari Fikir | Ferron Karşılığı | ZMax'a Sağlayacağı Somut Katkı |
| :---: | :--- | :--- | :--- |
| **Yüksek** | **LSCache Yanıt Başlık Köprüsü** | `http-cache/src/lscache.rs` | `zmax-cache` çekirdeği zaten etiket + SWR + Stampede içeriyor; PHP'den dönen `X-LiteSpeed-Cache-Control`, `X-LiteSpeed-Tag`, `X-LiteSpeed-Purge`, `_lscache_vary` başlıklarını ayrıştırıp bağlamak WordPress LSCache eklentisiyle ek eklenti olmadan uyum sağlar. |
| **Yüksek** | **HTTP/2 + HTTP/3 (`QUIC`) Desteği** | `zincio-http` (`h2`, `h3-quinn`) | Mevcut HTTP/1.1 + `mod_quic.toml` yer tutucusunun gerçeğe dönüştürülmesi (tarayıcı çoğullama, 0-RTT ve mobil hızlanma). |
| **Yüksek** | **Dahili ACME (`http-01` / `tls-alpn-01`) + OCSP Stapling** | `tls-acme` (`instant-acme`) + `ocsp-stapler` | Şu an `mod_acme.toml` ve `.well-known/acme-challenge` muafiyeti harici Certbot/ZePanel içindir; dahili yenileme eklendiğinde sıfır haricî bağımlılıkla tam otomatik SSL sağlanır. |
| **Orta** | **Brotli + Zstd + Precompressed Sidecar (`.br`/`.zst`/`.gz`)** | `http-compression` + `http-static` | `zmax-compress` içine Brotli/Zstd eklemek statik bant genişliğini %15–25 daha düşürür; `.br`/`.gz` hazır dosya okumak CPU maliyetini sıfırlar. |
| **Orta** | **Asenkron DNS (`hickory-resolver`) & `PROXY` Protokolü** | `http-proxy` (`hickory-resolver`, `ppp`) | Dinamik upstream hostname çözümlemelerinin worker'ları bloklamasını önler; HAProxy/Cloudflare L4 arkasında gerçek istemci IP'sini korur. |
| **Orta** | **İstek `Trace ID` & Yapısal Hata İzleme** | `http-traceid` + `observability-*` | ZMax loglarına benzersiz `X-Request-Id` / Trace ID ekleyip `/api/v1/logs` üzerinden filtrelemek canlı müşteri arızası tespitini çok hızlandırır. |
| **Orta** | **Linux `musl` için `jemalloc` / Arena Optimizasyonu** | `tikv-jemallocator` | ZMax Windows'ta `mimalloc` kullanırken Linux `musl`'da varsayılan ayırıcıyı kullanıyor; yüksek eşzamanlılıkta bellek parçalanmasını azaltmak için alternatif ayırıcı değerlendirilebilir. |

---

## 2. LiteSpeed Enterprise / OpenLiteSpeed vs ZMax Server (`v1.0.01`)

OpenLiteSpeed (OLS — `doc/ornekmimariler/openlitespeed` GPLv3 kaynak ağacı) ve ticari LiteSpeed Web Server Enterprise (LSWS) ile ZMax Server'ın gerçek kod düzeyi karşılaştırması aşağıdadır:

| Yetenek / Modül | LiteSpeed Enterprise (LSWS) | OpenLiteSpeed (OLS) | ZMax Server (`v1.0.01` Gerçek Kod) |
| :--- | :--- | :--- | :--- |
| **Temel Dil & Bellek Güvenliği** | C / C++ (Kapalı kaynak) | C / C++ (GPLv3) | ✅ **%100 Saf Rust** (Bellek taşması/UAF korumalı, `mimalloc` Win / statik `musl` Linux) |
| **HTTP/1.1 Keep-Alive & Pipelining** | ✅ Tam | ✅ Tam | ✅ **Var & Canlı Test Edildi** (`zmax-httpparser`, sıfır kopyalama dilim ayrıştırma) |
| **HTTP/2 & HTTP/3 (QUIC)** | ✅ Tam | ✅ Tam (`src/h2`, `src/quic`, `liblsquic`) | HTTP/2: `h2_engine.rs` kodlandı, doğrulanmadı (IMPLEMENTED); HTTP/3-QUIC: ❌ yok (`mod_quic.toml` şablon) |
| **TLS 1.2/1.3, SNI & Dinamik Reload** | ✅ Tam + OCSP + Session Resumption | ✅ Tam (`src/sslpp`) | 🟡 **TLS 1.2/1.3, SNI, Panel/API TLS, `force_https` & Reload var**; ❌ OCSP Stapling & Session Resumption henüz yok; panel/API portu sertifikası `SniResolver` ile yenilenir (kodda) |
| **`.htaccess` & `RewriteEngine`** | ✅ Tam Apache uyumlu (runtime reload olmadan) | ⚠️ Kısmi (Yeniden başlatma/reload odaklı) | ✅ **`zmax-rewrite` (alt-dizin `.htaccess` mtime önbelleği ve `[E=...]` dahil kütüphanede):** `RewriteEngine`, `RewriteBase`, `RewriteCond` (`-f/-d/-s/-l`, `NC`, `OR`), `RewriteRule` (`L/QSA/R/F/G`), `Redirect`, `DirectoryIndex`, `try_files`, PHP `PATH_INFO` `REQUEST_FILENAME` eşleme |
| **PHP Çalıştırma SAPI** | ✅ LSPHP (LSAPI — paylaşımlı bellek/socket) | ✅ LSPHP (`src/modules/mod_lsphp`, `lsapi`) & FastCGI | 🟡 **FastCGI (`zmax-fastcgi`):** TCP + Linux Unix Socket, 64 KiB üstü `PARAMS`/`STDIN`, çoklu `Set-Cookie`, `PATH_INFO`/`PATH_TRANSLATED`, timeout; ❌ LSAPI & Windows Named Pipe yok |
| **Statik Dosya & Zero-Copy** | ✅ `sendfile(2)` + AIO | ✅ `sendfile` + AIO | 🟡 **ETag/`304`, Range `206`/`416`, `HEAD`, UTF-8, altdizin index, gizli dosya koruması var**; büyük dosya (>2 MiB) & Range için `BufferPool` 64 KiB akış kullanılır (`zmax-static` içinde `sendfile(2)`, sidecar `.zst/.br/.gz` ve güvenli autoindex kodlandı; `web_engine.rs` `sendfile` çağırmıyor — hatta bağlı değil). |
| **WebP & AVIF İçerik Müzakeresi** | ✅ Rewrite/LSCache ile | ⚠️ Manuel Rewrite kuralları | ✅ **`auto_webp` / `auto_avif` yerleşik:** `Accept` başlığına göre dosya seçimi + `Vary: Accept` + önbellek etiket ayrımı |
| **Sayfa Önbelleği & LSCache** | ✅ Tam LSCache + ESI + Crawler | ✅ `src/modules/cache` (Tam) | 🟡 **`zmax-cache`:** Moka L1 RAM + L2 Disk + Tag Purge + Stampede Kalkanı + Stale-While-Revalidate (`SWR`) aktif; `X-LiteSpeed-*` yanıt başlık köprüsü kütüphanede (UNIT TESTED); ESI / Crawler yok |
| **Sıkıştırma** | ✅ Gzip + Brotli + Zstd | ✅ `modgzip` (Gzip + Brotli) | 🟡 **Saf Rust Gzip + Brotli (`zmax-compress`, UNIT TESTED)**; ❌ Zstd yok |
| **Ters Vekil & WebSocket** | ✅ Proxy + Load Balancer + Health Check | ✅ `src/extensions/proxy` | 🟡 **HTTP Proxy + WebSocket `Upgrade` + `UpstreamSocketPool` keep-alive + `preserve_host` + `path_prefix` aktif**; ❌ Çoklu backend yük dengeleme / sağlık kontrolü yok |
| **WAF, Brute-Force & Güvenlik** | ✅ ModSecurity CRS v3, `lsrecaptcha`, Brute-Force, IP ACL | ✅ `modsecurity-ls`, `lsrecaptcha`, Anti-DDoS | 🟡 **Token Bucket Rate Limit (`429`), `wp-login.php`/`xmlrpc.php` oto-ban, `WafInspector` (SQLi/XSS/CMDi/Traversal/`mod_coreruleset`), IP ACL CIDR, Hotlink, HSTS/CSP aktif**; ❌ Tam OWASP SecRule dosyaları, `zmax-botshield` CAPTCHA & `.htpasswd` Basic Auth yok |
| **Otomatik SSL (ACME)** | ✅ Dahili Let's Encrypt / ZeroSSL | ✅ `src/modules/modacme` | ❌ **Dahili ACME istemcisi yok** (`.well-known/acme-challenge/` muafiyetiyle harici Certbot/ZePanel destekli; `mod_acme.toml` şablon) |
| **Node.js / Python / Ruby / ASP.NET** | ✅ Context/AppServer | ✅ `nodejs_integration`, SCGI, uWSGI, WSGI | ❌ **AppServer Supervisor (`zmax-appserver`) ve Windows ASP.NET köprüsü yok** (yalnızca harici çalışan backend'e ters vekil yapılır) |
| **PageSpeed & GeoIP** | ✅/⚠️ PageSpeed haricî / GeoIP (`MaxMindDB`) | ✅ `src/modules/pagespeed` + `MaxMindDB` | ❌ **Kodda yok** (`mod_pagespeed.toml` ve `mod_geoip.toml` yalnızca ayar şablonu) |
| **Yönetim Arayüzü & API** | ✅ WebAdmin Konsolu (7080) | ✅ WebAdmin Konsolu (7080) | ✅ **Vue 3 WebAdmin (`19485`) + Evrensel REST API (`19486`) + `/metrics` Prometheus + vHost CRUD + Modül Toggle + Otomatik `0.0.0.0` Token + Çakışmasız Port Bloğu (`19480–19486`) + Panel Ters Vekil Önek Desteği** |
| **Graceful Reload & Çekirdek Sabitleme** | ✅ Sıfır kesintili soket devri + Core Pinning | ✅ Graceful restart | 🟡 **Yapılandırma/SNI/Modül/vHost sıcak reload (`/api/v1/reload`, Unix `SIGHUP`) aktif**; ❌ Çok süreçli sıfır kesintili `SO_REUSEPORT` ikili yükseltme & CPU `core_affinity` sabitleme yok |
| **Windows Server Desteği** | ❌ Yok (Sadece Linux/BSD) | ❌ Yok (Sadece Linux/BSD/macOS) | ✅ **Yerel `x86_64-pc-windows-msvc` + Linux `x64`/`arm64` statik `musl`** |

---

## 3. Workspace durumu

Crate başına gerçek durum ve etiketler tekrar edilmez; tek kaynak: [TAM_MODUL_VE_OZELLIK_MATRISI.md](../TAM_MODUL_VE_OZELLIK_MATRISI.md). Planlanan ama crate olarak açılmamış bileşenler (zmax-quic, zmax-acme, zmax-auth, zmax-botshield, zmax-pagespeed, zmax-dns, zmax-limits, zmax-appserver, zmax-taskrunner) orada listelidir.
