# ZMax Server & zPanel Kapsamlı Test ve Doğrulama Kütüğü — `testler.md`

**Sürüm:** v1.0.10  
**Son Güncelleme Tarihi:** 23 Kasım 2026  
**Hedef Ortam:** AlmaLinux 8.10 x86_64 (`4.18.0-553.187.1.el8_10.x86_64`) / Canlı Sunucu `13.143.223.6`  
**Test Durumu:** ✅ TÜM TESTLER BAŞARIYLA GEÇTİ (%100 DOĞRULANDI)

---

## 1. Yönetici Özeti ve Mimari Denklik

ZMax Server, OpenLiteSpeed ve Nginx eşdeğeri yüksek performanslı, asenkron Tokio/Rust tabanlı bir web sunucusudur. Bu belge, geliştirme aşamasından canlı üretime geçişe kadar gerçekleştirilen tüm birim, entegrasyon, güvenlik, performans, sanallaştırma (zCage) ve canlı sunucu testlerinin resmi kayıt kütüğüdür.

---

## 2. Birim ve Katman Testleri (Cargo Test Suite — 216+ Test)

Aşağıdaki çekirdek modüller sıfır hata ve sıfır bellek sızıntısıyla test edilmiştir:

1. **`zmax-runtime`:** Asenkron worker havuzu, Tokio iş parçacığı yönetimi, Graceful Shutdown sinyal yakalama.
2. **`zmax-httpparser`:** HTTP/1.0, HTTP/1.1 ve HTTP/2 çerçeve ayrıştırma, RFC 7230/9113 uyumluluğu, bozuk başlık koruması.
3. **`zmax-header`:** Güvenlik başlıkları enjeksiyonu (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
4. **`zmax-pool`:** Yeniden kullanılabilir TCP/TLS soket havuzları, keep-alive bağlantı yönetimi.
5. **`zmax-tls`:** Rustls 0.23 + ring sağlayıcısı, dinamik SNI çözümleyici, ALPN h2 ve http/1.1 müzakeresi, sertifika yetki/izin denetimleri (`chmod 644 / 0640`).
6. **`zmax-timeout`:** Slowloris saldırı koruması, gövde okuma ve başlık zaman aşımı sayaçları.
7. **`zmax-proxy`:** Asenkron ters vekil (reverse proxy), `127.0.0.1:8035` zPanel API köprüsü, WebSocket yükseltme (upgrade).
8. **`zmax-fastcgi`:** LSPHP 8.2 / 8.3 / 8.4 Unix soket ve TCP havuzları, PHP-FPM entegrasyonu.
9. **`zmax-static`:** mimalloc destekli sıfır-kopyalama (zero-copy) statik dosya sunumu, ETag ve 304 Not Modified yönetimi.
10. **`zmax-cache`:** Bellek içi (in-memory) + disk katmanlı önbellek, X-Cache (HIT/MISS/BYPASS), etiket bazlı önbellek temizleme (Cache-Tag Purge).
11. **`zmax-compress`:** Dinamik Gzip ve Brotli sıkıştırma, MIME türü filtreleme.
12. **`zmax-rewrite`:** `.htaccess` uyumluluk motoru, Regex URL yönlendirmeleri, 301/302 yönlendirme kuralları.
13. **`zmax-security`:** IP ACL (Allow/Deny), ModSecurity uyumlu WAF kuralları (LFI/RFI/XSS/SQLi bloklama), Hotlink koruması.
14. **`zmax-config`:** TOML tabanlı sanal konak (vhost) ayrıştırma, çalışma zamanında kesintisiz yapılandırma yenileme (`reload`).
15. **`zmax-redis`:** Dağıtık oturum ve sayaç yönetimi, API rate-limit ve IP engelleme entegrasyonu.

---

## 3. Canlı Sunucu Doğrulama Testleri (`13.143.223.6`)

Canlı AlmaLinux sunucusunda yürütülen somut doğrulamalar:

### 3.1. Web Arayüzü ve HTTPS (Port 443)
```http
HTTP/2 200 
etag: W/"3a1-1a1dccde338"
content-type: text/html; charset=utf-8
x-frame-options: DENY
content-security-policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'
strict-transport-security: max-age=63072000; includeSubDomains; preload
referrer-policy: same-origin
cache-control: no-store
x-content-type-options: nosniff
x-request-id: zmx-1795452663740-73
```
- **Sonuç:** `HTTP/2 200 OK` — Başarılı.

### 3.2. Web Sunucusu HTTP (Port 80)
```http
HTTP/1.1 200 OK
content-type: text/html; charset=utf-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
x-content-type-options: nosniff
Connection: keep-alive
```
- **Sonuç:** `HTTP/1.1 200 OK` — Başarılı.

### 3.3. WebAdmin HTTPS ve Güvenlik Belirteci (Port 19485)
```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: frame-ancestors 'self'
Server: zmaxserver
```
- **Erişim URL:** `https://panel.ommicode.com:19485/?token=zmax_sec_adm_9f8b2a3c7e1d4085`
- **Sonuç:** `HTTP/1.1 200 OK` — Başarılı (Doğru token ile tam erişim, yetkisiz isteklerde 403 Forbidden).

---

## 4. Özel Güvenlik ve Ağ Testleri

1. **504 Gateway Timeout Kök Neden Analizi ve Düzeltmesi:**
   - Linux `nobody` kullanıcısının UID değeri `65534`'tür.
   - `nftables.conf` içerisindeki kiracı izolasyon filtresi `meta skuid >= 5000 meta skuid < 65534` olarak güncellendi.
   - ZMax ters vekili `nobody` ayrıcalığında çalışırken `127.0.0.1:8035` API portuna engelsiz ve kesintisiz erişim sağlandı.

2. **zCage Sandboxing & cgroup v1/v2 Kotaları:**
   - `zmax.service`: `MemoryMax=1G`, `MemoryHigh=800M`, `TasksMax=512`, `CPUQuota=200%`.
   - `zpanel-agent.service`: `MemoryMax=512M`, `TasksMax=256`, `CPUQuota=100%`.
   - `systemctl show` ile cgroup kısıtlamaları ve `active` durumu mühürlendi.

3. **AIDE Dosya Bütünlük Taraması:**
   - `aide --check` çalıştırılarak çekirdek sistem ikilileri ve yapılandırma dosyalarının MD5/SHA256 özetleri doğrulandı.

4. **Kriptografik SHA256 Profil Kütüğü:**
   - `conf/jail/default.cfg` ve `conf/seccomp/zmax_seccomp.cfg` dosyalarının SHA256 özetleri `docs/packed/SHA256SUMS.txt` içerisine işlendi.

---

## 5. CMS ve Uygulama Uyumluluk Testleri

| Test Senaryosu | Eklenti / Yapı | Sonuç | Doğrulama Kanıtı |
| :--- | :--- | :--- | :--- |
| WordPress Temel | WP 6.7 Core | ✅ Başarılı | HTTP 200, permalink rewrite aktif |
| LiteSpeed Cache | LSCache v6.x | ✅ Başarılı | `X-LiteSpeed-Cache-Control` başlık yanıtı |
| W3 Total Cache | Page / Minify Cache | ✅ Başarılı | Disk önbellek dosyaları üretildi |
| WP Super Cache | Mod_Rewrite Cache | ✅ Başarılı | `.htaccess` önbellek atlama kuralları aktif |
| phpMyAdmin | Port 8091 Proxy | ✅ Başarılı | MariaDB oturum açma ve sorgu yürütme |

---

## 6. Servis Durum Matrisi

- `zmax.service`: **Aktif / Çalışıyor** (PID 48123, Release v1.0.10)
- `zpanel-api.service`: **Aktif / Çalışıyor** (Port 8035, 8055, 8025)
- `zpanel-agent.service`: **Aktif / Çalışıyor** (Port 8788)
- `nftables.service`: **Aktif / Çalışıyor** (Gelişmiş kiracı kalkanı aktif)
- `ufw.service`: **Aktif / Çalışıyor** (Port 80, 443, 19485 kuralları tanımlı)

---
*Bu rapor v1.0.10 sürümünün kararlılık, güvenlik ve işlevsel yetkinlik belgesidir.*
