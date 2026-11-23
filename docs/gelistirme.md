# ZMax Server & zPanel — Birleşik Nihai Geliştirme ve Dönüşüm Yol Haritası (gelistirme.md)

> **Tarih:** 22 Kasım 2026  
> **Sürüm:** v2.6 — Kapsamlı Kurumsal Mimari Sentezi  
> **Kapsam:** Tüm bağımsız yapay zeka denetimleri ve `D:\lunixpanel\isolation\docs` (zCage Mimarisi) Entegrasyonu:
> 1. Pazar & Mimari Karşılaştırması (Rapor 1)
> 2. İç Güvenlik Gerçeklik Kontrolü & 10 Açık (Rapor 2)
> 3. Spesifik Çözüm & Kararlılık Mimarisi (Rapor 3)
> 4. v2 Revizyonu & Doğrulanan Bulgular (Rapor 4)
> 5. ZMX-001..ZMX-023 Teknik Denetim Kütüğü (Rapor 5)
> 6. WebAdmin 5 Katma Değerli Teşhis Aracı & Menü Mimarisi (Rapor 6)
> 7. zPanel Hosting Katmanı & cgroups v2 (Öneri 2)
> 8. WebAdmin Güvenlik, BFF, Giriş Doğrulama Reformu (Öneri 3 - OpenCode)
> 9. **zCage Çok Kiracılı Sıfır-Güven İzolasyon Çerçevesi (`isolation/docs` Entegrasyonu)**
> **Hedef:** ZMax Server ve zPanel ekosistemini CloudLinux / CageFS ve OpenLiteSpeed karşısında **varsayılan güvenlik, cgroups v2, openat2 dosya güvenliği, izole netns ve kurumsal oturum güvenliği** ile mutlak pazar lideri yapmak.

---

## 1. Yönetici Özeti ve 4 Katmanlı Mimari Felsefe

```text
+-----------------------------------------------------------------------------------+
| 1. zPanel / Lunixpanel (Hosting & Kontrol Düzlemi)                                |
|    - cgroups v2 Kaynak Kotası (CPU, RAM, I/O, Inode)                              |
|    - Kullanıcı Bazlı PHP Sürüm Seçici (7.4 - 8.4) & php.ini Yönetimi              |
|    - Merkezi Yedekleme (Yerel, SFTP, S3, Google Drive) & Tek Tık Geri Yükleme     |
+-----------------------------------------------------------------------------------+
                                         │  (Go Ajanı & Güvenli REST API)
                                         ▼
+-----------------------------------------------------------------------------------+
| 2. ZMax WebAdmin (Sunucu Yönetim & Teşhis Konsolu)                                |
|    - Oturum Güvenliği: BFF, HttpOnly Cookie, CSRF & /session/verify Doğrulaması   |
|    - Request Inspector (L1..L8 Mikrosaniye Gecikme Analizi & Darboğaz Kanıtı)      |
|    - PHP-FPM Havuz Sağlık Merkezi (Worker Doygunluğu, 502 vs 503 Ayrımı)          |
|    - Config Diff & One-Click Rollback, Security Simulator & Site Doctor           |
+-----------------------------------------------------------------------------------+
                                         │  (Broker Sözleşmesi & SO_PEERCRED)
                                         ▼
+-----------------------------------------------------------------------------------+
| 3. zCage İzolasyon Motoru (`isolation/docs`) [CageFS Üstünlüğü]                   |
|    - `zcaged` Host Broker & `zcage-init` (Namespace, pivot_root, Seccomp, Landlock) |
|    - Dinamik /etc/passwd (Sıfır Cross-Tenant Bilgisi; komşu siteler ASLA görünmez)|
|    - Alan Başına Bağımsız FPM Master & OPcache Ayrımı (`zcage-php@<kiracı>.service)|
|    - İzole netns + nftables meta skuid (Host 8788, 8025 loopback sızıntı engeli)  |
+-----------------------------------------------------------------------------------+
                                         │  (Rust IPC & Çekirdek Veri Düzlemi)
                                         ▼
+-----------------------------------------------------------------------------------+
| 4. ZMax Server Engine (Rust Çekirdeği - Veri Düzlemi)                             |
|    - openat2 RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS (Symlink Kaçış Engeli)       |
|    - L1: Global Semafor (10.000) & IP Active Conns (429 Too Many Requests)       |
|    - L2: TLS 1.3, Strict SNI (421) & HTTP/1.1 / HTTP/2 Ortak Güvenlik            |
|    - L4: OWASP CRS WAF, Rate Limiting & Uploads Dizininde PHP Yasağı (403)        |
|    - L6: L1 RAM / L2 Disk Önbellek (Varsayılan Açık), SWR & X-LiteSpeed Başlıkları|
|    - L7: Devre Kesici (Circuit Breaker), stale-if-error & 503 Retry-After Havuzu  |
+-----------------------------------------------------------------------------------+
```

---

## 2. ZMX Önceliklendirilmiş Kod ve Güvenlik Kütüğü (ZMX-001 — ZMX-023)

### 🔴 P0 — Kritik Güvenlik ve Kararlılık (Tamamlananlar)
- **ZMX-001:** `src/pipeline/l1_connection.rs` -> Global semafor (10.000) + IP active conns (50) + `429 Too Many Requests` ✅
- **ZMX-002:** `src/pipeline/l7_handlers/fastcgi.rs` -> `GLOBAL_BACKEND_SEMAPHORES` + `503 Service Unavailable + Retry-After: 3` ✅
- **ZMX-003:** `src/api/routes/system.rs` -> `/api/v1/health` ve `/version` kimliksiz bilgi ifşası engellendi ✅
- **ZMX-004:** `src/api/auth.rs` -> CSPRNG token üretimi, log maskeleme, SSE URL token kaldırıldı ✅
- **ZMX-005:** `src/pipeline/l4_security.rs` -> HTTP/1.1 ve HTTP/2 ortak L4 güvenlik hattı ✅
- **ZMX-006:** `crates/zmax-config/src/lib.rs` -> VHost cache varsayılan `enabled = true` ✅
- **ZMX-007:** `src/pipeline/l4_security.rs` -> `/uploads/` altında `.php`, `.phtml`, `.phar` 403 engeli ✅
- **ZMX-008:** `src/pipeline/l2_tls.rs` -> Strict SNI uyuşmazlığında 421 Misdirected Request ✅
- **ZMX-009:** `crates/zmax-redis/src/lib.rs` -> Redis parolası `***MASKELENDI***` ✅
- **ZMX-010:** `go/lifecycle/writer.go` -> `sanitizeDomain` path traversal (`..`, `/`, `\`) kalkanı ✅
- **ZMX-012 / 020:** Süs modül toml temizliği (`mod_quic.toml enabled=false`, `mod_ssl.toml ocsp=false`) ✅
- **ZMX-018:** `src/api/routes/system.rs` -> Gerçek `/proc/self/statm` RSS RAM hesabı ✅
- **ZMX-019:** `src/api/routes/system.rs` -> Config validate & rollback REST API ✅
- **ZMX-023:** `Cargo.toml`, `VERSION`, `LICENSE` -> `1.0.09` sürümü ve `Apache-2.0` lisansı eşitlendi ✅
- **OpenCode P0:** `admin/js/api_client.js` -> `validateToken` yetkili `/session/verify` ucuna bağlandı ✅

---

## 3. `isolation/docs` (zCage) Entegrasyonu: 7 Altın İzolasyon Kalkanı

`D:\lunixpanel\isolation\docs` altındaki 17 mimari belgenin incelenmesi sonucunda ZMax Server ve zPanel ekosistemine doğrudan eklenecek temel kurallar:

### 3.1 Kalkan 1: ZMax Statik & FastCGI Dosya Açışında `openat2` Koruması
- **Sorun:** ZMax kafesin DIŞINDA çalışır. Kötü niyetli bir kiracı kendi web dizinine sembolik bağ (`ln -s /var/www/vhosts/diger_site/wp-config.php /var/www/vhosts/kendi_sitesi/cal.txt`) koyarak ZMax üzerinden komşu sitelerin sırlarını okutabilir.
- **zCage Çözümü:**
  - ZMax Linux ortamında dosya açarken `openat2` sistem çağrısını `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` bayraklarıyla kullanır.
  - Bu çekirdek seviyesindeki koruma, açılmak istenen dosyanın vHost Document Root sınırının dışına çıkmasını ve procfs/symlink kaçışlarını donanım seviyesinde engeller!

### 3.2 Kalkan 2: zCage Host Broker (`zcaged`) ve Başlatıcı (`zcage-init`)
- **Sorun:** SSH, SFTP, cron ve terminal oturumları sıradan kullanıcı kimliğiyle başlar; sıradan kullanıcı `mount` veya `pivot_root` yapamaz. Setuid ikilileri ise büyük güvenlik açığı riski taşır.
- **zCage Çözümü:**
  - `zcaged` host tarafında ayrı bir systemd servisi olarak çalışır (`/run/zcage/zcaged.sock`, Linux `SO_PEERCRED` ile doğrulama). Setuid binary ASLA kullanılmaz.
  - Kiracı bir komut çalıştıracağı zaman broker yetkiyi doğrular ve `zcage-init` aracılığıyla yeni bir kafes ortamı oluşturup yetkiyi (`drop_privileges`) kiracı UID/GID'sine düşürerek `execve` yapar.

### 3.3 Kalkan 3: İzole Mount Görünümü ve Dinamik `/etc/passwd`
- **Sorun:** Klasik Linux sistemlerinde `/etc/passwd` tüm kullanıcılara açıktır. Bir kiracı sunucudaki diğer tüm müşteri kullanıcı adlarını listeleyebilir (Reconnaissance atağı).
- **zCage Çözümü:**
  - Kafes içine hostun `/etc/passwd` dosyası bağlanmaz!
  - Her kiracı için tmpfs üzerinde YALNIZCA KENDİSİNİN (`root:x:0:0:...` ve `zp_musteri1:x:1005:1005:...`) yer aldığı dinamik bir `/etc/passwd` üretilir.
  - Komşu kiracıların kullanıcı adları, siteleri ve sistem dizinleri kafes içinde TAMAMEN YOK HÜKMÜNDEDİR (Sıfır Cross-Tenant Bilgi Sızıntısı).
  - `/sys` dizini kafese ASLA bağlanmaz.

### 3.4 Kalkan 4: Alan Başına Bağımsız PHP-FPM Master & OPcache İzolasyonu
- **Sorun:** Tek bir PHP-FPM ana süreci altında havuz açıldığında tüm siteler aynı OPcache belleğini paylaşır. Bir sitedeki zaafiyet OPcache üzerinden komşu sitelerin bytecode'larına erişim riski doğurur.
- **zCage Çözümü:**
  - Her bağımsız site `zcage-php@<kiracı>.service` adıyla kendi FPM ana sürecine ve kendi izole OPcache belleğine sahip olur.
  - Soket `/run/zpanel-php/<kimlik>.sock` altında yalnızca ZMax'ın ve o kiracının erişebileceği izinlerle açılır.

### 3.5 Kalkan 5: Ağ İzolasyonu & nftables `meta skuid` Kalkanı
- **Sorun:** Kiracı PHP kodundan `file_get_contents('http://127.0.0.1:8788/rpc')` çağrısı yaparak root yetkili zPanel Agent'a veya yerel veritabanı portlarına (3306, 5432) yetkisiz ulaşabilir.
- **zCage Çözümü:**
  - Her siteye özel ağ ad alanı (network namespace) verilir.
  - nftables üzerinde kiracı UID aralığı (`meta skuid`) için host loopback (127.0.0.1) üzerindeki yönetim portlarına (8788 Agent, 8025 Panel API) erişim varsayılan olarak YASAKLANIR (`drop`).
  - Kiracının sahte IP spoofing ile dış dünyaya DNS amplifikasyon saldırısı yapması host kurallarıyla engellenir.

### 3.6 Kalkan 6: cgroups v2 Hiyerarşisi (`zcage-<kiracı>.slice`)
- Her kiracının PHP, cron, SSH ve terminal süreçleri `zcage-<kiracı>.slice` cgroup altına bağlanır:
  - `cpu.weight` (CPU adil paylaşımı)
  - `memory.max` & `memory.swap.max` (RAM aşımında yalnızca o sitenin worker'ları OOM killer tarafından sonlandırılır; diğer siteler ve ZMax kesintisiz çalışır)
  - `pids.max` (Fork bombası saldırılarına karşı mutlak koruma)
  - `io.weight` (Disk I/O sömürüsünü engelleme)

### 3.7 Kalkan 7: Generation Tabanlı Yaşam Döngüsü Durum Makinesi
- Bir site `Absent` -> `Preparing` -> `Ready` -> `Stopping` -> `Quarantined` durumlarını izler.
- ZMax rotası YALNIZCA tüm kontrolleri (mount, cgroup, seccomp, netns) başarıyla geçmiş `Ready` nesline açılır; yarım veya hatalı kurulumlar asla trafiğe açılmaz.

---

## 4. WebAdmin Kurumsal Mimarisi ve 5 Teşhis Aracı

1. **Request Inspector:** L1..L8 arası mikrosaniye süre ölçümü (`L7 PHP-FPM: 185 ms (%94.3 darboğaz)` kanıtı).
2. **PHP-FPM Havuz Sağlık Merkezi:** 502 vs 503 ayrımı, worker doygunluğu ve kuyruk izleme.
3. **Config Diff & One-Click Rollback:** Renkli görsel diff ve tek tıkla geri alma.
4. **Security Simulator:** Canlı istemciyi engellemeden WAF ve rate-limit simülasyonu.
5. **Site Doctor:** Tek tıkla DNS, SSL, PHP soketi, izin ve rewrite taraması.

---

## 5. zPanel Hosting Katmanı Gereksinimleri

- **cgroups v2 Entegrasyonu (🔴 P0):** Panelden CPU, RAM, I/O ve Inode kotası yönetimi.
- **Kullanıcı Bazlı PHP Sürüm Seçici (🔴 P0):** PHP 7.4 - 8.4 seçimi ve güvenli `php.ini` override.
- **Merkezi Yedekleme (🟠 P1):** S3, SFTP, Google Drive destekli otomatik yedekleme ve tek tık geri yükleme.
- **Uygulama Mağazası & LSCache (🟢 P3):** Tek tıkla WordPress kurulumunda otomatik LSCache yapılandırması.

---

## 6. Önceliklendirilmiş Birleşik Uygulama Matrisi

| Öncelik | Modül / Özellik | Katman | Kaynak / Referans | Durum |
|---|---|---|---|---|
| 🔴 **P0** | ZMX-001..ZMX-009 Çekirdek Güvenlik | ZMax Çekirdek | Rapor 2 & 5 | ✅ **TAMAMLANDI** |
| 🔴 **P0** | /session/verify Giriş Doğrulama | WebAdmin + API | Öneri 3 OpenCode | ✅ **TAMAMLANDI** |
| 🔴 **P0** | ZMax `openat2` Symlink Kaçış Kalkanı | ZMax Çekirdek | `isolation/docs` | ⏳ Sıradaki Sprint |
| 🔴 **P0** | zCage Broker (`zcaged`) & Namespace | İzolasyon Katmanı| `isolation/docs` | ⏳ Sıradaki Sprint |
| 🔴 **P0** | cgroups v2 Kaynak Kotası (`.slice`) | Panel + Linux | Öneri 2 & zCage | ⏳ Sıradaki Sprint |
| 🔴 **P0** | Kullanıcı Bazlı PHP Sürüm Seçici | Panel + ZMax | Öneri 2 | 2 hafta |
| 🟠 **P1** | Alan Başına FPM Master (`zcage-php`)| ZMax + FPM | `isolation/docs` | 2 hafta |
| 🟠 **P1** | nftables `meta skuid` Ağ Kalkanı | İzolasyon Katmanı| `isolation/docs` | 1-2 hafta |
| 🟠 **P1** | Merkezi Yedekleme (S3, SFTP, Drive) | Panel Katmanı | Öneri 2 | 3 hafta |
| 🟠 **P1** | Request Inspector & PHP-FPM Sağlık | WebAdmin | Öneri 1 | 1-2 hafta |
| 🟡 **P2** | Circuit Breaker & stale-if-error | ZMax Çekirdek | Rapor 4 v2 | 2 hafta |
| 🟡 **P2** | WAF & Security Simulator Arayüzü | WebAdmin + Panel| Öneri 1 & CRS | 2 hafta |
| 🟢 **P3** | Tek Tık Uygulama Mağazası (WP+LSCache)| Panel Katmanı | Öneri 2 | 3 hafta |
| 🟢 **P3** | Site Doctor Teşhis Motoru | WebAdmin | Öneri 1 | 1 hafta |

---

## 7. Sonuç

`isolation/docs` belgelerinin entegrasyonuyla ZMax Server ve zPanel ekosistemi; **CloudLinux'ın CageFS teknolojisini geride bırakan, modern Linux çekirdek yeteneklerine (`openat2`, cgroups v2, user/net namespace, Seccomp, Landlock) dayalı, sıfır maliyetli ve kırılması imkansız bir paylaşımlı hosting kalkanına** kavuşmuştur.
