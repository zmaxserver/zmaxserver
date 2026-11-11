# ZMax Server v1.1+ : Üretim Olgunluğu (Production-Readiness) ve Sağlamlaştırma Önerileri

**Belge Amacı:** Bu rapor, `ZMax Server` projesinin `v1.0.1` (Wave 2 entegrasyon aşaması) durumunu analiz ederek, sistemin 7/24 kesintisiz çalışan, yüksek güvenlikli ve operasyonel olarak yönetilebilir bir "Üretim Sürümüne" (Production-Ready) geçişi için gereken kritik mühendislik adımlarını listeler.

**Mevcut Durum Özeti:** 18 crate'lik devasa bir mimari kurulmuş, 179 birim testi başarıyla geçmiştir. Çekirdek modüller (WAF, FastCGI, Cache, TLS, Zero-copy) büyük oranda tamamlanmıştır. Odak noktası artık **"modülleri yazmak" değil, "bu modüllerin birbiriyle kusursuz ve güvenli çalışmasını sağlamak"** olmalıdır.

---

## 🎯 1. Wave 2: Uçtan Uca (E2E) Entegrasyon ve Bin (İkili) Bağlantıları

Modüllerin (crate) tek başına test edilmesi yeterli değildir. `zmax-bin` içindeki ana istek hattının (request pipeline) tüm modülleri sırasıyla ve hatasız çağırması gerekir.

### 1.1. Log Yöneticisi (Logger) Entegrasyonu
*   **Mevcut Durum:** `logger.rs` yazıldı ve NCSA/JSON formatları test edildi, ancak `web_engine.rs` içindeki istek döngüsüne tam bağlanmadı.
*   **Öneri:** İstek yaşam döngüsünün en sonunda (response gönderildikten sonra), `state.log_manager.log_access(...)` fonksiyonunun tetiklendiğinden emin olun. Canlı bir test ortamında (iki farklı vHost ile) istek atıp, iki ayrı `access.log` dosyasına gerçek `%b` (bayt) ve `%D` (gecikme) değerlerinin düştüğünü doğrulayın.

### 1.2. HTTP/2 (h2) Motoru ve TLS ALPN Yönlendirmesi
*   **Mevcut Durum:** `h2_engine.rs` mevcut ancak `main.rs` içindeki TLS kabul döngüsünde ALPN (`h2` / `http/1.1`) protokolüne göre yönlendirme tam değil.
*   **Öneri:** TLS el sıkışması (handshake) bittiğinde, `negotiated_alpn` kontrolü yapılmalı. Eğer `h2` ise `h2_engine`'e, değilse `web_engine`'e yönlendirilmeli. *Kritik Risk:* HTTP/2 isteklerinde `:authority` (Host) başlığının WAF ve vHost yönlendirmesinde `Host` başlığı yerine doğru şekilde kullanıldığından emin olun.

### 1.3. WAF, Rewrite ve Error_Docs Entegrasyonu
*   **Mevcut Durum:** Modüller hazır, ancak istek hattında (pipeline) sıralama ve veri aktarımı henüz tam test edilmedi.
*   **Öneri:** İstek hattı şu sırayla çalışmalıdır: `Rate Limit -> WAF (IP/URL) -> vHost Bulma -> .htaccess (Rewrite) -> FastCGI/Static`. `.htaccess` içindeki `ErrorDocument` veya vHost `error_docs` ayarlarının, `write_error_response` merkezi fonksiyonuna doğru şekilde aktarıldığı test edilmelidir.

---

## 🛡️ 2. Güvenlik Sınırları ve İzolasyon (Zero-Trust)

### 2.1. `drop_privileges` (Yetki Düşürme) Sonrası Dosya İzinleri
*   **Mevcut Durum:** `zmax-core` içinde `setuid`/`setgid` yazıldı. Çekirdek root olarak başlayıp portları açacak, sonra yetkiyi düşürecek.
*   **Öneri:** Yetki düşürüldükten sonra (örneğin `nobody` kullanıcısına geçildiğinde), ZMax'in log dosyalarına (`logs/access.log`), önbellek dizinlerine (`cache/`) ve geçici dizinlere (`/tmp/zmax`) yazma yetkisinin olması gerekir. `drop_privileges` çağrılmadan önce bu dizinlerin sahiplikleri (`chown nobody`) ve izinleri (`chmod 755`) ayarlanmalıdır. Aksi takdirde sistem yetki düşürdükten sonra günlük dahi yazamaz hale gelir.

### 2.2. `suEXEC` (Site Bazlı İzolasyon)
*   **Mevcut Durum:** FastCGI için `FCGI_KEEP_CONN` var, ancak site bazlı yetki izolasyonu eksik.
*   **Öneri:** Bir vHost'un (örneğin `site1.com`) PHP betiği çalıştırdığında, bu betiğin sistemdeki kullanıcı yetkisi web sunucusunun kullanıcısından (nobody) farklı olmalıdır. Çoklu süreç (multi-worker) mimarisinde her vHost için ayrı bir Unix Domain Socket (UDS) ve ayrı bir kullanıcı tahsis edilmelidir (ZePanel/Go tarafının kuracağı PHP-FPM havuzları aracılığıyla).

---

## 🧠 3. Önbellek Tutarlılığı (L1 vs L2 vs Redis)

### 3.1. Çoklu Worker Süreçlerinde L1 (RAM) Senkronizasyonu
*   **Mevcut Durum:** `zmax-cache` içinde Moka L1 RAM ve L2 Disk var. Redis Pub/Sub (`ClusterSyncEvent`) ile süreçler arası haberleşme mevcut.
*   **Kritik Risk:** Worker A, bir sayfayı güncellediğinde önbelleği temizler (Purge). Ancak Worker B (veya C, D) kendi RAM'inde (Moka L1) eski veriyi tutmaya devam ederse, kullanıcılar eski içeriği görmeye devam eder.
*   **Öneri:** Redis'ten gelen `PurgeDomain` veya `PurgeTag` sinyali alındığında, ilgili Worker sadece L2/Redis'i değil, **kendi yerel L1 (Moka) önbelleğini de anında temizlemelidir.** Bu dağıtık önbellek tutarlılığı (Distributed Cache Coherency) için şarttır.

### 3.2. Cache Stampede ve Redis Distributed Lock
*   **Öneri:** Önbellek boş olduğunda binlerce isteğin aynı anda PHP-FPM'e (FastCGI) yüklenmesini engellemek için Redis üzerinden `SET NX PX` (Distributed Lock) mekanizması kullanılmalıdır. İlk istek kilidi alıp veriyi yüklerken, diğerleri kısa bir süre bekleyip önbellekten okumalıdır.

---

## 🏢 4. Operasyonel Dayanıklılık ve Çoklu Süreç Yönetimi

### 4.1. Çöken Worker'ları Otomatik Ayağa Kaldırma (Supervisor/Respawner)
*   **Mevcut Durum:** `SO_REUSEPORT` ile çoklu worker hedefleniyor, "zarif kapanma" (graceful shutdown) var.
*   **Öneri:** Ana süreç (Master Process), `SO_REUSEPORT` ile açtığı portları Worker süreçlere devreder. Eğer bir Worker süreci herhangi bir nedenle (Panic, OOM) çökerse, Master süreç bunu algılayıp **anında yeni bir Worker süreci başlatmalıdır (Respawn).** Bu, Nginx'in en temel hayatta kalma özelliğidir.

### 4.2. Windows ve Linux Farklılıkları (Conditional Compilation)
*   **Öneri:** `zmax-core` ve `zmax-runtime` içindeki `sendfile`, `setuid`, `sched_setaffinity` gibi fonksiyonlar sadece Linux'ta derlenmeli. Windows derlemelerinde (`x86_64-pc-windows-msvc`) bu fonksiyonların yerine `TransmitFile`, `SetThreadAffinityMask` gibi alternatifler veya güvenli "no-op" (hiçbir şey yapmayan) fallback'ler kullanılmalıdır. Aksi takdirde Windows derlemesi hata verir.

---

## 📊 5. Gözlemlenebilirlik (Observability) Derinleştirmesi

Sistemin içinde neler olduğunu görebilmek için sadece CPU/RAM değil, iş mantığı metrikleri de olmalıdır.
*   **Öneri (Prometheus Metrikleri):**
    *   `zmax_waf_blocked_requests_total{rule="sqli"}` (WAF tarafından engellenenler)
    *   `zmax_cache_hit_ratio` (L1 ve L2 önbellek isabet oranı)
    *   `zmax_fastcgi_pool_active_connections` (FastCGI havuzundaki dolu soket sayısı)
    *   `zmax_redis_pubsub_latency_ms` (Dağıtık senkronizasyon gecikmesi)

---

## 🚀 6. Yol Haritası ve Önceliklendirme (Action Plan)

Sistemi yayına almadan önce şu sıralamayı takip etmeniz önerilir:

| Öncelik | Görev | Gerekçe |
| :--- | :--- | :--- |
| **P0 (Kritik)** | `zmax-bin` Wave 2 Entegrasyonları ve E2E testleri | Modüllerin birbiriyle konuştuğunu kanıtlamak. |
| **P0 (Kritik)** | `drop_privileges` sonrası dosya izinleri testi | Log ve cache yazamayan bir sunucu çöker. |
| **P1 (Yüksek)** | Worker Respawner (Çöken süreci ayağa kaldırma) | 7/24 kesintisiz hizmet (High Availability) için şart. |
| **P1 (Yüksek)** | L1 Moka Önbelleğinin Redis Pub/Sub ile temizlenmesi | Kullanıcıların eski veri görmesini (Stale Data) engeller. |
| **P2 (Orta)** | Windows/Linux Platform Bazlı Kod Ayrımı (`#[cfg]`) | Çapraz platform derlemelerinin patlamasını önler. |
| **P3 (Düşük)** | Prometheus İş Mantığı Metrikleri | Sistemin darboğazlarını analiz etmek için. |

---

## 💎 Sonuç
ZMax Server, `v1.0.1` itibarıyla muazzam bir çekirdek mimariye sahiptir. Eksikler artık "özellik" eksikliği değil, **"sistem entegrasyonu ve operasyonel dayanıklılık"** eksikliğidir. Yukarıdaki P0 ve P1 adımları tamamlandığında, LiteSpeed ve Nginx gibi devlere karşı sadece hızıyla değil, aynı zamanda **güvenliği ve kararlılığıyla** da rakip olabilecek bir Rust şaheseri ortaya çıkacaktır.