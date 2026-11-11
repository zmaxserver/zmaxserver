# ZMax Server: Mimari Analiz, Boşluk Tespiti ve Kurumsal Sağlamlaştırma (Hardening) Raporu

## 📌 Yönetici Özeti (Executive Summary)
Bu doküman, **Cloudflare Pingora** tabanlı bir çekirdek üzerine inşa edilen, **OpenLiteSpeed/LiteSpeed** yeteneklerini (LSCache, FastCGI, Rewrite, WAF vb.) hedefleyen `ZMax Server` projesinin mevcut `v1.0.01` durumunu analiz eder. Proje, modül çeşitliliği ve temel yetenekler açısından büyük bir olgunluğa ulaşmıştır. Ancak, üretim (production) ortamında "tam güvenlik ve maksimum hız" hedeflerine ulaşması için kapatılması gereken **kritik mimari, güvenlik ve protokol boşlukları** bulunmaktadır. Bu rapor, yapay zeka destekli bir kod analizi ve mimari karar alma süreci için yol haritası niteliğindedir.

---

## 1. Mevcut Durum ve Olgunluk Analizi

Sistem şu anda aşağıdaki temel yeteneklere sahiptir:
*   **Çekirdek:** Tokio tabanlı asenkron motor, zarif kapanış (graceful shutdown), SIGHUP ile canlı yapılandırma yenileme.
*   **Güvenlik:** Temel WAF (SQLi, XSS, Traversal), Token Bucket tabanlı hız sınırlama (Rate Limiting), IP Banlama (Fail2Ban/XMLRPC), HSTS/CSP gibi güvenlik başlıkları.
*   **İçerik Sunumu:** `sendfile` yerine kullanıcı alanında (user-space) tamponlama (`BytesMut`), FastCGI üzerinden PHP desteği (Linux UDS ve Windows TCP), WebP/AVIF otomatik dönüştürme.
*   **Önbellekleme:** Moka tabanlı L1 RAM, Disk tabanlı L2, Stale-While-Revalidate (SWR) ve Stampede koruması.
*   **Protokol:** HTTP/1.1 (Keep-Alive, Pipelining, Chunked).

---

## 2. Kritik Boşluklar (Gap Analysis) ve Sağlamlaştırma Önerileri

Yapay zeka analizleri ve sektör standartları (Nginx, LiteSpeed, Pingora referansları) doğrultusunda, sistemin "Zırhlı" ve "Yıldırım Hızında" olması için şu 5 alanda mutasyon gereklidir:

### 🔴 2.1. Güvenlik ve İzolasyon: "Zero Trust" ve Yetki Düşürme
*   **Mevcut Durum:** `setuid/nobody` yetki düşürme ve `suEXEC` site bazlı izolasyon `📋 Planlanan` aşamasındadır.
*   **Risk:** Çekirdek motorun `root` yetkisiyle çalışması, FastCGI (PHP) üzerinden alınacak bir RCE (Uzak Kod Çalıştırma) açığının tüm sunucuyu ele geçirmesine (Privilege Escalation) yol açar.
*   **Aksiyon:** 
    *   `zmax-runtime` başlangıçta `CAP_NET_BIND_SERVICE` ile 80/443 portlarını açmalı, hemen ardından `setuid` ile `nobody` kullanıcısına düşmelidir.
    *   `zmax-fastcgi` her vHost (sanal sunucu) için ayrı bir Unix Domain Socket (UDS) ve ayrı bir sistem kullanıcısı (suEXEC benzeri) oluşturmalıdır. Bir site hacklendiğinde diğer sitelere erişememelidir.

### 🔴 2.2. Protokol Katmanı: HTTP/2 ve Request Smuggling Koruması
*   **Mevcut Durum:** HTTP/1.1 aktif. `h2` motoru ve `CL.TE/TE.CL` sertleştirmesi eksik.
*   **Risk:** WAF (`mod_coreruleset`) ne kadar güçlü olursa olsun, HTTP istek kaçakçılığı (Request Smuggling) zafiyeti varsa, WAF tamamen atlatılabilir. Ayrıca modern tarayıcılar HTTP/2 olmadan yavaş hisseder.
*   **Aksiyon:**
    *   `zmax-httpparser` içine `h2` (HTTP/2) çerçeve desteği eklenmeli (ALPN uzantısı ile).
    *   `Transfer-Encoding: chunked` ve `Content-Length` çelişkisini (Smuggling) sıkı bir şekilde reddeden RFC 7230 uyumlu başlık doğrulaması yazılmalıdır.

### 🟠 2.3. FastCGI Yaşam Döngüsü: Kalıcı Bağlantı Havuzu (Keep-Alive)
*   **Mevcut Durum:** `zmax-fastcgi` şu an istek başına soket açıp kapatmaktadır.
*   **Risk:** Yüksek eşzamanlılıkta (özellikle WordPress gibi her sayfada onlarca PHP isteği olan sitelerde) TCP/UDS handshake maliyeti, TIME_WAIT birikmesi ve CPU tüketimi sistemi kilitler.
*   **Aksiyon:** 
    *   `FCGI_KEEP_CONN = true` bayrağı aktif edilmelidir.
    *   Pingora'nın `UpstreamSocketPool` mantığı, `zmax-fastcgi` için de uygulanarak PHP-FPM soketleri havuzda tutulmalı ve istekler arasında yeniden kullanılmalıdır.

### 🟠 2.4. I/O ve Bellek Yönetimi: Zero-Copy ve Dağıtık Kilit
*   **Mevcut Durum:** Statik dosyalar `BytesMut` ile user-space'te okunuyor. `zmax-redis` çekirdeğe bağlı değil.
*   **Risk:** Büyük dosya sunumlarında CPU'nun şişmesi. Çoklu süreç mimarisine geçildiğinde L1 önbellek (Moka) tutarsızlığı.
*   **Aksiyon:**
    *   `zmax-static` modülünde, 2 MiB üzeri dosyalar için OS seviyesinde `sendfile(2)` (Linux) / `TransmitFile` (Windows) sistem çağrıları kullanılmalıdır.
    *   `zmax-redis`, `zmax-cache`'e bağlanmalı; çoklu süreçler (multi-process) arasında önbellek tutarlılığı ve "Stampede" (Önbellek çökmesi) koruması için dağıtık kilit (Distributed Lock) mekanizması olarak kullanılmalıdır. Ayrıca `Host` başlığı önbellek anahtarına (Cache Key) eklenerek Zehirlenme (Cache Poisoning) önlenmelidir.

### 🟡 2.5. Operasyonel Dayanıklılık: Çoklu Süreç ve İzleme
*   **Mevcut Durum:** Tek süreçli (single-process) Tokio çalışma zamanı. `SO_REUSEPORT` yok.
*   **Risk:** Tek bir Panik (Crash) tüm sunucuyu düşürür.
*   **Aksiyon:**
    *   `zmax-runtime`, `SO_REUSEPORT` kullanarak her CPU çekirdeği için ayrı bir süreç (worker) başlatmalıdır. Ana süreç (Master) çöken süreci yeniden doğurmalıdır.
    *   Loglama sistemine `X-Request-Id` (Trace ID) eklenerek, dağıtık sistemlerde hata ayıklama (debugging) kolaylaştırılmalıdır.

---

## 3. Modül Matrisi ve Hedef Durum (v1.1+)

| Modül / Katman | Mevcut Durum | Hedef Durum (Hardening) | Öncelik |
| :--- | :--- | :--- | :--- |
| **zmax-runtime** | 🟡 Kısmi | `setuid` yetki düşürme, `SO_REUSEPORT` çoklu süreç, FD devri. | 🔴 Yüksek |
| **zmax-httpparser** | 🟡 Kısmi | HTTP/2 (`h2`), PROXY Protocol, RFC 7230 tam uyumlu Smuggling filtresi. | 🔴 Yüksek |
| **zmax-fastcgi** | 🟡 Kısmi | `FCGI_KEEP_CONN=true` soket havuzu, `suEXEC` izolasyonu, `X-Sendfile` desteği. | 🔴 Yüksek |
| **zmax-static** | 🟡 Kısmi | `sendfile(2)` / Zero-copy, `.br` / `.zst` önceden sıkıştırılmış (precompressed) dosya sunumu. | 🟠 Orta |
| **zmax-cache / Redis** | 🟡 Kısmi | Redis Dağıtık Kilit (Distributed Lock), `Host` başlıklı güvenli Cache Key. | 🟠 Orta |
| **zmax-security** | 🟡 Kısmi | vHost bazlı WAF kuralları, dinamik IP ACL (CRUD API). | 🟠 Orta |
| **zmax-tls** | 🟡 Kısmi | OCSP Stapling, TLS Session Resumption (Hız). | 🟡 Düşük |
| **zmax-quic (HTTP/3)** | 📋 Planlanan | `quinn` UDP dinleyicisi entegrasyonu. | 🟡 Düşük |

---

## 4. Yapay Zeka İçin Kod Üretim / Analiz İpuçları (Prompting Guide)

*Eğer bu projeyi bir yapay zeka ile geliştirecekseniz, aşağıdaki komutları (prompt) kullanabilirsiniz:*

1.  **Güvenlik (Yetki Düşürme):** *"Rust ve Tokio kullanarak, root yetkisiyle 80. portu dinleyen bir TCP listener yaz. Bağlantıyı kabul ettikten sonra `nix` crate'i kullanarak `setuid` ve `setgid` ile yetkiyi `nobody` kullanıcısına düşüren ve güvenli bir şekilde istek işlemeye devam eden bir asenkron runtime tasarla."*
2.  **Hız (FastCGI Havuzu):** *"Rust'ta `bb8` veya `deadpool` gibi bir bağlantı havuzu (connection pool) kütüphanesi kullanarak, FastCGI soketlerini (UDS) havuzda tutan bir yapı yaz. `FCGI_KEEP_CONN` bayrağını nasıl yöneteceğimi ve kopan soketleri havuzdan nasıl düşüreceğimi kodla."*
3.  **Zero-Copy:** *"Tokio kullanarak bir dosyayı ağa yazarken, CPU tüketimini en aza indirmek için Linux `sendfile` sistem çağrısını (`tokio::io::AsyncWriteExt` yerine) nasıl entegre edebilirim? Örnek kod ver."*
4.  **Smuggling Koruması:** *"Rust'ta `httparse` kütüphanesi ile gelen bir HTTP isteğinde, `Transfer-Encoding: chunked` ve `Content-Length` başlıklarının aynı anda bulunması durumunu (Request Smuggling) tespit edip isteği 400 Bad Request ile reddeden bir doğrulama katmanı yaz."*

---

## 🎯 Sonuç
ZMax Server, **LiteSpeed'e gerçekten rakip olabilecek** bir potansiyele sahiptir. Ancak özellik eklemekten ziyade, mevcut özelliklerin **güvenlik sınırlarını (setuid, Smuggling) ve I/O verimliliğini (sendfile, FastCGI Pool)** derinleştirmeye odaklanmalıdır. Bu 5 kritik adım tamamlandığında, sistem hem "sıfır güvenlik" (Zero Trust) hem de "az CPU" (Low CPU) hedeflerine tam anlamıyla ulaşacaktır.