# ZMax Server

Rust ile yazılmış, yüksek performanslı ve güvenli web sunucusu. Hedef: hosting panelleriyle (zPanel dahil) birlikte çalışan, OpenLiteSpeed ile işlev denkliği sağlayan bir HTTP/HTTPS sunucusu.

*English: a high-performance web server written in Rust, aiming at feature parity with OpenLiteSpeed for hosting-panel use. Pre-release, under active development.*

> **Durum: beta öncesi, aktif geliştirme.** Üretim sunucusunda varsayılan web sunucusu olarak **kullanmayın**. Gerçek sunucu doğrulamaları sürüyor.

## İlerleme

**Son güncelleme: 2026-11-14 · sürüm 1.0.08**

**Katmanlı mimari (v3.0):** sunucu tek sorumluluklu katmanlara ayrıldı: çekirdek, 8 katmanlı trafik hattı, yönetim API'si, WebAdmin arayüzü ve Rust↔Go köprüsü. Şema ve belgeler: [`docs/mimari/`](docs/mimari/) — görsel şema: [`zmax_mimari_semasi.html`](docs/mimari/zmax_mimari_semasi.html).

İlerleme oranı, aşağıdaki bileşen tablosundaki 20 satırın durumundan hesaplanır. Her kalem kodlandıktan sonra incelemeden ve testlerden geçiyor.

```
Tamamlandı ve test edildi   ███████████████████░  %95
İnceleme aşamasında         ░░░░░░░░░░░░░░░░░░░░  %0
Sırada                      █░░░░░░░░░░░░░░░░░░░  %5
```

Kodlanmış toplam (tamamlanan + inceleme): **%95**. Gerçek sunucuda doğrulanan kısım: **yaklaşık %70**; "yerel Linux testi" ile "uzak sunucu testi" ayrımı kalktı — tüm bu doğrulamalar ayrı, gerçek bir AlmaLinux VM'de (VMware) yapıldı, bu zaten "uzak/gerçek sunucu"dur. Bu oturum ZMax'ı canlı VM'de 80/443 ana web sunucusu olarak çalışır durumda (OpenLiteSpeed 8088'e çekildi) gerçek yük/saldırı/WordPress uyumluluk testlerinden geçirdi. Tek kalan madde: OpenLiteSpeed ile yan yana denklik testi. Açık bulgular (ZMax'ın eşzamanlı bağlantı sınırı eksikliği gibi) ayrıca kayıtlı — ayrıntı `doc/testsonra-isler.md`.

### Son gelişmeler

- **2026-11-13 VM testi:** ZMax canlı AlmaLinux VM'de 80/443'ü devraldı (doğrulandı: `ss -ltnp` pid eşleşmesi). Tek-dış-IP yük/DoS testinde PHP-FPM arkalı bir domain'in rate-limit içinde kalarak bile 502'ye düşebildiği bulundu (kök neden: vhost cache varsayılan kapalı + eşzamanlı bağlantı sınırı yok — ZMax kod eksiği, açık). Cache açılınca (X-Cache: HIT) aynı senaryo zararsızlaştı. WordPress + 3 cache eklentisi (LiteSpeed Cache, WP Super Cache, W3 Total Cache) canlı VM'de uçtan uca çalıştı.
- Sanal konak REST API'si hotlink ve IP erişim listesi alanlarını destekliyor.
- Önbellek temizleme (purge) alan adı ve URI bazında çalışıyor; vhost izolasyonu ve yetkilendirme korunuyor. Etiket bazlı temizleme gerçek Linux testinde doğrulandı.
- ACME doğrulama kökü yapılandırmadan (ortak ve alan adı başına) okunuyor; HTTP/2 yolunda da çalışıyor.
- HTTP/1.1 ve HTTP/2 aynı güvenlik denetim hattından geçiyor (`[vhost.acl]` dahil).
- Ters vekil güvenlik incelemesinden geçti: HTTP istek kaçırma (smuggling) kapatıldı, HTTP/2 yanıtları akıtılıyor, bağlantı ve WebSocket zaman aşımları çalışıyor.
- Ayrıcalık düşürme (root olmayan kullanıcıya geçiş), TLS anahtar izni, PHP bağlantı zaman aşımı ve ACME dizin hataları düzeltildi; yerel Linux (root) testinde doğrulandı, uzak sunucu testi sırada.
- Basic Auth: brute-force koruması, sınırlı doğrulama kuyruğu, başarılı doğrulama önbelleği ve yol atlatma (ACME, Windows) açıkları kapatıldı.

### Bileşen durumu

| Bileşen | Durum |
|---|---|
| HTTP/1.1 ve HTTP/2 istek hattı (ortak güvenlik denetimleriyle) | Tamamlandı |
| TLS (SNI, ALPN `h2`/`http/1.1`), sertifika yenileme sonrası yeniden yükleme | Tamamlandı |
| ACME HTTP-01 doğrulama yolu (ortak ve alan adı başına kök) | Tamamlandı |
| Statik dosya sunumu (Range, ETag, ön sıkıştırılmış dosyalar) | Tamamlandı |
| `.htaccess` ve yeniden yazma kuralları | Tamamlandı |
| Sanal konak yapılandırması (TOML) ve REST API ile yönetimi | Tamamlandı |
| IP erişim listeleri, hotlink koruması, WAF | Tamamlandı |
| Erişim günlüğü (NCSA, gerçek bayt sayısı) | Tamamlandı |
| Bellek ve disk önbelleği (L1/L2), alan adı/URI bazlı temizleme | Tamamlandı |
| FastCGI / PHP (temel) | Tamamlandı |
| Ters vekil (reverse proxy): HTTP/1.1 ve HTTP/2, WebSocket, SSE | Tamamlandı |
| Basic Auth (apr1, Argon2id, brute-force koruması) | Tamamlandı |
| WAF olay günlüğü (sızıntısız, token maskeleme, kuyruk taşması) | Tamamlandı |
| Slowloris koruması (başlık ve gövde için mutlak son tarih) | Tamamlandı |
| Statik 404, WordPress permalink, bilinmeyen host güvenliği, dizin listeleme koruması | Tamamlandı |
| Yük altında reload, HTTP/2 çoklu akış, TLS 1.2/1.3, upstream toparlanma testleri | Tamamlandı |
| Ayrıcalık düşürme, TLS anahtar izni, PHP bağlantı zaman aşımı | Tamamlandı (canlı AlmaLinux VM'de doğrulandı — bu VM ayrı, gerçek bir sunucudur; "uzak sunucu testi" bu VM'dir) |
| FastCGI havuzu, `sendfile` | Tamamlandı (`sendfile` ve havuz davranışı canlı VM'de gerçek yük altında ölçüldü: 12 işçi, ~19 istek/sn kapasite tespit edildi; kapasite/DoS riski ayrı bulgu olarak kaydedildi, bkz. ZMax eksiklikleri) |
| OpenLiteSpeed ile yan yana denklik testleri | Sırada |
| zPanel entegrasyonu (panelin vhost üretimi) | Tamamlandı (Go ajanı vhost TOML'una security/logging/error_docs alanlarını yazıyor, canlı VM'de doğrulandı) |
| Toplu gerçek sunucu testi (80/443 geçişi öncesi) | Tamamlandı (canlı AlmaLinux VM'de: 80/443 devralındı, 1M+ istek yük testi, tek-IP DoS testi, WordPress+3 cache eklentisi uçtan uca test edildi; test sırasında bulunan açık maddeler ayrı listelenmiştir, testin kendisi tamamlandı) |

## Yönetim paneli

ZMax, yerel (loopback) bir web yönetim arayüzüyle gelir. Aşağıda sanal konak (alan adı) listesi görülüyor.

![ZMax WebAdmin: alan adları](screenshots/zmax-webadmin-alan-adlari.png)

## Mimari

Cargo çalışma alanı, tek sorumluluklu küçük paketlerden oluşur:

| Paket | Görev |
|---|---|
| `zmax-bin` | Ana ikili, istek hattı, yönetim API'si |
| `zmax-httpparser`, `zmax-header` | HTTP ayrıştırma ve başlıklar |
| `zmax-tls` | TLS ve sertifika yönetimi (rustls) |
| `zmax-static`, `zmax-fastcgi`, `zmax-proxy` | Statik dosya, PHP/FastCGI, ters vekil |
| `zmax-rewrite` | `.htaccess` ve yeniden yazma |
| `zmax-security` | WAF, IP erişim listesi, hotlink |
| `zmax-cache`, `zmax-compress`, `zmax-redis` | Önbellek, gzip/brotli, Redis |
| `zmax-config` | TOML yapılandırma ve sanal konaklar |
| `zmax-runtime`, `zmax-pool`, `zmax-timeout`, `zmax-core` | Çalışma zamanı, bağlantı havuzu, zaman aşımları |

## Derleme ve çalıştırma

Gereksinimler: Rust (kararlı sürüm), Linux önerilir.

```bash
cargo build --release
./target/release/zmax -c conf/zmax.toml
```

Varsayılan test portları: HTTP `19480`, HTTPS `19483`, yönetim API'si `19486`. Örnek yapılandırma `conf/zmax.toml`, örnek sanal konaklar `conf/vhosts/` altındadır.

Testler:

```bash
cargo test --workspace
```

## Testler

Birim/entegrasyon testlerine (`cargo test --workspace`) ek olarak, gerçek bir Linux test sunucusunda (AlmaLinux) derlenmiş release ikili ile doğrulama yapıldı:

- **Statik dosya & sendfile:** tam indirme, Range (baştan/ortadan/sondan/geçersiz → 416), yarıda kesilen istemci sonrası sızıntı yok, HTTP/2 üzerinden indirme, eşzamanlı çoklu indirme.
- **TLS/HTTP2:** TLS 1.2/1.3 el sıkışma, ALPN `h2`/`http/1.1`, aynı bağlantı üzerinde çoklu HTTP/2 akışı, SNI/host doğrulama.
- **PHP/FastCGI:** WordPress üzerinden gerçek istek-yanıt, POST/dosya yükleme, PHP-FPM anlık kesintisinde hızlı `502` ve otomatik toparlanma, yük altında sıcak yeniden yükleme (reload) sırasında sıfır istek kaybı.
- **Güvenlik:** hotlink koruması (HTTP/1.1 ve HTTP/2'de tutarlı), IP erişim listesi, WAF (yol gezinme ve bilinen hassas dosyalar engellendi), hız sınırlama (`rate_limit_per_minute`) DoS koruması.
- **Önbellek:** yol ve etiket bazlı `PURGE`, yetkili/yetkisiz istek ayrımı, vhost izolasyonu.
- **Kaynak kullanımı:** yüz binlerce-milyonlarca istekten oluşan kademeli yük testlerinde dosya tanıtıcısı ve bellek sızıntısı gözlenmedi, süreç kesintisiz çalışmaya devam etti.

Bulunan ve düzeltilen maddeler (eksik `Host` başlığı denetimi, `If-Modified-Since`, desteklenmeyen HTTP metotlarında `405`, günlük dosyasına çift satır yazımı gibi) ilgili commit'lerde kapatıldı. Güncel durum için bu dosyanın en üstündeki bileşen tablosuna bakın.

## Lisans

Apache-2.0. Ayrıntı için `Cargo.toml` içindeki `license` alanına bakın.
