# ZMAX SERVER – CHATGPT TEKNİK ÖNERİLERİ VE GELİŞTİRME REHBERİ

**Proje:** ZMax Server  
**Çalışma alanı:** `D:\zmaxserver`  
**Mevcut sürüm:** v1.0.1  
**Hedef:** Production-ready Rust Web Server  
**Panel:** Go tabanlı ZPanel – mevcut, çalışır ve stabil  
**Ana geliştirme dili:** Rust  
**Doküman:** `chatgptoneri.md`

---

# 1. CHATGPT İÇİN PROJE TALİMATLARI

Bu projede ChatGPT'nin görevi, mevcut ZMax Server kod tabanını analiz etmek, eksikleri tespit etmek, güvenli geliştirme önerileri sunmak ve uygulanabilir kod üretmektir.

Aşağıdaki kurallar zorunludur.

## 1.1 Mevcut kodu koru

- Öncelikle mevcut kaynak kodunu incele.
- Çalışan modülleri gereksiz yere yeniden yazma.
- Mevcut mimariyi anlamadan yeni mimari önerme.
- Aynı işi yapan ikinci bir modül oluşturma.
- Mevcut fonksiyonları ve API'leri sebepsiz yere değiştirme.
- Geriye dönük uyumluluğu koru.
- Değişikliklerin diğer modüllere etkisini incele.

## 1.2 Varsayım yapma

Bir özellik için yalnızca crate içinde kod bulunması, o özelliğin web server içinde çalıştığını kanıtlamaz.

Her özelliği şu kategorilerden biriyle işaretle:

| Durum | Açıklama |
|---|---|
| PLANNED | Henüz geliştirilmemiş |
| IMPLEMENTED | Kodlanmış |
| UNIT TESTED | Birim testleri başarılı |
| INTEGRATED | Ana uygulamaya bağlanmış |
| INTEGRATION TESTED | Gerçek istek akışında test edilmiş |
| PRODUCTION VERIFIED | Canlı veya üretim benzeri ortamda doğrulanmış |

Test edilmemiş özellikleri tamamlanmış olarak gösterme.

## 1.3 Değişiklik yapmadan önce

Her geliştirmede:

1. İlgili crate'i incele.
2. Kullanılan fonksiyonları ve çağrı noktalarını bul.
3. Bağımlılıkları kontrol et.
4. Ana uygulamadaki entegrasyonu incele.
5. Eksik davranışı belirle.
6. Değişiklik planını oluştur.
7. Kod değişikliğini yap.
8. Testleri çalıştır.
9. Sonuçları raporla.

---

# 2. PROJENİN MEVCUT DURUMU

ZMax Server 18 crate içeren Rust workspace mimarisine sahiptir.

Mevcut modüller:

```text
crates/
├── zmax-core
├── zmax-runtime
├── zmax-httpparser
├── zmax-header
├── zmax-pool
├── zmax-tls
├── zmax-timeout
├── zmax-proxy
├── zmax-fastcgi
├── zmax-static
├── zmax-cache
├── zmax-compress
├── zmax-rewrite
├── zmax-security
├── zmax-config
├── zmax-redis
├── zmax-obfuscate
└── zmax-bin
```

Mevcut envantere göre 17 alt kütüphane crate'inde toplam 179 birim testinin başarılı olduğu bildirilmiştir.

`zmax-bin` entegrasyonu ise Wave 2 aşamasındadır.

## 2.1 Tamamlanmış veya geliştirilmiş altyapılar

- HTTP/1.1 parser.
- PROXY Protocol v1/v2.
- Request Smuggling kontrolleri.
- TLS 1.2/1.3.
- ALPN.
- FastCGI.
- FCGI_KEEP_CONN.
- HTTPoxy koruması.
- X-Accel-Redirect.
- Static file handler.
- Linux sendfile.
- Precompressed sidecar.
- Gzip.
- Brotli.
- Hiyerarşik `.htaccess`.
- Moka L1 ve disk L2 cache.
- LiteSpeed Cache başlık köprüsü.
- WAF temel kontrolleri.
- Per-vHost WAF politikası.
- Upstream connection pool.
- Least Connections.
- Round Robin.
- Graceful shutdown altyapısı.
- Binary upgrade için FD devri altyapısı.

Bunlar yeniden yazılacak özellikler değil, ana uygulamadaki entegrasyonları ve gerçek davranışları doğrulanacak özelliklerdir.

---

# 3. BİRİNCİ ÖNCELİK: ZMAX-BIN ENTEGRASYONU

ChatGPT öncelikle `zmax-bin` içindeki entegrasyonları tamamlamaya odaklanmalıdır.

İlgili dosyalar:

```text
crates/zmax-bin/src/
├── main.rs
├── api.rs
├── logger.rs
├── web_engine.rs
└── h2_engine.rs
```

## 3.1 HTTP/2 entegrasyonu

Kontrol edilecekler:

- TLS ALPN üzerinden h2 seçimi.
- `main.rs` içinden `h2_engine` yönlendirmesi.
- HTTP/2 handshake.
- HTTP/2 stream yönetimi.
- Header dönüşümü.
- Request body aktarımı.
- Response streaming.
- HTTP/2 ve HTTP/1.1 ortak davranışı.

Özellikle HTTP/2 isteklerinin aşağıdaki sistemlerle uyumu doğrulanmalıdır:

- WAF.
- Rewrite.
- Cache.
- FastCGI.
- Static handler.
- Security headers.
- Access logging.
- Rate limiting.

HTTP/2 motoru yalnızca bağlantı kabul ediyor diye tamamlanmış sayılmamalıdır.

## 3.2 Per-domain logging

Kontrol edilecekler:

- `log_access()` gerçek istek döngüsünde çağrılıyor mu?
- Her vHost kendi access log dosyasına yazıyor mu?
- Her vHost kendi error log dosyasına yazıyor mu?
- Gerçek `bytes_sent` doğru hesaplanıyor mu?
- NCSA combined formatı doğru mu?
- JSON log formatı doğru mu?
- Log rotation çalışıyor mu?
- Log reopen aktif trafiği kesmeden çalışıyor mu?

## 3.3 WAF entegrasyonu

Kontrol edilecekler:

- Her vHost için WAF politikası uygulanıyor mu?
- `waf_enabled = false` doğru çalışıyor mu?
- `waf_exclude_paths` doğru uygulanıyor mu?
- HTTP/1.1 ve HTTP/2 aynı güvenlik kontrollerinden geçiyor mu?
- Engellenen istekler doğru HTTP durumuyla dönüyor mu?
- WAF olayları loglanıyor mu?

## 3.4 Error Documents

Kontrol edilecekler:

- 403.
- 404.
- 500.
- 502.
- 503.
- `.htaccess ErrorDocument`.
- Özel hata sayfaları.
- Traversal koruması.
- Hata sayfası döngüsü koruması.

## 3.5 API CRUD

Kontrol edilecekler:

- vHost oluşturma.
- vHost listeleme.
- vHost görüntüleme.
- vHost güncelleme.
- vHost silme.
- TOML doğrulama.
- Atomik dosya yazımı.
- Hatalı config rollback.
- Reload sonrası aktif konfigürasyon doğrulaması.

---

# 4. PRODUCTION GÜVENLİĞİ

Yeni özelliklerden önce aşağıdaki güvenlik konuları değerlendirilmelidir.

## 4.1 HTTP güvenliği

- Request Smuggling.
- CL.TE.
- TE.CL.
- Duplicate Content-Length.
- Header injection.
- CRLF injection.
- Invalid chunk encoding.
- Oversized headers.
- HTTP/2 stream flood.
- HPACK bellek sınırları.
- Flow-control saldırıları.

## 4.2 FastCGI güvenliği

- HTTPoxy.
- Script path doğrulaması.
- Document root dışına çıkış.
- Symlink kontrolleri.
- FCGI connection reuse güvenliği.
- PHP-FPM bağlantı hataları.
- X-Accel-Redirect yetkilendirmesi.
- Client disconnect davranışı.

## 4.3 TLS güvenliği

- Strict SNI.
- TLS 1.2/1.3.
- ALPN.
- OCSP Stapling.
- Session Resumption.
- Session Ticket Rotation.
- Sertifika reload.
- TLS handshake timeout.

## 4.4 Cache güvenliği

- Cache poisoning.
- Cross-domain cache leakage.
- Cookie izolasyonu.
- Authorization bypass.
- Vary header doğruluğu.
- Private response caching.
- Cache purge güvenliği.

## 4.5 WAF

Mevcut WAF'ın kapsamı ölçülmelidir.

Geliştirme hedefleri:

- OWASP CRS uyumluluğu.
- Detection Only.
- Blocking Mode.
- Anomaly scoring.
- Rule exclusions.
- Audit logging.
- False-positive yönetimi.

OWASP CRS uyumluluğu test edilmeden tamamlanmış kabul edilmemelidir.

---

# 5. EKSİK MODÜLLER VE GELİŞTİRME ÖNERİLERİ

Mevcut modüllerin ihtiyaçları doğrulandıktan sonra aşağıdaki özellikler değerlendirilmelidir.

| Özellik | Öncelik | Öneri |
|---|---|---|
| HTTP/2 entegrasyonu | P0 | Mevcut h2 motorunu tamamla |
| Zstd compression | P1 | Dinamik sıkıştırma ekle |
| OCSP Stapling | P1 | TLS geliştirmesi |
| Session Resumption | P1 | TLS geliştirmesi |
| DNS resolver | P1 | Asenkron TTL tabanlı resolver |
| Upstream health check | P1 | Proxy geliştirmesi |
| Circuit breaker | P1 | Proxy geliştirmesi |
| Backpressure | P1 | Bellek ve bağlantı güvenliği |
| Connection limits | P1 | IP/vHost/upstream sınırları |
| Bandwidth limits | P1 | IP/vHost trafik sınırları |
| OpenTelemetry | P2 | Dağıtık tracing |
| HTTP/3 | P2 | QUIC ve h3 |
| QPACK | P2 | HTTP/3 bağımlılığı |
| Advanced Bot Protection | P2 | Challenge sistemi |
| Pagespeed | P2 | İçerik optimizasyonu |

Yeni crate açmadan önce mevcut crate'lerde bu işlev için uygun bir yer bulunup bulunmadığı araştırılmalıdır.

---

# 6. PERFORMANS GELİŞTİRME ÖNERİLERİ

ZMax Server'ın hedefi düşük CPU ve RAM kullanımıyla yüksek eşzamanlı bağlantı yönetimidir.

ChatGPT performans önerilerini ölçüme dayandırmalıdır.

## 6.1 Ölçülecek metrikler

- Requests per second.
- Throughput.
- P50 latency.
- P95 latency.
- P99 latency.
- CPU usage.
- RSS memory.
- Allocation count.
- Context switches.
- Open file descriptors.
- Active connections.
- Cache hit ratio.
- Upstream latency.
- PHP response latency.

## 6.2 Benchmark senaryoları

1. Küçük statik dosya.
2. Büyük statik dosya.
3. Çok sayıda eşzamanlı bağlantı.
4. HTTP/1.1.
5. HTTP/2.
6. TLS handshake.
7. PHP-FPM.
8. WordPress.
9. Cache HIT.
10. Cache MISS.
11. Reverse proxy.
12. WebSocket.
13. Gzip.
14. Brotli.
15. Zstd.
16. Uzun süreli yük testi.

Nginx, OpenLiteSpeed ve Caddy ile aynı donanım ve aynı test koşullarında karşılaştırma yapılmalıdır.

Sonuçlar ölçülmeden ZMax'ın rakiplerinden hızlı olduğu iddia edilmemelidir.

---

# 7. MULTI-TENANT PHP İZOLASYONU

Hosting sunucusu için kritik güvenlik alanıdır.

Go panel mevcut olduğundan panel geliştirmesi bu dokümanın kapsamında değildir. Ancak Rust web server ile PHP-FPM arasındaki güvenli çalışma modeli değerlendirilmelidir.

Kontrol edilecekler:

- Her hesap için ayrı UID/GID.
- Her domain için uygun PHP-FPM havuzu.
- Unix socket izinleri.
- Document root sınırları.
- PHP-FPM process limitleri.
- CPU/RAM sınırları.
- Disk ve inode limitleri.
- Session ve temporary directory izolasyonu.
- Kullanıcılar arası dosya erişiminin engellenmesi.

`open_basedir` tek başına tenant izolasyonu sağlamaz.

---

# 8. TEST VE DOĞRULAMA POLİTİKASI

ChatGPT her kod değişikliğinden sonra uygun testleri çalıştırmalıdır.

Örnek:

```bash
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Çapraz derleme hedefleri ayrıca kontrol edilmelidir:

```text
x86_64-pc-windows-msvc
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
```

## 8.1 Entegrasyon testleri

- HTTP/1.1 gerçek istek.
- HTTP/2 gerçek istek.
- TLS sertifika seçimi.
- PHP-FPM.
- İki farklı vHost.
- Ayrı access/error log.
- WAF açık/kapalı.
- Cache HIT/MISS.
- Rewrite.
- Upstream kesintisi.
- Config reload.
- Binary upgrade.
- Rollback.

## 8.2 Uzun süreli testler

- 1 saat stres testi.
- 24 saat soak testi.
- Bellek sızıntısı kontrolü.
- Worker crash testi.
- Yük altında reload.
- Upstream hata senaryoları.

Test sonuçları raporlanmadan production-ready etiketi verilmemelidir.

---

# 9. GELİŞTİRME SIRASI

ChatGPT aşağıdaki sıralamayı temel almalıdır.

## Wave 1 – Entegrasyon

- HTTP/2.
- Per-domain logging.
- WAF.
- Error documents.
- API CRUD.
- Rewrite.
- TLS reload.

## Wave 2 – Uçtan uca doğrulama

- HTTP/1.1.
- HTTP/2.
- FastCGI.
- Static.
- Cache.
- WAF.
- Proxy.
- API.
- Logging.

## Wave 3 – Production güvenliği

- PHP izolasyonu.
- Connection limits.
- Backpressure.
- HTTP/2 güvenlik sınırları.
- TLS güvenliği.
- Cache güvenliği.
- WAF regresyon testleri.

## Wave 4 – Performans

- Zstd.
- FastCGI pool optimizasyonu.
- Proxy health check.
- sendfile benchmark.
- BufferPool optimizasyonu.
- Memory profiling.

## Wave 5 – Gelişmiş özellikler

- OCSP.
- Session Resumption.
- ACME.
- DNS resolver.
- OpenTelemetry.
- Gelişmiş rate limiting.

## Wave 6 – Yeni protokoller

- HTTP/3.
- QUIC.
- QPACK.
- Gelişmiş proxy özellikleri.

---

# 10. CHATGPT'NİN KOD ÜRETME KURALLARI

Kod üretirken:

1. Tam dosya yolunu belirt.
2. Hangi crate'in değiştiğini belirt.
3. Değişiklik sebebini açıkla.
4. Mevcut API uyumluluğunu kontrol et.
5. Gerekli Cargo bağımlılıklarını belirt.
6. Hata durumlarını ele al.
7. Unit test ekle.
8. Entegrasyon testi gerekiyorsa belirt.
9. Windows/Linux uyumluluğunu değerlendir.
10. Güvenlik etkilerini açıkla.

Büyük dosyalarda gereksiz yere tüm dosyayı değiştirme.

Mevcut kodun yalnızca bir bölümünün değiştirilmesi yeterliyse minimal patch tercih et.

Kod derlenmeden derleniyor deme.

Test çalıştırılmadan testler başarılı deme.

Dosyaya erişmeden dosyanın içeriğini biliyormuş gibi davranma.

---

# 11. CHATGPT'NİN KULLANMAMASI GEREKEN YAKLAŞIMLAR

- Tamamlanmış modülleri yeniden yazmak.
- Gereksiz crate oluşturmak.
- Test edilmemiş özellikleri tamamlandı göstermek.
- Benchmark sonucu uydurmak.
- Var olmayan fonksiyon veya dosya varsaymak.
- Sadece birim testiyle production başarısı iddia etmek.
- HTTP/2 ALPN desteğini HTTP/2 sunucusunun tamamlanmasıyla eş tutmak.
- Brotli desteğini Zstd desteği olarak değerlendirmek.
- WAF temel kontrollerini tam OWASP CRS uyumluluğu olarak göstermek.
- Hatalı konfigürasyonda çalışan config'i bozmak.
- Güvenlik kontrollerini performans gerekçesiyle kaldırmak.
- Go panelin mevcut özelliklerini yeniden geliştirmeye çalışmak.

---

# 12. CHATGPT'DEN BEKLENEN GELİŞTİRME RAPORU

Her çalışma sonunda şu format kullanılmalıdır:

## Yapılan İş

Değiştirilen modüller ve dosyalar.

## Mevcut Durum

Her özelliğin gerçek durumu.

## Değişiklikler

Eklenen, düzenlenen ve kaldırılan fonksiyonlar.

## Test Sonuçları

Gerçek komutlar ve gerçek sonuçlar.

## Güvenlik Değerlendirmesi

Olası riskler ve alınan önlemler.

## Performans Etkisi

Ölçülmüş sonuçlar veya henüz ölçülmediği bilgisi.

## Kalan Eksikler

Tamamlanmamış işler.

## Sonraki Adım

Önerilen tek bir sonraki geliştirme aşaması.

---

# 13. PROJENİN NİHAİ HEDEFİ

ZMax Server aşağıdaki özellikleri sağlayan production-grade Rust web server olmalıdır:

- HTTP/1.1 ve HTTP/2.
- Gelecekte HTTP/3.
- Güvenli TLS.
- Yüksek performanslı static delivery.
- PHP-FPM FastCGI.
- Reverse proxy.
- WebSocket.
- Gelişmiş cache.
- Gzip, Brotli ve Zstd.
- Rewrite ve `.htaccess`.
- WAF.
- Rate limiting.
- Per-domain logging.
- Prometheus metrics.
- Güvenli reload.
- Graceful shutdown.
- Binary upgrade.
- Düşük CPU ve RAM tüketimi.
- Yüksek eşzamanlı bağlantı kapasitesi.
- Güvenli multi-tenant çalışma.

**Temel prensip: Önce mevcut altyapıyı tamamla, sonra eksik özellikleri geliştir, en son performans optimizasyonuna geç.**

ZMax Server'ın başarısı crate sayısıyla değil; gerçek trafik altında güvenilir, hızlı, güvenli ve kararlı çalışmasıyla ölçülmelidir.