# ZMax Server — Sağlam Yapı (dört öneri belgesinin birleşimi)

Tarih: 2026-11-12
Kaynak: `chatgpt.md`, `chatgptoneri.md`, `seepseek.md`, `deepseek_oneri.md` (hepsi okundu) + `D:\zmaxserver\crates` kaynak kodu + VM uçtan uca testi (2026-11-11).
Kapsam: yalnız Rust web sunucusu (ZMax). Go paneli (ZPanel) çalışır durumda ve bu belgede yeniden yazılmaz; yalnız iki taraf arasındaki sözleşme yazılır.
Doğrulama ilkesi: kodda doğrulanmayan her bilgi "bilinmiyor" yazılmıştır. Bu belgedeki durum tablosu kaynak koddan okunarak çıkarıldı; çalıştırılıp denenmedi (`cargo test --workspace` çıkış kodu 0 dışında).

---

## 1. Değişmez ilkeler

1. **Önce gerçek durum.** Bir crate'te kod bulunması özelliğin çalıştığını göstermez. Her özellik şu etiketlerden biriyle işaretlenir: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` (istek hattına bağlı) → `INTEGRATION TESTED` (gerçek istek akışı) → `PRODUCTION VERIFIED`. Üst etiket, alttakilerin hepsi sağlanınca verilir.
2. **Modül çoğaltma yok.** Önce mevcut 18 crate'te yer aranır. Olmayan crate (`zmax-realip`, `zmax-metrics`, `zmax-log`, `zmax-acme`, `zmax-cli`) var sayılmaz. Yeni crate yalnız mevcut hiçbir crate'e sığmıyorsa ve gerekçesi yazılarak açılır.
3. **Çalışanı bozma.** Tamamlanmış modül yeniden yazılmaz; minimal yama. Hatalı yapılandırma çalışan yapılandırmayı bozmaz (son çalışan yapılandırma + geri alma).
4. **Kanıtsız söz yok.** Derlenmeden "derleniyor", çalıştırılmadan "geçti", ölçülmeden "daha hızlı" denmez. Benchmark sonucu uydurulmaz. Birim test ≠ üretim başarısı. ALPN'de `h2` duyurmak ≠ HTTP/2 sunucusu.
5. **Güvenlik performans uğruna kaldırılmaz.**
6. **Rust korur, Go birleştirir** (bölüm 3). Rust yönetim kararı vermez, Go trafiğe dokunmaz.

---

## 2. Koddan doğrulanan gerçek durum (2026-11-12, 01:xx düzeltmesi)

> Düzeltme: ZMax kodu 00:23–01:00 arasında değişti; bu tablonun günlük, HTTP/2, FastCGI, SO_REUSEPORT, test sayısı satırları güncellendi. Etiketli güncel durum: [TAM_MODUL_VE_OZELLIK_MATRISI.md](../TAM_MODUL_VE_OZELLIK_MATRISI.md).

| Özellik | Etiket | Kanıt / not |
|---|---|---|
| TLS 1.2/1.3, SNI, sertifika yeniden yükleme (vhost) | INTEGRATION TESTED (VM test portu) | `zmax-tls`, `refresh_tls_certs`; VM: TLS1.3, sertifika eşleşti |
| Panel/API portu sabit sertifikası yeniden yükleme | Eksik | `build_single_cert_acceptor` reload'da yenilenmiyor |
| `force_https` (ACME muaf) | INTEGRATED | `web_engine.rs` ~satır 490 |
| `hotlink_protection` | INTEGRATED | `web_engine.rs` ~satır 852 |
| `.htaccess` (`RewriteEngine/Base/Cond/Rule`, `Redirect/RedirectMatch`, `DirectoryIndex`, `ErrorDocument`, `try_files`, `PATH_INFO`) | INTEGRATED (yalnız kök `.htaccess`) | `zmax-rewrite/src/htaccess.rs`; VM testinde "kısmi" çıkmıştı, güncel ikiliyle tekrar sınanmalı |
| Alt klasör `.htaccess`, `Options`, `[E=HTTP_AUTHORIZATION]`, `[[vhost.rewrite]]` | Yok | |
| Vhost günlüğü (`logger.rs` `AsyncLogManager`) | INTEGRATED (koddan, 2026-11-12 01:xx) | `web_engine.rs:2720` `log_access`; NCSA combined + JSON; `main.rs:632` SIGUSR1 `reopen_all`. Gerçek `bytes_sent` hesabı ve VM çalışması DOĞRULANMADI (varsayılan 0) |
| Günlük satırı | INTEGRATED (biçim kodda) | `[ts]`, `bytes_sent`, referer, UA var; bayt değerinin doğruluğu doğrulanmadı |
| `error_docs` (`VHostErrorDocsSection`) | IMPLEMENTED | alan `web_engine.rs` bağlamına taşındı (~79-81, 264-266); istek mantığında kullanımı doğrulanmadı |
| Vhost WAF (`waf_enabled`, `waf_exclude_paths`) | IMPLEMENTED | `web_engine.rs` bağlamına taşındı; istek mantığında kullanımı doğrulanmadı |
| HTTP/2 | INTEGRATED (koddan, birim/VM testi yok) | `h2_engine.rs` (`h2::server`) var; `main.rs` ~398-422 ALPN `["h2","http/1.1"]` + `negotiated_alpn` → `handle_h2_connection`. WAF/rewrite/cache/günlük uyumu doğrulanmadı |
| ACME http-01 statik sunum | INTEGRATION TESTED (VM) | `.well-known/acme-challenge` |
| PHP (FastCGI, php-fpm havuzu) | INTEGRATION TESTED (VM) | WordPress sayfası döndü |
| Önbellek (L1 Moka, L2 disk, tag purge, SWR, stampede) | UNIT TESTED | `zmax-cache` 3 test; Redis Pub/Sub ile L1 tutarlılığı doğrulanmadı |
| API uçları (`/health`, `/metrics`, `/status`, `/logs`, `/ports`, `/cache/purge`, `/reload`, `/config`, `/vhosts`) | IMPLEMENTED | `api.rs`; vhost `PUT/POST` alan kapsamı eksik |
| `web_engine.rs` testleri | zmax-bin toplam 31 test | dosya dağılımı bilinmiyor |
| FastCGI `FCGI_KEEP_CONN` / havuz, HTTPoxy engeli | IMPLEMENTED | `zmax-fastcgi/src/lib.rs` ~23, 785, 813, 890-918; `zmax-bin` havuzlu çağrıyı kullanmıyor → INTEGRATED değil |
| `SO_REUSEPORT`, `sendfile`, `drop_privileges` | `SO_REUSEPORT`: IMPLEMENTED (`main.rs` ~121-137); `sendfile` `zmax-static`'te var, `web_engine` kullanmıyor; `drop_privileges` `zmax-core`'da var, `main.rs` çağırmıyor (INTEGRATED değil); worker respawn: bilinmiyor | |
| `logger.rs`, `h2_engine.rs` | VAR (879 / ~280 satır) | yukarıdaki satırlar |
| Birim test sayısı | 217 (grep: 186 kütüphane + 31 `zmax-bin`) | çalıştırılmadı |

**Belgeler arası çelişkiler (çözüm: koddan doğrula, hiçbirine güvenme):**
- `seepseek.md` (HTTP/1.1 yalnız, tek süreç, setuid planlı, keep-alive yok) ile `chatgptoneri.md` (bunların çoğu yapılmış) çelişiyor.
- `chatgpt.md` var olmayan crate'leri listeliyor.

---

## 3. Rust ↔ Go iş bölümü ve sözleşme

| Sorumluluk | ZMax (Rust) | ZPanel (Go ajan/API) |
|---|---|---|
| Gelen HTTP/HTTPS, TLS, ALPN | ✅ | ❌ dokunmaz |
| Önbellek, purge | ✅ | purge API'sini çağırır |
| WAF/DoS (kapıda keser) | ✅ | ban olaylarını nftables/iptables'a kalıcı yazar |
| Günlük yazma, döndürme | ✅ (vhost başına dosya, SIGUSR1) | günlük sayfası, `.gz` arşiv, istatistik/trafik hesabı |
| ACME dosyalarını sunma | ✅ | certbot'u yönetir, yenileme sonrası `reload` |
| vhost TOML yazımı | ❌ salt okunur tüketici | ✅ `/usr/local/zmax/conf/vhosts/<alan>.toml` |
| PHP-FPM havuzu, kullanıcı, soket izolasyonu | soketi güvenli kullanır | ✅ havuz/kullanıcı kurar (`/run/zpanel-php/<kimlik>.sock`) |
| Panel/webmail/Zplus proxy vhost'ları | ✅ `zmax-proxy` | ✅ vhost'ları yazar |
| İşletim sistemi güvenlik duvarı | ❌ | ✅ |
| Kurulum/güncelleme/geri dönüş (OLS'e dönüş) | ❌ | ✅ `zmax-gecis.sh`, `ajan-guncelle.sh` |

Sözleşme: Go TOML yazar → `POST http://127.0.0.1:19486/api/v1/reload` (ya da SIGHUP) → ZMax doğrular, atomik uygular, hata olursa eskisinde kalır. TOML alan adları değişirse iki taraf birlikte güncellenir.

---

## 4. Sıralı yol haritası

### Faz 0 — Gerçeği kapat (önce)
Yukarıdaki "bilinmiyor" satırlarını koddan kapat: FastCGI keep-alive, `sendfile`, `drop_privileges` izinleri, `SO_REUSEPORT`/worker modeli, `logger.rs`/`h2_engine.rs` varlığı, gerçek test sayısı. Her satıra 6 etiketten biri yazılır.

### Faz 1 — Entegrasyon (dört belgenin ortak P0'ı)
1. **Alan adına özel günlük:** vhost başına `access.log` ve `error.log`; gerçek gönderilen bayt, zaman damgası, NCSA combined (`IP - - [%d/%b/%Y:%H:%M:%S %z] "METHOD PATH HTTP/x" STATUS BAYT "Referer" "UA"`), JSON seçeneği, istek kimliği (`X-Request-Id`), `max_log_size_mb` döndürme, SIGUSR1 ile yeniden açma, tamponlu/asenkron yazıcı, disk hatası davranışı. Panelin trafik/kota hesabı bu bayttan yapılır.
2. **`error_docs` ve vhost WAF'ı istek hattına bağla.** İstek hattı sırası: `hız sınırı → WAF (IP/URL) → vhost bulma → .htaccess (rewrite) → FastCGI/statik`. `.htaccess ErrorDocument` ve vhost `error_docs` ortak `write_error_response` fonksiyonundan geçer; dizin kaçışı ve hata sayfası döngüsü koruması.
3. **HTTP/2:** mevcut olgun `h2` crate'i kullanılır (sıfırdan protokol yazılmaz). ALPN sonrası yönlendirme (`h2` → h2 motoru, yoksa HTTP/1.1), `:authority`'nin vhost/WAF'ta `Host` yerine doğru kullanımı, WAF/rewrite/cache/FastCGI/statik/günlük/hız sınırı uyumu. **Bitene kadar ALPN yalnız `http/1.1` duyurur.**
4. **API CRUD tamamlama:** `PUT/POST /api/v1/vhosts`: `hotlink_protection`, `allow_ips`, `deny_ips`, `rewrite.*`, `headers.*`, `logging.*`, `error_docs.*`, `security.waf_*`; TOML doğrulama, atomik yazım, hatalı yapılandırmada geri alma, reload sonrası aktif yapılandırma doğrulaması.
5. **`.htaccess` kalanları:** alt klasör `.htaccess`, `Options`, `[E=HTTP_AUTHORIZATION:...]`, mtime tabanlı ayrıştırıcı önbelleği, kural yürütme ve regex karmaşıklığı sınırı, yönlendirme döngüsü koruması.
6. **Panel/API portu sertifikası** `SniResolver::replace` gibi yeniden yüklenir.
7. **VM'de iki vhost ile uçtan uca test** (bölüm 6).

### Faz 2 — Üretim güvenliği ve operasyon (DeepSeek P0/P1 + ChatGPT §3–4)
- `drop_privileges` **öncesi** günlük/önbellek/tmp dizinlerinin sahipliği ve izni ayarlanır (yoksa yetki düşünce günlük yazılamaz); `CAP_NET_BIND_SERVICE` ile 80/443, sonra yetki düşürme.
- Worker çökerse yeniden başlatma (master/respawn); `SO_REUSEPORT` çoklu worker, isteğe bağlı CPU affinity (yapılandırılabilir).
- HTTP ayrıştırıcı: Request Smuggling (CL.TE, TE.CL, kopya `Content-Length`, çelişen `Transfer-Encoding`, geçersiz chunk, satır katlama), başlık/CRLF enjeksiyonu, aşırı büyük başlık, HTTP/2 akış taşması, HPACK bellek sınırı, akış denetimi saldırıları.
- FastCGI: `FCGI_KEEP_CONN` soket havuzu (önceki isteği bitmeden asla yeniden kullanma), HTTPoxy, `SCRIPT_FILENAME`/`PATH_INFO` doğrulama, kök dışına çıkış ve symlink kontrolü, `X-Accel-Redirect`/`X-Sendfile` yetkilendirmesi, istemci kopunca iptal.
- Önbellek güvenliği: önbellek anahtarına `Host`; Redis `PurgeDomain`/`PurgeTag` gelince **kendi L1 (Moka) önbelleğini de** temizleme; Redis dağıtık kilit (`SET NX PX`) ile stampede; çerez/Authorization bypass; özel yanıt önbelleklenmez; `Vary` doğruluğu.
- Güvenli yapılandırma yeniden yükleme: ayrıştır → doğrula → aday yapılandırma → bağımlılık denetimi → atomik etkinleştirme → zarif yeniden yükleme → sağlık denetimi → başarısızsa geri alma.
- Bağlantı ve bellek sınırları: IP/vhost/upstream başına bağlantı, gövde sınırı, başlık sınırı, tampon belleği sınırı, geri basınç (backpressure). İstek hızı sınırı ile bant genişliği sınırı ayrı şeylerdir.
- Sıfır kesinti ikili yükseltme (FD devri): yeni süreç sağlıklı olmadan eskisi kapatılmaz, başarısızsa geri dönüş.

### Faz 3 — Performans (ölçerek)
- Senaryolar: 1 KB/100 KB/1 MB/100 MB statik, aralık (Range) istekleri, HTTP/1.1, HTTP/2, TLS el sıkışma, PHP-FPM, WordPress, önbellek HIT/MISS, gzip/brotli, ters vekil, WebSocket, yüksek eşzamanlılık, uzun süreli kararlılık.
- Ölçüler: RPS, verim, P50/P95/P99, CPU, RSS, bağlam geçişi, açık FD, hata oranı. Nginx, OpenLiteSpeed, Caddy ve (varsa) Ferron ile aynı donanımda, ham sonuçlar saklanır.
- Optimizasyonlar: `sendfile(2)` (büyük dosya, tampon yoluyla karşılaştır), önceden sıkıştırılmış `.br/.gz/.zst`, ETag/If-None-Match/304, Zstd, FastCGI havuz ayarı, tampon havuzu üst sınırı.

### Faz 4 — Ürünleşme
- Tarayıcı/uygulama uyumluluğu gerçek uygulama paketleriyle: WordPress, Laravel, OpenCart, Drupal, Joomla.
- LiteSpeed Cache uyumu: `X-LiteSpeed-Cache-Control/Tag/Purge`, `_lscache_vary` (WordPress eklentisiyle).
- Basic Auth (`.htpasswd`, Argon2id), vhost başına.
- Üst akış sağlık denetimi, devre kesici, ağırlıklı dağıtım, WebSocket, DNS çözücü (TTL, negatif önbellek), TLS: OCSP stapling, oturum sürdürme, bilet anahtarı rotasyonu, sıkı SNI, el sıkışma zaman aşımı, sertifika süre izleme.
- Gözlemlenebilirlik: Prometheus (`waf_blocked_total`, önbellek isabet oranı, FastCGI havuz doluluğu, Redis Pub/Sub gecikmesi, TLS el sıkışma gecikmesi, yanıt süresi histogramı), isteğe bağlı OpenTelemetry. Kimlik bilgisi ve oturum çerezi asla günlüğe yazılmaz.
- CLI (`zmax status|reload|logs|purge|config validate|config rollback|tls status`): net çıkış kodları, etkileşimsiz çalışma.

### Faz 5 — Şimdilik YAPMA (çekirdek üretime hazır olana kadar)
HTTP/3 ve QUIC (`quinn`, `h3`), QPACK, Pagespeed, uygulama süpervizörü, küme/çoklu süreç koordinasyonu, JavaScript bot koruması, tam OWASP CRS uyumu (regresyon paketi çalışmadan "uyumlu" denmez), Windows'a özel yol ayrımı (Linux birincil hedef; `sendfile`/`setuid`/`sched_setaffinity` yalnız Linux'ta derlenir, Windows'ta no-op/alternatif).

---

## 5. Sürüm sırası (öneri)

| Sürüm | İçerik |
|---|---|
| v1.0.02 | Faz 0 + Faz 1 (günlük, `error_docs`, vhost WAF, HTTP/2 ya da `http/1.1`'e düşürme, API, `.htaccess` kalanları) |
| v1.0.03 | Faz 2 güvenlik: ayrıştırıcı sertleştirme + fuzz, FastCGI havuzu + HTTPoxy, önbellek tutarlılığı, `drop_privileges` izinleri, worker respawn |
| v1.0.04 | Güvenli yeniden yükleme + sınırlar (bağlantı/bellek/geri basınç) |
| v1.0.05 | Statik performans (`sendfile`, önceden sıkıştırılmış, Zstd, 304) |
| v1.0.06 | Vekil ve FastCGI (sağlık denetimi, dağıtım, akış) |
| v1.0.07 | TLS ve ACME (OCSP, oturum sürdürme, yenileme) |
| v1.0.08 | WAF/DDoS (CRS regresyonu, Detection Only/Blocking, bant sınırı) |
| v1.0.09 | Gözlemlenebilirlik (metrikler, istek kimliği, histogramlar) |
| v1.1.00 | Üretim sürümü: tam regresyon, performans doğrulama, güvenlik denetimi, 24 saat dayanıklılık, yükseltme ve geri dönüş testi, üretim belgeleri |

---

## 6. Kabul ölçütleri ve test politikası

Her değişiklikten sonra: `cargo fmt --all -- --check`, `cargo check --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`; çapraz derleme: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (Windows ayrı).

Entegrasyon testleri (VM, iki vhost): HTTP/1.1 ve HTTP/2 gerçek istek, TLS sertifika seçimi, PHP-FPM, ayrı access/error günlüğü (satırda tarih ve bayt), WAF açık/kapalı, önbellek HIT/MISS, rewrite, upstream kesintisi, yapılandırma yeniden yükleme, ikili yükseltme, geri dönüş.

Madde başına kabul:
- **Günlük:** iki vhost'a istek → her biri kendi dosyasında; satırda tarih ve gerçek bayt; SIGUSR1 sonrası yeni dosyaya yazar.
- **`error_docs`:** 404'te vhost'un `404.html`'i, yoksa varsayılan.
- **Vhost WAF:** `waf_enabled=false` vhost'ta imza geçer, `true`'da 403; `waf_exclude_paths` muaf.
- **HTTP/2:** `curl --http2 -I https://...` → `HTTP/2 200`; çok akışlı istek; `curl --http1.1` etkilenmez; ALPN doğru seçer.
- **`.htaccess`:** WordPress `/ornek-yazi/` → 200; alt klasör kuralı uygulanır.
- **Sertifika yenileme:** yenileme sonrası sunucu yeni sertifikayı sunar.

Uzun süreli: 1 saat stres, 24 saat dayanıklılık, bellek sızıntısı, worker çökmesi, yük altında yeniden yükleme, upstream kesintisi, trafik sıçraması. Parser için `cargo-fuzz`, özellik tabanlı test, regresyon paketleri.

Çalışma sonu rapor biçimi: Yapılan iş (dosyalar) · Gerçek durum (6 etiket) · Değişiklikler · Test komutu ve literal çıktısı · Güvenlik değerlendirmesi · Performans etkisi (ölçülmediyse "ölçülmedi") · Kalan eksikler · Tek sonraki adım.

---

## 7. Üretime hazırlık kontrol listesi (kutu yalnız kanıtla işaretlenir)

- **Runtime:** [ ] zarif kapanış [ ] zarif yeniden yükleme [ ] worker kurtarma [ ] bellek sınırı [ ] bağlantı sınırı [ ] uzun süreli kararlılık
- **HTTP:** [ ] HTTP/1.1 [ ] HTTP/2 [ ] Smuggling koruması [ ] başlık doğrulama [ ] Range [ ] Keep-Alive
- **TLS:** [ ] 1.2 [ ] 1.3 [ ] SNI [ ] ALPN [ ] OCSP [ ] oturum sürdürme [ ] sertifika yenileme
- **Statik:** [ ] sendfile [ ] WebP/AVIF [ ] gzip [ ] brotli [ ] zstd [ ] Range akışı [ ] koşullu istek
- **FastCGI:** [ ] PHP-FPM [ ] kalıcı bağlantı [ ] bağlantı kurtarma [ ] akış [ ] HTTPoxy [ ] iç yönlendirme
- **Vekil:** [ ] havuz [ ] sağlık denetimi [ ] dağıtım [ ] WebSocket [ ] geri basınç [ ] zaman aşımı
- **Güvenlik:** [ ] WAF [ ] CRS testleri [ ] hız sınırı [ ] IP ACL [ ] hotlink [ ] Basic Auth [ ] regresyon
- **Gözlem:** [ ] vhost erişim günlüğü [ ] vhost hata günlüğü [ ] istek kimliği [ ] Prometheus [ ] gecikme [ ] worker metrikleri
- **Sürüm:** [ ] temiz kurulum [ ] yükseltme [ ] geri dönüş [ ] yapılandırma göçü [ ] systemd [ ] güvenlik denetimi [ ] benchmark [ ] 24 saat dayanıklılık

---

## 8. Yapılmaması gerekenler (dört belgeden)

- Tamamlanmış modülü yeniden yazmak; gereksiz crate açmak; olmayan fonksiyon/dosya varsaymak.
- Test edilmemiş özelliği tamamlandı göstermek; sadece birim testiyle üretim başarısı iddia etmek.
- ALPN `h2` duyurusunu HTTP/2 uygulaması saymak; Brotli desteğini Zstd saymak; temel WAF'ı OWASP CRS uyumu saymak.
- Benchmark uydurmak; ölçmeden rakipten hızlı demek.
- Hatalı yapılandırmada çalışan yapılandırmayı bozmak; güvenlik denetimini performans gerekçesiyle kaldırmak.
- Go panelin mevcut özelliklerini Rust tarafında yeniden geliştirmek.
- Dosyaya erişmeden içeriğini biliyormuş gibi davranmak.

---

## 9. Go (ZPanel) tarafında bekleyen işler (ZMax kodu değil)

Günlük okuyucu ve trafik/kota hesabını ZMax günlüğüne bağlamak (Faz 1 madde 1 bitince) · panel/webmail/Zplus proxy vhost'ları · certbot yenileme ve `reload` · php-fpm kurulumu ve havuz/kullanıcı izolasyonu · OpenLiteSpeed ücretsiz uzantısı · `zmax-gecis.sh` içindeki eski "TLS yok" kapısını güncelleme · güncel paketleri VM'ye dağıtma · `.htaccess`'i vhost TOML kural alanlarına çeviren Go katmanı.
