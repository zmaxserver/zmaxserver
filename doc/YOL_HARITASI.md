# ZMax — Yol Haritası (fazlar, sürümler, kabul ölçütleri)

**Amaç:** sıralı faz/sürüm planı, test politikası, üretim kontrol listesi (dört yapay zeka önerisinin birleşimi; ham öneriler `arsiv/2026-11-12/yapayzeka-onerileri/`). **Güncellenir:** faz/sürüm kapsamı değişince; durum ve görev ayrıntısı burada tutulmaz. **Bağlı:** durum → [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md) · görevler → [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) · mimari → [`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md) · OLS denkliği → [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md)

---

## 1. Değişmez ilkeler

1. **Önce gerçek durum.** Bir crate'te kod bulunması özelliğin çalıştığını göstermez. Her özellik şu etiketlerden biriyle işaretlenir: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` (istek hattına bağlı) → `INTEGRATION TESTED` (gerçek istek akışı) → `PRODUCTION VERIFIED`. Üst etiket, alttakilerin hepsi sağlanınca verilir.
2. **Modül çoğaltma yok.** Önce mevcut 18 crate'te yer aranır. Olmayan crate (`zmax-realip`, `zmax-metrics`, `zmax-log`, `zmax-acme`, `zmax-cli`) var sayılmaz. Yeni crate yalnız mevcut hiçbir crate'e sığmıyorsa ve gerekçesi yazılarak açılır.
3. **Çalışanı bozma.** Tamamlanmış modül yeniden yazılmaz; minimal yama. Hatalı yapılandırma çalışan yapılandırmayı bozmaz (son çalışan yapılandırma + geri alma).
4. **Kanıtsız söz yok.** Derlenmeden "derleniyor", çalıştırılmadan "geçti", ölçülmeden "daha hızlı" denmez. Benchmark sonucu uydurulmaz. Birim test ≠ üretim başarısı. ALPN'de `h2` duyurmak ≠ HTTP/2 sunucusu.
5. **Güvenlik performans uğruna kaldırılmaz.**
6. **Rust korur, Go birleştirir** (bölüm 3). Rust yönetim kararı vermez, Go trafiğe dokunmaz.

---

## 2. Güncel durum

Etiketli durum yalnız [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md) içindedir (burada tekrar edilmez).

## 3. Rust ↔ Go iş bölümü

[`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md) §1 ve §4; panel tarafı işleri [`entegre/goentegre.md`](entegre/goentegre.md) §7.

## 4. Sıralı yol haritası

### Faz 0 — Gerçeği kapat (önce)
Kalan "bilinmiyor"ları koddan kapat (worker respawn, hatta bağlı olmayan kütüphane parçaları) ve her satıra matriste etiket yaz. Görev: [Kart 1, 8](ADIMLI_GELISTIRME_TAKIP.md).

### Faz 1 — Entegrasyon (v1.0.02)
Ayrıntı ve kabul testleri görev kartlarında (tekrar edilmez):
| Madde | Kart |
|---|---|
| Vhost başına günlük (NCSA combined/JSON, gerçek bayt, `X-Request-Id`, döndürme, SIGUSR1) | 1, 2 |
| `error_docs` + vhost WAF istek hattında; HTTP/2 doğrulaması (`h2` crate; bitene kadar ALPN `http/1.1`) | 1 |
| API CRUD tam alan, atomik yazım, geri alma | 3 |
| `.htaccess` kalanları, yönlendirme, regex/döngü sınırı | 4 |
| Hotlink listesi, IP ACL | 5 |
| Panel/API portu ve vhost sertifikası yenileme, ACME ortak kök | 6 |
| Panel tarafı TOML yazımı | 7 |
| VM'de iki vhost ile uçtan uca test | 1 |

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
- Basic Auth: **v1.0.03'e çekildi** (OLS denkliği, [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) C3): panelin yazdığı Apache MD5 `$apr1$` htpasswd dosyalarını doğrulamalı (+ Argon2id), vhost başına.
- Üst akış sağlık denetimi, devre kesici, ağırlıklı dağıtım, WebSocket, DNS çözücü (TTL, negatif önbellek), TLS: OCSP stapling, oturum sürdürme, bilet anahtarı rotasyonu, sıkı SNI, el sıkışma zaman aşımı, sertifika süre izleme.
- Gözlemlenebilirlik: Prometheus (`waf_blocked_total`, önbellek isabet oranı, FastCGI havuz doluluğu, Redis Pub/Sub gecikmesi, TLS el sıkışma gecikmesi, yanıt süresi histogramı), isteğe bağlı OpenTelemetry. Kimlik bilgisi ve oturum çerezi asla günlüğe yazılmaz.
- CLI (`zmax status|reload|logs|purge|config validate|config rollback|tls status`): net çıkış kodları, etkileşimsiz çalışma.

### Faz 5 — Şimdilik YAPMA (çekirdek üretime hazır olana kadar)
HTTP/3-QUIC **buradan çıkarıldı**: panelde `quicEnable` anahtarı var (OLS_DENKLIK A5) → v1.0.10 (OLS denklik kapısı). Burada kalanlar: QPACK, Pagespeed, uygulama süpervizörü, küme/çoklu süreç koordinasyonu, JavaScript bot koruması, tam OWASP CRS uyumu (regresyon paketi çalışmadan "uyumlu" denmez), Windows'a özel yol ayrımı (Linux birincil hedef; `sendfile`/`setuid`/`sched_setaffinity` yalnız Linux'ta derlenir, Windows'ta no-op/alternatif).

---

> **Sahip hedefi (2026-11-12): ZMax OLS ile denk olacak ve hatasız çalışacak.** Denklik için gereken özellikler, panelin gerçek OLS/ZMax üretimine göre [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) içinde satır satır listelidir; ZORUNLU çıkanlar buradaki fazlara çekilmiştir.

## 5. Sürüm sırası (öneri)

| Sürüm | İçerik |
|---|---|
| v1.0.02 | Faz 0 + Faz 1 (günlük, `error_docs`, vhost WAF, HTTP/2 ya da `http/1.1`'e düşürme, API, `.htaccess` kalanları) |
| v1.0.03 | Faz 2 güvenlik: ayrıştırıcı sertleştirme + fuzz, FastCGI havuzu + HTTPoxy, önbellek tutarlılığı, `drop_privileges` izinleri, worker respawn, Basic Auth (`$apr1$`), symlink izni davranışı |
| v1.0.04 | Güvenli yeniden yükleme + sınırlar (bağlantı/bellek/geri basınç) |
| v1.0.05 | Statik performans (`sendfile`, önceden sıkıştırılmış, Zstd, 304) |
| v1.0.06 | Vekil ve FastCGI (sağlık denetimi, dağıtım, akış) |
| v1.0.07 | TLS ve ACME (OCSP, oturum sürdürme, yenileme) |
| v1.0.08 | WAF/DDoS (CRS regresyonu, Detection Only/Blocking, bant sınırı) |
| v1.0.09 | Gözlemlenebilirlik (metrikler, istek kimliği, histogramlar) |
| v1.0.10 | **OLS denklik kapısı** ([`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) §2): HTTP/3-QUIC, OLS ↔ ZMax yan yana test, gerçek uygulamalar, panel işlevleri, 24 saat, yük altında reload, OLS'e geri dönüş. 80/443 varsayılanı yalnız bu kapıdan sonra |
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

## 9. Go (ZPanel) tarafında bekleyen işler

[`entegre/goentegre.md`](entegre/goentegre.md) §7.
