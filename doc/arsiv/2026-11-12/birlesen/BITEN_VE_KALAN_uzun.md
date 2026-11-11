# ZMax Server — Biten ve Kalan (2026-11-12, ~01:30)

**Nasıl hazırlandı:** Kaynak kod `D:\zmaxserver\crates` okundu (grep), VM testi (2026-11-11) ve panel (Go) oturumlarının raporları esas alındı. **Hiçbir şey çalıştırılıp denenmedi**: bu belge yazılırken `cargo` derlemesi çalışıyordu, sonucu bilinmiyor. Etiketler: `IMPLEMENTED` (kod var) → `UNIT TESTED` → `INTEGRATED` (istek hattına bağlı) → `INTEGRATION TESTED` → `PRODUCTION VERIFIED`. Hiçbir madde `PRODUCTION VERIFIED` değildir. Ayrıntı: [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md), plan: [`YOL_HARITASI.md`](YOL_HARITASI.md), takip: [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md).

---

## 1. BİTEN

### 1.1 ZMax (Rust) — istek hattına bağlı, VM'de ya da kodda görüldü
| Özellik | Etiket | Kanıt |
|---|---|---|
| TLS 1.2/1.3, SNI, vhost sertifikasını yeniden yükleme | INTEGRATION TESTED (VM test portu) | VM: TLS 1.3, sertifika eşleşti; `zmax-tls` 11 test |
| Statik dosya, ACME http-01 dosya sunumu | INTEGRATION TESTED (VM) | statik 200, `.well-known` 200 |
| PHP (FastCGI, php-fpm havuzu) | INTEGRATION TESTED (VM) | gerçek WordPress sayfası döndü |
| `force_https` (ACME muaf), `hotlink_protection` | INTEGRATED | `web_engine.rs` ~satır 490 / ~852 |
| `.htaccess` kökten: `RewriteEngine/Base/Cond/Rule`, `Redirect/RedirectMatch`, `DirectoryIndex`, `ErrorDocument` | INTEGRATED | `zmax-rewrite/src/htaccess.rs` (25 test); VM'de "kısmi" çıkmıştı, yeniden sınanmalı |
| HTTP/2 | INTEGRATED, **test yok** | `h2_engine.rs` (280 satır), `main.rs` ALPN → `h2_engine` yönlendirmesi |
| Vhost başına günlük (NCSA combined + JSON, vhost dosyası, `also_write_global`, SIGUSR1 yeniden açma) | INTEGRATED, **çalıştırılmadı** | `logger.rs` (879 satır), `web_engine.rs` `log_access`; `bytes_sent` artık iletiliyor, doğruluğu denenmedi |
| Vhost `error_docs` (özel hata sayfası) | INTEGRATED, **çalıştırılmadı** | `web_engine.rs` ~2625, ~2890 |
| Vhost WAF değeri (`waf_enabled`) | INTEGRATED, **çalıştırılmadı** | `web_engine.rs` ~440 (istek bağlamına geçiyor) |
| `SO_REUSEPORT` soket bağlayıcı | IMPLEMENTED | `main.rs` ~121–137 |
| Control API 19486 (`/health /metrics /status /logs /ports /cache/purge /reload /config /vhosts`) | IMPLEMENTED | `api.rs`; vhost günlük yolu yazıyor |
| Paketleme `.deb`, `.rpm`, `.tar.gz`, `.zip` | IMPLEMENTED | `D:\zmaxserver\packed`, `tools/` |
| Birim testleri | 217 `#[test]` (grep) | `zmax-bin` 31, `zmax-rewrite` 25, `zmax-config` 19, `zmax-fastcgi` 19, `zmax-httpparser` 17 … hepsi **çalıştırılmadı** |

### 1.2 Panel (Go, ZPanel) ZMax ile ilgili biten
- Web sunucusu seçimi `/etc/zpanel/webserver` (`zmax` | `openlitespeed`, dosya yoksa `zmax`); `zmax-gecis.sh` ile kapılı geçiş; ZMax 80/443'e **çevrilmiyor** (OpenLiteSpeed varsayılan kalıyor).
- Ajan: vhost TOML üretimi + `reload`, `zmax.syncSites/verifySites`, PHP işleyici listesi etkin web sunucusuna göre, php-fpm kurulum betiği (`php-fpm-kur.sh`).
- Hepsi **sunucuda tam denenmedi**; yalnızca VM'de ZMax test portlarında (19480/19483) uçtan uca test yapıldı.

### 1.3 Belgeler (bu oturum)
- Plan ve durum belgeleri koddan doğrulanarak yeniden yazıldı: `MIMARI_VE_PLAN.md`, `ADIMLI_GELISTIRME_TAKIP.md`, `TAM_MODUL_VE_OZELLIK_MATRISI.md`, `YOL_HARITASI.md`, `entegre\goentegre.md`, `karsilastirma\`, `tools\README.md`, `YAPAY_ZEKA_KURALLARI.md`. Eskiler silinmeden `arsiv\2026-11-12\` altına taşındı.

---

## 2. KALAN

### 2.1 ZMax (Rust)

**A. Hemen — doğrulama (her şeyin önkoşulu)**
- [x] `cargo test --workspace` (2026-11-12, çalıştırıldı): **216 geçti, 0 kaldı, 0 atlandı** (35 sonuç satırı, çıkış 0). Bu birim/crate testleridir; entegrasyon kanıtı değildir.
- [ ] Faz 1 maddelerini çalıştırarak doğrula (şu an yalnız "kodda var"): iki vhost → ayrı günlük dosyası, satırda tarih ve **gerçek bayt**; `error_docs` 404/403; vhost WAF açık/kapalı; `curl --http2` ve HTTP/1.1; `.htaccess` WordPress permalink; hepsi VM'de.
- [ ] İstek hattı entegrasyon testi: `zmax-bin` toplam 31 test (`logger.rs` 3, `web_engine.rs` 0, `h2_engine.rs` 0; geri kalanı `main.rs`/`api.rs`/`modules_runtime.rs`). Günlük, `error_docs`, vhost WAF ve HTTP/2 için gerçek istek testi yok (kütüphane testleri bunu kanıtlamaz).

**B. Kütüphanede var, hatta BAĞLANDI (2026-11-12)**
- [x] `execute_php_pooled` — FastCGI `FCGI_KEEP_CONN` soket havuzu `web_engine.rs:1612` içine bağlandı (`FastCgiClient::with_pool` ve `state.upstream_pool`).
- [x] `drop_privileges` — yetki düşürme (`zmax-core`) `main.rs:607` içine dinleyiciler bağlandıktan sonra çalışacak şekilde bağlandı.
- [x] `cpu_affinity` — çekirdek sabitleme `main.rs:603` içine bağlandı (`zmax_core::pin_current_thread_to_core`).
- [ ] `sendfile(2)` — `zmax-static` içinde var; büyük dosyalarda tamponlu akış `stream_file_range_pooled` devrede, saf sendfile entegrasyonu Linux ortamında ölçülecek.
- [x] HTTPoxy filtresi — `FastCgiParamsBuilder` ve `FastCgiRequest` içinde `HTTP_PROXY` başlığı süzülerek engellendi.

**C. Entegrasyon eksikleri**
- [ ] `PUT/POST /api/v1/vhosts` alan kapsamı: `hotlink_protection`, `allow_ips/deny_ips`, `rewrite`, `headers`, `error_docs`, `waf` girişini yazdığı doğrulanmadı.
- [ ] `.htaccess` kalanları: alt klasör `.htaccess`, `Options`, `[E=HTTP_AUTHORIZATION]`, `[[vhost.rewrite]]` TOML kural dizisi, yönlendirme döngüsü/regex sınırı.
- [ ] Panel/API portundaki sabit sertifikanın yeniden yüklenmesi (`build_single_cert_acceptor`).
- [ ] Worker çökerse yeniden başlatma (respawn): bilinmiyor.

**D. Üretim güvenliği (Faz 2)**
- [ ] Ayrıştırıcı sertleştirme: CL.TE/TE.CL, kopya `Content-Length`, başlık/CRLF enjeksiyonu, HTTP/2 akış/HPACK sınırları; `cargo-fuzz`.
- [ ] Önbellek: anahtara `Host`, Redis `PurgeDomain/Tag` ile L1 (Moka) temizliği, dağıtık kilit.
- [ ] Güvenli yeniden yükleme + geri alma, bağlantı/bellek/geri basınç sınırları, sıfır kesinti yükseltme (`SIGUSR2`).
- [ ] `drop_privileges` öncesi günlük/önbellek/tmp izinleri.

**E. Performans ve ürünleşme (Faz 3–4)**
- [ ] Ölçüm: Nginx / OpenLiteSpeed / Caddy ile aynı donanımda benchmark (hiç yapılmadı, hız iddiası yok).
- [ ] Brotli/Zstd yan dosya, ETag/304 optimizasyonu, LSCache başlık köprüsü (`X-LiteSpeed-*`).
- [ ] TLS: OCSP stapling, oturum sürdürme, ticket rotasyonu, sıkı SNI; PROXY Protocol entegrasyonu.
- [ ] **Basic Auth: v1.0.03'e çekildi** (`OLS_DENKLIK` C3, ZORUNLU). Panel Apache MD5 `$apr1$` biçiminde `.htpasswd` yazıyor (`domainsec/apply_auth.go`); yalnız Argon2id yetmez, `$apr1$` doğrulaması şart.
- [ ] Prometheus iş metrikleri, istek kimliği, CLI (`zmax status|reload|…`).
- [ ] Gerçek uygulama uyumu: WordPress, Laravel, OpenCart, Drupal, Joomla.
- [ ] 24 saat dayanıklılık, yük altında reload, güvenlik denetimi, yükseltme/geri dönüş testi.

**F. Şimdilik yapılmayacak (Faz 5)** — Pagespeed, uygulama süpervizörü, küme, JS bot koruması, tam OWASP CRS iddiası. **HTTP/3-QUIC artık Faz 5'te DEĞİL:** panelde `quicEnable` anahtarı var (`webserver/settings.go`), `OLS_DENKLIK` A5'te ZORUNLU, `YOL_HARITASI` v1.0.10 kapısına çekildi (QPACK onunla birlikte). **Sahip kararı:** ZMax OpenLiteSpeed ile denk olacak; zorunlu satırlar [`karsilastirma\OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md)'dedir.

### 2.2 Panel (Go) tarafı — ZMax'i varsayılan yapmadan önce
- [ ] **EN KRİTİK — panelin ZMax sürücüsü eksik yazıyor.** `sites/zmax.go` `RenderZmaxVhost` bugün ZMax TOML'una yalnız vhost, cache (kapalı), php, ssl, `force_https` ve `hotlink=false` yazıyor. **Yazılmayanlar:** vhost günlüğü (`[vhost.logging]`), `error_docs`, hotlink izinli liste, IP ACL, parola koruması, WAF (`waf_enabled`, `waf_exclude_paths`), proxy. Rust'ta kodun olması yetmez; panel TOML'a yazmazsa özellik çalışmaz.
- [ ] Panel ekranları ZMax'e bağlanmalı ya da ZMax seçiliyken devre dışı gösterilmeli: `webserver/settings.go` (HTTP/3, gzip, gövde sınırı) ve `performance.go` (LSCache profili).
- [ ] **E6** Panel/webmail/Zplus ters vekil vhost'ları (80/443'e geçişte karşılıksız kalıyor).
- [ ] **E8** certbot yenileme ZMax webroot ile ve yenileme sonrası `reload`; gerçek certbot denemesi yapılmadı.
- [ ] **E9** Installer'a php-fpm havuzu/kiracı hesabı/soket kurulumu (`cekirdek/installer` bugün kurmuyor).
- [ ] **E10** `openlitespeed` ücretsiz uzantı paketi (`uzantilar/ücretsiz` içinde yok).
- [ ] **E11** Günlük okuyucu, disk/trafik/kota hesabını ZMax günlüğüne bağlama (OpenLiteSpeed günlüğüne bağlı).
- [ ] **E14** `zmax-gecis.sh` içindeki eski "ZMax'te TLS yok" kapısını güncelleme; OLS'e tek komutla dönüş; güncel paketleri VM'ye dağıtma.
- [ ] `.htaccess`'i vhost TOML kural alanlarına çeviren Go katmanı.
- [ ] Panel "dışarıya aç" ve ZMax günlük/istatistik ekranları ZMax kaynağına göre.

### 2.3 Belgeler (devam eden)
- [x] `karsilastirma\OLS_DENKLIK.md`: OLS ↔ ZMax denklik matrisi ve kabul kapısı yazıldı (`zmax-doc-duzen`).
- [x] `YOL_HARITASI.md` ve takip belgesine "OLS denklik kapısı" (v1.0.10) eklendi.
- [x] `doc\README.md` belge haritası güncellendi (`BITEN_VE_KALAN.md` dahil).

---

## 3. ZMax'i 80/443'te varsayılan yapma kapısı (hepsi şart)
1. Alan adı günlüğü çalışıyor; panelin Günlükler, istatistik ve trafik rakamları ZMax günlüğünden doğru.
2. WordPress/Laravel permalink ve `.htaccess` gerçek sitelerde geçiyor.
3. `error_docs` ve vhost WAF çalışıyor.
4. HTTP/2 doğrulanmış (`curl --http2`; OLS ALPN `h2`'yi varsayılan sunar, bu yüzden ZORUNLU).
5. Panel/webmail/Zplus adresleri ZMax üzerinden açılıyor (E6).
6. Sertifika yenileme ve certbot ZMax ile gerçek denendi.
7. 24 saat dayanıklılık, **yük altında reload** ve OLS'e tek komutla geri dönüş denenmiş.
8. **OLS ↔ ZMax yan yana test:** aynı site iki sunucuda, durum kodu, başlıklar ve gövde karşılaştırması.
9. **5 gerçek uygulama:** WordPress, Laravel, OpenCart, Drupal, Joomla.
10. **HTTP/3** çalışıyor (ya da panelde `quicEnable` anahtarı ZMax seçiliyken gizli).
11. **Panel işlevleri ZMax'te çalışıyor:** hotlink, yönlendirme, parola korumalı dizin, IP engeli, ModSecurity/WAF, Node + WebSocket, webmail, phpMyAdmin, PHP sürüm/INI, günlük, trafik, `error_docs`, çöp kutusu, SSL yenileme.
12. **Panelin ZMax sürücüsü** yukarıdaki ayarları TOML'a yazıyor (bölüm 2.2 ilk madde).
13. [`karsilastirma\OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) içindeki tüm ZORUNLU satırlar INTEGRATION TESTED.

Bunlar tamamlanmadan 80/443 ZMax'e çevrilmez; OpenLiteSpeed varsayılan kalır.
