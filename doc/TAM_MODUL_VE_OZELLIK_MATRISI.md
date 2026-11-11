# ZMax — Modül ve Özellik Matrisi (TEK DOĞRULUK KAYNAĞI: durum etiketleri)

**Amaç:** her özellik/crate için gerçek durum etiketi + kanıt. Durum etiketi başka hiçbir belgede tutulmaz; diğer belgeler buraya bağlanır. **Güncellenir:** kod, test ya da VM sonucu değiştiğinde (tarih ve kanıtla). **Bağlı:** [`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md) (mimari) · [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) (görev kartları) · [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) (OLS denkliği)

Etiketler: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` (istek hattına bağlı) → `INTEGRATION TESTED` → `PRODUCTION VERIFIED`; üst etiket alttakilerin hepsini gerektirir. "Bilinmiyor" = doğrulanmadı. Hiçbir satır `PRODUCTION VERIFIED` değildir (80/443 üretim kullanımı yok).

**Test sonucu (rapor, 2026-11-12):** `cargo test --workspace --offline` = **216 geçti / 0 kaldı / 0 atlandı** (18 crate; bu oturumda yeniden çalıştırılmadı). Yerel Windows duman testi `doc/tools/live_smoke.py` (Web 19480 MISS→HIT, WebAdmin vekil yolu, Control API, vHost CRUD + traversal 400) ve `doc/tools/verify_packages.py` (7 paket: zip, 2 tar.gz, 2 deb, 2 rpm) başarılı raporlandı. Kod 00:23–01:00 arasında değişti; VM uçtan uca testi (2026-11-11, test portları 19480/19483) eski ikiliyle yapıldı.

**Crate olarak VAR (18):** `zmax-bin`, `zmax-cache`, `zmax-compress`, `zmax-config`, `zmax-core`, `zmax-fastcgi`, `zmax-header`, `zmax-httpparser`, `zmax-obfuscate`, `zmax-pool`, `zmax-proxy`, `zmax-redis`, `zmax-rewrite`, `zmax-runtime`, `zmax-security`, `zmax-static`, `zmax-timeout`, `zmax-tls`.
**Crate olarak YOK** (işlev varsa başka crate içindedir): `zmax-realip`, `zmax-metrics`, `zmax-log`, `zmax-acme`, `zmax-cli`, `zmax-dns`, `zmax-limits`, `zmax-quic`, `zmax-pagespeed`, `zmax-auth`, `zmax-botshield`, `zmax-appserver`, `zmax-taskrunner`.

---

## 1. Çekirdek sistem ve ağ

| Modül / özellik | Etiket | Kanıt / eksik |
|---|---|---|
| `zmax-runtime`: Tokio worker, SIGTERM/Ctrl+C kapanma, SIGHUP + `/api/v1/reload` sıcak yenileme | UNIT TESTED (7 test; `ShutdownCoordinator`, `SIGUSR2` FD devri yardımcıları kütüphanede) | `zmax-bin` içinde SIGUSR2 devri/reload hatta bağlılığı doğrulanmadı |
| `SO_REUSEPORT` | IMPLEMENTED | `main.rs` ~121-137 isteğe bağlı soket bağlayıcısı (`reuse_port`); worker respawn: bilinmiyor |
| `drop_privileges` (`zmax-core`) | IMPLEMENTED, **INTEGRATED DEĞİL** | `zmax-core/src/lib.rs`'te tanımlı; `main.rs` çağırmıyor |
| `core_affinity` (`pin_current_thread_to_core`), `SIGUSR2` FD devri | IMPLEMENTED (kütüphane) | `zmax-bin` bağlılığı doğrulanmadı |
| `zmax-pool`: `BytesMut` `BufferPool` (2 MiB üstü statik, `Range` 64 KiB akış) | IMPLEMENTED | birim test sayısı bilinmiyor |
| `zmax-pool`: `UpstreamSocketPool` (ters vekil keep-alive) | UNIT TESTED (`zmax-proxy` 3 test) | VM'de sınanmadı |
| FastCGI `FCGI_KEEP_CONN` soket havuzu | Bilinmiyor | belgeler çelişiyor; eski belge `false` ve her istekte yeni soket diyordu |
| `zmax-timeout`: header 10 s / body 30 s / keep-alive 65 s, Slowloris | UNIT TESTED (3 test, Slowloris simülasyonu dahil) | `tools/slowloris_test.ps1` sonucu bilinmiyor |
| Async DNS çözücü (`hickory-resolver`) | PLANNED | crate yok; sistem çözümlemesi kullanılır |
| Bant genişliği kısma / IP başına eşzamanlı bağlantı sınırı | PLANNED | crate yok; hız sınırı yalnız istek/dakika (`zmax-security`) |

## 2. HTTP protokolü ve güvenlik katmanı

| Modül / özellik | Etiket | Kanıt / eksik |
|---|---|---|
| `zmax-httpparser`: HTTP/1.1 (`httparse`), chunked, keep-alive, pipelining, 413/431/408 | UNIT TESTED (17 test; PROXY Protocol v1/v2 ve Request Smuggling reddi kütüphanede) + INTEGRATION TESTED (VM HTTP/1.1) | kütüphanede CL.TE/TE.CL, çift Content-Length, CRLF/NUL reddi testli; fuzz: PLANNED; PROXY Protocol hatta bağlılığı bilinmiyor |
| Gerçek IP (`resolve_real_ip`, `trusted_proxies`: CF-Connecting-IP / X-Forwarded-For / X-Real-IP) | IMPLEMENTED (`zmax-httpparser` içinde) | ayrı `zmax-realip` crate'i yok; entegrasyon testi bilinmiyor |
| `zmax-header`: güvenlik başlıkları (HSTS, CSP, X-Frame-Options, vb.), `Server` gizleme | IMPLEMENTED | CORS kural motoru PLANNED; testi bilinmiyor |
| `zmax-tls`: TLS 1.2/1.3, SNI, vhost sertifikası yeniden yükleme | INTEGRATION TESTED (VM: TLS 1.3, sertifika eşleşti; 11 birim test) | panel/API portu sabit sertifikası reload'da yenilenmiyor (Eksik) |
| `force_https` (ACME `.well-known` muaf) | INTEGRATED | VM'de yeniden sınanmalı |
| ALPN `h2` / HTTP/2 | INTEGRATED (2026-11-12 01:xx, koddan) | `zmax-bin/src/h2_engine.rs` (~280 satır, `h2::server`) var; `main.rs` ~398-422: ALPN `["h2","http/1.1"]` + `zmax_tls::negotiated_alpn` → `h2_engine::handle_h2_connection`. Birim/entegrasyon testi ve VM sınaması yok; WAF/rewrite/cache/günlük uyumu doğrulanmadı |
| OCSP stapling, oturum sürdürme, strict SNI | PLANNED | |
| HTTP/3-QUIC | PLANNED (Faz 5) | `mod_quic.toml` yalnız şablon, crate yok |
| PROXY Protocol v1/v2 | IMPLEMENTED (`zmax-httpparser` + `zmax-config` içinde kod; UNIT TESTED) | `zmax-bin` hattına bağlılığı doğrulanmadı |

## 3. İçerik sunumu ve uygulama motorları

| Modül / özellik | Etiket | Kanıt / eksik |
|---|---|---|
| `zmax-static`: ETag/304, Range, WebP/AVIF müzakeresi (`Vary: Accept`), ACME dosya sunumu | UNIT TESTED (13 test; kütüphanede sidecar `.zst/.br/.gz`, `sendfile`, autoindex, `error_docs` çözümleyici) + INTEGRATION TESTED (VM: statik, ACME http-01) | kütüphanede var; `web_engine.rs` `sendfile` çağırmıyor (grep: 0) → INTEGRATED değil |
| `zmax-fastcgi`: Unix soketi + TCP, PARAMS/STDIN, çoklu `Set-Cookie`, `PATH_INFO` | UNIT TESTED (19 test) + INTEGRATION TESTED (VM: gerçek WordPress sayfası php-fpm, eski ikili) | Windows `php-cgi.exe` TCP eski iddia; Named Pipe yok |
| FastCGI HTTPoxy engeli (`HTTP_PROXY` ortam değişkeni; `zmax-fastcgi/src/lib.rs` ~785, 813), `FCGI_KEEP_CONN` + havuzlu bağlantı (`lib.rs` ~23, 890-918, `execute_php_pooled`), `validate_script_within_root`, `X-Accel-Redirect`/`X-Sendfile` yol temizleme, `UpstreamBalancer` (least_conn) | IMPLEMENTED + UNIT TESTED (kütüphane: `zmax-fastcgi` 19 test, `zmax-pool`) | `zmax-bin` havuzlu çağrıyı kullanmıyor → INTEGRATED değil; streaming `FCGI_STDOUT`: bilinmiyor |
| `zmax-proxy`: ters vekil, WebSocket | UNIT TESTED (12 test) | panel/webmail/Zplus vhost'ları için kullanılmıyor (E6); VM'de sınanmadı |
| `zmax-rewrite`: `try_files`, kök `.htaccess` (`RewriteEngine/Base/Cond/Rule`, `Redirect/RedirectMatch`, `DirectoryIndex`, `ErrorDocument`), `PATH_INFO` | UNIT TESTED (25 test) + INTEGRATED (`htaccess_resolver` `web_engine.rs`'te kullanılıyor — grep) | VM'de WordPress permalink "kısmi" çıkmıştı; güncel ikiliyle yeniden sınanmalı |
| Alt klasör `.htaccess` (mtime önbellekli), `Options -Indexes`, `[E=KEY:VAL]`, `[[vhost.rewrite]]` (deklaratif kural) | UNIT TESTED (`zmax-rewrite` kütüphane) | güncel ikiliyle gerçek WordPress/alt klasör testi yapılmadı |
| `error_docs` (vhost başına hata sayfaları) | UNIT TESTED (kütüphane) | alan `web_engine.rs` istek bağlamına taşındı (~satır 79-81, 264-266); istek mantığında kullanımı doğrulanmadı |
| ASP.NET köprüsü, `zmax-appserver`, `zmax-taskrunner` | PLANNED | crate yok; çalışan backend'e `zmax-proxy` ile vekil yapılabilir |

## 4. Hız ve optimizasyon

| Modül / özellik | Etiket | Kanıt / eksik |
|---|---|---|
| `zmax-cache`: Moka L1, L2 disk, tag purge, SWR, stampede | UNIT TESTED (13 test; LSCache `X-LiteSpeed-*` köprüsü kütüphanede) | entegrasyon testi yok; Redis Pub/Sub ile L1 tutarlılığı doğrulanmadı |
| LSCache başlık köprüsü (`X-LiteSpeed-Cache-Control/Tag/Purge/Vary`) | UNIT TESTED (kütüphane) | hatta bağlılığı ve WordPress eklentisiyle uyumu doğrulanmadı |
| `zmax-compress`: Gzip + Brotli (`brotli` 3.5), `Accept-Encoding` q-ağırlığı (`zstd` yalnız müzakere/sidecar sırası) | UNIT TESTED (7 test) | **Zstd sıkıştırıcı yok** (Cargo'da `zstd` bağımlılığı yok); hatta bağlılığı doğrulanmadı |
| Pagespeed | PLANNED (Faz 5) | |

## 5. Güvenlik ve DDoS

| Modül / özellik | Etiket | Kanıt / eksik |
|---|---|---|
| `zmax-security`: token bucket hız sınırı (429), WP brute-force oto-ban, global WAF (SQLi/XSS/CMDi/traversal), CIDR ACL | UNIT TESTED (14 test) | gerçek istek akışında entegrasyon testi bilinmiyor; tam OWASP CRS uyumu iddia edilmez |
| `hotlink_protection` | INTEGRATED | |
| Vhost WAF (`waf_enabled`, `waf_exclude_paths`; `VHostWafPolicy`) | UNIT TESTED (kütüphane) | alan `web_engine.rs` bağlamına taşındı (~satır 79-81, 264-266); istek mantığında kullanımı doğrulanmadı |
| Basic Auth (`.htpasswd`, Argon2id), bot koruması | PLANNED | crate yok |

## 6. Yönetim, günlük, gözlemlenebilirlik, paketleme

| Modül / özellik | Etiket | Kanıt / eksik |
|---|---|---|
| `zmax-config`: TOML vhost şeması + canlı reload | UNIT TESTED (19 test) | |
| Control API 19486 (`/health`, `/metrics` Prometheus, `/status`, `/logs`, `/ports`, `/cache/purge`, `/reload`, `/config`, `/vhosts`) | IMPLEMENTED | `PUT/POST /vhosts` alan kapsamı eksik (hotlink, allow/deny, rewrite, headers, logging, error_docs, waf) |
| WebAdmin 19485 (Vue 3) | IMPLEMENTED | ACL/Hotlink ekranı PLANNED |
| Küresel `access.log` / `error.log` + `/api/v1/logs` | IMPLEMENTED | `/api/v1/logs?domain=&kind=` ve `POST /api/v1/logs/reopen` `api.rs`'te; çalıştırılıp doğrulanmadı |
| Vhost başına günlük (`VHostLoggingSection`, `logger.rs` ~879 satır `AsyncLogManager`) | INTEGRATED (koddan) | `web_engine.rs:2720` `log_access` çağrılıyor; NCSA combined (`[ts]`, `bytes_sent`, referer, UA) + JSON, vhost başına `access_log`, `also_write_global`, `main.rs:632` SIGUSR1 `reopen_all`. **Doğrulanmadı:** `bytes_sent` gerçek değerinin hesaplanması (varsayılan 0) ve VM'de çalışma |
| ACME | IMPLEMENTED (yalnız sunma) | `.well-known/acme-challenge` sunumu + `force_https` muafiyeti; dahili ACME istemcisi yok (certbot Go tarafında) |
| CLI | IMPLEMENTED (kısmi) | `zmax -v`, `-t/--check`, `-c <yol>` yerleşik; `zmaxctrl` + `zmax.service` paketli; `zmax-cli` crate'i ve `zmax status\|reload\|purge` yok |
| `web_engine.rs.bak` | artık yedek dosya | `crates/zmax-bin/src/` içinde duruyor; kaynak değil, silinmedi |
| `zmax-redis` (RESP2, AUTH/SELECT, `ClusterSyncEvent`) | UNIT TESTED (6 test) | `zmax-bin`'e bağlılığı kanıtlanmadı |
| `zmax-obfuscate` | UNIT TESTED | derleme anı dize şifreleme ([`sifleme.md`](sifleme.md)) |
| `zmax-bin` testleri | UNIT TESTED (31 test geçti, rapor) | `logger::tests::*` (NCSA, döndürme, JSON), `tests::wordpress_htaccess_permalink_and_fastcgi_headers`, `tests::panel_admin_proxy_prefix_and_tls_validation` adlı testler raporda var |
| Paketleme: `.deb`, `.rpm`, `.tar.gz`, `.zip` | IMPLEMENTED (betikler `tools/`) | kurulum/yükseltme/geri dönüş testi sonucu bilinmiyor; bkz. [`tools/README.md`](tools/README.md) |
| Canlı Linux VM uçtan uca (2026-11-11, eski ikili) | INTEGRATION TESTED (kısmi) | geçti: statik, PHP/WordPress sayfası, TLS 1.3, HTTP/1.1, ACME dosyası; kısmi: `.htaccess`; geçmedi: vhost günlüğü (o tarihte yoktu); HTTP/2 yoktu. Sonraki kod değişiklikleri (00:23–01:00) bu testten sonra: yeniden sınanmalı |
| 24 saat dayanıklılık, benchmark, güvenlik denetimi | PLANNED | çalıştırılmadı; sonuç uydurulmaz |

## 7. Panel tarafı (Go) bağımlılıkları

Bu matris yalnız ZMax (Rust) içindir. Go panelin ZMax'e bağlanan eksikleri: [`goentegre.md`](entegre/goentegre.md) §7.

## 8. Crate envanteri (18; test sayıları: `#[test]` grep + 216 geçti raporu)

Etiket sözlüğü: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` → `INTEGRATION TESTED` → `PRODUCTION VERIFIED`. "Hatta bağlı" sütunu `zmax-bin` içinde grep ile bakıldı (çalıştırılmadı).

| Crate | `#[test]` | Etiket | Yetenekler (kütüphane düzeyi) | `zmax-bin` hattına bağlı mı |
|---|---|---|---|---|
| `zmax-config` | 19 | UNIT TESTED | TOML/JSON şeması: `ServerGlobalConfig`, `ListenersConfig`, `LoggingConfig`, `VHostLoggingSection`, `VHostErrorDocsSection`, `VHostTlsSection`, `VHostStaticSection`, `VHostSecuritySection` (`waf_enabled`, `waf_exclude_paths`, `wp_brute_force`), `VHostRewriteRule`, `VHostPhpSection` (`upstreams`, `lb_policy`, `keep_conn`…), port çakışma denetimi | evet (yapılandırma) |
| `zmax-core` | 6 | UNIT TESTED | CLF/ISO zaman damgası formatlayıcı, `available_cpu_cores`, `pin_current_thread_to_core`, `drop_privileges` | `drop_privileges`: `main.rs` çağırmıyor (grep 0) |
| `zmax-runtime` | 6 | UNIT TESTED | `ShutdownCoordinator`, `RuntimeSignal` (Reload, ReopenLogs, UpgradeBinary, Shutdown), `SIGUSR2` FD devri yardımcıları | kısmen; `SIGUSR2` devri bağlılığı doğrulanmadı |
| `zmax-redis` | 6 | UNIT TESTED | RESP2, `AUTH`/`SELECT`/`PING`, `ClusterSyncEvent` (BanIp, UnbanIp, PurgeDomain, PurgeTag, PurgeAll, ReloadConfig) | doğrulanmadı |
| `zmax-timeout` | 3 | UNIT TESTED | header 10 s / body 30 s / keep-alive 65 s, Slowloris simülasyonu | evet |
| `zmax-tls` | 11 | UNIT TESTED; VM'de INTEGRATION TESTED (TLS 1.3, SNI) | rustls 0.23, `SniResolver` (sıcak sertifika değişimi), ALPN `["h2","http/1.1"]` | evet |
| `zmax-httpparser` | 17 | UNIT TESTED | `httparse` akış ayrıştırıcı, PROXY Protocol v1/v2, Request Smuggling reddi (CL.TE/TE.CL, çift Content-Length, CRLF/NUL), gerçek IP | evet; PROXY Protocol bağlılığı doğrulanmadı |
| `zmax-pool` | 7 | UNIT TESTED | `BufferPool`, `UpstreamSocketPool`, `UpstreamBalancer` (RoundRobin/LeastConn, pasif sağlık) | proxy evet; balancer bağlılığı doğrulanmadı |
| `zmax-fastcgi` | 19 | UNIT TESTED; VM'de INTEGRATION TESTED (eski ikili: WordPress sayfası) | PHP-FPM protokolü, HTTPoxy engeli, `execute_php_pooled` (`FCGI_KEEP_CONN`), `validate_script_within_root`, `X-Accel-Redirect`/`X-Sendfile` temizleme, `FCGI_STDERR` | **havuzlu çağrı kullanılmıyor** (grep 0) |
| `zmax-compress` | 7 | UNIT TESTED | Gzip + Brotli, `Accept-Encoding` q-ağırlığı, sidecar uzantı sırası | doğrulanmadı |
| `zmax-static` | 13 | UNIT TESTED; VM'de INTEGRATION TESTED (statik, ACME) | ETag/304, Range, WebP/AVIF, sidecar `.zst/.br/.gz`, `error_docs` çözümleyici, güvenli autoindex, Linux `sendfile(2)` | **`sendfile` çağrılmıyor** (grep 0) |
| `zmax-rewrite` | 25 | UNIT TESTED | `try_files`, alt-dizin `.htaccess` + `mtime` önbelleği, `RewriteCond/Rule` bayrakları (`L,R,QSA,NC,F,G,E`), `Options`, `ErrorDocument`, `[[vhost.rewrite]]` deklaratif | evet (`htaccess_resolver`); VM'de permalink "kısmi" çıkmıştı (eski ikili) |
| `zmax-cache` | 13 | UNIT TESTED | Moka L1 + L2 disk, SWR, stampede, tag purge, LSCache başlık köprüsü (`X-LiteSpeed-*`) | doğrulanmadı |
| `zmax-security` | 14 | UNIT TESTED | token bucket, wp-login oto-ban, genel WAF, `VHostWafPolicy` (`waf_enabled`, `waf_exclude_paths`), `generate_request_id` | `web_engine.rs`'te `waf_policy` referansı var (grep) |
| `zmax-proxy` | 12 | UNIT TESTED | ters vekil, keep-alive, WebSocket, `Host` koruma | evet; panel/webmail için kullanılmıyor |
| `zmax-header` | 4 | UNIT TESTED | güvenlik başlıkları (HSTS, CSP, X-Frame-Options, …) | evet |
| `zmax-obfuscate` | 3 | UNIT TESTED | derleme anı polimorfik dize şifreleme ([`sifleme.md`](sifleme.md)) | — |
| `zmax-bin` | 31 | IMPLEMENTED (entegrasyon sürüyor) | dinleyiciler, Control API (`api.rs`), `logger.rs` (AsyncLogManager, vhost günlüğü), `h2_engine.rs`, `web_engine.rs` | — |


Önceki ayrı `tamproje.md` raporlarının benzersiz bilgisi (216 test sonucu, duman/paket doğrulama çıktıları, kanıt test adları) bu belgenin başına ve §6'ya alındı; orijinalleri `arsiv/2026-11-12/birlesen/` altında.
