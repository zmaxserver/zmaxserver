# ZMax Server — Crate Envanteri ve Kod Durumu (2026-11-12)

Bu belge yalnız **crate başına envanter ve test sayısı** içindir. Tekrar eden bölümler kaldırıldı (orijinal `arsiv/2026-11-12/tamproje.md`): mimari/rol paylaşımı → [`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md); portlar ve panel kapsamı → [`goentegre.md`](goentegre.md); derleme/paketleme → [`tools/derleme.md`](tools/derleme.md); özellik durumu → [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md).
**Doğrulama notu:** `#[test]` sayıları `grep` ile sayıldı; `cargo test` bu oturumda **çalıştırılmadı**. Önceki sürüm "179 test %100 geçti" diyordu (zmax-bin hariç); çalıştırılmış çıktı olmadan bu iddia `UNIT TESTED` kanıtı sayılmaz. `zmax-bin` entegrasyonu (`logger.rs`, `h2_engine.rs`, `web_engine.rs`, `api.rs`, `main.rs`) başka bir oturumda sürüyor ("Wave 2").

## 1. Crate envanteri (18)

Etiket sözlüğü: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` → `INTEGRATION TESTED` → `PRODUCTION VERIFIED`. "Hatta bağlı" sütunu `zmax-bin` içinde grep ile bakıldı (çalıştırılmadı).

| Crate | `#[test]` | Etiket | Yetenekler (kütüphane düzeyi) | `zmax-bin` hattına bağlı mı |
|---|---|---|---|---|
| `zmax-config` | 19 | UNIT TESTED | TOML/JSON şeması: `ServerGlobalConfig`, `ListenersConfig`, `LoggingConfig`, `VHostLoggingSection`, `VHostErrorDocsSection`, `VHostTlsSection`, `VHostStaticSection`, `VHostSecuritySection` (`waf_enabled`, `waf_exclude_paths`, `wp_brute_force`), `VHostRewriteRule`, `VHostPhpSection` (`upstreams`, `lb_policy`, `keep_conn`…), port çakışma denetimi | evet (yapılandırma) |
| `zmax-core` | 6 | UNIT TESTED | CLF/ISO zaman damgası formatlayıcı, `available_cpu_cores`, `pin_current_thread_to_core`, `drop_privileges` | `drop_privileges`: `main.rs` çağırmıyor (grep 0) |
| `zmax-runtime` | 7 | UNIT TESTED | `ShutdownCoordinator`, `RuntimeSignal` (Reload, ReopenLogs, UpgradeBinary, Shutdown), `SIGUSR2` FD devri yardımcıları | kısmen; `SIGUSR2` devri bağlılığı doğrulanmadı |
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

## 2. Eski "8 maddelik eksik listesi" — gerçek durum

Kaynak: önceki `tamproje.md` §5; durumlar grep ile yeniden etiketlendi. Hiçbiri `INTEGRATION TESTED` değildir (iki vhost / `curl --http2` ile çalıştırılmadı).

| # | Madde | Etiket | Kanıt / kalan iş |
|---|---|---|---|
| 1 | Alan adına özel access/error günlüğü | IMPLEMENTED | `VHostLoggingSection` + `logger.rs`; `log_access` `main.rs`/`web_engine.rs`/`h2_engine.rs`'te çağrılıyor (grep). Kalan: iki canlı vhost'ta ayrı dosya + tarih + gerçek bayt kanıtı |
| 2 | Özel hata sayfaları (`error_docs`) | UNIT TESTED (kütüphane) | `resolve_error_doc_page` referansı `web_engine.rs`'te var (grep). Kalan: gerçek 404'te vhost sayfası + `.htaccess ErrorDocument` ortak yol |
| 3 | Alan adına özel WAF | UNIT TESTED (kütüphane) | `waf_policy` `web_engine.rs`'te (grep). Kalan: `waf_enabled=false` vs `true` gerçek istek testi |
| 4 | HTTP/2 | IMPLEMENTED | `h2_engine.rs` + `main.rs` ALPN yönlendirmesi (grep). Kalan: `curl --http2 -I` → `HTTP/2 200`, çok akış, WAF/rewrite/cache/FastCGI/log uyumu; kanıtlanana kadar ALPN `h2` duyurusu risklidir |
| 5 | REST API CRUD alan kapsamı | IMPLEMENTED | `api.rs` `format_vhost_json` ve `PUT/POST` tüm alanları kapsıyor iddiası; çalıştırılıp doğrulanmadı |
| 6 | `.htaccess` ve yönlendirme | UNIT TESTED (25 test) | `htaccess_resolver` hatta bağlı (grep). Kalan: güncel ikiliyle gerçek WordPress/alt klasör testi |
| 7 | Panel/API portu sertifika yenileme | IMPLEMENTED | `admin_tls`/`api_tls` `SniResolver`, `main.rs`; yenilemenin sunulduğu doğrulanmadı |
| 8 | Testler | UNIT TESTED | alt crate'lerde 186 `#[test]` (grep), `zmax-bin`'de 31; `cargo test --workspace` çıktısı bu oturumda alınmadı |

## 3. Panel (Go) / Linux VM kapsamı

ZMax kodu dışındaki işler (E6 panel/webmail vekil vhost'ları, E8 certbot, E9 php-fpm kurulumu, E10 OLS uzantısı, E11 trafik/kota, E14 `zmax-gecis.sh`) ve HTTP/3 (planlı, `quinn` bağımlılığı yok): [`goentegre.md`](goentegre.md) §7 ve [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md).

## 4. Sonraki adım

1. `cargo test --workspace` gerçekten çalıştırılıp çıktısı bu tabloya yazılacak.
2. Wave 2 entegrasyonu bitince sıra: [`YOL_HARITASI.md`](YOL_HARITASI.md) Faz 1 kabul testleri (VM'de iki vhost).
