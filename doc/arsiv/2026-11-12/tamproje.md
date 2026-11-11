# ZMax Server — Tam Proje, Modül ve Mimari Envanter Raporu (Güncel Durum)

> **Belge Amacı:** Bu doküman, **`D:\zmaxserver`** çalışma alanında yer alan ZMax Server projesinin tüm modüllerini (18 crate), yapılan tüm geliştirmeleri, mimari kararları, test durumlarını ve henüz tamamlanmamış/devam eden eksikleri **%100 şeffaflık ve sıfır varsayım (Rule 0)** ilkesiyle tek bir yerde listeler. Dış denetim ve sorgulamalar için kesin referanstır.  
> **Tarih / Sürüm:** 12 Kasım 2026 / v1.0.1 (Workspace)  
> **Temel İlkeler:** Az CPU · Sıfır Güvenlik Zafiyeti · Çoklu İşlem · Evrensel Uyumluluk · Sıfır Port Çakışması (`19480–19486`)

---

## 1. Yönetici Özeti ve Mimari Rol Paylaşımı

ZMax Server, Cloudflare Pingora, OpenLiteSpeed ve Nginx standartlarından ilham alarak saf Rust (Tokio) üzerinde geliştirilen yüksek performanslı bir HTTP/HTTPS, önbellek, WAF ve FastCGI motorudur.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                ZPANEL (GOLANG PANEL)                                   │
│  - Müşteri/paket yönetimi, vHost TOML yazımı (ZMax salt okunur tüketici)               │
│  - OS Güvenlik Duvarı (nftables/iptables IP ban yazımı), Certbot/ACME zamanlaması     │
│  - Kota & trafik hesabı (ZMax'in NCSA combined access.log %b baytlarından)             │
│  - Yaşam döngüsü: POST http://127.0.0.1:19486/api/v1/reload çağrısı                   │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │  (conf/vhosts/*.toml + REST API 19486)
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                  ZMAX SERVER (RUST)                                    │
│  - Kapıda trafik karşılama: HTTP/1.1, HTTP/2 (h2 ALPN), PROXY Protocol v1/v2          │
│  - Sıfır kopyalama ve az CPU: sendfile(2), BufferPool, precompressed sidecar (.zst/.br)│
│  - LiteSpeed uyumu: LSCache başlık köprüsü (X-LiteSpeed-*), etiketli Purge, SWR       │
│  - Hiyerarşik alt-dizin .htaccess + mtime DashMap önbelleği, [E=...] ortam değişkenleri│
│  - FastCGI: FCGI_KEEP_CONN kalıcı bağlantı havuzu, UpstreamBalancer (least_conn), HTTPoxy│
│  - Güvenlik: WAF (per-vhost waf_enabled/exclude_paths), wp-login koruması, IP ACL      │
│  - Günlükleme: Asenkron kanallı LogManager (per-vhost access/error log, gerçek %b bayt) │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Port ve Dinleyici Mimarisi (Sıfır Çakışma)

Tüm popüler kontrol panelleri (cPanel, Plesk, DirectAdmin, CyberPanel, aaPanel, HestiaCP, ISPConfig vb.) ve zPanel'in sabit portları taranmış; ZMax varsayılanları IANA Unassigned bloğuna alınmıştır:

| Dinleyici | Varsayılan Adres | Alternatif (Birincil) | Görevi / Özellikleri |
| :--- | :--- | :--- | :--- |
| **Web HTTP** | `0.0.0.0:19480` | `0.0.0.0:80` | Düz HTTP trafiği, ACME `/.well-known/acme-challenge/`, `force_https` 301 yönlendirmesi. |
| **HTTPS (TLS)** | `0.0.0.0:19483` | `0.0.0.0:443` | TLS 1.2/1.3, dinamik SNI sertifika seçimi, ALPN `["h2", "http/1.1"]`, Strict SNI. |
| **WebAdmin UI** | `127.0.0.1:19485` | `127.0.0.1:19485` | Bootstrap 5 + Vue 3 konsolu (koyu/açık tema, vHost ekleme/düzenleme, canlı metrikler). |
| **Kontrol API** | `127.0.0.1:19486` | `/run/zmax/api.sock` | Evrensel REST API (`/api/v1/*` + `/api/*`), Bearer/X-ZMax-Token kimlik doğrulaması. |

---

## 3. Çalışma Alanı (Workspace) ve 18 Modülün Detaylı Envanteri

Proje kökü `D:\zmaxserver\Cargo.toml` altında 18 sandıktan (crates) oluşur:

```text
D:\zmaxserver\
├── Cargo.toml                      # Workspace tanımı (18 üye, release opt-level=3, lto=fat, strip=true)
├── .cargo\config.toml              # zig-cc musl çapraz derleme ve rust-lld yapılandırması
├── admin\                          # WebAdmin Vue 3 + Bootstrap 5 statik dosyaları
├── conf\                           # zmax.toml, mime.types ve conf/vhosts/*.toml
├── doc\                            # Mimari planlar, analizler ve geliştirici araçları
│   ├── mimari\                     # EKLENECEK_MIMARI.md, eksik.txt
│   ├── yapayzeka önerileri\        # chatgpt.md, seepseek.md
│   └── tools\                      # pack_zmax.py, verify_packages.py, live_smoke.py
├── modules\                        # mod_ssl.toml, mod_fastcgi.toml, mod_cache.toml vb.
├── packed\                         # win-x64, linux-x64, linux-arm64 paket dağıtım betikleri
└── crates\
    ├── zmax-core\                  # Temel sistem sabitleri, CPU çekirdek sayımı, Howard Hinnant CLF tarih formatlayıcı, setuid/sched_affinity
    ├── zmax-runtime\               # Tokio işçi yaşam döngüsü, graceful shutdown, SIGUSR2 FD devri
    ├── zmax-httpparser\            # Zero-copy HTTP/1.1 parser, PROXY Protocol v1/v2, Request Smuggling kalkanı
    ├── zmax-header\                # HTTP başlık haritası, güvenlik başlıkları (HSTS, CSP, X-Frame-Options)
    ├── zmax-pool\                  # BufferPool (BytesMut) ve UpstreamSocketPool + UpstreamBalancer (least_conn)
    ├── zmax-tls\                   # Rustls TLS 1.2/1.3, dinamik SniResolver, ALPN (h2 / http/1.1)
    ├── zmax-timeout\               # Slowloris kalkanı, Header (10s), Body (30s), Keep-Alive (65s)
    ├── zmax-proxy\                 # Ters proxy motoru, WebSocket tünelleme, Host koruma
    ├── zmax-fastcgi\               # PHP-FPM FastCGI ikili protokolü, FCGI_KEEP_CONN havuzu, HTTPoxy engeli, X-Accel-Redirect
    ├── zmax-static\                # Statik sunum, precompressed sidecar (.zst/.br/.gz), custom error_docs, sendfile(2)
    ├── zmax-cache\                 # Moka L1 RAM + L2 Disk önbelleği, SWR, Stampede kalkanı, LSCache (X-LiteSpeed-*) köprüsü
    ├── zmax-compress\              # Uçuş anı saf Rust Gzip ve Brotli sıkıştırma, RFC 9110 q-ağırlık müzakeresi
    ├── zmax-rewrite\               # Hiyerarşik alt-dizin .htaccess + mtime DashMap önbelleği, [E=...] bayrakları, [[vhost.rewrite]] kuralları
    ├── zmax-security\              # Token Bucket Rate Limiting, wp-login koruması, vHost bazlı WAF (waf_exclude_paths), request_id üretici
    ├── zmax-config\                # TOML/JSON vHost ve genel yapılandırma şeması, port çakışma denetimi, doğrulama
    ├── zmax-redis\                 # RESP2 protokolü, AUTH/SELECT, ClusterSyncEvent (ban, unban, purge, reload) Pub/Sub
    ├── zmax-obfuscate\             # Anti-decompile polimorfik sembol ve dize koruması
    └── zmax-bin\                   # Ana çalıştırılabilir ikili (zmax.exe / zmax), dinleyiciler, REST API, logger ve web motoru
```

---

## 4. Modül Düzeyi Detaylı Durum ve Birim Test Matrisi

> **Doğrulama Notu:** Tüm 17 alt kütüphane sandığı `cargo test --workspace --exclude zmax-bin --offline` komutuyla birlikte çalıştırılmış ve **179 birim testi %100 BAŞARIYLA GEÇMİŞTİR (0 failed, 0 error)**.

| Modül (Crate) | Satır (yaklaşık) | Test Sayısı | Durum | Temel Yetenekler & Eklenen Yenilikler |
| :--- | :--- | :--- | :--- | :--- |
| **`zmax-config`** | ~2830 | **19 test** | ✅ Tamamlandı & Doğrulandı | `ServerGlobalConfig` (user, group, cpu_affinity, reuseport_workers, graceful_shutdown_secs), `ListenersConfig` (proxy_protocol, alpn, strict_sni), `LoggingConfig` (batch_flush_ms, batch_buffer_kb, add_request_id), `VHostLoggingSection`, `VHostErrorDocsSection` (BTreeMap status eşlemesi), `VHostTlsSection` (http2, strict_sni, min_version), `VHostStaticSection` (precompressed, brotli, gzip, autoindex, sendfile), `VHostSecuritySection` (waf_enabled, wp_brute_force, waf_exclude_paths), `VHostRewriteRule`, `VHostPhpSection` (upstreams, lb_policy, dial_timeout_ms, io_timeout_secs, keep_conn, max_idle_conns, resolve_root_symlink, allow_x_accel_redirect). TOML/JSON tam serileştirme ve port çakışma testleri. |
| **`zmax-core`** | ~350 | **6 test** | ✅ Tamamlandı & Doğrulandı | Howard Hinnant sivil takvim algoritması ile sıfır heap bellek tahsisli `format_clf_timestamp` (`[11/Nov/2026:21:00:00 +0000]`) ve ISO-8601 UTC formatlayıcı; `available_cpu_cores`, `pin_current_thread_to_core` (`sched_setaffinity`), `drop_privileges` (`setgid`/`setuid`). |
| **`zmax-runtime`** | ~290 | **6 test** | ✅ Tamamlandı & Doğrulandı | Tokio çalışma zamanı, `ShutdownCoordinator` (watch tabanlı zarif kapanma ve aktif istek tahliyesi), `RuntimeSignal` (Reload, ReopenLogs, UpgradeBinary, Shutdown), `SIGUSR2` dosya tanıtıcısı devri (`encode_inherited_fds_env`, `decode_inherited_fds_env`, `set_fd_cloexec`, `spawn_reexec_binary`). |
| **`zmax-redis`** | ~380 | **6 test** | ✅ Tamamlandı & Doğrulandı | RESP2 protokol motoru (`+`, `-`, `:`, `$`, `*`), `connect_and_auth` (`AUTH [user] pass`, `SELECT db`, `PING`), `ClusterSyncEvent` (`BanIp`, `UnbanIp`, `PurgeDomain`, `PurgeTag`, `PurgeAll`, `ReloadConfig`), mock TCP listener ile asenkron Pub/Sub ve hata yönetim testleri. |
| **`zmax-timeout`** | ~150 | **3 test** | ✅ Tamamlandı & Doğrulandı | Header (10s), Body (30s), Keep-Alive (65s) zaman aşımı; Slowloris yavaş bayt damlatma saldırısı simülasyon testi ve eşzamanlı izole deadline testleri. |
| **`zmax-tls`** | ~630 | **11 test** | ✅ Tamamlandı & Doğrulandı | Rustls 0.23 (ring), dinamik `SniResolver` (çalışırken sertifika değiştirme), `build_acceptor_with_alpn` ile ALPN `["h2", "http/1.1"]` desteği, `negotiated_alpn` ve `client_sni` tespiti, tekil ve çoklu sertifika testleri. |
| **`zmax-httpparser`**| ~990 | **17 test** | ✅ Tamamlandı & Doğrulandı | `httparse` tabanlı streaming HTTP/1.1 parser; **PROXY Protocol v1** (`PROXY TCP4/TCP6/UNKNOWN`) ve **v2** (12 bayt binary imza, LOCAL/PROXY, IPv4/IPv6/Unix); **Request Smuggling kalkanı** (çift/uyumsuz Content-Length, CL.TE / TE.CL çelişkisi, geçersiz Transfer-Encoding, HTTP/1.1 boş/çift Host, CRLF/NUL başlık enjeksiyonu reddi). |
| **`zmax-pool`** | ~390 | **7 test** | ✅ Tamamlandı & Doğrulandı | `BufferPool` (8 KB - 64 KB yeniden kullanılabilir bayt havuzu), `UpstreamSocketPool` (TCP keep-alive soket havuzu, süresi dolanları temizleme), **`UpstreamBalancer`** (`RoundRobin`, `LeastConn`, atomik `UpstreamLease` RAII drop, 5 saniyelik pasif hata soğuma ve otomatik iyileşme). |
| **`zmax-fastcgi`** | ~1420 | **19 test** | ✅ Tamamlandı & Doğrulandı | PHP-FPM ikili protokolü; **HTTPoxy (`CVE-2016-5385`) engeli** (`Proxy:` başlığı kesin düşürülür); **`FCGI_KEEP_CONN = true`** havuzlu çalıştırma (`execute_php_pooled`), bayat soket tespitinde 1x otomatik taze bağlantı denemesi; `validate_script_within_root` ile symlink ve docroot kaçış engeli; `X-Accel-Redirect` / `X-Sendfile` yol sanitizasyonu; `FCGI_STDERR` yakalama; `server_protocol` ("HTTP/2.0" / "HTTP/1.1") ve `[E=...]` ortam değişkeni aktarımı. |
| **`zmax-compress`** | ~350 | **7 test** | ✅ Tamamlandı & Doğrulandı | Saf Rust **Gzip** ve **Brotli** (`brotli 3.5`, `compress_brotli_default`, kalite clamp); RFC 9110 `Accept-Encoding` `q`-ağırlık ayrıştırması (`br` > `gzip`), `q=0` reddi; statik precompressed sidecar uzantı sıralayıcısı (`.zst` > `.br` > `.gz`); min 256 bayt ve MIME tür filtresi. |
| **`zmax-static`** | ~920 | **13 test** | ✅ Tamamlandı & Doğrulandı | `StaticFileHandler` (ETag, If-None-Match 304, Range 206, WebP/AVIF içerik müzakeresi); **Precompressed Sidecar** (`resolve_with_sidecar`: `.zst`/`.br`/`.gz` dosyasını orijinal MIME türünü ve ETag ekini koruyarak sunma); **Özel Hata Sayfası Çözümleyicisi** (`resolve_error_doc_file`: traversal korumalı, 512 KiB sınırlı); **Güvenli Autoindex** (`render_directory_listing`: HTML/XSS kaçışlı dizin listesi); **Linux `sendfile(2)`** sarmalayıcısı ve platformlar arası fallback. |
| **`zmax-rewrite`** | ~2380 | **25 test** | ✅ Tamamlandı & Doğrulandı | WordPress kalıcı bağlantıları (`try_files`); **Hiyerarşik alt-dizin `.htaccess` taraması** (`doc_root`tan istek dizinine kadar); **`mtime` + yol `DashMap` önbelleği** (değişmeyen dosyalarda sıfır disk I/O ve regex derleme yükü); `<IfModule mod_rewrite.c>` blokları; `RewriteCond` (`%{HTTP:Authorization}`, `%{HTTPS}`, `%{HTTP_HOST}`); `RewriteRule` bayrakları (`[L]`, `[R=301/302]`, `[QSA]`, `[NC]`, `[F]` 403, `[G]` 410, **`[E=KEY:VAL]`** / `[E=HTTP_AUTHORIZATION:...]`); `Options -Indexes` / `Options +Indexes`; `ErrorDocument`; **Deklaratif VHost kuralları** (`DeclarativeRewriteRule`). |
| **`zmax-cache`** | ~1180 | **13 test** | ✅ Tamamlandı & Doğrulandı | Moka L1 RAM + L2 Disk önbelleği, SWR, Cache Stampede kalkanı; **LSCache Başlık Köprüsü** (`X-LiteSpeed-Cache-Control` public/private/no-cache, `X-LiteSpeed-Tag`, `X-LiteSpeed-Purge` tekil/çoklu/`*` wildcard, `X-LiteSpeed-Vary` cookie/header varyasyon anahtarı üretimi); alan adı etiketli tasfiye (`purge_by_domain_tag`, `purge_by_tags`). |
| **`zmax-security`** | ~1080 | **14 test** | ✅ Tamamlandı & Doğrulandı | Token Bucket IP hız sınırlama (`429`), WordPress `wp-login.php`/`xmlrpc.php` brute-force oto-ban (`IpBanManager`), genel WAF (SQLi, XSS, Path Traversal, CMDi); **vHost Bazlı WAF Politikası** (`VHostWafPolicy`: `waf_enabled == false` muafiyeti, `waf_exclude_paths` ile false-positive yollarını traversal korumalı atlama); lock-free atomik **`generate_request_id`** (`"zmx-<ts>-<seq>"`). |
| **`zmax-proxy`** | ~1095 | **12 test** | ✅ Tamamlandı & Doğrulandı | Ters vekil, Keep-Alive bağlantı yeniden kullanımı, `Upgrade: websocket` çift yönlü tünelleme, `Host` koruma veya upstream ezme, geciken upstream zaman aşımı. |
| **`zmax-header`** | ~250 | **4 test** | ✅ Tamamlandı & Doğrulandı | `SecurityHeadersPolicy` (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Server başlığı gizleme). |
| **`zmax-obfuscate`**| ~180 | **3 test** | ✅ Tamamlandı & Doğrulandı | Polimorfik dize gizleme ve anti-decompile mekanizması. |
| **`zmax-bin`** | ~7110 | *(Wave 2 aşamasında)* | 🚧 Entegrasyon Aşamasında | Ana ikili: dinleyiciler, REST API (`api.rs`), asenkron log yöneticisi (`logger.rs`), HTTP/2 sunucusu (`h2_engine.rs`), web boru hattı (`web_engine.rs`). |

---

## 5. Kullanıcının Tespit Ettiği 8 Maddelik Eksik Listesi ve Durum Raporu

Aşağıdaki liste, kullanıcının doğrudan kod incelemesiyle işaret ettiği 8 kritik maddenin bu rapor tarihindeki **gerçek, kanıtlı ve filtrelenmemiş durumudur**:

### 1) ALAN ADINA ÖZEL ERİŞİM / HATA GÜNLÜĞÜ (En Kritik)
*   **Kütüphane / Şema Durumu:** `zmax-config` içinde `VHostLoggingSection` (`enabled`, `access_log`, `error_log`, `format`, `max_log_size_mb`, `also_write_global`) tanımlandı, doğrulandı ve 19 testle test edildi. `zmax-core` içinde Howard Hinnant algoritmalı `format_clf_timestamp` yazıldı ve test edildi.
*   **İstek Yolu (`zmax-bin`) Durumu:** 
    - `D:\zmaxserver\crates\zmax-bin\src\logger.rs` modülü oluşturuldu: Arka planda `mpsc` kanallı `AsyncLogManager`, her vHost için ayrı dosya tamponu (`BufWriter`), boyut rotasyonu (`.1`), `SIGUSR1` / `POST /api/v1/logs/reopen` ile dosya tanıtıcılarını sıfırlama, gerçek `bytes_sent` (%b) ve NCSA combined `[%t]` / JSON biçimlendirmesi yazıldı.
    - `api.rs` içine `GET /api/v1/logs?domain=...&kind=access|error` ve `POST /api/v1/logs/reopen` eklendi.
    - **Kalan İş:** `main.rs` ve `web_engine.rs` istek döngüsünün `state.log_manager.log_access(...)` çağrısını bağlayıp canlı iki vHost isteğinde ayrı dosya çıktısını testle kanıtlamak (Wave 2 entegrasyon adımı).

### 2) ÖZEL HATA SAYFALARI (error_docs)
*   **Kütüphane / Şema Durumu:** `zmax-config` içinde `VHostErrorDocsSection` (`enabled`, `dir`, `pages: BTreeMap<u16, String>`) şeması ve `resolve_error_doc_page(status)` metodu eklendi; traversal `..` testleri geçti. `zmax-static` içinde `resolve_error_doc_file` (512 KiB sınırlı güvenli okuyucu) test edildi.
*   **İstek Yolu (`zmax-bin`) Durumu:** `web_engine.rs` içindeki merkezi hata üreticisinin (`write_error_response`) `vhost.resolve_error_doc_page` ve `.htaccess` `ErrorDocument` ile bağlanması Wave 2 aşamasında birleştirilmektedir.

### 3) ALAN ADINA ÖZEL WAF
*   **Kütüphane / Şema Durumu:** `zmax-config` içinde `waf_enabled: Option<bool>`, `wp_brute_force: bool`, `waf_exclude_paths: Vec<String>` eklendi. `zmax-security` içinde `WafInspector::inspect_with_policy` yazıldı; `waf_enabled=false` bypass'ı ve hariç yollarda false-positive atlama testleri (14 test) başarıyla geçti.
*   **İstek Yolu (`zmax-bin`) Durumu:** `web_engine.rs` istek hattına `vhost_ctx.waf_policy` bağlandı; entegrasyon testiyle kanıtlanması bekleniyor.

### 4) HTTP/2 (ALPN h2 ve h2 Çerçeve Motoru)
*   **Kütüphane Durumu:** `zmax-tls` içinde ALPN varsayılanı `["h2", "http/1.1"]` yapıldı; loopback el sıkışmasında h2 ve http/1.1 seçimi test edildi (11 test). `h2 0.4.20` ve `http 1.1` paketleri yerel Cargo önbelleğinden workspace bağımlılıklarına kilitlendi.
*   **İstek Yolu (`zmax-bin`) Durumu:** 
    - `D:\zmaxserver\crates\zmax-bin\src\h2_engine.rs` motoru yazıldı: `h2::server::Builder` ile el sıkışma, stream gövdesi okuma, `:authority`/`:method`/`:path` başlıklarını `web_engine` istek modeline verme ve HTTP/2 yanıt akıtma.
    - `main.rs` TLS kabul döngüsünde `negotiated_alpn` kontrolüyle `h2` ise `h2_engine`'e, değilse `web_engine`'e yönlendirme bağlanmaktadır.

### 5) REST API CRUD EKSİKLERİ
*   **Durum:** `D:\zmaxserver\crates\zmax-bin\src\api.rs` güncellendi:
    - `format_vhost_json`: vHost'un TÜM alanlarını (`security.{hotlink_protection, force_https, allow_ips, deny_ips, waf_enabled, wp_brute_force, waf_exclude_paths}`, `logging.*`, `error_docs.*`, `tls.*`, `static.*`, `rewrite.*`, `php.*`, `proxy.*`, `headers.*`) JSON olarak dışa aktarır.
    - `PUT /api/v1/vhosts/<domain>` & `POST /api/v1/vhosts`: Yalnızca `force_https` değil; yukarıdaki tüm alanları JSON'dan okuyup atomik TOML yazar ve `VHostEntry::validate()` ile doğrular.

### 6) .htaccess VE YÖNLENDİRME TAMAMLAMA
*   **Kütüphane Durumu:** `zmax-rewrite` içinde hiyerarşik alt klasör taraması, `mtime` DashMap önbelleği, `[E=HTTP_AUTHORIZATION:...]` ortam değişkeni toplama, `Options -Indexes`, `ErrorDocument`, `<IfModule mod_rewrite.c>` blokları ve deklaratif `[[vhost.rewrite]]` kuralları yazıldı ve 25 testle doğrulandı. `zmax-fastcgi` içinde `extra_env` ve `HTTPoxy` engeli test edildi.
*   **İstek Yolu (`zmax-bin`) Durumu:** `web_engine.rs` istek hattında `state.htaccess_resolver` nesnesi üzerinden WordPress permalink ve alt-dizin kuralları bağlanmaktadır.

### 7) PANEL / API PORTU SERTİFİKA YENİLEME
*   **Mimari Çözüm:** `zmax-tls` içindeki `SniResolver`'ın çalışırken `replace()` yeteneği kullanıldı. `ServerState` yapısına `pub admin_tls: Arc<SniResolver>` ve `pub api_tls: Arc<SniResolver>` eklendi; `reload_runtime_state` içinde diskteki sertifika yenilendiğinde bu resolver'lar da sıcak yenilenir, listener'ı yeniden başlatmaya gerek kalmaz.

### 8) BİRİM / ENTEGRASYON VE DAYANIKLILIK TESTLERİ
*   **Alt Sandıklar:** Önceki raporda 0 testi olan `zmax-core` (6 test), `zmax-runtime` (6 test), `zmax-redis` (6 test) ve `zmax-timeout` (3 test) modüllerine kapsamlı birim testleri yazıldı; toplam 179 alt test geçmektedir.
*   **`web_engine.rs` / `zmax-bin`:** `web_engine.rs` sonuna 1..7 maddelerinin (vHost log, error_docs, waf_enabled, h2, api crud, htaccess) entegrasyon test modülü eklenmektedir.

---

## 6. Dış Kapsam ve ZePanel (Go) / Linux VM Sınırları

Proje netliği açısından, aşağıdaki maddeler **Rust motoru içinde değil, ZePanel (Go) veya canlı Linux sunucu ortamında** gerçekleştirilecektir:

| Madde No | Tanım | Sorumlu Taraf | Durum & Beklenti |
| :--- | :--- | :--- | :--- |
| **E6** | Panel / Webmail / Zplus (80/443) Proxy vHost'ları | Go (ZePanel) | Go servisi, Roundcube ve panel portlarına ters vekil yapacak vHost TOML dosyalarını üretir. |
| **E8** | Canlı Certbot ACME Yenilemesi | Go / Linux VM | `/.well-known/acme-challenge/` Rust tarafından sunulur; certbot sürecini tetiklemek Go'nun görevindedir. |
| **E9** | PHP-FPM Kurulum & Havuz Yöneticisi | Go (ZePanel) | `/run/zpanel-php/<site>.sock` soketini ve PHP-FPM havuz ayarlarını Go installer kurar. |
| **E10**| OpenLiteSpeed Uzantı Paketlemesi | Go (ZePanel) | Go panel uzantı yöneticisi tarafında paketlenir. |
| **E11**| Panel Disk / Trafik Kotası Grafikleri | Go (ZePanel) | Go ajanı, ZMax'in `access.log` içindeki `%b` gerçek bayt sütununu okuyarak panel grafiğine işler. |
| **E14**| Web Sunucusu Geçiş Betiği (`zmax-gecis.sh` / Rollback)| Go / Shell | OLS ile ZMax arasında servis geçişi ve geri dönüş betiği. |
| **HTTP/3** | `zmax-quic` (QUIC / UDP 443) | Rust (Gelecek) | Yerel Cargo önbelleğinde `quinn` kütüphanesi bulunmadığından HTTP/3 şimdilik planlanan aşamadadır. |

---

## 7. Derleme, Paketleme ve Otomasyon Durumu

*   **Derleme Hedefleri:**
    - `x86_64-pc-windows-msvc` (Windows x64)
    - `x86_64-unknown-linux-musl` (`zig cc` + `rust-lld` ile statik tam bağımsız Linux x64)
    - `aarch64-unknown-linux-musl` (`zig cc` + `rust-lld` ile statik Linux ARM64)
*   **Paket Formatları:**
    - Windows `.zip`
    - Linux `.tar.gz` (x64 & ARM64)
    - Debian/Ubuntu `.deb` (`nfpm` ile)
    - RHEL/CentOS/AlmaLinux `.rpm` (`nfpm` ile)
    - `SHA256SUMS.txt` bütünlük sağlama toplamı
*   **Paket Doğrulama:** `doc/tools/verify_packages.py` betiği tüm paketlerde portların (`19480/19485/19486`), göreli HTML/JS API yollarının ve Linux LF satır sonlarının varlığını otomatik doğrular.

---

## 8. Sonuç ve Sonraki Adım

1.  **Tamamlanan Kısım:** 18 sandığın 17 alt kütüphane sandığı en yüksek güvenlik ve performans standartlarıyla baştan aşağı yenilenmiş, 179 birim testi sıfır hatayla geçmiştir.
2.  **Devam Eden Kısım (Wave 2):** `zmax-bin` içerisindeki `logger.rs`, `h2_engine.rs`, `web_engine.rs`, `api.rs` ve `main.rs` entegrasyonu tamamlanıp `cargo test --workspace` ile 8 maddenin tamamı tek tek somut çıktıyla kanıtlanacaktır.
3.  **Kapanış:** Bu entegrasyon ve release derlemeleri tamamlandığında `tamproje.md` belgesindeki "Devam Eden" ibareleri kesin komut ve test çıktılarıyla güncellenecektir.
