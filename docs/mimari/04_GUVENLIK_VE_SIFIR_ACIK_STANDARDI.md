# ZMax Güvenlik ve Sıfır Açık (Zero-Trust) Standardı (v3.1, kodla doğrulanmış)

> Durum sütunu `main` = `birlesme2` = `dff16c6` kodunun okunmasıyla doldurulmuştur. **Var** = kodda ve çağrı yolunda görüldü; **Kısmi** = bir kısmı var; **Yok** = kodda bulunamadı (arama yapıldı); **Doğrulanmadı** = koddan teyit edilemedi. "Test geçti" iddiası değildir: bu belge testleri koşmadı (tam test `BIRLESME2.md`: 494 geçti). Kök: `agaclar/birlesme2/crates`.

## 1. Felsefe
Gelen hiçbir istek doğrulanmadan güvenilir sayılmaz. Her yönetim işlemi API'den geçer; API'nin önünde tek kapı vardır (istisnalar §3'te).

## 2. Saldırı → Savunma Matrisi

| Tehdit | Parça | Savunma (koddaki yer) | Durum |
|---|---|---|---|
| Kimlik atlama | A1 | Tek giriş `authorize_role` `zmax-bin/src/api/auth.rs:27`, `api/mod.rs:121`; rotalar kendi kontrolünü yazmaz | **Var** (istisna: `health`, `GET /api/version` auth'tan önce, `api/mod.rs:111`) |
| Boş token ile açık API | A1 | Token boşsa yalnız `local && !require_token` (`auth.rs:27-35`); `local` = eş ve gerçek IP loopback (`api/mod.rs:200`) | **Var** (M13) |
| Zamanlama saldırısı | A1 | `constant_time_eq` `api/auth.rs:8`; ayrıca `zmax-security/src/basic_auth.rs:356` | **Var** (uzunluk farkında erken döner: doğrulanmadı) |
| Kaba kuvvet (token tahmini) | A2 | 5 ardışık 401 → 900 sn ban (`api/guard.rs:55`, varsayılanlar `zmax-config/src/lib.rs:378-380`) + API rate limit 120/dk → 429 (`guard.rs:28`, `:381`) | **Var** (M17; loopback istemci muaf) |
| Yetki yükseltme | A1 | `AuthRole::{Admin, Read}`, okuma rolü yazma ucunda 403 (`api/mod.rs:128`, `auth.rs:72`) | **Var** (M13) |
| İzsiz değişiklik | A9 | `api/audit.rs:54` → `logs/audit.log`; vhost, modül, purge, reload, unban çağrılarında (`02` A9) | **Kısmi** (ban ekleme ucu yok; `rol` her kayıtta geçirilmiyor) |
| Bozuk yapılandırma ile çökme | K3 | Reload doğrulamayı **uygulamadan önce** yapar (`config/reload.rs:86` `validate_workspace_layout?`, takas 148); vhost yazımında geri alma (`api/services/vhost_service.rs:7,83`) | **Var** |
| Path traversal (API) | A2 | `has_parent_dir_traversal` `zmax-config/src/vhost_json.rs:152` yalnız vhost JSON alanlarında (74, 505); genel API yolunda yok | **Kısmi** (null-byte denetimi bulunamadı) |
| Path traversal (web) | L4+L7 | L4 gizli yol/path denetimi (`pipeline/l4_security.rs` adım 0); statik `canonicalize` + kök sınırı (`pipeline/l7_handlers/static_files.rs:113,291-292`) | **Var** |
| Webshell (uploads altında .php) | L4 | `/uploads/` altı `.php/.phtml/.phar` 403 kuralı `zmax-bin` ve `zmax-security` içinde **bulunamadı** | **Yok** |
| Slowloris / soket tüketimi | L1 | `header_timeout`/`body_timeout`/idle (`pipeline/l1_connection.rs:87-135`) | **Var** |
| HTTP flood | L4 | IP rate limit yalnız HTTP/1 (`web_engine/pipeline_h1.rs:132`) ve ek dinleyici (`extra_listeners.rs:487`); HTTP/2 yolunda **bulunamadı** | **Kısmi** |
| Sahte gerçek IP başlığı | L3 | `RealIpPolicy` + `trusted_proxies` (`pipeline/l3_realip.rs:7`, `modules/policy.rs:8`) | **Var** |
| Host/SNI sahteciliği | L2 | Çift/boş Host reddi `zmax-httpparser` (test `lib.rs:1651`); bilinmeyen Host 403 (`pipeline_h1.rs:68`); `strict_sni` yalnız yapılandırma alanı (`zmax-config/src/lib.rs:167`), uygulayan kod `zmax-bin`/`zmax-tls` içinde bulunamadı | **Kısmi** |
| h2'ye kapalı vhost'a h2 isteği | L2a | 421 (`web_engine/pipeline_h2.rs:84-94`) | **Var** |
| PHP-FPM boğma | L7 | `BackendSemaphores` tanımlı (`l7_handlers/upstream.rs:12`) ama kullanımı bulunamadı; ters vekil bağlantı sınırında 503 (`proxy.rs:195`); PHP için 503+`Retry-After` bulunamadı | **Kısmi** |
| Önbellek zehirleme | L6 | bypass çerezi/Authorization önbelleğe girmez (`pipeline/l6_cache.rs:52,93`), `build_cache_key` (`pipeline_h1.rs:607`) | **Var** |
| Clickjacking / MIME / HSTS | L8 | `resolve_vhost_security_headers` `pipeline/l8_response.rs:21` | **Var** |
| Basic Auth kaba kuvveti (L4a) | L4a | başarısız denemeler IP bazında sayılır, eşikte ban; hash `spawn_blocking`+`Semaphore` (`security_pipeline.rs:15`, `zmax-security/src/basic_auth.rs`) | **Var** |
| Ek dinleyici suistimali (L1a) | L1a | arka uç yalnız yapılandırmadan (Host'tan türetilmez), yasaklı IP + global ACL + hız sınırı (`web_engine/extra_listeners.rs:1-5,487`) | **Var** (vhost WAF yok: bilinçli) |
| Çok sunuculu ban/purge senkronu | K7 | Yayın `redis/sync.rs` (`publish_ban/unban/reload/purge_*`) + abone `redis/events.rs:52` (boot'ta `core/boot.rs:440`); döngü önleme `is_own_event` `events.rs:9` | **Var** (M19) |
| Redis erişilemezken istek yolu | K7 | `spawn_event` + zaman aşımı (`redis/sync.rs:29`); istek beklemez | **Var** |
| Redis şifresi/TLS sızması | K7 | `RedisConfig` `#[derive(Debug…)]` (`zmax-redis/src/lib.rs:46`); parola alanı maskelenmiyor (`#[debug(skip)]` yok) | **Yok** (`use_tls` desteği: doğrulanmadı) |
| Redis'e yetkisiz yazma | K7 | `zmax:` önek ve `zmax:cache:purge` kanalı (`mod_redis.toml` `pubsub_channel`); Redis erişim denetimi uygulama dışı | **Doğrulanmadı** |
| Token sızması (log/URL) | A2/K5/U2 | audit'e token yazılmaz (`audit.rs:9`); `?token=` adres çubuğundan silinir (`admin/js/api_client.js:43`); **SSE `createLogsStream` token'ı URL sorgusuna koyar** (`api_client.js:225`) | **Kısmi** |
| Kimliksiz uç nokta sızıntısı | A3 | `GET /api/v1/health` loopback dışından da kimliksiz (`api/routes/system.rs:14`, `api/mod.rs:111`); `GET /api/version` kimliksiz (`system.rs:37`) | **Yok** (Karar 9'a aykırı) |
| Metrik sızıntısı | A3 | `/metrics` auth'tan sonra, `okuma` yeter (`system.rs:55`, `auth.rs:80`) | **Var** (Karar 9) |

## 3. Erişim kanalı tablosu (A1+A2 uygular)

| Kanal | Kimlik şartı | Ağ şartı | Kimliksiz uç nokta (kodda) |
|---|---|---|---|
| Port 19486 (`api`) | `require_token` ve token; iki rol | Token boşsa yalnız loopback (Karar 2) | `GET /api/v1/health`, `GET /api/version` — **dış ağdan da** |
| Port 19485 (`admin`) | aynı | aynı | A7 statik dosya; `health`/`version` aynı |
| Unix soketi | dosya izni | yalnız yerel | — |

**Karar 9 uygulanma durumu:** `metrics` = uygulandı; `health` loopback kısıtı = **uygulanmadı** (kod bunu gerektiriyor: `health_version`'ı `local` bilgisiyle çağırmak veya auth sonrasına almak). Bu belge yalnız durumu yazar.

## 4. A1/A2 standartları
1. **Tek kapı:** `A2 → A1 → rota` (gerçek sıra: A2 önce, `api/mod.rs:116` ve `121`; planda A1→A2 yazılmıştı).
2. **Rol modeli:** Var (`read_token` ayrı; yönetim token'ı yazma). zPanel ve WebAdmin ayrı token alabilir (`api_token`/`admin_token`, `api_read_token`/`admin_read_token`).
3. **Boş token kapısı:** Var.
4. **Hot-reload:** token korunur (`api/auth.rs:112`, test `test_compute_effective_auth_preserves_tokens_and_auto_generates`).
5. **Değişiklik güvenliği:** vhost yazımı geri alınır (`vhost_service.rs`); **`.lock` yok** (Go tarafında var, `go/lifecycle/writer.go:20`).
6. **Denetim:** A9 Var (Kısmi: ban ekleme ucu yok).
7. **Girdi doğrulama:** `:domain` ve alan doğrulaması `zmax-config/src/vhost_json.rs`; JSON gövde boyutu `read_http_request_with_limits` (`api/http.rs:159`).
8. **Hata yanıtı:** iç yol sızıntısı taranmadı (**Doğrulanmadı**); `reload` hatası `e` mesajını aynen döner (`config_service.rs:29-34`).

## 5. Boru hattı standartları
- **L1:** zaman aşımları Var; IP başına eşzamanlı bağlantı sınırı **Yok**.
- **L2:** Host çift/yok → 400 Var (httpparser); `max_header_bytes`/`max_body_bytes` → 413 (testler `main.rs` `keepalive_pipelining_gzip_and_413_payload_limit` 314); Strict SNI uyuşmazlığı → 421 **bulunamadı**.
- **L3:** gerçek IP tek fonksiyonda (`l3_realip.rs:7`); API ve ek dinleyici doğrudan `zmax_httpparser::resolve_real_ip` çağırır (`api/mod.rs:193,221`, `api/admin_static.rs:38`, `extra_listeners.rs:398`).
- **L4:** loopback rate limit'ten muaf, WAF'tan muaf değil; `/xmlrpc.php` WP kalkanı kapsamında (`zmax-security/src/lib.rs:387`).
- **L5:** `force_https` ACME'yi bozmaz (`is_acme_challenge` `l5_router.rs:86`).
- **L7:** `canonicalize` kök sınırı Var; `SCRIPT_FILENAME` doğrulaması **Doğrulanmadı**.

## 6. Bellek ve kararlılık
- `Arc<T>` paylaşımı: Var (`ServerState` `core/state.rs:51`).
- `.unwrap()`/`.expect()`: `zmax-bin/src` altında test dışı sayım yapılmadı (grep testleri ayıklamadı): **Doğrulanmadı**.
- Her bekleme zaman aşımına sahip: **Doğrulanmadı** (tam tarama yapılmadı).

## 7. Kabul ölçütü
Parça "bitti" sayılmadan önce ilgili `cargo test -p zmax-bin <test>` çıktısı ve bu belgedeki satırın Durum'u `Var` olmalı. Bu sürümde `Yok`/`Kısmi` satırlar: webshell, HTTP/2 rate limit, Strict SNI uygulaması, PHP-FPM 503+Retry-After, Redis parola maskeleme, `health` loopback, SSE token, API `.lock`, IP başına bağlantı sınırı.
