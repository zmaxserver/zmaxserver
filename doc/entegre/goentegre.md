# ZPanel (Go) ↔ ZMax Server (Rust) — Entegrasyon Kılavuzu (tek güncel belge)

**Amaç:** Go panel ↔ ZMax sözleşmesi (portlar, API, TOML, günlük) ve panelde bekleyen işler. **Güncellenir:** TOML şeması/API/port değişince (iki taraf birlikte). **Bağlı:** [`../MIMARI_VE_PLAN.md`](../MIMARI_VE_PLAN.md) · durum [`../TAM_MODUL_VE_OZELLIK_MATRISI.md`](../TAM_MODUL_VE_OZELLIK_MATRISI.md) (bu belgedeki etiketler özet; matris geçerlidir) · kartlar [`../ADIMLI_GELISTIRME_TAKIP.md`](../ADIMLI_GELISTIRME_TAKIP.md)

Güncelleme: 2026-11-12. Bu belge eski `goentegre.md` (Go kod örnekleri, kanallar) ve `zpanel-entegre.md` (port bloğu, Control API, ters vekil kuralları) belgelerinin birleşimidir; orijinalleri `arsiv/2026-11-12/` içindedir.
Mimari ve iş bölümü: [`MIMARI_VE_PLAN.md`](../MIMARI_VE_PLAN.md) §1, §4 · Yol haritası: [`YOL_HARITASI.md`](../YOL_HARITASI.md) · Özellik durumları: [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](../TAM_MODUL_VE_OZELLIK_MATRISI.md)
Panel kaynağı: `D:\lunixpanel\zpanel-tam` (Go ajan `cekirdek/agent`, Node API `servis/api`) ve `D:\lunixpanel\zpanelv2` (Vue 3 arayüz). Panel çalışır durumdadır ve **bu depoda değiştirilmez**; ZMax paneldeki hiçbir portu değiştirmez.

---

## 1. Sözleşme (tek cümle)

Go vhost TOML'unu yazar → `POST http://127.0.0.1:19486/api/v1/reload` (ya da `SIGHUP`) → ZMax doğrular, atomik uygular; hata varsa eski yapılandırmada kalır. ZMax hiçbir yönetim kararı vermez. TOML alan adları değişirse iki taraf birlikte güncellenir.

| Bileşen | Yol / değer |
|---|---|
| vhost TOML | `/usr/local/zmax/conf/vhosts/<alan>.toml` (Windows geliştirme: `conf/vhosts/`) |
| Ana yapılandırma | `conf/zmax.toml` (+ `ZMAX_*` ortam değişkenleri) |
| Reload | `POST http://127.0.0.1:19486/api/v1/reload` · `SIGHUP` · (Linux) `systemctl reload zmax` |
| Sağlık / durum | `GET /api/v1/health`, `GET /api/v1/status` |
| Sunucu seçimi (panel) | `/etc/zpanel/webserver` içeriği `zmax` ya da `openlitespeed` |
| Geçiş / geri dönüş | `zmax-gecis.sh` (kapılı geçiş; OLS'e dönüş her zaman çalışmalı); güncelleme `ajan-guncelle.sh` (paket `packed\` içinden ZMax ikilisini yerleştirir) |
| php-fpm soketi | `/run/zpanel-php/<kimlik>.sock` (vhost başına havuz; TCP kullanılırsa `listen.allowed_clients = 127.0.0.1`) |
| ACME webroot | belge kökünde `.well-known/acme-challenge/`; ZMax statik sunar, `force_https` bunu muaf tutar |
| Günlük | vhost başına `access.log` + `error.log` (ZMax yazar, Go okur; bkz. §6) |

## 2. Portlar (çakışmasız blok `19480–19486`, IANA Unassigned)

| Bileşen | Yan yana (varsayılan) | Tam devralma | Anahtar (`zmax.toml`) | Ortam değişkeni |
|---|---|---|---|---|
| Web HTTP | `0.0.0.0:19480` | `0.0.0.0:80` | `[listeners.http]` | `ZMAX_HTTP_PORT` |
| HTTPS | `0.0.0.0:19483` | `0.0.0.0:443` | `[listeners.https]` | `ZMAX_HTTPS_PORT` |
| WebAdmin (Vue 3) | `127.0.0.1:19485` | aynı | `[listeners.admin]` | `ZMAX_ADMIN_PORT` |
| Control API | `127.0.0.1:19486` (ya da `unix_socket = "/run/zmax/api.sock"`) | aynı | `[listeners.api]` | `ZMAX_API_PORT` |

- **Test portları (VM):** ZMax `19480` (HTTP) ve `19483` (HTTPS) üzerinde çalışır, OpenLiteSpeed 80/443'te kalır. 80/443'e geçiş şartları: [`MIMARI_VE_PLAN.md`](../MIMARI_VE_PLAN.md) §6.
- Dışlanan panel portları (ZMax kullanmaz): cPanel 2082–2096, Plesk/CloudPanel 8443/8880, DirectAdmin 2222, CyberPanel/OLS 7080/8088/8090, Hestia 8083/8084, aaPanel 888/7800/8888, ISPConfig 8080/8081, ISPmanager 1500, Webmin 10000, zPanel 80/443/8025–8056/8080/8088/8091/8443/8787–8789/8880, Caddy admin 2019, Prometheus 9090 vb.; Linux ephemeral `32768–60999`. `zmax-config` birim testleri `KNOWN_PANEL_PORTS` listesine karşı çakışma denetler.
- WebAdmin 19485'e dışarıdan port açmak gerekmez.

## 3. Control API (`127.0.0.1:19486`)

Kimlik doğrulama: `[listeners.api] token = "..."`, `require_token = true` (ya da `ZMAX_API_TOKEN`) tanımlıysa `Authorization: Bearer <token>` veya `X-ZMax-Token: <token>`; yalnız `/api/v1/health` herkese açık. `0.0.0.0` dinlemede token zorunludur. CLI: `zmax -t` (`--check`) yapılandırma ve vhost dosyalarını doğrular; `zmax -v` sürüm.

| Uç | Görev | Durum |
|---|---|---|
| `GET /api/v1/health` | canlılık | IMPLEMENTED |
| `GET /api/v1/status` (`/api/status`) | telemetri: uptime, toplam istek, cache hit/miss, worker, RAM, vhost sayısı | IMPLEMENTED |
| `GET /api/v1/ports` | port keşfi/çakışma | IMPLEMENTED |
| `GET /api/v1/config` | maskelenmiş yapılandırma (token görünmez) | IMPLEMENTED |
| `POST /api/v1/reload` (`/api/reload`) | sıcak yeniden yükleme | IMPLEMENTED |
| `POST /api/v1/cache/purge` (`/api/purge`) | gövde boşsa tüm L1; `{"uri":...}` / `{"key":...}` tek anahtar | IMPLEMENTED |
| `GET /api/v1/vhosts`, `GET /api/v1/vhosts/<alan>` | liste / ayrıntı | IMPLEMENTED |
| `PUT /api/v1/vhosts/<alan>`, `POST /api/v1/vhosts` | atomik yazım (`.tmp` → rename) + reload | IMPLEMENTED (alan kapsamı eksik: `hotlink_protection`, `allow_ips`, `deny_ips`, `rewrite.*`, `headers.*`, `logging.*`, `error_docs.*`, `security.waf_*`) |
| `DELETE /api/v1/vhosts/<alan>` | TOML sil + reload | IMPLEMENTED |
| `GET /api/v1/logs` (`?domain=`) | günlük tamponu | IMPLEMENTED (küresel; `?domain=` filtresi: bilinmiyor) |
| `GET /api/v1/security/bans`, `POST /api/v1/security/unban` | aktif ban listesi / kaldırma | eski belgede "canlı" yazıyordu; doğrulanmadı |
| `GET /metrics` | Prometheus | IMPLEMENTED |

Alan adı doğrulaması RFC'ye uygun ve dizin kaçışına karşı korumalıdır.

## 4. vhost TOML (gerçek örnek: `conf/vhosts/example.com.toml`)

```toml
[vhost]
name = "example.com"
aliases = ["www.example.com"]
document_root = "www/example"
index_files = ["index.php", "index.html"]

[vhost.cache]
enabled = true
expire = 600

[vhost.php]
enabled = true
sapi = "fastcgi"
upstream = "127.0.0.1:9000"        # ya da unix:/run/zpanel-php/<kimlik>.sock

[vhost.ssl]
certificate = "conf/ssl/example.crt"
key = "conf/ssl/example.key"

[vhost.tls]
http2 = true                        # şemada var; HTTP/2 motoru bitene kadar etkisiz sayılmalı

[vhost.logging]
enabled = false
access_log = "logs/example.com.access.log"
error_log = "logs/example.com.error.log"

[vhost.static]
precompressed = true
brotli = true
gzip = true

[vhost.error_docs]
enabled = false
```

Ek alanlar (`[vhost.security]`: `force_https`, `hotlink_protection`, `allow_ips`, `deny_ips`, `waf_enabled`, `waf_exclude_paths`, `wp_brute_force`; `[vhost.proxy]`) için kesin şema `crates/zmax-config` okunarak doğrulanır; hangileri şemada var ve hangileri çalışıyor: [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](../TAM_MODUL_VE_OZELLIK_MATRISI.md). Eski Go örneğindeki `toml:"vhost.cache"` gibi noktalı etiketler iç içe tablo üretmez; Go tarafında iç içe struct kullanılmalıdır.

Go yazım kuralı: geçici dosyaya yaz → `rename` (atomik) → reload. Bozuk TOML ZMax'te eski yapılandırmayı korur, ama yine de yazmadan önce `zmax -t` ile doğrulanması önerilir.

## 5. Go tarafı örnekleri (kısaltılmış)

```go
// Reload: Linux'ta systemctl reload zmax; her yerde API
resp, err := http.Post("http://127.0.0.1:19486/api/v1/reload", "application/json", nil)

// Sağlık
resp, err := http.Get("http://127.0.0.1:19486/api/v1/health")   // 200 = canlı

// Önbellek
http.Post("http://127.0.0.1:19486/api/v1/cache/purge", "application/json", nil)                       // tümü
http.Post(".../api/v1/cache/purge", "application/json", strings.NewReader(`{"uri":"/sayfa"}`))       // tek anahtar

// Durum alanları: uptime_seconds, total_requests, cache_hits, cache_misses, workers, ram_mb
resp, err := http.Get("http://127.0.0.1:19486/api/v1/status")
```

Ban akışı: ZMax saldırganı kapıda keser; Go `GET /api/v1/security/bans` ile (ya da ileride `zmax-redis` Pub/Sub `zmax:waf:events` kanalıyla) listeyi alıp `nftables`/`iptables`'a kalıcı yazar. Redis kablolaması `zmax-bin`'de doğrulanmadığı için bugün güvenilir yol API'dir.

## 6. Günlük sözleşmesi (Go ↔ Rust)

- ZMax vhost başına `access.log` ve `error.log` yazar (hedef biçim NCSA combined: `IP - - [%d/%b/%Y:%H:%M:%S %z] "METHOD PATH HTTP/x" STATUS BAYT "Referer" "UA"`; isteğe bağlı JSON; `X-Request-Id`), `max_log_size_mb` ile döndürür, `SIGUSR1` ile dosyaları yeniden açar. **Bugün:** şema var, `zmax-bin` vhost günlüğünü okumuyor; satırda zaman damgası yok ve bayt sabit `-` (IMPLEMENTED, yalnız şema).
- Panelin günlük sayfası, istatistik ve **trafik/kota hesabı** bu baytlara dayanacağı için, ZMax gerçek gönderilen baytı yazana kadar trafik rakamı ZMax altında doğru olmaz.
- Günlük dosya yolu: panel şu an OpenLiteSpeed yolunu (`/var/log/zpanel/<alan>/access.log`) okur; ZMax tarafı için kaynaklar `/var/www/vhosts/<alan>/logs/access.log` ya da `logs/vhosts/<alan>.access.log` yazıyordu. **Hangisinin kullanılacağı kesinleşmedi (bilinmiyor)** — Faz 1 başında Go ve Rust birlikte tek yolu seçer ve bu satır güncellenir.
- Go: günlük sayfası, `.gz` arşiv/döndürme, istatistik ve trafik hesabını ZMax günlüğüne bağlar; ZMax yeniden açma sinyalini rotasyondan sonra bekler.

## 7. Go (ZPanel) tarafında bekleyen işler (ZMax kodu değil)

1. Günlük okuyucu ve trafik/kota hesabını ZMax günlüğüne bağlamak (Faz 1 günlük işi bitince) · disk/trafik kartları (E11).
2. Panel / webmail / Zplus ters vekil vhost'larını yazmak: `panelHost → zpanel-staff`, `webmail.<alan>`, Zplus (`[vhost.proxy]` TOML; ZMax bunları kendiliğinden üretmez). 80/443 geçişi öncesi şart (E6).
3. certbot webroot yönetimi, yenileme zamanlaması, yenileme sonrası TOML'daki `.pem/.key` yollarını güncelleyip `reload` (E7/E8). Gerçek certbot yenilemesinin ZMax üzerinden geçtiği henüz denenmedi.
4. php-fpm kurulumu: installer (`cekirdek/installer`) ZMax/php-fpm kurmuyor; `config/php-fpm/php-fpm-kur.sh` paketli. Havuz, soket (`/run/zpanel-php/<kimlik>.sock`) ve kiracı hesabı kurulumu installer'a taşınacak (E9).
5. OpenLiteSpeed ücretsiz uzantısı: `uzantilar/ücretsiz` içinde paket yok; kimlik `rpc.OpenLiteSpeedExtensionID` varsayıldı — paketleyip kimliği doğrulamak (E10).
6. `zmax-gecis.sh` içindeki eski "ZMax TLS bilmiyor" kapısını güncellemek (TLS artık çalışıyor; HTTPS sınaması yeniden değerlendirilecek). OLS'e dönüş yolu her zaman çalışmalı (E14).
7. Güncel paketleri (`.deb`, `.rpm`, `tar.gz`) VM'ye dağıtmak; `ajan-guncelle.sh` bunları yerleştirir. (Eski not "RPM yok"; güncel durum için [`tools/README.md`](../tools/README.md).)
8. `.htaccess` yönlendirme bloğunu (redirects paketi) vhost TOML kural alanlarına (`[[vhost.rewrite]]`) çevirmek; çevirisi olmayan direktifleri raporlamak (E2). `[[vhost.rewrite]]` şeması henüz yok.
9. Önbellek yönetimi ve telemetri ekranlarının hangi API uçlarına bağlı olduğunu doğrulamak (E13: bilinmiyor).
10. Panel ters vekil kuralı: bkz. §8.

## 8. WebAdmin (19485) panel ters vekil kuralları

WebAdmin Bootstrap 5 + Vue 3, tüm varlık ve API yolları **görelidir** (`css/...`, `js/...`, `fetch('api/status')`). Panelin altında (`/v1/zmax/console/` → `127.0.0.1:19485`) şu kurallar şarttır:
1. Konsol sonda `/` ile açılır; `/v1/zmax/console` gelirse `301/302` ile `/v1/zmax/console/` adresine yönlendirilir.
2. Önek soyulur: `/v1/zmax/console/<yol>` → `http://127.0.0.1:19485/<yol>`.
3. `[listeners.api] require_token = true` ise panel proxy'si `/api/*` isteklerine sunucu tarafında `Authorization: Bearer <token>` (ya da `X-ZMax-Token`) ekler; token tarayıcıya sızdırılmaz.
4. WebSocket gerekmez; arayüz 2 sn'de bir `GET api/status` ve `GET api/v1/vhosts` çağırır.

## 9. İş bölümü özeti

| Sorumluluk | Go | Rust |
|---|---|---|
| Hosting/müşteri/paket/kota | ✅ | ❌ |
| vhost TOML yazımı | ✅ | salt okunur |
| Gelen HTTP/HTTPS, önbellek, WAF/DoS, günlük yazma | ❌ | ✅ |
| İşletim sistemi güvenlik duvarı | ✅ | ❌ (Go'ya bildirir) |
| SSL | ✅ certbot/zamanlama | ✅ ACME dosyası sunumu + sertifika yenileme sonrası yükleme |
| Kurulum / güncelleme / OLS'e dönüş | ✅ | ❌ |
