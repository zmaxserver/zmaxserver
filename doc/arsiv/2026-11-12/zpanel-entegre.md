# ZPanel & Popüler Paneller ↔ ZMax Server Evrensel Entegrasyon ve Çakışmasız Port Kılavuzu

Bu doküman, **`D:\zmaxserver`** (ZMax Server v1.0.01) ile **`D:\lunixpanel\zpanelv2`**, **`D:\lunixpanel\zpanel-tam`** ve **tüm popüler hosting kontrol panelleri** (`cPanel/WHM`, `Plesk`, `DirectAdmin`, `CyberPanel/OLS`, `HestiaCP/VestaCP`, `aaPanel/FASTPANEL`, `CloudPanel`, `ISPConfig`, `ISPmanager`, `CWP`, `Webuzo`, `Webmin`) arasında **%0 port çakışması** ve **ortak Evrensel Control API** ile sorunsuz entegrasyon sağlanması için hazırlanmış kesin referanstır.

> **Sert Kural:** Mevcut `zpanel` (`zpanelv2` ve `zpanel-tam`) veya hedef panellerdeki hiçbir port **değiştirilmez**. ZMax Server varsayılan port bloğu IANA **Unassigned (`19480–19486`)** aralığına alınmış ve tamamen **`conf/zmax.toml`** + ortam değişkenlerinden okunur hale getirilmiştir.

---

## 1. İncelenen Bileşenler

| Bileşen | Yol | Teknoloji | Görevi |
| :--- | :--- | :--- | :--- |
| **ZMax Server** | `D:\zmaxserver\crates`, `conf`, `admin` | Rust (Tokio) + Bootstrap 5 WebAdmin | Yüksek hızlı HTTP/Önbellek/WAF/FastCGI motoru, `127.0.0.1:19485` WebAdmin & `127.0.0.1:19486` Control API |
| **zPanel v2 Arayüzü** | `D:\lunixpanel\zpanelv2\web` | Vue 3 + TS + Vite + `vue-i18n` | Panel web arayüzü (`--zp-*` tema, Bootstrap **kullanmaz**) |
| **zPanel API** | `D:\lunixpanel\zpanel-tam\servis\api` | Node.js + Fastify + PostgreSQL | Yetkilendirme, ayar şemaları, `/v1/*` REST API |
| **zPanel Server Agent** | `D:\lunixpanel\zpanel-tam\cekirdek\agent` | Go (`zpanel-agent`) | Yerel sistem yönetimi (`127.0.0.1:8788` JSON-RPC) |

---

## 2. Popüler Paneller & Altyapı Port Envanteri vs. ZMax Bloğu

### 2.1. Dışlanan (Çakışmaya Kapalı) Popüler Panel ve Servis Portları

Aşağıdaki portlar yaygın kontrol panelleri, konteyner/proxy yöneticileri ve OS ephemeral havuzları tarafından kullanıldığı için **ZMax Server varsayılanlarında kesinlikle kullanılmaz**:

| Yazılım / Ekosistem | Kullandığı Varsayılan Portlar | Açıklama |
| :--- | :--- | :--- |
| **cPanel / WHM** | `2082, 2083, 2086, 2087, 2095, 2096` | HTTP/HTTPS panel ve Webmail |
| **Plesk / CloudPanel** | `8443, 8880` | Panel HTTPS/HTTP (ayrıca Tomcat) |
| **DirectAdmin** | `2222` | Kontrol paneli |
| **CyberPanel / OpenLiteSpeed** | `7080, 8088, 8090` | CyberPanel & OLS WebAdmin/örnek |
| **HestiaCP / VestaCP** | `8083, 8084` | Kontrol paneli |
| **aaPanel / BT / FASTPANEL** | `888, 7800, 8888` | Panel ve phpMyAdmin |
| **ISPConfig / ISPmanager** | `1500, 8080, 8081` | ISPConfig (`8080/8081`), ISPmanager (`1500`) |
| **CWP / Webuzo / Webmin** | `2002–2005, 2030, 2031, 2304, 10000, 20000` | Yönetim panelleri ve API |
| **Proxy / DevOps / Konteyner** | `81` (NPM), `2019` (Caddy Admin), `3000` (Grafana/Dokploy), `8000` (Ajenti/Coolify), `8404` (HAProxy), `9000` (MinIO/PHP-FPM/Portainer), `9090` (Prometheus/Cockpit), `9443` (Portainer) | Altyapı ve ters vekil yöneticileri |
| **zPanel Sabit Portları** | `80, 443, 8025/8026, 8035/8036, 8045/8046, 8047/8789, 8055/8056, 8080, 8088, 8091, 8443, 8787–8789, 8880` (+ Dev: `5273, 5274, 8766, 18055, 55433`) | `zpanel-tam` & `zpanelv2` dokunulmaz portları |
| **OS Ephemeral Havuzları** | Linux `32768–60999`, Windows `49152–65535` | Çekirdek giden bağlantı portları (kalıcı servis bağlanmaz) |

> **Özel Not:** Önceki taslaklarda bulunan `8081` (ISPConfig/Nexus ile çakışır) ve `8443` (Plesk/CloudPanel/zPanel ile çakışır) ve `8050` (zPanel `8055` yakını) tamamen **kaldırılmıştır**.

### 2.2. Yeni ZMax Server Çakışmasız Port Bloğu (`19480–19486`)

Tüm paketler (`win`, `linux-x64`, `linux-arm64`, `deb`, `rpm`) çalışma zamanında `conf/zmax.toml` (ve `ZMAX_*` ortam değişkenleri) üzerinden bu bloğu kullanır:

| ZMax Bileşeni | Yan Yana Varsayılan (Çakışmasız) | Birincil / Tam Devralma Modu | Yapılandırma Anahtarı (`zmax.toml`) | Ortam Değişkeni | IANA / Çakışma Durumu |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Web HTTP** | **`0.0.0.0:19480`** | `0.0.0.0:80` | `[listeners.http]` | `ZMAX_HTTP_PORT` | ✅ IANA Unassigned (`0` çakışma) |
| **HTTPS & HTTP/3 QUIC** | **`0.0.0.0:19483`** (`tcp`/`udp`) | `0.0.0.0:443` | `[listeners.https]`, `mod_quic` | `ZMAX_HTTPS_PORT` | ✅ IANA Unassigned (`0` çakışma) |
| **WebAdmin Konsolu** | **`127.0.0.1:19485`** | `127.0.0.1:19485` | `[listeners.admin]` | `ZMAX_ADMIN_PORT` | ✅ IANA Unassigned (yerel güvenli GUI) |
| **Evrensel Kontrol API** | **`127.0.0.1:19486`** | `127.0.0.1:19486` (veya `unix_socket`) | `[listeners.api]` | `ZMAX_API_PORT` | ✅ IANA Unassigned (yalnız panel/ajan API) |
| **Redis İstemci / FastCGI** | `127.0.0.1:6379` / `unix:` veya `127.0.0.1:9000` | `conf/vhosts/*.toml` | `mod_redis`, `[vhost.php]` | — | ✅ Sunucudaki mevcut PHP-FPM/LSPHP/Redis'e bağlanır |

*(Otomatik doğrulama: `zmax-config` unit testleri `KNOWN_PANEL_PORTS` listesine ve Linux ephemeral sınırına `< 32768` karşı çakışma olmadığını test eder.)*

---

## 3. Evrensel Panel Kontrol API Sözleşmesi (`127.0.0.1:19486`)

Herhangi bir hosting paneli (`zPanel`, `cPanel`, `Plesk`, `DirectAdmin`, `CyberPanel`, `HestiaCP`, `aaPanel`, özel PHP/Go/Node.js/Python ajanları) aşağıdaki uçlarla **tek noktadan** konuşabilir:

- **Kimlik Doğrulama:** `conf/zmax.toml` `[listeners.api]` altında `token = "..."` / `require_token = true` (veya `ZMAX_API_TOKEN`) tanımlandığında `Authorization: Bearer <token>` veya `X-ZMax-Token: <token>` zorunlu olur (yalnızca `/api/v1/health` public sağlık yoklamasıdır).
- **Linux Unix Soketi Desteği:** `[listeners.api] unix_socket = "/run/zmax/api.sock"` tanımlandığında aynı API HTTP-over-UDS olarak da dinler.
- **Sözdizimi Kontrolü (CLI):** `zmax -t` (`--check`) yapılandırma ve `conf/vhosts/*.toml` dosyalarını doğrulayıp çıkış kodu döner; `zmax -v` sürüm yazdırır.

| Metot & Yol | Görevi | Dönüş / Davranış |
| :--- | :--- | :--- |
| `GET /api/v1/health` | Hızlı canlılık yoklaması | `{"ok":true,"status":"ok","engine":"zmax","version":"1.0.01","pid":...,"uptime_seconds":...,"vhosts":...}` |
| `GET /api/v1/status` & `GET /api/status` | Telemetri + aktif portlar | `uptime_seconds`, `total_requests`, `cache_hits`, `cache_misses`, `workers`, `ram_mb`, `vhosts_loaded`, `active_sites`, `ports`, `listeners`, `cache`, `security` |
| `GET /api/v1/ports` | Port keşif ve çakışma denetimi | `{collision_detected, ports: {http, https, admin, api}, listeners, known_panel_ports}` |
| `GET /api/v1/config` | Yüklü yapılandırmayı okuma | Maskelenmiş güvenli JSON özet (token değeri açığa çıkmaz) |
| `POST /api/v1/reload` & `POST /api/reload` | Sıcak yeniden yükleme | Diskten `zmax.toml` + `conf/vhosts/*.toml` yenilenir, vHost tablosu ve rate limit güncellenir |
| `POST /api/v1/cache/purge` & `POST /api/purge` | Önbellek temizleme | Gövde boş ise tüm L1 önbelleği temizler; `{"uri":"..."}` veya `{"key":"..."}` varsa yalnızca o anahtarı siler |
| `GET /api/v1/vhosts` | Aktif sanal konak listesi | `conf/vhosts/*.toml` altından yüklenen domain, `aliases`, `document_root`, `php_upstream`, `cache` listesi |
| `GET /api/v1/vhosts/<domain>` | Tekil sanal konak detayı | Belirtilen domain kaydı (`404` yoksa) |
| `PUT /api/v1/vhosts/<domain>` & `POST /api/v1/vhosts` | Atomik site ekleme/güncelleme | Katı RFC domain doğrulaması (traversal korumalı), `.tmp -> rename` TOML yazımı + otomatik reload |
| `DELETE /api/v1/vhosts/<domain>` | Güvenli site kaldırma | `conf/vhosts/<domain>.toml` silinir + otomatik reload |

---

## 4. Dosya Sistemi ve PHP Upstream Eşlemesi

- **Host Bazlı Sanal Konak Yönlendirmesi:** `handle_web_connection`, gelen `Host` başlığını (portu sıyırarak) `conf/vhosts/*.toml` içinde `name` ve `aliases` alanlarıyla eşleştirir ve ilgili `document_root` dizinini path-traversal korumalı sunar.
- **PHP FastCGI / LSPHP Soket Desteği (`zmax-fastcgi`):** `[vhost.php] upstream` değeri hem TCP (`127.0.0.1:9000`) hem Linux Unix Domain Socket (`unix:/run/php-fpm/site.sock` veya `/tmp/lshttpd/lsphp83.sock`) biçimlerini doğal olarak destekler.
- **Klasik Panel Entegrasyon Yolu (`zpanel`):**
  1. `zpanel-tam/cekirdek/agent` tarafına ayrı bir `zmax` sürücüsü eklenir (OLS portlarına dokunulmaz).
  2. vHost ekleme/silmede `PUT http://127.0.0.1:19486/api/v1/vhosts/<domain>` veya `/var/www/vhosts/<domain>/httpdocs` hedefli TOML yazımı + `POST /api/v1/reload` kullanılır.
  3. Yan yana çalıştırmada ZMax `19480/19483` portlarında hizmet verir; OLS tamamen kapatılırsa panel `conf/zmax.toml` üzerinden `http=80`, `https=443` değerine geçirilir.

---

## 5. Önyüz (UI) ve Ters Vekil (Reverse Proxy) Entegrasyon Sözleşmesi

- **`zpanelv2/web`** Bootstrap içermez (`--zp-*`, `.bp-*`); ZMax WebAdmin ise **`127.0.0.1:19485`** üzerinde bağımsız **Bootstrap 5 + Vue 3** olarak kalır (`OLS :7080` / panel içi gömülü konsol modeli). WebAdmin portuna dışarıdan firewall/port açılması **gerekmez**.
- **Tam Göreli Yol Desteği (Önek Bağlantısız):** [`admin/index.html`](file:///D:/zmaxserver/admin/index.html), [`admin/js/core.js`](file:///D:/zmaxserver/admin/js/core.js) ve [`admin/js/app.js`](file:///D:/zmaxserver/admin/js/app.js) içerisindeki tüm varlık ve API yolları **görelidir** (`favicon.svg`, `css/...`, `js/...`, `assets/...`, `fetch('api/status')`, `fetch('api/v1/vhosts')`, `fetch('api/purge')`, `fetch('api/v1/cache/purge')`). Böylece hem doğrudan `http://127.0.0.1:19485/` kökünde hem de panel ters vekili altında (örn. `/v1/zmax/console/`) HTML/JS yeniden yazımı gerektirmeden çalışır.
- **Panel Ters Vekil Kuralları (`/v1/zmax/console/` → `127.0.0.1:19485`):**
  1. **Sondaki `/` (Trailing Slash) Zorunluluğu:** Tarayıcıdaki göreli yolların (`/v1/zmax/console/css/...` ve `/v1/zmax/console/api/...`) doğru çözülmesi için konsol mutlaka sonunda `/` ile (`/v1/zmax/console/`) açılmalıdır; panel vekiline `/v1/zmax/console` (slashtan yoksun) istek gelirse `301`/`302` ile `/v1/zmax/console/` adresine yönlendirilmelidir.
  2. **Önek Soyma (Prefix Strip):** `/v1/zmax/console/<alt_yol>` istekleri önek sıyrılarak sunucu içinde `http://127.0.0.1:19485/<alt_yol>` hedefine iletilmelidir (`GET /v1/zmax/console/` → `GET /`, `GET /v1/zmax/console/api/status` → `GET /api/status`).
  3. **Token Üretimi & Otomatik Başlık Enjeksiyonu (`Önemli Güvenlik Detayı`):** ZMax'ta [`route_api`](file:///D:/zmaxserver/crates/zmax-bin/src/api.rs) yönlendiricisi hem `19486` Control API hem de `19485` üzerinden gelen `/api/*` uçlarını ortak servis eder. Panel, `[listeners.api]` altında `token = "..."` ve `require_token = true` yapılandırdığında, **oturum doğrulamalı Panel Proxy'si `127.0.0.1:19485` (ve `19486`) hedefine ilettiği `/api/*` isteklerine sunucu tarafında `Authorization: Bearer <token>` veya `X-ZMax-Token: <token>` başlığını otomatik eklemelidir**. Böylece WebAdmin konsolunda API çağrıları `401 Unauthorized` hatası almaz ve token tarayıcı istemcisine kesinlikle sızdırılmaz.
  4. **İletişim Tipi:** WebAdmin WebSocket gerektirmez; her `2` saniyede bir HTTP `GET api/status` ve `GET api/v1/vhosts` sorgusu yapar (`ZMax` yanıtlarında `X-Frame-Options` engeli bulunmaz).

---

## 6. `v1.1+` Hedef Sözleşmesi: Az CPU, Sıfır Zafiyet, Çoklu İşlem ve Panel Tam Uyumu

LiteSpeed/OpenLiteSpeed olmadan Linux'ta `80/443` birincil moda güvenli geçiş için aşağıdaki sözleşmeler [`mimari/EKLENECEK_MIMARI.md`](file:///D:/zmaxserver/doc/mimari/EKLENECEK_MIMARI.md) tasarımına göre ZMax + ZePanel arasında uygulanacaktır:

1. **Alan Adına Özel Günlükler (`Eksik 5`):** `VHostEntry` altında `[vhost.logging]` (`access_log`, `error_log`, `format`, `max_log_size_mb`); panel vHost üretirken `/var/www/vhosts/<domain>/logs/access.log` ve `error.log` yollarını yazar, ZMax yüksek eşzamanlılıkta kanallı batch writer ile diske basar ve `X-Request-Id` Trace ID ekler.
2. **Alan Adına Özel WAF & Tam Security CRUD:** `[vhost.security]` içinde `waf_enabled`, `wp_brute_force`, `waf_exclude_paths`; `PUT /api/v1/vhosts/<domain>` üzerinden `hotlink_protection`, `allow_ips`, `deny_ips`, `waf_enabled`, `proxy_path_prefix`, `access_log`/`error_log` alanlarının tam JSON yönetimi.
3. **Çok Kiracılı İzolasyon (`suEXEC` + PHP FastCGI Güvenliği & Hızı):** Site başına ayrı Linux kullanıcısıyla çalışan PHP-FPM Unix soketi (`unix:/run/php-fpm/<domain>.sock`), ZMax'ta **HTTPoxy (`Proxy` -> `HTTP_PROXY`) engeli**, `FCGI_KEEP_CONN` kalıcı havuzu, streaming `FCGI_STDOUT` ve `X-Accel-Redirect` iç dosya devri.
4. **Panel/Webmail `80/443` Vekil Şablonları & Yetki Düşürme:** ZMax `panel.*` / `webmail.*` sitelerini otomatik üretmez; ZePanel `conf/vhosts/panel.*.toml` ve `webmail.*.toml` `[vhost.proxy]` dosyalarını oluşturur. ZMax Linux'ta `80/443` açtıktan sonra `setuid`/`nobody` yetkisine düşer ve `HTTP/2` (`h2`) + dahili `zmax-acme` + `SIGUSR2` kesintisiz yükseltme ile çalışır.
