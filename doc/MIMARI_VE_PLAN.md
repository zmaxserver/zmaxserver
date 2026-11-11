# ZMax Server — Mimari

**Amaç:** katmanlar, crate sorumlulukları, istek hattı ve Rust↔Go sözleşmesi (kalıcı mimari kararlar). **Güncellenir:** mimari karar değişince; durum/test bilgisi buraya yazılmaz. **Bağlı:** durum → [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md) · fazlar → [`YOL_HARITASI.md`](YOL_HARITASI.md) · görevler → [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) · panel sözleşmesi → [`entegre/goentegre.md`](entegre/goentegre.md) · kurallar → [`YAPAY_ZEKA_KURALLARI.md`](YAPAY_ZEKA_KURALLARI.md)

ZMax: saf Rust HTTP/HTTPS/FastCGI web sunucusu (`zmax` Linux, `zmax.exe` Windows). Panel: ZPanel (Go, `D:\lunixpanel\zpanel-tam`, bu depoda değiştirilmez). **Hedef (sahip): OpenLiteSpeed ile denk ve hatasız** → [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md).

## 1. Katmanlar — Rust korur, Go birleştirir
```
İstemci ► ZMax (Rust) 80/443: TLS, hız sınırı, WAF, önbellek, vhost, .htaccess, FastCGI/statik/vekil, günlük
             ▲ reload (POST :19486/api/v1/reload | SIGHUP)        │ vhost TOML (salt okunur)
          ZPanel (Go): vhost TOML yazar, php-fpm havuzu, certbot, güvenlik duvarı, günlük/trafik/kota, kurulum/geri dönüş
```
| Sorumluluk | Rust (ZMax) | Go (ZPanel) |
|---|---|---|
| HTTP/HTTPS, TLS, ALPN, önbellek, WAF/DoS, günlük yazma/döndürme, ACME dosyası sunumu | ✅ | dokunmaz |
| vhost TOML yazımı, php-fpm havuzu/kullanıcı/soket, certbot, güvenlik duvarı, kurulum, OLS'e dönüş | ❌ | ✅ |
| Günlük sayfası, trafik/kota, ban listesini güvenlik duvarına yazma | ❌ | ✅ |
Kural: Rust yönetim kararı vermez, Go trafiğe dokunmaz; Go'nun mevcut işi Rust'ta yeniden yazılmaz.

## 2. Crate sorumlulukları (18; başka crate yok)
| Crate | Sorumluluk |
|---|---|
| `zmax-core` | ortak tipler, zaman damgası, CPU afinitesi, `drop_privileges` |
| `zmax-runtime` | Tokio worker, sinyaller (SIGTERM/SIGHUP/SIGUSR1/SIGUSR2), zarif kapanma |
| `zmax-pool` | `BufferPool`, `UpstreamSocketPool`, `UpstreamBalancer` |
| `zmax-tls` | TLS 1.2/1.3, SNI, ALPN, sertifika yeniden yükleme |
| `zmax-timeout` | Slowloris/zaman aşımları |
| `zmax-httpparser` | HTTP/1.1 ayrıştırıcı, PROXY Protocol, smuggling reddi, gerçek IP |
| `zmax-header` | başlık haritası, güvenlik başlıkları |
| `zmax-fastcgi` | PHP-FPM (TCP/UDS), HTTPoxy engeli, `FCGI_KEEP_CONN` havuzu |
| `zmax-proxy` | ters vekil, WebSocket |
| `zmax-static` | statik dosya (ETag/Range/WebP/AVIF/yan dosya/`sendfile`), `error_docs` çözümleyici |
| `zmax-cache` | Moka L1, disk L2, tag purge, SWR, stampede, LSCache başlık köprüsü |
| `zmax-rewrite` | `.htaccess` (kök+alt klasör), `try_files`, `PATH_INFO` |
| `zmax-security` | WAF (global + vhost), hız sınırı, ACL, hotlink, WP brute-force |
| `zmax-compress` | Gzip, Brotli |
| `zmax-config` | TOML vhost şeması + reload |
| `zmax-redis` | RESP2, Pub/Sub olayları |
| `zmax-obfuscate` | derleme anı dize şifreleme ([`sifleme.md`](sifleme.md)) |
| `zmax-bin` | `main.rs`, `web_engine.rs` (HTTP/1.1), `h2_engine.rs` (HTTP/2), `logger.rs` (vhost günlüğü), `api.rs` (Control API + WebAdmin), `modules_runtime.rs` |

Var olmayan crate'ler **var sayılmaz**: `zmax-realip`, `zmax-metrics`, `zmax-log`, `zmax-acme`, `zmax-cli`, `zmax-quic`, `zmax-auth`, `zmax-botshield`, `zmax-appserver`. Yeni crate yalnız hiçbir mevcut crate'e sığmıyorsa, gerekçe yazılarak açılır.

## 3. İstek hattı sırası
`hız sınırı → WAF (IP/URL, vhost `waf_enabled`/`waf_exclude_paths`) → vhost bulma (Host/`:authority`) → .htaccess (rewrite) → FastCGI | statik | vekil`. `.htaccess ErrorDocument` ve vhost `error_docs` ortak hata yanıtı fonksiyonundan geçer. Hangi adımın bugün bağlı olduğu: matris.

## 4. Rust ↔ Go sözleşmesi
Go vhost TOML'unu `/usr/local/zmax/conf/vhosts/<alan>.toml` olarak atomik yazar (geçici dosya + rename) → `POST http://127.0.0.1:19486/api/v1/reload` (ya da SIGHUP) → ZMax doğrular, atomik uygular; hata varsa eski yapılandırmada kalır. TOML alanı değişirse iki taraf birlikte güncellenir. Portlar, API, TOML örneği, günlük sözleşmesi: [`entegre/goentegre.md`](entegre/goentegre.md).

## 5. ZMax'i 80/443 varsayılan yapma şartı
OpenLiteSpeed, [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) §2 kabul kapısı (v1.0.10) kanıtla geçilene kadar varsayılan kalır. Kapı: yan yana test, 5 gerçek uygulama, panel işlevleri, 24 saat dayanıklılık, yük altında reload, OLS'e tek komutla dönüş. Panel/Go bekleyen işleri: `entegre/goentegre.md` §7.

## 6. Değişmez ilkeler
Önce gerçek durum · modül çoğaltma yok · çalışanı bozma (hatalı yapılandırmada eskisine dön) · kanıtsız söz yok (ALPN `h2` duyurusu ≠ HTTP/2; birim test ≠ üretim) · güvenlik performans uğruna kaldırılmaz. Tam liste: [`YAPAY_ZEKA_KURALLARI.md`](YAPAY_ZEKA_KURALLARI.md), [`YOL_HARITASI.md`](YOL_HARITASI.md) §1.
