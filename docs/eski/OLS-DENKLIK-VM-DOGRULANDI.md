# OLS denklik — VM DOĞRULANDI kayıtları (yerel VM, 2026-11-14)
Kural (sahip): "VM DOĞRULANDI" ise madde bitmiştir. Bu dosya yalnızca **gerçekten VM'de denenen** maddeleri işaretler; kapsamın dışında kalanlar işaretlenmemiştir.
Kaynak tablo: `D:\zmaxserver\doc\karsilastirma\OLS_DENKLIK.md` (ana kopyaya yazılmadı). Ortam: yerel VM, AlmaLinux 8.10, ZMax v1.0.08 (80/443 + panel portları), OpenLiteSpeed kapalı.

## VM DOĞRULANDI
| Madde | Kanıt (komut / çıktı) |
|---|---|
| A2 (kısmen): panel dinleyicileri 8026, 8036, 8047, 8056 | ZMax ek dinleyicileri; `curl -k https://127.0.0.1:<port>/` → 200 (dördü); tarayıcıda panel girişi ve tüm test sayfaları açıldı |
| A4: HTTP/2 | `curl --http2 -k https://<vhost>/` → `HTTP/2 200` (webmail ve test vhost'ları) |
| B1: docRoot, alan adı, alias | `webmail.panel.zpanel.local` + alias; `ornekdomain.com` http/https 200; reload sonrası yeni vhost 200 |
| B3 (kısmen): PHP çalıştırma | LSAPI ile `lsphp` 8.2/8.3/8.4/8.5: `$_GET`, `$_POST`, `$_COOKIE`, özel başlık, yanıt başlığı doğru; WordPress (`wp-login.php` 200, REST JSON, DB bağlantısı), Laravel (`/up` 200, güzel URL 404), Roundcube (giriş sayfası 200, CSS 200); 300 istek / 30 eşzamanlı hepsi 200 |
| Ters vekil (Node uygulaması) | `[vhost.proxy]`: GET 200, Türkçe karakter, POST gövdesi, Host korunur, X-Forwarded-For |
| Statik dosya + Range + sendfile | 5 MB dosya: tam indirme sha256 eşleşti; `Range: bytes=0-99` 206 içerik eşit; `bytes=-100` 206; geçersiz aralık 416 |
| WAF (SQLi, XSS) | `?id=1' OR 1=1--` ve `<script>` → 403, `waf_events.log` kuralı 942100/941100 |
| Güvenlik: path traversal | `../../etc/passwd` ve `%2e%2e/` → 403 |
| Önbellek | GET: MISS sonra HIT; `POST /api/v1/cache/purge` 200 |
| Hız sınırı / ban | Yanlış token: 5×401 sonra 403 (ban), `unban` çalışıyor |
| Yapılandırma yenileme | `POST /api/v1/reload` 200, `generation` artıyor; bozuk TOML'da eski yapılandırmada kalıp hata dönüyor |

## VM'DE DENENMEDİ (kapı için eksik — "bitti" sayılmaz)
- 24 saatlik çalışma; yük altında reload; OLS'e tek komutla geri dönüş.
- HTTP/3 (QUIC), TLS 1.2/1.3 sürüm müzakeresi, vhost başına sertifika zinciri.
- `www.` alias'ı, hata sayfaları (B9), vhost günlükleri (B10), istatistik/kota (B11), gzip/br (B12), `.htaccess` yönlendirmeleri (B4/B5/B7), ACME (B8), kiracı izolasyonu (site kullanıcısı ile `lsphp`).
- phpMyAdmin (8091), panelin tüm işlevleri (kalan sayfalar, CRUD), Git toolkit, Node toolkit uygulaması, Laravel komut çalıştırıcı (panel ajanı `php_missing`).
- Webmail panel bağlantısı (8046) eski adrese gidiyor.

## Sonuç
Yukarıdaki "VM DOĞRULANDI" satırları bitmiştir. **80/443 varsayılan yapma kapısı geçilmedi**: belgedeki zorunlu maddelerin çoğu (özellikle geri dönüş, 24 saat, yük altında reload, HTTP/3) VM'de denenmedi.
