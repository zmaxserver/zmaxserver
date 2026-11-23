# ZMax v1.0.08 - OLS denklik ek testleri (yerel VM 192.168.131.131, 2026-11-14)

Ortam: test vhost'lari zt-a.local / zt-b.local (conf/vhosts, 0664 grup nobody) yazildi, test bitince silindi ve reload edildi (vhosts_loaded=5, zmax active). ZMax durdurulmadi/yeniden baslatilmadi; yalniz POST /api/v1/reload.

## 1) Yuk altinda reload - GECTI (bir uyariyla)
- Temiz kosu: 20 esli `xargs -P 20 curl` (cift istek statik big.txt, tek istek PHP t.php), 1200 istek, bu sirada 10 reload.
  Cikti: `1200 200`; reload basarisiz=0; 5xx=0; kesinti yok.
- Ilk deneme (6000 istek, bekleme yok, 10 reload): `3876 200 / 2124 429`, 5xx=0, reload basarisiz=0. 429'lar reload'dan degil, IP basina hiz siniri (zmax.toml rate_limit_per_minute=2000) kaynakli: reload'suz taban kosu da `2000 429` verdi (pencere dolmustu). 
- Not: bu sinir, tek IP'den (panel/yuk testi) gelen yogun trafigi 429'a cevirir; OLS'te varsayilan boyle degil. Hata degil, bilinmesi gereken fark.

## 2) Ozellikler
- www alias'i - GECTI: `Host: www.zt-a.local` -> 200.
- Ozel hata sayfasi - GECTI: `[vhost.error_docs.pages]` altinda `404="404.html"` ve `403="403.html"` tanimliyken `/yok.html` -> govde `ERR404-OZEL` kod 404; `/yasak/` (indeks yok) -> `ERR403-OZEL` kod 403. Pages tablosu bos iken varsayilan ZMax sayfasi (`404 Not Found - ZMax Server 404`) donuyor (beklenen).
- Vhost gunlugu - KISMEN: access.log yaziliyor (combined, ornek: `"GET /yasak/ HTTP/1.1" 403 13`). error.log dosyasi hic olusmadi (403/404 error log'a yazilmiyor veya yalniz gercek hata aninda aciliyor) - DENENEMEDI/BELIRSIZ; OLS'teki gibi 404/403'un error log'a dusup dusmedigi dogrulanamadi.
- gzip - GECTI: `Accept-Encoding: gzip`, 20000 baytlik big.txt -> `Content-Encoding: gzip`, `Content-Length: 148`. Not: kucuk HTML (22 bayt) sikistirilmadi (esik, makul).
- Brotli - KALDI: `Accept-Encoding: br` -> Content-Encoding yok, 20000 bayt duz donuyor. Brotli desteklenmiyor (OLS br destekler).
- PHP - GECTI (yan bulgu): `t.php` -> `ZT-PHP 2` (docroot ikincitest httpdocs altinda). Docroot /var/www/zt-test altindayken `No input file specified.` dondu: ikincitest'in php-fpm havuzu kendi dizini disini (open_basedir/yol siniri) kapsamiyor; ZMax hatasi degil, havuz siniri.

## 3) HTTP/3 (QUIC) - KALDI (sunucu), istemci DENENEMEDI
- VM curl 7.61.1 (nghttp2, brotli var; HTTP3 yok) -> `curl --http3` yapilamaz.
- `ss -lunp | grep :443` -> UDP 443'u dinleyen yok (yalniz litespeed 8046 UDP: OLS'in kendi panel portu, QUIC). TCP 80/443'u zmax tutuyor.
- HTTPS yanitinda `alt-svc` basligi yok (`HTTP/2 200`, alt-svc yok). Sonuc: ZMax HTTP/3 sunmuyor; HTTP/2 var.

## 4) TLS - GECTI
- `-tls1_2`: `New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384` (sertifika self-signed uyarisi beklenen).
- `-tls1_3`: `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384`.
- `-tls1_1`: `sslv3 alert handshake failure`, `Cipher is (NONE)` -> reddediliyor. (Reddin sunucudan geldigi alert 40 ile gorulur.)

## 5) .htaccess yonlendirme - GECTI
Docroot altina .htaccess (RewriteEngine On; RewriteRule R=301/302; RewriteCond HTTP_HOST www; RewriteCond HTTPS !=on) yazildi:
- `/eski.html` -> `301 Moved Permanently`, Location `http://zt-b.local/yeni.html`
- `/gecici.html` -> `302 Found`, Location `http://zt-b.local/yeni.html`
- `Host: www.zt-b.local` -> `301`, Location `http://zt-b.local/index.html` (www -> non-www)
- HTTP'de `/zorla.html` -> `301`, Location `https://zt-b.local/zorla.html` (Force HTTPS)
Not: goreli hedef (`/yeni.html`) Location'da mutlak (`http://zt-b.local/...`) uretiliyor; islevsel olarak gecerli.

## 6) OLS'e tek komutla geri donus - (calistirilmadi, yalniz okundu)
Betik VAR: D:\zmaxserver\zmax-gecis.sh (146 satir, VM'de `sh zmax-gecis.sh [--kontrol | --geri-al]`).
- `--geri-al`: zmax.toml'u son yedekten (`zmax.toml.gecis-yedek`) geri yukler, ajan `-zmax-siteler ols-yenile` ile OLS 80/443 dinleyicilerini yeniden yazar, ZMax yeniden baslatilir (`geri_al`).
- Seceneksiz: vhost'lari yazar, test portlarinda sinar, hepsi gecerse ZMax'i 80/443'e alir ve OLS dinleyicilerini kaldirir; hata olursa otomatik eski hale doner.
- `/etc/zpanel/webserver` icinde `openlitespeed` yaziyorsa betik ZMax'i 19480/19483'e indirip OLS'i 80/443'e dondurur (tek komutla secim). Panel portlari (8026/8036/8046/8047/8056) OLS'te kalir, betik dokunmaz.
- Durum: bu test sirasinda calistirilmadi (ZMax'i durdurur).

## Ozet
GECTI: 1, 2 (www, ozel hata, gzip), 4, 5. KALDI: Brotli, HTTP/3. KISMEN/BELIRSIZ: error.log yazimi. 6 yalniz okundu. Kod duzeltilmedi.
