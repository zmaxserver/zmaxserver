# VM-TEST 1.0.08 (yerel test VM'si, AlmaLinux 8.10)
Yükleme: linux-x64.tar.gz (sha256 ec5b96ef...), ikili+admin yedeği VM'de /root/zmax-yedek-107; mevcut v1.0.07 -> v1.0.08, yalnız zmax servisi yeniden başlatıldı.
| Madde | Sonuç |
|---|---|
| `zmax -v` | GEÇTİ: v1.0.08 |
| /api/v1/health | GEÇTİ: 200 version 1.0.08 |
| /api/status (eski yol) | GEÇTİ: 401 (token yok; 404 değil, token kapısı önce çalışıyor) |
| token yok/yanlış -> /api/v1/status, /metrics | GEÇTİ: 401 |
| token ile status, version, metrics, cache purge | GEÇTİ: 200 |
| audit.log kaydı | GEÇTİ: reload, cache-purge satırları |
| config/validate bozuk TOML | GEÇTİ: valid=false, error_line=1, error_field="." |
| config/validate geçerli | GEÇTİ: valid=true |
| SSE /logs/stream, /events | GEÇTİ: bağlantı satırı geldi (": connected", ": ok"); akan log satırı denenmedi |
| statik (Host: localhost :80) | GEÇTİ: 200 1116 bayt |
| Go köprüsü (tünelle) Version/Health/Validate/Status/PurgeCache | GEÇTİ |
| Go Reload | KALDI (P1): 500 |
## Bulgular
- P1: POST /api/v1/reload -> "vHost dosyası okunamadı (...ikincitest.com.toml): Permission denied". zmax `nobody` çalışıyor; vhosts/*.toml (ikincitest, ornekdomain, ucuncutest) root:root 0640 (09:34'te yazılmış). generation artmıyor (0). Kök sebep yazan tarafın dosya izni; zmax yazım/okuma sözleşmesi (0644 veya grup) tanımsız.
- P3: eski yol /api/status 404 değil 401.
## Denenemeyenler
Rate limit/ban, devre kesici (ZMax durdurma), vhost yazma+generation artışı (P1 engelledi), Range/sendfile, PHP, Redis, lifecycle .lock yazımı.
Not: bu VM'de zmax 80/443'ü de dinliyor (önceden yapılandırılmış); yeniden başlatma kısa kesinti yaptı.

## Hata testleri (2. tur)
- Ardışık yanlış token, VM dışından (19485): 5x 401 sonra 403 -> GEÇTİ. `/api/v1/security/bans`: reason "API ardisik hatali kimlik dogrulama", süre ~900 sn. `unban` -> unbanned:true, banned_count 0 (GEÇTİ).
- P1: error.log'a otomatik üretilen admin token düz metin yazılıyor ("[GUVENLIK] ... otomatik Admin token üretildi: <token>"; ayrıca journal). Log sızıntısı.
- P2: ban olayı audit.log'a yazılmıyor (yalnız reload/cache-purge satırları var; ban/unban satırı görülmedi).
- P3: error.log'da test artığı vhost "ornek.com.toml" (/tmp/TestACertificate... anahtar yolu) TLS atlandı uyarısı; VM conf'unda olmayan vhost.
- Varsayılan durum: zmax 80/443'ü dinliyor (OpenLiteSpeed yalnız 8026/8036/8047), zmax enabled.

## 3. tur: ZMax tek sunucu kontrolü
- OpenLiteSpeed kapalı (lsws inactive, enabled); ZMax 80/443 + ek dinleyiciler 8026/8036/8047/8056 (-> 8025/8035/8789/8055), hepsi 200.
- vhost: ornekdomain.com http/https 200 (WordPress, php83 soketi); ikincitest/ucuncutest 302.
- P2: webmail arka ucu (127.0.0.1:8045) hiçbir süreçte yok; 8046 dinleyicisi eklenemedi.
- P2: php82/php84/php85-php-fpm failed (09:32'den beri; php83 çalışıyor).
- P3: /phpmyadmin/ ornekdomain.com vhost'unda 404 (ZMax üzerinden phpMyAdmin yolu tanımsız).
- MariaDB 3306/PostgreSQL 5432/Redis 6379 yalnız loopback, web sunucusuyla ilgisiz; httpd 8080 arka uç olarak çalışıyor.
- P1 açık: /api/v1/reload vhost izni (root 0640, zmax nobody).
- Yapılandırma: zmax.toml'a 4 [[listeners.extra]] eklendi; yedek VM'de /root/zmax.toml.yedek-108.

## 4. tur: tüm işlevler (lsws kapalı, dokunulmadı)
GEÇTİ:
- SSE /logs/stream: gerçek access.log satırları akıyor. /events: ": ok" (bağlantı); purge sırasında olay satırı gelmedi (P3, olay üreten işlem tanımsız).
- Rol: read_token ile GET status 200; POST cache/purge 403; POST reload 403; token yok POST 401; admin 200; boş token 401. (geçici read_token eklendi, geri alındı, yedek /root/zmax.toml.pre-role)
- reload: vhost dosyaları 0644 yapılınca 200, generation 1->2->3 artıyor, audit.log "reload ok".
- Bozuk vhost (zt-bad.toml) reload: hata dosya/satır/sütun verdi (satır 1, sütun 7); generation 2'de kaldı, eski site 200; yanıtta vhosts_loaded=0 yanıltıcı (P3).
- Go köprüsü: Version/Health/Validate/Status/PurgeCache/Reload (generation 4) GEÇTİ; ZMax durdurulunca 3/3 çağrı ErrUnavailable "sunucuya ulasilamadi" GEÇTİ.
- lifecycle (VM'de linux ikilisiyle): geçerli vhost yazıldı (0644, atomik) -> reload ok, vhost 5, yeni vhost 200; bozuk TOML doğrulamada reddedildi, sağlık generation 1'de kaldı. .lock/.bak/.tmp kalıntısı yok.
- Redis: PONG, kanal zmax:events var.
- Ban: bkz. 2. tur. Loopback yanlış token x12: 401'de kaldı (loopback muaf, beklenen).
KALDI:
- P1: API vhost oluşturma: "Geçici vHost dosyası yazılamadı: Permission denied" (conf/vhosts root sahipli, zmax nobody). Silme yolu aynı kökten test edilemedi.
- P1 (kök sebep teyit): vhost dosyaları root 0640 iken reload 500; 0644 yapınca düzeldi (3 dosya chmod 0644 yapıldı).

## 5. tur: zPanel arayüzü (kullanıcının Chrome'u, 8036 ZMax ek dinleyicisi üzerinden)
GEÇTİ: giriş açık (root), Anasayfa, Müşteriler, Satıcılar, Alan Adları (3), Abonelik, İstatistikler, Hizmet Yönetimi, Araçlar ana sayfa açıldı. Servis Planları: ekle (zt-test-plan) -> düzenle (açıklama, "plan güncellendi") -> sil (onay penceresi) -> liste 6 plana döndü.
KALDI/ŞÜPHELİ (P2): Uzantılar > Katalog > Backup Toolkit "Yükle" tıklandı; 3 sn sonra Yüklü uzantılar "0 uzantı", hata/bildirim yok.
DENENMEDİ: müşteri/satıcı/abonelik/alan adı ekle-düzenle-sil, uzantı kaldır/yan menüde göster-gizle, /tools altındaki ~60 sayfa ve sekmeler, panel butonları (hizmet durdur/yeniden başlat bilerek basılmadı).
Panel notları: footer zPanel v1.0.07; panel "OpenLiteSpeed Durduruldu" gösterir (9/10 hizmet); zMaxServer portları 19480/19483/19485/19486 yazıyor (gerçekte 80/443 + 8026/8036/8047/8056).

## 6. tur: LSAPI istemcisi (tek PHP = LSPHP; php-fpm gereksiz)
- Kod: crates/zmax-fastcgi/src/lsapi.rs, vhost.php.sapi = "lsapi" (upstream = lsphp -b adresi). Commit vm-yukle.
- VM (yerel): lsphp 8.2/8.3/8.4/8.5 -b ile 4 geçici vhost: hepsi 200; sorgu dizesi, Cookie, özel başlık (X-Ozel), yanıt başlığı (X-Test) ve POST gövdesi doğru ($_GET/$_COOKIE/$_SERVER/$_POST). php_sapi_name()=litespeed.
- Birim testi: istek paketi yapısı, yanıtın CGI biçimine çevrilmesi (2/2).
- AÇIK: lsphp süreçlerini başlatıp ayakta tutan yönetici (systemd/zPanel), mevcut vhost'ların sapi=lsapi'ye taşınması, php-fpm'in kaldırılması; büyük yanıt, kesilen bağlantı, eşzamanlı yük testi yapılmadı.

## 7. tur: çekirdek hatalar (öncelik çekirdek, sonra panel)
- DÜZELTİLDİ (VM'de, ayar düzeyi): P1 vhost dizin izni. `conf/vhosts` root:nobody 2775, dosyalar 0664 (yedek /root/vhosts-yedek-*). Sonuç: API vhost oluştur 200 (nobody sahipli dosya), liste 5, HTTP 200, sil 200, dosya silindi, audit.log "vhost-kaydet/vhost-sil ok". Reload ok, generation artıyor.
- DÜZELTİLDİ (kod, commit 06af0db): P1 admin token günlüğe yazılmıyor; P2 ban olayı audit.log'a düşüyor.
- YANLIŞ ALARM: /events boş değil: reload "vhost_applied", bozuk vhost "config_rejected" olayı akıyor (cache purge olay üretmiyor, tasarım gereği). P3 geçersiz.
- KALIYOR (kalıcılık): `conf/vhosts` izni yeni kurulumda/paketle sağlanmalı (kurulum betiği + zPanel'in yazım modu 0640/root:root yerine group nobody). Paket betiği bu ağaçta yok -> paketle oturumunda yapılacak.
- KALIYOR P3: bozuk vhost'lu reload yanıtında vhosts_loaded=0 (sunucu eski yapılandırmada kalıyor, doğru değil yazıyor).
- KALIYOR P3: /api/status (eski yol) 404 yerine 401.

## 8. tur: toolkit ile yapılan uygulamalar (yerel VM, ZMax + LSAPI)
- BULGU (P1, panel/kurulum): kurulu `lsphp84` yalnız common/mysqlnd/pdo/xml/process/pear/devel paketleriyle geliyordu; **mbstring, opcache, intl, gd, bcmath yok**. Laravel (mbstring zorunlu) ve çoğu WordPress eklentisi bu haliyle çalışmaz. 8047 bileşen yöneticisi "gerekli tüm modüller" diyor. Test için `dnf install lsphp84-mbstring lsphp84-opcache lsphp84-intl lsphp84-gd lsphp84-bcmath` yapıldı (zpanel-litespeed deposu); VM'de kalıcı. Varsayılan PHP kurulumuna bu modüller eklenmeli (diğer sürümler 8.2/8.3/8.5 için de).
- Laravel (composer create-project, SQLite, `lsphp84 -b`, vhost `sapi="lsapi"`, kök `public/`): `/` 200 (70403 bayt), `/up` 200, `/yok-sayfa` 404 (Laravel'in kendi 404'ü: güzel URL -> index.php yönlendirmesi çalışıyor), `POST /` 405 (rota yok, doğru). GEÇTİ.
- Node (panelin node ikilisi, ters vekil `[vhost.proxy]`): GET 200 Türkçe karakter doğru, `/json` Host korundu + X-Forwarded-For, POST gövdesi 200. GEÇTİ.
- WordPress (ornekdomain.com belge kökü, `lsphp84` LSAPI, ayrı geçici vhost): `wp-login.php` 200 (başlık "Oturum aç ‹ ornek.com — WordPress", PHP hatası yok), ana sayfa 200, REST kökü JSON (veritabanı bağlantısı çalışıyor), `xmlrpc.php` 403. GEÇTİ.
- Temizlik: geçici vhost'lar, /var/www/zt, test süreçleri silindi; ornekdomain.com 200.
- DENENMEDİ: Docker (VM'de docker yok), Git/Composer/Node/Laravel/WordPress **toolkit sayfaları** (panelde yükle + kullan), PM2, kuyruk/cron, uzun yük.

## 9. tur: toolkit sayfaları ve gereksinimler (2026-11-14)
- 9 yerleşik toolkit panelden kuruldu (Docker, Laravel, Node, Git, WordPress, Repair, Migration, Monitoring, Backup): hepsi 201.
- Sayfa açılışları: Docker/Laravel/Node/Git açıldı, hata yok. Gereksinimler:
  - **Docker:** "Docker kurulu değil". `dnf install docker-ce ...` AlmaLinux 8'de podman/buildah/runc ile çakışıyor; çözüm `--allowerasing` podman, buildah, cockpit-podman, podman-catatonit paketlerini SİLER (VM'de podman konteyneri yok). Silmeden önce sahip onayı bekleniyor. Alternatif: `podman-docker` (silmeden, docker komut uyumu).
  - **Node:** "Node.js 18/20/22 kurulu değil" (sürüm kurulumu panel Node toolkit arayüzünden; kurulum kaynağı/yolu henüz çözülmedi).
  - **Laravel:** 0 uygulama bulundu (tarama için alan adı belge kökünde `artisan` + `composer.json` olan bir Laravel projesi gerekli).
  - **Git:** 3 alan adı, depo bağlı değil (bağlamak için bir git deposu adresi gerekli).
