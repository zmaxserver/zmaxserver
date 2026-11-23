# Düzeltilen hatalar (VM-TEST 1.0.08, 2026-11-14)
Dal: vm-yukle (D:\zmaxserver\katmanlizmax\doc\agaclar\vm). Push yok. Ayrıntı: VM-TEST-1.0.08.md.

| # | Önem | Hata | Düzeltme | Doğrulama |
|---|---|---|---|---|
| 1 | P1 | Otomatik üretilen admin token error.log/journal'a düz metin yazılıyordu | crates/zmax-bin/src/api/auth.rs: mesaj tokenı yazmaz (06af0db) | VM: error.log/journal'da `zmax_adm_` sayısı 0 |
| 2 | P2 | Ban olayı audit.log'a yazılmıyordu | api/guard.rs: ban'da `audit::kayit("ban")` (06af0db) | VM: `| api | bilinmiyor | ban | <ip> | ok` satırı |
| 3 | P1 | API vhost oluşturma/reload `Permission denied` (conf/vhosts root:root 0640, zmax nobody) | VM ayarı: conf/vhosts root:nobody 2775, dosyalar 0664 (yedek /root/vhosts-yedek-*) | VM: oluştur 200, HTTP 200, sil 200, reload generation artıyor, audit vhost-kaydet/sil ok |
| 4 | P1 | PHP: yalnız FastCGI, LSPHP (LSAPI) bağlanamıyordu (2 tür PHP gerekiyordu) | crates/zmax-fastcgi/src/lsapi.rs + vhost.php.sapi="lsapi" (7d0c3e7) | VM: lsphp 8.2/8.3/8.4/8.5 hepsi 200; GET/Cookie/özel başlık/POST doğru; birim test 2/2 |
| 5 | P2 | /api/v1/status `ram_mb` sabit 12 yazıyordu (sahte metrik) | api/routes/system.rs: /proc/self/statm gerçek RSS | cargo test geçti; VM doğrulaması aşağıda |
| 6 | P3 | Reddedilen reload yanıtında `vhosts_loaded:0` (yanlış) | api/services/config_service.rs: gerçek yüklü sayı | cargo test geçti; VM doğrulaması aşağıda |

## Yanlış alarm / geçersiz
- /events boş sanılmıştı: reload "vhost_applied", bozuk vhost "config_rejected" olayı akıyor (cache purge olay üretmez, tasarım).
- php82/84/85-php-fpm "failed": bu birimler hiç etkin değil; LSAPI yoluyla gereksiz.

## Açık (çekirdek)
- conf/vhosts izni kalıcı değil: paket/kurulum betiği + zPanel yazım modu (0640 root:root) grup `nobody` olmalı.
- lsphp süreçlerini başlatıp ayakta tutan yönetici yok; vhost'lar hâlâ php-fpm kullanıyor.
- Go köprüsü Status modeli: sunucu `ram_mb` gönderir, Go `memory_usage_kb`/`active_connections` bekler -> 0 dönüyor (go dizini bu oturumun kapsamı dışı, düzeltilmedi).
- /api/status eski yol 404 yerine 401 (P3).

## 2. liste (WebAdmin / paket)
| # | Önem | Hata | Düzeltme | Doğrulama |
|---|---|---|---|---|
| 7 | P0 | WebAdmin (19485) siyah ekran: pakette `admin/js/app.js` yok, `index.html` yüklüyor -> `SyntaxError: Unexpected token '<'`. Kök sebep: `doc/tools/pack_zmax.py` `sync_admin` app.js ve css/admin.css'i "eski" diye siliyor | VM'ye app.js kopyalandı. KALICI: pack_zmax.py'de app.js silme listesinden çıkarılmalı (betik D:\zmaxserver\doc\tools, paketle oturumu) | VM: WebAdmin açılıyor, konsol hatası yok. tar.gz/deb/rpm admin/ eksik, yeniden paketlenmeli |
| 8 | P2 | WebAdmin sürümü sabit "v1.0.01" (altbilgi, karşılama kartı, sunucu bilgisi) | Sürüm /api/v1/status `version` alanından; karşılama kartındaki sürüm kaldırıldı (sahip isteği); altbilgi ve motor satırı dinamik | Tarayıcı: "ZMax Server v1.0.08" (altbilgi + motor satırı), kartta yok |
| 9 | P1 | Panel->WebAdmin geçişi anahtarsız | ZMax tarafı hazır (`#token=`/`?token=` okunuyor). Panel bağlantısı `#token=<admin token>` ile üretilmeli | PANEL KODU KAPSAM DIŞI, açık |
AÇIK: WebAdmin'de sabit "PHP-FPM FastCGI 127.0.0.1:9000" etiketi (i18n.js, app.js), "Boşta RAM" etiketi; panel "uzantı Yükle" çalışmıyor.

## 3. liste (WebAdmin düğmeleri, hız sınırı) — commit 69af6b6
| # | Önem | Hata | Düzeltme | Doğrulama |
|---|---|---|---|---|
| 10 | P1 | "Tümünü Önbelleği Boşalt" düğmesi API'yi çağırmıyordu (`@purge-all-cache="fetchStatus"`, yalnız durumu yeniliyordu) | app.js `purgeAllCache` (POST /api/v1/cache/purge + bildirim) | Tarayıcı: POST 200, "Tüm önbellek başarıyla temizlendi" |
| 11 | P2 | "Yenile" düğmesi görsel geri bildirim vermiyordu | `refreshNow` + "Durum yenilendi" bildirimi (tr/en/de/fr/ru) | İstekler 200, bildirim çıkıyor |
| 12 | P1 | WebAdmin kendi hız sınırına takılıyordu: 5 uç nokta x 2 sn yoklama = 150/dk, API sınırı 120/dk -> 429, sayfa 0 gösteriyor | yoklama 5 sn; varsayılan `api_rate_limit_per_minute` 120 -> 600 (zmax-config) | VM: 200 ardışık istekte 429 = 0 |
| 13 | P3 | Başlıkta aynı işi yapan iki düğme ("Oturum Açık" + "Yönetici") | "Yönetici" düğmesi kaldırıldı (sahip emri) | Tarayıcı: başlıkta yalnız "Oturum Açık" |

# SONRAYA YAPILACAK İŞ / GELİŞTİRME NOTLARI (sahip, 2026-11-14)
- Bot kontrol ekranı (Cloudflare "tarayıcı doğrulanıyor" benzeri): ZMax'te vhost/site bazında açılıp kapatılabilen robot doğrulama sayfası. Ayarı zPanel'de `/tools/web/zmax/settings` sayfasından açılıp kapanacak. Henüz kodlanmadı; tasarım ve onay bekliyor.

## 4. liste (panel + köprü) — 2026-11-14
| # | Önem | Hata | Düzeltme | Doğrulama |
|---|---|---|---|---|
| 14 | P1 | Panel uzantı "Yükle" 500: `ext_installed_version_check` ihlali. Kök sebep: mağaza yayımlı sürüm göndermediği için tüm uzantıların `version` değeri "" ; yerleşik (BUILTIN) uzantı kaydı `entry.version` ile yazılıyor | Kaynak: D:\lunixpanel\zpanel\araclar\is\api-work\src\modules\extensions\index.ts (yerleşikte sürüm geçersizse PANEL_VERSION). VM'de derlenmiş dist/modules/extensions/index.js'e aynı yama (yedek /root/ext-index.js.yedek), zpanel-api yeniden başlatıldı | Tarayıcı: Yükle 201; Devre dışı/etkinleştir, Yeniden yükle, Ayarlar > "Kenar menüsünde göster" (menüde Backup Toolkit çıktı, sayfası açıldı), Kaldır (liste boş, menü kalktı) hepsi çalıştı |
| 15 | P2 | WebAdmin'de sabit "PHP-FPM" etiketleri (LSAPI'ye geçişte yanlış) | i18n.js: "PHP-FPM" -> "PHP" (15 yer) | VM'ye yüklendi, sayım 0 |
| 16 | P2 | Go köprüsü `Status()` bellek 0 dönüyordu (sunucu `ram_mb` gönderir) | models.go `RAMMB`, client.go `Status` KB türetir | go test ./... (aşağıya bakın) |
NOT: panel kaynağı git deposu değil; derlenmiş paket ve zpanel-api yeniden üretilmeli (paketle-zpanel oturumu). VM'deki yama yalnız bu test VM'sinde.
AÇIK: `/api/status` eski yol 404 yerine 401 (tasarım, P3); pack_zmax.py `app.js` silme (paketleme).

## 5. liste — 2026-11-14 (commit ZMax: "eski /api/<ad> yolları 404")
| # | Önem | Hata | Düzeltme | Doğrulama |
|---|---|---|---|---|
| 17 | P3 | `/api/status` (eski yol) 404 yerine 401 | api/mod.rs: `/api/` altında `/api/v1/` olmayan yollar kimlik doğrulamadan önce 404 | VM: /api/status 404, /api/purge 404, /api/v1/health 200, /metrics 401, v1/status+token 200; cargo test geçti |
| 18 | P2 | Panel Node toolkit sürüm listesi sabit 18/20/22; 24/26 yok | Kaynak: api-work validate.ts, web-work node-versions.ts -> 20/22/24/26. VM'de dist yamalı (yedekler /root/validate.js.yedek, /root/node-versions.js.yedek) | Tarayıcı: Node.js 20, 22, 24, 26 listede, "kurulu değil" yok (VM'de /opt/zpanel/node/20,22,24,26 kuruldu) |
| 19 | P1 | zplus-webmail uzantısı kurulunca OpenLiteSpeed'i (litespeed süreci) kendiliğinden başlattı (lsws "kapalı kalacak" talimatına aykırı) | Süreç elle durduruldu (`lswsctrl stop`); uzantı kurulumunun OLS başlatması AÇIK | VM: litespeed süreci yok |

## AÇIK (bu turda bitmedi)
- **Webmail:** Roundcube `/var/www/roundcube/public_html/` OLS vhost'u (8045/8046) tarafından sunuluyor; OLS kapalı olduğundan webmail kapalı. ZMax'te Roundcube'u LSAPI ile sunmak için vhost + 8046 TLS dinleyici modeli (ek dinleyici yalnız ters vekil destekler) tasarlanmalı.
- **Panel -> WebAdmin anahtarlı link:** Panel web kodu `adminToken` varsa `?token=` ekliyor (ZmaxConsoleView.vue), ama API (`/v1/zmax/status`) `adminToken` döndürmüyor; panel ZMax token'ını bilmiyor (ZPANEL_ZMAX_TOKEN yok, zmax.toml'u agent okuyor). Çözüm: agent `zmax.toml`'dan admin token'ı yalnız yazma yetkisine açık bir uçta döndürmeli (panel ajanı ayrı ikili).
- **phpMyAdmin:** ZMax'te `/phpmyadmin/` yolu tanımsız (404); nereden sunulacağı (ayrı port/vhost) kararı yok.
- **Paketleme:** pack_zmax.py `app.js` silme (paketle oturumuna iletildi, doğrulanmadı); yeni ikili/panel paketleri üretilmedi.
- **Kurulum betiği:** gereksinim.md'deki modül/araç/izin ayarları betiğe işlenmedi; `lsphp` süreç yöneticisi yok; lsws hâlâ `enabled`.
- **Test edilmedi:** Laravel/Git toolkit sayfaları, panelin kalan sayfaları ve CRUD'ları.

## 6. liste — Webmail ZMax üzerinden (sahip kararı: hostname vhost)
- Çözüm: ZMax vhost `webmail.panel.zpanel.local` (alias `webmail.zpanel.local`), belge kökü `/var/www/roundcube/public_html`, `sapi="lsapi"`, upstream `127.0.0.1:31946`; `lsphp85 -b` için systemd birimi `zmax-lsphp-roundcube.service` (User=nobody, Restart=on-failure, enabled). OpenLiteSpeed gerekmez.
- Doğrulama (VM): giriş sayfası 200 ("zPanel Webmail"), CSS 200, HTTPS h2 200, PHP hatası yok, ornekdomain.com 200, litespeed süreci 0.
- Erişim: istemci bilgisayarda `192.168.131.131 webmail.panel.zpanel.local` hosts kaydı (DNS yoksa). Panelin 8046 yönlendirmesi/uzantı bağlantısı bu adrese çevrilmeli (panel kodu, AÇIK).
- Kalan: aynı kalıp diğer PHP vhost'lar için `lsphp` birimi üretmeli (lsphp süreç yöneticisi); kurulum betiği.

## 7. liste — ÇEKİRDEK (Rust/LSAPI), commit "LSAPI: lsphp PID bildirimi"
| # | Önem | Hata | Düzeltme | Doğrulama |
|---|---|---|---|---|
| 20 | P2 | LSAPI istemcisi her istekte `error.log`'a bozuk `[PHP STDERR] ... PID<ikili>` satırı yazıyordu (lsphp'nin "\0PID"+pid bildirimi hata çıktısı sanılıyordu) | zmax-fastcgi/src/lsapi.rs: 8 bayt "\0PID.." STDERR paketi atlanır; birim testi eklendi | VM: 3 istek sonrası PHP STDERR satırı 0; 300 istek / 30 eşzamanlı hepsi 200, FastCGI Hata 0, zmax active; birim test 3/3 |
NOT: Sahip talimatı: yan işler değil, çekirdek hatalar öncelik. phpMyAdmin hostname vhost denemesi geri alındı (config `signon`, /phpmyadmin/ yoluna ve panel oturumuna bağlı; ayrı karar). docs/kurulum/gereksinim-kur.sh taslak (VM'de çalıştırılmadı).

## 8. liste — Laravel Toolkit (2026-11-14, giriş yapılmış panel)
- GEÇTİ: Laravel Toolkit > "Alan adlarını tara": `ucuncutest.com` altındaki `zt-laravel` (Laravel 13.42.0) bulundu; ▶ ile etkinleştirildi; liste "Etkin alan adı 1, Bulunan uygulama 1", ortam `local`, bakım "Kapalı"; uygulama araç sayfası açıldı (komut çalıştırıcı, bakım modu, .env, kuyruk işçisi, günlük bölümleri görünüyor).
- KALDI (P1, panel ajanı): Komut çalıştırıcı "Çalıştır" -> `POST .../actions/artisan` 409 `nl.php_missing` ("Alan adının PHP sürümüne ait php komut satırı ikilisi bulunamadı"). Alan adı PHP 8.3 (php-fpm/fastcgi), `lsphp83` kurulu ve site kullanıcısıyla çalışıyor (`PHP 8.3.36`), ama panel ajanı CLI'yi bulamıyor (Remi `php83-php-cli` yok; ajan ikilisi hangi yolu aradığı belirsiz). "PHP sürümü" kartı "-" (okunamadı).
- KALDI (P2, panel arayüzü): 409/hata dönünce arayüz hiçbir uyarı göstermiyor (düğme sessiz kalıyor).
- Çözüm yolu: tek PHP politikası (LSPHP) için panel ajanı CLI'yi `lsphpNN/bin/php` olarak çözmeli; geçici: Remi `php83-php-cli` kurulumu (ikinci PHP türü, sahip karar versin). Panel ajan ikilisi bu oturumun kapsamı dışı.
- Test dosyaları VM'de: /var/www/vhosts/ucuncutest.com/zt-laravel (silinmedi; Laravel Toolkit kaydı etkin).
