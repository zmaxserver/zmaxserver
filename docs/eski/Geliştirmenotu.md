# Geliştirme Notu (sonraya yapılacak işler)
Kaynak: sahip talimatı, 2026-11-14. Bu dosyadaki işler **henüz kodlanmadı**; sahip "yap" demeden başlanmaz.

## 1. Bot kontrol ekranı (Cloudflare "tarayıcı doğrulanıyor" benzeri)
**İstek:** ZMax'te robot doğrulama sayfası. Ayar, zPanel'de `https://<sunucu>:8036/tools/web/zmax/settings` sayfasından açılıp kapatılacak.

**Yorum / öneri (onay bekliyor):**
- Varsayılan **kapalı**; site (vhost) bazında açılır.
- Önce yalnızca **saldırı altında** devreye girsin (ban/kimlik doğrulama hata eşiği aşılınca), sürekli açık mod ikinci aşama.
- **Muaf:** arama motoru botları (doğrulanmış Googlebot/Bingbot), `/api/` ve webhook yolları, kayıtlı beyaz liste IP'leri, loopback.
- Doğrulama: JavaScript sınaması veya hafif proof-of-work; geçince imzalı, süreli çerez (ör. 30 dk). Çerez sunucu tarafında doğrulanır.
- Gerçek korumayı IP itibarı ve davranış analizi verir; ekran tek başına yetmez, WAF ve ban sistemini tamamlar.
- Risk: gerçek ziyaretçide sürtünme, SEO botlarının engellenmesi, API/webhook istemcilerinin kırılması → muaf listesi şart.

**Parçalar:**
1. ZMax (Rust): vhost ayarı (`bot_check.enabled`, `mode = "attack" | "always"`, `exempt_paths`, `exempt_ips`, `cookie_ttl_sec`), doğrulama sayfası, imzalı çerez, `audit.log` kaydı.
2. WebAdmin (19485): ayar ekranı.
3. zPanel (Go/Vue, `/tools/web/zmax/settings`): açma/kapama ve muaf listesi (panel kodu ayrı oturum).

## 2. Açık çekirdek işler (bu turlardan kalan)
- `lsphp` süreçlerini başlatıp ayakta tutan yönetici (systemd/zPanel); vhost'ları `sapi = "lsapi"`'ye taşıma; php-fpm'i kaldırma. LSAPI istemcisi hazır (commit 7d0c3e7), VM'de 8.2–8.5 doğrulandı; büyük yanıt, kesilen bağlantı, eşzamanlı yük testleri yapılmadı.
- `conf/vhosts` izni kalıcı olmalı: kurulum/paket betiği + zPanel yazım modu (grup `nobody`).
- Paketleme: `pack_zmax.py` `admin/js/app.js` dosyasını siliyor → WebAdmin siyah ekran; paketler yeniden üretilmeli.
- Panel → WebAdmin geçiş linki `#token=<anahtar>` ile üretilmeli (ZMax tarafı hazır).
- WebAdmin'de sabit "PHP-FPM FastCGI 127.0.0.1:9000" etiketi.
- Go köprüsü `Status` modeli: sunucu `ram_mb` gönderir; Go `memory_usage_kb`/`active_connections` bekliyor (0 dönüyor).
- Panel: uzantı "Yükle" çalışmıyor; kalan sayfalar/CRUD/toolkit testleri (Laravel, WordPress, Node, Composer, Docker...).
- `/api/status` eski yol 404 yerine 401.

## 3. Bot kontrol ayarı nerede olacak (sahip, netleştirme)
- Ayar yeri: zPanel `https://<sunucu>:8036/tools/web/zmax/settings` ("ZMax Ayarları" sayfası).
- Sayfadaki mevcut alanlar (2026-11-14 görüldü): işçi sayısı, önbellek belleği (MB), önbellek süresi (sn), dakikadaki istek sınırı (IP başına), keep-alive süresi, slowloris başlık/gövde süresi, günlük düzeyi, "İstek sınırlamasını aç", Vazgeç / "Kaydet ve uygula".
- Bot kontrol ayarı bu forma "Güvenlik" grubu olarak eklenecek (aç/kapat, mod, muaf yollar/IP, çerez süresi); "Kaydet ve uygula" ZMax yapılandırmasını yeniden yükler.
- Not: portlar ve dinleme adresleri panelden değiştirilemez (zmax.toml elle); bot ayarı bu kısıtı etkilemez.
- Ön koşul: ZMax tarafında bot kontrol modülü ve `zmax.toml` anahtarları (bölüm 1, parça 1) önce kodlanmalı; panel formu ancak ondan sonra bağlanır.

## 4. Saldırı modu: ülke engelleme vb. (sahip, 2026-11-14; aynı ayar sayfası)
- İstek: `/tools/web/zmax/settings` sayfasında "Saldırı altında" davranışları: ülke engelleme/zorlaştırma gibi.
- Öneri (onay bekliyor): ülke başına üç eylem: izin ver / bot doğrulamasına yönlendir / engelle. Saldırı algılanınca (ban/401/istek eşiği aşılınca) otomatik devreye girme seçeneği + elle "Saldırı modu" anahtarı.
- Muaf: kendi IP'm/yönetici IP'leri, doğrulanmış arama botları, `/api/` ve webhook yolları, loopback.
- Gereksinim: IP→ülke veritabanı (ör. MaxMind GeoLite2 `.mmdb`: lisans/hesap koşulu ve güncelleme gerekir; çevrimdışı `.mmdb` dosyası ZMax tarafından okunur). Veritabanı yoksa özellik devre dışı ve ayar ekranında uyarı.
- Riskler: VPN/proxy ve CDN arkasındaki gerçek ziyaretçi IP'si (X-Forwarded-For güvenilir proxy listesi); yanlış ülke eşleşmesi; kendini dışarıda bırakma (yönetici IP'si muaf olmalı).
- Parçalar: ZMax (Rust: geoip arama, ülke politikası, saldırı modu durum makinesi, audit.log), WebAdmin ekranı, zPanel ayar formu. Bölüm 1 ile aynı modül altında toplanır.

## 5. GeoIP veritabanı kaynağı (sahip: github.com/wp-statistics, 2026-11-14)
Bakıldı (yalnız okundu, hiçbir şey indirilmedi):
- `wp-statistics/GeoLite2-Country`: MaxMind GeoLite2-Country, yaklaşık 2 MB, otomatik güncellenir, anahtarsız doğrudan indirme: `https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz`. README lisansı CC BY-SA 4.0 diyor. Ülke engelleme için yeterli ve en hafif seçenek.
- Diğerleri: `GeoLite2-City`, `GeoLite2-ASN` (ASN: hosting/VPN ağı tespiti), `DbIP-City-lite` (MIT), `geo` (geo.wp-statistics.com).
- Kontrol edilecek: lisans/atıf koşulu (MaxMind GeoLite2 EULA ayrıca atıf ve yeniden dağıtım sınırı koyar; depoda lisans dosyası "None" görünüyor, README CC BY-SA 4.0 yazıyor) ve ZMax paketine gömmek yerine panelden indirme/güncelleme (ör. haftalık) tercih edilmesi.
- ZMax (Rust) `.mmdb` okuyabilir (maxminddb crate); veritabanı yoksa özellik kapalı + uyarı.
- Karar (sahip): veritabanı pakete gömülmez, **indirilir** (panel/ZMax ayar ekranından, jsDelivr bağlantısıyla; güncelleme periyodik). İndirme kodu henüz yazılmadı.
- Karar (sahip): GeoIP veritabanı güncelleme periyodu **haftalık**.
- Karar (sahip): haftalık güncelleme **cron** ile yapılacak (sunucuda zamanlanmış görev; ZMax/panel betiği veritabanını indirir, doğrular, yarım indirmede eskisini korur, ardından ZMax yapılandırmasını yeniden yükler). Cron girişi ve betik henüz yazılmadı.

## 6. WAF kural seti (sahip, 2026-11-14; "geliştirme notu")
- İhtiyaç: ZMax'e kapsamlı bir **WAF kural seti** lazım. Bugün elle denenen SQLi ve XSS istekleri 403 aldı ve `waf_events.log`'a OWASP CRS numaralarıyla (942100, 941100) düştü; ancak kural motoru/kural dosyası `zmax-security` crate'inde ayrı bir modül olarak görünmüyor (crate'te acl, basic_auth, hotlink, waf_events var). Kuralların nerede tanımlı olduğu ve kaç kural olduğu kodlamadan önce çıkarılmalı.
- Kapsam önerisi (onay bekliyor): SQL injection, XSS, path traversal/LFI, RFI, komut enjeksiyonu, kötü User-Agent/tarayıcı botları, yaygın CMS keşif yolları (wp-login brute force, xmlrpc), protokol ihlalleri, büyük/şüpheli gövde. OWASP Core Rule Set (CRS) uyumlu numaralama (kural numarası + önem + eylem: logla/engelle/doğrulamaya yönlendir).
- Yönetim: kural bazlı aç/kapat, paranoya seviyesi, site (vhost) bazında istisna, "yalnız logla" modu (yanlış pozitif denemesi için), `waf_events.log` ve WebAdmin "WAF ve Güvenlik" ekranı.
- Bot kontrol ekranı ve ülke engelleme (bölüm 1 ve 4) ile aynı güvenlik modülü altında toplanır; Pingora'da hazır WAF yoktur (Pingora yalnızca proxy çatısı).
- Henüz kodlanmadı.

## 7. Zararlı kod engelleme (sahip, 2026-11-14; "geliştirme notu")
- İstek: sunucuya zararlı kod (webshell, backdoor, gizli PHP) yazılamasın veya yazılsa bile çalışmasın.
- Öneri (onay bekliyor), katmanlar:
  1. **Çalıştırmayı engelle:** yükleme klasörlerinde PHP çalıştırma kapalı (ör. `wp-content/uploads`, `storage`, `tmp`, `cache`); ZMax vhost kuralı: bu yollarda `.php/.phtml/.phar` isteği 403. Çift uzantı (`a.php.jpg`), `.htaccess` ile kural açma, `.user.ini` yazma engellenir.
  2. **PHP sertleştirme (lsphp/LSAPI):** vhost başına `open_basedir`, `disable_functions` (`exec, system, passthru, shell_exec, proc_open, popen, eval benzeri`), `allow_url_include=0`, `upload_tmp_dir` ayrı; ZMax'in LSAPI istemcisi vhost başına `php_admin_value` iletebilir.
  3. **Yazma izleme/tarama:** belge kökünde yeni `.php` oluşunca (inotify) imza/heuristik tarama (base64+eval, gizli parametre ile komut, bilinen webshell adları); şüpheliyi karantinaya al + `audit.log`/bildirim.
  4. **Kullanıcı/izin ayrımı:** site başına ayrı sistem kullanıcısı, belge kökü dışına yazma yok; ZMax yapılandırma dizinleri site kullanıcısına yazılabilir olmaz.
  5. **WAF:** yükleme isteklerinde (multipart) dosya türü/uzantı/içerik doğrulaması (bölüm 6 ile aynı modül).
- Açık soru: tarama zPanel mi ZMax mi yapacak (ağır iş dosya sistemi izleme olduğundan zPanel/ayrı ajan daha uygun; ZMax yalnız çalıştırmayı engeller ve PHP sertleştirme ayarlarını iletir).
- Henüz kodlanmadı.

### 7.1 Saldırı yolu (sahip, 2026-11-14): eklenti ve PHP açıkları
Zararlı kod çoğunlukla WordPress/CMS **eklenti açıkları** ve **PHP/uygulama açıkları** üzerinden yazılıyor. Eklenecek önlemler (onay bekliyor):
- **Kod dizini yazılamaz:** PHP sürecinin çalıştığı kullanıcı site kodunu (`wp-content/plugins`, `themes`, çekirdek) değiştiremez; yalnız `uploads`/`cache` yazılabilir ve orada PHP çalışmaz. Eklenti açığı olsa bile kalıcı backdoor yazılamaz.
- **Sanal yama (WAF):** bilinen eklenti/CMS açıkları (CVE) için istek kalıpları engellenir; açık bir eklentiye giden yollar için kural paketi (bölüm 6 ile aynı modül, güncellenebilir kural dosyası).
- **Açık tarama + güncelleme uyarısı:** kurulu eklenti/tema/CMS sürümleri bir güvenlik zafiyet listesiyle karşılaştırılır (panel tarafı); eskimiş sürümlerde uyarı, otomatik güncelleme seçeneği.
- **PHP sürümü:** desteklenmeyen sürümler (8.2 öncesi) için panelde uyarı; site başına sürüm seçimi (lsphp 8.2–8.5 zaten mevcut).
- **Çalıştırılan komutu kısıtla:** `disable_functions` + `open_basedir` (bölüm 7, katman 2) açık sömürülse de komut çalıştırmayı engeller.
- **İzleme:** yazma sonrası yeni/değişen `.php` için karantina ve bildirim (bölüm 7, katman 3).

## 8. Sıra (sahip, 2026-11-14)
1. Önce panel ve ZMax hata/bug'ları düzeltilir.
2. **Sonra** toolkit ile yapılan uygulamaların testi: Laravel, WordPress, Node, Composer, Docker, Git, Backup vb. toolkitlerle kurulmuş örnek projeler, ZMax (LSAPI) üzerinde çalıştırılıp denenir.

## 9. Test sırası (sahip, 2026-11-14)
Tüm hatalar bitince **yeniden test**, bu sırayla:
1. **Panel** (tüm sayfalar, sekmeler, ekle/düzenle/sil, uzantı ve toolkit işlemleri).
2. **ZMax Go–Rust uyumluluğu** (Go köprüsü ↔ Rust API: Version, Health, Validate, Reload, Status, PurgeCache, Events, lifecycle yazımı, devre kesici; sözleşme sürümü).
3. **En son güvenlik testleri** (WAF, ban/hız sınırı, token/rol, path traversal, zararlı kod/webshell engelleme, TLS, başlıklar).
