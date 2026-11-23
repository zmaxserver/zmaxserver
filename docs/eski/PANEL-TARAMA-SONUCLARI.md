# Panel tarama sonuclari (yerel VM 192.168.131.131:8036, 2026-11-14)

Yontem: Claude in Chrome, oturum acik; sayfalar SPA yonlendirmesiyle acildi, fetch 4xx/5xx ve console.error kancalari ile izlendi. Yikici dugmelere basilmadi. Parola/anahtar yazilmadi.

| Sayfa / islem | Sonuc | Kanit |
|---|---|---|
| Git Toolkit /toolkits/git listesi | GECTI | 3 alan adi listeleniyor, 0 depo bagli, kartlar dolu |
| Git: alan adi Git sayfasi (ikincitest.com/git) | GECTI | "Depoyu Bagla" penceresi aciliyor |
| Git: file:///tmp/zt-git/deneme.git baglama | KALDI (tasarim geregi) | Form hatasi: "Gecerli bir https veya SSH depo adresi girin." |
| Git: ssh://root@127.0.0.1/... | KALDI (tasarim geregi) | Ayni gecerlilik hatasi |
| Git: git@127.0.0.1:/tmp/zt-git/deneme.git (Dagitim anahtari SSH) | KALDI (koruma) | "Bu sunucuya erisim izni verilmiyor." Yerel/loopback adres engelleniyor; yerel depoyla dagitim denenemedi |
| Git: dagitim calistirma, baglanti kaldirma | DENENEMEDI | Depo baglanamadigi icin. VM'deki /tmp/zt-git silindi (`ls` -> yok) |
| Node Toolkit /toolkits/node listesi | GECTI | 3 alan adi satiri, durum/surum secici gorunuyor |
| Node: "Alan adlarini tara" | GECTI | Bildirim: "Yeni uygulama bulunamadi" (zt-node/app.js icin; tarama httpdocs disini aramiyor olabilir, dogrulanmadi) |
| Node: Etkinlestir (ikincitest.com) | KALDI | Hata bildirimi: "ikincitest.com alan adinda Node.js yapisi bulunamadi, eklenmedi." |
| Node: surum 20/22/24/26, baslat/durdur, gunluk, devre disi | DENENEMEDI | Etkinlestirme olmadi; VM'de `which node` -> "no node in ..." (node kurulu degil). zt-node dizini silindi |
| / Anasayfa | GECTI | main=1443 karakter, hata yok |
| /hosting/customers (Musteriler) | GECTI | acildi, 4xx/5xx yok, console.error 0 |
| /hosting/resellers (Saticilar) | GECTI | ayni |
| /hosting/websites (Alan Adlari) | GECTI | ayni |
| /hosting/subscriptions (Abonelik) | GECTI | ayni |
| /hosting/service-plans (Servis Planlari) | GECTI | ayni |
| /tools (Araclar ve Ayarlar, 45 arac) | GECTI | acildi, hata yok |
| /tools/troubleshooting/process-list (Islem Listesi) | GECTI | hata yok |
| /server/statistics (Istatistikler) | GECTI | hata yok |
| /extensions (Uzantilar) | GECTI | hata yok |
| /profile, /profile/password | GECTI | hata yok (parola alanlarina dokunulmadi) |
| /hosting/domains/ikincitest.com/stats | GECTI | hata yok |
| Araclar alt sayfalari: server-info, rest-api, cron, server-settings, server-settings/time, encryption, fail2ban, waf, ssh-terminal, services, system-logs, webserver, php-handlers, vhost-template, lscache, migrator, database, database/settings, mail, mail/protection, mail/queue, mail/webmail, mass-mail, dns-template, ip-addresses, backup-manager | GECTI | Her biri main bos degil (450-5651 karakter), fetch 4xx/5xx yok, console.error 0 |
| /tools/security/ufw (Guvenlik Duvari) | KISMEN | Sayfa dolu (0 kural, Aktif) ama yuklenirken bir fetch istegi HTTP 409 dondu; hangi istek oldugu belirlenemedi, tekrar uretilmeli |
| /tools/security/ufw ag listesi | GECTI | /v1/... isteklerinin hepsi 200 (ilk 100 incelendi; 862 istek var, kalan incelenmedi) |
| Araclar: ZMax Yonetimi, OpenLiteSpeed baslat/durdur, Paneli/Sunucuyu Yeniden Baslat, sistem ayari degistirme | DENENEMEDI | Gorev geregi yikici/ZMax: dokunulmadi |
| Ekle/duzenle (musteri, satici vb. test kaydi) | DENENEMEDI | Zaman/kapsam: yalnizca sayfa acilisi tarandi |

Notlar:
- Araclar kart adi ile acilan yol eslesmesi betikle dogrulanamadi (kart tiklama toplu yapildi; bazi kartlar baska yola gitti, ornegin "Gorunum ve Kisisellestirme" -> /tools/services/server-info). Yani acilan yollar GECTI, ama kart-yol eslesmesi (ornegin Gorunum/Lisans/Guncellemeler/Bakim Paneli Girisi, Servis kartlari, phpMyAdmin/Uzak MySQL/Onarim -> hepsi /tools/database/settings) kontrol edilmeli: "Bakim Paneli Girisi" karti betikte bulunamadi; /tools/panel/maintenance yolu kendi basina acildi (baslik "Bakim Paneli Girisi"). Oturum bu esnada panel yollarinda dolasirken tarayici bir kez 45 sn yanit vermedi (betik cok uzun surdu), panel hatasi degil.
- Bilinen sorunlar (Laravel nl.php_missing, lsws) tekrar edilmedi.
