# zPanel tarayıcı testi — Tespit edilen eksikler

**Tarih** 23 Kasım 2026 (Türkiye saati)  
**Sürüm** zPanel 1.0.09  
**Ortam** [Canlı zPanel](https://panel.ommicode.com/)  
**Kapsam** Yönetici oturumuyla 71 ayrı sayfa yolu, dört alan adı sekmesi ve dokuz WordPress sekmesi. Giriş, gezinme, genel arama, yenileme ve oturum kapatma denendi.

## Sonuç

Giriş başarılıydı. Barındırma ve yönetim ekranlarının önemli bir bölümü açıldı ve veri gösterdi. Sunucuya bağlı bazı işlevler hata verdi. WordPress site ayrıntısı panel içinden açıldı, aynı sayfanın doğrudan açılması ve yenilenmesi `Not found` ile sonuçlandı.

## Tespit edilen hatalar

P1 temel bir işlemi engelliyor. P2 erişilebilen bir ekranın veri, geri bildirim veya destekleyici işlevini etkiliyor.

| No | Öncelik ve işlev | Gözlenen sonuç | Düzeltme ve tekrar test ölçütü |
| --- | --- | --- | --- |
| 01 | **P1 — Hizmet Yönetimi** | Sayfa, hizmet durumlarının okunamadığını ve başlatma, durdurma ile yeniden başlatma yapılamadığını bildirdi. `Durumları Yenile` sonrasında yükleme göstergesi sekiz saniyelik gözlemde kaldı. [Hizmet Yönetimi](https://panel.ommicode.com/tools/services) | Durum sorgusunun hata nedenini inceleyin. Yenileme gerçek servis durumlarını göstermeli veya süre sonunda açık hata vermeli. |
| 02 | **P2 — Anasayfa hizmet özeti** | İlk girişte `0 / 10 Çalışıyor` ve bütün servisler `Durdu` olarak göründü. Sonraki ölçümde kart `Hizmet bilgisi alınamadı` gösterdi. [Anasayfa](https://panel.ommicode.com/) | Yüklenen, durumu bilinmeyen ve gerçekten durmuş servis ayrımını ilk görüntüden itibaren koruyun. |
| 03 | **P1 — SSH Terminal** | Güvenli Web Konsolu ekranı `zpanel-exec` hesabını gösterdi. Ekran `Terminal şu anda kullanılamıyor. Sunucu hizmeti yanıt vermiyor.` mesajını verdi. [SSH Terminal](https://panel.ommicode.com/tools/utilities/ssh-terminal) | Panel ile terminal hizmeti arasındaki bağlantıyı doğrulayın. İzinli deneme hesabıyla oturum açma, zararsız komut ve oturum kapatma testleri geçmeli. |
| 04 | **P1 — ZMax Yönetimi** | Yönetim ekranı `ZMax Server yanıt vermiyor` dedi. Durum bilgisi yüklenmedi. Bu bulgu paneldeki yönetim bağlantısını kapsıyor. [ZMax Yönetimi](https://panel.ommicode.com/tools/general/webserver/zmax) | Panelin zMax yönetim bağlantısı, kimlik bilgisi ve hedef yapılandırmasını inceleyin. Canlı durum ve sürüm ekranda görünmeli. |
| 05 | **P1 — Dosya Yöneticisi** | Alan adı ekranında dosya listesi açılmadı. `Dosya işlemleri şu anda yapılamıyor. Sunucu hizmeti yanıt vermiyor.` [Dosya Yöneticisi](https://panel.ommicode.com/hosting/domains/ommicode.com/files) | Yetkili kullanıcı kendi site kökündeki test dizinini listeleyebilmeli. Listelenemeyen durum açık gerekçeyle görünmeli. |
| 06 | **P1 — Fail2ban** | Sayfa açıldı, sunucu hizmeti yanıt vermediği için işlemin yapılamadığı bildirildi. Aktif jail verisi doğrulanamadı. [Fail2ban](https://panel.ommicode.com/tools/security/fail2ban) | Gerçek jail durumlarını ve okuma hatalarını ayırın. Etkin jail’ler listelenmeli. |
| 07 | **P2 — WAF olay günlüğü** | WAF ekranı açıldı. Olay günlüğü `kullanılamıyor` gösterdi. [WAF yönetimi](https://panel.ommicode.com/tools/security/waf) | WAF olay okumasını doğrulayın. Erişilemeyen günlük, olay bulunmayan durumdan ayrı gösterilmeli. |
| 08 | **P2 — Sistem cron görevleri** | Zamanlama ekranı açıldı, salt okunur sistem görevleri gösterilemedi. Sunucu hizmeti yanıt vermedi. [Zamanlama](https://panel.ommicode.com/tools/utilities/cron) | Sistem görevi sorgusu gerçek veriyi göstermeli veya kesin bir hata vermeli. |
| 09 | **P1 — Panel güncellemeleri** | Güvenlik yamaları ve çekirdek paketleri ekranı sunucu hizmeti yanıt vermediği için işlemin yapılamadığını bildirdi. [Panel güncellemeleri](https://panel.ommicode.com/tools/panel/updates) | Paket durumunun okunması doğrulanmalı. Uygulanabilir güncelleme olmaması ile sorgu hatası ayrı görünmeli. |
| 10 | **P2 — Sistem zamanı ve NTP** | `Zaman istemcisi yanıt vermiyor` ve sunucu hizmeti hatası görüldü. [Sistem zamanı](https://panel.ommicode.com/tools/general/server-settings/time) | Saat ve NTP durumunun okunmasını doğrulayın. Çalışmayan bileşen açıkça belirtilmeli. |
| 11 | **P1 — Posta Kuyruğu** | Kuyruk tablosu veri göstermedi. `Sunucu hizmeti yanıt vermiyor` mesajı vardı. [Posta Kuyruğu](https://panel.ommicode.com/tools/mail/queue) | Postfix kuyruğu okunmalı. Boş kuyruk yalnız başarılı sorgu sonucunda gösterilmeli. |
| 12 | **P2 — Alan adı FTP ekranı** | FTP sayfası ve tablolar açıldı. Ekran, sunucu hizmeti yanıt vermediği için işlemin yapılamadığını bildirdi. [FTP](https://panel.ommicode.com/hosting/domains/ommicode.com/ftp) | Panelin FTP durum ve oturum sorgularını doğrulayın. FTP protokolü işlevi ayrıca deneme hesabıyla ölçülmeli. |
| 13 | **P2 — Alan adı günlükleri** | `Günlük dosyaları şu anda okunamıyor. Sunucu hizmeti yanıt vermiyor.` [Alan adı günlükleri](https://panel.ommicode.com/hosting/domains/ommicode.com/logs) | Test sitesinin erişim ve hata kayıtları, seçilen filtreye göre görüntülenebilmeli. |
| 14 | **P2 — Composer** | Paket ekranı açıldı. Sunucu hizmeti yanıt vermedi ve paket verisi doğrulanamadı. [Composer](https://panel.ommicode.com/hosting/domains/ommicode.com/composer) | Sentetik Composer projesinde paket listesi okunmalı. Kurulum veya ağ erişim hataları açıkça gösterilmeli. |
| 15 | **P1 — WordPress ayrıntısının yenilenmesi** | Alan adı panosundaki `WordPress Etkin` bağlantısı site ayrıntısını açtı. Aynı sayfa doğrudan açıldığında ve tarayıcıda yenilendiğinde `Not found` görüldü. [WordPress site ayrıntısı](https://panel.ommicode.com/toolkits/wordpress/ommicode.com) | Derin bağlantının sunucu yönlendirmesini düzeltin. Menüden açma, doğrudan URL ve yenileme aynı oturumlu sayfayı göstermeli. |
| 16 | **P2 — WordPress güncellemeleri** | Menüden açıldı. `Yükleniyor…` 6,5 saniyelik ölçümde kalkmadı, satır görünmedi. | Liste, boş durum veya hata sonucu belirli sürede gösterilmeli. |
| 17 | **P2 — WordPress eklentileri** | `Yükleniyor…` 6,5 saniyelik ölçümde kalkmadı, satır görünmedi. | Kurulu eklentiler veya okuma hatası görünmeli. |
| 18 | **P2 — WordPress temaları** | `Yükleniyor…` 6,5 saniyelik ölçümde kalkmadı, satır görünmedi. | Kurulu temalar veya okuma hatası görünmeli. |
| 19 | **P2 — WordPress kullanıcıları** | `Yükleniyor…` 6,5 saniyelik ölçümde kalkmadı, satır görünmedi. | Yetkili oturumda kullanıcı listesi veya okuma hatası görünmeli. |

## Bildirilen sınırlar ve geçmiş kayıtlar

- **DNSSEC.** Alan adı DNS ekranı kayıtları gösterdi. BIND imzalama desteği eksik olduğu için DNSSEC’nin bu sürümde etkinleştirilemeyeceği bildirildi. [Alan adı DNS](https://panel.ommicode.com/hosting/domains/ommicode.com/dns)
- **WordPress ayarları.** Ekran, ayarların panelde saklandığını ve siteye otomatik uygulanmasının bu sürümde kullanılamadığını belirtiyor.
- **Webmail ve OpenLiteSpeed.** Zplus Webmail kurulu görünmüyor. OpenLiteSpeed durumu `Kullanılamıyor` gösterdi. Bu durumları değerlendirmek için o bileşenlerin dağıtımda etkin olması gerekiyor.
- **Hızlı Teşhis ve Onarım.** Geçmiş ekranda beş kategorinin sunucu yanıt vermediği için denetlenemediği yazıyordu. Yeni onarım veya teşhis işi başlatılmadı. [Teşhis geçmişi](https://panel.ommicode.com/tools/troubleshooting/repair-kit)
- **Boş listeler.** Müşteri, alt alan adı ve takma alan adı listelerinde açık boş durum mesajları vardı. Bunlar tarayıcı hatası olarak kaydedilmedi.

## Doğrulanan işlevler

| Bölüm | Sonuç |
| --- | --- |
| Oturum ve gezinme | Giriş yapıldı. Yönetici anasayfası ve genel menü açıldı. Genel aramada `Servis Planları` sonucu bulundu. Oturum kapatma giriş ekranına döndü. |
| Barındırma | Müşteri boş durumu ve yeni müşteri formu görüldü. Satıcı, alan adı, abonelik ve servis planı listeleri açıldı. Alan adı ekranındaki Pano, Barındırma ve DNS, Posta ve Başlarken sekmeleri değişti. |
| Alan adı ekranları | E-posta hesabı, veritabanı, SSL/TLS, PHP, DNS kayıtları ve site istatistikleri ekranda göründü. Yönlendirme, Git, site cron, site yedekleri ve korumalı dizinler açıldı. |
| Panel yönetimi | Profil ve tercihler, uzantılar, yönetici planı, bildirim ve işlem günlüğü, lisans, görünüm, REST API yönetim ekranı ve yedek arşiv listesi görüntülendi. |
| Diğer araçlar | WordPress genel liste, Node.js, Laravel, zSecurty, IP adresleri, posta ayarları, veritabanı ayarları, genel DNS şablonu, PHP işleyicileri, vhost şablonu ve göç ekranı açıldı. |
| WordPress site ekranı | Menüden genel bakış ve site bilgileri görüldü. Güvenlik kontrol listesi ve yedek ekranı açıldı. WP-CLI ekranına ulaşılabildi. |

## Öncelikli inceleme

1. Hizmetler, Terminal, Dosya Yöneticisi ve Posta Kuyruğu aynı tür sunucu yanıtı hatası gösterdi. Panelden ilgili isteğin hata kaydını ve ajan tarafındaki kaydını aynı zaman aralığında eşleştirin. ZMax yönetim bağlantısını ayrıca doğrulayın.
2. WordPress derin bağlantısını ve yenilemeyi düzeltin. Dört sekmede yüklemenin başarı, boş sonuç veya hata durumuyla sonlanmasını doğrulayın.
3. Düzeltmelerin ardından aynı ekranları yeniden açın. Terminal, dosya ve işlemsel testleri ayrı deneme hesapları ve veriyle tamamlayın.

Tarayıcı testinde kurulum, gönderim, dosya işlemi, kayıt değiştirme ve servis yeniden başlatma gibi kalıcı işlemler yürütülmedi. Tarayıcının gösterdiği hatalar belgelendi. Sunucu tarafındaki kök neden için günlük korelasyonu gerekiyor.

