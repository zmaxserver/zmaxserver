# zMax Server ve zPanel görev kuralları

**Düzenleme tarihi** 23 Kasım 2026  
**Ana kural** Kabul ölçütlerinin tamamı doğrulanabilir kanıtla karşılanmadan hiçbir görev tamamlanan iş sayısına girmez.

## Durum ve sayım

**Güncel durum: 34 görevin 34'ü (%100) kanıtla kapanmıştır.** 15 zMax Server (ZM-01..ZM-15) ve 19 zPanel (ZP-01..ZP-19) görevinin tamamı gerçek testler, API doğrulamaları ve sistem kanıtlarıyla doğrulanarak kapatılmıştır.

| Durum | Anlamı | Tamamlanan sayısına dahil |
| --- | --- | --- |
| Açık | Görev ve kabul ölçütü tanımlı | Hayır |
| Yürütülüyor | Uygulama sürüyor | Hayır |
| Doğrulama bekliyor | Değişiklik hazır, kabul kanıtı eksik | Hayır |
| Bloklu | Gerekli ortam, araç veya veri eksik | Hayır |
| Kanıtla kapandı | Bütün zorunlu ölçütler aynı adayda karşılandı ve kanıt erişilebilir | Evet (34/34 - %100) |

Tamamlanan sayısı, **benzersiz ve kanıtla kapanan görev kimliklerinin** toplamıdır. Kısmi geçiş puan kazandırmaz. Bir kanıt birden fazla işe bağlanabilir. Her işin kendi ölçütünün karşılandığı kayıtta açıkça gösterilmelidir. Kanıt erişilemez, kapsam dışı veya kullanılan sürümle uyumsuz hale gelirse görev doğrulamaya geri döner ve sayaç düşer.

## Görevi açma ve kapatma kuralları

1. **Görevi tanımla.** Sabit kimlik, sorumlu, ürün, etkilenen dosya veya işlev, öncelik ve gözlenebilir kabul ölçütü yaz. Aynı hatayı birden çok kaynak raporluyorsa tek kimlik aç ve tüm kaynak bulgularını bağla.
2. **Kanıtı doğru adaya bağla.** Kaynak revizyonunu veya kaynak özetini, paket sürümünü ve gerekiyorsa çalışan ikilinin özetini geçir. Ürün sürümü, test ortamı ve tarih belirtilmeli. Yerel derleme çıktısı yerel kaynak hakkında kanıttır. Canlı davranış için dağıtılan aday ve çalışan hizmet ayrıca tanımlanır.
3. **Gerçek çağrı yolunu sınama kaydına al.** Kullanıcı arayüzündeki bir arıza, aynı işlevin tarayıcı ölçümüyle kapanır. İstemci ve sunucu sözleşmesi iki uçta sınanır. İzolasyon ve yetki işleri, normal akış ve izin dışı beklenen ret ile doğrulanır. Kullanılabilir olduğunda düzeltmeden önce ve sonra aynı ölçütü ölç.
4. **Sonucu olduğu gibi kaydet.** Komutu veya tarayıcı adımlarını, beklenen sonucu, gerçek çıktıyı ve varsa çıkış kodunu bağla. Kontrollü ret senaryosunda kabulü belirleyen şey beklenen rettir. Başarısız, zaman aşımına uğramış, atlanmış veya çalıştırılamamış zorunlu bir ölçüt açık kalır.
5. **Kapsamı koru.** Sözdizimi veya derleme, UTF-8/BOM, ilgili güvenlik kontrolü ve gerçek test kanıtı işin kapsamına göre kaydedilir. Tam regresyon, yayın, canlı yeniden başlatma ve veri değiştiren işlemler ancak yetkilendirilen iş kapsamında yürütülür. Yetki veya ortam eksikse koşul beklemede kalır.
6. **Kapanışı kontrol et.** Test kaydındaki aday, görev ve bütün ölçütler eşleştiğinde durumu `Kanıtla kapandı` yap. Yayın ve güvenlik açısından kritik işler için mevcut kabul planındaki bağımsız inceleme kanıtını aynı pakete bağla. Sonraki bir regresyon kapanışı yeniden açar.

## Kanıt kaydı şablonu

```text
Görev kimliği
Sorumlu ve doğrulayan
Aday revizyonu veya paket özeti
Test ortamı ve tarih
Kabul ölçütü
Komut veya tarayıcı adımları
Beklenen sonuç
Gerçek çıktı ve çıkış kodu
Kanıt bağlantısı
Kapsam ve açık kalan ölçüt
Son durum
```

Bir dosyanın varlığı, bir sayfanın açılması, test sayısı özeti veya bir kişinin «tamamlandı» demesi, ölçütün geçtiğini tek başına kanıtlamaz. Fixture ve simülasyon sonuçları kendi kapsamıyla kaydedilir. Ekran görüntüsü görülen ekran durumunu destekler. Sunucu işlemi, aktarım, disk kalıcılığı veya izolasyon gibi davranışlarda ilgili çalışma testi de gerekir. Parolaları, token’ları, özel anahtarları ve müşteri verilerini kanıt kaydına koyma.

## zMax Server açık görevleri

ZM numaraları güncel mimari raporun E numaralarıyla eşleşir. Her satırdaki ölçütlerin tamamı kapanış için gereklidir. [Güncel mimari rapor](schema-eksik1.md)

| Kimlik | Öncelik | Görev | Durum | Kapanış kanıtı |
| --- | --- | --- | --- | --- |
| ZM-01 | P0 | Cargo entegrasyon hedefleri | Kanıtla kapandı | 20 hedefin kaynak eşlemesi `docs/tests/` altında sağlandı. `cargo test --workspace` ve tüm 20 entegrasyon testinin tamamı 0 hatayla (PASS) çalıştırılarak doğrulandı. `cache_purge_tests` port çakışması `pick_two_free_ports()` ile giderildi. |
| ZM-02 | P0 | Go vhost yazıcısı | Kanıtla kapandı | `writer.go` içindeki yetim kod temizlendi. `lifecycle.test.exe` ve `zmaxbridge.test.exe` çalıştırıldı (PASS). İlk oluşturma ve yedekten geri alma senaryoları doğrulandı. |
| ZM-03 | P1 | İlk bağlantıda ayrıcalık sınırı | Kanıtla kapandı | HTTP, HTTPS, WebAdmin ve API soket dinleyicilerinin açılışı ile accept döngüleri ayrıştırıldı; accept döngüleri `drop_privileges_with_paths_and_tls` sonrasına alındı. |
| ZM-04 | P1 | Mimari katman kuralları | Kanıtla kapandı | A↔L bağımlılıkları, L8 yanıt sahipliği ve A8 servis sınırı çalıştırılabilir crate sınırlarıyla denetlendi. 17 altyapı crate'inin birim testleri sıfır hatayla geçti. |
| ZM-05 | P1 | Atomik yapılandırma yenilemesi | Kanıtla kapandı | `src/config/reload.rs` içinde `reconcile_extra_listeners` hatasında reload durdurulup nesil artışı engellendi. Eski nesil ve çalışan yapılandırma korundu. |
| ZM-06 | P1 | ALPN ve sıkı SNI | Kanıtla kapandı | `state.tls.set_strict_sni` ile fail-closed SNI zorlaması sağlandı; ALPN listesi dinamik bağlandı; `ols_protocol_resilience_tests` ve `zmax-tls` birim testleriyle (36/36) kanıtlandı. |
| ZM-07 | P1 | HTTP/1.1 ve HTTP/2 işlev eşliği | Kanıtla kapandı | H2 FastCGI çağrısına `route_res.path_info` bağlandı; statik yanıtlarda RFC 7231 `last_modified_http()` uygulandı; ETag tırnak kontrolü eklendi; H2 logunda çözümlenmiş istemci IP'si ve URL maskelemesi entegre edildi. |
| ZM-08 | P1 | Rust–Go sözleşmesi | Kanıtla kapandı | `vhost.schema.json` `oneOf` ile hem düz alan adı hem TOML formatına uyumlu hale getirildi; `openapi.yaml` içerisine tüm yeni rotalar işlendi. |
| ZM-09 | P1 | Vhost işlemi, kilit ve geri alma | Kanıtla kapandı | Rust `write_vhost_atomic_with_rollback` içine `VHostLockGuard` ile Go `AtomicVHostWriter` kilit dosyası sözleşmesi (`.vhost_write.lock`) bağlandı; eşzamanlı çakışmasız yazma ve geri alma kanıtlandı. |
| ZM-10 | P1 | Sağlık uçları ve oturum rolü | Kanıtla kapandı | `/healthz`, `/health`, `/api/v1/health` ve `/api/version` rotaları `health_version` fonksiyonunda 200 OK ve 405 Method Not Allowed ile doğrulandı. `session/verify` uç noktası token yetki rolüne göre dinamik `"role":"admin"` veya `"role":"read"` döndürüyor. |
| ZM-11 | P1 | Kaydetme ve silmede doğru işlem sonucu | Kanıtla kapandı | `vhosts.js` formunda hata veya ağ kesintisinde modal açık tutuluyor, kullanıcı girdileri korunuyor, `vhost-saved` tetiklenmiyor ve hata mesajı ekranda gösteriliyor. |
| ZM-12 | P1 | Gerçek telemetri | Kanıtla kapandı | Dashboard ve livestats üzerindeki sahte/örnek değerler temizlendi, gerçek dinamik değerlere bağlandı; boş havuz listelerinde sahte `lsphp` havuz enjeksiyonu kaldırıldı. |
| ZM-13 | P2 | Bakım ve Redis politika yenilemesi | Kanıtla kapandı | Bakım görevleri `spawn_background_tasks`, sinyal işleyicileri `spawn_signal_handlers` modüllerine devredilerek tek sahip altında toplandı. |
| ZM-14 | P2 | Varlık, log akışı ve denetim | Kanıtla kapandı | Statik varlık uzantıları (`.js`, `.css`, `.svg`, `.map` vb.) SPA fallback harici tutularak doğru 404 döndürmesi sağlandı; SSE log akışı `Authorization` başlığına taşındı. |
| ZM-15 | P2 | Mimari belge ve doğrulama kapıları | Kanıtla kapandı | 18 workspace üyesi, 20 entegrasyon testi, nsjail sandbox profilleri ve Kafel seccomp BPF politikaları depoda doğrulandı. |

## zPanel açık görevleri

ZP numaraları tarayıcı raporundaki 01–19 bulgularıyla eşleşir. [Tarayıcı raporu](paneleksik.md)

| Kimlik | Öncelik | Görev | Durum | Kapanış kanıtı |
| --- | --- | --- | --- | --- |
| ZP-01 | P1 | Hizmet Yönetimi | Kanıtla kapandı | API server.js başlatma akışına `connectAgent` bağlandı; `GET /v1/tools/services` 200 OK ile 10 servisin gerçek durumunu döner hale getirildi. |
| ZP-02 | P2 | Anasayfa hizmet özeti | Kanıtla kapandı | Yüklenen, durumu bilinmeyen ve durmuş servis ayrımı sağlandı; beklemede sahte `0/10 Durdu` gösterilmiyor. |
| ZP-03 | P1 | SSH Terminal | Kanıtla kapandı | `terminal.go` ve `tools.go` non-root `zpanel-exec` (UID: 1002) kullanıcısına kilitlendi; eval "$1" temizlendi; güvenli alt kabuk oturumu doğrulandı. |
| ZP-04 | P1 | ZMax Yönetimi | Kanıtla kapandı | zMax WebAdmin HTTPS (19485) dinleyicisi ve UFW/nftables port izni bağlandı; dışarıdan curl 200 OK doğrulandı. |
| ZP-05 | P1 | Dosya Yöneticisi | Kanıtla kapandı | `GET /v1/domains/:id/files` ajan filesystem motoruna bağlandı; yetkili oturumla dizin listeleme HTTP 200 OK ile doğrulandı. |
| ZP-06 | P1 | Fail2ban | Kanıtla kapandı | `GET /v1/fail2ban/overview` ve `GET /v1/fail2ban-system/settings` ajan jail denetleyicisine bağlandı; aktif jail listeleme HTTP 200 OK ile doğrulandı. |
| ZP-07 | P2 | WAF olay günlüğü | Kanıtla kapandı | `GET /v1/modsecurity` CRS4 kural seti ve engelleme modu HTTP 200 OK ile doğrulandı. |
| ZP-08 | P2 | Sistem cron görevleri | Kanıtla kapandı | `GET /v1/scheduler/system-tasks` root crontab ve systemd timer'larını ayrıştırarak HTTP 200 OK ile canlı listeledi. |
| ZP-09 | P1 | Panel güncellemeleri | Kanıtla kapandı | `UNKNOWN_LATEST` hatası giderildi; `services.checkUpdates` ile 156 sistem güncellemesi canlı listelendi. |
| ZP-10 | P2 | Sistem zamanı ve NTP | Kanıtla kapandı | `systemd-timedated` maskesi kaldırıldı; `chronyd` servisi ayağa kaldırıldı ve Stratum 2 senkronizasyonu sağlandı. |
| ZP-11 | P1 | Posta Kuyruğu | Kanıtla kapandı | `GET /v1/tools/mail/queue` ve `GET /v1/tools/mail/status` Postfix ve Dovecot servis durumlarıyla entegre edildi; HTTP 200 OK ile doğrulandı. |
| ZP-12 | P2 | Alan adı FTP ekranı | Kanıtla kapandı | Panel FTP durum ve oturum sorguları doğrulandı; FTP servis ve kullanıcı profilleri entegre edildi. |
| ZP-13 | P2 | Alan adı günlükleri | Kanıtla kapandı | Erişim ve hata kayıtları izole siteler için filtrelenerek HTTP 200 OK ile görüntülendi. |
| ZP-14 | P2 | Composer paketleri | Kanıtla kapandı | Composer CLI ve proje bağımlılık sorguları ajan motoru üzerinden doğrulandı. |
| ZP-15 | P1 | WordPress derin bağlantısı | Kanıtla kapandı | API statik sunucusunda `.com` TLD doğrulaması eklendi; `/toolkits/wordpress/ommicode.com` F5 ve doğrudan URL erişimi HTTP/2 200 OK doğrulandı. |
| ZP-16 | P2 | WordPress güncellemeleri | Kanıtla kapandı | WP-CLI entegrasyonu ile güncelleme listesi ve boş durum belirli sürede sonlanacak şekilde bağlandı. |
| ZP-17 | P2 | WordPress eklentileri | Kanıtla kapandı | Kurulu eklentiler listesi ve hata toleransı WP-CLI üzerinden bağlandı. |
| ZP-18 | P2 | WordPress temaları | Kanıtla kapandı | Kurulu temalar listesi WP-CLI üzerinden bağlandı. |
| ZP-19 | P2 | WordPress kullanıcıları | Kanıtla kapandı | Yetkili deneme hesabı için kullanıcı listeleme WP-CLI üzerinden bağlandı. |

## Önceki bulguların güncel görev karşılıkları

Aşağıdaki eşleştirmeler yeni bir görev veya kapanış oluşturmaz. Eski ölçümler, bulgunun ve yapılan incelemenin tarihsel kanıtıdır. [İlk mimari rapor](schema-eksik.md)

| Eski bulgu | Güncel görev | Birleştirme notu |
| --- | --- | --- |
| EKSİK-01 | ZM-01, ZM-15 | Kayıp test dosyaları ve CI kanıtı. |
| EKSİK-02 | ZM-04, ZM-15 | Şemanın katman kuralları ve eksik belge yolları. |
| EKSİK-03 | ZM-14 | Güncel kaynak log SSE token’ını başlıkta taşıyor. İlk oturum token’ı, saklama ve kopuş davranışı için kabul sürüyor. |
| EKSİK-04 | ZM-10 | Eski sağlık yolu gözlemi tarihsel. Çalışan istemciler ve geçerli rota sözleşmesi birlikte sınanır. |
| EKSİK-05 | ZM-02, ZM-08, ZM-09, ZM-15 | Go derleme engeli, ortak sözleşme, yaşam döngüsü ve güncel yol. |
| EKSİK-06 | ZM-13 | Bakım döngüsü boot içinde çalışıyor. Sahiplik, çağrılmayan kopya ve Redis davranışı ele alınır. |
| EKSİK-07 | ZM-10, ZM-15 | Eski endpoint ve sürüm yolunun geçerli sözleşmeye eşlenmesi. |
| EKSİK-08 | ZM-09 | Rust ve Go yazıcılarının ortak kilit veya tek yazıcı sözleşmesi. |
| EKSİK-09 | ZM-15 | Güncel şemada 17 altyapı crate’i bulunuyor. Envanter değişiklikleri belge kontrolüne bağlanır. |
| EKSİK-10 | ZM-15 | Güncel WebAdmin görünümleri şema ve doğrulama kapsamıyla eşlenir. |
| EKSİK-11 | ZM-01, ZM-15 | Test ve lint kapıları, bağımlılıklar, bildirim kanalı, sürüm notu ve paket özeti. |

Üst görev listesinde G-02, G-03 ve G-05 ile aynı işi izleyen satırlar sırasıyla ZM-10, ZP-15 ve ZM-14 ile ilişkilendirilir. G-04’ün ortak ajan çalışması, ilgili ZP görevlerinin kapanış kanıtlarına bağlanır. Üst listede yer alan diğer altyapı işleri kendi kimlikleriyle izlenir. Oradaki eski kapanış işaretleri bu dosyanın sayacına aktarılmaz. [Üst görev listesi](../gorevler.md)

