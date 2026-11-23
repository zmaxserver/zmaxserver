# zMax Server — Mimari şema eksikleri

**İnceleme tarihi** 23 Kasım 2026 (Türkiye saati)  
**Kaynak sürümü** `VERSION=1.0.09`, Cargo `1.0.9`  
**Temel belge** [36 parçalı mimari şema](mimari/zmax_mimari_semasi.html)  
**Şema SHA-256** `15DBD65ACE8EDFE941D8D85AB0032D4CB1850FF71DE7981391C527486B838BE8`

## Sonuç

Şemadaki **36 bileşenin tamamı kaynakta eşleşiyor**. Bu denetim **15 bulgu grubu** belirledi. İki yayın engeli var. Cargo’nun tanımladığı 20 entegrasyon testinin dosyaları eksik. Go vhost yazıcısında derlemeye engel olan bir sözdizimi hatası var.

Rust ana ikilisi derleme kontrolünü geçti. WebAdmin’in 148 yerel kontrolü geçti. Ayrı bir hata simülasyonu, vhost kaydetme başarısızken arayüzün başarı gösterdiğini doğruladı. Bileşen kapsamı yönetim arayüzünü, API’yi, Rust–Go köprüsünü, çekirdeği, iki HTTP işleme yolunu, altyapı crate’lerini, modül yapılandırmasını ve test girişlerini içeriyor.

[Önceki inceleme](schema-eksik.md)

## 36 bileşenin kaynak karşılığı

**Bağlı** ana çağrı yolunda karşılığı var. **Kısmi** bileşen mevcut ve şema davranışında eksik var. **Engelli** kaynak mevcut ve derleme engeli var.

| ID | Bileşen | Durum | Kanıt |
| --- | --- | --- | --- |
| U1 | WebAdmin iskeleti | Bağlı | SPA girişi ve istemci betikleri var. [Kaynak](../admin/index.html#L439) |
| U2 | API istemcisi | Kısmi | SSE token’ı artık başlıkta. Sağlık çağrısı eski yolda. [Kaynak](../admin/js/api_client.js#L132) |
| U3 | Uygulama kökü | Bağlı | Gezinme, tema ve dil uygulama kökünde. [Kaynak](../admin/js/app.js#L85) |
| U4 | Dashboard | Kısmi | Bazı sunucu ve kaynak değerleri sabit. [Kaynak](../admin/js/views/dashboard.js#L140) |
| U5 | Vhost ekranı | Kısmi | Kayıt hatası arayüzde başarıya dönüşüyor. [Kaynak](../admin/js/views/vhosts.js#L210) |
| U6 | Cache ve WAF | Kısmi | Okuma ve temizlik bağlı. API’deki alan adı kapsamlı temizlik UI’da yok. [Kaynak](../admin/js/views/cache_waf.js#L33) |
| U7 | Log ekranı | Kısmi | Arama, tail ve SSE bağlı. Akış sonu açık hata olarak yansımıyor. [Kaynak](../admin/js/views/logs.js#L102) |
| B1 | Rust–Go sözleşmesi | Kısmi | JSON şeması ve OpenAPI, uygulanan sözleşmeyi tam karşılamıyor. [Kaynak](../go/contract/vhost.schema.json#L5) |
| B2 | Rust köprü uçları | Kısmi | Version, validate ve events var. Validate ile reload doğrulaması farklı. [Kaynak](../src/api/bridge.rs#L58) |
| B3 | Go istemcisi | Kısmi | Unix soketi ve timeout var. Hata tipi, sağlık yolu ve olay tüketimi eksik. [Kaynak](../go/zmaxbridge/client.go#L102) |
| B4 | Vhost dosya yazıcısı | Engelli | Paket düzeyinde yetim blok var. Go ve Rust aynı kilidi uygulamıyor. [Kaynak](../go/lifecycle/writer.go#L135) |
| B5 | Yaşam döngüsü | Kısmi | Uygulama akışı var. Sürüm, nesil ve geri alma kanıtı eksik. [Kaynak](../go/lifecycle/lifecycle.go#L50) |
| A1 | Kimlik ve rol | Kısmi | Okuma/yönetim ayrımı var. Oturum yanıtı gerçek rolü yansıtmıyor. [Kaynak](../src/api/mod.rs#L141) |
| A2 | API koruması | Bağlı | Koruma kimlikten önce çalışıyor. Şemadaki sıra buna uymuyor. [Kaynak](../src/api/mod.rs#L136) |
| A3 | Sistem ve durum | Kısmi | Sağlık yolu geçişi, telemetri, geçmiş ve geri alma eksikleri var. [Kaynak](../src/api/routes/system.rs#L15) |
| A4 | Vhost rotaları | Kısmi | Silme rotası dosyayı doğrudan değiştiriyor ve reload hatasını yutuyor. [Kaynak](../src/api/routes/vhosts.rs#L148) |
| A5 | Ban ve önbellek | Bağlı | Ban ve önbellek rotaları ile kapsamlı temizlik servisleri var. [Kaynak](../src/api/routes/security_cache.rs#L13) |
| A6 | Log API | Kısmi | Tail, yeniden açma ve SSE var. Okuma rolünün SSE kapsamı tanımlanmalı. [Kaynak](../src/api/routes/logs.rs#L121) |
| A7 | Arayüz dosyası | Kısmi | SPA geri dönüşü var. Eksik varlık da yanlışlıkla uygulama HTML’i alabiliyor. [Kaynak](../src/api/admin_static.rs#L78) |
| A8 | Yönetim servisleri | Kısmi | Servisler var. Rotaların bir kısmı kalıcılık işini kendisi yürütüyor. [Kaynak](../src/api/services/mod.rs) |
| A9 | Denetim | Kısmi | Denetim kaydı var. Gerçek rol ve nihai işlem sonucu eksik. [Kaynak](../src/api/audit.rs#L54) |
| K1 | Boot ve sinyaller | Kısmi | Çalışan boot ve sinyal yolu var. Kabul görevleri yetki düşürmeden önce başlıyor. [Kaynak](../src/core/boot.rs#L449) |
| K2 | Ortak durum | Bağlı | ServerState, RuntimeState ve atomik sayaçlar var. K2’nin API türü bağımlılığı sürüyor. [Kaynak](../src/core/state.rs#L3) |
| K3 | Yapılandırma | Kısmi | Yükleme ve doğrulama var. Yayınlama ile ek dinleyici sonucu tek işlem değil. [Kaynak](../src/config/reload.rs#L111) |
| K4 | Modüller | Bağlı | 18 modül TOML’u ve derlenen politika nesnesi var. [Kaynak](../src/modules/policy.rs) |
| K5 | Logger | Bağlı | Sınırlı kuyruk, dosya yazıcısı, canlı yayın ve rotasyon var. [Kaynak](../src/logger/mod.rs#L105) |
| K6 | Bakım görevleri | Kısmi | Bakım boot içinde çalışıyor. Şemadaki modül girişten çağrılmıyor. [Kaynak](../src/core/boot.rs#L430) |
| K7 | Redis | Kısmi | Yayın ve abonelik bağlı. Politika yenileme ve olay kaybı görünürlüğü eksik. [Kaynak](../src/redis/events.rs#L52) |
| L1 | Bağlantı | Kısmi | Kabul ve ek dinleyiciler bağlı. L1 doğrudan API’ye bağlanıp yanıt yazıyor. [Kaynak](../src/pipeline/l1_connection.rs#L3) |
| L2 | Protokol ve TLS | Kısmi | H1, H2 ve ALPN var. Yapılandırılmış ALPN ve SNI davranışı tam bağlı değil. [Kaynak](../src/core/boot.rs#L460) |
| L3 | Gerçek IP | Kısmi | H1 ve H2 çözümleme kullanıyor. H2 logu soket eşini yazıyor. [Kaynak](../src/pipeline/l2_protocol/h2.rs#L391) |
| L4 | Güvenlik | Bağlı | Ortak güvenlik ve HTTPS’ye yönlendirme kararları bağlı. [Kaynak](../src/pipeline/l4_security.rs#L48) |
| L5 | Yönlendirme | Kısmi | Vhost ve proxy akışı var. TOML rewrite kuralları yürütülmüyor. [Kaynak](../src/pipeline/l5_router.rs#L436) |
| L6 | Önbellek | Kısmi | H1 ve H2 yenileme, statik önbellek ve temizlik sırası farklı. [Kaynak](../src/web_engine/pipeline_h2.rs#L343) |
| L7 | İşleyiciler | Kısmi | Statik, FastCGI ve proxy bağlı. H2 PHP ve statik davranışı eksik. [Kaynak](../src/web_engine/pipeline_h2.rs#L374) |
| L8 | Yanıt | Kısmi | Ortak H1 yazıcısı var. H2 başlık ve günlük akışında L8 kullanılmıyor. [Kaynak](../src/pipeline/l2_protocol/h2.rs#L352) |

## Eksikler ve sapmalar

### E01 · P0 — 20 entegrasyon testi çözümlenemiyor

`cargo metadata`, ana paketteki 20 açık test hedefinin tamamının `docs/tests/` altında kaynak beklediğini gösteriyor. Hedeflerin 20’si de eksik. `cargo check --locked --offline --all-targets` çıkış kodu `101` ile `could not compile due to 20 previous target resolution errors` döndürdü. Ana ikilinin kontrolü ayrı olarak geçti. Eksik bağımsız hedefleri geri getirin veya bildirimleri gerçek dosya konumuna bağlayın. Kabul için Cargo bütün hedefleri çözümlemeli ve testler temiz bir ortamda çalışabilmeli. [Cargo test bildirimleri](../Cargo.toml#L40)

### E02 · P0 — Go vhost yazıcısında sözdizimi engeli

`Rollback` kapandıktan sonra paket düzeyinde sahipsiz bir `if` ve `return` bloğu var. Go yaşam döngüsü paketi bu haliyle derlenemez. Yetim kodun amaçladığı ilk oluşturma geri almasını fonksiyonun içine alın ve ayrı test edin. Yerel ortamda Go çalıştırıcısı bulunmadığından bulgu doğrudan kaynak sözdizimine dayanıyor. [Go yazıcısı](../go/lifecycle/writer.go#L135)

### E03 · P1 — Dinleyiciler yetki düşürmeden önce başlatılıyor

HTTP ve HTTPS kabul döngüleri ile yönetim dinleyicisi görevleri, zMax’in ayrıcalık düşürme çağrısından önce başlatılıyor. Risk, süreç ayrıcalıklı başlatıldığında ilk bağlantıların yanlış kimlik altında işlenebilmesi. Soket hazırlığını ve istemci kabulünü ayrı aşamalar yapın. İlk kabulden önce etkin kimliği doğrulayın. Çalışan Linux ikilisi üzerinde bu koşul ayrıca ölçülmeli. [HTTP kabulü](../src/core/boot.rs#L449) · [Yönetim kabulü](../src/core/boot.rs#L526) · [Yetki düşürme](../src/core/boot.rs#L795)

### E04 · P1 — Katman yönü ve yanıt sahipliği şemaya uymuyor

Şemanın 1–4 numaralı kuralları, A ve L katmanlarının ortak K2 üzerinden bağlanmasını, sonraki katmanı doğrudan çağırmamasını, sokete L8’in yazmasını ve A rotalarının işi A8’e devretmesini öngörüyor. Kaynakta L1 API yardımcılarını içe aktarıyor, L5 ve L6 L8’e doğrudan bağlı, A7 web motorunun yazıcısını çağırıyor. H2 ve bazı bağlantı/işleyici yolları yanıtı L8 dışında yazıyor. A4 vhost silme işini rota katmanında yapıyor. Paylaşılan HTTP türlerini tarafsız bir yerde toplayın. İzin verilen protokol yazıcılarını şemada tanımlayıp kenarları otomatik test edin. [Şema kuralları](mimari/zmax_mimari_semasi.html#L525) · [L1](../src/pipeline/l1_connection.rs#L3) · [L5](../src/pipeline/l5_router.rs#L6) · [L6](../src/pipeline/l6_cache.rs#L4) · [A7](../src/api/admin_static.rs#L98)

### E05 · P1 — Yapılandırma yenilemesi kısmi değişikliği başarı sayabiliyor

Reload doğrulaması mevcut. Limitleyici, log, TLS ve statik işleyici farklı adımlarda güncelleniyor, ardından ortak çalışma durumu yayımlanıyor. Ek dinleyici uzlaştırmasının döndürdüğü hatalar atılıyor ve nesil sayacı artıyor. Bu akış yeni yapılandırmanın bir kısmı uygulanamadığında başarılı reload sonucu verebilir. Kabul ölçütü, geçersiz dinleyici ayarında eski neslin ve çalışan yapılandırmanın korunması, hatanın API’ye yansımasıdır. [Reload adımları](../src/config/reload.rs#L111) · [Dinleyici sonucu ve nesil](../src/config/reload.rs#L159)

### E06 · P1 — TLS protokol ayarlarının çalışma zamanı bağlantısı eksik

HTTPS başlangıcı ALPN listesini `h2/http/1.1` olarak sabit veriyor. Yeniden yükleme yapılandırılmış listeyi hesaplıyor. Normal reload yolunda liste kullanılmıyor. `strict_sni` yapılandırma ve serileştirme alanı olarak var, istemciyi kabul eden kodda tüketicisi bulunamadı. Kabul için ayarları TLS dinleyicisine bağlayın ve her iki ayarın etkisini izole TLS testinde ölçün. QUIC modülü dosyada devre dışı yol haritası olarak tanımlı. Şema HTTP/HTTPS/H2 gösteriyor, bu nedenle QUIC ayrı bir şema açığı olarak sayılmadı. [ALPN başlangıcı](../src/core/boot.rs#L460) · [ALPN reload](../src/config/reload.rs#L172) · [SNI yapılandırması](../crates/zmax-config/src/lib.rs#L180) · [QUIC modülü](../modules/mod_quic.toml#L8)

### E07 · P1 — HTTP/1.1 ve HTTP/2 işleme farkları

- **Yönlendirme ve PHP.** H1 rewrite ve htaccess bayraklarını uygular. H2 aynı denetimleri yapmadan çözümleyiciye gidiyor ve PHP’ye boş `PATH_INFO` gönderiyor. TOML `rewrite.rules` bağlama kopyalanıyor, çalışma yolunda yürütülmüyor. [H1](../src/web_engine/pipeline_h1.rs#L444) · [H2](../src/web_engine/pipeline_h2.rs#L271) · [H2 FastCGI](../src/web_engine/pipeline_h2.rs#L374) · [TOML kuralları](../src/pipeline/l5_router.rs#L436)
- **Önbellek.** H1 eski yanıtı sunup arka planda yenileme ve eşzamanlı istek birleştirme kullanıyor. H2 PHP yolunda yalnız taze önbelleği kullanıyor. H2 statik yolu dosyaya gidiyor. Temizleme ve proxy kararının sırası da iki hatta farklı. [H1 cache](../src/web_engine/pipeline_h1.rs#L618) · [H2 cache](../src/web_engine/pipeline_h2.rs#L343)
- **Statik yanıt.** H2 dosyayı bütünüyle okuyor ve H1’in bayt aralığı ile dosya akışı yolunu paylaşmıyor. Başarılı statik yanıtta ETag yeniden tırnaklanıyor, `Last-Modified` alanına HTTP tarihi yerine Unix saniyesi yazılıyor. [H2 statik yanıt](../src/web_engine/pipeline_h2.rs#L472) · [H1 tarih ve aralık](../src/pipeline/l7_handlers/static_files.rs#L365)
- **Başlıklar ve günlük.** H2 normal yanıtlarında L8’in yapılandırılmış güvenlik başlığı uygulaması bulunamadı. H2 günlüğü çözümlenen istemci IP’si yerine soket eşini kullanıyor ve L8’in URL maskelemesini paylaşmıyor. [H2 yazıcı](../src/pipeline/l2_protocol/h2.rs#L352) · [H2 günlük](../src/pipeline/l2_protocol/h2.rs#L391) · [L8 maskeleme](../src/pipeline/l8_response.rs#L372)

Aynı iki vhost ile H1/H2’nin yapılandırma, statik yanıt, PHP yönlendirmesi ve log çıktısını karşılaştıran bir kabul matrisi kullanın. Bilinçli protokol istisnalarını belgeye ekleyin.

### E08 · P1 — Köprü şeması ve anlamsal doğrulama ayrışmış

JSON şeması düz kökte `domain` ve `root` bekliyor. Dağıtılan iki TOML örneğinde kök `vhost`, alanlar `vhost.name` ve `vhost.document_root`. Düz yapıya dönüşüm sözleşmede tanımlanmalı veya şema gerçek dosya biçimiyle hizalanmalı. Ayrıca OpenAPI, kullanılan status ve events uçlarını ve kimlik modelini kapsamıyor. Köprüde validate yalnız veri yapısını okuyor. İstek alan adını ve normal reload’un anlamsal kurallarını aynı şekilde denetlemiyor. Gerçek örnekleri hem Go hem Rust tarafında aynı kabul verisiyle doğrulayın. [JSON şeması](../go/contract/vhost.schema.json#L5) · [OpenAPI](../go/contract/openapi.yaml#L6) · [Rust validate](../src/api/bridge.rs#L58) · [Reload doğrulaması](../src/config/reload.rs#L84)

### E09 · P1 — Köprü istemcisi ve vhost işlemi bütünlük kanıtı üretmiyor

Go istemcisinde Unix soketi ve beş saniye zaman aşımı var. `MaxRetries` kullanılmıyor, olay tüketicisi eksik. HTTP hata yanıtı, yapılandırma reddinin tipli JSON ayrıntıları çözülmeden genel hataya dönüyor. Yaşam döngüsü uygulamadan önce sürüm kontrolünü çağırmıyor, nesil artışını doğrulamıyor ve geri alma/ikinci reload hatalarını atıyor. İlk oluşturmada boş yedek yolu aktif rollback ile işlemiyor. Rust yönetim yazarı Go `.lock` sözleşmesini paylaşmıyor. Tek yazıcı veya ortak kilit belirleyin. Yazma, geri alma ve ikinci reload sonucu bağımsız olarak doğrulansın. [Go HTTP hata yolu](../go/zmaxbridge/client.go#L102) · [Yaşam döngüsü](../go/lifecycle/lifecycle.go#L50) · [Go dosya kilidi](../go/lifecycle/writer.go#L35) · [Rust yazıcı](../src/api/services/vhost_service.rs#L17)

### E10 · P1 — Sağlık yolu ve oturum rolü istemcilerle uyumsuz

Sağlık yanıtı `/healthz` ve `/health` yollarına taşındı. WebAdmin ve Go istemcisi hâlâ `/api/v1/health` çağırıyor. WebAdmin dinleyicisindeki erken yol denetimi yeni sağlık yollarını yönetim yönlendiricisine ulaşmadan eliyor. Şema yalnız `/api/v1` hedefini veriyor, kaynakta eski yönetim takma yolları kabul edilmeye devam ediyor. Oturum doğrulaması kimlik kapısından geçiyor, ancak okuma rolü için de sabit `admin` etiketini döndürüyor. Sağlık yolunu istemciler, dinleyiciler ve OpenAPI’de eşleştirin. Yanıta doğrulanmış rolü taşıyın ve probe alanlarını amaçlarına göre sınırlandırın. [Rust sağlık](../src/api/routes/system.rs#L15) · [Yol kapısı](../src/api/mod.rs#L91) · [WebAdmin](../admin/js/api_client.js#L132) · [Go Health](../go/zmaxbridge/client.go#L136) · [Oturum rolü](../src/api/routes/system.rs#L1365)

### E11 · P1 — WebAdmin ve API başarısız işlemi başarılı gösterebiliyor

Vhost formu HTTP 500 ve bağlantı hatasında modalı kapatıyor, `vhost-saved` yayımlıyor. İki yerel Node simülasyonu bunu doğruladı. Ayrıca yönetim tarafı bazı yapılandırma yazma hatalarını, rollback ve reload sonucunu atıyor. Vhost silme, yeniden yükleme hatasında da başarı yanıtı üretebiliyor. Sonucu dosya yazımı ve yeni neslin uygulanması tamamlanana kadar başarıya çevirmeyin. Başarısızlıkta form girdisi korunmalı. [WebAdmin kaydetme](../admin/js/views/vhosts.js#L210) · [Kalıcılık](../src/api/routes/system.rs#L414) · [Rollback](../src/api/routes/system.rs#L1288) · [Vhost silme](../src/api/routes/vhosts.rs#L148)

### E12 · P1 — Örnek telemetri canlı veri olarak kalıyor

Dashboard sabit RAM sınırı, önbellek ve servis durumu değerleri gösteriyor. Canlı istatistiklerde boş havuz veya dinleyici listesi geldiğinde örnek satırlar kalıyor. Yönetim API’si de harici uygulama kaydı bulunmadığında örnek havuzlar üretebiliyor. Örnekleri yalnız ayrı tanıtım kipinde tutun. Gerçek veride ölçülmeyen ve boş sonuçları ayrı gösterin. [Dashboard](../admin/js/views/dashboard.js#L140) · [Canlı istatistik](../admin/js/views/livestats.js#L59) · [API havuzları](../src/api/routes/system.rs#L1177)

### E13 · P2 — Çekirdek bakım ve Redis politika yenilemesi kısmi

Bakım döngüsü gerçek başlangıçta `boot.rs` içinde çalışıyor. Şemadaki `core/tasks.rs` yordamı çağrılmıyor ve aynı döngüyü tekrar içeriyor. Sinyaller için de çalışan boot yolu ve çağrılmayan bir yardımcı var. Redis aboneliği çalışıyor. Abone `ban_sync` değerini bağlanırken yakalıyor ve yeniden bağlanma anahtarı bu bayrağı kapsamıyor. Aynı bağlantı bilgileriyle politika değişince eski değer kalabilir. Dolu olay kuyruğunda gönderim hatası atılıyor. Bakımı tek sahip altında toplayın, Redis politikasını güncel okuyun ve kayıp olay sayacını görünür kılın. [Boot bakımı](../src/core/boot.rs#L430) · [Bakım yordamı](../src/core/tasks.rs#L6) · [Redis abonesi](../src/redis/events.rs#L47)

### E14 · P2 — WebAdmin varlık, akış ve denetim davranışları eksik

Eksik JS/CSS dosyası, SPA HTML’ine geri düşüp başlığa varlık türüyle `200` dönebilir. SPA gezinme yolu ve statik dosya hatasını ayırın. Log SSE artık token’ı istek başlığında taşıyor. Şemadaki SSE sorgu belirteci notu bu akış için eski. İlk girişte URL belirteci alma ve tarayıcıda kalıcı saklama sürüyor. Log akış sonu ve okuma rolü kapsamı gözden geçirilmeli. Denetim kaydında rol `bilinmiyor` olarak yazılıyor ve bazı işlemler tamamlanmadan başarı kaydediliyor. [Statik varlık](../src/api/admin_static.rs#L78) · [SSE](../admin/js/api_client.js#L261) · [Token başlangıcı](../admin/js/api_client.js#L11) · [Okuma kuralları](../src/api/auth.rs#L78) · [Denetim rolü](../src/api/audit.rs#L54) · [Cache denetimi](../src/api/services/cache_service.rs#L68)

### E15 · P2 — Mimari belge ve otomatik doğrulama kapısı eksik

Şema `doc/00_MIMARI_GENEL_BAKIS.md` ve `01–07` ayrıntı belgelerine gönderme yapıyor. Bu kaynak kopyasında `doc/` yok. Şemadaki eski Go yolunu gerçek `go/` diziniyle güncelleyin ve ayrıntı belgelerinin güncel yollarını yayımlayın. Mimari kural yapılandırması ve yerel `.github/workflows` görünmüyor. 18 Cargo çalışma alanı üyesi, ana ikili ve 17 altyapı crate’inden oluşuyor. Altyapı adları şemada var. Otomatik katman kuralı ve CI kanıtı bu kopyada eksik. [Şema başlangıcı](mimari/zmax_mimari_semasi.html#L28) · [Köprü yol notu](mimari/zmax_mimari_semasi.html#L490) · [Cargo çalışma alanı](../Cargo.toml#L1)

## Çalıştırılan kontroller

| Kontrol | Gerçek sonuç |
| --- | --- |
| `cargo metadata --offline --locked --no-deps --format-version=1` | Exit `0`. `workspace_members=18`, `explicit_test_targets=20 missing_test_sources=20`. |
| `cargo check --locked --offline --all-targets` | Exit `101`. `could not compile due to 20 previous target resolution errors`. |
| `cargo check --locked --offline --bin zmax` | Exit `0`. `Finished dev profile`, `29 warnings`. Kullanılmayan import ve yardımcılar var. |
| `node tests/webadmin_test.js` | `Toplam: 82 \| Başarılı: 82 \| Başarısız: 0`. |
| `node tests/webadmin_runtime_sim.js` | `Toplam: 66 \| Başarılı: 66 \| Başarısız: 0`. |
| Vhost kaydetme hata simülasyonu | `http_500 modal_closed=true vhost_saved=true` ve `network_error modal_closed=true vhost_saved=true`. |
| TOML ve JSON şeması karşılaştırması | İki örnekte `domain` ile `root` kök alanları eksik, kökte `vhost` ek alanı var. |
| Master Suite `architecture.js` | `PASS=0 FAIL=0 WARN=0 SKIPPED=1`. Mimari kural yapılandırması bulunamadı. |
| Go testleri | `go` ve `gofmt` bu ortamda bulunmadı. Kaynak sözdizimi ve sözleşme okundu. |

## Öncelik ve doğrulama sınırı

1. Önce Cargo test hedeflerini ve Go yazıcısını derlenebilir hale getirin.
2. Yayın öncesi başlangıç yetkisi, durum ve disk tutarlılığı, vhost geri alma, H1/H2 eşliği ve köprü uç sözleşmesini doğrulayın. WebAdmin başarısız işlemi açıkça bildirmeli.
3. Şema bağlantılarını güncelleyip otomatik katman kuralını ve CI kaydını aynı aday paketle ilişkilendirin.

Denetim aktif kaynak ağacında yürütüldü. Git üstverisi bulunmadığı için şemanın tarihsel commit’iyle bire bir kaynak kökeni doğrulanamadı. Ölçümler Windows’taki yerel kopyaya ait. Canlı sürüm, Linux’a özel akışlar ve gerçek Redis/PHP-FPM entegrasyonu ayrı kabul testi gerektiriyor.

