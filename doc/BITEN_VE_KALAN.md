# ZMax — Biten ve Kalan (özet)

**Amaç:** sahibin tek bakışta okuyacağı özet; ayrıntı ve etiketler başka belgelerdedir, burada tekrar edilmez. **Güncellenir:** önemli bir kart bitince / durum değişince. **Bağlı:** durum → [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md) · görevler → [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) · plan → [`YOL_HARITASI.md`](YOL_HARITASI.md) · OLS denkliği → [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md)
(Sahibin yazdırdığı uzun sürümün orijinali: `arsiv/2026-11-12/birlesen/BITEN_VE_KALAN_uzun.md`.)

## Biten (kanıt matriste)
- Çekirdek v1.0.01: 18 crate, `cargo test --workspace` raporu 216 geçti, 7 paket (`.zip`, `.tar.gz`, `.deb`, `.rpm`) doğrulandı.
- VM (eski ikili, test portları 19480/19483): statik, PHP/WordPress sayfası, TLS 1.3, HTTP/1.1, ACME dosyası geçti.
- Kodda bağlı ama **çalıştırılıp doğrulanmadı**: vhost günlüğü, `error_docs`, vhost WAF, HTTP/2, `SO_REUSEPORT`.
- Panel (Go): sunucu seçimi (`/etc/zpanel/webserver`), `zmax-gecis.sh`, vhost TOML yazımı + reload; ZMax 80/443'e **çevrilmedi** (OLS varsayılan).
- Belgeler: sadeleştirildi, görev kartlarına ayrıldı.

## Kalan (öncelik sırasıyla; ayrıntı kartlarda)
1. Kart 1: günlük, `error_docs`, WAF, HTTP/2'yi gerçek istekle doğrula. Kart 2–6: gerçek bayt, API CRUD, `.htaccess`/yönlendirme, hotlink+ACL, ACME/sertifika.
2. **Kart 7 (Go, en kritik):** panel ZMax TOML'una bugün yalnız vhost/cache/php/ssl/`force_https`/hotlink=false yazıyor; günlük, `error_docs`, ACL, parola koruması, WAF, vekil yazılmıyor.
3. Kart 8–11: FastCGI havuzu/`drop_privileges`/`sendfile` hatta bağlama, Basic Auth `$apr1$`, vekil başlıkları, WAF olayları. Kart 12: OLS denklik kapısı (HTTP/3 dahil).
4. Panel işleri (E6, E8–E11, E14): [`entegre/goentegre.md`](entegre/goentegre.md) §7.

## 80/443 varsayılan yapma kapısı
[`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) §2 (yan yana test, 5 uygulama, panel işlevleri, protokol, 24 saat + yük altında reload, OLS'e tek komutla dönüş, araçlar) kanıtla geçilene kadar OpenLiteSpeed varsayılan kalır.
