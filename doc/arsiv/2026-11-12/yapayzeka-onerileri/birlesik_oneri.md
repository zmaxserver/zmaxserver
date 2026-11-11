# ZMax Server: Birleşik Öneri (ChatGPT + DeepSeek, koda göre doğrulanmış)

Tarih: 2026-11-12. Kaynak: bu klasördeki dört dosya + `D:\zmaxserver\crates` kaynak kodunun okunması. Kod çalıştırılıp denenmedi (yalnız `cargo test --workspace` çıkış kodu 0 görüldü). Doğrulanmayanlar "bilinmiyor" yazıldı.

## 1. Dosyaların uygunluğu

| Dosya | Uygun mu | Neden |
|---|---|---|
| `chatgptoneri.md` | Büyük ölçüde uygun | Yöntem sağlam: "kod var ≠ çalışıyor", 6 durum etiketi, önce entegrasyon. P0 listesi (HTTP/2, vhost günlüğü, WAF, error_docs) koddan doğrulanan eksiklerle aynı. |
| `deepseek_oneri.md` | Uygun | Entegrasyon ve operasyon odaklı: `drop_privileges` sonrası dosya izni, worker respawn, L1 önbellek tutarlılığı gerçek riskler. Prometheus ve Windows maddeleri düşük öncelik. |
| `chatgpt.md` | Uygun değil | `zmax-realip`, `zmax-metrics`, `zmax-log`, `zmax-acme`, `zmax-cli` crate'lerini "var" sayıyor. Gerçek 18 crate içinde yok. |
| `seepseek.md` | Eski, güvenilmez | "HTTP/1.1 aktif, h2 yok, tek süreç, FastCGI keep-alive yok, setuid planlı" diyor. `chatgptoneri.md` bunların çoğunu yapılmış sayıyor; ikisi çelişiyor, koddan kontrol gerekir. |

Ortak sorunlar:
- `chatgptoneri.md` ve `deepseek_oneri.md`, `zmax-bin/src/logger.rs` ve `h2_engine.rs` dosyalarından söz ediyor. Şu anki ağaçta `zmax-bin/src` içinde yalnız `api.rs`, `main.rs`, `modules_runtime.rs`, `web_engine.rs` var. Önce bu doğrulanmalı.
- "179 birim testi" rakamı doğrulanmadı (başka bir inceleme 131 saymıştı).

## 2. Koddan doğrulanan gerçek durum (2026-11-12)

| Özellik | Durum | Kanıt |
|---|---|---|
| `force_https` | INTEGRATED | `web_engine.rs` satır ~490, ACME muaf |
| `hotlink_protection` | INTEGRATED | `web_engine.rs` satır ~852 |
| `.htaccess` (`RewriteEngine/Base/Cond/Rule`, `RedirectMatch`, `DirectoryIndex`, `ErrorDocument`) | INTEGRATED (yalnız kök `.htaccess`) | `zmax-rewrite/src/htaccess.rs`, `main.rs` |
| Vhost günlüğü (`VHostLoggingSection`) | Yalnız şemada | `zmax-config`'te tanım var, `zmax-bin` içinde okunmuyor |
| Günlük satırı | Eksik | `IP - - "METHOD PATH HTTP/1.1" STATUS -` (zaman damgası yok, bayt sabit `-`) |
| `error_docs` (`VHostErrorDocsSection`) | Yalnız şemada | `web_engine.rs`'te kullanımı yok |
| Vhost WAF (`waf_enabled`, `waf_exclude_paths`) | Yalnız şemada | `web_engine.rs`'te okunmuyor |
| HTTP/2 | Yarım, riskli | `zmax-tls` ALPN `["h2","http/1.1"]` duyuruyor, `zmax-bin/Cargo.toml`'da `h2 = "0.4"` var, `zmax-bin/src` içinde `h2` kullanan kod yok |
| TLS 1.3, SNI, sertifika yeniden yükleme | INTEGRATION TESTED (VM, test portu) | VM testi, `refresh_tls_certs` |
| `web_engine.rs` testleri | Yok | `#[test]` sayısı 0 |
| Worker / `SO_REUSEPORT`, `drop_privileges` izinleri, FastCGI keep-alive, `sendfile` | Bilinmiyor | Doğrulanmadı |

## 3. Birleşik yol haritası

### Kurallar (her çalışmada)
1. Her özellik 6 etiketten biriyle işaretlenir: PLANNED, IMPLEMENTED, UNIT TESTED, INTEGRATED, INTEGRATION TESTED, PRODUCTION VERIFIED.
2. Dosyada geçen crate, dosya ve sayılar önce koddan doğrulanır. Olmayan crate açılmaz.
3. Çalışan modül yeniden yazılmaz, minimal yama yapılır. Hatalı yapılandırma çalışan yapılandırmayı bozmaz.
4. Test çalıştırılmadan "geçti", derlenmeden "derleniyor" denmez. Benchmark uydurulmaz.
5. Panel (Go) özellikleri yeniden yazılmaz. PHP kullanıcı/havuz izolasyonu Go panelin işidir, ZMax yalnız soketi güvenli kullanır.

### Faz 0: Gerçeği tespit
Yukarıdaki tabloyu koddan doğrula. "Bilinmiyor" satırlarını kapat (worker modeli, `drop_privileges`, FastCGI keep-alive, `sendfile`). `logger.rs` ve `h2_engine.rs` var mı, belirle.

### Faz 1: Entegrasyon (iki kaynağın ortak P0'ı)
1. **Alan adına özel günlük:** vhost başına `access.log` ve `error.log`; gerçek gönderilen bayt, zaman damgası, NCSA combined (`IP - - [%d/%b/%Y:%H:%M:%S %z] "METHOD PATH HTTP/x" STATUS BAYT "Referer" "UA"`); `max_log_size_mb` döndürme; SIGUSR1 ile yeniden açma; tamponlu yazıcı. Panelin trafik/kota hesabı bu bayttan yapılır.
2. **`error_docs` ve vhost WAF'ı istek hattına bağla.** Sıra: hız sınırı → WAF → vhost bulma → `.htaccess` → FastCGI/statik.
3. **HTTP/2:** ya bitir (ALPN yönlendirmesi, `:authority`, WAF/rewrite/cache/log uyumu) ya da bitene kadar ALPN'i yalnız `http/1.1` yap.
4. **API:** `PUT/POST /api/v1/vhosts` eksik alanlar (`hotlink_protection`, ACL, `rewrite`, `logging`, `error_docs`, `security.waf_*`), TOML doğrulama, atomik yazım, hatalı yapılandırmada geri alma.
5. **`.htaccess` kalanları:** alt klasör `.htaccess`, `Options`, `[E=HTTP_AUTHORIZATION]`.
6. **İki vhost ile VM'de uçtan uca test:** HTTP/1.1, HTTP/2, FastCGI, statik, önbellek, WAF açık/kapalı, iki ayrı günlük.

### Faz 2: Üretim güvenliği (DeepSeek P0/P1 + ChatGPT §4)
- `drop_privileges` sonrası günlük, önbellek ve tmp dizinlerine yazma izni (aksi hâlde yetki düşünce günlük yazılamaz).
- Worker çökerse yeniden başlatma; `SO_REUSEPORT` durumu.
- Request smuggling (CL.TE/TE.CL), kopya `Content-Length`, başlık/CRLF enjeksiyonu testleri; HTTP/2 akış taşması.
- Redis `PurgeDomain`/`PurgeTag` gelince kendi L1 (Moka) önbelleğini de temizleme; önbellek anahtarına `Host`.
- Panel/API portundaki sabit sertifikanın yeniden yüklenmesi.

### Faz 3: Performans (ölçerek)
Nginx ve OpenLiteSpeed ile aynı donanımda: küçük/büyük statik, HTTP/1.1, HTTP/2, TLS el sıkışma, PHP-FPM, WordPress, önbellek HIT/MISS. RPS, P50/P95/P99, CPU, RSS. Ölçülmeden "daha hızlı" iddiası yok.

### Faz 4: Şimdilik yapma
OCSP, oturum sürdürme, Zstd, HTTP/3, QPACK, OpenTelemetry, Pagespeed, Prometheus özel metrikleri, Windows'a özel yol ayrımı. Faz 1 ve 2 bitince değerlendirilir.

## 4. Çalışma sonu raporu (zorunlu biçim)
Yapılan iş (dosyalar) · Gerçek durum (6 etiket) · Değişiklikler · Test komutu ve literal çıktısı · Güvenlik değerlendirmesi · Performans etkisi (ölçülmediyse "ölçülmedi") · Kalan eksikler · Tek sonraki adım.

## 5. Go (panel) tarafında yapılacaklar (ZMax kodu değil)
E6 panel/webmail/Zplus proxy vhost'ları · E8 certbot yenileme · E9 php-fpm kurulumu ve havuz/kullanıcı izolasyonu · E10 OpenLiteSpeed uzantısı · E11 günlük okuyucu ve kota/trafik hesabı · E14 `zmax-gecis.sh` içindeki eski "TLS yok" kapısı. Bunlar ZMax Faz 1 madde 1-2 bitince başlar.
