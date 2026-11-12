# ZMax — Görev Kartları (TEK KAYNAK: yapılacak işler)

**Amaç:** yapay zekaya verilebilir, numaralı, önceliklendirilmiş görev kartları. **Güncellenir:** kart bitince (kanıtla) ya da yeni iş çıkınca; durum etiketi burada tutulmaz → [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md). **Bağlı:** [`YOL_HARITASI.md`](YOL_HARITASI.md) (faz/sürüm) · [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) (satır kodları A1…E4) · [`entegre/goentegre.md`](entegre/goentegre.md) (Go sözleşmesi) · [`YAPAY_ZEKA_KURALLARI.md`](YAPAY_ZEKA_KURALLARI.md)

**Kullanım:** bir kartı **tek başına** ver. Kural: kartın dışına çıkma; YAPILMAYACAK listesine dokunma; kanıtsız "bitti" deme (kanıt = komut + literal çıktı). Test portları: HTTP `127.0.0.1:19480`, HTTPS `127.0.0.1:19483`, API `127.0.0.1:19486`. Her kart sonunda: `cargo fmt --all -- --check && cargo check --workspace && cargo test --workspace --offline && cargo clippy --workspace --all-targets -- -D warnings`.

**Bitenler (özet, kanıt matriste):** çekirdek v1.0.01 (18 crate, 216 test geçti raporu, 7 paket). Eski adım 1–7 tamam.

## Kart sırası
| # | Kart | Faz/Sürüm | OLS satırı | Sahip |
|---|---|---|---|---|
| 1 | Faz 0 doğrulama + istek hattı entegrasyon testleri (günlük, error_docs, WAF, HTTP/2) | v1.0.02 | A4, B9, B10, C5 | R |
| 2 | Günlükte gerçek bayt, panel/fail2ban uyumu | v1.0.02 | B10, B11, C4 | R (+G) |
| 3 | vhost API CRUD tam alan + atomik yazım/geri alma | v1.0.02 | — | R |
| 4 | `.htaccess` ve yönlendirme gerçek-site doğrulaması | v1.0.02 | B2, B4, B5, B7, B15 | R |
| 5 | Hotlink listesi + IP ACL (şema + istek hattı) | v1.0.02 | C1, C2 | R (+G) |
| 6 | ACME ortak kök + sertifika yenileme sonrası sunum | v1.0.02/07 | B8, E2 | R (+G) |
| 7 | **Go:** `RenderZmaxVhost` genişletme (panel TOML'a her alanı yazsın) | v1.0.02 | B9, B10, C1–C3, C5, D1 | G |
| 8 | FastCGI havuzunu hatta bağla, `drop_privileges`, `sendfile`, symlink izni | v1.0.03 | B3, B14 | R |
| 9 | Basic Auth (`$apr1$`) | v1.0.03 | C3 | R |
| 10 | Vekil: `X-Forwarded-*`, tamponsuz akış, WebSocket | v1.0.06 | D1–D3 | R |
| 11 | WAF aç/kapa/istisna + olay günlüğü/sayaç | v1.0.08 | C5 | R (+G) |
| V1-1 | **HTTP/2 yolu, HTTP/1.1 ile aynı güvenlik denetimlerinden geçsin** (VM-TEST-1 bulgusu) — ÖNCELİKLİ, Kart 5 ile birlikte | v1.0.02 | C1, C2, C5, B9 | R |
| 12 | OLS denklik kapısı (HTTP/3 dahil) | v1.0.10 | tümü | R+G |
Sonraki fazlar (kart henüz yok; Faz 2–4 maddeleri): [`YOL_HARITASI.md`](YOL_HARITASI.md) §4.

---

## Kart 1 — Faz 0 doğrulama + istek hattı entegrasyon testleri
- **Hedef:** "kodda var" denen günlük, `error_docs`, vhost WAF ve HTTP/2'nin gerçek istekte çalıştığını testle kanıtlamak (bugün hiçbiri çalıştırılıp doğrulanmadı).
- **Dokunulacak:** `crates/zmax-bin/src/web_engine.rs` (test modülü), `main.rs`, `h2_engine.rs`, `logger.rs`; testler `crates/zmax-bin/tests/` (yeni) ya da `#[cfg(test)]`.
- **Yapılacak:** (1) iki vhost'lu geçici yapılandırma ile süreç başlatan entegrasyon testi; (2) iki vhost'a istek → her biri kendi `access_log`'unda, satırda tarih ve gerçek bayt; (3) vhost `error_docs` 404 → vhost `404.html`, yoksa varsayılan sayfa; (4) `waf_enabled=false` vhost'ta SQLi imzası 200, `true`'da 403, `waf_exclude_paths` muaf; (5) `curl --http2` → `HTTP/2 200`, çok akışlı istek, `--http1.1` etkilenmez; (6) HTTP/2'de WAF/rewrite/log çalışıyor mu; (7) `SIGUSR1` sonrası günlük yeni dosyaya yazıyor.
- **YAPILMAYACAK:** yeni özellik, refactor, crate ekleme, ALPN'i kaldırma/değiştirme (HTTP/2 başarısızsa yalnız raporla), panel (Go) kodu.
- **Kabul testi:** `cargo test -p zmax-bin --offline` (yeni testler geçer); elle: `curl -s -o /dev/null -w '%{http_code}' -H 'Host: ornek1.test' http://127.0.0.1:19480/` ve `curl -sk --http2 -I --resolve ornek1.test:19483:127.0.0.1 https://ornek1.test:19483/` → `HTTP/2 200`; `tail -n1 <access_log>` → `[tarih] … STATUS BAYT` (BAYT 0 değil, `Content-Length` ile eşit).
- **Kanıt:** komut + literal çıktı; geçmeyen maddeler "FAIL" olarak yazılır; matris etiketi yalnız kanıtla yükseltilir.
- **Go bağımlılığı:** yok.

## Kart 2 — Günlükte gerçek bayt, panel/fail2ban uyumu
- **Hedef:** `bytes_sent` gerçek gönderilen baytı yazsın; panelin günlük/trafik okuyucusu ve fail2ban satırı ayrıştırabilsin.
- **Dokunulacak:** `crates/zmax-bin/src/logger.rs`, `web_engine.rs` (`log_access` çağrıları, ~satır 2676–2727), `h2_engine.rs`. Panel okuyucu (okuma amaçlı): `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\{logs,stats,domainstats}`, biçim: `sites/logs.go` (`%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`).
- **Yapılacak:** statik, FastCGI, vekil, önbellek HIT, hata sayfası ve HTTP/2 yollarında gerçek bayt; HEAD/304'te 0 → `-` kuralı (NCSA); satır biçimi panelin `logs.ParseAccess` testiyle aynı; günlük yolu kararı için `entegre/goentegre.md` §6'ya tek yol yaz.
- **YAPILMAYACAK:** yeni günlük biçimi, JSON varsayılanı yapmak, panel kodunu değiştirmek.
- **Kabul testi:** her yanıt tipi için `curl -s -o /dev/null -w '%{size_download}'` değeri = günlükteki bayt; panelin `logs_test` ayrıştırıcısı örnek satırı ayrıştırır (`go test ./internal/logs/...` panel deposunda, yalnız okuma).
- **Kanıt:** tablo: yanıt tipi | `size_download` | günlük baytı.
- **Go bağımlılığı:** `sites/logs.go` (yol/biçim), `logs`, `stats`, `domainstats` paketleri; `RenderZmaxVhost` `[vhost.logging]` yazmıyor (Kart 7).

## Kart 3 — vhost API CRUD tam alan + atomik yazım/geri alma
- **Hedef:** `PUT/POST /api/v1/vhosts` tüm vhost alanlarını yazsın; hatalı TOML çalışan yapılandırmayı bozmasın.
- **Dokunulacak:** `crates/zmax-bin/src/api.rs` (`format_vhost_json`, PUT/POST), `crates/zmax-config`.
- **Yapılacak:** `hotlink_protection`, `allow_ips`, `deny_ips`, `rewrite.*`, `headers.*`, `logging.*`, `error_docs.*`, `security.waf_*` alanlarının JSON→TOML turu (yazıp geri okuyunca eşit); geçersiz alan 400 + dosya değişmez; reload sonrası aktif yapılandırma = yazılan.
- **YAPILMAYACAK:** yeni uç, kimlik doğrulama değişikliği, şema yeniden adlandırma.
- **Kabul testi:** `python doc/tools/live_smoke.py` + yeni birim testleri: alan başına PUT → GET eşitliği; bozuk gövde → 400 ve `conf/vhosts/<alan>.toml` baytları değişmemiş.
- **Kanıt:** PUT/GET JSON çifti + komut çıktısı.
- **Go bağımlılığı:** panelin yazdığı TOML ile aynı şema (`sites/zmax.go` `RenderZmaxVhost`).

## Kart 4 — `.htaccess` ve yönlendirme gerçek-site doğrulaması
- **Hedef:** WordPress/Laravel permalink, panelin yönlendirme bloğu ve `.htaccess` ek direktifleri güncel ikiliyle gerçek vhost'ta geçsin (VM'de "kısmi" çıkmıştı).
- **Dokunulacak:** `crates/zmax-rewrite/src/htaccess.rs` ve gerekirse `web_engine.rs` bağlantısı.
- **Yapılacak:** panelin ürettiği blok (`redirects/redirects.go`: `RewriteCond %{HTTPS} off`, `%{HTTP_HOST}`, `RewriteRule … [L,R=301]`, `%1` geri başvurusu) için birim + entegrasyon testi; `<FilesMatch> Deny/Require all denied`; `Options -Indexes`; `ErrorDocument`; yönlendirme döngüsü ve regex karmaşıklığı sınırı; bilinmeyen `Host` yanıtı (OLS_DENKLIK B15).
- **YAPILMAYACAK:** `AddType/AddHandler`, mod_* yeni direktif ailesi, `.htaccess`'i TOML'a çeviren Go katmanı.
- **Kabul testi:** `cargo test -p zmax-rewrite --offline`; `curl -sI -H 'Host: wp.test' http://127.0.0.1:19480/ornek-yazi/` → `200`; `…/` `force_https` vhost'unda → `301 Location: https://…`; `www`↔non-www 301.
- **Kanıt:** komut+çıktı; WordPress dizinini kullanan VM çıktısı (varsa).
- **Go bağımlılığı:** `redirects/redirects.go`, `sites/htaccess_compat.go` (okuma).

## Kart 5 — Hotlink listesi + IP ACL
- **Hedef:** panelin hotlink (uzantı + izinli alan listesi) ve IP engeli ZMax'te de aynı davranışı versin.
- **Dokunulacak:** `crates/zmax-config` (şema), `crates/zmax-security`, `web_engine.rs`.
- **Yapılacak:** `hotlink_protection` bool'una ek izinli referer alanları + uzantı listesi (varsayılanlar geriye uyumlu); `allow_ips`/`deny_ips` CIDR'ın istek hattında vhost başına uygulandığını test et; boş Referer izin verilir (`RewriteCond %{HTTP_REFERER} !^$` karşılığı).
- **YAPILMAYACAK:** coğrafi engel, hız sınırı değişikliği.
- **Kabul testi:** birim testleri + `curl -H 'Referer: http://baska.test/' http://127.0.0.1:19480/resim.jpg` → 403, izinli referer → 200; engelli CIDR'dan istek → 403.
- **Kanıt:** komut+çıktı.
- **Go bağımlılığı:** `domainsec/apply_render.go` (hotlink), `domainsec/apply_ip.go` (ACL) biçimleri; Kart 7.

## Kart 6 — ACME ortak kök + sertifika yenileme sonrası sunum
- **Hedef:** certbot doğrulama dosyası hem belge kökünden hem panelin ortak kökünden sunulsun; sertifika yenilenince yeni sertifika sunulsun.
- **Dokunulacak:** `zmax-config` (ACME kök alanı), `zmax-static`, `web_engine.rs`; `zmax-tls` yeniden yükleme.
- **Yapılacak:** `/.well-known/acme-challenge/` isteğini vhost belge kökünden, yoksa ortak kökten (`/var/www/acme`) sun (`force_https` muaf); reload sonrası SNI tablosu yeni dosyayı okur; panel/API portu sertifikası (`admin_tls`/`api_tls`) da yenilenir.
- **YAPILMAYACAK:** dahili ACME istemcisi (`zmax-acme`), DNS-01.
- **Kabul testi:** dosya koy → `curl -s http://127.0.0.1:19480/.well-known/acme-challenge/x` = içerik; sertifikayı değiştir + `curl -X POST :19486/api/v1/reload` → `openssl s_client -connect 127.0.0.1:19483 -servername ornek1.test | openssl x509 -noout -serial` yeni seri.
- **Kanıt:** önce/sonra seri numaraları.
- **Go bağımlılığı:** `sites/sites.go` `acmeContext`/`AcmeRoot`, `ssl/ssl.go` (certbot webroot).

## Kart 7 — Go: `RenderZmaxVhost` genişletme (panel)
- **Hedef:** panel, OLS vhost'unda ürettiği her şeyi ZMax TOML'una da yazsın (bugün yalnız `[vhost]`, cache=false, php, ssl, `force_https`, `hotlink_protection=false` yazıyor).
- **Dokunulacak (panel deposu):** `cekirdek/agent/internal/sites/zmax.go` (`RenderZmaxVhost`, `ZmaxSpec`) + ilgili `_test.go`.
- **Yapılacak:** Kart 2/3/5'te Rust şeması hazır olan alanları yaz: `[vhost.logging]`, `[vhost.error_docs]`, hotlink, `allow_ips/deny_ips`, `security.waf_*`, `[vhost.proxy]` (Node), parola koruması (Kart 9 sonrası); `zmax.go` dosya başı yorumundaki "şemada yok" listesini güncelle; `webserver/settings.go` (H3/gzip/gövde) ve `performance.go` ekranlarını ZMax'te karşılığı yoksa "desteklenmiyor" göster.
- **YAPILMAYACAK:** OLS yazım yolunu değiştirmek, panel arayüzü, Rust kodu.
- **Kabul testi:** panel deposunda `go test ./internal/sites/...` (TOML çıktısı `zmax-config` ile ayrıştırılabilir: `zmax -t -c <yapılandırma>`).
- **Kanıt:** üretilen TOML örneği + `zmax -t` çıkış kodu 0.
- **Go bağımlılığı:** kartın kendisi Go işidir; Rust şeması hazır olmadan ilgili alan yazılmaz.

## Kart 8 — FastCGI havuzunu hatta bağla, `drop_privileges`, `sendfile`, symlink izni
- **Hedef:** kütüphanede hazır olup `zmax-bin`'in çağırmadığı üç parça gerçekten çalışsın; üretim yetki modeli güvenli olsun.
- **Dokunulacak:** `web_engine.rs` (FastCGI çağrısı → `execute_php_pooled`), `zmax-static` + `web_engine.rs` (`sendfile`), `main.rs` (`drop_privileges` bind sonrası), `zmax-fastcgi` (`resolve_root_symlink`).
- **Yapılacak:** havuzlu bağlantı (önceki istek bitmeden yeniden kullanma yok, bayat soket yeniden denemesi); `drop_privileges` **öncesi** günlük/önbellek/tmp sahipliği; `CAP_NET_BIND_SERVICE` ile 80/443; müşteri docroot symlink'inin OLS `allowSymbolLink 1` ile aynı davranışı; HTTPoxy (`Proxy:` → hiçbir zaman `HTTP_PROXY`) istek yolu testi.
- **YAPILMAYACAK:** yeni PHP özelliği, SAPI değişikliği, worker modeli yeniden yazımı.
- **Kabul testi:** `cargo test -p zmax-fastcgi -p zmax-bin --offline`; `curl -H 'Proxy: http://x' …` ile PHP `getenv('HTTP_PROXY')` boş; 1000 ardışık PHP isteğinde yeni bağlantı sayısı (`ss -tn`) << 1000; süreç `ps -o user` = yetkisiz kullanıcı, günlük yazılıyor.
- **Kanıt:** komut+çıktı.
- **Go bağımlılığı:** php-fpm havuz soketi/kullanıcısı (`sites/zmax_fpm.go`, `tenant.go`).

## Kart 9 — Basic Auth (`$apr1$`)
- **Hedef:** panelin parola korumalı dizinleri (htpasswd `$apr1$`) ZMax'te de çalışsın.
- **Dokunulacak:** `zmax-security` (ya da `zmax-header`; yeni crate açma), `zmax-config` (`[vhost.auth]`/dizin listesi), `web_engine.rs`.
- **Yapılacak:** Apache MD5 `$apr1$` doğrulama (+ Argon2id), `realm`, dizin öneki, sabit zamanlı karşılaştırma, parola günlüğe yazılmaz.
- **YAPILMAYACAK:** OAuth/JWT, oturum çerezi.
- **Kabul testi:** `htpasswd -nbm kul parola` ile üretilen hash'le `curl -u kul:parola` → 200, yanlış parola → 401 `WWW-Authenticate`.
- **Kanıt:** komut+çıktı.
- **Go bağımlılığı:** `domainsec/apply_auth.go` (dosya biçimi), Kart 7.

## Kart 10 — Vekil: `X-Forwarded-*`, tamponsuz akış, WebSocket
- **Hedef:** panel/webmail/Zplus/Node uygulamaları ZMax vekilinin arkasında OLS'teki gibi çalışsın.
- **Dokunulacak:** `crates/zmax-proxy`, `zmax-config` (`[vhost.proxy]`), `web_engine.rs`.
- **Yapılacak:** istemci adresini `X-Forwarded-For` **sonuna** ekle (var olan değeri silme), HTTPS'te `X-Forwarded-Proto/Host`; `respBuffer 0` karşılığı akış (SSE: `: heartbeat` satırları gelir gelmez iletilir), `initTimeout`/keep-alive ayarları; WebSocket `Upgrade`.
- **YAPILMAYACAK:** yük dengeleme, sağlık denetimi, devre kesici (v1.0.06 sonrası).
- **Kabul testi:** sahte backend (`python -m http.server` ya da SSE üreten betik) ile: backend `X-Forwarded-For` alır; SSE parçası ≤1 sn içinde istemciye ulaşır; `websocat` yankı testi.
- **Kanıt:** komut+çıktı.
- **Go bağımlılığı:** `config/ols/vhosts/zpanel-*/vhost.conf` yorumları (davranış kaynağı), `sites/proxyctx.go`, `webmail.go`, `zplus.go`; Kart 7.

## Kart 11 — WAF aç/kapa/istisna + olay günlüğü/sayaç
- **Hedef:** panelin ModSecurity ekranı (aç/kapa, yola göre istisna, 24 saatlik sayaç) ZMax WAF'ına bağlanabilsin.
- **Dokunulacak:** `zmax-security`, `web_engine.rs`, `logger.rs` (WAF olay satırı).
- **Yapılacak:** WAF olayı denetim günlüğüne yazılır (kural, yol, IP, zaman); aç/kapa vhost başına; istisna `waf_exclude_paths`.
- **YAPILMAYACAK:** OWASP CRS uyumu iddiası (Faz 5).
- **Kabul testi:** SQLi isteği → 403 + olay satırı; istisna yolu → 200.
- **Kanıt:** komut+çıktı. **Go:** `modsec/`, `domainsec/waf.go` (olay biçimi uyarlaması).

## Kart 12 — OLS denklik kapısı (v1.0.10)
- **Hedef:** [`OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) §2'nin tamamını kanıtla geçmek; HTTP/3-QUIC'i eklemek (ya da panelde `quicEnable` anahtarının ZMax seçiliyken "desteklenmiyor" gösterilmesini yazılı kabul ettirmek).
- **Yapılacak/Kabul:** OLS_DENKLIK §2'deki 7 madde (yan yana test, 5 uygulama, panel işlevleri, protokol, 24 saat/yük altında reload, geri dönüş, araçlar).
- **YAPILMAYACAK:** kapı geçilmeden 80/443'ü ZMax'e çevirmek.
- **Kanıt:** her madde için komut+çıktı dosyası.

## Kart V1-1 — HTTP/2 yolu güvenlik denetimleri eşitliği (VM-TEST-1 bulgusu)
- **Neden:** canlıda (VM-TEST-1) HTTPS/h2 üzerinde hotlink koruması çalışmadı; `handle_h2_dispatched_request` (`web_engine.rs`) `hotlink_protection` alanını okumuyor. Başka denetimler (IP ACL, vhost WAF, force_https, rewrite) için de h2 yolu kanıtsız.
- **Dokunulacak:** `web_engine.rs` / `h2_engine.rs` (ortak denetim fonksiyonu; mümkünse yeni modül, ortak dosyada yalnız çağrı satırı).
- **Yapılacak:** iki yolun denetimleri koddan çıkarılıp farklar tablosu (denetim | HTTP/1.1 | HTTP/2 | düzeltme); eksikler ortak fonksiyon üzerinden her iki yola bağlanır; Kart 5 RED maddeleri (listeler `&[]` değil, vhost'tan) birlikte kapanır.
- **YAPILMAYACAK:** yeni özellik, HTTP/3.
- **Kabul testi:** her denetim için hem HTTP/1.1 hem h2 gerçek istek: yabancı Referer 403 / boş 200 / izinli 200; deny CIDR 403; WAF 403; force_https 301. Uzak test sunucusunda (Aşama 1) `curl --http2` ile tekrar, `VM-TEST-2.md`.
- **Kanıt:** komut+çıktı.
