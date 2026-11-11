# ZMax ↔ OpenLiteSpeed Denklik Matrisi ve Kabul Kapısı

**Amaç:** ZMax'in OLS ile denkliği için gereken özellik matrisi (panelin gerçek OLS/ZMax üretimine göre) + "hatasız" kabul kapısı. **Güncellenir:** panel üretimi ya da ZMax durumu değişince; ZMax etiketleri özettir, geçerli olan matristir. **Bağlı:** [`../TAM_MODUL_VE_OZELLIK_MATRISI.md`](../TAM_MODUL_VE_OZELLIK_MATRISI.md) · [`../ADIMLI_GELISTIRME_TAKIP.md`](../ADIMLI_GELISTIRME_TAKIP.md) (kartlar) · [`../YOL_HARITASI.md`](../YOL_HARITASI.md)

Hedef (sahip): **ZMax, OpenLiteSpeed (OLS) ile denk olacak ve hatasız çalışacak.**
Güncelleme: 2026-11-12. Kaynak: gerçek panel kodu `D:\lunixpanel\zpanel-tam` (yalnız okundu, değiştirilmedi); ZMax durumu: [`../TAM_MODUL_VE_OZELLIK_MATRISI.md`](../TAM_MODUL_VE_OZELLIK_MATRISI.md). Etiketler: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` → `INTEGRATION TESTED` → `PRODUCTION VERIFIED`. Kanıtsız bilgi "bilinmiyor"; panel kullanmıyorsa "kullanmıyor".
Bu tarama panel dosyalarının başlık/yorum ve ilgili kod bloklarını okudu; her dosya satır satır okunmadı.

**Kritik bulgu:** panelin ZMax sürücüsü (`cekirdek/agent/internal/sites/zmax.go`, `RenderZmaxVhost`) bugün **yalnız** şunları yazıyor: `[vhost]` (name, aliases, document_root, index_files), `[vhost.cache] enabled=false`, `[vhost.php]`, `[vhost.ssl]`, `[vhost.security] hotlink_protection=false` + `force_https`. OLS vhost'unda panelin ürettiği günlük, `error_docs`, hotlink listesi, IP ACL, parola koruması, WAF, proxy, yönlendirme/htaccess uyumu ZMax TOML'una **hiç yazılmıyor** (dosyanın kendi yorumu: şemada yok diye). Yani ZMax kodunda olması yetmez; her satırda iki taraf da (Rust şema/davranış + Go yazım) gerekir.

Sınıflar: **ZORUNLU** = panel bugün kullanıyor, 80/443 geçişinden önce şart. **ZORUNLU\*** = panel ayar olarak yönetmiyor ama OLS'in varsayılan davranışı; sahibin "OLS ile denk" hedefi gereği şart. **İSTEĞE BAĞLI** = OLS'te var, panel kullanmıyor. Sahip: R = Rust (bu repo), G = Go (panel). Faz = [`../YOL_HARITASI.md`](../YOL_HARITASI.md) sürümü; **K** = OLS denklik kapısı (§3).

## 1. Denklik matrisi

### A. Dinleyiciler ve protokol
| # | Özellik | Panel/OLS'te ne yapıyor (kanıt) | ZMax karşılığı (etiket + kanıt) | Sınıf | Sahip | Faz |
|---|---|---|---|---|---|---|
| A1 | Müşteri siteleri 80/443, her alan + `www.` eşlemesi | `sites/sites.go` `block()`: `listener zpanelHttp/zpanelHttps *:80/*:443`, `map <alan> <alan>, www.<alan>`; ZMax 80/443'teyse OLS 8080/8443'e iner | `[listeners.http/https]`, Host+aliases eşleme: INTEGRATION TESTED (VM, test portlarında 19480/19483); 80/443'te çalışma denenmedi | ZORUNLU | R+G | K |
| A2 | Panel dinleyicileri 8026/8036/8056/8047/8046/8045, phpMyAdmin 8091 | `config/ols/zpanel-listeners.conf` (OLS `listener`, `map … *`, TLS `/etc/zpanel/tls/*.pem`); vhost'lar `config/ols/vhosts/zpanel-*/vhost.conf` | ZMax tarafında panel portları için vhost yok; `zmax-proxy` UNIT TESTED. ZMax 80/443'teyken bu portları kimin sunacağı (OLS çalışmıyorsa) **bilinmiyor** — `sites.go` yorumu: "panel portları ayrı blokta" | ZORUNLU | G (+R `[vhost.proxy]`) | K |
| A3 | TLS 1.2+1.3, sertifika zinciri, vhost başına `vhssl` | `sites.go` `vhsslFor` (`privkey.pem`, `fullchain.pem`, `certChain 1`), listener `sslProtocol 24` | `zmax-tls` SNI: INTEGRATION TESTED (VM, TLS 1.3); `[vhost.ssl]` panel yazıyor (`RenderZmaxVhost`) | ZORUNLU | R+G | K |
| A4 | HTTP/2 | Panel ayarı yok (grep: h2 yok); OLS ALPN `h2`'yi varsayılan sunar | `h2_engine.rs` + `main.rs` ALPN yönlendirmesi: INTEGRATED (koddan); `curl --http2`/VM testi yok; şemada `[vhost.tls] http2` var | ZORUNLU\* | R | v1.0.02, K |
| A5 | HTTP/3 (QUIC) | `webserver/settings.go` `H3` → `tuning quicEnable` (panel UI anahtarı); varsayılan değer panelde yok (httpd_config'ten okunur): bilinmiyor | PLANNED (`quinn`/`zmax-quic` yok) | ZORUNLU (panel anahtarı var) | R (+G anahtarı gizleme) | K (v1.0.10) |
| A6 | Genel ayarlar: keep-alive süresi, en büyük istek gövdesi, gzip aç/kapa | `webserver/settings.go` `Config{KaTimeout, Body, Gzip}` → `tuning keepAliveTimeout/maxReqBodySize/enableGzipCompress` | keep-alive: `zmaxconf` izinli anahtar `security.keep_alive_timeout_sec` (IMPLEMENTED); gövde sınırı anahtarı `zmaxconf`'ta **yok** (413 `zmax-httpparser` UNIT TESTED); gzip aç/kapa anahtarı yok | ZORUNLU | R+G | v1.0.04 |
| A7 | PHP işçi havuzu boyutu | `Config.Lsapi` → `extprocessor lsphp maxConns` + `PHP_LSAPI_CHILDREN` | php-fpm `pm.max_children` (panel `sites/zmax_fpm.go` havuz yazıyor); panel ekranının ZMax'e bağlanması: bilinmiyor | ZORUNLU | G | K |
| A8 | Sayfa önbelleği profili (high/balanced/dev) | `webserver/performance.go` `profileCache` → `module cache enableCache/expireInSeconds` (sunucu geneli LSCache) | `zmax-cache` UNIT TESTED; `cache.default_ttl_seconds` `zmaxconf`'ta; panel ZMax vhost'unda `cache enabled=false` yazıyor ("OLS vhost'unda da yoktu"). Profil→ZMax eşlemesi yok | ZORUNLU | G (+R) | v1.0.05 |
| A9 | LSCache başlık protokolü (`X-LiteSpeed-*`) | Panel yönetmiyor (grep: `sites`, `webserver`, `wordpress` paketlerinde yok); OLS modülü başlıkları kendisi işler | `zmax-cache` köprüsü UNIT TESTED, hatta bağlılığı doğrulanmadı | İSTEĞE BAĞLI | R | Faz 5'te kalır (Faz 3 listesinde) |

### B. Sanal konak ve içerik
| # | Özellik | Panel/OLS'te ne yapıyor (kanıt) | ZMax karşılığı | Sınıf | Sahip | Faz |
|---|---|---|---|---|---|---|
| B1 | docRoot, alan adı, alias | `sites.go` `vhostConf`: `docRoot`, `vhDomain`, `vhAliases www.<alan>` | `[vhost] name/aliases/document_root`: INTEGRATION TESTED (VM) | ZORUNLU | R+G | K |
| B2 | Dizin dosyaları, `Options ±Indexes` | `index { indexFiles index.php, index.html; autoIndex }`; `htaccess_compat.go` (`Options` → `autoIndex`) | `index_files` + `zmax-static` autoindex, `zmax-rewrite` `Options`: UNIT TESTED | ZORUNLU | R | v1.0.02 |
| B3 | PHP çalıştırma, kiracı izolasyonu | OLS `scripthandler lsapi:lsphp php`, kiracıya özel `extprocessor` (`extUser/extGroup`, `sites/tenant.go`); sürüm/INI: `php/php.go` | php-fpm havuzu + `[vhost.php] upstream=unix:…`: INTEGRATION TESTED (VM, WordPress sayfası). Sürüm değiştirme ve INI'nin php-fpm havuzuna yansıması: bilinmiyor. Kiracı hesabının belge köküne ZMax'in erişimi: bilinmiyor | ZORUNLU | G (+R) | K |
| B4 | `.htaccess` yükleme | `rewrite { enable 1; autoLoadHtaccess 1 }` (`sites.go`) | `zmax-rewrite` UNIT TESTED (25 test); kök+alt dizin, `htaccess_resolver` hatta bağlı (grep). VM'de permalink "kısmi" çıkmıştı (eski ikili) | ZORUNLU | R | v1.0.02 |
| B5 | `.htaccess` ek direktifleri | `htaccess_compat.go`: `Options`, `ErrorDocument`, `<FilesMatch> Deny` → `context exp:` `allowBrowse 0` | `Options`, `ErrorDocument`: UNIT TESTED; `FilesMatch/Deny/Require all denied`: koddan doğrulanmadı | ZORUNLU | R | v1.0.02 |
| B6 | `AddType`/`AddHandler` | Panel **kullanmıyor** (`htaccess_compat.go`: native karşılık üretilmiyor, satırlar OLS ayrıştırıcısına bırakılıyor) | bilinmiyor | İSTEĞE BAĞLI | R | Faz 5 |
| B7 | Yönlendirmeler (Force HTTPS, www/non-www, 301/302) | `redirects/redirects.go`: domain `.htaccess`'ine `# BEGIN zPanel Redirects` bloğu (`RewriteCond %{HTTPS} off`, `%{HTTP_HOST}`, `RewriteRule … [L,R=301]`, `%1`) | `zmax-rewrite` RewriteCond/Rule UNIT TESTED; vhost `force_https` INTEGRATED; panel ZMax'te `force_https`'i bu bloktan okuyor (`zmax.go` `forceHTTPS`). `%{HTTPS}` ve `%1` geri başvurusunun testi: bilinmiyor | ZORUNLU | R | v1.0.02 |
| B8 | ACME `.well-known` | `sites.go` `acmeContext`: `/var/www/acme/.well-known/acme-challenge/` ortak kök + `docroot/.well-known` | docroot içi statik sunum: INTEGRATION TESTED (VM, ACME http-01); ortak `/var/www/acme` kökü ZMax'te yok (şemada ACME context yok — `zmax.go` yorumu); `force_https` ACME muaf: INTEGRATED | ZORUNLU | R+G | v1.0.02 |
| B9 | Özel hata sayfaları | `sites/errordocs.go`: `<ana dizin>/error_docs/<kod>.html` (400, 403, 404, 500, 502, 503 …), OLS `errorpage` + `context` | `[vhost.error_docs]` UNIT TESTED (şema + `zmax-static` çözümleyici); `web_engine.rs` bağlamında alan var, kullanımı doğrulanmadı; panel ZMax TOML'una yazmıyor | ZORUNLU | R+G | v1.0.02 |
| B10 | Alan adına özel erişim/hata günlüğü | `sites/logs.go`: `<LogRoot>/<alan>/access.log`+`error.log`, biçim `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`, `rollingSize 2047M`, `keepDays 30`; okuyucular `logs`, `stats`, `domainstats` | `logger.rs` INTEGRATED (koddan): NCSA combined + JSON, SIGUSR1; **gerçek `bytes_sent` ve VM çalışması doğrulanmadı**; panel TOML'a `[vhost.logging]` yazmıyor; günlük yolu kararı açık (`../entegre/goentegre.md` §6) | ZORUNLU | R+G | v1.0.02 |
| B11 | İstatistik / trafik / kota | `stats`, `domainstats` paketleri B10 günlüğünü okur | B10'a bağlı: bayt doğru değilse trafik rakamı yanlış | ZORUNLU | R+G | v1.0.02 |
| B12 | Sıkıştırma | vhost `enableGzip 1`; panel vhost'larında `enableGzip 0`, `enableBr 0` (SSE için); müşteri vhost'unda `enableBr` yok (OLS varsayılanı: bilinmiyor) | `zmax-compress` Gzip + Brotli UNIT TESTED; hatta bağlılığı doğrulanmadı; Zstd yok | ZORUNLU (gzip), İSTEĞE BAĞLI (br/zstd) | R | v1.0.05 |
| B13 | Statik dosya başlıkları | Panel `expires`/cache başlığı **yazmıyor** (grep: yok); OLS varsayılanı ETag/Last-Modified | ETag/304/Range `zmax-static` UNIT TESTED + VM statik | ZORUNLU\* | R | K |
| B14 | Sembolik bağ izni | vhost `allowSymbolLink 1` (müşteri sitesi), `restrained 1` | symlink/`resolve_root_symlink` davranışı: bilinmiyor | ZORUNLU\* | R | v1.0.03 |
| B15 | Varsayılan / bilinmeyen Host, bakım sayfası | `sites/default_page.go`, `config/ols/vhosts/zpanel-maintenance` | bilinmeyen Host'a ZMax yanıtı: bilinmiyor | ZORUNLU | R | v1.0.02 |
| B16 | Çöp kutusu | `files/trash.go` (panel dosya yöneticisi); web sunucusundan bağımsız | ZMax'te yapılacak bir şey yok; yine de kapıda regresyon | İSTEĞE BAĞLI (denklik gerekmez) | G | K (kontrol) |

### C. Güvenlik
| # | Özellik | Panel/OLS'te ne yapıyor (kanıt) | ZMax karşılığı | Sınıf | Sahip | Faz |
|---|---|---|---|---|---|---|
| C1 | Hotlink koruması | `domainsec/apply_render.go`: vhost `rewrite` kuralları (`RewriteCond %{HTTP_REFERER}`, uzantı listesi, izinli alan adları) | `hotlink_protection` bool: INTEGRATED; izinli alan/uzantı listesi şemada **yok**; panel `false` yazıyor | ZORUNLU | R (şema) + G | v1.0.02 |
| C2 | IP erişim kısıtı (CIDR allow/deny) | `domainsec/apply_ip.go`: `accessControl { allow *; deny <ağlar> }`, CIDR doğrulama | `allow_ips`/`deny_ips` + `zmax-security` CIDR ACL: UNIT TESTED; panel TOML'a yazmıyor | ZORUNLU | R+G | v1.0.02 |
| C3 | Parola korumalı dizin | `domainsec/apply_auth.go`: `realm`/`userDB` htpasswd, **Apache MD5 `$apr1$`**; `context <dizin>/ allowBrowse 1 realm` | Basic Auth yok (PLANNED). Planlanan Argon2id yetmez: panelin `$apr1$` dosyalarını doğrulamalı | ZORUNLU | R (+G) | v1.0.03 (Faz 4'ten çekildi) |
| C4 | Kaba kuvvet koruması | `domainsec/apply_brute.go`: fail2ban jail, alan günlük dizinini izler (`maxretry/findtime/bantime`) | ZMax günlüğü fail2ban'ın okuyacağı biçim/konumda olmalı (B10); ZMax kendi wp-login oto-banı UNIT TESTED | ZORUNLU | R+G | v1.0.02 |
| C5 | ModSecurity / OWASP CRS | `modsec/modsec.go`: `module mod_security` aç/kapa, `SecRuleEngine`, kural seti seçimi, yola göre istisna; `domainsec/waf.go` denetim günlüğü sayacı | Temel WAF (SQLi/XSS/CMDi/traversal) UNIT TESTED; `waf_enabled`/`waf_exclude_paths` şema+bağlam (kullanımı doğrulanmadı); **CRS uyumu yok**; WAF olay günlüğü biçimi yok | ZORUNLU (aç/kapa, istisna, sayaç); CRS tam uyum İSTEĞE BAĞLI | R+G | v1.0.08; CRS Faz 5 |
| C6 | Güvenlik başlıkları (HSTS vb.) | Müşteri siteleri: panel yazmıyor. Panel vhost'ları: `extraHeaders`; `serversettings/hsts.go` panel HSTS'ini yazar | `zmax-header` UNIT TESTED; panel vhost'larında ZMax'e taşınırsa `[vhost.headers]` gerekir | ZORUNLU (yalnız panel vhost'ları ZMax'e taşınırsa) | R+G | K |
| C7 | Gerçek istemci IP (CDN arkası) | Panel yönetmiyor (`useIpInProxyHeader` kapalı tutuluyor) | `trusted_proxies` + `resolve_real_ip` UNIT TESTED | İSTEĞE BAĞLI | R | Faz 4 |
| C8 | Hız sınırı / Slowloris | Panel OLS için yönetmiyor | `zmaxconf` izinli anahtarlar (rate limit, slowloris) IMPLEMENTED | İSTEĞE BAĞLI | G | — |

### D. Vekil ve uygulamalar
| # | Özellik | Panel/OLS'te ne yapıyor (kanıt) | ZMax karşılığı | Sınıf | Sahip | Faz |
|---|---|---|---|---|---|---|
| D1 | Node.js uygulaması ters vekil | `sites/proxyctx.go` + `nodeapp`: `extprocessor type proxy 127.0.0.1:<port>`, `context /` | `zmax-proxy` UNIT TESTED (12 test); panel ZMax'e `[vhost.proxy]` yazmıyor; VM'de sınanmadı | ZORUNLU | R+G | v1.0.06 → K |
| D2 | WebSocket | OLS proxy bağlamı WebSocket'i varsayılan iletir (panel ayarı yok) | `Upgrade: websocket` tünelleme UNIT TESTED | ZORUNLU\* | R | v1.0.06 |
| D3 | Vekil başlıkları ve tamponlama | OLS `X-Forwarded-For` sonuna istemci adresi ekler, HTTPS'te `X-Forwarded-Proto/Host` ekler; panel Fastify buna güvenir (`trustProxy`); `respBuffer 0` (SSE), `initTimeout 300`, `pcKeepAliveTimeout` (`config/ols/vhosts/zpanel-*/vhost.conf` yorumları) | `zmax-proxy` bu başlıkları ekliyor mu, tamponsuz akış var mı: bilinmiyor | ZORUNLU | R | v1.0.06 → K |
| D4 | Panel/webmail/Zplus `80/443` vekil vhost'ları | `sites/webmail.go`, `zplus.go`, `proxyctx.go`; OLS'te `map` + `context /` proxy | `zmax-proxy` kütüphane; vhost TOML yazımı (G) yok; E6 | ZORUNLU | G+R | K |
| D5 | Webmail (Roundcube) | `config/ols/vhosts/zpanel-webmail/vhost.conf`: lsapi PHP (uds), `context /`; `sites/webmail.go` ek host | php-fpm FastCGI ile eşdeğer çalışır mı: bilinmiyor | ZORUNLU | G+R | K |
| D6 | phpMyAdmin | `/phpmyadmin/` bağlamı → `127.0.0.1:8091` vekil (`zpanel-staff/vhost.conf`) | D1'e bağlı | ZORUNLU | G | K |
| D7 | Laravel / WordPress / OpenCart / Drupal / Joomla | `laravelapp`, `wordpress` paketleri; `.htaccess` + permalink | Gerçek uygulama testi yok (yalnız VM'de bir WordPress sayfası) | ZORUNLU | R+G | K (kabul kapısı) |

### E. İşletim
| # | Özellik | Panel/OLS'te ne yapıyor (kanıt) | ZMax karşılığı | Sınıf | Sahip | Faz |
|---|---|---|---|---|---|---|
| E1 | Sıcak yeniden yükleme | `sites.go` `reload()` (OLS); ZMax: `zmax.go` `reloadZmax()` → `POST :19486/api/v1/reload` | reload API IMPLEMENTED; yük altında reload testi yok | ZORUNLU | R+G | v1.0.04, K |
| E2 | Sertifika yenileme | `ssl/ssl.go`: certbot webroot (http) / DNS, yenileme sonrası reload | ACME dosyası sunumu INTEGRATION TESTED; yenilenen sertifikanın sunulması denenmedi | ZORUNLU | G+R | v1.0.07 → K |
| E3 | OLS'e geri dönüş | `config/zmax/zmax-gecis.sh`, `config/ols/ols-gecis.sh`; `/etc/zpanel/webserver` (`zmax`\|`openlitespeed`) | betik var; "TLS yok" kapısı eski; tek komutla geri dönüş denenmedi | ZORUNLU | G | K |
| E4 | Sağlık sondası | `zmax.go` `VerifyZmax`: Host başlığıyla HTTP/HTTPS GET, kod <500 = başarı | çalışır; yalnızca "<500" ölçütü (gövde/başlık karşılaştırması yok) | ZORUNLU | G | K |

## 2. Kabul kapısı — "hatasız"

80/443 varsayılanı ancak aşağıdakilerin **hepsi** kanıtlı geçince yapılır (kutu yalnız literal komut çıktısıyla işaretlenir):

1. **Yan yana test (OLS ↔ ZMax):** aynı site (aynı belge kökü, aynı php-fpm/lsphp çıktısı) iki sunucuda; ZMax 19480/19483, OLS 8080/8443 (panelin yan yana düzeni). Her yol için karşılaştırılacaklar: durum kodu, `Content-Type`, `Location`, `Set-Cookie`, `Cache-Control`/`ETag`/`Vary`, `Content-Encoding`, gövde özeti (sha256). Fark yalnız bilinen güvenli başlıklarda (`Server`, `Date`) olabilir; her fark yazılı gerekçeyle kabul edilir. [ ]
2. **Gerçek uygulamalar** (her biri kurulum + giriş + yazı/ürün ekleme + kalıcı bağlantı + dosya yükleme + çıkış): WordPress, Laravel, OpenCart, Drupal, Joomla. [ ]
3. **Panel işlevleri ZMax altında** (OLS'te geçen her biri): [ ] günlük sayfası (tarih+gerçek bayt) · [ ] istatistik/trafik/kota rakamı OLS ile aynı büyüklükte · [ ] `error_docs` (400/403/404/500/502/503) · [ ] çöp kutusu (panel; regresyon) · [ ] SSL alma ve **yenileme sonrası yeni sertifikanın sunulması** · [ ] hotlink · [ ] yönlendirmeler (Force HTTPS, www, 301/302) · [ ] IP engeli · [ ] parola korumalı dizin (`$apr1$`) · [ ] kaba kuvvet jail'i · [ ] ModSecurity aç/kapa/istisna · [ ] Node.js uygulaması + WebSocket · [ ] webmail · [ ] phpMyAdmin · [ ] PHP sürüm/INI değişimi · [ ] alt alan adı/ek alan adı.
4. **Protokol:** `curl --http1.1`, `--http2` (çok akış) · HTTP/3 ya da panel anahtarının "desteklenmiyor" gösterilmesi · TLS 1.2/1.3 el sıkışması. [ ]
5. **Dayanıklılık:** 1 saat stres, **24 saat** dayanıklılık (bellek/FD sızıntısı yok), **yük altında reload** (sıfır düşen istek), worker çökmesi, upstream (php-fpm) kesintisi. [ ]
6. **Geri dönüş:** ZMax → OLS tek komutla (`zmax-gecis.sh` / `/etc/zpanel/webserver`), sonra tekrar ZMax; her iki yönde siteler 200 döner. [ ]
7. **Test araçları:** `cargo fmt/check/test/clippy` temiz; ayrıştırıcı fuzz; Slowloris/hız sınırı betikleri (`../tools/`). [ ]

Çıktılar: kanıt dosyaları (komut + literal çıktı) `docs/kanit/` benzeri bir yere kaydedilir (yer sahibin kararı); "geçti" yalnız kanıtla yazılır.

## 3. Faz etkisi (YOL_HARITASI ve ADIMLI_GELISTIRME_TAKIP güncellendi)

- **Yeni "OLS denklik kapısı" (K, v1.0.10, 80/443 öncesi son kapı):** §2'nin tamamı + yukarıda K işaretli satırlar.
- **Faz 5'ten çekilenler (ZORUNLU çıktı):** HTTP/3-QUIC (A5: panelde `quicEnable` anahtarı var) → v1.0.10. Not: HTTP/3 yetişmezse geçici çözüm panel (G) tarafında ZMax seçiliyken H3 anahtarını "desteklenmiyor" göstermek; bu çözüm yazılı kabul gerektirir.
- **Faz 4'ten öne çekilenler:** Basic Auth `$apr1$` (C3) → v1.0.03; panel/webmail/Zplus vekil + vekil başlıkları (D1–D6) → v1.0.06 ve kapıdan önce; WAF aç/kapa/istisna/sayaç (C5) → v1.0.08.
- **Faz 5'te kalanlar (İSTEĞE BAĞLI):** LSCache `X-LiteSpeed-*` (A9), `AddType/AddHandler` (B6), Brotli/Zstd ayrıntısı, gerçek IP / CDN (C7), tam OWASP CRS uyumu (C5), Pagespeed, JS bot koruması, HTTP/3 dışındaki protokol işleri, küme koordinasyonu.
- **Go işleri (panel; ayrı oturum):** `RenderZmaxVhost`'u genişletmek (günlük, `error_docs`, hotlink listesi, ACL, auth, WAF, proxy, yönlendirme); `webserver/settings.go` ve `performance.go` ekranlarını ZMax'e bağlamak veya devre dışı göstermek; `zmax-gecis.sh` kapısını güncellemek; günlük yolu kararı.
