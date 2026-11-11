## Kart 7 — Go: RenderZmaxVhost genişletme (rapor: 2026-11-12)

**Kural son okunma/sürüm:** v5 (2026-11-12) — işe başlarken ve rapordan önce (8a) yeniden okundu; sürüm satırı değişmedi.
**Okunanlar:** `doc/YAPAY_ZEKA_KURALLARI.md` (tamamı), `doc/README.md`, `doc/ADIMLI_GELISTIRME_TAKIP.md` Kart 7 (+ Kart 9 notu), `doc/karsilastirma/OLS_DENKLIK.md` (A5–A8, B9, B10, C1, C2, C5 satırları), `doc/entegre/goentegre.md` (tamamı), `doc/DUZELTMELER.md` (tamamı), `doc/BITTI.md` şablonu; Rust (yalnız okundu): `crates/zmax-config/src/lib.rs` (`VHostEntry`, `VHostSecuritySection`, `VHostLoggingSection`, `VHostErrorDocsSection`, `VHostProxySection`, `validate_ip_or_cidr`, `is_safe_error_docs_dir`, `is_valid_log_format`), `zmax-security/src/lib.rs` (`IpAccessList::is_allowed`, `path_matches_exclude_prefix`), `zmax-bin/src/modules_runtime.rs` (hotlink sabit uzantı listesi), `zmax-bin/src/main.rs` (`-t`/`-c` bayrakları); Go (panel): `sites/zmax.go`, `zmax_test.go`, `sites/logs.go`, `errordocs.go`, `sites/sites.go` (`writeVhost`, `apply`), `domainsec/apply*.go`, `modsec/modsec.go`, `webserver/{webserver,settings,performance,status}.go`, `rpc/toolkits_webserver.go`, `servis/api/.../webserver-adapter.ts` ve `servis/web/src/views/tools/general/PerformanceBoosterView.vue` (yalnız `notApplied` gösterim yolunu görmek için, değiştirilmedi).
**Kural ve düzeltme kontrolü:** `DUZELTMELER.md`'deki hatalar bu işte tekrarlanmadı: sayı yalnız çalıştırıp görülenden yazıldı; "kanıtlandı/hatasız/tamamlandı/onaylandı/kilitlendi" yazılmadı; `DUZELTMELER.md` düzenlenmedi (yalnız okundu); `D:\zmaxserver` altında yalnız bu rapor dosyası yazıldı (Rust/belge/yapılandırma dosyasına dokunulmadı); `*.bak/*.orig/*.tmp` yok (`find` boş); geçici `zz_dump_test.go` silindi; ölçülmemiş performans iddiası yok. Temiz: tüm maddeler. Sorunlu: yok. Karar gerektiren noktalar "Kalan eksikler / Denetçi kararı" başlığında.

### Yapılan iş
Panelin OLS vhost'unda ürettiği ayarlardan ZMax şemasında VAR olanlar `RenderZmaxVhost` çıktısına eklendi; şemada olmayanlar yazılmadı. Panel güvenlik sekmesi ayarları OLS tarafında yalnız `vhconf.conf` içinde durduğundan (ayrı yapısal kayıt yok) `ZmaxSpec` değerleri oradan ve panelin günlük/hata-sayfası/modsec dosyalarından okur. `webserver` ekranları ZMax seçiliyken karşılığı olmayan ayarları "desteklenmiyor" diye bildirir.

| Alan (ZMax TOML) | Kaynak (panel) | Yazım kuralı |
|---|---|---|
| `[vhost.logging]` enabled/access_log/error_log/format/max_log_size_mb/also_write_global | `sites/logs.go` `logDir(alan)` = `<LogRoot>/<alan>/` (varsayılan `/var/log/zpanel/<alan>/access.log` + `error.log`) | günlük dizini varsa yazılır; `format="combined"` (OLS `accessLogFormat` ile aynı sütunlar), `max_log_size_mb=2047` (OLS `rollingSize 2047M`; döndürmeyi panel yapar), `also_write_global=false` (OLS `useServer 0`) |
| `[vhost.error_docs]` enabled/dir + `[vhost.error_docs.pages]` 400,401,403,404,500,502,503 | `sites/errordocs.go` (`<ana dizin>/error_docs/<kod>.html`; vhconf'ta `# BEGIN zpanel-errordocs` bloğu = OLS'te de bağlanmış) | yalnız o blok varsa yazılır (OLS ile aynı koşul: ana alan adı, klasör hazır, panel dışı errorpage yok) |
| `security.hotlink_protection` | vhconf `zpanel-domainsec:web` grubundaki `RewriteCond %{HTTP_REFERER}` | tam bir Referer koşulu (alan adının kendisi) varsa `true`; izinli ek alan adı varsa `false` (bkz. karar 1) |
| `security.deny_ips` (`allow_ips` boş) | vhconf `zpanel-domainsec:ip` `deny a, b` satırı (panel beyaz listeyi engel listesinden zaten çıkarır) | geçersiz girdi atlanır (ZMax tek geçersiz girdide tüm vhost tablosunu yüklemez) |
| `security.waf_enabled` | vhconf `zpanel-domainsec:waf` (`modsecurity on/off`) | `off`→`false`; `on`→`true`; etkin kip "detect" ise yazılmaz (bkz. karar 2) |
| `security.waf_exclude_paths` | modsec yönetilen `conf/modsec/zpanel.conf` istisnaları (`@beginsWith <yol>`) | sunucu kipi block/detect ve alan adı WAF'ı kapalı değilse; tekilleştirilir; `/` yazılmaz (bkz. karar 3) |
| `security.force_https` | (değişmedi) `.htaccess` yönlendirme bloğu | — |
| Web sayfası: H3, gzip, gövde sınırı, LSCache profili | `webserver.Apply` / `ApplyPerformance` | ZMax seçiliyken `Applied`'dan çıkar, `NotApplied`'a `"h3 (ZMax: desteklenmiyor)"`, `"gzip (ZMax: ...)"`, `"body (ZMax: ...)"`, `"lscache (ZMax: ...)"` eklenir; panelin mevcut "uygulanamadı: {names}" bildirimi bunu gösterir (web arayüzü değiştirilmedi) |

`zmax.go` baş yorumundaki "şemada yok" listesi güncellendi (parola koruması, hotlink liste/uzantı/yanıt kodu, WAF detect kipi + kural bazlı istisna, güvenlik başlıkları, `[[vhost.rewrite]]`, www zorlaması, `.htaccess` ek direktifleri, ACME ortak kökü, kaba kuvvet, `[vhost.proxy]`).

### Gerçek durum (etiket)
- Go: yeni TOML alanlarının üretimi ve vhconf/modsec/günlük okuyucuları → **UNIT TESTED** (aşağıdaki tablo-testleri; ayrıca domainsec'in gerçek `renderIP`/`renderWeb` çıktısıyla sözleşme testi).
- Üretilen TOML'un ZMax şemasıyla ayrıştırılması → `zmax.exe -t` çıkış kodu 0 (yalnız yapılandırma/şema doğrulaması; **istek hattında panelin ürettiği TOML ile gerçek istek DENENMEDİ**, **VM'de DENENMEDİ**). ZMax'in bu alanları istek hattında kullandığı Kart 1 raporunda ayrı konu; burada yeniden sınanmadı.
- Panelde ZMax seçiliyken "desteklenmiyor" bildirimi → **UNIT TESTED** (`webserver` paketi); gerçek arayüzde görünüşü **denenmedi**.
- ZMax işçi hesabının `<LogRoot>/<alan>/` dizinine yazabilmesi: **bilinmiyor / denenmedi** (dizini panel OLS işçisi hesabıyla 0750 yaratır, bkz. `sites/logs.go` `ensureLogDir`).

### Kabul testleri (komut + gerçek çıktı)
Go: `C:\Prolocal\bin\go\bin\go.exe` (go1.27.3 windows/amd64), dizin `D:\lunixpanel\zpanel-tam\cekirdek\agent`.

1. `go test -count=1 ./internal/sites/... ./internal/webserver/... ./internal/domainsec/... ./internal/modsec/... ./internal/redirects/... ./internal/zmaxconf/...`
```
ok  	zpanel/agent/internal/sites	9.259s
ok  	zpanel/agent/internal/webserver	1.310s
ok  	zpanel/agent/internal/domainsec	3.541s
ok  	zpanel/agent/internal/modsec	2.222s
ok  	zpanel/agent/internal/redirects	1.935s
ok  	zpanel/agent/internal/zmaxconf	1.273s
```
(değişiklikten önce de `go test ./internal/sites/...` → `ok ... 7.560s`.)

2. Her yeni alan için tablo-testi (girdi → üretilen TOML satırı): `go test -count=1 -v -run 'TestRenderZmaxVhostNewFieldsTable|TestZmaxDenyIPs|TestZmaxHotlink|TestZmaxSpec' ./internal/sites/`
```
--- PASS: TestRenderZmaxVhostNewFieldsTable (0.00s)      # hotlink, engel/izin listesi, waf açık/kapalı, waf yol istisnası, günlük, hata sayfaları, "yeni alan yok" (9 alt durum)
--- PASS: TestZmaxDenyIPsKeepsOnlyValidEntries (0.00s)
--- PASS: TestZmaxHotlinkOnlyWithoutExtraAllowedDomains (0.00s)
--- PASS: TestZmaxSpecReadsPanelSettings (0.02s)
--- PASS: TestZmaxSpecWafCases (0.06s)                   # 7 durum: bölüm yok / kapalı / sunucu detect / alan detect / block / sunucuda kapalı / yönetilen dosya yok
--- PASS: TestZmaxSpecWithoutPanelFilesWritesNoOptionalSections (0.00s)
ok  	zpanel/agent/internal/sites	1.551s
```
`go test -count=1 -v -run 'Zmax|OpenLiteSpeedKeeps' ./internal/webserver/ ./internal/domainsec/`
```
--- PASS: TestApplyOnZmaxReportsUnsupportedSettings (0.01s)
--- PASS: TestApplyOnOpenLiteSpeedKeepsEverythingApplied (0.01s)      # OLS davranışı değişmedi
--- PASS: TestApplyPerformanceOnZmaxReportsLscacheUnsupported (0.01s)
ok  	zpanel/agent/internal/webserver	0.847s
--- PASS: TestZmaxSpecReadsRealDomainsecBlocks (0.01s)               # domainsec'in gerçek renderIP/renderWeb çıktısı → ZmaxSpec
ok  	zpanel/agent/internal/domainsec	0.991s
```
Girdi→çıktı örneği (`TestRenderZmaxVhostNewFieldsTable`, "engel listesi"): `DenyIPs: ["203.0.113.0/24","198.51.100.7","2001:db8::/32"]` → `deny_ips = ["203.0.113.0/24", "198.51.100.7", "2001:db8::/32"]`; "hata sayfaları": `ErrorDocsDir: "/var/www/vhosts/ornek.com/error_docs"` → `[vhost.error_docs]\nenabled = true\ndir = "..."` + `[vhost.error_docs.pages]` altında `400 = "400.html"` … `503 = "503.html"`.

3. ZMax ayrıştırıcısı: tüm alanlar dolu bir vhost (`ornek.com.toml`) + en yalın bir vhost (`yalin.com.toml`) `RenderZmaxVhost` ile üretildi (geçici, test dosyası silindi); `D:\zmaxserver\conf\zmax.toml` kopyası + `conf\vhosts\` geçici dizinde (scratchpad `...\scratchpad\zt`), `ZMAX_HOME` o dizine:
`D:\zmaxserver\target\release\zmax.exe -t -c <geçici>\conf\zmax.toml` (ikili 12.11.2026 01:58:29, 5321728 bayt)
```
[UYARI] vHost 'ornek.com' document_root dizini henüz mevcut değil: C:/var/www/vhosts/ornek.com/httpdocs
[UYARI] vHost 'yalin.com' document_root dizini henüz mevcut değil: C:/var/www/vhosts/yalin.com/httpdocs
[UYARI] Yüklü modül sayısı beklenen 18'den az (bulunan: 0).
[OK] Yapilandirma dogrulandi: ...\zt\conf\zmax.toml | HTTP=0.0.0.0:19480 | Admin=127.0.0.1:19485 | API=127.0.0.1:19486 | vHosts=2 | Moduller=0
CIKIS_KODU=0
```
(Uyarılar Windows'ta Linux yolları yüzünden; hata değil.) Negatif kontrol (ayrıştırıcının vhost alanlarını gerçekten denetlediğini görmek için): `deny_ips` içine `"300.1.1.1"` konunca → `Error: ... vHost 'ornek.com' için geçersiz security.deny_ips öğesi ('300.1.1.1')`, `NEGATIF_CIKIS_KODU=1`; dosya geri alındı.
Üretilen `ornek.com.toml` (alan bölümü): `[vhost.security]` → `hotlink_protection = true`, `force_https = true`, `allow_ips = ["10.0.0.0/8"]`, `deny_ips = [...]`, `waf_enabled = true`, `waf_exclude_paths = ["/wp-admin/", "/api"]`; `[vhost.logging]` → `enabled = true`, `access_log = "/var/log/zpanel/ornek.com/access.log"`, `error_log = ".../error.log"`, `format = "combined"`, `max_log_size_mb = 2047`, `also_write_global = false`; `[vhost.error_docs]` + `[vhost.error_docs.pages]` yukarıdaki gibi.

4. OLS testleri bozulmadı + `gofmt`/`go vet`:
`gofmt -l internal/sites internal/webserver internal/domainsec internal/rpc/toolkits_webserver.go` → çıktı boş.
`GOOS=linux go vet ./internal/sites/... ./internal/webserver/... ./internal/domainsec/... ./internal/rpc/...` → çıktı boş (hata yok). `GOOS=linux go build ./...` → çıktı boş.
`go test -count=1 ./...` (Windows): 50 paket `ok`; başarısız olanlar BU DEĞİŞİKLİKTEN BAĞIMSIZ Windows-yalnız sorunlar, dokunulmayan paketler: `ftp`, `files`, `tools`, `scheduler`, `stats`, `wordpress`, `rpc`, `cmd/*` → `undefined: syscall.Kill` / `syscall.Stat_t` (derleme, Linux'a özgü); `fail2ban` (`günlük yolu geçersiz`, Windows yolu), `maintenance` (lisans dosyası kipi). `rpc` paketi Windows'ta derlenmiyor (`tools` bağımlılığı); bu yüzden `rpc` testleri çalıştırılamadı — `GOOS=linux go vet` ile yalnız derleme/vet doğrulandı, testi **denenmedi**.

### Değişiklikler (panel deposu `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\`; panel deposunda git yok)
- `sites/zmax.go` (değişti): baş yorum güncellendi; `ZmaxVhost` alanları (`Hotlink, AllowIPs, DenyIPs, WafEnabled, WafExcludePaths, LogDir, ErrorDocsDir`); `RenderZmaxVhost` (güvenlik alanları + `[vhost.logging]` + `[vhost.error_docs]`/`.pages`); `ZmaxSpec` (vhconf/günlük okuma); yeni: `domainsecGroup`, `validIPRule`, `zmaxDenyIPs`, `zmaxHotlink`, `zmaxWaf`; import: `net/netip`, `regexp`.
- `sites/zmax_panel_test.go` (yeni): tablo-testleri ve `ZmaxSpec` okuma testleri.
- `webserver/webserver.go` (değişti): `Service.Selected func() string`, `zmaxSelected`, `zmaxUnsupported`. `webserver/settings.go` (`Apply`: ZMax'te `h3`,`gzip`,`body`), `webserver/performance.go` (`ApplyPerformance`: ZMax'te `lscache`). `webserver/zmax_test.go` (yeni, 3 test).
- `rpc/toolkits_webserver.go` (değişti, 2 satır): `webserver.Service{Selected: sites.Service{}.SelectedWebServer}`.
- `domainsec/zmax_contract_test.go` (yeni, yalnız test): domainsec'in gerçek bölümleriyle `ZmaxSpec` uyumu (sites→domainsec içe aktarma döngü olduğundan sözleşme testi domainsec tarafında).
Tam yol listesi: `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\{sites\zmax.go, sites\zmax_panel_test.go, webserver\webserver.go, webserver\settings.go, webserver\performance.go, webserver\zmax_test.go, rpc\toolkits_webserver.go, domainsec\zmax_contract_test.go}`. OLS yazım yolu (`writeVhost`, `domainsec.apply*`, `logs.go`, `errordocs.go`, `modsec.go`) DEĞİŞMEDİ.

### Güvenlik riski
- WAF yol istisnası: OLS'te istisna tek bir kuralı (`ctl:ruleRemoveById`) kaldırır; ZMax'te `waf_exclude_paths` o yoldaki TÜM WAF denetimini kapatır → panelde tek kural için tanımlı istisna ZMax'te o yol için WAF'ı tamamen kapatır. Hafifletme: kök (`/`) istisnası yazılmıyor. Kalan risk denetçi kararına bağlı (karar 3).
- Hotlink: şemada yalnız bool; izinli ek alan adı olan alanlarda koruma yazılmıyor (ortak site kesilmesin diye); yani panelde "açık" görünen koruma ZMax'te kapalı kalır (karar 1).
- WAF "detect" kipi ZMax'te temsil edilemediğinden `waf_enabled` yazılmaz (sunucu geneli ZMax ayarı geçerli kalır; ZMax geneli WAF'ın panelden yönetilmediği için kipi "block" olabilir: bilinmiyor).
- Sırlar dosyaya/sohbete yazılmadı; parola dosyaları (htpasswd) ZMax'e taşınmadı.

### Performans
Ölçülmedi. (Ek maliyet: `ZmaxSpec` her site için bir `vhconf.conf` + bir `zpanel.conf` dosyası okur; yalnız vhost eşitleme sırasında, istek hattında değil.)

### Kalan eksikler
**Rust şeması bekliyor / yazılmadı:**
1. Parola korumalı dizin (`$apr1$`) — şemada yok (Kart 9).
2. Hotlink izinli alan listesi, uzantı listesi, yanıt kodu (403/404), boş Referer ayarı — şemada yalnız bool.
3. Alan adı düzeyinde WAF "detect" kipi ve kural bazlı istisna (rule id) — şemada yalnız `waf_enabled` + yol listesi.
4. Güvenlik başlıkları (HSTS/XFO/XCTO/Referrer): `[vhost.headers]` şemada var (`security_headers`, `hsts`) ama panelin ayrıntılı ayarlarıyla eşleşmiyor, bu kartta yazılmadı.
5. Yönlendirme kuralları (`[[vhost.rewrite]]` şemada `rules` var), www zorlaması, `.htaccess` ek direktifleri — bu görevin listesinde değildi.
6. ACME ortak kökü `/var/www/acme` (şemada context yok).
7. Kaba kuvvet (`wp_brute_force` şemada var; panelin fail2ban ayarıyla eşleşmesi yok).
8. `webserver`: keep-alive için `zmaxconf` izinli anahtarı var (`security.keep_alive_timeout_sec`) ama panel ZMax'e yazmıyor; `lsapi` (OLS lsphp havuzu) ZMax seçiliyken de OLS'e yazılıyor ve "uygulandı" sayılıyor (php-fpm havuz boyutu ayrı). Bu ikisi görev listesinde (H3, gzip, gövde, LSCache) olmadığından dokunulmadı.
9. Bu kart ZMax'in günlük/error_docs/WAF/ACL alanlarını istek hattında panelin ürettiği TOML ile çalıştırmadı (yalnız `-t`); VM denemesi yok; günlük dizini sahipliği (ZMax işçi hesabı) bilinmiyor; `SyncZmax` günlük dizinini kendisi yaratmaz (OLS `writeVhost`/`Ensure` yolu yaratır; dizin yoksa `[vhost.logging]` yazılmaz).

**Denetçi kararı gereken noktalar (kendi başıma karar verdim; istenmezse geri alınır):**
- Karar 1 (hotlink): izinli ek alan adı varsa `false` yazıyorum (fail-open). Alternatif: her zaman panel `açık` ise `true`.
- Karar 2 (WAF detect): alan adı ya da sunucu kipi detect ise `waf_enabled` yazmıyorum (nil). Alternatif: `true` (ZMax engeller, OLS yalnız günlüğe yazardı).
- Karar 3 (istisna): rule-id bazlı istisnayı yol bazlı tam muafiyete çeviriyorum (kök hariç). Alternatif: hiç yazmamak (ZMax OLS'in izin verdiği yolu bloklayabilir).
- Karar 4 (`[vhost.proxy]`): kart metni (`ADIMLI_GELISTIRME_TAKIP.md` Kart 7) `[vhost.proxy]` (Node) listeler, görev talimatı ise proxy'yi "şemada olmayan, yazma" diye saydı; oysa `zmax-config` `VHostProxySection` (enabled, upstream, path_prefix, preserve_host, websocket) şemada VAR. Talimata uyup yazmadım; yazılması istenirse ayrı iş (kaynak: `sites/proxyctx.go`, tenant/nodeapp durumu).
- Karar 5 (günlük `also_write_global=false`, `max_log_size_mb=2047`): OLS `useServer 0` / `rollingSize 2047M` karşılığı; ZMax varsayılanı (true / 100) bırakılırsa panelin döndürmesiyle çakışır ve genel günlüğe kopya düşerdi.

### Kart dışı yapılan/dokunulan
- `webserver.Service` yapısına `Selected` alanı ve `rpc/toolkits_webserver.go` bağlama satırı: kartın "ekranları ZMax'te desteklenmiyor göster" maddesi için gerekliydi (Go tarafı), arayüz/Node/web değişmedi.
- `domainsec/zmax_contract_test.go`: yalnız test; sites→domainsec döngüsü yüzünden sözleşme testi o pakette durur.
- Geçici kabul dosyası (`sites/zz_dump_test.go`, scratchpad `zt\` dizini) yalnız `zmax -t` için kullanıldı; depoda kalmadı.

### Tek sonraki adım
Denetçi kararı bekleniyor (yukarıdaki Karar 1–5 dahil).
