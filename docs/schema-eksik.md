# MİMARİ ŞEMASI ↔ KAYNAK KOD EŞLEŞTİRME — EKSİKLER RAPORU

**Tarih:** 23 Kasım 2026
**Şema:** `D:\lunixpanel\zmaxserver\docs\mimari\zmax_mimari_semasi.html` (52.088 B, 589 satır, v3.1, altlık: `birlesme2 / dff16c6`)
**Depo:** `D:\lunixpanel\zmaxserver` — `VERSION=1.0.09`, `Cargo.toml version=1.0.9`
**Yöntem:** Şemadaki 36 bileşen kimliği (U1–U7, B1–B5, A1–A9, K1–K7, L1–L8) çıkarıldı; her biri gerçek dosya yoluyla eşleştirildi. Ardından `Cargo.toml`, `doc/` referansları, SSE/health kodu, crate listesi ve CI dosyaları ayrıca tarandı. Canlı sunucu ölçümleri `testler/eksik1.md` §11'den alındı.

---

## 0. Sonuç

**İyi haber:** Şemanın tanımladığı **36 parçanın 36'sı da kodda mevcut.** Birinci parti 132 `.rs`/`.go` dosyasında `todo!`, `unimplemented!`, `not implemented`, `TODO`, `FIXME` **bulunamadı** (0 sonuç). Yani "iskelet" eksik değil.

**Kötü haber:** **11 eksik** var — biri P0, altısı P1, dördü P2. En kritiği: `Cargo.toml` içindeki **20 test hedefinin hiçbirinin kaynak dosyası yok**; bu yüzden `cargo test` derlenemez ve `yayin-oncesi-dogrulama.md` K2 kapısı (CI testleri) kanıt üretemez.

Şema ayrıca kendi içinde **8 adet "KISMİ / açık sorun" notu** taşıyor; bunların çoğu kodda ve canlı sunucuda birebir karşılık buluyor. Yani şema "hayali" değil, **bilinen borçları doğru gösteriyor** — ama kapanmamışlar.

| Özet | Değer |
|---|---|
| Şema parçası | 36 (7 + 8 + 9 + 7 + 5) |
| Kodda karşılığı olan | **36 / 36** ✅ |
| Birinci parti kaynak dosya | 132 `.rs`/`.go` |
| TODO / stub | **0** ✅ |
| Eksik | **11** (1 P0, 6 P1, 4 P2) |
| Şema'nın kendi açık notu | 8 |
| Eksik Cargo test dosyası | **20 / 20** ❌ |

---

## 1. 36 parçanın eşleştirme tablosu

### 1.1 WebAdmin — U1…U7 (7/7 mevcut)

| ID | Şema bileşeni | Beklenen dosya | Durum |
|---|---|---|---|
| U1 | İskelet | `admin/index.html` | ✅ |
| U2 | API istemcisi | `admin/js/api_client.js` | ✅ dosya var, ⚠️ **SSE token URL'de** (bkz. E-03) |
| U3 | Uygulama kökü | `admin/js/app.js` | ✅ |
| U4 | Dashboard | `admin/js/views/dashboard.js` | ✅ |
| U5 | VHost | `admin/js/views/vhosts.js` | ✅ |
| U6 | Önbellek / WAF | `admin/js/views/cache_waf.js` | ✅ |
| U7 | Loglar | `admin/js/views/logs.js` | ✅ |

### 1.2 Rust ↔ Go köprüsü — B1…B5 (5/5 dosya var, 4'ü KISMİ)

| ID | Şema bileşeni | Beklenen dosya | Durum |
|---|---|---|---|
| B1 | Sözleşme | `go/contract/` (openapi.yaml, vhost.schema.json, contract_version) | ⚠️ şema "KISMİ" diyor |
| B2 | Rust uç noktaları | `src/api/bridge.rs` | ✅ |
| B3 | Go istemci paketi | `go/zmaxbridge/` (client.go, config.go, errors.go, models.go + test) | ⚠️ "KISMİ" + yol farkı (bkz. E-05) |
| B4 | Dosya sözleşmesi | `go/lifecycle/writer.go` | ⚠️ "KISMİ" |
| B5 | Yaşam döngüsü | `go/lifecycle/` (lifecycle.go, writer.go, writer_test.go) | ⚠️ "KISMİ" |

### 1.3 Yönetim API — A1…A9 (9/9 mevcut)

| ID | Şema bileşeni | Beklenen dosya | Durum |
|---|---|---|---|
| A1 | Kimlik / yetki | `src/api/auth.rs` | ✅ |
| A2 | Koruma | `src/api/guard.rs` | ✅ |
| A3 | Sistem | `src/api/routes/system.rs` | ✅ dosya var, ⚠️ **health kimliksiz** (bkz. E-04) |
| A4 | VHost | `src/api/routes/vhosts.rs` | ✅ |
| A5 | Ban / önbellek | `src/api/routes/security_cache.rs` | ✅ dosya var, ⚠️ şema `security_cache.rs` diyor, gerçek yol `routes/` altında (küçük sapma) |
| A6 | Loglar | `src/api/routes/logs.rs` | ✅ |
| A7 | Arayüz dosyası | `src/api/admin_static.rs` | ✅ |
| A8 | Servisler | `src/api/services/` (cache, config, security, vhost) | ✅ |
| A9 | Denetim | `src/api/audit.rs` | ✅ |

### 1.4 Çekirdek — K1…K7 (7/7 mevcut)

| ID | Şema bileşeni | Beklenen dosya | Durum |
|---|---|---|---|
| K1 | Boot / sinyal | `src/core/boot.rs` + `src/core/signals.rs` | ✅ |
| K2 | Ortak durum | `src/core/state.rs` | ✅ |
| K3 | Yapılandırma | `src/config/` (mod, reload, acme) | ✅ |
| K4 | Modüller | `src/modules/` + `modules/*.toml` (18 modül) | ✅ |
| K5 | Logger | `src/logger/` (format, rotate, tail, worker, tests) | ✅ |
| K6 | Arka plan görevleri | `src/core/tasks.rs` | ⚠️ şema "KISMİ" diyor (bkz. E-06) |
| K7 | Redis | `src/redis/` (client, events, sync) | ✅ |

### 1.5 Web trafik hattı — L1…L8 (8/8 mevcut)

| ID | Şema bileşeni | Beklenen dosya | Durum |
|---|---|---|---|
| L1 | Bağlantı | `src/pipeline/l1_connection.rs` | ✅ |
| L2 | Protokol / TLS | `src/pipeline/l2_protocol.rs` + `l2_protocol/h2.rs` | ✅ |
| L3 | Gerçek IP | `src/pipeline/l3_realip.rs` | ✅ |
| L4 | Güvenlik | `src/pipeline/l4_security.rs` | ✅ |
| L5 | Yönlendirme | `src/pipeline/l5_router.rs` | ✅ |
| L6 | Önbellek | `src/pipeline/l6_cache.rs` | ✅ |
| L7 | İşleyiciler | `src/pipeline/l7_handlers/` (fastcgi, proxy, static_files, upstream) | ✅ |
| L8 | Yanıt | `src/pipeline/l8_response.rs` | ✅ |

---

## 2. EKSİK-01 (P0) — 20 Cargo test hedefinin dosyası yok

**Kanıt**
```
Cargo.toml → 20 adet [[test]] bloğu
Örnek: name = "cache_integration_tests"  path = "docs/tests/cache_integration_tests.rs"
        name = "kart9_auth_hardening_tests" path = "docs/tests/kart9_auth_hardening_tests.rs"
        name = "public_version_tests"   path = "docs/tests/public_version_tests.rs"
        ... (20'si de aynı şekilde docs/tests/*.rs)

docs/tests/  → KLASÖR YOK
tests/       → sadece webadmin_runtime_sim.js, webadmin_test.js
```
Eksik dosyaların tamamı:
`cache_integration_tests`, `cache_purge_auth_tests`, `cache_purge_tests`, `ek_dinleyici_tests`, `kart10_proxy_tests`, `kart10_smuggling_matrix_tests`, `kart11_waf_tests`, `kart12_filesmatch_tests`, `kart12_reload_stress_tests`, `kart3b_api_tests`, `kart6_acme_tls_tests`, `kart8_sendfile_privs_tests`, `kart8_start_tests`, `kart9_auth_hardening_tests`, `kart9_basic_auth_tests`, `ols_b5_htaccess_tests`, `public_version_tests`, `v1_1b_acl_tests`, `kart12_statik_tests`, `ols_protocol_resilience_tests` — **20/20 eksik**.

**Etki:** `cargo test` bu hedefleri derlemeye çalışır ve "couldn't read ... No such file or directory" ile düşer. Yani WAF, auth hardening, smuggling, ACL, sendfile ayrıcalığı gibi **güvenlik kritiği testlerin hiçbiri çalışmıyor.** K2 kapısı ("CI testleri yeşil") bugün kanıt üretemez; "AI test etti" iddiası savunulamaz.

**Düzeltme (ikisi birlikte):**
1. Testleri `doc`/`docs` altından `tests/` klasörüne taşı ve `path = "tests/<ad>.rs"` yap; ya da dosyaları geri getir.
2. CI'da zorunlu kapı:
```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
```
3. Şemaya "test durumu" kolonu ekle; her parçanın hangi testle doğrulandığı yazılsın.

---

## 3. EKSİK-02 (P1) — Şemanın işaret ettiği 8 mimari dokümanın hiçbiri yok

**Kanıt**
```
Şema satır 29: "Ayrıntı belgeleri: doc/00_MIMARI_GENEL_BAKIS.md ve 01-07."
SVG'de adı geçenler:
  01_WEB_TRAFIK_BORU_HATTI_8_KATMAN.md
  02_YONETIM_API_9_MODUL.md
  03_WEBADMIN_UI_7_BILESEN.md
  05_KONTROL_DUZLEMI_CEKIRDEK.md
  07_RUST_GO_KOPRUSU.md
  (00, 04, 06 başlıkta "01–07" olarak referans ediliyor)

D:\lunixpanel\zmaxserver\doc  → KLASÖR YOK
docs/  → yalnızca duzeltme.md, ek_guvenlik.md, gelistirme.md, gorevler.md,
         eski/, logo/, mimari/, packed/
```
**Etki:** Şema "karar 00 §5 / 00 §7" gibi atıflar veriyor ama kaynak belge yok. Bağımlılık kuralları (L ve A birbirini içe aktarmaz, yalnız K2 üzerinden konuşur; yalnız L8 sokete yazar; API rotaları iş mantığı içermez) **denetlenemez**, sadece şemada yazılı kalır.

**Düzeltme:** `doc/` altına 00–07 dosyalarını oluştur ya da şemadaki yolları mevcut `docs/` dosyalarına güncelle. Ardından her kuralı CI'da `cargo + grep` ile denetle (ör. `grep -r "use crate::pipeline" src/api/ → boş olmalı`).

---

## 4. EKSİK-03 (P1) — SSE token'ı URL'de taşıyor

**Kanıt**
```
Şema satır 485: "SSE istemcisi token'ı ?token= ile yollar; sunucu yalnız başlık okur."
Şema satır 89:  "⚠ SSE token URL'de"
admin/js/api_client.js:
  21: let queryToken = urlParams.get('token');
  25: const hashMatch = window.location.hash.match(/token=([a-zA-Z0-9_\-]+)/);
  33: this.setToken(cleanToken);
```
Yani şema **bu akışın bozuk olduğunu bizzat yazıyor**: istemci `?token=` ile gönderiyor, sunucu sadece `Authorization` başlığını okuyor. `EventSource` API'si özel başlık gönderemediği için düzeltme `fetch()` + `ReadableStream` ya da HttpOnly çerez gerektirir.

**Etki:** (1) SSE uçları kimlik doğrulamasında 401 döner, canlı log/events akışı çalışmaz; (2) token URL'de kaldığı için erişim logları, tarayıcı geçmişi ve referrer üzerinden sızar.

**Düzeltme**
```js
// önerilen: çerez tabanlı
const es = new EventSource('/api/v1/logs/stream', { withCredentials: true });
// veya: fetch + stream + Authorization header
```
Sunucuda `?token=` kabul ediliyorsa **kaldır**; yalnız `Authorization: Bearer` / HttpOnly çerez kabul et. Regresyon testi: `?token=< geçerli >` ile istek **401** dönmeli.

---

## 5. EKSİK-04 (P1) — health uçu kimliksiz

**Kanıt**
```
Şema satır 213:   "⚠ health kimliksiz"
Şema satır 540:   "⚠ KISMİ: metrics okuma-token; health loopback YOK"
src/api/routes/system.rs:
  15: if clean == "/healthz" || clean == "/health" || ...
  41: // 1a. Genel altyapı sürüm ucu (/version): token'sız, salt okunur probe.
  43: if clean == "/version" {
Canlı (4. tur): /api/v1/health → 200, /api/version → 200, /api/v1/vhosts → 401
```
**Etki:** `/api` öneki altında kimliksiz 200 dönen uçlar var. Daha önce WebAdmin auth kararı health üzerinden veriliyordu; `/v1/auth/me`'ye geçilmiş olsa da yanlış bir gelecek değişiklik yine bu ucu "giriş başarılı" sanabilir. Ayrıca sürüm/pid/uptime/vhost sayısı kimliksiz sızdırılıyor.

**Düzeltme:** `/healthz`, `/version`, `/metrics` uçlarını `/api` önekinden **çıkar** (altyapı probe'u yap); `/api/**` altında hiçbir istisna bırakma. Canlı test matrisi `testler/eksik/eksikler.md` E-04'te.

---

## 6. EKSİK-05 (P1) — Rust↔Go köprüsü 4 parçada "KISMİ", yol farkı sürüyor

**Kanıt**
```
Şema B1/B3/B4/B5 kutularında "KISMİ" etiketi var.
Şema satır 490: "Go paketi ve sözleşme katmanlizmax/go altında (izlenmiyor)"
Şema satır 537 (karar 6): "Go paketi: katmanlizmax/go/zmaxbridge (yol farklı)"
Gerçek: go/zmaxbridge/, go/contract/, go/lifecycle/  (depo kökünde, "katmanlizmax" öneki YOK)
```
**Etki:** Go paketi şemadaki yolda aranırsa bulunamaz; sözleşme/testlerin "aynı dosyalardan beslenmesi" (satır 493) doğrulanamaz. Üstelik 4 parça resmen yarım olarak işaretli.

**Düzeltme:** Şemadaki yolu `go/zmaxbridge` ve `go/contract` olarak güncelle (ya da gerçek dizini şemadaki yola taşı — **birini seç, ikisini birden yapma**). B1/B3/B4/B5 için kabul kriteri yaz: sözleşme sürümü,writer testi, lifecycle testi yeşil olmadan parça "tamam" sayılmasın.

---

## 7. EKSİK-06 (P1) — K6 arka plan görevleri "KISMİ"

**Kanıt:** Şema K6 kutusunda "KISMİ" etiketi; dosya `src/core/tasks.rs` mevcut ama şema satır 509 başlatma sırasında `K6 → K2` diyor. Yani görevler ortak duruma yazıyor olmalı; bunun testi/CI kanıtı yok.

**Etki:** Arka plan görevleri yarım kaldığı için zamanlayıcı tabanlı işler (temizlik, yeniden yükleme, metrik toplama) eksik/güvenilmez olabilir.

**Düzeltme:** `tasks.rs` içindeki görev listesini şemaya ekle; her görev için "başlatma sırası K6→K2" testi yaz; şemadaki "KISMİ" etiketini yalnız test yeşil olunca kaldır.

---

## 8. EKSİK-07 (P1) — Karar 4 hâlâ KISMİ: `GET /api/version` kaldı

**Kanıt**
```
Şema satır 535: "4 Yalnız /api/v1 — KISMİ (GET /api/version kaldı, M15)"
Canlı: /api/version → 200
```
Bu, EKSİK-04 ile aynı kökene işaret ediyor ama **ayrı bir karar maddesi** olduğu için ayrı takip edilmeli.

**Düzeltme:** `/api/version` ya `/api/v1/version` + token olur ya da `/version` (altyapı) olur. Şemadaki karar 4'ü "UYGULANDI" yapmadan önce canlı testi (`curl ... /api/version → 401/404`) ekle.

---

## 9. EKSİK-08 (P2) — Karar 5: Rust API vhost yazımında `.lock` yok

**Kanıt:** Şema satır 536: `"5 Vhost yazarı Go — KISMİ (Rust API .lock yok)"`; satır 493: vhost TOML'unu yalnız Go yazar (B4).

**Etki:** Rust tarafından yazılan vhost değişiklikleri ile Go writer arasında yarış koşullusu oluşabilir; iki yazıcı varsa dosya bozulabilir.

**Düzeltme:** Rust tarafına dosya kilidi (`flock`/`.lock`) ekle ya da Rust API'sini salt okunur yapıp tüm yazımı B4'e zorunlu kıl. Tercih: **tek yazıcı ilkesi** — yazım yalnız Go, Rust sadece doğrular.

---

## 10. EKSİK-09 (P2) — Şema crate listesi güncel değil

**Kanıt**
```
Gerçek crates/ → 17 klasör:
cache, compress, config, core, fastcgi, header, httpparser, obfuscate, pool,
proxy, redis, rewrite, runtime, security, static, timeout, tls

Şema "ALTYAPI" bandında (satır 407–427) kutular:
runtime·header, obfuscate·core, timeout, httpparser·tls, httpparser (TEKRAR),
security, rewrite, cache, fastcgi·static, proxy·pool, compress
→ "httpparser" iki kez; "config" ve "redis" kutu olarak yok.
(satır 520'de metinle bahsedilmiş ama kutularda görünmüyor)
```
**Etki:** Şemaya bakan biri `zmax-config` ve `zmax-redis`'i altyapı katmanında göremez; duplike `httpparser` kutusu kafa karıştırır.

**Düzeltme:** 17 crate'i şemaya tek tek, duplikatsız ekle; `zmax-config → K3`, `zmax-redis → K7` oklarını koru.

---

## 11. EKSİK-10 (P2) — WebAdmin "7 bileşen" diyor ama 13 view var

**Kanıt**
```
Şema: U1–U7 (7 bileşen)
admin/js/views/ → dashboard, vhosts, cache_waf, logs + listeners, livestats,
                   modules, server_config, settings, templates  (6 fazla)
```
**Etki:** Şema, gerçek arayüzün kapsamınıeksik gösteriyor; bu 6 view için mimari karar/test kaydı yok.

**Düzeltme:** Şemayı 13 bileşene güncelle ya da bu 6 view'in hangi U bileşenine bağlı olduğunu (ör. U3 alt modül) tanımla.

---

## 12. EKSİK-11 (P2) — CI ve sürüm güvenliği dosyaları yok

**Kanıt**
```
.github      YOK
Makefile     YOK
deny.toml    YOK
clippy.toml  YOK
rustfmt.toml YOK
SECURITY.md  YOK
CHANGELOG.md YOK
```
**Etki:** `yayin-oncesi-dogrulama.md` K2 (CI testleri) ve K4 (checksum + SECURITY.md) kapıları bugün **kanıtsız**. Bağımlılık denetimi (`cargo deny`), format/lint zorunluluğu ve güvenlik açığı bildirme yolu yok.

**Düzeltme:** En az `.github/workflows/ci.yml` (test + clippy + fmt + deny), `deny.toml`, `SECURITY.md`, `CHANGELOG.md` ekle. Checksum'ları `docs/packed/SHA256SUMS.txt` ile eşleştir.

---

## 13. Şema ↔ canlı sunucu çelişkileri

| Şema notu | Canlı ölçüm (4. tur) | Durum |
|---|---|---|
| `SSE token URL'de` (satır 89/485) | kodda `?token=` okunuyor | ✅ Şema doğru, **açık** |
| `health kimliksiz` (satır 213) | `/api/v1/health → 200` | ✅ Şema doğru, **açık** |
| `Yalnız /api/v1 — KISMİ` (satır 535) | `/api/version → 200` | ✅ Şema doğru, **açık** |
| `metrics okuma-token; health loopback YOK` (satır 540) | `/api/v1/vhosts → 401` (token çalışıyor) | ⚠️ metrik tarafı ayrı test edilmeli |

Yani şema **abartmıyor**; aksine canlı bulgular şemanın kendi notlarını doğruluyor. Bu, raporun savunma değerini artırıyor: "AI şemayı yazdı, sorun yok" denemez; şema sorunları bizzat listeliyor.

---

## 14. Öncelikli aksiyon planı

| Sıra | İş | Kapı |
|---|---|---|
| 1 | 20 test dosyasını geri getir / `tests/` altına taşı; `cargo test --all-targets` yeşil | **K2** |
| 2 | `doc/00–07` belgelerini oluştur; bağımlılık kurallarını CI'da denetle | K1 |
| 3 | SSE token'ı URL'den kaldır; çerez/stream geçişi | K2 |
| 4 | `/api/**` altındaki health/version uçlarını ayır; token zorunlu | K2 |
| 5 | Go paket yolunu şemayla eşitle; B1/B3/B4/B5 kabul kriteri yaz | K1 |
| 6 | K6 görevleri + `.lock` (tek yazıcı ilkesi) | K1 |
| 7 | Crate listesi + view sayısı + CI/SECURITY dosyaları | K4 |

---

## 15. Doğrulama komutları

```powershell
# 20 test dosyası kontrolü
Select-String -Path Cargo.toml -Pattern 'docs/tests' | Measure-Object   # 20 olmalı
Test-Path docs\tests                                                     # True olmalı

# 36 parça dosya kontrolü (kısa örnek)
Test-Path src\pipeline\l8_response.rs
Test-Path src\api\bridge.rs
Test-Path go\zmaxbridge\client.go
Test-Path admin\js\api_client.js

# Doküman referansı
Test-Path doc\00_MIMARI_GENEL_BAKIS.md    # True olmalı

# Birinci parti stub taraması (gürültüsüz)
Get-ChildItem src,go,crates -Recurse -Include *.rs,*.go |
  Select-String -Pattern 'todo!\(|unimplemented!\(|not implemented|TODO|FIXME'
# Beklenen: 0 sonuç

# Şema kendi notları
Select-String -Path docs\mimari\zmax_mimari_semasi.html -Pattern 'KISM|SSE token|health kimliksiz|health loopback'
```

---

## 16. Son söz

Şema **kodun gerçek durumunu büyük ölçüde doğru yansıtıyor**: 36 parçanın hepsi var, stub yok. Ancak **test altyapısı tamamen kırık** (20 eksik dosya) ve şemanın kendi işaret ettiği 8 açık sorun hâlâ duruyor. Ücretsiz dağıtımdan önce en az EKSİK-01…EKSİK-07 kapanmalı; aksi halde "36 parçalı mimari tamamlandı" cümlesi, çalışmayan testler ve kimliksiz health uçu karşısında savunulamaz.

> Not: Bu rapor yalnızca yerel depo (`D:\lunixpanel\zmaxserver`) üzerinde yapılan statik incelemeye dayanır; canlı sunucuya değişiklik yapılmadı. Yayın kapıları için bağımsız test ve ikinci göz incelemesi ayrıca gereklidir.
