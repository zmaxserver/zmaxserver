# ZMax — 10 Ajanlı Çalışma Yapısı

**Amaç:** 10 yapay zeka ajanı aynı anda, birbirinin işini bozmadan çalışsın. **Güncellenir:** şerit/dosya sahipliği değişince. **Bağlı:** [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) (kartlar), [`YAPAY_ZEKA_KURALLARI.md`](YAPAY_ZEKA_KURALLARI.md) (her ajan uyar), [`DUZELTMELER.md`](DUZELTMELER.md) (denetçi kararı).
**Karar (sahip):** tek kartta tek ajan, ajanlar paralel. **Denetçi (Claude)** her kartı bağımsız doğrular; kararı yalnız o yazar.

## 0. Neden bu kurallar (okuma zorunlu)
- `web_engine.rs` (~2900 satır), `main.rs`, `zmax-config/src/lib.rs` birçok kartın ortak dosyasıdır. İki ajan aynı dosyayı aynı anda düzenlerse biri ötekinin işini **sessizce ezer**. Bu belge bunu engellemek içindir.
- Bu klasörde **git yoktu**. Paralel çalışma için ön koşul bölüm 1'dir.

## 1. Ön koşul: ayrı çalışma kopyası (ana kopyaya YAZMAK YASAK)
1. **Ana kopya `D:\zmaxserver` yalnız birleştirici/denetçi içindir.** Hiçbir ajan buraya yazmaz.
2. Her ajan kendi kopyasında çalışır: `D:\zmaxserver-ajan\aNN\` (NN = 01…10). Kopya: ana kopyanın **Kart 1 ONAYLI olduktan sonraki** anlık görüntüsü (`target\` hariç).
3. Her ajanın kendi derleme klasörü: `CARGO_TARGET_DIR=D:\zmaxserver-ajan\target-aNN` (ortak `target` kilidi yok).
4. Sürüm geçmişi: ana kopyada `git init` + tek `main` dalı (denetçi yapar). Ajan kopyası `git clone` ile alınır, ajan **kendi dalında** (`ajan-NN-kart-K`) commit atar. (`git` kurulu değilse: ajan işini `diff -ruN` yamasıyla `D:\zmaxserver-ajan\yama\aNN-kartK.patch` olarak verir.)
5. Ajan işini **birleştirmez**; kartı bitirince rapor yazar (bölüm 6). Birleştirmeyi denetçi, ONAYLI'dan sonra, sırayla yapar (bölüm 5).

## 2. Ajan ↔ kart ↔ dosya sahipliği
| Ajan | Kart | Yazabildiği dosyalar (SAHİP) | Okuyabilir (yazamaz) |
|---|---|---|---|
| **a01** | 1 (düzeltme, 4 madde) | `web_engine.rs`/`main.rs` **test** modülleri, `doc/tools/verify_all_acceptance.py` | tümü |
| **a02** | 2 günlükte gerçek bayt | `logger.rs`, `web_engine.rs` (yalnız `record_and_log`/`log_access` çağrı noktaları), `h2_engine.rs` günlük çağrısı | panel `logs`/`stats` (Go, okuma) |
| **a03** | 3 vhost API CRUD | `api.rs`, `zmax-config` içinde **yeni** `vhost_json.rs` | |
| **a04** | 4 `.htaccess`/yönlendirme | `zmax-rewrite/src/*` | `web_engine.rs` bağlantı noktası (yalnız çağrı satırı) |
| **a05** | 5 hotlink listesi + IP ACL | `zmax-security/src/*` (yeni `hotlink.rs`, `acl.rs`), `zmax-config` yeni `security_ext.rs` | |
| **a06** | 6 ACME ortak kök + sertifika yenileme | `zmax-static/src/*` (ACME), `zmax-tls/src/*`, `zmax-config` yeni `acme.rs` | |
| **a07** | 7 **Go panel** `RenderZmaxVhost` | `zpanel-tam\cekirdek\agent\internal\sites\zmax.go` + `_test.go` **(başka depo, Rust'a dokunmaz)** | Rust şeması (okuma) |
| **a08** | 8 FastCGI havuzu/`drop_privileges`/`sendfile` | `zmax-fastcgi/src/*`, `zmax-core/src/*`, `zmax-static` `sendfile` bölümü, `main.rs` yalnız `drop_privileges` bağlama satırı | |
| **a09** | 9 Basic Auth (`$apr1$`) | `zmax-security` yeni `basic_auth.rs`, `zmax-config` yeni `auth.rs` | |
| **a10** | 10 vekil (`X-Forwarded-*`, akış, WebSocket) | `zmax-proxy/src/*`, `zmax-config` yeni `proxy_ext.rs` | |
| (sırada) | 11 WAF olay günlüğü | a05 bitince boş ajana verilir | |
| (sonra) | 12 OLS denklik kapısı | tüm kartlar ONAYLI olunca | |

**Başlama sırası:** Kart 1 **ONAYLI** olmadan hiçbir ajan başlamaz (temel anlık görüntü). Kart 7 (Go) şemayı bekler: a07 yalnız ilgili Rust kartı **ONAYLI** olunca o alanı yazar (örn. günlük alanı → Kart 2 ONAYLI; ACL → Kart 5). Kart 11, Kart 5 ONAYLI olmadan başlamaz.

## 3. Ortak ("sıcak") dosya kuralı (çakışmayı önleyen asıl kural)
`web_engine.rs`, `main.rs`, `api.rs`, `zmax-config/src/lib.rs` **ortak dosyadır**. Kurallar:
1. **Yeni kodu yeni dosyaya/modüle yaz** (tablodaki "yeni …rs" dosyaları). Ortak dosyada yalnız: `mod x;` satırı, `use` satırı ve **tek çağrı satırı** ekle.
2. Ortak dosyada fonksiyon **taşıma, yeniden adlandırma, yeniden biçimlendirme (rustfmt), yorum temizliği YASAK**. `cargo fmt` yalnız kendi dosyalarına (`rustfmt <dosya>`).
3. `zmax-config` şemasına alan: kendi `*_ext.rs` dosyanda struct, `lib.rs`'te yalnız `pub use` + `VHostEntry`'ye **tek alan** (`#[serde(default)]`, geriye uyumlu). Alan adı çakışmasını önlemek için ön ek: kendi kart konusu (`auth_`, `acl_`, `proxy_`, …).
4. Sahibi olmadığın dosyaya yazman gerekirse **durma, yazma**: raporda "başka ajanın dosyası: <dosya> <ne gerekli>" yaz; denetçi çözer.
5. Aynı ortak dosyada iki kartın çağrı satırı çakışırsa birleştirmede denetçi çözer; ajanın görevi satırı **ayırt edilebilir** kılmaktır: çağrının üstüne `// [kart-K] …` yorum satırı.

## 4. Kaynak sınırları (bilgisayar 16 GB: bellek krizi yaşandı)
- **Aynı anda en çok 3 `cargo` derlemesi.** Kilit: `D:\zmaxserver-ajan\derleme-N.kilit` (N=1..3) dosyasını `New-Item` ile oluşturabilen derler, bitince siler; oluşturamazsa 30 sn bekleyip yeniden dener. `cargo test` çalıştırırken de aynı kilit.
- Ajanlar çoğunlukla düşünür/yazar; derleme-test dışında CPU harcamaz. Tarayıcı, ekran aracı, ağır araç **açma**.
- **Test portları (çakışmasın):** ajan `NN` için HTTP `21000+10·NN`, HTTPS `21001+10·NN`, API `21002+10·NN`, admin `21003+10·NN` (a01: 21010…, a10: 21100…). Testler **19480–19486'yı KULLANMAZ** (VM/ana sunucu). Port sabit yazma: yapılandırmadan al.
- Her ajan kendi geçici dizini: `D:\zmaxserver-ajan\tmp\aNN\`; test sonrası temizle.

## 5. Birleştirme (denetçi) ve doğrulama sırası
1. Rapor gelince denetçi **kendi derlemesiyle** doğrular (bölüm 6'daki kontrol listesi). Karar: `DUZELTMELER.md` (**ONAYLI/RED**).
2. **ONAYLI** kart ana kopyaya şu sırayla birleştirilir (şema → motor → uç): **3, 5, 6, 9, 10** (config şeması ekleyenler) → **2, 4, 8** (istek hattı) → **11** → **7** (Go, şema hazır alanlarla). Her birleştirmeden sonra `cargo test --workspace` (toplam artmalı, 0 kalmalı). Çakışma varsa kartın ajanı kendi kopyasını güncel ana kopyaya **yeniden uyarlar** (denetçi tarif eder).
3. Birleştirilmemiş ONAYLI iş "ONAYLI (beklemede)" olarak tabloda durur; ajan **durmaz**: sıradaki boş karta ya da yeniden uyarlamaya geçer.

## 6. Rapor ve köprü (ajan başına ayrı dosya: 10 ajan aynı dosyaya YAZMAZ)
- **Rapor yeri:** `D:\zmaxserver\doc\bitti\KART-<no>.md` (kart başına **tek dosya**; ajan yalnız kendi kartının dosyasını yazar). Şablon: `doc\BITTI.md` içindeki şablon aynen. Başlık: `## Kart <no> — <ad>`. `doc\BITTI.md` yalnız Kart 1'in eski raporu ve şablon olarak kalır.
- **Köprü** (`doc\tools\kopru_izle.py`) `doc\bitti\*.md` dosyalarını izler; değişince denetçiye bildirim gider. Kararı yalnız denetçi `DUZELTMELER.md` kart durum tablosuna yazar; ajanlar tabloyu **yalnız okur** (kendi kartının satırı).
- **Ajan döngüsü:** işi yap → 8a öz denetim → `bitti\KART-<no>.md` yaz → sohbete tek satır `BİLDİRİM: …` → `DUZELTMELER.md`'de kendi kartının kararını 2–3 dakikada bir oku → ONAYLI: dur ve boş kart ya da yeniden uyarlama talimatı bekle; RED: düzelt, aynı dosyaya yeni bölüm ekle; DURDUR: dur.
- Kural sürümü ve "Okunanlar" satırı raporda zorunlu (kural dosyasına bak). Kural dosyasını çalışırken sürekli yeniden oku.

## 7. Denetçi kontrol listesi (her rapor için)
1. `cargo test --workspace` toplamı (`test result` satırlarının toplamı; ajanın kopyasında ve birleştirdikten sonra ana kopyada) · 2. kartın kabul testinin **kendi çalıştırmam** · 3. ajanın **yalnız kendi sahip olduğu dosyalara** yazdığı (dosya zamanı/diff) · 4. ortak dosyada fonksiyon taşıma/biçimlendirme yok · 5. "bağlandı" iddiaları çağrı satırıyla · 6. raporun sayıları cargo çıktısıyla aynı · 7. ölçülmemiş performans iddiası yok · 8. `*.bak`/artık dosya yok · 9. kart dışı iş yok · 10. portlar ajanın bloğunda.

## 8. Riskler (bilinçli kabul)
- 10 ajan = 10 rapor: denetçi doğrulaması darboğaz olur; kartlar küçük tutulur, otomatik doğrulama betiği (`doc\tools\dogrula.py`) denetçide hazır olacak.
- Birleştirme çakışması kaçınılmaz olabilir (özellikle `web_engine.rs`); bölüm 3 bunu azaltır, sıfırlamaz.
- Derleme kilidi (en çok 3) hızı sınırlar; 10 ajanın hepsi derleme beklerse hız kazancı azalır. Bu yüzden çoğu ajan derleme dışı zamanda yazar/test tasarlar.
