# ZMax Server — Yapay Zeka Çalışma Kuralları

Bu klasörde (`D:\zmaxserver`) kod ya da belge yazan her yapay zeka işe başlamadan bu dosyayı okur ve aynen uygular.
**Kural sürümü: v8 (2026-11-12).** Bu dosya sık güncellenir. (v5: GitHub çalışma düzeni, 8c. v6: çakışma önleme, 8c madde 9. v7: gerçek test önce / VM döngüsü, 8d. v8: iki test sunucusu, giriş bilgisi yasağı, aşama 1/aşama 2, 8d.)
**SÜREKLİ KURALA BAK (zorunlu):** Bu dosyayı yalnız işe başlarken değil **çalışırken de** yeniden oku: (a) her yeni görev kartının başında, (b) her ~30 dakikada ya da ~20 araç çağrısında bir, (c) kod yazmaya/silmeye/bağlamaya başlamadan hemen önce, (d) bir testi "geçti" ya da bir özelliği "bitti" demeden önce, (e) uzun bir kesintiden (bağlam sıkıştırma, yeniden başlatma) sonra, (f) `DUZELTMELER.md` yeni karar yazdığında. Her okumada **kural sürümü** satırını bir öncekiyle karşılaştır; değiştiyse dosyanın tamamını baştan oku. Hafızandaki eski kurala güvenme. Raporda "Kural son okunma: <saat>, sürüm v4" yaz.
**ZORUNLU OKUMA (işe başlamadan, bu sırayla; okumadan kod yazma):**
1. Bu dosya.
2. `doc/README.md` — belge haritası, hangi bilgi nerede.
3. `doc/MIMARI_VE_PLAN.md` — katmanlar, istek hattı sırası, Rust ↔ Go iş bölümü.
4. `doc/TAM_MODUL_VE_OZELLIK_MATRISI.md` — her özelliğin **gerçek durumu** (etiket + kanıt).
5. `doc/ADIMLI_GELISTIRME_TAKIP.md` — **yalnız verilen tek görev kartı** (hedef, dosyalar, yapılacak/yapılmayacak, kabul testi).
6. `doc/entegre/goentegre.md` — görev paneli (Go) ile ZMax arasındaki sözleşme (vhost TOML, reload API, portlar), kart panel ayarıyla ilgiliyse.
7. `doc/karsilastirma/OLS_DENKLIK.md` — OpenLiteSpeed denklik matrisi; kartın dokunduğu özelliğin satırı ZORUNLU mu, kabul kapısı ne.
8. `doc/BITEN_VE_KALAN.md` §3 — 80/443 geçiş kapısı (hangi şartlar sağlanmadan ZMax varsayılan olamaz).
9. `doc/tools/README.md` — derleme, paketleme, test betikleri (`live_smoke.py` vb.), kartın kabul testini çalıştırmak için.
10. `doc/DUZELTMELER.md` — önceki raporlarda bağımsız doğrulamada yanlış çıkan şeyler; aynı hatayı tekrarlama.
11. **Kod:** kartın dokunduğu crate'ler (`D:\zmaxserver\crates\...`) ve `zmax-bin/src` çağrı noktaları; Go tarafı gerekiyorsa `D:\lunixpanel\zpanel-tam` içinde `sites/zmax.go` (`RenderZmaxVhost`) — **yalnız okumak için**.
Plan ve sürümler: `doc/YOL_HARITASI.md` (gerekirse). Hepsini okuduğunu raporun başında tek satırla yaz: "Okunanlar: …".
**ÇOK AJANLI ÇALIŞMA:** 10 ajan paralel çalışıyorsa `doc/AJAN_YAPISI.md` **zorunlu okuma**dır ve bu dosyanın üstündedir: ana kopya `D:\zmaxserver`'e **yazma** (kendi `D:\zmaxserver-ajan\aNN\` kopyanda çalış), yalnız kendi kartının sahip olduğu dosyalara yaz, ortak dosyada (`web_engine.rs`, `main.rs`, `api.rs`, `zmax-config/src/lib.rs`) yeni kodu yeni dosyaya yaz, raporunu `doc/bitti/KART-<no>.md`'ye yaz (tek dosya `BITTI.md`'ye değil), derleme kilidine ve port bloğuna uy.
**Çalışma düzeni:** Aynı anda tek görev kartı, ama **kartlar arasında durmadan** ilerlersin (aşağıdaki karar akışı). Bitirmeden önce öz denetim (bölüm 8a), sonra raporu **sohbete değil `doc/BITTI.md` dosyasına** yaz (en alta yeni bölüm; şablon dosyanın içinde; bölüm 8 biçimi) ve dur. Raporu **denetçi (Claude) bağımsız doğrular** ve kararı `doc/DUZELTMELER.md`'ye **ONAYLI** ya da **RED** olarak yazar (kart durum tablosu ve karar sözlüğü orada). **`DUZELTMELER.md` senin için SAHİPTİR; buradaki karar ve talimat kuralların üstündedir.** Sen **kendiliğinden durmazsın**: **ONAYLI** → o karta dokunma, tablodaki sıradaki BEKLİYOR kartı (en küçük numara) alıp hemen başla. **RED** → o kartın düzeltme talimatını hemen yap, yeni bölümü `BITTI.md`'ye ekle, karar bekle. **BEKLİYOR** (raporu yazdın) → oturumu kapatma; `DUZELTMELER.md`'yi her 2–3 dakikada bir yeniden oku, karar gelince yukarıdakini uygula. **DURDUR** → hemen dur, yarım işini `BITTI.md`'ye yaz. Tablodaki tüm kartlar ONAYLI olunca ya da DURDUR görünce biter. `DUZELTMELER.md`'yi yalnız oku, düzenleme. Kendi işini kendin onaylama, "bitti/onaylandı" deme. Çalışmaya başlamadan önce tabloda **kendi kartının kararına** bak; ONAYLI karta tekrar dokunma. Her yeni kartta bölüm 8a öz denetimini uygula.

## 1. Temel kural: yalnız söylenen iş
1. Yalnız verilen talimat yapılır. Kendi kafandan özellik, crate, dosya, ayar, ek adım **eklenmez**.
2. Talimatın dışında bir iş gerekli görülürse önce tek kısa öneri yazılır, sahip "yap" demeden yapılmaz.
3. Belirsiz bir şey varsa tahmin edilmez: "bilinmiyor" yazılır, gerekirse tek kısa soru sorulur.
4. Tarama/inceleme bulgusu talimat değildir; sahip "yap" demeden işe dönüşmez.

## 2. Doğruluk: uydurma yasak
1. Bir bilgi ancak dosyayı açıp okuduktan sonra söylenir. Okumadığın dosyanın içeriğini biliyormuş gibi yazma.
2. Var olmayan crate, dosya, fonksiyon, yapılandırma anahtarı **varsayma**. Mevcut crate'ler (18): `zmax-bin`, `zmax-cache`, `zmax-compress`, `zmax-config`, `zmax-core`, `zmax-fastcgi`, `zmax-header`, `zmax-httpparser`, `zmax-obfuscate`, `zmax-pool`, `zmax-proxy`, `zmax-redis`, `zmax-rewrite`, `zmax-runtime`, `zmax-security`, `zmax-static`, `zmax-timeout`, `zmax-tls`. `zmax-realip`, `zmax-metrics`, `zmax-log`, `zmax-acme`, `zmax-cli` **yoktur**.
3. Bir crate'te kod bulunması özelliğin çalıştığını göstermez. Şemada (`zmax-config`) alan olması, istek hattında kullanıldığını göstermez; `zmax-bin` içinde çağrıldığı yeri göster.
4. Her özellik şu etiketlerden biriyle yazılır, üst etiket altındakilerin hepsi sağlanınca verilir: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` (istek hattına bağlı) → `INTEGRATION TESTED` (gerçek istek) → `PRODUCTION VERIFIED`.
5. Sayı, tarih, boyut, test adedi: yalnız çalıştırıp/okuyup gördüğün değer yazılır; tahmin ya da başka belgeden kopya yazılmaz. İki belge çelişiyorsa koda bakılır, hiçbirine körü körüne güvenilmez.
6. Benchmark/hız rakamı uydurulmaz. Ölçülmediyse "ölçülmedi" yazılır. Ölçmeden "rakipten hızlı" denmez.
7. ALPN'de `h2` duyurmak HTTP/2 sunucusu değildir; Brotli desteği Zstd desteği değildir; temel WAF OWASP CRS uyumu değildir.
8. **Kod hızlı değişir, belge eskir.** İşe başlarken durumu belgeden değil **koddan yeniden oku** (grep, `cargo test`). Belgedeki tarih eskiyse ya da kodla çelişiyorsa kod doğrudur; belgeyi düzelt.
9. **"Kütüphanede var" ≠ "hatta bağlı".** Bir fonksiyonun `zmax-bin` içinde çağrıldığı satırı göster; çağrılmıyorsa etiket en çok `IMPLEMENTED`'dır. (Örnek: 2026-11-12 sabahı `execute_php_pooled`, `drop_privileges`, `sendfile` bu durumdaydı; sonradan ikisi bağlandı, `sendfile` hâlâ bağlı değil. Güncel durum için koda bak.)

## 3. Kanıt: "yaptım" demek için
1. Derlenmeden "derleniyor", çalıştırılmadan "testler geçti", denenmeden "çalışıyor" denmez.
2. Rapora çalıştırdığın komut ve **gerçek çıktısı** yazılır (örn. `cargo test --workspace` → çıkış kodu ve sonuç satırı). Çıktıyı yorumlayıp değiştirme.
3. Birim test ≠ entegrasyon ≠ üretim. Hangisini yaptığını açıkça yaz. Test yazılmamış özellik tamamlanmış sayılmaz.
4. Çalıştıramadığın/denemediğin şeyi "SKIPPED" ya da "denenmedi" yaz; geçti gibi gösterme.
5. Sunucuda (VM) denenmeyen şey "sunucuda denenmedi" diye işaretlenir.
6. **Kanıtın türü etikete uymalı.** Bir crate'in birim testi (`zmax-static`, `zmax-security`, `zmax-tls` ALPN vb.) istek hattı testi değildir. "İstek hattında test edildi / entegrasyon testli" demek için `zmax-bin` içinden geçen gerçek istek (ya da VM'de `curl`) ve çıktısı gerekir.
7. Test sayısı = `cargo test --workspace` çıktısındaki `test result` satırlarının toplamı. Başka belgeden sayı kopyalanmaz. (Referans, çalıştırıldı 2026-11-12: 216 geçti, 0 kaldı.)
8. "Kanıtlandı", "tamamlandı", "hatasız", "denk" kelimeleri yalnız çalıştırılmış entegrasyon testi ve çıktısıyla yazılır.

## 4. Kod değiştirirken
1. Önce ilgili crate'i, çağrı noktalarını ve `zmax-bin` entegrasyonunu oku.
2. Çalışan modülü yeniden yazma; minimal yama yap. Geriye dönük uyumluluğu (TOML şeması, API) bozma.
3. Yeni crate açmadan önce mevcut crate'lerde yer ara; açarsan gerekçesini yaz.
4. Hatalı yapılandırma çalışan yapılandırmayı bozmamalı (doğrula → atomik uygula → hata olursa eskisinde kal).
5. Güvenlik denetimini performans gerekçesiyle kaldırma. Gizli anahtar, parola, çerez günlüğe yazılmaz.
6. Kullanıcı girdisinden (yol, başlık, sorgu) dosya yolu/komut kurma; dizin kaçışı ve symlink kontrolü yap.
7. Linux birincil hedef; Windows'a özel kod `#[cfg]` ile ayrılır.

## 5. Rust ↔ Go iş bölümü (karıştırma)
- **ZMax (Rust):** gelen HTTP/HTTPS trafiği, TLS, önbellek, WAF/DoS, günlük yazma, rewrite, ACME dosyasını sunma. Yönetim kararı vermez, vhost TOML **yazmaz** (salt okunur tüketici).
- **ZPanel (Go):** müşteri/paket/kota, vhost TOML yazımı (`/usr/local/zmax/conf/vhosts/<alan>.toml`), certbot, işletim sistemi güvenlik duvarı, PHP-FPM havuzu/kullanıcı izolasyonu, panel arayüzü. Go paneli çalışır durumdadır; Rust tarafında yeniden yazılmaz.
- Sözleşme: Go TOML yazar → `POST http://127.0.0.1:19486/api/v1/reload` (ya da SIGHUP) → ZMax doğrular ve uygular. TOML alan adı değişirse iki taraf birlikte güncellenir.
- **Özellik iki tarafta birlikte tamam sayılır.** Rust'ta kod olsa bile panelin ZMax sürücüsü (`zpanel-tam` içinde `sites/zmax.go` `RenderZmaxVhost`) o ayarı TOML'a yazmıyorsa özellik panel için **yoktur**. Rust'ta yeni TOML alanı eklerken Go tarafı için yazılacak alanı görev raporuna "Go'ya not" olarak ekle (kodunu Go oturumu yazar).
- **Hedef (sahip kararı): ZMax, OpenLiteSpeed ile denk olacak.** 80/443'ü ZMax'e çevirme kapısı `BITEN_VE_KALAN.md` §3 ve `karsilastirma/OLS_DENKLIK.md` içindeki tüm ZORUNLU satırların INTEGRATION TESTED olmasıdır. Bu sağlanmadan hiçbir yapay zeka 80/443'ü çevirmez, "OpenLiteSpeed'e gerek kalmadı" demez.

## 6. Belge yazarken
1. Hiçbir belge **silinmez**; kaldırılan/birleştirilen dosya `doc/arsiv/<tarih>/` altına taşınır ve oradaki README'ye nereye birleştiği yazılır.
2. Bir bilgi tek belgede yazılır; tekrar edilmez, bağlantı verilir.
3. Her durum satırında etiket (bölüm 2.4) ve kanıt (dosya yolu, satır ya da test) bulunur.
4. Doğrulanmayan her şey "bilinmiyor" olarak işaretlenir.
5. Dil Türkçe, BOM'suz UTF-8; Türkçe karakter (ç ğ ı ö ş ü) bozulmaz.

## 7. Yasaklar (kısa liste)
- Test edilmemiş özelliği tamamlandı göstermek; benchmark uydurmak; olmayan dosya/crate varsaymak.
- Sahip istemeden özellik, crate, belge, ayar eklemek; sorulmadan kapsam genişletmek.
- Çalışan yapılandırmayı bozmak; tamamlanmış modülü sebepsiz yeniden yazmak.
- Dosyaya bakmadan içeriğini biliyormuş gibi anlatmak.
- Depoya yedek/geçici dosya bırakmak (`*.bak`, `*.orig`, `*.tmp`; örn. `web_engine.rs.bak`).
- Sahip onayı olmadan sunucuda (VM) dosya yazmak, çalışan servisi durdurmak ya da 80/443'e dokunmak; panel (Go) kodunu değiştirmek (Go ayrı oturumun işidir).
- Bir seferde birden çok görev kartı yapmak; verilen kartın dışına çıkmak.
- Sohbette gereksiz uzun açıklama, tekrar, süsleme.

## 8a. Bitirmeden ÖNCE öz denetim (zorunlu, raporu yazmadan)
Her işi bitirdiğini düşündüğünde **raporu yazmadan önce** şu sırayı uygula:
1. Bu dosyayı (`YAPAY_ZEKA_KURALLARI.md`) **yeniden oku**; bölüm 1-7'yi işine karşı tek tek kontrol et.
2. `doc/DUZELTMELER.md`'yi oku; oradaki her düzeltme maddesinin **aynı hatasını** bu işte yapıp yapmadığını kontrol et (örn. birim testini istek hattı testi saymak, kart dışı iş yapmak, ölçülmemiş performans iddiası, çıktısız "geçti", `*.bak` bırakmak).
3. Kartın **kabul testlerini** tek tek çalıştır; çalıştıramadığını "denenmedi" yaz.
4. Kart dışı değişiklik, artık dosya, ölçülmemiş iddia, "kanıtlandı/hatasız/tamamlandı" kelimesi var mı bak; varsa kaldır ya da kanıtla.
5. Rapora **"Kural ve düzeltme kontrolü:"** satırı ekle: neyi kontrol ettin, hangi maddeler temiz, hangisi sorunlu. Sorun varsa önce düzelt, sonra raporla.
Bu denetimi atlayan rapor geçersiz sayılır.

## 8c. GitHub: ortak çalışma yeri (iki yapay zeka + denetçi aynı depoda)
**Depo:** https://github.com/zmaxserver/zmaxserver (**AÇIK/herkese görünür**). Yerel kopya `D:\zmaxserver`, uzak `origin`, ana dal `main`. Push yetkisi bu bilgisayarın GitHub oturumuyla gelir; parola/jeton **asla** sohbete, dosyaya, komut satırına yazılmaz.
1. **Açık depo = gizli bilgi YASAK:** parola, jeton, API anahtarı, özel anahtar (`*.pem`, `*.key`), sertifika özel anahtarı, kişisel veri, sunucu IP/parolası commit edilmez. `.gitignore`'u gevşetme. Şüphe varsa commit etme, denetçiye yaz.
2. **`main` korunur: yalnız denetçi (Claude) `main`'e birleştirir ve push eder.** Sen `main`'e doğrudan push etme, `--force`/geçmiş yeniden yazma **yasak**, başka ajanın dalına yazma yasak.
3. **Her kart kendi dalında:** işe başlarken `git fetch origin && git checkout -b kart-<no>-<kısa-ad> origin/main` (güncel `main`'den). Dal adı: `kart-2-gunluk-bayt`.
4. **Commit:** küçük, anlamlı, kısa Türkçe mesaj, kart ön ekiyle: `[kart-2] günlükte gerçek bayt`. Kart dışı dosyayı commit etme (`git status` ile bak). Derleme çıktıları/`target` zaten `.gitignore`'da.
5. **Bitirince:** dalı it (`git push -u origin kart-<no>-<ad>`), raporunda **dal adı + son commit SHA** yaz (`BITTI.md`/`bitti/KART-<no>.md`). Denetçi o dalı çekip doğrular; **ONAYLI** ise `main`'e (`--no-ff`) birleştirir. Sonra `git fetch origin && git rebase origin/main` ile dalını güncelle ya da yeni kartta `main`'den yeni dal aç.
6. **RED'de** aynı dala yeni commit at, `git push` et (aynı dal); yeni bölümü rapora ekle.
7. Rapor/karar dosyaları (`BITTI.md`, `bitti/`, `DUZELTMELER.md`) `main`'dedir: **`DUZELTMELER.md`'yi yalnız denetçi commit eder**; sen dalında bu dosyayı değiştirme.
8. Çakışma çıkarsa **çözmeye çalışma, durma**: raporda "çakışma: <dosya>" yaz; denetçi çözer.
9. **ÇAKIŞMAYI ÖNLEME (v6, zorunlu):**
   - **Ana klasör `D:\zmaxserver` iletişim yeridir** (karar/rapor dosyaları orada). Devam eden kartını bu klasörde bitirebilirsin; **bir sonraki karttan itibaren kendi worktree'ni aç ve orada çalış:** `git worktree add D:\zmaxserver-ajan\<ad> -b kart-<no>-<ad> origin/main`. Aynı klasörde iki dal olmaz.
   - **Karar ve rapor dosyalarını ABSOLUT yolla oku/yaz:** `D:\zmaxserver\doc\DUZELTMELER.md` (yalnız oku), `D:\zmaxserver\doc\bitti\KART-<no>.md` (yaz). Bu dosyalar **dal commit'ine GİRMEZ**.
   - **`git add -A`, `git add .`, `git commit -a` YASAK.** Değiştirdiğin dosyaları **adıyla** ekle; her commit öncesi `git diff --cached --stat` ile kart dışı dosya olmadığını doğrula.
   - **Commit etme:** `doc/DUZELTMELER.md`, `doc/BITTI.md`, `doc/bitti/` (denetçi `main`'de commit eder), `doc/ornekmimariler/`, `target/`, `*.pem`, `*.key`.
   - **Bu kurallar şu an git kancasıyla ZORLANMIYOR** (kanca kurulumu sahip onayını bekliyor); uyum **denetçi tarafından commit geçmişinden (`git log`, `git diff --stat`) kontrol edilir**: `main`'e ajan commit'i, dal commit'inde iletişim dosyası ya da kart dışı dosya bulunursa kart RED olur. İleride kanca kurulursa (`.git/hooks`) onu atlatma/değiştirme/silme (`--no-verify`, `core.hooksPath`) **kesin yasak**.
   - Başka birinin (denetçi/ajan) dosyasını **değiştirme, geri alma (`git checkout -- <dosya>`), silme**.

## 8d. Gerçek test önce: VM döngüsü (sahip kararı, v7)
**İlke:** Kâğıt üzerindeki doğrulama (birim/entegrasyon testi) yetmez; eksikleri **gerçek sunucuda gerçek siteyle** denemek en hızlı bulur. Bu yüzden iş **döngüyle** yürür:
1. **Derle:** denetçinin `main`'indeki ONAYLI hâlden Linux ikilisi.
2. **VM testi:** yalnız **VM oturumu** (`paketleme-v2`) yapar; ZMax test portlarında (19480/19483/19486), 80/443/panel/OpenLiteSpeed'e dokunmadan, kalıcı değişiklik olmadan. Sonuç `doc/bitti/VM-TEST-<n>.md`: her madde GEÇTİ/KALDI/DENENEMEDİ + komut + literal çıktı + hangi karta ait.
3. **Eksik listesi → kart:** `KALDI` maddeleri **öncelikli kart** olur (planlı kartlardan önce). Kart adı `Kart V<n>-<k>`; denetçi `ADIMLI_GELISTIRME_TAKIP.md`'ye ekler.
4. **Ajanlar düzeltir:** kural, dal, rapor, denetçi onayı aynen geçerli.
5. **Tekrar VM testi:** düzeltme `main`'e girince aynı madde yeniden denenir; geçerse kartın kararı **VM DOĞRULANDI** olur.
**Sonuçlar:**
- **Kart önceliği:** (1) VM testinde `KALDI` çıkan kartlar, (2) ONAYLI ama henüz VM'de denenmemiş kartların VM maddeleri, (3) planlı yeni kartlar. VM sonucu gelmeden **yeni büyük kart başlatma** (küçük, bağımsız kartlar serbest).
- **Kart kararı iki kademeli:** `ONAYLI` = kod + test (denetçi); `VM DOĞRULANDI` = gerçek sunucuda geçti. `OLS_DENKLIK` ZORUNLU satırları ancak `VM DOĞRULANDI` olunca geçilmiş sayılır.
- **Her kart raporuna ekle:** "VM'de denenecek komutlar" bölümü (3-8 satır: komut, beklenen sonuç). VM oturumu bunları test listesine alır.
- **VM erişimi, iki test sunucusu (sahip kararı):** (a) **yerel test VM'si** → **VM oturumu** (`paketleme-v2`) kullanır; (b) **uzak test sunucusu** (içinde müşteri alan adı YOK; adı/giriş bilgisi sahip tarafından **ZMax'i yazan yapay zekaya doğrudan verilir**, bu açık depoya YAZILMAZ) → o yapay zeka kullanabilir. **Aynı anda her sunucuda tek taraf** çalışır; aynı sunucuyu ikisi birden kullanmaz.
- **Giriş bilgileri:** parola, anahtar, jeton, sunucu adı/IP'si **hiçbir dosyaya, commit'e, rapora, sohbete veya komut satırı argümanına YAZILMAZ** (depo AÇIK). Raporlarda sunucu "uzak test sunucusu" olarak anılır.
- **AŞAMA 1 (şimdi, iki sunucuda da):** yalnız ZMax **test portları** (19480/19483/19486); **80/443'e, panele (8026/8036/8047), OpenLiteSpeed'e dokunma yok** (durdurma/yeniden başlatma yok); kalıcı değişiklik yok (test dosyaları kendi dizininde, bitince temizlenir, ZMax test süreci bitince durdurulur); sistem paketi kurma/silme, güvenlik duvarı/yapılandırma değişikliği yok. Test portlarını internete **AÇMA**, testler sunucu içinden `127.0.0.1` ile. Her VM testinde başlangıç/bitiş saati ve çalıştırılan her komut `VM-TEST-<n>.md`'ye yazılır.
- **EMİR (sahip, ZMax'i yazan yapay zekaya): UZAK TEST SUNUCUSUNDA TEST ZORUNLUDUR.** Sana sunucu bilgisi verildiyse: (1) her kartın kabul testini **önce yerelde**, sonra **uzak test sunucusunda** (Aşama 1 sınırlarıyla) çalıştır; (2) "VM'de denenecek komutlar" bölümündeki her komutu **kendin** orada çalıştır; (3) sonucu (komut + literal çıktı, GEÇTİ/KALDI/DENENEMEDİ) kart raporuna ya da `doc/bitti/VM-TEST-<n>.md`'ye yaz; (4) uzak sunucuya erişemiyorsan **dur ve sahibe söyle**, "VM'de denenmedi" diye geçiştirip kartı bitirme (VM testi gereken maddeler ancak VM'de geçerse `VM DOĞRULANDI` olur). Testi atlamak ihlaldir. Yalnız Aşama 1 sınırı içinde: izinsiz 80/443/panel/OpenLiteSpeed'e dokunma, kalıcı değişiklik yapma.
- **AŞAMA 2 (80/443 geçişi, `zmax-gecis.sh`):** YALNIZ `DUZELTMELER.md`'ye denetçi/sahip **"AŞAMA 2 İZNİ"** yazarsa, VM-TEST-1'de aşama 1 maddeleri geçtikten ve **OpenLiteSpeed'e tek komutla geri dönüş önce denenip rapora yazıldıktan** sonra. İzin yoksa yasak.
- Emin olmadığın komutu çalıştırma, dur ve sor. **Diğer ajanlar VM'ye dokunmaz** (bağlanma, dosya yazma, servis durdurma yasak); yalnız yukarıdaki iki rol.
- **VM sonucu geldiğinde** `DUZELTMELER.md` kart tablosuna "VM" notu denetçi tarafından yazılır; ajan tabloyu yine yalnız okur.

## 8b. Köprü: denetçiyle otomatik bildirim (bil ve ona göre yaz)
Seninle denetçi (Claude) arasında **otomatik bir köprü çalışır**: `doc/tools/kopru_izle.py` her 5 sn'de `BITTI.md` ve `DUZELTMELER.md`'yi izler; içerik değişince denetçiye anında bildirim gider. Bu yüzden:
- Raporunu **yalnız `doc/BITTI.md`'ye**, dosyadaki `<!-- Yapay zeka: raporunu bu satırın ALTINA ekle. -->` satırının **altına** yaz; şablon işaretini silme/değiştirme.
- Her rapor bölümünün başlığı tam şu biçimde olmalı: `## Kart <no> — <ad>` (köprü bu başlığı okur). Eski bölümleri silme, yeni bölümü en alta ekle.
- Raporu **tek seferde, tamamlanmış** yaz; yarım rapor yazıp sonra düzeltme (her değişiklik denetçiye "denetim gerekli" bildirimi gönderir).
- **Kendin de bildir:** raporu `BITTI.md`'ye yazdıktan hemen sonra sohbete tek satır yaz: `BİLDİRİM: BITTI.md güncellendi — Kart <no> — denetçi kararı bekleniyor (DUZELTMELER.md'yi izliyorum).` Köprü denetçiyi zaten uyarır; bu satır sahibin de görmesi içindir. Karar gelince (ONAYLI/RED/DURDUR) yine tek satır bildir: `BİLDİRİM: Kart <no> kararı <KARAR> — <ne yapıyorum>`. Başka uzun sohbet yazma.
- Denetçinin kararı `DUZELTMELER.md`'de anında görünür; senin tarafında köprü yok: o dosyayı 2–3 dakikada bir sen yeniden okursun (bölüm "Çalışma düzeni").
- `kopru_izle.py` ve bu iki dosyanın biçimini bozma; köprüyü durdurma/değiştirme (sahip/denetçi yönetir).

## 8. Çalışma sonu rapor biçimi (kısa)
**Yapılan iş** (dosyalar) · **Gerçek durum** (etiket) · **Test** (komut + literal çıktı) · **Güvenlik riski** · **Performans** (ölçüldüyse sayı, değilse "ölçülmedi") · **Kalan eksikler** · **Tek sonraki adım**.
