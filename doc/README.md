# ZMax Server — Doküman Haritası

**Amaç:** tüm belgelerin haritası ve yapay zekaya verme sırası. **Güncellenir:** belge eklenince/taşınınca. **Bağlı:** her belge kendi başında amaç / güncelleme / bağlı belgeleri söyler.

**Hedef (sahip):** ZMax, OpenLiteSpeed ile denk ve hatasız çalışacak. Etiketler: `PLANNED` → `IMPLEMENTED` → `UNIT TESTED` → `INTEGRATED` → `INTEGRATION TESTED` → `PRODUCTION VERIFIED`; kanıtsız bilgi "bilinmiyor".

## Yapay zekaya verme sırası
1. [`YAPAY_ZEKA_KURALLARI.md`](YAPAY_ZEKA_KURALLARI.md) 2. bu README 3. [`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md) 4. [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md) 5. **tek görev kartı** ([`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) içinden). Panel (Go) kartı ise ek olarak [`entegre/goentegre.md`](entegre/goentegre.md).

## Tek doğruluk kaynakları
| Konu | Tek yer |
|---|---|
| Durum etiketleri, test sonucu, crate envanteri | [`TAM_MODUL_VE_OZELLIK_MATRISI.md`](TAM_MODUL_VE_OZELLIK_MATRISI.md) |
| Görev kartları (yapılacak) | [`ADIMLI_GELISTIRME_TAKIP.md`](ADIMLI_GELISTIRME_TAKIP.md) |
| Mimari, katmanlar, istek hattı, Rust↔Go sözleşmesi | [`MIMARI_VE_PLAN.md`](MIMARI_VE_PLAN.md) |
| Fazlar, sürümler, test politikası, üretim kontrol listesi | [`YOL_HARITASI.md`](YOL_HARITASI.md) |
| OLS denklik matrisi + kabul kapısı | [`karsilastirma/OLS_DENKLIK.md`](karsilastirma/OLS_DENKLIK.md) |
| Panel↔ZMax: portlar, API, TOML, günlük, panel işleri | [`entegre/goentegre.md`](entegre/goentegre.md) |
| Biten/kalan özeti (sahip) | [`BITEN_VE_KALAN.md`](BITEN_VE_KALAN.md) |
| Bağımsız doğrulamada yanlış/eksik çıkan raporlar ve düzeltme talimatları (kart başına) | [`DUZELTMELER.md`](DUZELTMELER.md) |
| Yapay zekanın bitirdiği kartların raporları (yapay zeka yazar, denetçi doğrular) | [`BITTI.md`](BITTI.md) (Kart 1) ve çok ajanda `bitti/KART-<no>.md` |
| **10 ajanlı çalışma yapısı** (kart↔ajan↔dosya sahipliği, çakışma kuralları, birleştirme) | [`AJAN_YAPISI.md`](AJAN_YAPISI.md) |
| Yapay zeka çalışma kuralları (sahip yazdırdı) | [`YAPAY_ZEKA_KURALLARI.md`](YAPAY_ZEKA_KURALLARI.md) |

## Yardımcı belgeler
[`karsilastirma/FERRON_VE_LITESPEED_KARSILASTIRMA.md`](karsilastirma/FERRON_VE_LITESPEED_KARSILASTIRMA.md) (rakip kıyası) · [`ISLETIM_SISTEMI_GEREKSINIMLERI_VE_HESAPLAMALAR.md`](ISLETIM_SISTEMI_GEREKSINIMLERI_VE_HESAPLAMALAR.md) (OS ayarları) · [`sifleme.md`](sifleme.md) (`zmax-obfuscate`) · [`tools/README.md`](tools/README.md) (derleme/paketleme/test; betikler `tools/` içinde) · `ornekmimariler/` (referans kod, değiştirilmez) · [`arsiv/2026-11-12/`](arsiv/2026-11-12/README.md) (eski/birleşen belgeler).

Panel (Go) kodu `D:\lunixpanel\zpanel-tam` içindedir, bu klasörde değiştirilmez. `D:\zmaxserver\goentegre.md` (proje kökü) eski kopyadır.