# Arşiv — 2026-11-12 doküman birleştirme

Hiçbir dosya silinmedi. Güncel harita: [`../../README.md`](../../README.md).
Durum sözlüğü: **taşındı** = orijinal doc'ta artık yok, burada. **birleşti: X** = içeriği X'e alındı, orijinal burada. **kopya (orijinal Y'de)** = Y güncel haliyle yerinde, burada güncellemeden önceki hali var.

| Arşivdeki dosya | Durum | Güncel yer |
|---|---|---|
| `GELISTIRME_PLANI.md` | taşındı; birleşti: `ADIMLI_GELISTIRME_TAKIP.md`, `MIMARI_VE_PLAN.md` | — |
| `mimari/EKLENECEK_MIMARI.md` | taşındı; birleşti: `ADIMLI_GELISTIRME_TAKIP.md` (Faz 1–4, TOML uzantıları) | — |
| `mimari/eksik.txt` | taşındı; birleşti: `ADIMLI_GELISTIRME_TAKIP.md` (E1–E15), `entegre/goentegre.md` §7 | — |
| `zpanel-entegre.md` | taşındı; birleşti: `entegre/goentegre.md` | — |
| `yapayzeka-onerileri/chatgpt.md`, `chatgptoneri.md`, `seepseek.md`, `deepseek_oneri.md`, `birlesik_oneri.md` | taşındı; birleşti: `YOL_HARITASI.md` | — |
| `yapayzeka-onerileri/ZMAX_SAGLAM_YAPI.md` | taşındı (aynı içerik `YOL_HARITASI.md` olarak kaldı) | `YOL_HARITASI.md` |
| `tamproje.md` | kopya (orijinal güncellemeden önceki hali) | birleşti: `TAM_MODUL_VE_OZELLIK_MATRISI.md` §8; orijinal artık doc kökünde yok |
| `birlesen/tamproje_birlesmeden-onceki-son.md` | taşındı (birleşmeden önceki son hali) | `TAM_MODUL_VE_OZELLIK_MATRISI.md` §8 |
| `tools/derleme.md` | kopya (güncellemeden önceki hali) | birleşti: `tools/README.md` alt bölümü; orijinal `tools/` altında artık yok |
| `birlesen/tools-derleme_birlesmeden-onceki-son.md` | taşındı (birleşmeden önceki son hali) | `tools/README.md` |
| `tools/README.md` | kopya (orijinal `tools/README.md`'de, derleme rehberi dahil güncel). `tools/` betikleri yerinde, arşive alınmadı | `tools/README.md` |
| `FERRON_VE_LITESPEED_KARSILASTIRMA.md` | kopya (güncellemeden önceki hali) | orijinal `karsilastirma/FERRON_VE_LITESPEED_KARSILASTIRMA.md` (taşındı, güncel) |
| `ISLETIM_SISTEMI_GEREKSINIMLERI_VE_HESAPLAMALAR.md` | kopya: güncellendi, kökte duruyor; buradaki eski hali | `ISLETIM_SISTEMI_GEREKSINIMLERI_VE_HESAPLAMALAR.md` |
| `sifleme.md` | kopya: güncellendi, kökte duruyor; buradaki eski hali | `sifleme.md` |
| `MIMARI_VE_PLAN.md` | kopya (eski sürüm; yeniden yazıldı) | `MIMARI_VE_PLAN.md` |
| `ADIMLI_GELISTIRME_TAKIP.md` | kopya (eski sürüm; yerine birleşik takip yazıldı) | `ADIMLI_GELISTIRME_TAKIP.md` |
| `goentegre.md` | kopya (eski sürüm; yerine birleşik belge yazıldı) | `entegre/goentegre.md` |

| `birlesen/tamproje_216-test-raporu.md` | taşındı (yeni sürüm raporu) | benzersiz bilgisi (216 test sonucu, duman/paket çıktıları, kanıt test adları) `TAM_MODUL_VE_OZELLIK_MATRISI.md` başına ve §8'e birleşti |
| `birlesen/BITEN_VE_KALAN_uzun.md` | kopya (sahibin uzun sürümü) | kısaltılmış `BITEN_VE_KALAN.md` doc kökünde |
| `ADIMLI_GELISTIRME_TAKIP.md` / `YOL_HARITASI.md` eski içerik | eski takip: arşivdeki `ADIMLI_GELISTIRME_TAKIP.md`; `YOL_HARITASI` §2 durum tablosu, §3 ve §9: kaldırıldı (matris, MIMARI, goentegre §7'de) | — |

Notlar:
- `MIMARI_VE_PLAN`, `ADIMLI_GELISTIRME_TAKIP`, `goentegre` arşiv kopyaları: üzerine yazmadan önce arşivlenemediği için okunan içerikten yeniden yazıldı (bayt düzeyinde aynı olduğu doğrulanmadı).
- `TAM_MODUL_VE_OZELLIK_MATRISI.md` yerinde düzeltildi; güncellemeden önceki hali arşivlenmedi.
- `YAPAY_ZEKA_KURALLARI.md` sahibin dosyası, dokunulmadı (yalnız eski bir bağlantı ifadesi çıkarıldı).
- Boş `doc/mimari/` klasörü kaldı.

## Optimizasyon: satır sayıları (önce → sonra, 2026-11-12)
| Belge | Önce | Sonra | Not |
|---|---|---|---|
| `MIMARI_VE_PLAN.md` | 110 | 54 | durum tablosu matrise, kalan bağlantı |
| `ADIMLI_GELISTIRME_TAKIP.md` | 142 | 130 | 12 görev kartı |
| `YOL_HARITASI.md` | 182 | 139 | durum/iş bölümü/Go listesi kaldırıldı (matris, MIMARI, goentegre) |
| `BITEN_VE_KALAN.md` | 108 | 20 | uzun sürüm `birlesen/BITEN_VE_KALAN_uzun.md` |
| `TAM_MODUL_VE_OZELLIK_MATRISI.md` | 121 | 123 | 216 test sonucu eklendi (`tamproje` birleşti) |
| `tamproje.md` | 165 | — | arşive taşındı, birleşti |
| `entegre/goentegre.md` | 158 | 160 | yalnız 3 satırlık başlık eklendi |
| `karsilastirma/OLS_DENKLIK.md` | 97 | 99 | başlık |
| `karsilastirma/FERRON_VE_LITESPEED_KARSILASTIRMA.md` | 76 | 78 | başlık |
| `ISLETIM_SISTEMI_…md`, `sifleme.md`, `tools/README.md` | 92 / 94 / 294 | 94 / 96 / 296 | yalnız başlık eklendi, **içerik sıkıştırılmadı** |
| `README.md` | 21 | 25 | verme sırası + tek kaynak tablosu |
| `YAPAY_ZEKA_KURALLARI.md` | 56 | — | sahibin dosyası, dokunulmadı |