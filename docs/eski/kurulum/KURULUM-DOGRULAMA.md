# Kurulum doğrulama (yerel VM 192.168.131.131, 2026-11-14)

Betik: `docs/kurulum/gereksinim-kur.sh` (7 adım: LSPHP 12 modül x 4 sürüm, araçlar, composer/Node 20-22-24-26/pm2, Docker `--allowerasing`, vhost izinleri, zmax drop-in, lsws kapalı, doğrulama bölümü).

## Komutlar
- `sh -n gereksinim-kur.sh` (yerel ve VM): sözdizimi tamam.
- `scp` ile `/tmp/gereksinim-kur.sh`, VM'de `sh /tmp/gereksinim-kur.sh` ardışık 2 kez: `CIKIS=0` ve `CIKIS=0`.
- Önce/sonra `systemctl is-active zmax zpanel-api docker`: `active active active` / `active active active` (değişmedi, hiçbir servis yeniden başlatılmadı). `systemctl is-enabled lsws`: `disabled`.
- `/tmp/gereksinim-kur.sh` ve log silindi.

## Doğrulama bölümü çıktısı (literal)
```
== Dogrulama ==
lsphp82 tamam
lsphp83 tamam
lsphp84 tamam
lsphp85 tamam
Composer version 2.11.2 2026-11-10 10:09:37
v20.20.2
v22.23.5
v24.22.3
v26.13.1
docker 26.1.3
7.1.2
TAMAM
```

## Bulunan/düzeltilen hata
- İlk denemede `pm2 -v` başarısızdı (PATH'te node yok). Çözüm: `/usr/local/bin/pm2` artık node PATH'ini ayarlayan sarmalayıcı. Düzeltme sırasında eski symlink'e `>` yazımı gerçek pm2 dosyasını bozdu; betiğe `rm -f /usr/local/bin/pm2` eklendi ve VM'de `npm install -g pm2` ile pm2 yeniden kuruldu (7.1.2).

## Kapsam sınırı
- Doğrulama yalnız "zaten kurulu" yolunu kanıtlar (dnf "Yapılacak bir şey yok"). Boş sistemde ilk kurulum (Docker/podman `--allowerasing`, Node indirme, zmax drop-in ilk yazım) bu VM'de çalıştırılmadı: MANUAL/SKIPPED.
- Drop-in dosyası VM'de zaten aynıydı (`cmp` eşit, daemon-reload yapılmadı).

Sonuç: GEÇTİ (idempotent yeniden çalıştırma); temiz kurulum yolu doğrulanmadı.
