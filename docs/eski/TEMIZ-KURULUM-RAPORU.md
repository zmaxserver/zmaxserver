# Temiz kurulum testi — yerel VM (192.168.131.131, AlmaLinux 8.10), 2026-11-14
Durum: ARA RAPOR (zPanel temiz kurulumu, imzalı yerel yayın klasörü gelene kadar bekliyor).

## Yapılanlar
1. VM'den zPanel kaldırıldı: `bash zpanel-uninstaller --evet` (dosyalar/veri silindi; uninstaller 1175 paketi `rpm -e` ile kaldıramadı, "temizlik tamamlanamadı", paketler duruyor — P2 uninstaller). ZMax elle kaldırıldı. `./install --check` → `Ön kontrol: PASS`.
2. zPanel 1.0.09 `./install --hostname panel.zpanel.local --ayrintili` → `package could not be downloaded or verified: release: downloaded package does not match its SHA-256 or size` (CIKIS=1). `install` paketi https://www.betasoft.com.tr/zpanel/ üzerinden (release.json + imza) indiriyor, internetteki yayın yerel 1.0.09 paketleriyle eşleşmiyor. Çözüm: yerel imzalı yayın klasörü (paketle-zpanel oturumundan istendi).

## ZMax 1.0.09 paket testi (tek başına)
- rpm SHA256 `6786479e…` SHA256SUMS ile eşleşti; `rpm -qpl` içinde admin/js/app.js var; `dnf install` → `zmax -v` = v1.0.09.
- **BULGU P0 (düzeltildi, yeniden paketlenmeli):** servis başlamıyor: `[KRİTİK GÜVENLİK HATASI] Yetki düşürme başarısız: root olarak çalışırken server.user ve server.group boş olamaz (fail-closed)`. Sebep conf/zmax.toml'da `# user = ""`. Düzeltme: D:\lunixpanel\zmaxserver\conf\zmax.toml `user/group = "nobody"` + pack_zmax.py postinst (Debian'da nogroup).
- Geçici düzeltmeyle (VM'de conf): health 200, `/api/status` 404, WebAdmin `/` 200, `/js/app.js` 200 (JS içerik, "<!DOCTYPE" değil), `stats.version` var, `?id=1' OR 1=1--` 403 (WAF), `../../etc/passwd` 403, vhost API oluştur/sil.
- **BULGU P1 (düzeltildi, yeniden paketlenmeli):** temiz kurulumda `conf/vhosts` root:root 755: API'den vhost oluşturma Permission denied. Düzeltme: zmax.service `ExecStartPre` (tools\zmaxserver\assets\linux-x64\systemd\zmax.service). VM'de denendi: 2775 root:nobody, POST 200, DELETE 200.
- **BULGU P1 (düzeltildi):** `config/zmax/zmax-kur.sh` "ZMax paketinde install.sh yok" (arşiv üst dizinli). Düzeltme: `find -maxdepth 2`. VM'de `ZMAX_RELEASE_URL=file://...` ile: SHA256 doğrulandı, install.sh çalıştı, ZMax v1.0.09 active, portlar 19480/19485/19486.
- **BULGU (sahip/başka oturum):** GitHub v1.0.09 release'indeki ZMax paketleri eski (SHA256SUMS `fe2d07d1…` ve `6786479e…`); yerel yeni paket `b24064fb…`. Release güncellenmeli, yoksa zmax-kur.sh çöken paketi kurar.

## Bekleyen
- zPanel temiz kurulumu (imzalı yerel yayın), panel açılışı, ZMax servis durumu (zPanel kurulumundan), WebAdmin 19485, panel taraması.
- ZMax paketlerinin yeniden üretimi (conf + unit) ve VM'de tekrar test.

## 2. tur — ZMax 1.0.09 yeniden üretilmiş paket (rpm SHA256 3a9e6512…, tar.gz 3ece6251…) — GEÇTİ
VM'de `dnf install ./zmax-server-1.0.09-1.x86_64.rpm` → `zmax -v` = v1.0.09, servis active (kullanıcı nobody), `conf/vhosts` 2775 root:nobody (unit ExecStartPre), portlar 19480/19485/19486.
- health 200; `/api/status` 404; WebAdmin `/` 200; `/js/app.js` 200 (gerçek JS); `stats.version` var
- statik 19480 200; WAF `?id=1' OR 1=1--` 403; path traversal 403
- API: vhost oluştur 200 → yeni vhost HTTP 200 → reload 200 (generation 2) → vhost sil 200; cache purge 200; SSE akıyor; token günlükte yok (0); PHP STDERR satırı 0; audit.log kayıtları (reload, vhost-sil, cache-purge).

## 3. tur — zPanel temiz kurulum (yerel imzalı yayın, https, test `install`)
Düzen: Windows'ta http yayın (paketle-zpanel) → VM'de https sunucu (127.0.0.1:8443, kendinden imzalı sertifika, SSL_CERT_FILE + sistem güven deposuna test sertifikası eklendi; test sonrası kaldırılacak) → `ZPANEL_RELEASE_URL=https://127.0.0.1:8443/ ./install.test --hostname panel.zpanel.local --server-ip 192.168.131.131`.
Bulgular (literal):
1. `install` http adresi reddediyor: `release: the release address must be https` (beklenen, test düzeneği https'e çevrildi).
2. Adım 3'te `curl: (60) SSL certificate problem` (kendinden imzalı test sertifikası; sistem güven deposuna eklenince çözüldü) — ürün hatası değil, test düzeneği.
3. **Uninstaller sonrası aynı VM'ye tekrar kurulum bozuluyor (P1, uninstaller):** `zpanel-uninstaller --evet` dosya/veriyi siliyor ama 1175 paketi `rpm -e` ile kaldıramıyor (`temizlik tamamlanamadı`), rpm kayıtları kalıyor. Sonuç: initdb `/var/lib/pgsql/17/data erişim engellendi` (dizin root sahipli), MariaDB `mysql-prepare-db-dir: ... directory is not empty`, OLS `httpd_config.conf` yok. Her seferinde paketler elle kaldırılıp (`dnf remove`, `rpm -e --justdb zpanel`) temizlendi.
4. **Adım 9 düşüyor (P1, kurulum betiği):** `openlitespeed -t` çıkış kodu 1: `Uid of /var/www/zpanel-acme/ is 0, smaller than minimum requirement 11`. `lib/automatic.sh configure_acme_vhost` dizini root oluşturuyor; yalnız alan adı ile kurulumda (AUTO_CERT=1, IP_MODE=0) çalışan yol. VM'de `chown nobody:nobody` ile `-t` çıkışı 0 oldu. Kaynakta düzeltildi (`D:\lunixpanel\zpanel\lib\automatic.sh`); paketle-zpanel yeniden paketleyecek.
5. Adım 1–8 GEÇTİ: ön kontrol PASS, sistem paketleri, zPanel paketi, veritabanı (PostgreSQL 17 + MariaDB, 9 göç uygulandı, admin root oluşturuldu), panel yapılandırma, sertifika, servis birimleri.
6. Not: `install` IP'yi bir denemede `192.168.131.131`, sonraki denemede başka (dış) bir adres olarak buldu; `--server-ip` ile sabitlendi.

Bekleyen: yeniden paketleme sonrası temiz kurulum (VM temizleme betiği `/root/zp109/temizle.sh` hazır), panel açılışı, ZMax'in kurulumdan indirilmesi (`zmax-kur.sh`, release adresi: GitHub release eski paketi içeriyor), WebAdmin 19485, panel taraması.

## 4. tur — zPanel temiz kurulum SONUÇ: 12/12 GEÇTİ (yerel imzalı yayın, https, test `install`), CIKIS=0
Komut: `ZPANEL_RELEASE_URL=https://127.0.0.1:8443/ ./install.test --hostname panel.zpanel.local --server-ip 192.168.131.131 --ayrintili`
- Adımlar 1–12 tamam; `✓ Kurulum tamamlandı.`
- Servisler active: zpanel-api, zpanel-agent, zpanel-worker, zpanel-installer, postgresql-17, mariadb, redis, lshttpd (OLS), httpd, postfix, dovecot, named, pure-ftpd, fail2ban.
- Portlar: 80, 8026, 8036, 8046, 8047, 8056 dinliyor; `curl -k https://127.0.0.1:<port>/` → 200 (8036, 8026, 8056, 8047, 8046); `curl http://127.0.0.1:8055/v1/health` → `{"status":"ok","version":"1.0.09"}`.
- ZMax: kurulum sırasında `zmax-kur.sh` GERÇEK GitHub release'inden indirdi (`https://github.com/zmaxserver/zmaxserver/releases/download/v1.0.09/zmax-server-v1.0.09-linux-x64.tar.gz`), `ZMax SHA256 doğrulandı`, install.sh çalıştı, `zmax -v` = v1.0.09. AMA servis çöküyor (NRestarts=4, `[KRİTİK GÜVENLİK HATASI] Yetki düşürme başarısız: ... server.user ve server.group boş`): GitHub'daki release paketi eski.
- Kaynakta düzeltilen kurulum hataları (paketle-zpanel yeniden paketledi): (a) `lib/automatic.sh` ACME dizini root sahipli → `openlitespeed -t` 1, (b) `lib/hosting.sh` OLS Example/html root sahipli → aynı, (c) `config/zmax/zmax-kur.sh` install.sh bulunamadı (arşiv üst dizini), (d) `zmax-kur.sh` umask 077 → ZMax dosyaları 600/700, WebAdmin 404 (umask 022 eklendi, yeniden paketleme bekliyor).
- Yeni ZMax paketiyle (yerel, SHA256 3ece6251…) elle kurulunca: servis active, v1.0.09, portlar 19480/19485/19486, conf/vhosts 2775 root:nobody; dosya modları düzeltilince WebAdmin 200, /js/app.js JS, statik 200.
- DENENEMEDİ: panel arayüzü taraması (panel girişi root sistem parolasıyla yapılır; parola girmek yasak, giriş gerekir), WebAdmin tarayıcıda.
- SAHİBE AİT: GitHub release v1.0.09 ZMax paketlerini yeni paketlerle değiştirmek.
- ÜRÜN HATASI (uninstaller): paketleri kaldırmıyor, aynı sunucuya yeniden kurulum bozuluyor (§3).
Test düzeneği izleri (VM): /root/zp109 (https sunucu, yayın kopyası), /etc/pki/ca-trust/source/anchors/zp-test-srv.pem (test sertifikası; iş bitince kaldırılacak).
