# gereksinim.md — İlk kurulumda kurulacaklar
Kaynak: yerel VM testi (AlmaLinux 8.10, 2026-11-14) ve sahip talimatı: "ilk kurulum yapısında bunlar kurulsun". Bu liste kurulum betiğine/paketine eklenecek; **henüz kurulum betiğine işlenmedi**.

## 1. LSPHP modülleri (her sürüm: 8.2, 8.3, 8.4, 8.5)
Bulgu: varsayılan kurulum yalnız `common, mysqlnd, pdo, xml, process, pear, devel` paketlerini getiriyordu; Laravel ve WordPress için gerekli modüller eksikti.
Her `lsphpNN` için (zpanel-litespeed deposu):
- `lsphpNN-mbstring` (Laravel için zorunlu, WordPress önerilen)
- `lsphpNN-opcache`
- `lsphpNN-intl`
- `lsphpNN-gd`
- `lsphpNN-bcmath`
- Doğrulandı (8.4): bu beşi kurulunca `php -m` içinde görünüyor.
- **Standart (sahip kararı, 2026-11-14):** `mbstring, opcache, intl, gd, bcmath` ile birlikte `pgsql`, `pecl-redis`, `pecl-imagick`, `ldap`, `pecl-memcached`, `pecl-imap`, `soap` — yani her `lsphpNN` için 12 modül, ilk kurulumda hepsi kurulur.

## 2. Araçlar
| Araç | Neden | Durum |
|---|---|---|
| `git` | Git Toolkit | VM'de var |
| `unzip` | Composer/WordPress/uzantı paketleri | VM'de var |
| `composer` | Laravel Toolkit, Composer araçları | VM'de **yok**; sistem geneli kurulum (`/usr/local/bin/composer`, lsphp ile çalışacak sarmalayıcı) |
| Node.js **20 / 22 / 24 / 26** (sahip: 18 değil; hepsi LTS) | Node Toolkit sürüm seçimi | Yan yana kurulur: `/opt/zpanel/node/<ana sürüm>/bin/node` (8047 bileşen yöneticisinin düzeni). Node 26 için `libatomic` gerekir. Panelin kendi çalışma zamanı (`/opt/zpanel/runtime/node`) yalnız panel içindir |
| `pm2` | Node uygulamalarını ayakta tutma | VM'de **yok** |
| Docker Engine | Docker Toolkit ("Docker kurulu değil") | VM'de **yok** (aşağıya bak) |

## 3. Docker (karar bekliyor)
- AlmaLinux 8'de `docker-ce` kurulumu `podman`, `buildah`, `cockpit-podman`, `podman-catatonit` ile çakışıyor; `--allowerasing` bunları siler (VM'de podman konteyneri yok).
- Seçenekler: (a) `docker-ce` kurup podman paketlerini sil (gerçek Docker Engine), (b) `podman-docker` + `podman.socket` (silmeden, docker uyumlu).
- İlk kurulumda hangisinin kullanılacağı sahip kararı.

## 4. Sunucu tarafı ayarlar (kurulumda)
- `conf/vhosts` dizini: grup `nobody`, mod `2775`; dosyalar `0664` (ZMax `nobody` olarak okur/yazar). zPanel'in yazdığı vhost dosyaları da grup `nobody` okunabilir olmalı.
- Site PHP'si: `vhost.php.sapi = "lsapi"` ve upstream `lsphp -b` adresi; `lsphp` süreçlerini başlatıp ayakta tutan birim (systemd/zPanel). php-fpm kurulmaz ("tek PHP: LSPHP").
- `php-cgi` yerine LSAPI kullanıldığı için FastCGI sarmalayıcı gerekmez.
- GeoIP veritabanı (ülke): kurulumda değil, panel/ZMax'ten indirilir; haftalık cron ile güncellenir (Geliştirmenotu.md bölüm 5).

## 5. Doğrulama (kurulum sonrası kontrol listesi)
1. `lsphpNN -m` içinde `mbstring intl gd bcmath Zend OPcache` var.
2. `composer --version` çalışıyor; `composer create-project laravel/laravel` ZMax üzerinde `/up` 200.
3. Node uygulaması `[vhost.proxy]` ile 200; `node -v` seçilen sürümü gösteriyor, `pm2 -v` çalışıyor.
4. `docker version` (veya podman-docker) çalışıyor; Docker Toolkit "kurulu" gösteriyor.
5. API'den vhost oluştur/sil 200 (izin düzeltmesi).
