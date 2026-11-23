# Yerel VM ile temiz (canlı benzeri) kurulum farkları — 2026-11-14
Canlı sunucuya bağlanılmadı (adres/giriş bilgisi yok, kuralla yasak); bu liste yalnızca **VM'de benim yaptığım değişiklikleri** verir. Canlı bunları içermez, canlıda aynı sonuçlar için kurulum betiğine işlenmeleri gerekir.

| # | VM'de yapılan | Canlıda yoksa sonuç |
|---|---|---|
| 1 | ZMax ikilisi vm-yukle derlemesi (8 düzeltme), /usr/local/zmax/admin yamalı (app.js, i18n, index.html, dashboard) | Canlıda eski ikili: token günlüğe yazılır, LSAPI yok, WebAdmin siyah ekran olabilir |
| 2 | zmax.service.d/vhosts-izin.conf: conf/vhosts grup nobody 2775 | API vhost oluşturma ve reload izin hatası verir |
| 3 | lsws devre dışı (disable --now); zmax 80/443 + panel portları 8026/8036/8047/8056 (zmax.toml [[listeners.extra]], yedek /root/zmax.toml.yedek-108) | OpenLiteSpeed açılışta 80/443'ü alabilir; panel portları OLS'te |
| 4 | lsphp82–85: mbstring, opcache, intl, gd, bcmath, pgsql, redis, imagick, ldap, memcached, imap(8.2 hariç), soap | Laravel/WordPress modül eksikliği |
| 5 | Docker CE 26.1.3 (podman, buildah, cockpit-podman, runc kaldırıldı); Composer 2.11.2 (/usr/local/bin), pm2 7.1.2, Node 20/22/24/26 (/opt/zpanel/node/N), libatomic | Docker/Node/Laravel toolkit "kurulu değil" |
| 6 | Panel: dist yamaları (ext_installed sürümü, Node sürüm listesi) ve zpanel-api yeniden başlatıldı; 9 yerleşik toolkit kuruldu | Uzantı Yükle 500 verir; Node 24/26 listede yok |
| 7 | zmax-lsphp-roundcube.service + vhost webmail.panel.zpanel.local (Roundcube ZMax'ten) | Webmail OLS'e bağlı kalır |
| 8 | Test artığı: /var/www/vhosts/ucuncutest.com/zt-laravel (Laravel Toolkit kaydı etkin) | — |
| 9 | php83 (Remi php-fpm) hâlâ çalışıyor, site PHP'si fastcgi; yalnız webmail LSAPI | Canlı da aynı olabilir; karar bekliyor |

Canlıyı karşılaştırmak için gereken: sunucu adresi + salt-okunur erişim. Sahibin açık izni olmadan bağlanılmaz.
