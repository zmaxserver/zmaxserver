#!/bin/sh
# gereksinim.md'deki ilk kurulum gereksinimlerini kurar (AlmaLinux 8, yinelenebilir/idempotent).
# Hicbir servisi yeniden baslatmaz.
set -eu
LSPHP_VERS="82 83 84 85"
MODS="mbstring opcache intl gd bcmath pgsql pecl-redis pecl-imagick ldap pecl-memcached pecl-imap soap"
NODE_MAJORS="20 22 24 26"

echo "[1/7] LSPHP modulleri (her surum icin 12 modul; lsphp82 pecl-imap yok -> --skip-broken)"
PK=""
for v in $LSPHP_VERS; do for m in $MODS; do PK="$PK lsphp$v-$m"; done; done
dnf -y install --skip-broken $PK

echo "[2/7] Araclar (libatomic, git, unzip)"
dnf -y install libatomic git unzip

echo "[3/7] Composer + Node surumleri + pm2"
if [ ! -x /usr/local/bin/composer.phar ]; then
  curl -fsSL -o /usr/local/bin/composer.phar https://getcomposer.org/download/latest-stable/composer.phar
  chmod 755 /usr/local/bin/composer.phar
fi
printf '#!/bin/sh\nexec /usr/local/lsws/lsphp84/bin/php /usr/local/bin/composer.phar "$@"\n' > /usr/local/bin/composer
chmod 755 /usr/local/bin/composer
for m in $NODE_MAJORS; do
  [ -x /opt/zpanel/node/$m/bin/node ] && continue
  V=$(curl -fsS https://nodejs.org/dist/index.json | python3 -c "import sys,json;print([r['version'] for r in json.load(sys.stdin) if r['version'].startswith('v$m.')][0])")
  F=node-$V-linux-x64.tar.xz
  curl -fsSL -o /tmp/$F https://nodejs.org/dist/$V/$F
  curl -fsS https://nodejs.org/dist/$V/SHASUMS256.txt | grep " $F\$" | (cd /tmp && sha256sum -c -)
  mkdir -p /opt/zpanel/node/$m
  tar xJf /tmp/$F -C /opt/zpanel/node/$m --strip-components=1
  rm -f /tmp/$F
done
[ -f /opt/zpanel/node/24/lib/node_modules/pm2/bin/pm2 ] || PATH=/opt/zpanel/node/24/bin:$PATH npm install -g pm2
rm -f /usr/local/bin/pm2
printf '#!/bin/sh
PATH=/opt/zpanel/node/24/bin:$PATH exec /opt/zpanel/node/24/bin/pm2 "$@"
' > /usr/local/bin/pm2
chmod 755 /usr/local/bin/pm2

echo "[4/7] Docker Engine (podman paketleri --allowerasing ile kaldirilir)"
if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
  dnf -y install dnf-plugins-core
  dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  dnf -y install --allowerasing docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable --now docker

echo "[5/7] ZMax vhost dizini izinleri (grup nobody, 2775/g+rw)"
V=/usr/local/zmax/conf/vhosts
if [ -d "$V" ]; then chgrp -R nobody "$V"; chmod 2775 "$V"; chmod g+rw "$V"/*.toml 2>/dev/null || true; fi

echo "[6/7] zmax.service drop-in (vhosts-izin.conf)"
D=/etc/systemd/system/zmax.service.d
mkdir -p "$D"
cat > "$D/vhosts-izin.conf.yeni" <<'EOF'
[Unit]
Description=ZMax Server - ZePanel High Speed HTTP Engine

[Service]
# conf/vhosts: ZMax (nobody) okur/yazar; zPanel (root) 0640 yazsa da grup nobody okuyabilsin.
ExecStartPre=/bin/sh -c "d=/usr/local/zmax/conf/vhosts; [ -d $d ] && chgrp -R nobody $d && chmod 2775 $d && chmod g+rw $d/*.toml 2>/dev/null; true"
EOF
if cmp -s "$D/vhosts-izin.conf.yeni" "$D/vhosts-izin.conf" 2>/dev/null; then
  rm -f "$D/vhosts-izin.conf.yeni"
else
  mv "$D/vhosts-izin.conf.yeni" "$D/vhosts-izin.conf"; systemctl daemon-reload
fi

echo "[7/7] lsws kapali tutulur (ZMax 80/443'u alir)"
if systemctl list-unit-files lsws.service 2>/dev/null | grep -q '^lsws'; then systemctl disable --now lsws || true; fi

echo "== Dogrulama =="
H=0
for v in $LSPHP_VERS; do
  PHP=/usr/local/lsws/lsphp$v/bin/php
  if [ ! -x $PHP ]; then echo "EKSIK: $PHP"; H=1; continue; fi
  M=$($PHP -m)
  for x in mbstring intl gd bcmath; do echo "$M" | grep -qix "$x" || { echo "EKSIK: lsphp$v $x"; H=1; }; done
  echo "$M" | grep -qi 'opcache' || { echo "EKSIK: lsphp$v opcache"; H=1; }
  echo "lsphp$v tamam"
done
composer --version --no-interaction 2>/dev/null | head -1 || H=1
for m in $NODE_MAJORS; do /opt/zpanel/node/$m/bin/node -v || H=1; done
docker version --format 'docker {{.Server.Version}}' || H=1
pm2 -v || H=1
if [ $H -eq 0 ]; then echo "TAMAM"; else echo "HATA: eksikler var"; fi
exit $H
