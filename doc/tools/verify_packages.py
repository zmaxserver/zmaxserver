#!/usr/bin/env python3
"""ZMax Server üretilen dağıtım paketlerinin bütünlük ve içerik doğrulayıcısı."""

import argparse
import gzip
import io
import os
import sys
import tarfile
import zipfile

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.abspath(os.path.join(TOOLS_DIR, "..", ".."))
DEFAULT_VERSION = "1.0.01"
DEFAULT_RELEASE = "1"

REQUIRED_COMMON = [
    "admin/index.html",
    "admin/favicon.svg",
    "admin/assets/zmax_black.svg",
    "admin/assets/zmax_white.svg",
    "admin/assets/zpanel_icon.svg",
    "admin/css/bootstrap.min.css",
    "admin/css/core.css",
    "admin/js/bootstrap.bundle.min.js",
    "admin/js/core.js",
    "admin/js/i18n.js",
    "admin/js/vue.global.prod.js",
    "conf/zmax.toml",
    "conf/mime.types",
    "conf/vhosts/localhost.toml",
    "conf/vhosts/example.com.toml",
    "fcgi-bin/php-fpm.conf",
    "modules/mod_quic.toml",
    "modules/mod_ssl.toml",
    "modules/mod_fastcgi.toml",
    "modules/mod_cache.toml",
    "www/html/index.html",
    "www/php/info.php",
]


def parse_cpio_entries(cpio_bytes):
    pos = 0
    entries = []
    while pos + 110 <= len(cpio_bytes):
        magic = cpio_bytes[pos:pos + 6]
        assert magic in (b"070701", b"070702"), f"Hatalı CPIO magic: {magic!r}"
        mode = int(cpio_bytes[pos + 14:pos + 22], 16)
        filesize = int(cpio_bytes[pos + 54:pos + 62], 16)
        namesize = int(cpio_bytes[pos + 94:pos + 102], 16)
        name_start = pos + 110
        name_end = name_start + namesize
        name = cpio_bytes[name_start:name_end].rstrip(b"\x00").decode("utf-8", errors="replace")
        pos = (name_end + 3) & ~3
        if name == "TRAILER!!!":
            break
        payload = cpio_bytes[pos:pos + filesize]
        entries.append((name, mode, filesize, payload))
        pos = ((pos + filesize) + 3) & ~3
    return entries


def verify_common_payload(fmt, path, toml_txt, adm_html, adm_js, require_lf=False):
    assert b"port = 19480" in toml_txt and b"port = 19485" in toml_txt and b"port = 19486" in toml_txt, (
        f"{fmt} zmax.toml beklenen port bloğunu (19480/19485/19486) içermiyor: {path}"
    )
    if require_lf:
        assert b"\r\n" not in toml_txt, f"{fmt} zmax.toml CRLF içeriyor: {path}"

    assert b'href="css/core.css"' in adm_html and b'href="/css/' not in adm_html, (
        f"{fmt} WebAdmin index.html mutlak yol içeriyor: {path}"
    )
    has_rel_api = b"apiFetch('api/status')" in adm_js or b"fetch('api/status')" in adm_js
    has_abs_api = b"fetch('/api/" in adm_js or b"apiFetch('/api/" in adm_js
    assert has_rel_api and not has_abs_api, (
        f"{fmt} core.js göreli API yolu doğrulamasından geçemedi: {path}"
    )


def inspect_rpm(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data[:4] == b"\xed\xab\xee\xdb", f"RPM sihirli başlık hatalı: {path}"
    gz_idx = data.find(b"\x1f\x8b\x08", 96)
    assert gz_idx > 0, f"RPM içinde gzip yük bulunamadı: {path}"
    cpio_bytes = gzip.decompress(data[gz_idx:])
    entries = parse_cpio_entries(cpio_bytes)
    by_name = {name.lstrip("./"): (mode, size, payload) for name, mode, size, payload in entries}

    for rel in REQUIRED_COMMON:
        full = f"usr/local/zmax/{rel}"
        assert full in by_name, f"RPM içinde eksik: {full} ({path})"
    for extra in (
        "usr/local/zmax/bin/zmax",
        "usr/local/zmax/bin/zmaxctrl",
        "usr/local/zmax/logs",
        "usr/local/zmax/cachedata",
        "usr/lib/systemd/system/zmax.service",
        "usr/local/bin/zmax",
        "usr/local/bin/zmaxctrl",
    ):
        assert extra in by_name, f"RPM içinde eksik: {extra} ({path})"

    assert "usr/local/zmax/install.sh" not in by_name, f"RPM içinde gereksiz install.sh var: {path}"
    assert not any(n.endswith(".log") for n in by_name), f"RPM içinde log dosyası artığı var: {path}"

    mod_count = sum(1 for n in by_name if n.startswith("usr/local/zmax/modules/mod_") and n.endswith(".toml"))
    assert mod_count == 18, f"RPM modül sayısı 18 olmalı, bulunan={mod_count}: {path}"

    verify_common_payload(
        "RPM",
        path,
        by_name["usr/local/zmax/conf/zmax.toml"][2],
        by_name["usr/local/zmax/admin/index.html"][2],
        by_name["usr/local/zmax/admin/js/core.js"][2],
        require_lf=True,
    )
    assert b"\r\n" not in by_name["usr/local/zmax/bin/zmaxctrl"][2], f"RPM zmaxctrl CRLF içeriyor: {path}"
    assert b"\r\n" not in by_name["usr/lib/systemd/system/zmax.service"][2], f"RPM service CRLF içeriyor: {path}"
    print(f"[OK] RPM tam paket doğrulandı ({len(entries)} öğe, {mod_count} modül, {len(data)} B): {os.path.basename(path)}")


def inspect_targz(path):
    with tarfile.open(path, "r:gz") as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        prefix = names[0].split("/")[0]
        name_set = set(names)
        for rel in REQUIRED_COMMON:
            assert f"{prefix}/{rel}" in name_set, f"TAR.GZ eksik: {rel} ({path})"
        for extra in ("bin/zmax", "bin/zmaxctrl", "install.sh", "systemd/zmax.service", "logs", "cachedata"):
            assert f"{prefix}/{extra}" in name_set, f"TAR.GZ eksik: {extra} ({path})"
        assert not any(n.endswith(".log") for n in names), f"TAR.GZ içinde log artığı var: {path}"
        mod_count = sum(1 for n in names if "/modules/mod_" in n and n.endswith(".toml"))
        assert mod_count == 18, f"TAR.GZ modül sayısı={mod_count}: {path}"

        verify_common_payload(
            "TAR.GZ",
            path,
            tf.extractfile(f"{prefix}/conf/zmax.toml").read(),
            tf.extractfile(f"{prefix}/admin/index.html").read(),
            tf.extractfile(f"{prefix}/admin/js/core.js").read(),
            require_lf=True,
        )
        ctrl_txt = tf.extractfile(f"{prefix}/bin/zmaxctrl").read()
        assert b"\r\n" not in ctrl_txt and b"19486" in ctrl_txt, f"TAR.GZ zmaxctrl hatalı: {path}"
        inst_txt = tf.extractfile(f"{prefix}/install.sh").read()
        assert b"\r\n" not in inst_txt and b"19485" in inst_txt, f"TAR.GZ install.sh hatalı: {path}"
    print(f"[OK] TAR.GZ tam paket doğrulandı ({len(names)} öğe, {mod_count} modül): {os.path.basename(path)}")


def inspect_deb(path):
    with open(path, "rb") as f:
        data = f.read()
    assert data.startswith(b"!<arch>\ndebian-binary"), f"DEB ar başlığı hatalı: {path}"
    pos = 8
    parts = {}
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("ascii", errors="replace").strip()
        size = int(hdr[48:58].decode("ascii", errors="replace").strip())
        pos += 60
        parts[name] = data[pos:pos + size]
        pos += size + (size % 2)

    assert "control.tar.gz" in parts and "data.tar.gz" in parts, f"DEB bölümleri eksik: {path}"

    with tarfile.open(fileobj=io.BytesIO(parts["control.tar.gz"]), mode="r:gz") as ctf:
        cnames = set(ctf.getnames())
        for req_ctrl in ("./control", "./conffiles", "./md5sums", "./postinst", "./prerm", "./postrm"):
            assert req_ctrl in cnames, f"DEB control eksik {req_ctrl}: {path}"
        conffiles_txt = ctf.extractfile("./conffiles").read().decode("utf-8")
        assert "/usr/local/zmax/conf/zmax.toml" in conffiles_txt and "\r\n" not in conffiles_txt

    with tarfile.open(fileobj=io.BytesIO(parts["data.tar.gz"]), mode="r:gz") as dtf:
        dmembers = {m.name.lstrip("./"): m for m in dtf.getmembers()}
        for rel in REQUIRED_COMMON:
            assert f"usr/local/zmax/{rel}" in dmembers, f"DEB içinde eksik: {rel} ({path})"
        for extra in (
            "usr/local/zmax/bin/zmax",
            "usr/local/zmax/bin/zmaxctrl",
            "usr/local/zmax/logs",
            "usr/local/zmax/cachedata",
            "etc/systemd/system/zmax.service",
            "usr/local/bin/zmax",
            "usr/local/bin/zmaxctrl",
        ):
            assert extra in dmembers, f"DEB içinde eksik: {extra} ({path})"
        assert dmembers["usr/local/bin/zmax"].issym() and dmembers["usr/local/bin/zmaxctrl"].issym()
        assert dmembers["usr/local/zmax/bin/zmax"].mode == 0o755
        assert dmembers["usr/local/zmax/bin/zmaxctrl"].mode == 0o755
        assert "usr/local/zmax/install.sh" not in dmembers, f"DEB içinde gereksiz install.sh var: {path}"
        assert not any(n.endswith(".log") for n in dmembers), f"DEB içinde log artığı var: {path}"
        mod_count = sum(1 for n in dmembers if n.startswith("usr/local/zmax/modules/mod_") and n.endswith(".toml"))
        assert mod_count == 18, f"DEB modül sayısı={mod_count}: {path}"

        verify_common_payload(
            "DEB",
            path,
            dtf.extractfile("./usr/local/zmax/conf/zmax.toml").read(),
            dtf.extractfile("./usr/local/zmax/admin/index.html").read(),
            dtf.extractfile("./usr/local/zmax/admin/js/core.js").read(),
            require_lf=True,
        )
    print(f"[OK] DEB tam paket doğrulandı ({len(dmembers)} öğe, {mod_count} modül, {len(data)} B): {os.path.basename(path)}")


def inspect_zip(path):
    with zipfile.ZipFile(path, "r") as zf:
        names = set(zf.namelist())
        for rel in REQUIRED_COMMON:
            assert f"win/{rel}" in names, f"ZIP içinde eksik: {rel} ({path})"
        for extra in ("win/bin/zmax.exe", "win/bin/zmaxctrl.bat", "win/logs/", "win/cachedata/"):
            assert extra in names, f"ZIP içinde eksik: {extra} ({path})"
        assert not any(n.endswith(".log") for n in names), f"ZIP içinde test logu kalmış: {path}"
        mod_count = sum(1 for n in names if n.startswith("win/modules/mod_") and n.endswith(".toml"))
        assert mod_count == 18, f"ZIP modül sayısı={mod_count}: {path}"

        verify_common_payload(
            "ZIP",
            path,
            zf.read("win/conf/zmax.toml"),
            zf.read("win/admin/index.html"),
            zf.read("win/admin/js/core.js"),
            require_lf=False,
        )
    print(f"[OK] ZIP tam paket doğrulandı ({len(names)} öğe, {mod_count} modül): {os.path.basename(path)}")


def parse_args():
    parser = argparse.ArgumentParser(description="ZMax Server dağıtım paketlerini doğrular.")
    parser.add_argument("--root", default=DEFAULT_ROOT, help="ZMax Server kök dizini")
    parser.add_argument("--version", default=DEFAULT_VERSION, help="Paket sürümü (varsayılan: 1.0.01)")
    parser.add_argument("--release", default=DEFAULT_RELEASE, help="RPM sürüm numarası (varsayılan: 1)")
    parser.add_argument("--allow-missing", action="store_true", help="Diskte olmayan paketleri atla")
    return parser.parse_args()


def main():
    args = parse_args()
    packed = os.path.join(os.path.abspath(args.root), "packed")
    v = args.version
    r = args.release

    checks = [
        (os.path.join(packed, f"zmax-server-v{v}-windows-x64.zip"), inspect_zip),
        (os.path.join(packed, f"zmax-server-v{v}-linux-x64.tar.gz"), inspect_targz),
        (os.path.join(packed, f"zmax-server-v{v}-linux-arm64.tar.gz"), inspect_targz),
        (os.path.join(packed, "deb", f"zmax-server_{v}_amd64.deb"), inspect_deb),
        (os.path.join(packed, "deb", f"zmax-server_{v}_arm64.deb"), inspect_deb),
        (os.path.join(packed, "rpm", f"zmax-server-{v}-{r}.x86_64.rpm"), inspect_rpm),
        (os.path.join(packed, "rpm", f"zmax-server-{v}-{r}.aarch64.rpm"), inspect_rpm),
    ]

    verified = 0
    for pkg_path, fn in checks:
        if not os.path.exists(pkg_path):
            if args.allow_missing:
                print(f"[ATLANDI] Bulunamadı: {os.path.relpath(pkg_path, packed)}")
                continue
            raise FileNotFoundError(f"Beklenen paket bulunamadı: {pkg_path}")
        fn(pkg_path)
        verified += 1

    if verified == 0:
        print("[HATA] Doğrulanacak hiçbir paket bulunamadı.", file=sys.stderr)
        sys.exit(1)

    print(f"TUM PAKET KONTROLLERI BASARILI ({verified} paket doğrulandı).")


if __name__ == "__main__":
    main()
