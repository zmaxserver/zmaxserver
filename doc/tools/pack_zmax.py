#!/usr/bin/env python3
"""ZMax Server kurumsal dağıtım paket üreticisi (.zip, .tar.gz, .deb, .rpm, SHA256SUMS.txt)."""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_ROOT = os.path.abspath(os.path.join(TOOLS_DIR, "..", ".."))
DEFAULT_VERSION = "1.0.01"
DEFAULT_RELEASE = "1"
LEGACY_NFPM_PATH = r"D:\lunixpanel\zpanel-tam\araclar\nfpm\nfpm.exe"


def find_nfpm_executable(explicit_path=None):
    """Sistemde nfpm yürütülebilir dosyasını birden fazla olası konumda arar."""
    candidates = []
    if explicit_path:
        candidates.append(explicit_path)

    env_nfpm = os.environ.get("NFPM_EXE", "").strip()
    if env_nfpm:
        candidates.append(env_nfpm)

    candidates.extend([
        os.path.join(TOOLS_DIR, "nfpm.exe"),
        os.path.join(TOOLS_DIR, "nfpm"),
    ])

    for cmd in ("nfpm", "nfpm.exe"):
        found = shutil.which(cmd)
        if found:
            candidates.append(found)

    candidates.append(LEGACY_NFPM_PATH)

    local_app = os.environ.get("LOCALAPPDATA", "")
    user_prof = os.environ.get("USERPROFILE", "")
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    if local_app:
        candidates.append(os.path.join(local_app, "Microsoft", "WinGet", "Links", "nfpm.exe"))
    if user_prof:
        candidates.append(os.path.join(user_prof, "scoop", "shims", "nfpm.exe"))
    if program_data:
        candidates.append(os.path.join(program_data, "chocolatey", "bin", "nfpm.exe"))

    checked = []
    for path in candidates:
        if not path:
            continue
        norm = os.path.normpath(path)
        if norm not in checked:
            checked.append(norm)
        if os.path.isfile(norm):
            return norm

    searched_list = "\n  - ".join(checked)
    raise FileNotFoundError(
        "nfpm aracı bulunamadı! RPM paket üretimi için nfpm gereklidir.\n"
        f"Aranan konumlar:\n  - {searched_list}\n"
        "Çözüm:\n"
        "  1) WinGet ile kurun: winget install goreleaser.nfpm\n"
        "  2) veya nfpm.exe dosyasını D:\\zmaxserver\\doc\\tools\\nfpm.exe konumuna kopyalayın\n"
        "  3) veya NFPM_EXE ortam değişkeni / --nfpm parametresi ile yol belirtin\n"
        "  4) RPM paketini atlamak için --skip-rpm bayrağını kullanın."
    )


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_lf(path):
    with open(path, "rb") as f:
        data = f.read()
    new_data = data.replace(b"\r\n", b"\n")
    if new_data != data:
        with open(path, "wb") as f:
            f.write(new_data)


def copy_if_changed(src, dst):
    if os.path.exists(dst) and file_sha256(src) == file_sha256(dst):
        return
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)


def sync_admin(root_dir, target_admin):
    if os.path.exists(target_admin):
        shutil.rmtree(target_admin)
    shutil.copytree(os.path.join(root_dir, "admin"), target_admin)
    for stale in (
        os.path.join(target_admin, "css", "admin.css"),
        os.path.join(target_admin, "js", "app.js"),
    ):
        if os.path.exists(stale):
            os.remove(stale)


def sync_tree_files(src_dir, dst_dir, lf_normalize=False):
    os.makedirs(dst_dir, exist_ok=True)
    lf_exts = (".toml", ".types", ".conf", ".html", ".php", ".sh", ".service", ".js", ".css", ".svg")
    for root_dir, _, files in os.walk(src_dir):
        rel = os.path.relpath(root_dir, src_dir)
        out_dir = dst_dir if rel == "." else os.path.join(dst_dir, rel)
        os.makedirs(out_dir, exist_ok=True)
        for fn in files:
            src_f = os.path.join(root_dir, fn)
            dst_f = os.path.join(out_dir, fn)
            copy_if_changed(src_f, dst_f)
            if lf_normalize and (fn.endswith(lf_exts) or fn == "zmaxctrl"):
                normalize_lf(dst_f)


def sync_common_dirs(root_dir, target_root, lf_normalize=False):
    for d in ("bin", "conf", "conf/vhosts", "modules", "www", "www/html", "www/php", "fcgi-bin", "logs", "cachedata"):
        os.makedirs(os.path.join(target_root, d), exist_ok=True)
    for sub in ("conf", "modules", "fcgi-bin", "www"):
        sync_tree_files(os.path.join(root_dir, sub), os.path.join(target_root, sub), lf_normalize=lf_normalize)
    sync_admin(root_dir, os.path.join(target_root, "admin"))
    if lf_normalize:
        sync_tree_files(os.path.join(target_root, "admin"), os.path.join(target_root, "admin"), lf_normalize=True)


def reset_runtime_dirs(target_root):
    for clean_dir in ("logs", "cachedata"):
        p_clean = os.path.join(target_root, clean_dir)
        if os.path.exists(p_clean):
            shutil.rmtree(p_clean)
        os.makedirs(p_clean, exist_ok=True)


def stage_linux_dir(root_dir, packed_dir, target_dir, bin_src, fallback_dir=None):
    sync_common_dirs(root_dir, target_dir, lf_normalize=True)
    copy_if_changed(bin_src, os.path.join(target_dir, "bin", "zmax"))

    if fallback_dir and os.path.isdir(fallback_dir):
        for rel in ("bin/zmaxctrl", "install.sh", "systemd/zmax.service"):
            src_f = os.path.join(fallback_dir, rel)
            dst_f = os.path.join(target_dir, rel)
            if os.path.exists(src_f) and not os.path.exists(dst_f):
                copy_if_changed(src_f, dst_f)

    svc_deb = os.path.join(packed_dir, "deb", "zmax.service")
    if os.path.exists(svc_deb):
        os.makedirs(os.path.join(target_dir, "systemd"), exist_ok=True)
        copy_if_changed(svc_deb, os.path.join(target_dir, "systemd", "zmax.service"))

    reset_runtime_dirs(target_dir)
    for lf_file in (
        os.path.join(target_dir, "bin", "zmaxctrl"),
        os.path.join(target_dir, "install.sh"),
        os.path.join(target_dir, "systemd", "zmax.service"),
    ):
        if os.path.exists(lf_file):
            normalize_lf(lf_file)


def build_zip(packed_dir, src_dir, zip_path):
    if os.path.exists(zip_path):
        os.remove(zip_path)
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for empty_dir in ("logs", "cachedata"):
            arc_dir = os.path.relpath(os.path.join(src_dir, empty_dir), packed_dir).replace("\\", "/") + "/"
            zf.writestr(arc_dir, b"")
        for root_dir, dirs, files in os.walk(src_dir):
            rel = os.path.relpath(root_dir, src_dir).replace("\\", "/")
            if rel in ("logs", "cachedata") or rel.startswith("logs/") or rel.startswith("cachedata/"):
                continue
            if not files and not dirs:
                arc_dir = os.path.relpath(root_dir, packed_dir).replace("\\", "/") + "/"
                zf.writestr(arc_dir, b"")
            for fn in sorted(files):
                full = os.path.join(root_dir, fn)
                arc = os.path.relpath(full, packed_dir).replace("\\", "/")
                zf.write(full, arc)


def tarinfo_filter(ti, exec_names=("zmax", "zmaxctrl", "install.sh", "postinst", "prerm")):
    ti.uid = 0
    ti.gid = 0
    ti.uname = "root"
    ti.gname = "root"
    base = os.path.basename(ti.name)
    if ti.isdir():
        ti.mode = 0o755
    elif base in exec_names or ti.name.endswith(".sh"):
        ti.mode = 0o755
    else:
        ti.mode = 0o644
    return ti


def build_targz(src_dir, targz_path, arc_prefix):
    if os.path.exists(targz_path):
        os.remove(targz_path)
    os.makedirs(os.path.dirname(targz_path), exist_ok=True)
    with tarfile.open(targz_path, "w:gz", compresslevel=9) as tf:
        for root_dir, _, files in os.walk(src_dir):
            rel_dir = os.path.relpath(root_dir, src_dir).replace(os.sep, "/")
            arc_dir = arc_prefix if rel_dir == "." else f"{arc_prefix}/{rel_dir}"
            di = tarfile.TarInfo(name=arc_dir)
            di.type = tarfile.DIRTYPE
            di.mtime = int(time.time())
            tf.addfile(tarinfo_filter(di))
            if rel_dir in ("logs", "cachedata") or rel_dir.startswith("logs/") or rel_dir.startswith("cachedata/"):
                continue
            for fn in sorted(files):
                full = os.path.join(root_dir, fn)
                arc = f"{arc_dir}/{fn}"
                tf.add(full, arcname=arc, filter=tarinfo_filter)


def make_ar_member(name, data):
    now = int(time.time())
    header = f"{name:<16}{now:<12}0     0     100644  {len(data):<10}`\n".encode("ascii")
    if len(header) != 60:
        raise ValueError(f"Geçersiz ar başlık uzunluğu: {len(header)}")
    pad = b"\n" if (len(data) % 2 == 1) else b""
    return header + data + pad


def build_deb(src_dir, arch, version, deb_path):
    if os.path.exists(deb_path):
        os.remove(deb_path)
    os.makedirs(os.path.dirname(deb_path), exist_ok=True)

    now = int(time.time())
    dir_set = {
        "./etc",
        "./etc/systemd",
        "./etc/systemd/system",
        "./usr",
        "./usr/local",
        "./usr/local/bin",
        "./usr/local/zmax",
        "./usr/local/zmax/logs",
        "./usr/local/zmax/cachedata",
    }
    file_items = []
    conffiles = []
    md5_lines = []
    total_bytes = 0

    for root_dir, dirs, files in os.walk(src_dir):
        rel_dir = os.path.relpath(root_dir, src_dir).replace(os.sep, "/")
        if rel_dir == "systemd" or rel_dir.startswith("systemd/"):
            continue
        dst_dir = "./usr/local/zmax" if rel_dir == "." else f"./usr/local/zmax/{rel_dir}"
        dir_set.add(dst_dir)
        for d in dirs:
            if rel_dir == "." and d == "systemd":
                continue
            dir_set.add(f"{dst_dir}/{d}")
        if rel_dir in ("logs", "cachedata") or rel_dir.startswith("logs/") or rel_dir.startswith("cachedata/"):
            continue
        for fn in sorted(files):
            if rel_dir == "." and fn == "install.sh":
                continue
            full = os.path.join(root_dir, fn)
            arc = f"{dst_dir}/{fn}"
            file_items.append((full, arc))
            sz = os.path.getsize(full)
            total_bytes += sz
            h = hashlib.md5()
            with open(full, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            deb_rel = arc[2:]
            md5_lines.append(f"{h.hexdigest()}  {deb_rel}")
            if rel_dir.startswith("conf") or rel_dir.startswith("modules") or rel_dir.startswith("fcgi-bin"):
                conffiles.append("/" + deb_rel)

    svc_full = os.path.join(src_dir, "systemd", "zmax.service")
    if os.path.exists(svc_full):
        file_items.append((svc_full, "./etc/systemd/system/zmax.service"))
        total_bytes += os.path.getsize(svc_full)
        h = hashlib.md5()
        with open(svc_full, "rb") as fh:
            h.update(fh.read())
        md5_lines.append(f"{h.hexdigest()}  etc/systemd/system/zmax.service")

    installed_kb = max(1, (total_bytes + 1023) // 1024)
    control_txt = (
        f"Package: zmax-server\n"
        f"Version: {version}\n"
        f"Section: httpd\n"
        f"Priority: optional\n"
        f"Architecture: {arch}\n"
        f"Installed-Size: {installed_kb}\n"
        f"Maintainer: ZePanel Team <info@zepanel.com>\n"
        f"Homepage: https://zepanel.com\n"
        f"Suggests: php-fpm, ca-certificates\n"
        f"Description: ZMax Server v{version} - ZePanel High-Speed Rust Web Engine\n"
        f" Standalone ultra-low memory Rust HTTP engine with Bootstrap 5 WebAdmin,\n"
        f" universal REST Control API (/api/v1/* on port 19486) and FastCGI/LSCache.\n"
    ).encode("utf-8")

    conffiles_txt = ("\n".join(sorted(conffiles)) + "\n").encode("utf-8")
    md5sums_txt = ("\n".join(sorted(md5_lines)) + "\n").encode("utf-8")

    postinst_txt = (
        "#!/bin/sh\n"
        "set -e\n"
        "mkdir -p /usr/local/zmax/logs /usr/local/zmax/cachedata\n"
        "if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n"
        "    systemctl daemon-reload >/dev/null 2>&1 || true\n"
        "    systemctl enable zmax.service >/dev/null 2>&1 || true\n"
        "fi\n"
        "exit 0\n"
    ).encode("utf-8")

    prerm_txt = (
        "#!/bin/sh\n"
        "set -e\n"
        "if [ \"$1\" = \"remove\" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n"
        "    systemctl disable --now zmax.service >/dev/null 2>&1 || true\n"
        "fi\n"
        "exit 0\n"
    ).encode("utf-8")

    postrm_txt = (
        "#!/bin/sh\n"
        "set -e\n"
        "if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then\n"
        "    systemctl daemon-reload >/dev/null 2>&1 || true\n"
        "fi\n"
        "exit 0\n"
    ).encode("utf-8")

    ctrl_buf = io.BytesIO()
    with tarfile.open(fileobj=ctrl_buf, mode="w:gz") as tf:
        ctrl_members = [
            ("./control", control_txt, 0o644),
            ("./conffiles", conffiles_txt, 0o644),
            ("./md5sums", md5sums_txt, 0o644),
            ("./postinst", postinst_txt, 0o755),
            ("./prerm", prerm_txt, 0o755),
            ("./postrm", postrm_txt, 0o755),
        ]
        for name, content, mode in ctrl_members:
            ti = tarfile.TarInfo(name=name)
            ti.size = len(content)
            ti.mode = mode
            ti.uid = 0
            ti.gid = 0
            ti.uname = "root"
            ti.gname = "root"
            ti.mtime = now
            tf.addfile(ti, io.BytesIO(content))

    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz") as tf:
        for d in sorted(dir_set):
            di = tarfile.TarInfo(name=d)
            di.type = tarfile.DIRTYPE
            di.mode = 0o755
            di.uid = 0
            di.gid = 0
            di.uname = "root"
            di.gname = "root"
            di.mtime = now
            tf.addfile(di)
        for full, arc in sorted(file_items, key=lambda x: x[1]):
            tf.add(full, arcname=arc, filter=tarinfo_filter)
        for link_arc, link_target in (
            ("./usr/local/bin/zmax", "/usr/local/zmax/bin/zmax"),
            ("./usr/local/bin/zmaxctrl", "/usr/local/zmax/bin/zmaxctrl"),
        ):
            si = tarfile.TarInfo(name=link_arc)
            si.type = tarfile.SYMTYPE
            si.linkname = link_target
            si.mode = 0o777
            si.uid = 0
            si.gid = 0
            si.uname = "root"
            si.gname = "root"
            si.mtime = now
            tf.addfile(si)

    deb_bytes = (
        b"!<arch>\n"
        + make_ar_member("debian-binary", b"2.0\n")
        + make_ar_member("control.tar.gz", ctrl_buf.getvalue())
        + make_ar_member("data.tar.gz", data_buf.getvalue())
    )
    with open(deb_path, "wb") as f:
        f.write(deb_bytes)


def build_rpm(nfpm_exe, src_dir, nfpm_arch, version, release, rpm_path):
    if os.path.exists(rpm_path):
        os.remove(rpm_path)
    os.makedirs(os.path.dirname(rpm_path), exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        postinst = os.path.join(tmp, "postinstall.sh")
        prerm = os.path.join(tmp, "preremove.sh")
        postrm = os.path.join(tmp, "postremove.sh")
        cfg_path = os.path.join(tmp, f"nfpm-{nfpm_arch}.yaml")

        with open(postinst, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "#!/bin/sh\n"
                "set -e\n"
                "if command -v systemctl >/dev/null 2>&1; then\n"
                "    systemctl daemon-reload >/dev/null 2>&1 || true\n"
                "    systemctl enable zmax.service >/dev/null 2>&1 || true\n"
                "fi\n"
                "exit 0\n"
            )
        with open(prerm, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "#!/bin/sh\n"
                "set -e\n"
                "if [ \"$1\" = \"0\" ] && command -v systemctl >/dev/null 2>&1; then\n"
                "    systemctl disable --now zmax.service >/dev/null 2>&1 || true\n"
                "fi\n"
                "exit 0\n"
            )
        with open(postrm, "w", encoding="utf-8", newline="\n") as f:
            f.write(
                "#!/bin/sh\n"
                "set -e\n"
                "if [ \"$1\" = \"0\" ] && command -v systemctl >/dev/null 2>&1; then\n"
                "    systemctl daemon-reload >/dev/null 2>&1 || true\n"
                "fi\n"
                "exit 0\n"
            )

        lines = [
            "name: zmax-server",
            f"arch: {nfpm_arch}",
            "platform: linux",
            f"version: {version}",
            "version_schema: none",
            f"release: '{release}'",
            "section: httpd",
            "priority: optional",
            "maintainer: ZePanel Team <info@zepanel.com>",
            "vendor: ZePanel",
            "homepage: https://zepanel.com",
            "license: MIT OR Apache-2.0",
            f'description: "ZMax Server v{version} - ZePanel High-Speed Rust Web Engine for AlmaLinux/RHEL/Rocky"',
            "umask: 0o022",
            "contents:",
        ]

        dir_set = {"/usr/local/zmax"}
        file_entries = []
        for root_dir, dirs, files in os.walk(src_dir):
            rel_dir = os.path.relpath(root_dir, src_dir).replace(os.sep, "/")
            if rel_dir == "systemd":
                continue
            dst_dir = "/usr/local/zmax" if rel_dir == "." else f"/usr/local/zmax/{rel_dir}"
            dir_set.add(dst_dir)
            for d in dirs:
                if rel_dir == "." and d == "systemd":
                    continue
                dir_set.add(f"{dst_dir}/{d}")
            if rel_dir in ("logs", "cachedata") or rel_dir.startswith("logs/") or rel_dir.startswith("cachedata/"):
                continue
            for fn in sorted(files):
                if rel_dir == "." and fn == "install.sh":
                    continue
                full = os.path.join(root_dir, fn)
                dst = f"{dst_dir}/{fn}"
                is_exec = fn in ("zmax", "zmaxctrl") or fn.endswith(".sh")
                is_cfg = rel_dir.startswith("conf") or rel_dir.startswith("modules") or rel_dir.startswith("fcgi-bin")
                mode = "0755" if is_exec else "0644"
                file_entries.append((full, dst, mode, is_cfg))

        for d in sorted(dir_set):
            lines += [
                f"  - dst: {json.dumps(d)}",
                "    type: dir",
                "    file_info:",
                "      mode: 0755",
                "      owner: root",
                "      group: root",
            ]

        for full, dst, mode, is_cfg in sorted(file_entries, key=lambda x: x[1]):
            lines += [f"  - src: {json.dumps(full)}", f"    dst: {json.dumps(dst)}"]
            if is_cfg:
                lines.append("    type: config|noreplace")
            lines += ["    file_info:", f"      mode: {mode}", "      owner: root", "      group: root"]

        svc_src = os.path.join(src_dir, "systemd", "zmax.service")
        lines += [
            f"  - src: {json.dumps(svc_src)}",
            "    dst: /usr/lib/systemd/system/zmax.service",
            "    file_info:",
            "      mode: 0644",
            "      owner: root",
            "      group: root",
            "  - src: /usr/local/zmax/bin/zmax",
            "    dst: /usr/local/bin/zmax",
            "    type: symlink",
            "  - src: /usr/local/zmax/bin/zmaxctrl",
            "    dst: /usr/local/bin/zmaxctrl",
            "    type: symlink",
            "scripts:",
            f"  postinstall: {json.dumps(postinst)}",
            f"  preremove: {json.dumps(prerm)}",
            f"  postremove: {json.dumps(postrm)}",
            "overrides:",
            "  rpm:",
            "    depends:",
            "      - bash",
            "      - systemd",
            "      - ca-certificates",
            "rpm:",
            "  compression: gzip",
        ]

        with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

        subprocess.run(
            [nfpm_exe, "package", "--config", cfg_path, "--packager", "rpm", "--target", rpm_path],
            check=True,
        )


def parse_args():
    parser = argparse.ArgumentParser(description="ZMax Server tüm platform paketlerini üretir.")
    parser.add_argument("--root", default=DEFAULT_ROOT, help="ZMax Server kök dizini (varsayılan: D:\\zmaxserver)")
    parser.add_argument("--version", default=DEFAULT_VERSION, help="Paket sürümü (varsayılan: 1.0.01)")
    parser.add_argument("--release", default=DEFAULT_RELEASE, help="RPM sürüm numarası (varsayılan: 1)")
    parser.add_argument(
        "--target",
        choices=("all", "win", "linux-x64", "linux-arm64"),
        default="all",
        help="Üretilecek hedef platform (varsayılan: all)",
    )
    parser.add_argument("--nfpm", default=None, help="nfpm yürütülebilir dosyasının tam yolu")
    parser.add_argument("--skip-rpm", action="store_true", help="RPM üretimini atla")
    parser.add_argument(
        "--require-all",
        action="store_true",
        help="--target all seçiliyken eksik hedef binary varsa hata ile çık",
    )
    return parser.parse_args()


def write_checksums(packed_dir, artifacts, version, release, partial_mode):
    known_rels = [
        f"zmax-server-v{version}-windows-x64.zip",
        f"zmax-server-v{version}-linux-x64.tar.gz",
        f"deb/zmax-server_{version}_amd64.deb",
        f"rpm/zmax-server-{version}-{release}.x86_64.rpm",
        f"zmax-server-v{version}-linux-arm64.tar.gz",
        f"deb/zmax-server_{version}_arm64.deb",
        f"rpm/zmax-server-{version}-{release}.aarch64.rpm",
    ]
    if partial_mode:
        targets = [os.path.join(packed_dir, rel) for rel in known_rels if os.path.exists(os.path.join(packed_dir, rel))]
    else:
        targets = artifacts

    sums_lines = []
    for p in targets:
        rel = os.path.relpath(p, packed_dir).replace("\\", "/")
        size = os.path.getsize(p)
        digest = file_sha256(p)
        sums_lines.append(f"{digest}  {rel}  ({size} bytes)")
        if p in artifacts:
            print(f"PACKED: {rel} -> {size} bytes | sha256={digest[:16]}...")

    with open(os.path.join(packed_dir, "SHA256SUMS.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sums_lines) + "\n")


def main():
    args = parse_args()
    root = os.path.abspath(args.root)
    packed = os.path.join(root, "packed")
    version = args.version
    release = args.release

    win_bin = os.path.join(root, "target", "release", "zmax.exe")
    lin_x64_bin = os.path.join(root, "target", "x86_64-unknown-linux-musl", "release", "zmax")
    lin_arm64_bin = os.path.join(root, "target", "aarch64-unknown-linux-musl", "release", "zmax")

    win_dir = os.path.join(packed, "win")
    lin_x64_dir = os.path.join(packed, "linux-x64")
    lin_arm64_dir = os.path.join(packed, "linux-arm64")

    want_win = args.target in ("all", "win")
    want_x64 = args.target in ("all", "linux-x64")
    want_arm64 = args.target in ("all", "linux-arm64")

    if args.target != "all":
        req_map = {
            "win": (win_bin, "cargo build --release"),
            "linux-x64": (lin_x64_bin, "cargo build --release --target x86_64-unknown-linux-musl"),
            "linux-arm64": (lin_arm64_bin, "cargo build --release --target aarch64-unknown-linux-musl"),
        }
        bin_path, build_cmd = req_map[args.target]
        if not os.path.exists(bin_path):
            print(f"[HATA] Hedef binary bulunamadı: {bin_path}", file=sys.stderr)
            print(f"       Önce şu komutu çalıştırın: {build_cmd}", file=sys.stderr)
            sys.exit(1)
    elif args.require_all:
        missing = [p for p in (win_bin, lin_x64_bin, lin_arm64_bin) if not os.path.exists(p)]
        if missing:
            print("[HATA] --require-all etkin ancak aşağıdaki binary dosyaları eksik:", file=sys.stderr)
            for m in missing:
                print(f"  - {m}", file=sys.stderr)
            sys.exit(1)

    has_linux_build = (want_x64 and os.path.exists(lin_x64_bin)) or (want_arm64 and os.path.exists(lin_arm64_bin))
    nfpm_exe = None
    if has_linux_build and not args.skip_rpm:
        nfpm_exe = find_nfpm_executable(args.nfpm)
        print(f"[INFO] Kullanılan nfpm: {nfpm_exe}")

    old_zip = os.path.join(packed, "zmax-server-v1.0.0-windows-x64.zip")
    if os.path.exists(old_zip):
        os.remove(old_zip)

    artifacts = []

    if want_win:
        if os.path.exists(win_bin):
            sync_common_dirs(root, win_dir)
            copy_if_changed(win_bin, os.path.join(win_dir, "bin", "zmax.exe"))
            copy_if_changed(win_bin, os.path.join(root, "bin", "zmax.exe"))
            zmaxctrl_bat = os.path.join(root, "bin", "zmaxctrl.bat")
            if os.path.exists(zmaxctrl_bat):
                copy_if_changed(zmaxctrl_bat, os.path.join(win_dir, "bin", "zmaxctrl.bat"))
            win_zip = os.path.join(packed, f"zmax-server-v{version}-windows-x64.zip")
            build_zip(packed, win_dir, win_zip)
            artifacts.append(win_zip)
        else:
            print(f"[ATLANDI] Windows binary bulunamadı: {win_bin}")

    if want_x64:
        if os.path.exists(lin_x64_bin):
            stage_linux_dir(root, packed, lin_x64_dir, lin_x64_bin, fallback_dir=lin_arm64_dir)
            lin_x64_tgz = os.path.join(packed, f"zmax-server-v{version}-linux-x64.tar.gz")
            build_targz(lin_x64_dir, lin_x64_tgz, f"zmax-server-v{version}-linux-x64")
            artifacts.append(lin_x64_tgz)

            deb_amd64 = os.path.join(packed, "deb", f"zmax-server_{version}_amd64.deb")
            build_deb(lin_x64_dir, "amd64", version, deb_amd64)
            artifacts.append(deb_amd64)

            if nfpm_exe:
                rpm_x64 = os.path.join(packed, "rpm", f"zmax-server-{version}-{release}.x86_64.rpm")
                build_rpm(nfpm_exe, lin_x64_dir, "amd64", version, release, rpm_x64)
                artifacts.append(rpm_x64)
        else:
            print(f"[ATLANDI] Linux x64 binary bulunamadı: {lin_x64_bin}")

    if want_arm64:
        if os.path.exists(lin_arm64_bin):
            stage_linux_dir(root, packed, lin_arm64_dir, lin_arm64_bin, fallback_dir=lin_x64_dir)
            lin_arm64_tgz = os.path.join(packed, f"zmax-server-v{version}-linux-arm64.tar.gz")
            build_targz(lin_arm64_dir, lin_arm64_tgz, f"zmax-server-v{version}-linux-arm64")
            artifacts.append(lin_arm64_tgz)

            deb_arm64 = os.path.join(packed, "deb", f"zmax-server_{version}_arm64.deb")
            build_deb(lin_arm64_dir, "arm64", version, deb_arm64)
            artifacts.append(deb_arm64)

            if nfpm_exe:
                rpm_arm64 = os.path.join(packed, "rpm", f"zmax-server-{version}-{release}.aarch64.rpm")
                build_rpm(nfpm_exe, lin_arm64_dir, "arm64", version, release, rpm_arm64)
                artifacts.append(rpm_arm64)
        else:
            print(f"[ATLANDI] Linux ARM64 binary bulunamadı: {lin_arm64_bin}")

    if not artifacts:
        print("[HATA] Hiçbir hedef binary bulunamadığı için paket üretilemedi.", file=sys.stderr)
        sys.exit(1)

    write_checksums(packed, artifacts, version, release, partial_mode=(args.target != "all"))
    print(f"[OK] Toplam {len(artifacts)} paket üretildi -> {packed}")


if __name__ == "__main__":
    main()
