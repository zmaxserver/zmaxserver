#!/usr/bin/env python3
"""ZMax Server dağıtım paketlerinin (.zip, .tar.gz, .deb, .rpm) iç yapısını inceleme aracı."""

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


def inspect_zip(path):
    with zipfile.ZipFile(path, "r") as zf:
        return sorted([(i.filename, i.file_size, "DIR" if i.is_dir() else "FILE") for i in zf.infolist()])


def inspect_targz(path):
    with tarfile.open(path, "r:gz") as tf:
        rows = []
        for m in tf.getmembers():
            kind = "DIR" if m.isdir() else ("LINK" if m.issym() else "FILE")
            rows.append((m.name, m.size, kind, oct(m.mode & 0o7777)))
        return sorted(rows)


def inspect_deb(path):
    with open(path, "rb") as f:
        data = f.read()
    if not data.startswith(b"!<arch>\n"):
        raise ValueError(f"Geçersiz DEB ar başlığı: {path}")
    pos = 8
    parts = {}
    while pos + 60 <= len(data):
        hdr = data[pos:pos + 60]
        name = hdr[:16].decode("ascii", errors="replace").strip()
        size = int(hdr[48:58].decode("ascii", errors="replace").strip())
        pos += 60
        parts[name] = data[pos:pos + size]
        pos += size + (size % 2)

    res = {}
    for k, v in parts.items():
        if k.startswith("data.tar"):
            mode = "r:gz" if k.endswith(".gz") else ("r:xz" if k.endswith(".xz") else "r:*")
            with tarfile.open(fileobj=io.BytesIO(v), mode=mode) as tf:
                res["data"] = sorted([
                    (m.name, m.size, "DIR" if m.isdir() else ("LINK" if m.issym() else "FILE"), oct(m.mode & 0o7777))
                    for m in tf.getmembers()
                ])
        elif k.startswith("control.tar"):
            mode = "r:gz" if k.endswith(".gz") else ("r:xz" if k.endswith(".xz") else "r:*")
            with tarfile.open(fileobj=io.BytesIO(v), mode=mode) as tf:
                res["control"] = sorted([(m.name, m.size) for m in tf.getmembers()])
    return res


def inspect_rpm(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\xed\xab\xee\xdb":
        raise ValueError(f"Geçersiz RPM sihirli başlığı: {path}")
    gz_idx = data.find(b"\x1f\x8b\x08", 96)
    if gz_idx == -1:
        raise ValueError(f"RPM içinde gzip yük bulunamadı: {path}")
    cpio = gzip.decompress(data[gz_idx:])
    pos = 0
    entries = []
    while pos + 110 <= len(cpio):
        magic = cpio[pos:pos + 6]
        if magic not in (b"070701", b"070702"):
            raise ValueError(f"Geçersiz CPIO magic ({magic!r}) konum={pos}: {path}")
        mode = int(cpio[pos + 14:pos + 22], 16)
        filesize = int(cpio[pos + 54:pos + 62], 16)
        namesize = int(cpio[pos + 94:pos + 102], 16)
        name_start = pos + 110
        name_end = name_start + namesize
        name = cpio[name_start:name_end].rstrip(b"\x00").decode("utf-8", errors="replace")
        pos = (name_end + 3) & ~3
        if name == "TRAILER!!!":
            break
        ftype_bits = mode & 0o170000
        if ftype_bits == 0o040000:
            kind = "DIR"
        elif ftype_bits == 0o120000:
            kind = "LINK"
        else:
            kind = "FILE"
        entries.append((name, filesize, kind, oct(mode & 0o7777)))
        pos = ((pos + filesize) + 3) & ~3
    return len(data), len(cpio), sorted(entries)


def print_zip(path):
    rows = inspect_zip(path)
    print(f"=== ZIP: {os.path.basename(path)} ({len(rows)} öğe) ===")
    for name, sz, kind in rows:
        print(f"  {kind:4} {sz:>9} B  {name}")


def print_targz(path):
    rows = inspect_targz(path)
    print(f"=== TAR.GZ: {os.path.basename(path)} ({len(rows)} öğe) ===")
    for name, sz, kind, mode in rows:
        print(f"  {kind:4} {mode:6} {sz:>9} B  {name}")


def print_deb(path):
    info = inspect_deb(path)
    print(f"=== DEB: {os.path.basename(path)} ===")
    print("  CONTROL:", info.get("control"))
    for name, sz, kind, mode in info.get("data", []):
        print(f"  {kind:4} {mode:6} {sz:>9} B  {name}")


def print_rpm(path):
    total_sz, payload_sz, entries = inspect_rpm(path)
    print(f"=== RPM: {os.path.basename(path)} ({total_sz} B, payload={payload_sz} B, {len(entries)} öğe) ===")
    for name, sz, kind, mode in entries:
        print(f"  {kind:4} {mode:6} {sz:>9} B  {name}")


def inspect_file(path):
    lower = path.lower()
    if lower.endswith(".zip"):
        print_zip(path)
    elif lower.endswith(".tar.gz") or lower.endswith(".tgz"):
        print_targz(path)
    elif lower.endswith(".deb"):
        print_deb(path)
    elif lower.endswith(".rpm"):
        print_rpm(path)
    else:
        raise ValueError(f"Desteklenmeyen paket uzantısı: {path}")


def parse_args():
    parser = argparse.ArgumentParser(description="ZMax Server dağıtım paketlerinin içeriğini inceler.")
    parser.add_argument("--root", default=DEFAULT_ROOT, help="ZMax Server kök dizini")
    parser.add_argument("--version", default=DEFAULT_VERSION, help="Paket sürümü (varsayılan: 1.0.01)")
    parser.add_argument("--release", default=DEFAULT_RELEASE, help="RPM sürüm numarası (varsayılan: 1)")
    parser.add_argument(
        "--format",
        choices=("all", "zip", "tar", "deb", "rpm"),
        default="all",
        help="İncelenecek paket türü (varsayılan: all)",
    )
    parser.add_argument("--file", default=None, help="Doğrudan incelenecek tek paket dosyası yolu")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.file:
        if not os.path.exists(args.file):
            print(f"[HATA] Dosya bulunamadı: {args.file}", file=sys.stderr)
            sys.exit(1)
        inspect_file(args.file)
        return

    packed = os.path.join(os.path.abspath(args.root), "packed")
    v = args.version
    r = args.release

    groups = {
        "zip": [os.path.join(packed, f"zmax-server-v{v}-windows-x64.zip")],
        "tar": [
            os.path.join(packed, f"zmax-server-v{v}-linux-x64.tar.gz"),
            os.path.join(packed, f"zmax-server-v{v}-linux-arm64.tar.gz"),
        ],
        "deb": [
            os.path.join(packed, "deb", f"zmax-server_{v}_amd64.deb"),
            os.path.join(packed, "deb", f"zmax-server_{v}_arm64.deb"),
        ],
        "rpm": [
            os.path.join(packed, "rpm", f"zmax-server-{v}-{r}.x86_64.rpm"),
            os.path.join(packed, "rpm", f"zmax-server-{v}-{r}.aarch64.rpm"),
        ],
    }

    selected = list(groups.keys()) if args.format == "all" else [args.format]
    inspected = 0
    for fmt in selected:
        for pkg in groups[fmt]:
            if os.path.exists(pkg):
                inspect_file(pkg)
                inspected += 1
            else:
                print(f"[ATLANDI] Bulunamadı: {pkg}")

    if inspected == 0:
        print("[HATA] İncelenecek hiçbir paket bulunamadı.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
