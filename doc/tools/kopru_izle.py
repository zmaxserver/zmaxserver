#!/usr/bin/env python3
"""ZMax köprü izleyici: yapay zeka (BITTI.md) <-> denetçi (DUZELTMELER.md) otomatik bildirim.

Her 5 sn'de iki dosyayı kontrol eder; içerik değişince tek satır yazar (stdout).
Denetçi (Claude) bu çıktıyı Monitor ile okur ve bildirim olarak alır.
Yalnız standart kütüphane. Dosyaları DEĞİŞTİRMEZ, yalnız okur.

Kullanım: python kopru_izle.py [aralik_sn]
"""
from __future__ import annotations

import hashlib
import re
import sys
import time
from pathlib import Path

DOC = Path(__file__).resolve().parent.parent
BITTI = DOC / "BITTI.md"
DUZ = DOC / "DUZELTMELER.md"
BITTI_DIR = DOC / "bitti"
ARALIK = float(sys.argv[1]) if len(sys.argv) > 1 else 5.0
SABLON_ISARET = "<!-- Yapay zeka: raporunu bu satırın ALTINA ekle. -->"


def oku(yol: Path) -> str | None:
    try:
        return yol.read_text(encoding="utf-8")
    except OSError:
        return None


def ozet_hash(metin: str | None) -> str | None:
    return hashlib.sha256(metin.encode("utf-8")).hexdigest() if metin is not None else None


def bitti_ozeti(metin: str | None) -> str:
    """BITTI.md: şablon işaretinden sonraki raporlar; son 'Kart' başlığı ve rapor satır sayısı."""
    if metin is None:
        return "dosya yok"
    _, _, sonrasi = metin.partition(SABLON_ISARET)
    rapor = sonrasi.strip()
    if not rapor:
        return "rapor YOK (yalnız şablon)"
    basliklar = re.findall(r"^## (Kart[^\n]*)", sonrasi, flags=re.M)
    son = basliklar[-1].strip() if basliklar else "(başlık yok)"
    return f"{len(basliklar)} rapor bölümü, son: {son} ({len(rapor.splitlines())} satır)"


def duz_ozeti(metin: str | None) -> str:
    """DUZELTMELER.md: kart durum tablosundaki satırlar."""
    if metin is None:
        return "dosya yok"
    satirlar: list[str] = []
    ic = False
    for s in metin.splitlines():
        if s.startswith("## KART DURUM TABLOSU"):
            ic = True
            continue
        if ic and s.startswith("## "):
            break
        if ic and s.startswith("|") and not s.startswith("|---") and "Karar" not in s:
            hucre = [h.strip() for h in s.strip("|").split("|")]
            if len(hucre) >= 3:
                satirlar.append(f"{hucre[0]}={hucre[2]}")
    return "; ".join(satirlar) if satirlar else "tablo bulunamadı"


def klasor_hashleri() -> dict[str, str]:
    """doc/bitti/KART-*.md: dosya adı -> içerik özeti (çok ajanlı rapor dosyaları)."""
    sonuc: dict[str, str] = {}
    if BITTI_DIR.is_dir():
        for f in sorted(BITTI_DIR.glob("*.md")):
            metin = oku(f)
            if metin is not None:
                sonuc[f.name] = hashlib.sha256(metin.encode("utf-8")).hexdigest()
    return sonuc


def main() -> None:
    onceki: dict[str, str | None] = {"bitti": None, "duz": None}
    onceki_klasor: dict[str, str] = {}
    ilk = True
    print(f"[kopru] izleme basladi (aralik {ARALIK}s): BITTI.md + DUZELTMELER.md", flush=True)
    while True:
        b = oku(BITTI)
        d = oku(DUZ)
        hb, hd = ozet_hash(b), ozet_hash(d)
        if ilk:
            print(f"[kopru] BASLANGIC BITTI.md: {bitti_ozeti(b)}", flush=True)
            print(f"[kopru] BASLANGIC DUZELTMELER.md kararlari: {duz_ozeti(d)}", flush=True)
            onceki_klasor = klasor_hashleri()
            print(f"[kopru] BASLANGIC bitti/ klasoru: {len(onceki_klasor)} rapor dosyasi {sorted(onceki_klasor)}", flush=True)
            ilk = False
        else:
            if hb != onceki["bitti"]:
                print(f"[kopru] YAPAY ZEKA BITTI.md'yi GUNCELLEDI -> {bitti_ozeti(b)}  (denetim gerekli)", flush=True)
            if hd != onceki["duz"]:
                print(f"[kopru] DUZELTMELER.md degisti (karar/talimat) -> {duz_ozeti(d)}", flush=True)
            simdi = klasor_hashleri()
            for ad, h in simdi.items():
                if onceki_klasor.get(ad) != h:
                    yeni = "YENI" if ad not in onceki_klasor else "GUNCELLENDI"
                    print(f"[kopru] AJAN RAPORU {yeni}: bitti/{ad} (denetim gerekli)", flush=True)
            onceki_klasor = simdi
        onceki["bitti"], onceki["duz"] = hb, hd
        time.sleep(ARALIK)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
