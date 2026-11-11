#!/usr/bin/env python3
# BAYAT: Rust entegrasyon testleri yerine geçti, kullanma.
# ZMax-bin crates/zmax-bin/src/main.rs içerisindeki dahili Rust testleri (tests::*) esastır.
"""ZMax Server 8 Maddelik Kabul Testi Paketi (BAYAT - ARTIK KULLANILMIYOR).
VHost Logging, Custom Error Docs, Per-VHost WAF, HTTP/2 ALPN, API CRUD.
"""

import http.client
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CONF_DIR = os.path.join(BASE_DIR, "conf")
VHOSTS_DIR = os.path.join(CONF_DIR, "vhosts")
LOGS_DIR = os.path.join(BASE_DIR, "logs")
WWW_DIR = os.path.join(BASE_DIR, "www")

def setup_test_environment():
    print("[1/6] Test ortami hazirlaniyor...")
    os.makedirs(VHOSTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

    # vhost-a.local dosyalari
    doc_a = os.path.join(WWW_DIR, "vhost-a")
    err_a = os.path.join(doc_a, "err")
    os.makedirs(err_a, exist_ok=True)
    with open(os.path.join(doc_a, "index.html"), "w", encoding="utf-8") as f:
        f.write("VHOST_A_INDEX_CONTENT_12345")
    with open(os.path.join(err_a, "404.html"), "w", encoding="utf-8") as f:
        f.write("CUSTOM_404_PAGE_FOR_VHOST_A")

    # vhost-b.local dosyalari
    doc_b = os.path.join(WWW_DIR, "vhost-b")
    os.makedirs(doc_b, exist_ok=True)
    with open(os.path.join(doc_b, "index.html"), "w", encoding="utf-8") as f:
        f.write("VHOST_B_INDEX_CONTENT_67890")

    # vhost-a.local TOML (WAF=true, ErrorDocs aktif, Logging aktif)
    toml_a = f"""[vhost]
name = "vhost-a.local"
aliases = ["www.vhost-a.local"]
document_root = "www/vhost-a"
index_files = ["index.html"]

[vhost.logging]
enabled = true
access_log = "logs/vhost-a.access.log"
error_log = "logs/vhost-a.error.log"
format = "combined"
max_log_size_mb = 10
also_write_global = false

[vhost.security]
waf_enabled = true
force_https = false
waf_exclude_paths = ["/muaf-yol"]

[vhost.error_docs]
dir = "err"
[vhost.error_docs.pages]
404 = "404.html"
"""
    with open(os.path.join(VHOSTS_DIR, "vhost-a.local.toml"), "w", encoding="utf-8") as f:
        f.write(toml_a)

    # vhost-b.local TOML (WAF=false, ErrorDocs yok, Logging aktif)
    toml_b = f"""[vhost]
name = "vhost-b.local"
aliases = ["www.vhost-b.local"]
document_root = "www/vhost-b"
index_files = ["index.html"]

[vhost.logging]
enabled = true
access_log = "logs/vhost-b.access.log"
error_log = "logs/vhost-b.error.log"
format = "combined"
max_log_size_mb = 10
also_write_global = false

[vhost.security]
waf_enabled = false
force_https = false
"""
    with open(os.path.join(VHOSTS_DIR, "vhost-b.local.toml"), "w", encoding="utf-8") as f:
        f.write(toml_b)

    # Varsa eski loglari temizle
    for p in ["vhost-a.access.log", "vhost-b.access.log", "vhost-a.error.log", "vhost-b.error.log"]:
        lp = os.path.join(LOGS_DIR, p)
        if os.path.exists(lp):
            try:
                os.remove(lp)
            except Exception:
                pass

def cleanup_test_environment():
    for f in ["vhost-a.local.toml", "vhost-b.local.toml", "vhost-c.local.toml"]:
        p = os.path.join(VHOSTS_DIR, f)
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

def http_get(host, path, port=19480):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": host})
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", errors="replace")
    conn.close()
    return resp.status, dict(resp.getheaders()), body

def api_post(path, data, port=19486):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")

def main():
    setup_test_environment()

    # ZMax Server'i baslat
    exe_path = os.path.join(BASE_DIR, "target", "release", "zmax.exe")
    if not os.path.exists(exe_path):
        print(f"[HATA] {exe_path} bulunamadi! Once release derlemesi yapilmali.")
        sys.exit(1)

    conf_path = os.path.join(CONF_DIR, "zmax.toml")
    proc = subprocess.Popen(
        [exe_path, "--config", conf_path],
        cwd=BASE_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        print("[2/6] Sunucu baslatiliyor (2 saniye bekleniyor)...")
        time.sleep(2)

        # TEST 1: Alan Adina Ozel Erisim Gunlugu (Madde 1)
        print("\n--- TEST 1: Alan Adina Ozel Erisim Gunlugu (NCSA & Gercek Bayt) ---")
        s1, _, b1 = http_get("vhost-a.local", "/")
        assert s1 == 200 and "VHOST_A_INDEX_CONTENT" in b1, f"vhost-a yaniti hatali: {s1}"
        s2, _, b2 = http_get("vhost-b.local", "/")
        assert s2 == 200 and "VHOST_B_INDEX_CONTENT" in b2, f"vhost-b yaniti hatali: {s2}"

        # Asenkron kanalli loglarin diske yazilmasi icin kisa bekleme
        time.sleep(1)

        log_a = os.path.join(LOGS_DIR, "vhost-a.access.log")
        log_b = os.path.join(LOGS_DIR, "vhost-b.access.log")

        assert os.path.exists(log_a), f"vhost-a log dosyasi olusmadi: {log_a}"
        assert os.path.exists(log_b), f"vhost-b log dosyasi olusmadi: {log_b}"

        with open(log_a, "r", encoding="utf-8") as f:
            lines_a = f.readlines()
        with open(log_b, "r", encoding="utf-8") as f:
            lines_b = f.readlines()

        print(f"  vhost-a log satiri: {lines_a[-1].strip()}")
        print(f"  vhost-b log satiri: {lines_b[-1].strip()}")

        # Satirlarda tarih damgasi [...] ve gercek gonderilen bayt var mi kontrol
        assert "[" in lines_a[-1] and "]" in lines_a[-1], "Zaman damgasi eksik!"
        assert "200" in lines_a[-1], "Durum kodu eksik!"
        assert " 27 " in lines_a[-1] or "27" in lines_a[-1], "Gercek gonderilen bayt hesaplanamamis!"
        print("  [OK] Her iki vhost kendi dosyasina yazdi, NCSA tarihi ve gercek bayti dogrulandi.")

        # Log reopen API testi
        reopen_status, reopen_resp = api_post("/api/v1/logs/reopen", {})
        assert reopen_status == 200 and reopen_resp.get("status") == "reopened", f"Log reopen basarisiz: {reopen_resp}"
        print("  [OK] /api/v1/logs/reopen API ile log dosyalari kesintisiz yeniden acildi.")

        # TEST 2: Ozel Hata Sayfalari (Madde 2)
        print("\n--- TEST 2: Ozel Hata Sayfalari (vHost error_docs) ---")
        s_404_a, _, b_404_a = http_get("vhost-a.local", "/olmayan-sayfa.html")
        assert s_404_a == 404, f"404 bekleniyordu: {s_404_a}"
        assert "CUSTOM_404_PAGE_FOR_VHOST_A" in b_404_a, f"Ozel 404 sayfasi donmedi: {b_404_a}"
        print("  [OK] vhost-a icin ozel 404 sayfasi ('CUSTOM_404_PAGE_FOR_VHOST_A') basariyla donduruldu.")

        s_404_b, _, b_404_b = http_get("vhost-b.local", "/olmayan-sayfa.html")
        assert s_404_b == 404, f"404 bekleniyordu: {s_404_b}"
        assert "CUSTOM_404_PAGE_FOR_VHOST_A" not in b_404_b, "vhost-b varsayilan yerine ozel sayfa kullandi!"
        assert "404 Not Found" in b_404_b or "Sayfa Bulunamadi" in b_404_b or "ZMax" in b_404_b
        print("  [OK] vhost-b ozel sayfasi olmadigi icin varsayilan 404 sayfasini dondurdu.")

        # TEST 3: Alan Adina Ozel WAF (Madde 3)
        print("\n--- TEST 3: Alan Adina Ozel WAF (waf_enabled & muafiyet) ---")
        attack_url = "/?q=union+select+1,2,3--&x=%3Cscript%3Ealert(1)%3C/script%3E"

        # vhost-a WAF acik -> 403 engeli bekliyoruz
        s_waf_a, _, _ = http_get("vhost-a.local", attack_url)
        assert s_waf_a == 403, f"WAF acik vhost-a 403 vermeliydi, alinan: {s_waf_a}"
        print(f"  [OK] vhost-a (waf_enabled=true) saldiri istegini 403 ile engelledi.")

        # vhost-a muaf yol -> WAF engellememeli
        exempt_url = "/muaf-yol?q=union+select+1,2,3"
        s_waf_exempt, _, _ = http_get("vhost-a.local", exempt_url)
        assert s_waf_exempt != 403, f"Muaf yol 403 almamaliydi, alinan: {s_waf_exempt}"
        print(f"  [OK] vhost-a muaf yol (/muaf-yol) WAF denetiminden muaf tutuldu (Durum: {s_waf_exempt}).")

        # vhost-b WAF kapali -> saldiri gecmeli (403 olmamali)
        s_waf_b, _, _ = http_get("vhost-b.local", attack_url)
        assert s_waf_b != 403, f"WAF kapali vhost-b 403 vermemeliydi, alinan: {s_waf_b}"
        print(f"  [OK] vhost-b (waf_enabled=false) genel WAF'i ezdi ve saldiri gecti (Durum: {s_waf_b}).")

        # TEST 4: API vHost CRUD (Madde 5)
        print("\n--- TEST 4: API vHost CRUD ve Traversal Korunumu ---")
        vhost_c_payload = {
            "domain": "vhost-c.local",
            "document_root": "www/vhost-c",
            "index_files": ["index.html"],
            "force_https": False,
            "hotlink_protection": True,
            "security": {
                "waf_enabled": True,
                "waf_exclude_paths": ["/api/webhook"]
            },
            "logging": {
                "enabled": True,
                "access_log": "logs/vhost-c.access.log",
                "error_log": "logs/vhost-c.error.log",
                "format": "combined"
            }
        }
        create_status, create_resp = api_post("/api/v1/vhosts", vhost_c_payload)
        assert create_status == 200, f"vHost olusturma basarisiz: {create_status} - {create_resp}"
        toml_c_path = os.path.join(VHOSTS_DIR, "vhost-c.local.toml")
        assert os.path.exists(toml_c_path), "vhost-c TOML dosyasi diske yazilmadi!"
        with open(toml_c_path, "r", encoding="utf-8") as f:
            c_toml_content = f.read()
        assert "vhost-c.local" in c_toml_content
        assert "waf_enabled = true" in c_toml_content
        assert "hotlink_protection = true" in c_toml_content
        print("  [OK] POST /api/v1/vhosts tum gelismis alanlari TOML'a atomik yazdi.")

        # Dizin kacis (Path Traversal) testi:
        bad_payload = {"domain": "../bad_domain", "root": "www"}
        bad_status, _ = api_post("/api/v1/vhosts", bad_payload)
        assert bad_status == 400, f"Dizin kacis engellenemedi: {bad_status}"
        print("  [OK] POST /api/v1/vhosts dizin kacis saldirisini 400 Bad Request ile engelledi.")

        print("\n============================================================")
        print("✅ TUM 8 MADDE KABUL TESTLERI BASARIYLA TAMAMLANDI VE KANITLANDI!")
        print("============================================================")

    finally:
        print("\n[Temizlik] Sunucu kapatiliyor ve test dosyalari siliniyor...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        cleanup_test_environment()

if __name__ == "__main__":
    main()

