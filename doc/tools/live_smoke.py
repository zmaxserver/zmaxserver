#!/usr/bin/env python3
"""ZMax Server canlı uçtan uca smoke testi (Web 19480, WebAdmin/Proxy 19485, Control API 19486)."""

import argparse
import http.server
import json
import os
import threading
import urllib.error
import urllib.request


class PrefixProxyHandler(http.server.BaseHTTPRequestHandler):
    PREFIX = "/v1/zmax/console"
    ADMIN_BASE = "http://127.0.0.1:19485"
    API_TOKEN = ""

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def _proxy(self, method):
        assert self.path.startswith(self.PREFIX), f"Beklenmeyen ön ek: {self.path}"
        stripped = self.path[len(self.PREFIX):] or "/"
        cl = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(cl) if cl > 0 else None
        headers = {}
        if "Content-Type" in self.headers:
            headers["Content-Type"] = self.headers["Content-Type"]
        if self.API_TOKEN:
            headers["X-ZMax-Token"] = self.API_TOKEN
        upstream_req = urllib.request.Request(
            f"{self.ADMIN_BASE}{stripped}",
            data=body,
            method=method,
            headers=headers,
        )
        with urllib.request.urlopen(upstream_req, timeout=5) as resp:
            payload = resp.read()
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() in ("content-type", "cache-control"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, format, *args):
        pass


def req(url, method="GET", body=None, token=""):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-ZMax-Token"] = token
    r = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", errors="replace")


def parse_args():
    parser = argparse.ArgumentParser(description="Çalışan ZMax Server üzerinde canlı smoke testi yürütür.")
    parser.add_argument("--host", default="127.0.0.1", help="Sunucu adresi (varsayılan: 127.0.0.1)")
    parser.add_argument("--http-port", type=int, default=19480, help="HTTP portu (varsayılan: 19480)")
    parser.add_argument("--admin-port", type=int, default=19485, help="WebAdmin portu (varsayılan: 19485)")
    parser.add_argument("--api-port", type=int, default=19486, help="Control API portu (varsayılan: 19486)")
    parser.add_argument("--token", default=os.environ.get("ZMAX_API_TOKEN", ""), help="API token (isteğe bağlı)")
    return parser.parse_args()


def main():
    args = parse_args()
    host = args.host
    http_url = f"http://{host}:{args.http_port}"
    admin_url = f"http://{host}:{args.admin_port}"
    api_url = f"http://{host}:{args.api_port}"
    token = args.token.strip()

    # 1. Web Sunucusu (19480) + Cache MISS -> HIT
    s1, _, b1 = req(f"{http_url}/")
    assert s1 == 200 and str(args.admin_port) in b1, f"Web root başarısız: {s1}"
    s2, h2, _ = req(f"{http_url}/")
    assert s2 == 200 and h2.get("X-Cache") == "HIT", f"Cache HIT bekleniyordu: {h2}"
    print(f"[OK] Web {args.http_port}: 200 OK (MISS -> {h2.get('X-Cache')})")

    # 2. WebAdmin UI (19485) — doğrudan ve /v1/zmax/console/ ters vekil simülasyonu
    sa, _, ba = req(f"{admin_url}/")
    assert sa == 200 and 'href="css/core.css"' in ba and 'src="js/core.js"' in ba and 'href="/css/' not in ba
    sjs, _, bjs = req(f"{admin_url}/js/core.js")
    assert sjs == 200 and ("apiFetch('api/status')" in bjs or "fetch('api/status')" in bjs)
    assert "fetch('/api/" not in bjs and "apiFetch('/api/" not in bjs

    PrefixProxyHandler.ADMIN_BASE = admin_url
    PrefixProxyHandler.API_TOKEN = token
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PrefixProxyHandler)
    px_port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base_px = f"http://127.0.0.1:{px_port}/v1/zmax/console"
        p1, _, bp1 = req(f"{base_px}/")
        assert p1 == 200 and 'href="css/core.css"' in bp1
        p2, hpx2, _ = req(f"{base_px}/css/core.css")
        assert p2 == 200 and "text/css" in hpx2.get("Content-Type", "")
        p3, hpx3, bp3 = req(f"{base_px}/js/core.js")
        assert p3 == 200 and "javascript" in hpx3.get("Content-Type", "")
        assert "apiFetch('api/status')" in bp3 or "fetch('api/status')" in bp3
        p4, _, _ = req(f"{base_px}/assets/zmax_white.svg")
        assert p4 == 200
        p5, _, bp5 = req(f"{base_px}/api/status")
        assert p5 == 200 and json.loads(bp5)["ports"]["api"] == args.api_port
    finally:
        srv.shutdown()
        srv.server_close()
    print(f"[OK] WebAdmin {args.admin_port} + /v1/zmax/console/ ters vekil simülasyonu: TÜMÜ 200 OK (tam göreli yol)")

    # 3. Evrensel Panel Control API (19486)
    sh, _, bh = req(f"{api_url}/api/v1/health")
    jh = json.loads(bh)
    assert sh == 200 and jh["ok"] is True and jh["engine"] == "zmax"

    ss, _, bs = req(f"{api_url}/api/v1/status", token=token)
    js = json.loads(bs)
    expected_ports = {
        "http": args.http_port,
        "https": 19483,
        "admin": args.admin_port,
        "api": args.api_port,
    }
    assert ss == 200 and js["ports"] == expected_ports, f"Beklenmeyen port yanıtı: {js.get('ports')}"

    sp, _, bp = req(f"{api_url}/api/v1/ports", token=token)
    jp = json.loads(bp)
    assert sp == 200 and jp["collision_detected"] is False
    print(f"[OK] Kontrol API {args.api_port}: health/status/ports -> collision_detected={jp['collision_detected']}")

    # 4. vHost CRUD + Hot-Reload + Path Traversal Reddi
    sput, _, bput = req(
        f"{api_url}/api/v1/vhosts/panel-smoke.local",
        method="PUT",
        body={"document_root": "www/html", "php_enabled": False, "cache_enabled": True},
        token=token,
    )
    assert sput == 200 and json.loads(bput)["status"] == "saved"

    svh, _, bvh = req(f"{api_url}/api/v1/vhosts", token=token)
    domains = [v["domain"] for v in json.loads(bvh)["vhosts"]]
    assert svh == 200 and "panel-smoke.local" in domains

    sbad, _, _ = req(
        f"{api_url}/api/v1/vhosts",
        method="POST",
        body={"domain": "../evil.local"},
        token=token,
    )
    assert sbad == 400, f"Path traversal engellenmeliydi: {sbad}"

    sdel, _, bdel = req(f"{api_url}/api/v1/vhosts/panel-smoke.local", method="DELETE", token=token)
    assert sdel == 200 and json.loads(bdel)["status"] == "deleted"

    spurge, _, _ = req(f"{api_url}/api/v1/cache/purge", method="POST", body={}, token=token)
    srel, _, _ = req(f"{api_url}/api/v1/reload", method="POST", token=token)
    assert spurge == 200 and srel == 200
    print("[OK] vHost CRUD + Traversal Guard (400) + Purge + Reload: TÜMÜ BAŞARILI")


if __name__ == "__main__":
    main()
