# ZMax Server — English Documentation (`readme-en.md`)

[Türkçe](readme-tr.md) · [Main README](README.md) · [Test Records](testler.md)

---

## 1. Overview

**ZMax Server (v1.0.10)** is a high-performance, asynchronous web server written in pure Rust with Tokio runtime. It is engineered to deliver zero-compromise speed, low memory footprint, and native security. ZMax Server achieves comprehensive feature parity with **OpenLiteSpeed (OLS)** and seamlessly integrates with hosting control planes, specifically **zPanel**.

### Core Capabilities
- **Asynchronous Work-Stealing Workers:** Multi-threaded Tokio event loop supporting epoll/kqueue/IOCP.
- **Ultra-Low Memory Footprint:** Integrated `mimalloc` allocator with baseline memory consumption of ~12 MB.
- **HTTP/1.1 & HTTP/2 Core:** Full conformance with RFC 7230 and RFC 9113, request smuggling mitigation.
- **Dynamic TLS Engine:** `rustls 0.23` with ring backend; ALPN `h2`/`http/1.1`, dynamic SNI dispatch, live cert reloading.
- **FastCGI / LSPHP Integration:** Unix Domain Socket and TCP connection pools for PHP 8.2, 8.3, and 8.4.
- **Reverse Proxy & Gateway:** Upstream bridge for zPanel API (8035), WebAdmin (19485), WebSocket upgrade and SSE streaming.
- **zCage Sandboxing:** Linux cgroup v1/v2 enforcement (CPU, RAM, PID limits), seccomp filter integration, namespace isolation.
- **Multi-Tiered Cache (L1/L2):** In-memory and disk caching with Cache-Tag based targeted purge capabilities.
- **WAF & Traffic Security:** IP access control lists, OWASP Core Ruleset alignment, Hotlink protection, Slowloris mitigation.
- **WebAdmin Dashboard:** Secure HTTPS administrative dashboard built on Vue.js and Bootstrap.

---

## 2. Architectural Pipeline

ZMax Server processes incoming network packets through an 8-stage modular pipeline:

```
[Inbound Client Request]
          │
          ▼
[L1: Network & Connection]  ─── TCP Socket Re-use, TLS Handshake, ALPN Negotiation
          │
          ▼
[L2: Protocol Parsing]     ─── HTTP/1.1 & HTTP/2 Frame Validation
          │
          ▼
[L3: RealIP & Ingress]     ─── X-Forwarded-For, CIDR-based Trusted Proxies
          │
          ▼
[L4: Security & WAF]       ─── IP ACL, Threat Scoring, Rate Limiter
          │
          ▼
[L5: Routing Engine]       ─── Virtual Host Resolution, Context Rules, .htaccess
          │
          ▼
[L6: Caching Tier]         ─── L1 Memory / L2 Disk Evaluation (HIT/MISS/BYPASS)
          │
          ▼
[L7: Protocol Handlers]    ─── Zero-Copy Static Files / LSPHP FastCGI / Upstream Proxy
          │
          ▼
[L8: Response & Headers]   ─── HSTS, CSP, X-Frame-Options, Dynamic Compression (Brotli/Gzip)
```

---

## 3. Live Server Validation Results (`13.143.223.6`)

Verified on production AlmaLinux 8.10 x86_64:

1. **Panel Core Port 443 (HTTPS):**
   - Status: `HTTP/2 200 OK`
   - Security Headers: HSTS (`max-age=63072000`), CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
2. **Web Server Port 80 (HTTP):**
   - Status: `HTTP/1.1 200 OK`
3. **WebAdmin Port 19485 (HTTPS):**
   - Endpoint: `https://panel.ommicode.com:19485/?token=zmax_sec_adm_9f8b2a3c7e1d4085`
   - Status: `HTTP/1.1 200 OK` (SAMEORIGIN, `frame-ancestors 'self'`)
4. **Tenant Network Isolation:**
   - Validated via `nftables`: `nobody` (UID 65534) upstream socket access preserved; unprivileged tenant UID space (>= 5000) shielded from internal control ports (`8025`, `8035`, `8055`, `8788`).

---

## 4. Building and Running

### Prerequisites
- Rust 1.78+ (stable)
- Linux Kernel 4.18+ (cgroup v2 & nftables recommended)

### Build Release Binary
```bash
cargo build --release --bin zmax
```

### Launch Server
```bash
./target/release/zmax --config conf/zmax.toml
```

### Zero-Downtime Reload
```bash
kill -HUP $(pidof zmax)
```

---

## 5. Related Links

- [Comprehensive Test Verification Ledger](testler.md)
- [Visual Architecture Diagram](docs/mimari/zmax_mimari_semasi.html)
- [Turkish Documentation (Türkçe Belgeler)](readme-tr.md)
