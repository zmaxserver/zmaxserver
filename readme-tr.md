# ZMax Server — Türkçe Dokümantasyon (`readme-tr.md`)

[English](readme-en.md) · [Ana Sayfa (README)](README.md) · [Test Kütüğü](testler.md)

---

## 1. Genel Bakış

**ZMax Server (v1.0.10)**, yüksek eşzamanlılık ve düşük bellek tüketimi için Rust ve asenkron Tokio motoru ile geliştirilmiş yeni nesil web sunucusudur. Başta **zPanel** olmak üzere modern barındırma panelleri ile tam uyumlu çalışmak ve **OpenLiteSpeed (OLS)** ile birebir işlev ve mimari denklik sağlamak üzere tasarlanmıştır.

### Öne Çıkan Yetenekler
- **Asenkron Work-Stealing Workers:** Tokio çalışma zamanı üzerinde epoll/kqueue/IOCP çoklu iş parçacığı mimarisi.
- **Ultra-Düşük Bellek Ayırıcı:** `mimalloc` ile ~12 MB temel bellek ayak izi.
- **HTTP/1.1 & HTTP/2 Çekirdeği:** RFC 7230 ve RFC 9113 tam uyumluluğu, gelişmiş istek kaçırma (smuggling) kalkanı.
- **Dinamik TLS Motoru:** `rustls 0.23` + ring; ALPN `h2`/`http/1.1`, dinamik SNI çözümleyici, canlı sertifika yenileme.
- **LSPHP & FastCGI Entegrasyonu:** PHP 8.2, 8.3, 8.4 için Unix Domain Socket ve TCP bağlantı havuzları.
- **Ters Vekil (Reverse Proxy):** zPanel API (8035), WebAdmin (19485), WebSocket ve SSE akış desteği.
- **zCage Güvenlik Kalkanı:** Linux cgroup v1/v2 kaynak kotaları (CPU, RAM, PID), seccomp filtreleri ve ad alanı (namespace) izolasyonu.
- **Katmanlı Önbellek (L1/L2 Cache):** Bellek içi + disk tabanlı önbellek, X-Cache başlıkları, Cache-Tag bazlı anlık temizleme (Purge).
- **WAF & Güvenlik:** IP ACL kuralları, SQLi/XSS/LFI/RFI koruması, Hotlink kalkanı, Slowloris zaman aşımı koruması.
- **WebAdmin Yönetim Paneli:** HTTPS üzerinden modern, Vue.js/Bootstrap tabanlı görsel izleme ve yönetim arayüzü.

---

## 2. Mimari Katmanlar

ZMax Server, 8 aşamalı ardışık boru hattı (pipeline) mimarisiyle istekleri işler:

```
[İstemci İsteği]
       │
       ▼
[L1: Ağ & Bağlantı]  ─── TCP Soket, TLS El Sıkışma, ALPN Müzakeresi
       │
       ▼
[L2: Protokol Ayrıştırma]  ─── HTTP/1.1 & HTTP/2 Çerçeve Doğrulama
       │
       ▼
[L3: RealIP & Ağ Kalkanı]  ─── X-Forwarded-For, Güvenilen Vekil (Trusted Proxies)
       │
       ▼
[L4: Güvenlik & WAF]  ─── IP ACL, ModSecurity Kuralları, Rate Limiter
       │
       ▼
[L5: Yönlendirici (Router)]  ─── Sanal Konak Eşleme, Context Kuralları, .htaccess
       │
       ▼
[L6: Önbellek (Cache)]  ─── L1 Bellek / L2 Disk Önbellek Kontrolü (HIT/MISS)
       │
       ▼
[L7: İşleyiciler (Handlers)]  ─── Statik Dosya (Zero-Copy) / LSPHP / Reverse Proxy
       │
       ▼
[L8: Yanıt & Güvenlik Başlıkları]  ─── HSTS, CSP, X-Frame-Options, Sıkıştırma (Gzip/Brotli)
```

---

## 3. Canlı Sunucu Doğrulama Kanıtları (`13.143.223.6`)

AlmaLinux 8.10 canlı üretim ortamında gerçekleştirilen uçtan uca testler:

1. **Ana Panel Port 443 (HTTPS):**
   - Yanıt: `HTTP/2 200 OK`
   - Başlıklar: HSTS (`max-age=63072000`), CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
2. **Web Sunucusu Port 80 (HTTP):**
   - Yanıt: `HTTP/1.1 200 OK`
3. **WebAdmin Port 19485 (HTTPS):**
   - URL: `https://panel.ommicode.com:19485/?token=zmax_sec_adm_9f8b2a3c7e1d4085`
   - Yanıt: `HTTP/1.1 200 OK` (SAMEORIGIN, `frame-ancestors 'self'`)
4. **Kiracı Ağ İzolasyonu:**
   - `nftables` üzerinde `nobody` (UID 65534) upstream erişimi korunurken kiracı kullanıcıları (UID >= 5000) iç portlardan (`8025`, `8035`, `8055`, `8788`) izole edildi.

---

## 4. Derleme ve Çalıştırma

### Gereksinimler
- Rust 1.78+ (kararlı kanal)
- Linux Kernel 4.18+ (cgroup v2 ve nftables önerilir)

### Derleme (Release)
```bash
cargo build --release --bin zmax
```

### Çalıştırma
```bash
./target/release/zmax --config conf/zmax.toml
```

### Canlı Yeniden Yükleme (Zero-Downtime Reload)
```bash
kill -HUP $(pidof zmax)
```

---

## 5. İlgili Belgeler

- [Tüm Yapılan Testler ve Doğrulama Kütüğü](testler.md)
- [Mimari Görsel Şema](docs/mimari/zmax_mimari_semasi.html)
- [İngilizce Belgeler (English Documentation)](readme-en.md)
