# ZMax Server Derin Sistem Mimarisi

- **Resmi İsim:** ZMax Server (`zmaxserver`)
- **İkili (Binary):** `zmax.exe` (Windows) / `zmax` (Linux)
- **Kontrol Paneli:** ZePanel (`zepanel.com`)
- **Alan Adı & Repo:** `zmaxserver.com` & `github.com/zmaxserver`

## 1. Mimari Felsefe
ZMax Server; doğrudan işletim sistemi çekirdek çağrıları (Windows `IOCP` / Linux `epoll`) üzerine oturtulmuş, saf Rust bellek güvenliğine sahip ve 4 çekirdek ilkeyi hedefleyen yüksek verimli bir HTTP/FastCGI motorudur:
- **Az CPU:** `BytesMut` bellek havuzu, `UpstreamSocketPool`, Moka L1/L2 önbellek (Stampede/SWR) ve hedef `v1.1+` ile `core_affinity`, OS `sendfile(2)`/`TransmitFile`, `.zst`/`.br`/`.gz` sidecar ve `FCGI_KEEP_CONN` soket havuzu.
- **Sıfır Güvenlik Zafiyeti:** Slowloris/Request Smuggling kalkanı, WAF, WP brute-force, CIDR ACL, Hotlink, `0.0.0.0` zorunlu token, [`zmax-obfuscate`](file:///D:/zmaxserver/doc/sifleme.md) ve hedef `v1.1+` ile `Proxy`/HTTPoxy engeli, `setuid`/`nobody` yetki düşürme, per-vhost `suEXEC` UDS & domain WAF.
- **Çoklu İşlem & Yüksek Eşzamanlılık:** Çok çekirdekli Tokio asenkron işçileri, `SIGHUP`/API sıcak reload ve hedef `v1.1+` ile `SO_REUSEPORT` multi-worker, `SIGUSR2` FD devri, çoklu PHP-FPM yük dengeleme, `zmax-appserver` supervisor ve `zmax-redis`.
- **Her Şeye Uyumlu Evrensel Yapı:** Windows x64 + Linux `x64`/`arm64` statik `musl`, PHP FastCGI (TCP/Unix soket), `.htaccess`/`try_files`/`PATH_INFO`, WebP/AVIF, Ters Vekil/WebSocket, `19480–19486` çakışmasız panel API ve hedef `v1.1+` ile HTTP/2 (`h2`), HTTP/3 (`QUIC`), `PROXY Protocol`, `zmax-acme` & alan adına özel günlükler.

## 2. 7 Katmanlı Mimari Şeması (`v1.0.01` Mevcut Çekirdek + `v1.1+` Hedefler)
1. **Katman 0 (OS & Donanım):** Windows `IOCP` / Linux `epoll`, *hedef:* `SO_REUSEPORT`, `TransmitFile` / `sendfile(2)` & `setuid`/`nobody`.
2. **Katman 1 (Runtime & Bellek):** `zmax-runtime` (Asenkron Worker'lar, Ctrl+C/`SIGTERM`/`SIGHUP`; *hedef:* Thread Pinning & `SIGUSR2` FD devri) ve `zmax-pool` (`BufferPool` & `UpstreamSocketPool`; *hedef:* FastCGI `keep_conn` havuzu).
3. **Katman 2 (Ağ & TLS):** `zmax-tls` (TLS 1.3/1.2, dinamik SNI; *hedef:* gerçek ALPN `h2`, `zmax-acme`, OCSP Stapling) ve `zmax-timeout` (Slowloris Kalkanı).
4. **Katman 3 (HTTP Çekirdeği):** `zmax-httpparser` (Zero-Copy HTTP/1.1 Parser + Trusted RealIP; *hedef:* HTTP/2–3 & `PROXY Protocol`) ve `zmax-header` (HeaderMap & Güvenlik Başlıkları).
5. **Katman 4 (Upstream & Dağıtım):** `zmax-fastcgi` (PHP-FPM TCP/UDS; *hedef:* `HTTP_PROXY` engeli, streaming, `X-Accel-Redirect`), `zmax-proxy` (Ters Proxy / WebSocket; *hedef:* asenkron DNS) ve `zmax-static` (ETag/Range/WebP/AVIF; *hedef:* sidecar & `sendfile`).
6. **Katman 5 (Hız & Koruma):** `zmax-cache` (Moka L1/L2, Tag Purge, SWR, Stampede; *hedef:* LSCache başlık köprüsü), `zmax-rewrite` (`.htaccess`, `try_files`, `PATH_INFO`; *hedef:* alt-dizin önbelleği), `zmax-security` (WAF, WP Shield, Rate Limit, ACL, Hotlink; *hedef:* domain WAF, `.htpasswd`, BotShield) ve `zmax-compress` (Gzip; *hedef:* Brotli/Zstd).
7. **Katman 6 (Yönetim & İkili):** `zmax-config` (TOML vHost + reload), `zmax-bin` (`19485` WebAdmin + `19486` Control API + `/metrics` + rotasyonlu log; *hedef:* alan adına özel loglar & `Trace ID`).

> 📌 Eklenecek tüm yeni mimari katmanların ayrıntılı yol haritası: [`mimari/EKLENECEK_MIMARI.md`](file:///D:/zmaxserver/doc/mimari/EKLENECEK_MIMARI.md) · [`GELISTIRME_PLANI.md`](file:///D:/zmaxserver/doc/GELISTIRME_PLANI.md).
