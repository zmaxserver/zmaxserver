# ZMax Server - Windows & Linux Sunucu Gereksinimleri ve Çekirdek Hesaplama Raporu

Bu belge; ZMax Server'ın hem **Linux (Ubuntu, Debian, AlmaLinux, Rocky Linux)** hem de **Windows Server (2016, 2019, 2022, 2025)** işletim sistemlerinde donanım sınırlarında ve sıfır çakışmayla çalışabilmesi için gereken tüm çekirdek düzeyindeki teknik hesaplamaları içerir.

---

## 1. İşletim Sistemi Çekirdeği Karşılaştırma Matrisi (`v1.0.01` Mevcut vs `v1.1+` Hedef)

| Alan | Linux Sunucu Mimarisi | Windows Server Mimarisi | ZMax Server Gerçek Durumu & Hedef |
| :--- | :--- | :--- | :--- |
| **Asenkron Ağ Motoru** | `epoll` (+ `io_uring` opsiyonel) | `IOCP` (I/O Completion Ports) | ✅ **Aktif:** Rust `tokio` / `mio` ile her iki OS'te yerel çekirdek olay döngüsü çalışır. |
| **Statik Dosya Sıfır Kopyalama** | `sendfile(2)` veya `splice(2)` | `TransmitFile` (`mswsock.dll`) | 🟡 **`v1.0.01`:** 2 MiB üstünde `BufferPool` 64 KiB akış aktif; 📋 **Hedef `v1.1+`:** OS `sendfile(2)` / `TransmitFile` ve `.zst`/`.br`/`.gz` precompressed sidecar. |
| **Çoklu İşlem & Çekirdek Paylaşımı** | `SO_REUSEPORT` + `core_affinity` + `SIGUSR2` | `IOCP` Port Paylaşımı | 🟡 **`v1.0.01`:** `available_parallelism` çoklu Tokio worker; 📋 **Hedef `v1.1+`:** Thread-per-core pinleme, çekirdek başı `SO_REUSEPORT` ve `0 ms` FD devriyle ikili yükseltme. |
| **Yetki Düşürme & İzolasyon** | `setuid`/`nobody`, `CAP_NET_BIND_SERVICE`, Namespaces | Windows Service (`LocalService`) | 🟡 **`v1.0.01`:** [`zmax.service`](file:///D:/zmaxserver/packed/linux-x64/systemd/zmax.service) şu an `User=root` çalışır; 📋 **Hedef `v1.1+`:** `80/443` bind sonrası `nobody` yetki düşürme, `systemd` sertleştirme (`NoNewPrivileges`, `ProtectSystem=strict`) ve vHost başı `suEXEC` soket. |
| **PHP Hızlı İletişimi (IPC)** | Unix Domain Socket (`/run/php/...`) | TCP (`127.0.0.1:9000`) + *Hedef:* Named Pipe | 🟡 **Aktif:** Linux UDS + TCP ve Windows TCP (`php-cgi.exe`) canlı testlidir; 📋 **Hedef `v1.1+`:** `FCGI_KEEP_CONN` soket havuzu, HTTPoxy `Proxy` soyma, `X-Accel-Redirect` & Windows Named Pipe. |
| **ASPX / ASP.NET Desteği** | Mono / .NET Core Kestrel Proxy | Yerel Kestrel / IIS Arka Uç Proxy | ✅ **`zmax-proxy` (Ters Vekil + WebSocket):** Arka plandaki Kestrel/IIS adresine proxy yapılır (yerleşik özel ASP.NET köprü modülü yol haritasındadır). |
| **Servis Modeli** | Systemd Daemon (`Type=simple`, `LimitNOFILE=65535`) | Konsol / `zmaxctrl.bat` | ✅ **`zmax.service` & `zmaxctrl` hazır** *(canlı Linux VM testi bekleniyor)*; 📋 **Hedef `v1.1+`:** `Type=notify`, Windows Service (`services.msc`) ve `setrlimit(RLIMIT_NOFILE)`. |
| **Süreç İçi Bellek Yöneticisi** | `musl` varsayılan ayırıcı / `tikv-jemallocator` | Microsoft `mimalloc` | ✅ **Windows:** `mimalloc` etkin (`Cargo.toml`); 📋 **Linux `musl` Hedef:** Yüksek eşzamanlılıkta bellek parçalanmasını düşürmek için `tikv-jemallocator` kıyaslaması. |

---

## 2. Linux Sunucu Hesaplamaları ve Çekirdek Optimizasyonları

### A. Soket ve Dosya Tanımlayıcı (File Descriptor) Hesabı
* **Varsayılan Linux Sınırı:** Genellikle `1024` açık dosya (yüksek yükte sunucuyu kilitler).
* **ZMax Server Hesabı:**
  * 100.000 anlık eşzamanlı ziyaretçi için:
    - 100.000 gelen istemci soketi
    - 5.000 PHP-FPM / Upstream açık Keep-Alive soketi
    - 10.000 açık statik dosya & per-vhost log tanıtıcısı
    - Toplam gereken limit: **~120.000 FD**.
* **Çözüm (Mevcut & Hedef):**
  - Mevcut [`zmax.service`](file:///D:/zmaxserver/packed/linux-x64/systemd/zmax.service) biriminde `LimitNOFILE=65535` tanımlıdır; yüksek trafikli düğümlerde `LimitNOFILE=1048576` önerilir.
  - **Hedef `v1.1+`:** Başlangıçta otomatik `setrlimit(RLIMIT_NOFILE)` yükseltme + `cap_net_bind_service` sonrası `nobody` kullanıcıya düşürme ve kanallı toplu (batched) domain log yazımı (FD/CPU tasarrufu).

### B. Linux Ağ Yığını Çekirdek Parametreleri (`/etc/sysctl.conf`)
```ini
# Gelen bağlantı kuyruğunu genişlet (Syn Flood önleme)
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# TIME_WAIT soketlerini hızlı geri dönüştür
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Bellek tamponları (100Gbps hazır)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

---

## 3. Windows Server Hesaplamaları ve Özel Durumlar

### A. Windows Port 80/443 ve IIS Çakışması Engelleme
* **Problem:** Windows Server'da varsayılan olarak **IIS (W3SVC)** veya `HTTP.sys` 80 portunu rezerve edebilir.
* **Hesaplanan Çözüm:**
  1. ZMax Server, Windows'ta `SO_EXCLUSIVEADDRUSE` veya temiz port dinleme ile portu tam kontrolüne alır.
  2. Eğer sunucuda hem ZMax hem de eski IIS ASPX siteleri çalışacaksa:
     - ZMax Server 80 ve 443 portunu tutar (tüm trafiği karşılar).
     - IIS ise arka planda sadece `127.0.0.1:8080` portunu dinleyecek şekilde yapılandırılır.
     - ZMax Server gelen istek `.aspx` olduğunda isteği arka plandaki IIS'e proxy eder, yanıtı alıp milisaniyede kullanıcıya basar. Çakışma sıfırlanır!

### B. Windows Registry Ağ Optimizasyonları
Windows Server'da saniyede 50.000+ istek karşılanırken port tükenmesini (ephemeral port exhaustion) engellemek için:
```reg
; TCP bekleme süresini 240 saniyeden 30 saniyeye düşür
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]
"TcpTimedWaitDelay"=dword:0000001e
"MaxUserPort"=dword:0000fffe
```

---

## 4. Donanım ve Bellek Tüketim Hedefleri

| Metrik | Nginx | OpenLiteSpeed | ZMax Server (Mimari Hedef) |
| :--- | :--- | :--- | :--- |
| **Boşta (Idle) RAM Tüketimi** | 25 - 40 MB | 60 - 120 MB | **Düşük ayak izi** (Windows `mimalloc`; Linux `musl` statik ikili — tam VM profil ölçümü yapılacaktır) |
| **Yüksek Eşzamanlılıkta CPU/RAM** | Çok süreçli | Olay güdümlü + LSAPI | **Thread-per-Core + `BufferPool` + `FCGI_KEEP_CONN` + Sidecar (`.zst`/`.br`/`.gz`)** |
| **Statik Dosya CPU Maliyeti** | `sendfile(2)` | `sendfile(2)` | **`BufferPool` akış aktif; hedef `v1.1+`: `TransmitFile` / `sendfile(2)`** |
| **Windows Üzerinde Çalışma** | Kısıtlı | ❌ Yok (WSL2 Zorunlu) | **%100 Yerel Windows x64 `IOCP` + Linux `x64`/`arm64` `musl`** |

---

## 5. Sonuç ve Platform Soyutlama Garantisi
İşletim sistemi farklılıkları kod tabanında derleme anı bayraklarıyla (`#[cfg(unix)]` / `#[cfg(windows)]`) izole edilir:
- **Linux:** `epoll`, Unix Domain Soket (`php-fpm` & `/run/zmax/api.sock`), `SIGHUP`/`SIGTERM` sinyalleri; *hedef `v1.1+`:* `SO_REUSEPORT`, `core_affinity`, `sendfile(2)`, `setuid`/`nobody` yetki düşürme, `SIGUSR2` FD devri ve Linux Namespaces/suEXEC izolasyonu.
- **Windows:** `IOCP`, `mimalloc`, `php-cgi.exe` TCP FastCGI; *hedef `v1.1+`:* `TransmitFile`, Named Pipe FastCGI ve yerel `services.msc` NT servisi.

Ayrıntılı eklenecek bileşen tasarımı için: [`mimari/EKLENECEK_MIMARI.md`](file:///D:/zmaxserver/doc/mimari/EKLENECEK_MIMARI.md).

