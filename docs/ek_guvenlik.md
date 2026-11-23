# ZMax Server & zPanel — Port Kabukları Gizleme & Ek Güvenlik Kalkanı (ek_guvenlik.md)

> **Tarih:** 23 Kasım 2026  
> **Kapsam:** Port Cloaking (Hayalet Port), Banner Stripping, Sessiz Düşürme (Silent Drop), Dinamik Port Knocking ve Çekirdek İzolasyon Standartları  
> **Hedef:** Sunucunun Shodan, Censys, Nmap, Masscan ve otomatik bot tarayıcılarında **tamamen görünmez (stealth / hayalet)** hale getirilmesi; port ve servis kabuklarının dış dünyaya ifşa edilmesinin engellenmesi.

---

## 1. Problem Tanımı: "Tüm Portların Açık Görünmesi" Riski

Geleneksel web hosting panellerinde (cPanel, Plesk, CyberPanel, OpenLiteSpeed vb.) ve standart Linux kurulumlarında şu zaafiyetler görülür:
1. **Banner Grabbing & Keşif (Reconnaissance):** Saldırganlar Shodan veya Masscan ile sunucunun IP'sini tarar; HTTP başlıklarından (`Server: LiteSpeed`, `X-Powered-By: PHP/8.x`, `X-Turbo-Charged-By`), hata sayfalarından veya açık portlardan sunucu mimarisini tespit eder.
2. **Kabuk ve Yönetim Portlarının İfşası:** Panel arayüzleri (8025, 8035, 8056, 19485 WebAdmin, 19486 API, 8091 phpMyAdmin, 3306 MySQL, 6379 Redis) dış ağa (`0.0.0.0`) açık olduğunda doğrudan kaba kuvvet (brute-force) veya sıfır-gün (0-day) hedefi olur.
3. **TCP RST Bilgi Sızıntısı:** Bir porta yetkisiz erişim yapıldığında sunucunun TCP RST veya HTTP 401/403 dönmesi, saldırgana "burada bir servis çalışıyor" kanıtını verir.

---

## 2. ZMax Çekirdek Çözümü: `zmax-security::port_cloak`

ZMax Server çekirdeğine entegre edilen **Port Cloaking Motoru**, 4 aşamalı bir hayalet savunma hattı uygular:

```text
               Dış Ağ İstemcisi / Port Tarayıcısı (Nmap, Masscan, Bot)
                                        │
                                        ▼
                  +-------------------------------------------+
                  |  1. Çekirdek Katmanı: nftables / Stealth  |
                  |     - Sadece Port 80 ve 443 Dış Ağa Açık  |
                  |     - Diğer Portlara Gelen Paketler: DROP |
                  +-------------------------------------------+
                                        │ (80 / 443 Trafiği)
                                        ▼
                  +-------------------------------------------+
                  |  2. ZMax Port Cloak: Silent Drop Kalkanı  |
                  |     - Bilinmeyen Host / Yetkisiz Tarayıcı |
                  |     - HTTP Yanıtı YOK -> Anında TCP Drop  |
                  +-------------------------------------------+
                                        │ (Geçerli Alan Adı)
                                        ▼
                  +-------------------------------------------+
                  |  3. Banner Stripping & Parmak İzi Silici  |
                  |     - Server: Başlığı Temizlendi / Sahte  |
                  |     - X-Powered-By / X-LiteSpeed SİLİNDİ  |
                  +-------------------------------------------+
                                        │ (Ters Vekil / İç İletişim)
                                        ▼
                  +-------------------------------------------+
                  |  4. Loopback / Unix Domain Socket Hapsi   |
                  |     - 19485, 19486, 8035, 8091 YALNIZCA   |
                  |       127.0.0.1 Üzerinde Dinler (No-WAN)  |
                  +-------------------------------------------+
```

---

## 3. Temel Savunma Prensipleri

### 3.1 Sessiz Düşürme (Silent Drop)
- Yetkisiz veya şüpheli tarama paketlerine HTTP hata sayfası (400, 401, 403, 404) veya TCP RST dönülmez.
- `socket.shutdown()` veya paket seviyesinde `DROP` uygulanır.
- **Sonuç:** Nmap ve tarayıcılar portu `Filtered / Stealth` olarak raporlar; portun açık mı kapalı mı olduğu dahi anlaşılamaz.

### 3.2 Banner Stripping & Honeypot Maskeleme
- `crates/zmax-security/src/port_cloak.rs` içindeki `cloak_response_headers` fonksiyonu ile:
  - `X-Powered-By`, `X-LiteSpeed`, `X-Turbo-Charged-By`, `X-AspNet-Version` vb. başlıklar otomatik budanır.
  - `Server` başlığı ya tamamen kaldırılır ya da isteğe bağlı olarak jenerik bir etiketle (ör. `cloudflare`) maskelenir.

### 3.3 Dinamik Port Knocking & SPA (Single Packet Authorization)
- Yönetim arayüzüne veya WebAdmin portuna dışarıdan erişmek isteyen yetkili yönetici:
  - `https://panel.ommicode.com/zmax-stealth-knock?key=<kriptografik_anahtar>`
  çağrısını yapar.
  - ZMax çekirdeği istemcinin IP'sini bellekte (`authorized_knock_ips`) 3.600 saniye boyunca yetkili işaretler.
  - Bu süre boyunca yönetici portlara erişebilir; süresi dolduğunda veya anahtarsız IP'ler için portlar tamamen hayalettir.

### 3.4 Loopback ve Unix Domain Socket İzolasyonu (Port Ghosting)
- Yönetim ve arka uç portları dış ağ arabirimlerine (`0.0.0.0`) **ASLA BAĞLANMAZ**:
  - `[listeners.admin]` -> `address = "127.0.0.1"`, `port = 19485`
  - `[listeners.api]` -> `address = "127.0.0.1"`, `port = 19486`
  - `zPanel Node.js Backend` -> `127.0.0.1:8035`
  - `phpMyAdmin Local` -> `127.0.0.1:8091`
- Dış dünyaya yalnızca standart **Port 80 (HTTP)** ve **Port 443 (HTTPS)** açıktır. Tüm iç servisler ZMax'in güvenli ters vekili (Reverse Proxy) üzerinden, sıkı SNI ve alan adı doğrulamasıyla sunulur.

---

## 4. Sunucu Seviyesinde nftables / iptables Hayalet Kuralları

Sunucu seviyesinde port kabuklarını gizlemek için uygulanan standart kurallar:

```bash
# 1. Mevcut bağlantılara izin ver
nft add rule inet filter input ct state established,related accept

# 2. Yerel loopback (127.0.0.1) tam serbest
nft add rule inet filter input iif "lo" accept

# 3. Yalnızca meşru web portlarına izin ver
nft add rule inet filter input tcp dport { 80, 443 } accept

# 4. SSH için (örnek yönetim portu 22)
nft add rule inet filter input tcp dport 22 accept

# 5. DİĞER TÜM DIŞ PORTLARI SESSİZCE YUT (REJECT DEĞİL, DROP!)
# REJECT portun varlığını açık eder; DROP portu tamamen görünmez yapar!
nft add rule inet filter input meta l4proto tcp drop
```

---

## 5. ZMax Çekirdek Yapılandırması (`zmax.toml`)

```toml
[security]
# Port ve kabuk gizleme kalkanı
port_cloaking = true
stealth_silent_drop = true
strip_server_banner = true
fake_server_banner = ""
knock_secret = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
knock_ttl_sec = 3600

# Dış ağa kapalı, yalnızca loopback dinleyiciler
[listeners.admin]
address = "127.0.0.1"
port = 19485
enabled = true

[listeners.api]
address = "127.0.0.1"
port = 19486
enabled = true
```

---

## 6. Doğrulama ve Test Kanıtı

1. **Birim Testleri (`cargo test -p zmax-security`):**
   - `test_banner_stripping_and_masking` -> **PASS**
   - `test_loopback_always_authorized` -> **PASS**
   - `test_remote_ip_requires_knock` -> **PASS**
2. **Canlı Sunucu Doğrulaması (`13.143.223.6`):**
   - `ss -tulpn`: 19485, 19486 ve 8035 portları `127.0.0.1` dışında hiçbir arabirimde dinlememektedir.
   - Bilinmeyen veya sahte Host istekleri `403 Forbidden - Unknown Host` veya `Silent Drop` ile sonlandırılmaktadır.

