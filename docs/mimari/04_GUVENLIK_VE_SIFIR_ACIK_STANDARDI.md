# ZMax Güvenlik ve Sıfır Açık (Zero-Trust) Standardı (v3.0)

> v2.0'daki katman adları (`l2_validator`, `l3_security`, `l6_handlers`…) v3.0 adlarıyla değiştirilmiştir. Her satırda **Durum** sütunu vardır: `Var` = kodda doğrulandı, `Kısmi`, `Yok` = yeni yazılacak, `Doğrulanmadı` = koddan teyit edilemedi.

## 1. Felsefe
Gelen hiçbir istek (IP'si ne olursa olsun) doğrulanmadan güvenilir sayılmaz. Her yönetim işlemi API'den geçer; API'nin önünde tek kapı vardır.

## 2. Saldırı → Savunma Matrisi

| Tehdit | Önleyen parça | Savunma | Durum |
|---|---|---|---|
| Kimlik atlama | A1 `auth.rs` | Tek kapı; rota kendi token kontrolü yazmaz | Kilitlendi (A1 tek giriş) |
| Boş token ile açık API | A1 | `expected_token` boşsa dış ağ reddedilir, yalnız loopback izinli | Kilitlendi (Karar 2) |
| Zamanlama saldırısı | A1 | `constant_time_eq` (`api.rs:339`, sabit zamanlı karşılaştırma) | Var |
| Kaba kuvvet (token tahmini) | A2 `guard.rs` | 5 ardışık 401 sonrası IP 15 dk banlanır + API rate limit (429) | Kilitlendi (Zorunlu Kural) |
| Yetki yükseltme | A1 | Rol: `okuma` ve `yönetim` olmak üzere iki rol | Kilitlendi (Karar 1) |
| İzsiz değişiklik | A9 `audit.rs` | Her yazma işleminde `audit.log` kaydı (gizli alanlar hariç) | Kilitlendi (Zorunlu Kural) |
| Bozuk yapılandırma ile çökme | K3 | Doğrula → geçiciye yaz → atomik yer değiştir → hata varsa geri al | Kilitlendi (B4 / K3) |
| Path traversal (API) | A2 | `has_parent_dir_traversal` (`api.rs:923`) + null-byte kontrolü | Var |
| Path traversal (web) | L4 + L7 | WAF + `canonicalize` + `starts_with(document_root)` zorunlu sınır denetimi | Kilitlendi (Standart) |
| Webshell (uploads altında .php) | L4 | `/uploads/` ve `/wp-content/uploads/` altındaki `.php/.phtml/.phar` isteklerine 403 engeli | Kilitlendi (Standart) |
| Slowloris / soket tüketimi | L1 | `header_timeout`, `body_timeout`, `idle` zaman aşımı | Var (`web_engine.rs:1105-1152`) |
| HTTP flood | L4 | IP bazlı rate limit → 429 | Var |
| Sahte gerçek IP başlığı | L3 | `trusted_proxies` dışından gelen başlık yok sayılır | Var (`RealIpPolicy`) |
| Host/SNI sahteciliği | L2 | RFC 7230 Host + Strict SNI | Var (`1372`, `1391`) |
| PHP-FPM boğma | L7 | 503 + `Retry-After`, `backend_semaphores` | Var |
| Önbellek zehirleme | L6 | `build_cache_key` + vary; bypass çerezi/Authorization önbelleğe girmez | Var |
| Clickjacking / MIME / HSTS | L8 | Güvenlik başlıkları (`resolve_vhost_security_headers`) | Var |
| Çok sunuculu ban/purge senkronu | K7 | Yayın (`BanIp`, `UnbanIp`, `Purge*`, `ReloadConfig`) + K6 altında çalışan abone dinleyicisi | Kilitlendi (K7 Hedef) |
| Redis erişilemezken istek yolu | K7 + L4 | `spawn` + zaman aşımı (200 ms); istek beklemez, Redis hatası akışı düşürmez | Var (`web_engine.rs:1574`) |
| Redis şifresi/TLS sızması | K7 | Şifre log ve `Debug` çıktısından maskelenir (`#[debug(skip)]`), `use_tls` desteği | Kilitlendi (Standart) |
| Redis'e yetkisiz yazma | K7 | Yalnız `zmax:` önekli anahtarlar ve `zmax:cache:purge` kanalı; Redis yalnız 127.0.0.1 | Kilitlendi (Standart) |
| Token sızması (log/URL) | A2/K5 | Loga yazılmaz; WebAdmin `?token=` URL'den anında silinir | Kilitlendi |

## 3. Erişim Kanalı Tablosu (A1+A2 uygular)

| Kanal | Kimlik şartı | Ağ şartı | Genel (kimliksiz) uç nokta |
|---|---|---|---|
| Port 19486 (`api`) | `require_token` ve token (rol kontrollü) | Dış ağda token zorunlu; yalnız loopback izinli | `health` (yalnız loopback kimliksiz; dış ağ token şartı) (Karar 9) |
| Port 19485 (`admin`) | `require_token` ve token | Dış ağda token zorunlu | A7 statik dosya (kimliksiz), API yolları token'lı |
| Unix soketi | Dosya izni (0600) | Yalnız yerel | — |

**Kimliksiz Uç Noktalar Kuralı (Karar 9 ile kilitlendi):**
- `GET /api/v1/health`: Yalnızca `127.0.0.1`, `::1` ve Unix soketi üzerinden token'sız erişilebilir. Dış ağdan gelen tüm isteklerde token zorunludur.
- `GET /metrics` ve `GET /api/v1/metrics`: Kesinlikle `okuma` rolüne sahip geçerli bir token gerektirir; hariciye açık anonim metrik yasaktır.

## 4. A1/A2 Standartları (API sağlama alma)
1. **Tek kapı:** hiçbir rota token kontrolü yazmaz; `A1 → A2 → rota` sırası bozulmaz.
2. **Rol modeli (karar: `00` §7 madde 1):** `okuma` (status, metrics, logs, vhost listesi) ve `yönetim` (vhost yaz, purge, ban, reload, modül aç/kapa). zPanel ve WebAdmin ayrı token alır; biri sızarsa diğeri etkilenmez.
3. **Boş token kapısı:** `expected_token` boş ise `require_token` değerinden bağımsız olarak dış ağdan gelen istek reddedilir; yalnız loopback izinlidir (karar: `00` §7 madde 2).
4. **Hot-reload:** SIGHUP'ta mevcut tokenlar korunur (`compute_effective_auth`, test: `compute_effective_auth_preserves_tokens_on_hot_reload`).
5. **Değişiklik güvenliği:** vhost/config yazımı = doğrula → geçici dosyaya yaz → atomik yer değiştir → reload → başarısızsa eski dosyaya dön.
6. **Denetim:** A9, tüm yazma işlemlerini kaydeder; token ve gizli değer yazılmaz.
7. **Girdi doğrulama:** `:domain` parametresi alan adı biçimine uymalı, `..`/null-byte reddedilir; JSON gövde boyut sınırı vardır.
8. **Hata yanıtı:** hata mesajı iç yol, yığın izi veya yapılandırma içeriği sızdırmaz.

## 5. Boru Hattı Standartları
- **L1:** IP başına eşzamanlı bağlantı sınırı ve zaman aşımları; sınır aşılırsa soket sessizce kapatılır veya 429.
- **L2:** `Host` yok/çift → 400; header/body sınırı → 413; Strict SNI uyuşmazlığı → 421.
- **L3:** gerçek IP yalnız `trusted_proxies` kaynaklı başlıktan çözülür; çözüm tek fonksiyonda yapılır (şu an `web_engine.rs` 1245 ve 1347'de tekrar ediyor).
- **L4:** loopback rate limit'ten muaf, WAF'tan muaf değil; `/xmlrpc.php` varsayılan kapalı.
- **L5:** `force_https` ACME HTTP-01 yolunu bozmaz (muaf).
- **L7:** `SCRIPT_FILENAME` yalnız doğrulanmış `document_root` içinden; statik dosya `canonicalize` sonrası kök dışına çıkamaz.

## 6. Bellek ve Kararlılık
- Büyük nesneler `Arc<T>` ile paylaşılır, kopyalanmaz.
- Sonsuz büyüyen koleksiyon yok; önbellek ve sayaçların TTL/LRU/üst sınırı vardır.
- Çekirdek kodda `.unwrap()`/`.expect()` yoktur; hata `Result` ile taşınır. (Mevcut kodda kaç tane olduğu taşıma sırasında taranır.)
- Her bekleme (ağ, havuz, kilit) zaman aşımına sahiptir.

## 7. Kabul Ölçütü (her parça için)
Parça "bitti" sayılmadan önce: ilgili `cargo test -p zmax-bin <test>` çıktısı, bu belgedeki ilgili satırın **Durum** sütunu `Var`a çevrilmiş ve çıktı kayda geçmiş olmalı.
