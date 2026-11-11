## Kart 5 — Hotlink listesi + IP ACL (2026-11-12 02:50)

**Okunanlar:** `doc/AJAN_YAPISI.md`, `doc/ADIMLI_GELISTIRME_TAKIP.md` (Kart 5), `doc/BITTI.md`, `doc/YAPAY_ZEKA_KURALLARI.md`, `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\domainsec\apply_render.go`, `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\domainsec\apply_ip.go`, `crates/zmax-config/src/lib.rs`, `crates/zmax-security/src/lib.rs`, `crates/zmax-bin/src/web_engine.rs`, `crates/zmax-bin/src/main.rs`.

**Kural ve düzeltme kontrolü:**
- `AJAN_YAPISI.md` Ajan a05 dosya sahipliği sınırlarına tam uyuldu:
  - `crates/zmax-config/src/security_ext.rs` oluşturuldu.
  - `crates/zmax-security/src/hotlink.rs` ve `crates/zmax-security/src/acl.rs` oluşturuldu.
  - `crates/zmax-bin/src/web_engine.rs` dosyasında yalnızca tek bir çağrı satırı bağlandı (başında `// [kart-5] hotlink ve ACL kontrolü`).
  - Sahip olunmayan hiçbir dosyaya dokunulmadı (`modules_runtime.rs` vb. değiştirilmedi).
- Kaynak ve port sınırları kuralı:
  - Derleme ve testlerde `D:\zmaxserver-ajan\derleme-2.kilit` kullanıldı.
  - `CARGO_TARGET_DIR=D:\zmaxserver-ajan\target-a05` izole hedefi kullanıldı.
  - Test portları olarak HTTP 21050, HTTPS 21051, API 21052 kullanıldı (19480-19486 portlarına asla dokunulmadı).
  - Geçici dizin `D:\zmaxserver-ajan\tmp\a05` test sonrası tamamen temizlendi.

**Yapılan iş:**
1. `crates/zmax-config/src/security_ext.rs`: `HotlinkConfig` (`enabled`, `allowed_referers`, `extensions`) ve `VhostAclConfig` (`allow_ips`, `deny_ips`) şemaları tanımlandı. `VHostEntry` içine `#[serde(default)]` ile eklendi. Geriye dönük uyumluluk için `effective_hotlink()` ve `effective_acl()` yardımcıları sağlandı.
2. `crates/zmax-security/src/hotlink.rs`: Referer başlığı denetleyici motoru oluşturuldu. Boş referer (`None` veya `""`) doğrudan izinlidir (`RewriteCond %{HTTP_REFERER} !^$`). İzinli referer alan adları (`allowed_referers`, `*.ornek.com` wildcard ve `request_host` / `vhost_aliases`) ile eşleşiyorsa izin verilir; korunan uzantı (`.jpg`, `.png`, `.webp`, `.mp4` vb.) harici yabancı referer ile talep edilmişse `403 Forbidden` döner. Korunmayan uzantılar (`.html`, `.css` vb.) hotlink engeline takılmaz.
3. `crates/zmax-security/src/acl.rs`: `VhostAcl` tekil IP ve IPv4/IPv6 CIDR motoru oluşturuldu. `allow_ips` ve `deny_ips` hiyerarşisi (allow önceliği, deny engeli, sıkı beyaz liste kuralı) uygulandı.
4. `crates/zmax-bin/src/web_engine.rs`: Statik dosya hattında `// [kart-5] hotlink ve ACL kontrolü` ile `zmax_security::is_hotlink_blocked` çağrısı bağlandı.
5. Birim testleri (`zmax-config`: 22 test, `zmax-security`: 27 test) ve entegrasyon testleri (`integration_kart5`: 3 senaryo testi) yazıldı ve %100 yeşil tamamlandı.
6. Canlı sunucu (port 21050) üzerinde uçtan uca kabul testleri başarıyla doğrulandı.

**Gerçek durum (etiket):**
- `HotlinkConfig` ve `VhostAclConfig` TOML / JSON şeması → **INTEGRATION TESTED** (22/22 config testi geçti).
- Hotlink Referer ve uzantı denetimi → **INTEGRATION TESTED** (curl ile 403 ve 200 kanıtlandı).
- IP / CIDR ACL denetimi → **INTEGRATION TESTED** (curl ile engelli CIDR 403, allow istisnası 200 kanıtlandı).

**Kabul testleri (kartın):**
1. Birim ve paket entegrasyon testleri:
```powershell
$env:CARGO_TARGET_DIR = "D:\zmaxserver-ajan\target-a05"
cargo test -p zmax-security -p zmax-config
```
Çıktı:
```
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s (zmax-config)
test result: ok. 27 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s (zmax-security)
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s (integration_kart5)
```

2. Canlı Sunucu Hotlink Kabul Testi (HTTP Port: 21050):
- Yabancı referer ile resim talebi:
```powershell
curl.exe -s -i -H "Referer: http://baska.test/" http://127.0.0.1:21050/resim.jpg
```
Çıktı:
```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8
Content-Length: 34
Connection: keep-alive
Keep-Alive: timeout=65
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Server: zmaxserver

403 Forbidden - Hotlink Protection
```

- Kendi referer'ı ile resim talebi:
```powershell
curl.exe -s -i -H "Referer: http://127.0.0.1:21050/" http://127.0.0.1:21050/resim.jpg
```
Çıktı:
```http
HTTP/1.1 200 OK
Content-Type: image/jpeg
Content-Length: 22

RESIM_ICERIGI_KART5_OK
```

- Boş referer ile doğrudan resim talebi:
```powershell
curl.exe -s -i http://127.0.0.1:21050/resim.jpg
```
Çıktı:
```http
HTTP/1.1 200 OK
Content-Type: image/jpeg
Content-Length: 22

RESIM_ICERIGI_KART5_OK
```

- Yabancı referer ile korunmayan dosya türü (.html) talebi:
```powershell
curl.exe -s -i -H "Referer: http://baska.test/" http://127.0.0.1:21050/index.html
```
Çıktı:
```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 17

ANASAYFA_KART5_OK
```

3. Canlı Sunucu IP / CIDR ACL Kabul Testi (HTTP Port: 21050):
- Engelli CIDR (`127.0.0.0/8`) üzerinden istek:
```powershell
curl.exe -s -i http://127.0.0.1:21050/index.html
```
Çıktı:
```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8
Content-Length: 32
Connection: close
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Server: zmaxserver

403 Forbidden - IP Access Denied
```

- Allow listesi istisnası (`allow_ips = ["127.0.0.1"]`, `deny_ips = ["127.0.0.0/8"]`):
```powershell
curl.exe -s -i http://127.0.0.1:21050/index.html
```
Çıktı:
```http
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 17

ANASAYFA_KART5_OK
```

**Değişiklikler:**
- `crates/zmax-config/src/security_ext.rs` (yeni dosya): `HotlinkConfig`, `VhostAclConfig`, `default_hotlink_extensions`.
- `crates/zmax-config/src/lib.rs`: `security_ext` modülü, `VHostEntry.hotlink`, `VHostEntry.acl`, `effective_hotlink()`, `effective_acl()`.
- `crates/zmax-security/src/acl.rs` (yeni dosya): `VhostAcl`, `is_ip_allowed`.
- `crates/zmax-security/src/hotlink.rs` (yeni dosya): `is_hotlink_blocked`, `extract_referer_host`, `host_matches_pattern`, `is_extension_protected`, `HotlinkGuard`.
- `crates/zmax-security/src/lib.rs`: `pub mod acl`, `pub mod hotlink`, `pub use acl::*`, `pub use hotlink::*`.
- `crates/zmax-security/tests/integration_kart5.rs` (yeni dosya): Kart 5 kabul matrisi senaryo testleri.
- `crates/zmax-bin/src/web_engine.rs`: Tek çağrı satırı `// [kart-5] hotlink ve ACL kontrolü`.

**Güvenlik riski:** Yok. Referer çözümlemesinde host/port/scheme sanitization yapıldı, IP ve localhost adreslerinde sahte subdomain (`evil.127.0.0.1`) eşleşmeleri engellendi.
**Performans:** `extract_referer_host` ve `ip_matches_cidr_spec` sıfır heap ayrımı / hızlı bit maskesi ile çalışır; bellek tahsisi minimize edilmiştir.
**Kalan eksikler:** Yok.
**Kart dışı yapılan/dokunulan:** Yok.
**Tek sonraki adım:** Denetçi onayı bekleniyor.
