# ZMax & zPanel — Aktif Görev Listesi (gorevler.md)
**Son Güncelleme:** 2026-11-23 14:05  
**Kaynak Raporlar:** `D:\lunixpanel\testler` (`eksikler.md`, `eksik2.md`, `guvenlik2.md`, `sontest.md`, `testraporu.md`, `yayin-oncesi-dogrulama.md`) ve `D:\lunixpanel\testler\eksik\paneleksik.md`

---

## 1. Ekip Rol Dağılımı (7 Coder + 3 Tester + 1 Proje Yöneticisi)

- **Proje Yöneticisi:** Mimari koordinasyon, görev dağıtımı, `duzeltme.md` yönetimi ve 4/4 yayın kapısı denetimi
- **Coder 1 (Firewall & Güvenlik Duvarı):** UFW kural ekleme/kaydetme, kalıcılık ve log entegrasyonu (TAMAMLANDI)
- **Coder 2 (Panel Arayüz & SPA Derin Bağlantı):** SPA routing Fallback ve WordPress alt sekme optimizasyonları (TAMAMLANDI)
- **Coder 3 (API & Token Güvenliği):** Token zorunluluğu (E-04: `/api/version` ve `/api/v1/health` 401 kilitlenmesi, unauthenticated `/healthz` ayrımı) (TAMAMLANDI)
- **Coder 4 (Ajan İletişimi & Servis Senkronizasyonu):** Ajan durum eşitlemesi (Hizmet Yönetimi, Dosya Yöneticisi, Terminal, Fail2ban "Sunucu yanıt vermiyor" giderimi) (TAMAMLANDI)
- **Coder 5 (Frontend Güvenliği & Çerez Mimarisi):** Token'ların `localStorage` yerine `HttpOnly, Secure, SameSite=Strict` çerezlere taşınması (E-05), WAF ve Composer uçları
- **Coder 6 (İşletim Sistemi, SSH & Ağ Sıkılaştırma):** SSH `MaxAuthTries 3` (E-09), IPv6 `accept_ra = 0` (E-10), Egress kısıtlama politikası (E-05) (TAMAMLANDI)
- **Coder 7 (Denetim, Bütünlük & Otomasyon):** Auditd ≥12 kural (E-11), `aide-check.timer` (E-12), `dnf-automatic` (E-13), TLS anahtar izinleri 640 (E-14) (TAMAMLANDI)
- **Tester 1 (Kernel & Yeniden Başlatma Dayanıklılığı):** Çekirdek 186.1 reboot ve kalıcılık testleri (E-06 / T-01) (TAMAMLANDI)
- **Tester 2 (Panel Fonksiyonel & Entegrasyon Testleri):** `paneleksik.md` 19 maddenin ve UFW kural testlerinin uçtan uca doğrulanması (T-02) (TAMAMLANDI)
- **Tester 3 (Güvenlik, İzolasyon & Yayın Kapıları Kabulü):** `dogrula.sh` (6/6 PASS), dış port taraması, non-root terminal denetimi (T-03) (TAMAMLANDI)

---

## 2. Yapılan İşler (Kapanan ve Doğrulanan Maddeler)

| No | Modül / Madde | Kapsam | Durum | Somut Kanıt |
|---|---|---|---|---|
| K-01 | Terminal Root İzolasyonu | `s.User == "root"` engellendi, `eval "$1"` kaldırıldı, `zpanel-exec` eklendi | ✅ TAMAMLANDI | Go 1.26 ile derlendi (`/opt/zpanel/bin/zpanel-agent`, 20.7 MB, 23.11 08:11), strings taramasında root kabuk kalıntısı yok |
| K-02 | SSH Parola Kapatılması | `PermitRootLogin without-password`, `PasswordAuthentication no`, `X11Forwarding no` | ✅ TAMAMLANDI | `/etc/ssh/sshd_config` uygulandı; `sshd -T` ile doğrulandı, yalnız `id_ed25519` yetkili |
| K-03 | zMax Hardening | `User=nobody`, tek capability (`CAP_NET_BIND_SERVICE`), `MemoryDenyWriteExecute=true` | ✅ TAMAMLANDI | `systemd-analyze security zmax` skoru **1.7 OK** (Hedef ≤ 2.0 sağlandı) |
| K-04 | Ağ Kalkanı (Hayalet Port) | nftables input DROP politikası; yalnız 22, 80, 443, 53, 123 portlarına izin | ✅ TAMAMLANDI | `nft list ruleset` aktif; yetkisiz portlar filtrelendi |
| K-05 | AIDE Bütünlük Kurulumu | `aide-0.16` kuruldu, 9.9 MB veri tabanı ilklendirildi | ✅ TAMAMLANDI | `/var/lib/aide/aide.db.gz` hazır |
| K-06 | DNF Güvenlik Güncellemeleri | 25 güvenlik bildirimi kapatıldı, güncel çekirdek kuruldu | ✅ TAMAMLANDI | `kernel-4.18.0-553.186.1.el8_10` kuruldu ve reboot ile devreye alındı |
| K-07 | Parola Politikası | Parola eskime ve karmaşıklık kuralları sıkılaştırıldı | ✅ TAMAMLANDI | `chage -M 90 -m 7 root`, `/etc/security/pwquality.conf` (minlen=12) aktif |
| K-08 | Servis Kafesleri (Drop-in) | `zpanel-agent`, `zsecurty`, `zpanel-installer` cage profilleri uygulandı | ✅ TAMAMLANDI | Ajan: 3.5 OK, Securty: 2.7 OK, Installer: 3.2 OK seviyesine çekildi |
| K-09 | Panel Canlı Yayın | DNS BIND port 53 nftables'a eklendi, yerel hosts tanımlandı | ✅ TAMAMLANDI | `https://panel.ommicode.com/` HTTP/2 200 OK ile yerelden doğrulanarak açıldı |
| K-10 | UFW Altyapısı | AlmaLinux üzerine UFW paketi kuruldu, temel kurallar eklendi | ✅ TAMAMLANDI | `ufw status verbose` active |
| K-11 | IPv6 Router Advertisement (E-10) | Router advertisement paketleri engellendi | ✅ TAMAMLANDI | `/etc/sysctl.d/99-zpanel-ipv6.conf` ile `net.ipv6.conf.all.accept_ra = 0` ve `default = 0` uygulandı |
| K-12 | Auditd ≥12 Kural (E-11) | 5 ek kritik denetim kuralı yüklendi | ✅ TAMAMLANDI | `/etc/audit/rules.d/99-zpanel.rules` yüklendi; aktif kural sayısı **14** oldu (`augenrules --load`) |
| K-13 | AIDE Zamanlayıcısı (E-12) | Haftalık dosya bütünlük tarama zamanlayıcısı kuruldu | ✅ TAMAMLANDI | `aide-check.service` ve haftalık `aide-check.timer` oluşturulup etkinleştirildi |
| K-14 | TLS Anahtar İzinleri (E-14) | Özel anahtar dosya izinleri 640 yapıldı | ✅ TAMAMLANDI | `/etc/zpanel/tls/*.pem` izinleri `640` ve sahiplik `root:nobody` yapıldı |
| K-15 | SSH MaxAuthTries (E-09) | Kaba kuvvet parola denemeleri 3 ile sınırlandı | ✅ TAMAMLANDI | `/etc/ssh/sshd_config` içine `MaxAuthTries 3` uygulandı |
| K-16 | WordPress Derin Bağlantı (P-15) | `/toolkits/wordpress/...` F5/doğrudan açılış 404 Not Found hatası giderildi | ✅ TAMAMLANDI | `apps/api/dist/static.js` regexi düzeltildi; `https://panel.ommicode.com/toolkits/wordpress/ommicode.com` 200 OK ile açılıyor |
| K-17 | Otomatik Güvenlik Güncellemesi (E-13) | `dnf-automatic` servisi kuruldu ve güvenlik moduna alındı | ✅ TAMAMLANDI | `apply_updates = yes`, `upgrade_type = security` ayarlandı, `dnf-automatic.timer` aktif |
| K-18 | Kernel 186.1 Reboot & Kalıcılık (E-06) | Sunucu kontrollü reboot edildi; açılışta yeni çekirdek ve servisler doğrulandı | ✅ TAMAMLANDI | `uname -r` -> `4.18.0-553.186.1.el8_10.x86_64`; zmax, api, ufw ve nftables ayakta |
| K-19 | Yayın Öncesi 6 Kabul Testi (T-03) | Bağımsız dış test paketi çalıştırıldı | ✅ TAMAMLANDI | 6/6 PASS: Health (200), Auth/Me (401), Terminal Exec (401), SNI localhost (403), HTTP->HTTPS (301), WP SPA (200) |
| K-20 | UFW Kural Ekleme & Kaydetme (G-01/P-20) | UFW kural ekleme arayüzü ve backend hatası giderildi | ✅ TAMAMLANDI | UFW kuruldu, `/var/log/ufw.log` ve `/var/lib/zpanel` izinleri sağlandı, `beUfw` tespiti aktif |

---

## 3. Yayın Kapısı Değerlendirmesi (4/4 PASS Durumu)

1. **K1 - Kod İncelemesi:** PASS (Terminal root zinciri kırıldı, eval "$1" temizlendi, SPA regex onarıldı, UFW backend sağlandı).
2. **K2 - Otomatik Test & Regresyon:** PASS (Kimliksiz istekler 401, health 200, SNI bypass 403, HTTP redirect 301).
3. **K3 - İzolasyon ve Servis Güvenliği:** PASS (zMax skoru 1.7 OK, zpanel-agent 3.5 OK, zsecurty 2.7 OK, installer 3.2 OK).
4. **K4 - Bütünlük ve Şeffaflık:** PASS (Auditd 14 kural, AIDE veritabanı ve timer aktif, güncel kernel devrede).
