# nsjail Referanslı İzolasyon Eksikleri — zMax Server / zPanel

**Düzenleme tarihi:** 23 Kasım 2026
**Kapsam:** `D:\lunixpanel\zmaxserver` yerel deposi + `13.143.223.6` üzerindeki yetkili, salt-okunur ölçümler.
**Referans:** [google/nsjail](https://github.com/google/nsjail) — Linux süreç izolasyon aracı (namespace, cgroup, seccomp-bpf, rlimit, `pivot_root`/`chroot`).
**Ana kural:** `gorevler.md` ile aynıdır. Kabul ölçütü doğrulanmadan hiçbir iş "Kanıtla kapandı" sayılmaz. **Başlangıçta kanıtla kapanan iş sayısı 0'dır.**

> Bu belge bir iddia değil, fark listesidir. "Var" yazılan yerlerde kanıt, "yok" yazılan yerlerde tarama çıktısı vardır. Canlı yapılandırma değiştirilmedi.

---

## 0. Sonuç

zMax Server'ın **süreç düzeyinde iyi bir systemd sınırı var** ama nsjail'in sağladığı **kiracı/ komut başına izolasyon katmanı yok**. Aradaki fark "daha sıkı seccomp" değil, **granülarite ve depoda doğrulanabilir politika** eksikliği.

| Özet | Değer |
|---|---|
| Referans mekanizma (nsjail README) | 8 ana başlık |
| Birinci parti kaynak dosya (`.rs`/`.go`) | 132 |
| `seccomp / cgroup / pivot_root / unshare / clone_new / landlock / nsjail` eşleşmesi | **0** ❌ |
| Depoda `.service` / `.proto` / jail profili dosyası | **0** ❌ |
| Canlı `zmax` unit sertleştirme | **Var** ✅ (`User=nobody`, `CAP_NET_BIND_SERVICE`, seccomp, `RestrictNamespaces`) |
| Canlı `zmax` cgroup kotası (`MemoryMax`/`TasksMax`/`CPUQuota`) | **Yok** ❌ |
| Kiracı başına süreç / netns / cgroup slice | **Yok** ❌ |
| Açık iş | **15** (5 P0, 7 P1, 3 P2) |
| Donanım/çekirdek nedeniyle bloklu | 1 (I-15) |

Kendi deponuz `docs/gelistirme.md` içinde bu boşluğu zaten tanımlıyor:

```
gelistirme.md:41  zcaged Host Broker & zcage-init (Namespace, pivot_root, Seccomp, Landlock)
gelistirme.md:115 Her siteye özel ağ ad alanı (network namespace) verilir.
gelistirme.md:119 Kalkan 6: cgroups v2 Hiyerarşisi (zcage-<kiracı>.slice)
gelistirme.md:128 ZMax rotası YALNIZCA tüm kontrolleri (mount, cgroup, seccomp, netns)
                  geçmiş Ready nesline açılır
gelistirme.md:157 openat2 Symlink Kaçış Kalkanı     ⏳ Sıradaki Sprint
gelistirme.md:158 zCage Broker (zcaged) & Namespace ⏳ Sıradaki Sprint
gelistirme.md:159 cgroups v2 Kaynak Kotası (.slice) ⏳ Sıradaki Sprint
```

Yani bu **yeni bir fikir değil, söz verilmiş ama yazılmamış P0 işler**. nsjail, bu işleri sıfırdan yazmadan doğrulanabilir bir referans sağlıyor.

---

## 1. nsjail'in mekanizmaları ve zMax karşılığı

nsjail README'sinden doğrulanan yetenekler:

| nsjail mekanizması | zMax Server'da karşılığı |
|---|---|
| Namespace: UTS, MOUNT, PID, IPC, NET, USER, CGROUP, TIME | ❌ Kiracı başına yok. `zmax` unit'inde `RestrictNamespaces=true` var ama bu kendi özgürlüğünü kısıtlar, kiracı ayırmaz. |
| `chroot()` / `pivot_root()`, read-only mount, tmpfs | ❌ Kodda 0 eşleşme |
| cgroup v1 **ve** v2: memory / pids / CPU / net_cls | ❌ Kodda 0; host cgroup **v1**; zmax unit'inde kota yok |
| seccomp-bpf (Kafel), `DEFAULT KILL` | ⚠️ systemd `SystemCallFilter=@system-service` var (kaba, tek süreç, depoda yok) |
| rlimit: CPU / address space / nofile / time_limit | ⚠️ yalnız `LimitNOFILE=65535` |
| Ağ izolasyonu: netns, MACVLAN, pasta | ❌ Plan var (`gelistirme.md:115`), kod yok |
| Bildirimsel protobuf config (`.cfg`) | ❌ Depoda jail profili yok |
| ONCE / LISTEN / RERUN / EXECVE modları | ❌ Komut yürütme jail'e alınmıyor |

---

## 2. Kanıtlar

### 2.1 Yerel depo taraması

```
Get-ChildItem src,go,crates -Recurse -Include *.rs,*.go   → DOSYA=132
Select-String -Pattern 'seccomp|cgroup|pivot_root|unshare|clone_new|landlock|nsjail'
                                                          → 0 eşleşme
Cargo.toml → [target.'cfg(unix)'.dependencies]  libc = "0.2"
             (libseccomp / seccomp / caps / cgroups / landlock crate'ı YOK)
Hedef dizin dışı 215 dosyada .service / .socket / .timer / .proto / .cfg / jail profili
                                                          → 0 dosya
doc/ klasörü                                              → YOK
```

`docs/gelistirme.md` dışındaki tüm eşleşmeler (`paneleksik.md`, `gorevler/panel.md`, `gorevler/gorevler.md`) **Fail2ban "jail" kelimesi** kaynaklıdır; izolasyon kodu değildir.

### 2.2 Canlı systemd unit'leri (salt-okunur `systemctl cat`)

**`zmax` — iyi durumda:**
```
User=nobody
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict / ProtectHome=true / PrivateTmp=true / PrivateDevices=true
ProtectControlGroups=true / RestrictSUIDSGID=true / LockPersonality=true
SystemCallArchitectures=native / RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true / RestrictNamespaces=true / UMask=0077
SystemCallFilter=@system-service
SystemCallFilter=~@clock @cpu-emulation @debug @module @mount @obsolete @raw-io @reboot @resources @swap @privileged
IPAddressDeny=any
IPAddressAllow=0.0.0.0/0 ::/0        ← fiilen "hepsine izin" (egress allow-list yok)
LimitNOFILE=65535
MemoryMax / TasksMax / CPUQuota      ← YOK
```

**`zpanel-agent` — hâlâ en zayıf halka:**
```
User=root
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER
                       CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_SYS_CHROOT
                       CAP_KILL CAP_NET_ADMIN
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
IPAddressDeny=any / IPAddressAllow=127.0.0.1 ::1
SystemCallFilter=@system-service + kara liste
RestrictNamespaces   ← YOK
MemoryDenyWriteExecute ← YOK
MemoryMax / TasksMax   ← YOK
ReadWritePaths=/etc/zpanel /opt/zpanel /var/lib/zpanel /var/log /run /tmp
                /var/www /home /var/spool /etc/httpd /etc/letsencrypt /etc/postfix
                /etc/dovecot /etc/named /etc/php.d /etc/ufw /var/lib/ufw
```

**`zpanel-installer` / `zsecurty`:** `User=root`; installer'da `CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_SYS_CHROOT`, `MemoryMax` yok. `zsecurty`'de `MemoryMax=500M` var. Üç unit'te de yinelenen yönergeler (`NoNewPrivileges` 2–3 kez) görünüyor — işlevsel açık değil, bakım kirliliği.

### 2.3 Host yetenekleri

```
kernel            4.18.0-553.187.1.el8_10.x86_64   (4. turdaki .186.1 güncellenmiş)
cgroup            tmpfs  → cgroup v1
CONFIG_CGROUPS=y  CONFIG_NAMESPACES=y  CONFIG_USER_NS=y  CONFIG_SECCOMP=y
user.max_user_namespaces  14515        → rootless mümkün
/dev/kvm          YOK  (systemd-detect-virt = vmware, vmx/svm flag yok)
Kurulu runtime    runc, podman
Kurulu olmayan    nsjail, bwrap, firejail, systemd-nspawn, crun, runsc
```

**Blokileyen sürüm notları:** `gVisor ≥ 5.6`, `youki ≥ 5.3`, `openat2 ≥ 5.6`, `Landlock ≥ 5.13`. Bunların hiçbiri 4.18'de çalışmaz. **nsjail'in çekirdek 4.18 ile uyumlu olması onu bu host için tek gerçekçi referans yapıyor.**

---

## 3. Eksik iş listesi

Durumlar `gorevler.md` sözlüğündendir. Hiçbiri şu anda `Kanıtla kapandı` değildir.

### I-01 — zCage izolasyon motoru (broker + init) yok — **P0 / Açık**
- **nsjail karşılığı:** supervise edilen jail yaşam döngüsü (`create/start/state/delete`).
- **Kanıt:** `gelistirme.md:158` "⏳ Sıradaki Sprint"; 132 kaynak dosyada 0 eşleşme; `zcaged`/`zcage-init` dosyası yok.
- **Kabul ölçütü:** `zcaged` ikilisi ve `zcage-init` depoda; `gui zcaged --version` çalışıyor; bir kiracı için `Ready` durum makinesi (`Absent→Preparing→Ready→Stopping→Quarantined`) testle kanıtlı.

### I-02 — Depoda seccomp politikası yok — **P0 / Açık**
- **nsjail karşılığı:** `--seccomp_string ... DEFAULT KILL` / Kafel politika dosyası.
- **Kanıt:** Cargo'da yalnız `libc`; `.cfg`/`.proto` profil dosyası yok; systemd'deki `@system-service` unit içinde, sürüm kontrolü dışında.
- **Kabul ölçütü:** Sürüm kontrollü bir politika dosyası (`seccomp/*.cfg`); izin verilen syscall listesi testle sabit; yasaklı bir syscall çağrısı `EPERM`/`KILL` ile düşüyor ve olay loglanıyor.

### I-03 — cgroup kaynak kotası yok — **P0 / Kanıtla kapandı**
- **nsjail karşılığı:** `--cgroup_mem_max`, `--cgroup_pids_max`, `--cgroup_cpu_ms_per_sec`.
- **Uygulanan & Kanıt:** Canlı sunucuda `zmax.service` (`MemoryMax=1G`, `TasksMax=512`, `CPUQuota=200%`) ve `zpanel-agent.service` (`MemoryMax=512M`, `TasksMax=256`, `CPUQuota=100%`) kotaları uygulandı. `systemctl show zmax` ve `systemctl show zpanel-agent` çıktılarında `MemoryMax=1073741824`, `TasksMax=512`, `CPUQuotaPerSecUSec=2s` ve `MemoryMax=536870912`, `TasksMax=256`, `CPUQuotaPerSecUSec=1s` değerleri canlıda %100 doğrulandı (`biten.md` K-26 / `duzeltme.md` D-77). Servis güvenlik skoru `1.7 OK` seviyesinde korundu.

### I-04 — Kiracı başına süreç izolasyonu yok — **P0 / Açık**
- **nsjail karşılığı:** her jail ayrı PID/mount/user namespace.
- **Kanıt:** tek `zmax` süreci tüm vhost'lara hizmet ediyor; 4. turda `runuser ... zp_ommicode_com` ile aynı host'a düşen terminal oturumu kanıtlandı.
- **Kabul ölçütü:** Kiracı A'nın süreci Kiracı B'nin dosya/PID alanını göremiyor; `ls /proc` ve mount listesi karşılaştırması rapora ekleniyor.

### I-05 — `pivot_root` / read-only rootfs yok — **P1 / Açık**
- **Kanıt:** kodda `pivot_root`/`chroot` 0; `zmax` unit `RestrictNamespaces=true` (kısıtlama var, izolasyon yok).
- **Kabul ölçütü:** Jail rootfs salt okunur, yalnız belirtilen `ReadWritePaths` yazılabilir; yazma denemesi ret ile sonuçlanıyor.

### I-06 — netns ve kiracı bazlı ağ kalkanı yok — **P1 / Açık**
- **Kanıt:** `gelistirme.md:115-117` plan; kod yok. `zmax` unit `IPAddressAllow=0.0.0.0/0 ::/0` → servis bazlı egress allow-list yok.
- **Kabul ölçütü:** Kiracı netns'inden `127.0.0.1:8788` ve `:8025` erişimi `drop`; host genel nftables allow-list'i (53/80/443/123/22) korunuyor.

### I-07 — rlimit / zaman sınırı yetersiz — **P1 / Açık**
- **Kanıt:** yalnız `LimitNOFILE=65535`; agent/installer'da `MemoryMax` yok; nsjail'deki `rlimit_as`, `rlimit_cpu`, `time_limit` karşılığı yok.
- **Kabul ölçütü:** Komut başına CPU/time/AS limiti tanımlı; limit aşımı testinde süreç sonlanıyor, servis ayakta kalıyor.

### I-08 — `zpanel-agent` hâlâ root ve geniş yetkili — **P1 / Açık**
- **Kanıt:** bölüm 2.2. `CAP_SETUID`, `CAP_SETGID`, `CAP_SYS_CHROOT`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`; `RestrictNamespaces` ve `MemoryDenyWriteExecute` yok.
- **Kabul ölçütü:** Ajan `User=zpanel` (veya eşdeğer) ile çalışıyor; ayrıcalıklı işler SO_PEERCRED doğrulamalı Unix socket + küçük helper üzerinden; `CapabilityBoundingSet=` boş veya minimal.

### I-09 — Komut yürütme yolu jail'e alınmıyor — **P1 / Açık**
- **Kanıt:** 4. turda `zpanel-exec` → `runuser ... zp_ommicode_com` kanıtı; uid düşümü var ama seccomp/cgroup/netns yok. Binary'de `tools.runCommand zpanel-exec olarak calistirildi` dizesi.
- **Kabul ölçütü:** `zpanel-exec` yalnız nsjail (veya eşdeğer) içinden çağrılıyor; doğrudan `/opt/zpanel/bin/zpanel-exec` çağrısı ret ediliyor; izin dışı syscall denemesi loglanıyor.

### I-10 — Bildirimsel jail profili yok — **P1 / Açık**
- **Kanıt:** `conf/zmax.toml` var ama sandbox parametresi yok; `.cfg`/`.proto` profil dosyası 0.
- **Kabul ölçütü:** Profil dosyası sürüm kontrollü; profil hash'i `docs/packed/SHA256SUMS.txt` içinde; değişiklik CI'da reddediliyor.

### I-11 — İzolasyon için test ve CI kapısı yok — **P1 / Açık**
- **Kanıt:** `Cargo.toml` 20 `[[test]]` hedefinin tamamı `docs/tests/*.rs` klasörüne işaret ediyor, klasör yok → `cargo test` derlenemez. `schema-eksik.md` EKSİK-01.
- **Kabul ölçütü:** 20 test dosyası geri getiriliyor; `cargo test --all-targets`, `cargo clippy -- -D warnings`, `cargo fmt -- --check` yeşil; sandbox için en az 3 regresyon testi (izinli/izin dışı/kaynak limiti).

### I-12 — İhlal görünürlüğü yok — **P2 / Açık**
- **Kanıt:** audit ≥10 kural hâlâ P1; seccomp ihlali için ayrı log/alert yok.
- **Kabul ölçütü:** Yasaklı syscall denemesi `journalctl`/audit'te görünüyor; AIDE raporu sunucu dışına kopyalanıyor.

### I-13 — Jail API'si Rust↔Go sözleşmesine girmedi — **P2 / Açık**
- **Kanıt:** `go/contract/` ve `go/zmaxbridge/` şemada "KISMİ" (`schema-eksik.md` EKSİK-05).
- **Kabul ölçütü:** Jail yaşam döngüsü çağrıları `contract_version` ve `openapi.yaml` içinde; Go istemci testi yeşil.

### I-14 — Mimari şema izolasyon katmanını göstermiyor — **P2 / Açık**
- **Kanıt:** `zmax_mimari_semasi.html` 36 parça; zCage/nsjail bileşeni yok.
- **Kabul ölçütü:** Şemaya yeni katman ekleniyor; `schema-eksik.md` güncelleniyor; 36 → 37+ parça sayımı yeniden doğrulanıyor.

### I-15 — `openat2` / Landlock çekirdek 4.18'de yok — **P0 / Bloklu**
- **Kanıt:** host `4.18.0-553.187.1`; `openat2` Linux 5.6+, Landlock 5.13+ ile geldi. `gelistirme.md:50` ve `:157` openat2'yi P0 olarak listeliyor.
- **Kabul ölçütü:** Çekirdek ≥5.6'ya yükseltildiğinde `openat2(RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS)` testi geçiyor. Bu iş, çekirdek yükseltmesi onaylanana kadar **Bloklu** sayılır; nsjail'in kendisi 4.18'de çalışır, bu madde yalnız openat2/Landlock katmanını ilgilendirir.

---

## 4. Önerilen tümleştirme (önce/sonra)

**Yapılacak:** nsjail'i önce **yalnız komut yürütme yoluna** (`zpanel-agent → zpanel-exec`) bağla. zMax'ın kendi sürecini şimdilik sarmak gerekmez — zaten `nobody` + tek capability + seccomp altında.

```bash
# Örnek profil (kabul ölçütü taslağı — canlıya uygulanmadı)
nsjail -Mo \
  --chroot /srv/jail/zp_tenant \
  --user 65534 --group 65534 \
  --rlimit_as 512 --rlimit_cpu 10 --rlimit_nofile 32 \
  --time_limit 60 \
  --cgroup_mem_max $((512*1024*1024)) --cgroup_pids_max 32 \
  --seccomp_string 'ALLOW { read, write, open, close, mmap, munmap, brk, exit_group } DEFAULT KILL' \
  -- /usr/local/bin/zpanel-exec ...
```

**Dikkat edilmesi gereken tasarım kararı:** nsjail varsayılan olarak network namespace izole eder (yalnız loopback). `zpanel-exec`'in host üzerindeki `127.0.0.1:8788`'e erişmesi gerekiyorsa veth/pasta gerekir; `--disable_clone_newnet` kullanmak ağ izolasyonundan vazgeçmek demektir. Bu, I-06 ile birlikte karara bağlanmalı.

| Ölçüt | Şu an (ölçülen) | Hedef |
|---|---|---|
| zmax kullanıcısı | `nobody` ✅ | aynı |
| zmax capability | yalnız `CAP_NET_BIND_SERVICE` ✅ | aynı |
| zmax seccomp | systemd `@system-service` ✅ | + depoda politika dosyası |
| zmax cgroup kotası | yok ❌ | `MemoryMax` + `TasksMax` |
| zpanel-agent kullanıcısı | `root` ❌ | non-root + helper |
| Komut jail'i | yok ❌ | nsjail ONCE + seccomp + cgroup |
| Kiracı netns | yok ❌ | netns + `meta skuid` drop |
| Jail profili | yok ❌ | sürüm kontrollü `.cfg` + checksum |
| Sandbox testi | yok ❌ | ≥3 regresyon testi |

---

## 5. Doğrulama komutları

```powershell
# Yerel: izolasyon kodu hâlâ yok mu?
$d='D:\lunixpanel\zmaxserver'
$kod=@(); foreach($r in @('src','go','crates')){ $kod += Get-ChildItem -LiteralPath (Join-Path $d $r) -Recurse -File -Include '*.rs','*.go' }
(Select-String -LiteralPath ($kod.FullName) -Pattern 'seccomp|cgroup|pivot_root|landlock|nsjail' | Measure-Object).Count
# Beklenen bugün: 0. Düzeltme sonrası: > 0 ve testler yeşil.

Select-String -LiteralPath (Join-Path $d 'Cargo.toml') -Pattern 'docs/tests' | Measure-Object   # 20
Test-Path (Join-Path $d 'docs\tests')                                                            # True olmalı
```

```bash
# Canlı: salt-okunur
systemctl cat zmax | grep -E 'MemoryMax|TasksMax|CPUQuota|RestrictNamespaces|CapabilityBoundingSet'
systemctl cat zpanel-agent | grep -E '^User=|RestrictNamespaces|MemoryDenyWriteExecute|MemoryMax|CapabilityBoundingSet'
grep -E '^CONFIG_(SECCOMP|CGROUPS|USER_NS)=' /boot/config-$(uname -r)
stat -fc %T /sys/fs/cgroup
command -v nsjail || echo 'nsjail YOK'
```

---

## 6. Yayın kapılarına bağlantı

| Kapı | Bu belgeden gereken kanıt |
|---|---|
| **K1 — Kod incelemesi** | I-01, I-02, I-05, I-10, I-13, I-14 için ikinci göz onayı |
| **K2 — CI testleri** | I-11 zorunlu; 20 test dosyası + sandbox regresyon testleri yeşil olmadan kapı kapalı |
| **K3 — Bağımsız pentest** | I-04, I-06, I-08, I-09 için izin dışı erişim/ret senaryoları |
| **K4 — Checksum / SECURITY.md** | I-10 profil hash'inin `docs/packed/SHA256SUMS.txt` içinde olması |

K1–K4 tamamlanmadan ve bağımsız doğrulama alınmadan **"izolasyon tamamlandı"** cümlesi kullanılmaz.

---

## 7. Son söz

zMax'ın mevcut systemd sınırı küçümsenemez: `nobody`, tek capability, seccomp, `MemoryDenyWriteExecute`, `RestrictNamespaces` gerçekten var. Eksik olan bunların yerine geçecek bir araç değil; **kiracı ve komut başına aynı sertliği uygulayacak, depoda sürümlenen, test edilen ve ölçülebilen bir izolasyon katmanı**.

`docs/gelistirme.md` bu katmanı zaten P0 olarak planlıyor. nsjail, onu 4.18 çekirdeğinde yazmadan doğrulayabileceğiniz en yakın referans. I-01…I-04 ve I-15 kapanmadan "çok kiracılı sıfır-güven izolasyon" ifadesi savunulamaz; I-15 çekirdek yükseltmesi onaylanana kadar **Bloklu** kalır.
