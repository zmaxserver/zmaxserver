# ⚡ ZPanel (Go) - ZMax Server (Rust) Entegrasyon Kılavuzu

> **Önemli Güncel Referans:** Gerçek **`zPanel v2` (`D:\lunixpanel\zpanelv2`)**, **`zpanel-tam` (`D:\lunixpanel\zpanel-tam`)** ve **popüler tüm hosting panelleriyle** %100 çakışmasız yeni **`19480–19486` port bloğu** + Evrensel REST API (`/api/v1/*`) sözleşmesi için ana dokümana bakın: [`zpanel-entegre.md`](file:///D:/zmaxserver/doc/zpanel-entegre.md)

Bu belge, **ZPanel (Golang)** kontrol panelinin **ZMax Server (Rust)** web sunucusu motoru ile haberleşmesini, sanal konak (vHost) yönetimini, WAF güvenlik olaylarının aktarımını ve önbellek kontrolünü sağlayan tüm entegrasyon adımlarını ve hazır Go kod yapılarını içerir.

---

## 1. Mimari İletişim Kanalları

ZPanel (Go) ile ZMax (Rust) arasında **üç temel kanal** üzerinden haberleşme sağlanır:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          ZPANEL (GOLANG)                               │
└──────────────┬─────────────────────────┬───────────────────────┬───────┘
               │                         │                       │
      1. Dosya Sistemi           2. Yerel IPC Soket        3. Redis / Kanal
      (vHost TOML Yazımı)        (REST API / UDS)          (Pub/Sub & IP Sync)
               │                         │                       │
               ▼                         ▼                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         ZMAX SERVER (RUST)                             │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Deklaratif Dosya Sistemi:** ZPanel, her alan adı için `conf/vhosts/[domain].toml` dosyası üretir.
2. **Yerel IPC / REST Soketi:** `http://127.0.0.1:19486` (Evrensel Kontrol API) veya `/run/zmax/api.sock` üzerinden telemetri okur, vHost CRUD uygular, reload ve önbellek temizliği yapar. (`WebAdmin GUI` ayrıca `127.0.0.1:19485` üzerinden çalışır.)
3. **Güvenlik & Sinyalizasyon:** ZMax'in engellediği saldırgan IP'ler Go tarafına iletilir; Go bu IP'leri Linux `iptables` / `nftables` duvarına işler.

---

## 2. Sanal Konak (vHost) Üretimi

ZPanel'de bir müşteri yeni bir alan adı açtığında, Go servisi ZMax'in vHost dizinine ilgili TOML dosyasını yazar.

### Go vHost Veri Modeli (`vhost.go`):

```go
package zmax

import (
	"fmt"
	"os"
	"path/filepath"
	"github.com/pelletier/go-toml/v2"
)

type VHostConfig struct {
	VHost struct {
		Name         string   `toml:"name"`
		Aliases      []string `toml:"aliases"`
		DocumentRoot string   `toml:"document_root"`
		IndexFiles   []string `toml:"index_files"`
	} `toml:"vhost"`
	Cache struct {
		Enabled bool `toml:"enabled"`
		Expire  int  `toml:"expire"`
	} `toml:"vhost.cache"`
	PHP struct {
		Enabled  bool   `toml:"enabled"`
		SAPI     string `toml:"sapi"`
		Upstream string `toml:"upstream"`
		Timeout  int    `toml:"timeout"`
	} `toml:"vhost.php"`
	SSL struct {
		Certificate string `toml:"certificate,omitempty"`
		Key         string `toml:"key,omitempty"`
	} `toml:"vhost.ssl"`
	Security struct {
		HotlinkProtection bool     `toml:"hotlink_protection"`
		ForceHTTPS        bool     `toml:"force_https"`
		AllowIPs          []string `toml:"allow_ips,omitempty"`
		DenyIPs           []string `toml:"deny_ips,omitempty"`
	} `toml:"vhost.security"`
}

// Alan adını ZMax vHosts dizinine yazar
func CreateVHost(zmaxConfDir string, config VHostConfig) error {
	filePath := filepath.Join(zmaxConfDir, "conf", "vhosts", fmt.Sprintf("%s.toml", config.VHost.Name))
	
	data, err := toml.Marshal(config)
	if err != nil {
		return fmt.Errorf("toml dönüştürme hatası: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("vhost dosyası yazılamadı: %w", err)
	}

	return ReloadZMax()
}
```

---

## 3. Servis Yaşam Döngüsü ve Yeniden Yükleme (Lifecycle)

ZPanel, ZMax Server'ı sıfır kesintiyle (Zero-Downtime Graceful Reload) yönetir:

```go
package zmax

import (
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
)

// ZMax'i sıfır kesintiyle tazeler (Reload)
func ReloadZMax() error {
	if runtime.GOOS == "linux" {
		cmd := exec.Command("systemctl", "reload", "zmax")
		return cmd.Run()
	} else {
		// Windows üzerinde zmaxctrl veya Evrensel Kontrol API (127.0.0.1:19486)
		resp, err := http.Post("http://127.0.0.1:19486/api/v1/reload", "application/json", nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return nil
	}
}

// Servis durumunu kontrol eder
func IsZMaxRunning() bool {
	resp, err := http.Get("http://127.0.0.1:19486/api/v1/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
```

---

## 4. WAF ve Güvenlik Olayları Entegrasyonu

ZMax (Rust), saldırganları bellek içinde milisaniye altında tespit edip engeller.
- **Şu An Canlı Olan Yol (`v1.0.01`):** ZPanel (Go), `GET http://127.0.0.1:19486/api/v1/security/bans` (veya `/run/zmax/api.sock`) üzerinden aktif ban listesini çekip `iptables`/`nftables`'a yazabilir; kaldırmak için `POST /api/v1/security/unban` kullanır.
- **Hedef Küme Yolu (`v1.1+` — `zmax-redis` kablolaması sonrası):** Aşağıdaki Redis Pub/Sub dinleyicisi `zmax-redis` ana ikiliye bağlandığında gerçek zamanlı olay akışı için kullanılacaktır:

```go
package zmax

import (
	"context"
	"fmt"
	"os/exec"
	"github.com/redis/go-redis/v9"
)

// ZMax'ten gelen ban bildirimlerini dinler ve Linux iptables'a kalıcı yazar
func StartWAFSyncListener(rdb *redis.Client) {
	ctx := context.Background()
	pubsub := rdb.Subscribe(ctx, "zmax:waf:events")
	defer pubsub.Close()

	ch := pubsub.Channel()

	for msg := range ch {
		// Örnek mesaj payload: "45.154.255.88:SQL_Injection"
		bannedIP := msg.Payload
		fmt.Printf("[WAF ALARMI] ZMax IP engelledi: %s. iptables kuralı yazılıyor...\n", bannedIP)
		
		// Linux Netfilter / iptables'a kalıcı kural ekle
		exec.Command("iptables", "-I", "INPUT", "-s", bannedIP, "-j", "DROP").Run()
	}
}
```

---

## 5. Önbellek (L1/L2 Cache) Yönetimi

ZPanel arayüzünden tek bir sitenin veya tüm sunucunun önbelleğini anında boşaltmak için Go fonksiyonu:

```go
package zmax

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Tüm sunucu L1/L2 önbelleğini anında boşaltır
func PurgeAllCache() error {
	resp, err := http.Post("http://127.0.0.1:19486/api/v1/cache/purge", "application/json", nil)
	if err != nil {
		return fmt.Errorf("zmax api bağlantı hatası: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("purge başarısız: %d", resp.StatusCode)
	}

	return nil
}

// Belirli bir alan adına veya URI anahtarına ait önbelleği temizler
func PurgeDomainCache(uriKey string) error {
	payload, _ := json.Marshal(map[string]string{"uri": uriKey})
	resp, err := http.Post("http://127.0.0.1:19486/api/v1/cache/purge", "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
```

---

## 6. Canlı Telemetri ve Sağlık Takibi

ZPanel Dashboard'undaki sayaçları beslemek için ZMax'ten anlık metrik çeken Go yapısı:

```go
package zmax

import (
	"encoding/json"
	"net/http"
	"time"
)

type ZMaxStatus struct {
	UptimeSeconds uint64 `json:"uptime_seconds"`
	TotalRequests uint64 `json:"total_requests"`
	CacheHits     uint64 `json:"cache_hits"`
	CacheMisses   uint64 `json:"cache_misses"`
	Workers       int    `json:"workers"`
	RamMB         int    `json:"ram_mb"`
}

func GetServerStatus() (*ZMaxStatus, error) {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:19486/api/v1/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var status ZMaxStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}

	return &status, nil
}
```

---

## 7. Özet İş Bölümü ve Görev Paylaşımı

| Özellik / Sorumluluk | ZPanel (Go) | ZMax Server (Rust) |
| :--- | :--- | :--- |
| **Hosting & Müşteri Yönetimi** | ✅ Evet (Kullanıcı, Paket, Kota) | ❌ Hayır (Görevi Değil) |
| **vHost TOML Dosyası Yazımı** | ✅ Evet (`conf/vhosts/`) | ❌ Hayır (Salt Okunur Tüketici) |
| **Gelen HTTP/HTTPS Trafiği** | ❌ Hayır (Dokunmaz) | ✅ Evet (Saniyede 100k+ RPS) |
| **L1 RAM / L2 Disk Önbellek** | ❌ Hayır | ✅ Evet (0.04 ms Yanıt) |
| **Hızlı WAF / DoS Engeli (0.01 ms)** | ❌ Hayır | ✅ Evet (Kapıda Keser) |
| **Linux İşletim Sistemi Güvenlik Duvarı** | ✅ Evet (`iptables / nftables`) | ❌ Hayır (Go'ya Bildirir) |
| **Let's Encrypt SSL Koordinasyonu** | ✅ Evet (Zamanlayıcı / Cron) | ✅ Evet (ACME Challenge Sunumu) |
