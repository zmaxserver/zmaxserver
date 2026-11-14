package zmaxbridge

import (
	"time"
)

// Config ZMax Go köprü istemcisi yapılandırması
type Config struct {
	// SocketPath Unix domain soket yolu (tercih edilen kanal: /run/zmax/api.sock)
	SocketPath string
	// TCPAddr Soket yoksa TCP adresi (varsayılan: 127.0.0.1:19486)
	TCPAddr string
	// APIToken Yetkilendirme tokenı
	APIToken string
	// Timeout İstek başına zaman aşımı (varsayılan: 5s)
	Timeout time.Duration
	// MaxRetries Hata durumunda yeniden deneme adedi
	MaxRetries int
	// ClientContractVersion İstemcinin beklediği sözleşme sürümü
	ClientContractVersion string
}

// DefaultConfig varsayılan güvenli istemci yapılandırmasını döner
func DefaultConfig() Config {
	return Config{
		SocketPath:            "/run/zmax/api.sock",
		TCPAddr:               "127.0.0.1:19486",
		Timeout:               5 * time.Second,
		MaxRetries:            2,
		ClientContractVersion: "1.0",
	}
}

