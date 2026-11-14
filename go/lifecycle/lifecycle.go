package lifecycle

import (
	"context"
	"fmt"
	"strings"
	"zmaxbridge/zmaxbridge"
)

// Manager ZMax vHost yaşam döngüsünü (B5) uçtan uca yöneten orkestratör
type Manager struct {
	client *zmaxbridge.Client
	writer *AtomicVHostWriter
}

// NewManager yeni bir yaşam döngüsü yöneticisi oluşturur
func NewManager(client *zmaxbridge.Client, writer *AtomicVHostWriter) *Manager {
	return &Manager{
		client: client,
		writer: writer,
	}
}

// EnsureCompatibility Açılışta Go istemcisi ile ZMax sunucusunun sözleşme sürümünü doğrular
func (m *Manager) EnsureCompatibility(ctx context.Context) error {
	ver, err := m.client.Version(ctx)
	if err != nil {
		return fmt.Errorf("lifecycle: surum denetimi basarisiz: %w", err)
	}

	clientMajor := "1"
	serverMajor := strings.Split(ver.ContractVersion, ".")[0]
	if clientMajor != serverMajor {
		return &zmaxbridge.ErrContractMismatch{
			ClientVersion: "1.0",
			ServerVersion: ver.ContractVersion,
		}
	}
	return nil
}

// ApplyVHostSafe Şema kurallarına tam uyumlu vHost uygulama döngüsü:
// 1. Kilit al (.lock)
// 2. Sunucuya Validate sor (POST /api/v1/config/validate)
// 3. Mevcut dosyayı yedekle (.bak)
// 4. Atomik diske yaz (fsync + rename)
// 5. Sunucuyu yeniden yükle (POST /api/v1/reload)
// 6. Generation ve error kontrolü yap
// 7. Hata varsa otomatik geri al (Rollback)
func (m *Manager) ApplyVHostSafe(ctx context.Context, domain string, tomlContent []byte) (*zmaxbridge.ReloadResponse, error) {
	// 1. Kilit al
	lock, err := m.writer.AcquireLock()
	if err != nil {
		return nil, err
	}
	defer m.writer.ReleaseLock(lock)

	// 2. Sunucuya doğrula
	valResp, err := m.client.Validate(ctx, domain, string(tomlContent))
	if err != nil {
		return nil, fmt.Errorf("lifecycle: dogrulama hatasi: %w", err)
	}
	if !valResp.Valid {
		return nil, &zmaxbridge.ErrRejected{
			File:    domain + ".toml",
			Field:   valResp.ErrorField,
			Message: valResp.Message,
		}
	}

	// 3. Mevcut dosyayı yedekle
	backupPath, err := m.writer.Backup(domain)
	if err != nil {
		return nil, fmt.Errorf("lifecycle: yedekleme hatasi: %w", err)
	}

	// 4. Atomik yaz
	if err := m.writer.WriteAtomic(domain, tomlContent); err != nil {
		return nil, fmt.Errorf("lifecycle: atomik yazma hatasi: %w", err)
	}

	// 5. Reload sinyali gönder
	reloadResp, err := m.client.Reload(ctx)
	if err != nil {
		// Hata durumunda derhal geri al
		_ = m.writer.Rollback(domain, backupPath)
		// Sunucuyu eski yapılandırmada kalması için tekrar reload et
		_, _ = m.client.Reload(ctx)
		return nil, fmt.Errorf("lifecycle: reload basarisiz, geri alindi: %w", err)
	}

	// 6. Sonuç denetimi
	if !reloadResp.Ok || len(reloadResp.Errors) > 0 {
		_ = m.writer.Rollback(domain, backupPath)
		_, _ = m.client.Reload(ctx)
		return reloadResp, &zmaxbridge.ErrRejected{
			File:    domain + ".toml",
			Message: fmt.Sprintf("reload hatalari: %s", strings.Join(reloadResp.Errors, ", ")),
		}
	}

	return reloadResp, nil
}

