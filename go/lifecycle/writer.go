package lifecycle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// sanitizeDomain yol gezinme (path traversal) ve zararlı karakterleri engeller (ZMX-010)
func sanitizeDomain(domain string) (string, error) {
	clean := strings.TrimSpace(domain)
	if clean == "" || strings.Contains(clean, "/") || strings.Contains(clean, "\\") || strings.Contains(clean, "..") || strings.ContainsRune(clean, 0) {
		return "", fmt.Errorf("lifecycle: gecersiz domain adi veya guvensiz yol karakteri")
	}
	for _, r := range clean {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return "", fmt.Errorf("lifecycle: guvensiz karakter tespit edildi: %c", r)
		}
	}
	return clean, nil
}

// AtomicVHostWriter vHost TOML dosyalarını güvenli ve atomik yazan bileşen (B4)
type AtomicVHostWriter struct {
	vhostsDir string
	lockFile  string
}

// NewAtomicVHostWriter yeni bir atomik yazıcı oluşturur
func NewAtomicVHostWriter(vhostsDir string) *AtomicVHostWriter {
	return &AtomicVHostWriter{
		vhostsDir: vhostsDir,
		lockFile:  filepath.Join(vhostsDir, ".vhost_write.lock"),
	}
}

// AcquireLock Eşzamanlı yazmayı engelleyen kilit dosyasını alır (5 saniye zaman aşımı)
func (w *AtomicVHostWriter) AcquireLock() (*os.File, error) {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f, err := os.OpenFile(w.lockFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			return f, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("lifecycle: kilit dosyasi alinamadi (.lock bekleme zaman asimi)")
}

// ReleaseLock Kilit dosyasını serbest bırakır
func (w *AtomicVHostWriter) ReleaseLock(lock *os.File) {
	if lock != nil {
		lock.Close()
		os.Remove(w.lockFile)
	}
}

// WriteAtomic Geçici dosyaya yazar, fsync eder ve atomik isim değişikliği (rename) yapar
func (w *AtomicVHostWriter) WriteAtomic(domain string, content []byte) error {
	safeDomain, err := sanitizeDomain(domain)
	if err != nil {
		return err
	}
	targetPath := filepath.Join(w.vhostsDir, safeDomain+".toml")
	tmpPath := filepath.Join(w.vhostsDir, fmt.Sprintf(".%s.tmp.%d", safeDomain, time.Now().UnixNano()))

	// 1. Geçici dosyayı oluştur
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("lifecycle: gecici dosya olusturulamadi: %w", err)
	}

	// 2. İçeriği yaz
	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("lifecycle: gecici dosyaya yazilamadi: %w", err)
	}

	// 3. Diske kalıcı yazıldığını doğrula (fsync)
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("lifecycle: fsync basarisiz: %w", err)
	}
	tmpFile.Close()

	// 4. Atomik rename ile hedef dosyanın yerine geçir
	if err := os.Rename(tmpPath, targetPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("lifecycle: atomik degisim basarisiz: %w", err)
	}

	return nil
}

// Backup mevcut TOML dosyasını bir önceki sürüme yedekler (.bak)
func (w *AtomicVHostWriter) Backup(domain string) (string, error) {
	safeDomain, err := sanitizeDomain(domain)
	if err != nil {
		return "", err
	}
	src := filepath.Join(w.vhostsDir, safeDomain+".toml")
	if _, err := os.Stat(src); os.IsNotExist(err) {
		return "", nil // İlk defa oluşturuluyorsa yedek yok
	}

	bak := filepath.Join(w.vhostsDir, fmt.Sprintf(".%s.prev.bak", safeDomain))
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(bak, data, 0644); err != nil {
		return "", err
	}
	return bak, nil
}

// Rollback hata durumunda yedeği geri yükler
func (w *AtomicVHostWriter) Rollback(domain, backupPath string) error {
	safeDomain, err := sanitizeDomain(domain)
	if err != nil {
		return err
	}
	target := filepath.Join(w.vhostsDir, safeDomain+".toml")
	if backupPath == "" {
		// Öncesinde dosya yoktu, yeni oluşturulan hatalı dosyayı kaldır
		if _, err := os.Stat(target); err == nil {
			return os.Remove(target)
		}
		return nil
	}
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("lifecycle: geri yuklenecek yedek dosya bulunamadi: %s", backupPath)
	}
	if err := os.Rename(backupPath, target); err != nil {
		return fmt.Errorf("lifecycle: yedekten geri yukleme basarisiz: %w", err)
	}
	return nil
}

