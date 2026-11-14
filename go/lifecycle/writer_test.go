package lifecycle

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicVHostWriter_WriteAndBackup(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "zmax_test_vhosts")
	if err != nil {
		t.Fatalf("Gecici dizin olusturulamadi: %v", err)
	}
	defer os.RemoveAll(tempDir)

	writer := NewAtomicVHostWriter(tempDir)

	domain := "example.com"
	content1 := []byte("domain = 'example.com'\nroot = '/var/www/example'\n")

	// 1. İlk atomik yazma
	if err := writer.WriteAtomic(domain, content1); err != nil {
		t.Fatalf("WriteAtomic basarisiz: %v", err)
	}

	target := filepath.Join(tempDir, domain+".toml")
	read1, err := os.ReadFile(target)
	if err != nil || string(read1) != string(content1) {
		t.Fatalf("Yazilan dosya okunamadi veya eslesmedi")
	}

	// 2. Yedekleme
	bak, err := writer.Backup(domain)
	if err != nil || bak == "" {
		t.Fatalf("Backup basarisiz: %v", err)
	}

	// 3. İkinci yazma (güncelleme)
	content2 := []byte("domain = 'example.com'\nroot = '/var/www/newroot'\n")
	if err := writer.WriteAtomic(domain, content2); err != nil {
		t.Fatalf("Ikinci yazma basarisiz: %v", err)
	}

	// 4. Rollback
	if err := writer.Rollback(domain, bak); err != nil {
		t.Fatalf("Rollback basarisiz: %v", err)
	}

	readRolledBack, err := os.ReadFile(target)
	if err != nil || string(readRolledBack) != string(content1) {
		t.Fatalf("Rollback sonrasi dosya ilk icerikle eslesmedi")
	}
}

