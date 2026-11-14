package zmaxbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Version_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/version" {
			t.Errorf("Beklenmeyen yol: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VersionResponse{
			ServerVersion:     "1.0.0",
			ContractVersion:   "1.0",
			SupportedFeatures: []string{"h2", "tls", "purge", "waf"},
		})
	}))
	defer ts.Close()

	cfg := Config{
		TCPAddr:               ts.Listener.Addr().String(),
		Timeout:               2 * time.Second,
		ClientContractVersion: "1.0",
	}
	client := NewClient(cfg)

	ver, err := client.Version(context.Background())
	if err != nil {
		t.Fatalf("Version() basarisiz: %v", err)
	}
	if ver.ServerVersion != "1.0.0" {
		t.Errorf("Beklenen sunucu surumu 1.0.0, gelen: %s", ver.ServerVersion)
	}
}

func TestClient_Version_Mismatch(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VersionResponse{
			ServerVersion:   "2.0.0",
			ContractVersion: "2.0",
		})
	}))
	defer ts.Close()

	cfg := Config{
		TCPAddr:               ts.Listener.Addr().String(),
		ClientContractVersion: "1.0",
	}
	client := NewClient(cfg)

	_, err := client.Version(context.Background())
	if err == nil {
		t.Fatal("Surum uyusmazliginda hata bekleniyordu, nil geldi")
	}
	if _, ok := err.(*ErrContractMismatch); !ok {
		t.Errorf("Beklenen hata türü ErrContractMismatch, gelen: %T", err)
	}
}

func TestClient_Validate_Rejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ValidateResponse{
			Valid:      false,
			ErrorLine:  12,
			ErrorField: "root",
			Message:    "dizin mevcut degil",
		})
	}))
	defer ts.Close()

	client := NewClient(Config{TCPAddr: ts.Listener.Addr().String()})
	_, err := client.Validate(context.Background(), "test.com", "root = '/nonexistent'")
	if err == nil {
		t.Fatal("Gecersiz toml icin hata bekleniyordu")
	}
	rej, ok := err.(*ErrRejected)
	if !ok {
		t.Fatalf("Beklenen hata ErrRejected, gelen: %T", err)
	}
	if rej.Field != "root" {
		t.Errorf("Beklenen alan root, gelen: %s", rej.Field)
	}
}

