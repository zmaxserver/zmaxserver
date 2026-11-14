package zmaxbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Client ZMax yönetim API'si ile konuşan güvenli Go istemcisi
type Client struct {
	cfg        Config
	httpClient *http.Client
	baseURL    string
	mu         sync.RWMutex
	lastGen    int64
}

// NewClient yeni bir ZMax köprü istemcisi örneği oluşturur
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.ClientContractVersion == "" {
		cfg.ClientContractVersion = "1.0"
	}

	transport := &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression: false,
	}

	baseURL := "http://zmax-local"

	// Unix domain soket önceliği
	if cfg.SocketPath != "" {
		if fi, err := os.Stat(cfg.SocketPath); err == nil && (fi.Mode()&os.ModeSocket != 0) {
			transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", cfg.SocketPath)
			}
		} else if cfg.TCPAddr != "" {
			baseURL = fmt.Sprintf("http://%s", cfg.TCPAddr)
		}
	} else if cfg.TCPAddr != "" {
		baseURL = fmt.Sprintf("http://%s", cfg.TCPAddr)
	}

	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		baseURL: baseURL,
	}
}

func (c *Client) doRequest(ctx context.Context, method, path string, body any, target any) error {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("zmaxbridge: istek govdesi serilestirilemedi: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("zmaxbridge: istek olusturulamadi: %w", err)
	}

	if c.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &ErrUnavailable{Address: c.baseURL, Cause: err}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("zmaxbridge: yanit okunamadi: %w", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("zmaxbridge: sunucu hatasi (%d): %s", resp.StatusCode, string(respBytes))
	}

	if target != nil {
		if err := json.Unmarshal(respBytes, target); err != nil {
			return fmt.Errorf("zmaxbridge: yanit cozumlenemedi: %w", err)
		}
	}
	return nil
}

// Version ZMax sürüm ve sözleşme uyumluluk kontrolünü gerçekleştirir
func (c *Client) Version(ctx context.Context) (*VersionResponse, error) {
	var resp VersionResponse
	if err := c.doRequest(ctx, http.MethodGet, "/api/v1/version", nil, &resp); err != nil {
		return nil, err
	}

	clientMajor := strings.Split(c.cfg.ClientContractVersion, ".")[0]
	serverMajor := strings.Split(resp.ContractVersion, ".")[0]
	if clientMajor != serverMajor {
		return &resp, &ErrContractMismatch{
			ClientVersion: c.cfg.ClientContractVersion,
			ServerVersion: resp.ContractVersion,
		}
	}

	return &resp, nil
}

// Health ZMax sunucu durumunu ve mevcut generation numarasını alır
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var resp HealthResponse
	if err := c.doRequest(ctx, http.MethodGet, "/api/v1/health", nil, &resp); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.lastGen = resp.Generation
	c.mu.Unlock()
	return &resp, nil
}

// Validate TOML yapılandırmasını uygulamadan doğrular
func (c *Client) Validate(ctx context.Context, domain, tomlContent string) (*ValidateResponse, error) {
	req := ValidateRequest{
		Domain:      domain,
		TomlContent: tomlContent,
	}
	var resp ValidateResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/config/validate", req, &resp); err != nil {
		return nil, err
	}
	if !resp.Valid {
		return &resp, &ErrRejected{
			File:    domain + ".toml",
			Field:   resp.ErrorField,
			Message: resp.Message,
		}
	}
	return &resp, nil
}

// Reload ZMax sunucusuna yapılandırmayı yeniden yükleme sinyali verir
func (c *Client) Reload(ctx context.Context) (*ReloadResponse, error) {
	var resp ReloadResponse
	if err := c.doRequest(ctx, http.MethodPost, "/api/v1/reload", nil, &resp); err != nil {
		return nil, err
	}
	if !resp.Ok || len(resp.Errors) > 0 {
		msg := "yeniden yukleme basarisiz"
		if len(resp.Errors) > 0 {
			msg = strings.Join(resp.Errors, "; ")
		}
		return &resp, &ErrRejected{
			File:    "vhosts",
			Message: msg,
		}
	}

	c.mu.Lock()
	c.lastGen = resp.Generation
	c.mu.Unlock()

	return &resp, nil
}

// PurgeCache Önbelleği URI, alan adı veya etiket bazlı temizler
func (c *Client) PurgeCache(ctx context.Context, req PurgeRequest) error {
	return c.doRequest(ctx, http.MethodPost, "/api/v1/cache/purge", req, nil)
}

// Status Sunucu performans ve bağlantı durumunu alır
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var resp StatusResponse
	if err := c.doRequest(ctx, http.MethodGet, "/api/v1/status", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

