package zmaxbridge

// VersionResponse GET /api/v1/version yanıt modeli
type VersionResponse struct {
	ServerVersion     string   `json:"server_version"`
	ContractVersion   string   `json:"contract_version"`
	SupportedFeatures []string `json:"supported_features"`
}

// HealthResponse GET /api/v1/health yanıt modeli
type HealthResponse struct {
	Status          string `json:"status"`
	Generation      int64  `json:"generation"`
	ContractVersion string `json:"contract_version"`
	UptimeSec       int64  `json:"uptime_sec"`
}

// ValidateRequest POST /api/v1/config/validate istek modeli
type ValidateRequest struct {
	Domain      string `json:"domain"`
	TomlContent string `json:"toml_content"`
}

// ValidateResponse POST /api/v1/config/validate yanıt modeli
type ValidateResponse struct {
	Valid      bool   `json:"valid"`
	ErrorLine  int    `json:"error_line,omitempty"`
	ErrorField string `json:"error_field,omitempty"`
	Message    string `json:"message,omitempty"`
}

// ReloadResponse POST /api/v1/reload yanıt modeli
type ReloadResponse struct {
	Ok           bool     `json:"ok"`
	Generation   int64    `json:"generation"`
	VhostsLoaded int      `json:"vhosts_loaded"`
	Errors       []string `json:"errors"`
}

// PurgeRequest POST /api/v1/cache/purge istek modeli
type PurgeRequest struct {
	Domain string   `json:"domain,omitempty"`
	URI    string   `json:"uri,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// StatusResponse GET /api/v1/status yanıt modeli
type StatusResponse struct {
	ActiveConns   int64  `json:"active_connections"`
	TotalRequests int64  `json:"total_requests"`
	MemoryUsageKB uint64 `json:"memory_usage_kb"`
}

