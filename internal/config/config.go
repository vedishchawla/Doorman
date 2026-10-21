package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// DevicePostureDefault holds default device posture for local development.
type DevicePostureDefault struct {
	DiskEncrypted  bool `json:"disk_encrypted"`
	OSPatchAgeDays int  `json:"os_patch_age_days"`
}

// Config holds runtime configuration for the proxy.
type Config struct {
	ListenAddr       string
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	CookieSecret     string
	CookieSecure     bool
	BackendAURL      string
	BackendBURL      string

	// Policy / OPA
	OPAURL            string
	PolicyCacheTTL    time.Duration
	PolicyCacheMaxSize int
	PolicyTZ          *time.Location

	// Dev-only defaults (logged as warnings if set)
	DevDefaultCountry string
	DevDefaultPosture *DevicePostureDefault
}

// LoadFromEnv loads configuration from environment variables.
// Required variables must be set with no defaults; missing or empty values will return an error.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:       getEnv("PROXY_LISTEN_ADDR", ":8081"),
		OIDCIssuerURL:    getEnv("OIDC_ISSUER_URL", "http://localhost:8080/realms/zt"),
		OIDCClientID:     getEnv("OIDC_CLIENT_ID", "zt-proxy"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  getEnv("OIDC_REDIRECT_URL", "http://localhost:8081/auth/callback"),
		CookieSecret:     os.Getenv("COOKIE_SECRET"),
		CookieSecure:     getEnv("COOKIE_SECURE", "false") == "true",
		BackendAURL:      getEnv("BACKEND_A_URL", "http://backend-a:8080"),
		BackendBURL:      getEnv("BACKEND_B_URL", "http://backend-b:8080"),
		OPAURL:           getEnv("OPA_URL", "http://localhost:8181"),
	}

	if cfg.OIDCClientID == "" {
		return nil, errors.New("OIDC_CLIENT_ID is required")
	}
	if cfg.OIDCIssuerURL == "" {
		return nil, errors.New("OIDC_ISSUER_URL is required")
	}
	if cfg.OIDCClientSecret == "" {
		return nil, errors.New("OIDC_CLIENT_SECRET is required with no default")
	}
	if cfg.CookieSecret == "" {
		return nil, errors.New("COOKIE_SECRET is required with no default")
	}
	if len([]byte(cfg.CookieSecret)) < 32 {
		return nil, errors.New("COOKIE_SECRET must be at least 32 bytes")
	}

	// Policy cache TTL
	ttlStr := getEnv("POLICY_CACHE_TTL", "0")
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid POLICY_CACHE_TTL %q: %w", ttlStr, err)
	}
	cfg.PolicyCacheTTL = ttl

	// Policy cache max size
	maxSizeStr := getEnv("POLICY_CACHE_MAX_SIZE", "10000")
	maxSize, err := strconv.Atoi(maxSizeStr)
	if err != nil || maxSize < 0 {
		return nil, fmt.Errorf("invalid POLICY_CACHE_MAX_SIZE %q", maxSizeStr)
	}
	cfg.PolicyCacheMaxSize = maxSize

	// Policy timezone
	tzStr := getEnv("POLICY_TZ", "Asia/Kolkata")
	loc, err := time.LoadLocation(tzStr)
	if err != nil {
		return nil, fmt.Errorf("invalid POLICY_TZ %q: %w", tzStr, err)
	}
	cfg.PolicyTZ = loc

	// Dev-only defaults
	if v := os.Getenv("DEV_DEFAULT_COUNTRY"); v != "" {
		cfg.DevDefaultCountry = v
	}
	if v := os.Getenv("DEV_DEFAULT_POSTURE"); v != "" {
		var dp DevicePostureDefault
		if err := json.Unmarshal([]byte(v), &dp); err != nil {
			return nil, fmt.Errorf("invalid DEV_DEFAULT_POSTURE JSON: %w", err)
		}
		cfg.DevDefaultPosture = &dp
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if v, exists := os.LookupEnv(key); exists {
		return v
	}
	return defaultVal
}
