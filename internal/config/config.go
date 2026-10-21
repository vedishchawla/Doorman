package config

import (
	"errors"
	"os"
)

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

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if v, exists := os.LookupEnv(key); exists {
		return v
	}
	return defaultVal
}
