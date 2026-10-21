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
	BackendAURL      string
	BackendBURL      string
}

// LoadFromEnv loads configuration from environment variables, applying sensible defaults.
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:       getEnv("PROXY_LISTEN_ADDR", ":8080"),
		OIDCIssuerURL:    getEnv("OIDC_ISSUER_URL", "http://keycloak:8080/realms/zt"),
		OIDCClientID:     getEnv("OIDC_CLIENT_ID", "zt-proxy"),
		OIDCClientSecret: getEnv("OIDC_CLIENT_SECRET", "zt-proxy-dev-secret"),
		OIDCRedirectURL:  getEnv("OIDC_REDIRECT_URL", "https://localhost/auth/callback"),
		CookieSecret:     getEnv("COOKIE_SECRET", "dev-cookie-secret-min-32-chars-long!"),
		BackendAURL:      getEnv("BACKEND_A_URL", "http://backend-a:8080"),
		BackendBURL:      getEnv("BACKEND_B_URL", "http://backend-b:8080"),
	}

	if cfg.OIDCClientID == "" {
		return nil, errors.New("OIDC_CLIENT_ID cannot be empty")
	}
	if cfg.OIDCIssuerURL == "" {
		return nil, errors.New("OIDC_ISSUER_URL cannot be empty")
	}
	if len(cfg.CookieSecret) < 16 {
		return nil, errors.New("COOKIE_SECRET must be at least 16 characters long")
	}

	return cfg, nil
}

func getEnv(key, defaultVal string) string {
	if v, exists := os.LookupEnv(key); exists && v != "" {
		return v
	}
	return defaultVal
}
