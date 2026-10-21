package config

import (
	"strings"
	"testing"
)

func setValidEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OIDC_CLIENT_SECRET", "dev-secret-value-12345")
	t.Setenv("COOKIE_SECRET", "super-secret-cookie-key-at-least-32-bytes!")
}

func TestLoadFromEnv_ValidDefaults(t *testing.T) {
	setValidEnv(t)

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error loading valid config: %v", err)
	}

	if cfg.ListenAddr != ":8081" {
		t.Errorf("expected default ListenAddr ':8081', got %q", cfg.ListenAddr)
	}
	if cfg.OIDCRedirectURL != "http://localhost:8081/auth/callback" {
		t.Errorf("expected default redirect URL 'http://localhost:8081/auth/callback', got %q", cfg.OIDCRedirectURL)
	}
	if cfg.OIDCClientID != "zt-proxy" {
		t.Errorf("expected default OIDCClientID 'zt-proxy', got %q", cfg.OIDCClientID)
	}
	if cfg.OIDCClientSecret != "dev-secret-value-12345" {
		t.Errorf("expected OIDCClientSecret to match env, got %q", cfg.OIDCClientSecret)
	}
}

func TestLoadFromEnv_MissingClientSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("OIDC_CLIENT_SECRET", "")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing OIDC_CLIENT_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "OIDC_CLIENT_SECRET") {
		t.Errorf("expected error mentioning OIDC_CLIENT_SECRET, got %v", err)
	}
}

func TestLoadFromEnv_MissingCookieSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("COOKIE_SECRET", "")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for missing COOKIE_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "COOKIE_SECRET") {
		t.Errorf("expected error mentioning COOKIE_SECRET, got %v", err)
	}
}

func TestLoadFromEnv_ShortCookieSecret(t *testing.T) {
	setValidEnv(t)
	t.Setenv("COOKIE_SECRET", "less-than-32-bytes")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for short COOKIE_SECRET, got nil")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Errorf("expected error mentioning at least 32 bytes, got %v", err)
	}
}

func TestLoadFromEnv_EmptyRequiredVars(t *testing.T) {
	tests := []struct {
		envKey string
	}{
		{"OIDC_CLIENT_ID"},
		{"OIDC_ISSUER_URL"},
	}

	for _, tc := range tests {
		t.Run(tc.envKey, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv(tc.envKey, "")

			_, err := LoadFromEnv()
			if err == nil {
				t.Fatalf("expected error for empty %s, got nil", tc.envKey)
			}
		})
	}
}

func TestLoadFromEnv_CustomOverrides(t *testing.T) {
	setValidEnv(t)
	t.Setenv("PROXY_LISTEN_ADDR", ":9999")
	t.Setenv("OIDC_CLIENT_ID", "custom-client")
	t.Setenv("OIDC_REDIRECT_URL", "https://proxy.example.com/callback")

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ListenAddr != ":9999" {
		t.Errorf("expected ':9999', got %q", cfg.ListenAddr)
	}
	if cfg.OIDCClientID != "custom-client" {
		t.Errorf("expected 'custom-client', got %q", cfg.OIDCClientID)
	}
	if cfg.OIDCRedirectURL != "https://proxy.example.com/callback" {
		t.Errorf("expected custom redirect url, got %q", cfg.OIDCRedirectURL)
	}
}
