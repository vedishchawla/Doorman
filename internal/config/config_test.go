package config

import (
	"testing"
)

func TestLoadFromEnv_Defaults(t *testing.T) {
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("unexpected error loading defaults: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Errorf("expected default ListenAddr ':8080', got %q", cfg.ListenAddr)
	}
	if cfg.OIDCClientID != "zt-proxy" {
		t.Errorf("expected default OIDCClientID 'zt-proxy', got %q", cfg.OIDCClientID)
	}
}

func TestLoadFromEnv_Custom(t *testing.T) {
	t.Setenv("PROXY_LISTEN_ADDR", ":9999")
	t.Setenv("OIDC_CLIENT_ID", "custom-client")
	t.Setenv("COOKIE_SECRET", "super-secret-cookie-value-123456")

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
	if cfg.CookieSecret != "super-secret-cookie-value-123456" {
		t.Errorf("expected custom cookie secret, got %q", cfg.CookieSecret)
	}
}

func TestLoadFromEnv_InvalidCookieSecret(t *testing.T) {
	t.Setenv("COOKIE_SECRET", "short")

	_, err := LoadFromEnv()
	if err == nil {
		t.Fatal("expected error for short cookie secret, got nil")
	}
}
