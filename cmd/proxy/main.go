package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
	"github.com/vedishchawla/doorman/internal/policy"
)

func main() {
	// JSON logging per architecture rules
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Warn about dev-only defaults
	if cfg.DevDefaultCountry != "" {
		slog.Warn("DEV_DEFAULT_COUNTRY is set — using dev default geo for all requests", "country", cfg.DevDefaultCountry)
	}
	if cfg.DevDefaultPosture != nil {
		slog.Warn("DEV_DEFAULT_POSTURE is set — using dev default device posture for all requests",
			"disk_encrypted", cfg.DevDefaultPosture.DiskEncrypted,
			"os_patch_age_days", cfg.DevDefaultPosture.OSPatchAgeDays,
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	authCfg := auth.AuthenticatorConfig{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		CookieSecret: []byte(cfg.CookieSecret),
		CookieSecure: cfg.CookieSecure,
	}

	authenticator, err := auth.NewAuthenticator(ctx, authCfg)
	if err != nil {
		slog.Error("failed to initialize OIDC authenticator", "error", err)
		os.Exit(1)
	}
	defer authenticator.Close()

	policyClient := policy.NewClient(cfg.OPAURL, cfg.PolicyCacheTTL, cfg.PolicyCacheMaxSize)

	router, err := NewProxyRouter(cfg, authenticator, policyClient)
	if err != nil {
		slog.Error("failed to initialize proxy router", "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown channel
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("starting zero-trust ingress proxy",
			"addr", cfg.ListenAddr,
			"issuer", cfg.OIDCIssuerURL,
			"opa", cfg.OPAURL,
			"backend_a", cfg.BackendAURL,
			"backend_b", cfg.BackendBURL,
			"policy_cache_ttl", cfg.PolicyCacheTTL.String(),
			"policy_tz", cfg.PolicyTZ.String(),
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("proxy server stopped with error", "error", err)
			os.Exit(1)
		}
	}()

	<-shutdownCh
	slog.Info("shutting down proxy server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Error("server graceful shutdown failed", "error", err)
	}
	slog.Info("proxy server stopped cleanly")
}
