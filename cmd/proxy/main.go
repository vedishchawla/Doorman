package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vedishchawla/doorman/internal/audit"
	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
	"github.com/vedishchawla/doorman/internal/policy"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--healthcheck" {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second)
		if err != nil {
			os.Exit(1)
		}
		_ = conn.Close()
		return
	}

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

	auditFile, err := os.OpenFile(cfg.AuditLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		slog.Error("failed to open audit log", "path", cfg.AuditLogFile, "error", err)
		os.Exit(1)
	}
	metrics := audit.NewMetrics()
	auditLogger := audit.NewLogger(auditFile, cfg.AuditBufferSize, cfg.AuditRecentSize, metrics)
	defer func() {
		if err := auditLogger.Shutdown(); err != nil {
			slog.Error("failed to flush audit log", "error", err)
		}
		_ = auditFile.Close()
	}()
	router.SetObservability(auditLogger, metrics)

	metricsServer := &http.Server{
		Addr:    ":9090",
		Handler: http.HandlerFunc(metrics.MetricsHandler),
	}
	go func() {
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("metrics server stopped with error", "error", err)
		}
	}()

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
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("metrics server shutdown failed", "error", err)
	}
	slog.Info("proxy server stopped cleanly")
}
