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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	authCfg := auth.AuthenticatorConfig{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		CookieSecret: []byte(cfg.CookieSecret),
	}

	authenticator, err := auth.NewAuthenticator(ctx, authCfg)
	if err != nil {
		slog.Error("failed to initialize OIDC authenticator", "error", err)
		os.Exit(1)
	}
	defer authenticator.Close()

	router, err := NewProxyRouter(cfg, authenticator)
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
			"backend_a", cfg.BackendAURL,
			"backend_b", cfg.BackendBURL,
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
