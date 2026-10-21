package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
)

// ProxyRouter manages routing and reverse proxying to backend-a and backend-b.
type ProxyRouter struct {
	backendA      *url.URL
	backendB      *url.URL
	proxyA        *httputil.ReverseProxy
	proxyB        *httputil.ReverseProxy
	authenticator *auth.Authenticator
	counter       uint64
}

// NewProxyRouter initializes reverse proxies for both backends.
func NewProxyRouter(cfg *config.Config, authenticator *auth.Authenticator) (*ProxyRouter, error) {
	urlA, err := url.Parse(cfg.BackendAURL)
	if err != nil {
		return nil, fmt.Errorf("invalid BACKEND_A_URL: %w", err)
	}

	urlB, err := url.Parse(cfg.BackendBURL)
	if err != nil {
		return nil, fmt.Errorf("invalid BACKEND_B_URL: %w", err)
	}

	r := &ProxyRouter{
		backendA:      urlA,
		backendB:      urlB,
		authenticator: authenticator,
	}

	r.proxyA = r.createReverseProxy(urlA, "backend-a")
	r.proxyB = r.createReverseProxy(urlB, "backend-b")

	return r, nil
}

func (pr *ProxyRouter) createReverseProxy(target *url.URL, targetName string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Set target host header
		req.Host = target.Host

		// Delete any incoming identity headers to prevent spoofing
		req.Header.Del("X-User")
		req.Header.Del("X-Email")
		req.Header.Del("X-Roles")
		req.Header.Del("X-Subject")

		// Inject identity claims from request context if authenticated
		if claims, ok := auth.ClaimsFromContext(req.Context()); ok && claims != nil {
			if claims.PreferredUsername != "" {
				req.Header.Set("X-User", claims.PreferredUsername)
			} else {
				req.Header.Set("X-User", claims.Subject)
			}

			if claims.Email != "" {
				req.Header.Set("X-Email", claims.Email)
			}

			if len(claims.Roles) > 0 {
				req.Header.Set("X-Roles", strings.Join(claims.Roles, ","))
			}

			req.Header.Set("X-Subject", claims.Subject)
		}
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		slog.Error("reverse proxy error", "target", targetName, "url", r.URL.String(), "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"bad_gateway","message":"failed to reach upstream backend"}`))
	}

	return proxy
}

// Handler returns the HTTP handler with all routes, auth endpoints, and reverse proxy routing.
func (pr *ProxyRouter) Handler() http.Handler {
	mux := http.NewServeMux()

	// Health check (unauthenticated)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Auth endpoints (unauthenticated)
	mux.HandleFunc("/auth/login", pr.authenticator.HandleLogin)
	mux.HandleFunc("/auth/callback", pr.authenticator.HandleCallback)

	// Protected backend proxy handler
	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route selection:
		// 1. Explicit path prefix
		if strings.HasPrefix(r.URL.Path, "/backend-a") || strings.HasPrefix(r.URL.Path, "/a/") {
			pr.proxyA.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/backend-b") || strings.HasPrefix(r.URL.Path, "/b/") {
			pr.proxyB.ServeHTTP(w, r)
			return
		}

		// 2. Explicit header or query override
		targetHeader := strings.ToLower(r.Header.Get("X-Target-Backend"))
		targetQuery := strings.ToLower(r.URL.Query().Get("backend"))
		if targetHeader == "backend-b" || targetQuery == "b" || targetQuery == "backend-b" {
			pr.proxyB.ServeHTTP(w, r)
			return
		}
		if targetHeader == "backend-a" || targetQuery == "a" || targetQuery == "backend-a" {
			pr.proxyA.ServeHTTP(w, r)
			return
		}

		// 3. Round-robin between the two backends
		count := atomic.AddUint64(&pr.counter, 1)
		if count%2 == 1 {
			pr.proxyA.ServeHTTP(w, r)
		} else {
			pr.proxyB.ServeHTTP(w, r)
		}
	})

	// All protected routes go through the auth middleware
	mux.Handle("/", pr.authenticator.Middleware(proxyHandler))

	return mux
}
