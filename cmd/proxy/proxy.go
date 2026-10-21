package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
	"github.com/vedishchawla/doorman/internal/policy"
	"github.com/vedishchawla/doorman/internal/posture"
)

// ProxyRouter manages routing and reverse proxying to backend-a and backend-b.
type ProxyRouter struct {
	backendA      *url.URL
	backendB      *url.URL
	proxyA        *httputil.ReverseProxy
	proxyB        *httputil.ReverseProxy
	authenticator *auth.Authenticator
	policyClient  *policy.Client
	policyCfg     policyConfig
	counter       uint64
}

// policyConfig holds policy-related configuration for the proxy.
type policyConfig struct {
	TZ                *time.Location
	DevDefaultCountry string
	DevDefaultPosture *config.DevicePostureDefault
	PostureVerifier   *posture.Verifier // nil = posture verification disabled
	PostureDisabled   bool
}

// NewProxyRouter initializes reverse proxies for both backends.
func NewProxyRouter(cfg *config.Config, authenticator *auth.Authenticator, pc *policy.Client) (*ProxyRouter, error) {
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
		policyClient:  pc,
		policyCfg: policyConfig{
			TZ:                cfg.PolicyTZ,
			DevDefaultCountry: cfg.DevDefaultCountry,
			PostureDisabled:   cfg.PostureDisabled,
		},
	}

	if cfg.DevDefaultPosture != nil {
		r.policyCfg.DevDefaultPosture = cfg.DevDefaultPosture
	}

	if cfg.PosturePublicKey == "" && !cfg.PostureDisabled {
		return nil, fmt.Errorf("POSTURE_PUBLIC_KEY is required unless POSTURE_DISABLED=true")
	}

	if cfg.PosturePublicKey != "" {
		v, err := posture.NewVerifier(cfg.PosturePublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid POSTURE_PUBLIC_KEY: %w", err)
		}
		r.policyCfg.PostureVerifier = v
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
		req.Header.Del("X-Device-Posture") // never forward raw posture token to backend

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

	// Wrap proxy handler with policy check, then auth middleware
	policyWrapped := pr.policyMiddleware(proxyHandler)

	// All protected routes go through the auth middleware
	mux.Handle("/", pr.authenticator.Middleware(policyWrapped))

	return mux
}

// policyMiddleware evaluates OPA policy after authentication.
func (pr *ProxyRouter) policyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			// Should not happen — auth middleware runs first
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","reason":"missing claims","policy_id":"internal-error"}`))
			return
		}

		// Build policy input
		cleanedPath := policy.CleanPath(r.URL.Path)

		// IP from RemoteAddr, never from client headers
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		// Geo: no client header source; use dev default if set
		geo := ""
		if pr.policyCfg.DevDefaultCountry != "" {
			geo = pr.policyCfg.DevDefaultCountry
		}
		if geo == "" {
			slog.Warn("policy denied: missing geo", "user", claims.PreferredUsername, "path", cleanedPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","reason":"missing geo","policy_id":"missing-geo"}`))
			return
		}

		// Device posture: verify the header unless posture checks are explicitly disabled.
		var policyPosture *policy.DevicePosture

		if pr.policyCfg.PostureVerifier != nil {
			// Verifier configured: header is required
			tokenHeader := r.Header.Get("X-Device-Posture")
			pc, err := pr.policyCfg.PostureVerifier.Verify(tokenHeader)
			if err != nil {
				slog.Warn("policy denied: posture token invalid",
					"user", claims.PreferredUsername,
					"path", cleanedPath,
					"error", err.Error(),
				)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				resp := map[string]string{
					"error":     "forbidden",
					"reason":    "invalid device posture token: " + err.Error(),
					"policy_id": "invalid-posture-token",
				}
				_ = json.NewEncoder(w).Encode(resp)
				return
			}
			policyPosture = &policy.DevicePosture{
				DeviceID:       pc.DeviceID,
				DiskEncrypted:  pc.DiskEncrypted,
				FirewallOn:     pc.FirewallOn,
				OSPatchAgeDays: pc.OSPatchAgeDays,
			}
		} else if pr.policyCfg.PostureDisabled && pr.policyCfg.DevDefaultPosture != nil {
			// No verifier: use dev default if set
			policyPosture = &policy.DevicePosture{
				DiskEncrypted:  pr.policyCfg.DevDefaultPosture.DiskEncrypted,
				FirewallOn:     pr.policyCfg.DevDefaultPosture.FirewallOn,
				OSPatchAgeDays: pr.policyCfg.DevDefaultPosture.OSPatchAgeDays,
			}
		}

		// Fail closed: missing posture means deny
		if policyPosture == nil {
			slog.Warn("policy denied: missing device posture", "user", claims.PreferredUsername, "path", cleanedPath)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"forbidden","reason":"missing device posture","policy_id":"missing-posture"}`))
			return
		}

		policyTime := policy.FormatPolicyTime(time.Now(), pr.policyCfg.TZ)

		input := policy.Input{
			User:          claims.PreferredUsername,
			Roles:         claims.Roles,
			Resource:      cleanedPath,
			Method:        r.Method,
			IP:            ip,
			Geo:           geo,
			Time:          policyTime,
			DevicePosture: policyPosture,
		}

		decision, _ := pr.policyClient.Evaluate(r.Context(), input)

		if !decision.Allow {
			slog.Warn("policy denied request",
				"user", input.User,
				"resource", input.Resource,
				"method", input.Method,
				"reason", decision.Reason,
				"policy_id", decision.PolicyID,
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			resp := map[string]string{
				"error":     "forbidden",
				"reason":    decision.Reason,
				"policy_id": decision.PolicyID,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}

		next.ServeHTTP(w, r)
	})
}
