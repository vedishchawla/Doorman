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

	"github.com/vedishchawla/doorman/internal/audit"
	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
	"github.com/vedishchawla/doorman/internal/mtls"
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
	auditLogger   *audit.Logger
	metrics       *audit.Metrics
}

// SetObservability configures asynchronous audit logging and Prometheus metrics.
func (pr *ProxyRouter) SetObservability(logger *audit.Logger, metrics *audit.Metrics) {
	pr.auditLogger = logger
	pr.metrics = metrics
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

	if !cfg.MTLSDisabled && (cfg.MTLSCAFile == "" || cfg.MTLSClientCertFile == "" || cfg.MTLSClientKeyFile == "") {
		return nil, fmt.Errorf("mTLS files are required unless MTLS_DISABLED=true")
	}

	r.proxyA = r.createReverseProxy(urlA, "backend-a")
	r.proxyB = r.createReverseProxy(urlB, "backend-b")
	if !cfg.MTLSDisabled {
		transport, err := mtls.NewTransport(mtls.Config{
			CAFile: cfg.MTLSCAFile, ClientCertFile: cfg.MTLSClientCertFile, ClientKeyFile: cfg.MTLSClientKeyFile,
		})
		if err != nil {
			return nil, fmt.Errorf("invalid mTLS configuration: %w", err)
		}
		r.proxyA.Transport = transport
		r.proxyB.Transport = transport.Clone()
	}

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
		state, _ := audit.StateFromContext(r.Context())
		start := time.Now()
		// Route selection:
		// 1. Explicit path prefix
		if strings.HasPrefix(r.URL.Path, "/backend-a") || strings.HasPrefix(r.URL.Path, "/a/") {
			pr.proxyA.ServeHTTP(w, r)
			if state != nil {
				state.UpstreamMS = float64(time.Since(start).Microseconds()) / 1000
				state.Step = 6
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/backend-b") || strings.HasPrefix(r.URL.Path, "/b/") {
			pr.proxyB.ServeHTTP(w, r)
			if state != nil {
				state.UpstreamMS = float64(time.Since(start).Microseconds()) / 1000
				state.Step = 6
			}
			return
		}

		// 2. Explicit header or query override
		targetHeader := strings.ToLower(r.Header.Get("X-Target-Backend"))
		targetQuery := strings.ToLower(r.URL.Query().Get("backend"))
		if targetHeader == "backend-b" || targetQuery == "b" || targetQuery == "backend-b" {
			pr.proxyB.ServeHTTP(w, r)
			if state != nil {
				state.UpstreamMS = float64(time.Since(start).Microseconds()) / 1000
				state.Step = 6
			}
			return
		}
		if targetHeader == "backend-a" || targetQuery == "a" || targetQuery == "backend-a" {
			pr.proxyA.ServeHTTP(w, r)
			if state != nil {
				state.UpstreamMS = float64(time.Since(start).Microseconds()) / 1000
				state.Step = 6
			}
			return
		}

		// 3. Round-robin between the two backends
		count := atomic.AddUint64(&pr.counter, 1)
		if count%2 == 1 {
			pr.proxyA.ServeHTTP(w, r)
		} else {
			pr.proxyB.ServeHTTP(w, r)
		}
		if state != nil {
			state.UpstreamMS = float64(time.Since(start).Microseconds()) / 1000
			state.Step = 6
		}
	})

	// Wrap proxy handler with policy check, then auth middleware
	policyWrapped := pr.policyMiddleware(proxyHandler)

	// The audit endpoint is authenticated but does not audit itself.
	mux.Handle("/api/audit", pr.authenticator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pr.auditLogger == nil {
			http.Error(w, "audit logging unavailable", http.StatusServiceUnavailable)
			return
		}
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok || claims == nil || !containsRole(claims.Roles, "admin") {
			if state, ok := audit.StateFromContext(r.Context()); ok {
				state.Decision, state.Reason, state.PolicyID, state.Step = "deny", "admin role required", "audit-admin-required", 3
			}
			http.Error(w, "admin role required", http.StatusForbidden)
			return
		}
		pr.auditLogger.AuditHandler(w, r)
	})))

	// All protected routes go through the auth middleware and audit middleware.
	protected := pr.authenticator.Middleware(policyWrapped)
	mux.Handle("/", protected)
	return pr.auditMiddleware(mux)
}

func containsRole(roles []string, want string) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}

func (pr *ProxyRouter) auditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pr.auditLogger == nil {
			next.ServeHTTP(w, r)
			return
		}
		state := audit.NewRequestState(r)
		r = audit.WithState(r, state)
		recorder := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		if claims, ok := auth.ClaimsFromContext(r.Context()); ok && claims != nil {
			state.User = claims.PreferredUsername
			state.Roles = append([]string(nil), claims.Roles...)
		}
		if state.Decision == "" {
			if recorder.status >= http.StatusOK && recorder.status < http.StatusMultipleChoices {
				state.Decision = "allow"
			} else {
				state.Decision = "deny"
			}
		}
		if state.Reason == "" && state.Decision == "deny" {
			state.Reason = "authentication failed"
			state.PolicyID = "authentication"
		}
		if state.AuthMS == 0 {
			state.AuthMS = float64(time.Since(state.StartedAt).Microseconds()) / 1000
		}
		pr.auditLogger.Record(audit.Entry{
			Timestamp: time.Now().UTC(), RequestID: state.RequestID, User: state.User,
			Roles: state.Roles, Resource: state.Resource, Method: state.Method,
			Decision: state.Decision, Reason: state.Reason, PolicyID: state.PolicyID,
			ClientIP: state.ClientIP, Geo: state.Geo, DeviceID: state.DeviceID,
			Step: state.Step, AuthMS: state.AuthMS, OPAMS: state.OPAMS, UpstreamMS: state.UpstreamMS,
		})
		if pr.metrics != nil {
			pr.metrics.Observe(state.Decision, *state)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

// policyMiddleware evaluates OPA policy after authentication.
func (pr *ProxyRouter) policyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, _ := audit.StateFromContext(r.Context())
		if state != nil {
			state.AuthMS = float64(time.Since(state.StartedAt).Microseconds()) / 1000
			state.Step = 2
		}
		claims, ok := auth.ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			if state != nil {
				state.Decision, state.Reason, state.PolicyID, state.Step = "deny", "missing claims", "internal-error", 3
			}
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
		if state != nil {
			state.Geo = geo
			state.User = claims.PreferredUsername
			state.Roles = append([]string(nil), claims.Roles...)
		}
		if geo == "" {
			if state != nil {
				state.Decision, state.Reason, state.PolicyID, state.Step = "deny", "missing geo", "missing-geo", 3
			}
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
				if state != nil {
					state.Decision, state.Reason, state.PolicyID, state.Step = "deny", "invalid device posture token: "+err.Error(), "invalid-posture-token", 3
				}
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
			if state != nil {
				state.DeviceID = pc.DeviceID
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
			if state != nil {
				state.Decision, state.Reason, state.PolicyID, state.Step = "deny", "missing device posture", "missing-posture", 3
			}
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

		opaStart := time.Now()
		decision, _ := pr.policyClient.Evaluate(r.Context(), input)
		if state != nil {
			state.OPAMS = float64(time.Since(opaStart).Microseconds()) / 1000
			state.Step = 4
			state.Decision = "allow"
			state.Reason = decision.Reason
			state.PolicyID = decision.PolicyID
		}

		if !decision.Allow {
			if state != nil {
				state.Decision = "deny"
			}
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
