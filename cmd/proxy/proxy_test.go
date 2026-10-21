package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
)

type testRig struct {
	fakeOIDC  *httptest.Server
	privKey   *rsa.PrivateKey
	kid       string
	backendA  *httptest.Server
	backendB  *httptest.Server
	lastReqA  *http.Request
	lastReqB  *http.Request
	mu        sync.Mutex
}

func setupTestRig(t *testing.T) *testRig {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	rig := &testRig{
		privKey: privKey,
		kid:     "test-key",
	}

	// Backend A
	rig.backendA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.lastReqA = r.Clone(r.Context())
		rig.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"backend": "backend-a",
			"user":    r.Header.Get("X-User"),
			"roles":   r.Header.Get("X-Roles"),
		})
	}))

	// Backend B
	rig.backendB = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.mu.Lock()
		rig.lastReqB = r.Clone(r.Context())
		rig.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"backend": "backend-b",
			"user":    r.Header.Get("X-User"),
			"roles":   r.Header.Get("X-Roles"),
		})
	}))

	// Fake OIDC
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := rig.fakeOIDC.URL
		_ = json.NewEncoder(w).Encode(auth.OIDCDiscovery{
			Issuer:                base,
			AuthorizationEndpoint: base + "/auth",
			TokenEndpoint:         base + "/token",
			JWKSURI:               base + "/certs",
		})
	})

	mux.HandleFunc("/certs", func(w http.ResponseWriter, r *http.Request) {
		pub := rig.privKey.Public().(*rsa.PublicKey)
		nBytes := pub.N.Bytes()
		eBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}

		_ = json.NewEncoder(w).Encode(auth.JSONWebKeySet{
			Keys: []auth.JSONWebKey{
				{
					Kty: "RSA",
					Kid: rig.kid,
					Use: "sig",
					Alg: "RS256",
					N:   base64.RawURLEncoding.EncodeToString(nBytes),
					E:   base64.RawURLEncoding.EncodeToString(eBytes),
				},
			},
		})
	})

	rig.fakeOIDC = httptest.NewServer(mux)
	return rig
}

func (tr *testRig) Close() {
	tr.fakeOIDC.Close()
	tr.backendA.Close()
	tr.backendB.Close()
}

func (tr *testRig) signToken(t *testing.T, claims auth.Claims) string {
	t.Helper()
	header := `{"alg":"RS256","kid":"` + tr.kid + `","typ":"JWT"}`
	type fullClaims struct {
		auth.Claims
		Aud []string `json:"aud"`
	}
	claimsJSON, err := json.Marshal(fullClaims{Claims: claims, Aud: claims.Audience})
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	p1 := base64.RawURLEncoding.EncodeToString([]byte(header))
	p2 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	input := p1 + "." + p2

	hash := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, tr.privKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	p3 := base64.RawURLEncoding.EncodeToString(sig)
	return input + "." + p3
}

func TestProxyRouter_Healthz(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	cfg := &config.Config{
		BackendAURL:      rig.backendA.URL,
		BackendBURL:      rig.backendB.URL,
		OIDCIssuerURL:    rig.fakeOIDC.URL,
		OIDCClientID:     "zt-proxy",
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "https://localhost/auth/callback",
		CookieSecret:     "secret-key-that-is-at-least-32-bytes-long!",
	}

	authenticator, err := auth.NewAuthenticator(context.Background(), auth.AuthenticatorConfig{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		CookieSecret: []byte(cfg.CookieSecret),
		HTTPClient:   rig.fakeOIDC.Client(),
	})
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	router, err := NewProxyRouter(cfg, authenticator)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	resp, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestProxyRouter_ForwardingWithIdentityHeaders(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	cfg := &config.Config{
		BackendAURL:      rig.backendA.URL,
		BackendBURL:      rig.backendB.URL,
		OIDCIssuerURL:    rig.fakeOIDC.URL,
		OIDCClientID:     "zt-proxy",
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "https://localhost/auth/callback",
		CookieSecret:     cookieSecret,
	}

	authenticator, err := auth.NewAuthenticator(context.Background(), auth.AuthenticatorConfig{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		CookieSecret: []byte(cfg.CookieSecret),
		HTTPClient:   rig.fakeOIDC.Client(),
	})
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	router, err := NewProxyRouter(cfg, authenticator)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	// 1. Unauthenticated request to / -> 401 for API
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated API, got %d", resp.StatusCode)
	}

	// 2. Authenticated request with session cookie
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "user-456",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Email:             "alice@example.com",
		Roles:             []string{"admin", "viewer"},
	})

	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	authedReq, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	authedReq.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})

	authedResp, err := server.Client().Do(authedReq)
	if err != nil {
		t.Fatalf("authenticated request failed: %v", err)
	}
	defer authedResp.Body.Close()

	if authedResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", authedResp.StatusCode)
	}

	var res map[string]interface{}
	if err := json.NewDecoder(authedResp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if res["user"] != "alice" {
		t.Errorf("expected downstream to receive user 'alice', got %v", res["user"])
	}
	if res["roles"] != "admin,viewer" {
		t.Errorf("expected downstream to receive roles 'admin,viewer', got %v", res["roles"])
	}

	// Verify explicit routing to backend-b
	reqB, _ := http.NewRequest(http.MethodGet, server.URL+"/backend-b/test", nil)
	reqB.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})
	respB, err := server.Client().Do(reqB)
	if err != nil {
		t.Fatalf("backend-b request failed: %v", err)
	}
	defer respB.Body.Close()

	var resB map[string]interface{}
	_ = json.NewDecoder(respB.Body).Decode(&resB)
	if resB["backend"] != "backend-b" {
		t.Errorf("expected backend 'backend-b', got %v", resB["backend"])
	}
}
