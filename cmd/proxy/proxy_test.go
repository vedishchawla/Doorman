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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vedishchawla/doorman/internal/auth"
	"github.com/vedishchawla/doorman/internal/config"
	"github.com/vedishchawla/doorman/internal/policy"
	"github.com/vedishchawla/doorman/internal/posture"
)

type testRig struct {
	fakeOIDC *httptest.Server
	fakeOPA  *httptest.Server
	privKey  *rsa.PrivateKey
	kid      string
	backendA *httptest.Server
	backendB *httptest.Server
	lastReqA *http.Request
	lastReqB *http.Request
	mu       sync.Mutex
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

	// Fake OPA — default allow
	rig.fakeOPA = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":     true,
				"reason":    "",
				"policy_id": "",
				"denials":   []interface{}{},
			},
		})
	}))

	return rig
}

func (tr *testRig) Close() {
	tr.fakeOIDC.Close()
	tr.fakeOPA.Close()
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

func (tr *testRig) newRouterWithPolicy(t *testing.T, opaHandler http.Handler) (*ProxyRouter, *auth.Authenticator) {
	t.Helper()

	if opaHandler != nil {
		tr.fakeOPA.Close()
		tr.fakeOPA = httptest.NewServer(opaHandler)
	}

	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:       tr.backendA.URL,
		BackendBURL:       tr.backendB.URL,
		OIDCIssuerURL:     tr.fakeOIDC.URL,
		OIDCClientID:      "zt-proxy",
		OIDCClientSecret:  "secret",
		OIDCRedirectURL:   "https://localhost/auth/callback",
		CookieSecret:      "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:            tr.fakeOPA.URL,
		PolicyTZ:          ist,
		MTLSDisabled:      true,
		PostureDisabled:   true,
		DevDefaultCountry: "IN",
		DevDefaultPosture: &config.DevicePostureDefault{
			DiskEncrypted:  true,
			FirewallOn:     true,
			OSPatchAgeDays: 5,
		},
	}

	authenticator, err := auth.NewAuthenticator(context.Background(), auth.AuthenticatorConfig{
		IssuerURL:    cfg.OIDCIssuerURL,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.OIDCRedirectURL,
		CookieSecret: []byte(cfg.CookieSecret),
		HTTPClient:   tr.fakeOIDC.Client(),
	})
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}

	pc := policy.NewClient(cfg.OPAURL, 0, 100)

	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	return router, authenticator
}

func TestProxyRouter_Healthz(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	router, authenticator := rig.newRouterWithPolicy(t, nil)
	defer authenticator.Close()

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
	router, authenticator := rig.newRouterWithPolicy(t, nil)
	defer authenticator.Close()

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
}

func TestProxyRouter_HeaderSpoofingProtection(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	router, authenticator := rig.newRouterWithPolicy(t, nil)
	defer authenticator.Close()

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	// Token with only viewer role
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "bob",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "bob",
		Roles:             []string{"viewer"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	// Client sends spoofed header: X-Roles: admin, X-User: root
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})
	req.Header.Set("X-Roles", "admin")
	req.Header.Set("X-User", "root")

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var res map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Backend must see the viewer role and bob user, not spoofed headers
	if res["roles"] != "viewer" {
		t.Errorf("expected downstream to see roles 'viewer', got %v", res["roles"])
	}
	if res["user"] != "bob" {
		t.Errorf("expected downstream to see user 'bob', got %v", res["user"])
	}
}

func TestProxyRouter_PolicyDeny(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	// OPA that denies everything
	denyOPA := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":     false,
				"reason":    "Denied: device is not compliant: disk is not encrypted",
				"policy_id": "disk-not-encrypted",
				"denials": []interface{}{
					map[string]interface{}{"rule_id": "disk-not-encrypted", "message": "Denied: device is not compliant: disk is not encrypted"},
				},
			},
		})
	})

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	router, authenticator := rig.newRouterWithPolicy(t, denyOPA)
	defer authenticator.Close()

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var res map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode: %v", err)
	}
	if res["policy_id"] != "disk-not-encrypted" {
		t.Errorf("expected policy_id 'disk-not-encrypted', got %q", res["policy_id"])
	}
}

func TestProxyRouter_MissingGeo_Deny(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	// Create router WITHOUT dev defaults for geo
	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:      rig.backendA.URL,
		BackendBURL:      rig.backendB.URL,
		OIDCIssuerURL:    rig.fakeOIDC.URL,
		OIDCClientID:     "zt-proxy",
		OIDCClientSecret: "secret",
		OIDCRedirectURL:  "https://localhost/auth/callback",
		CookieSecret:     "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:           rig.fakeOPA.URL,
		PolicyTZ:         ist,
		MTLSDisabled:     true,
		PostureDisabled:  true,
		// No DevDefaultCountry — geo will be empty
		DevDefaultPosture: &config.DevicePostureDefault{
			DiskEncrypted:  true,
			OSPatchAgeDays: 5,
		},
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

	pc := policy.NewClient(cfg.OPAURL, 0, 100)
	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for missing geo, got %d", resp.StatusCode)
	}

	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res["policy_id"] != "missing-geo" {
		t.Errorf("expected policy_id 'missing-geo', got %q", res["policy_id"])
	}
}

func TestProxyRouter_MissingPosture_Deny(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:       rig.backendA.URL,
		BackendBURL:       rig.backendB.URL,
		OIDCIssuerURL:     rig.fakeOIDC.URL,
		OIDCClientID:      "zt-proxy",
		OIDCClientSecret:  "secret",
		OIDCRedirectURL:   "https://localhost/auth/callback",
		CookieSecret:      "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:            rig.fakeOPA.URL,
		PolicyTZ:          ist,
		MTLSDisabled:      true,
		DevDefaultCountry: "IN",
		PostureDisabled:   true,
		// No DevDefaultPosture — posture will be nil
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

	pc := policy.NewClient(cfg.OPAURL, 0, 100)
	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for missing posture, got %d", resp.StatusCode)
	}

	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res["policy_id"] != "missing-posture" {
		t.Errorf("expected policy_id 'missing-posture', got %q", res["policy_id"])
	}
}

func TestProxyRouter_PolicyPathCleaning(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	var receivedInput map[string]interface{}
	captureOPA := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if inp, ok := body["input"].(map[string]interface{}); ok {
			receivedInput = inp
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow": true, "reason": "", "policy_id": "", "denials": []interface{}{},
			},
		})
	})

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	router, authenticator := rig.newRouterWithPolicy(t, captureOPA)
	defer authenticator.Close()

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	// Request to /backend-a/admin/x should clean to /admin/x in policy input
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/backend-a/admin/x", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if receivedInput == nil {
		t.Fatal("OPA did not receive input")
	}
	resource, _ := receivedInput["resource"].(string)
	if resource != "/admin/x" {
		t.Errorf("expected policy resource '/admin/x', got %q", resource)
	}
}

func TestProxyRouter_PostureToken_Valid(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	privKey, err := posture.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate posture key: %v", err)
	}
	pubPEM, err := posture.EncodePublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	var capturedInput map[string]interface{}
	fakeOPAHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if inp, ok := body["input"].(map[string]interface{}); ok {
			capturedInput = inp
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow": true, "reason": "", "policy_id": "", "denials": []interface{}{},
			},
		})
	})

	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:       rig.backendA.URL,
		BackendBURL:       rig.backendB.URL,
		OIDCIssuerURL:     rig.fakeOIDC.URL,
		OIDCClientID:      "zt-proxy",
		OIDCClientSecret:  "secret",
		OIDCRedirectURL:   "https://localhost/auth/callback",
		CookieSecret:      "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:            rig.fakeOPA.URL,
		PolicyTZ:          ist,
		MTLSDisabled:      true,
		PostureDisabled:   true,
		DevDefaultCountry: "IN",
		PosturePublicKey:  pubPEM,
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

	rig.fakeOPA.Close()
	rig.fakeOPA = httptest.NewServer(fakeOPAHandler)
	cfg.OPAURL = rig.fakeOPA.URL

	pc := policy.NewClient(cfg.OPAURL, 0, 100)
	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	postureClaims := posture.PostureClaims{
		DeviceID:       "dev-123",
		DiskEncrypted:  true,
		FirewallOn:     true,
		OSPatchAgeDays: 3,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
	postureToken, err := posture.SignToken(postureClaims, privKey)
	if err != nil {
		t.Fatalf("failed to sign posture token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})
	req.Header.Set("X-Device-Posture", postureToken)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify posture claims forwarded to OPA input
	if capturedInput == nil {
		t.Fatal("OPA did not receive input")
	}
	dp, ok := capturedInput["device_posture"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected device_posture in OPA input, got %v", capturedInput["device_posture"])
	}
	if dp["device_id"] != "dev-123" || dp["disk_encrypted"] != true || dp["firewall_on"] != true || dp["os_patch_age_days"] != float64(3) {
		t.Errorf("unexpected posture claims in OPA input: %v", dp)
	}

	// Verify X-Device-Posture was stripped before reaching backend
	rig.mu.Lock()
	lastReq := rig.lastReqA
	rig.mu.Unlock()
	if lastReq == nil {
		t.Fatal("backendA did not receive request")
	}
	if lastReq.Header.Get("X-Device-Posture") != "" {
		t.Errorf("expected X-Device-Posture to be stripped, got %q", lastReq.Header.Get("X-Device-Posture"))
	}
}

func TestProxyRouter_PostureToken_Expired(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	privKey, err := posture.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate posture key: %v", err)
	}
	pubPEM, err := posture.EncodePublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:       rig.backendA.URL,
		BackendBURL:       rig.backendB.URL,
		OIDCIssuerURL:     rig.fakeOIDC.URL,
		OIDCClientID:      "zt-proxy",
		OIDCClientSecret:  "secret",
		OIDCRedirectURL:   "https://localhost/auth/callback",
		CookieSecret:      "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:            rig.fakeOPA.URL,
		PolicyTZ:          ist,
		MTLSDisabled:      true,
		DevDefaultCountry: "IN",
		PosturePublicKey:  pubPEM,
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

	pc := policy.NewClient(cfg.OPAURL, 0, 100)
	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	// Expired posture token
	postureClaims := posture.PostureClaims{
		DeviceID:       "dev-123",
		DiskEncrypted:  true,
		FirewallOn:     true,
		OSPatchAgeDays: 3,
		IssuedAt:       time.Now().Add(-10 * time.Minute).Unix(),
		ExpiresAt:      time.Now().Add(-1 * time.Second).Unix(),
	}
	postureToken, err := posture.SignToken(postureClaims, privKey)
	if err != nil {
		t.Fatalf("failed to sign posture token: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})
	req.Header.Set("X-Device-Posture", postureToken)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res["policy_id"] != "invalid-posture-token" {
		t.Errorf("expected policy_id 'invalid-posture-token', got %q", res["policy_id"])
	}
}

func TestProxyRouter_PostureToken_Tampered(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	privKey, err := posture.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate posture key: %v", err)
	}
	pubPEM, err := posture.EncodePublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:       rig.backendA.URL,
		BackendBURL:       rig.backendB.URL,
		OIDCIssuerURL:     rig.fakeOIDC.URL,
		OIDCClientID:      "zt-proxy",
		OIDCClientSecret:  "secret",
		OIDCRedirectURL:   "https://localhost/auth/callback",
		CookieSecret:      "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:            rig.fakeOPA.URL,
		PolicyTZ:          ist,
		MTLSDisabled:      true,
		DevDefaultCountry: "IN",
		PosturePublicKey:  pubPEM,
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

	pc := policy.NewClient(cfg.OPAURL, 0, 100)
	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	postureClaims := posture.PostureClaims{
		DeviceID:       "dev-123",
		DiskEncrypted:  false,
		FirewallOn:     false,
		OSPatchAgeDays: 999,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
	postureToken, err := posture.SignToken(postureClaims, privKey)
	if err != nil {
		t.Fatalf("failed to sign posture token: %v", err)
	}

	// Tamper with the token payload
	parts := strings.Split(postureToken, ".")
	fakeClaims := posture.PostureClaims{
		DeviceID:       "dev-123",
		DiskEncrypted:  true,
		FirewallOn:     true,
		OSPatchAgeDays: 1,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
	fakePayload, _ := json.Marshal(fakeClaims)
	tamperedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(fakePayload) + "." + parts[2]

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})
	req.Header.Set("X-Device-Posture", tamperedToken)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res["policy_id"] != "invalid-posture-token" {
		t.Errorf("expected policy_id 'invalid-posture-token', got %q", res["policy_id"])
	}
}

func TestProxyRouter_PostureToken_Missing(t *testing.T) {
	rig := setupTestRig(t)
	defer rig.Close()

	privKey, err := posture.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate posture key: %v", err)
	}
	pubPEM, err := posture.EncodePublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	ist, _ := time.LoadLocation("Asia/Kolkata")
	cfg := &config.Config{
		BackendAURL:       rig.backendA.URL,
		BackendBURL:       rig.backendB.URL,
		OIDCIssuerURL:     rig.fakeOIDC.URL,
		OIDCClientID:      "zt-proxy",
		OIDCClientSecret:  "secret",
		OIDCRedirectURL:   "https://localhost/auth/callback",
		CookieSecret:      "secret-key-that-is-at-least-32-bytes-long!",
		OPAURL:            rig.fakeOPA.URL,
		PolicyTZ:          ist,
		MTLSDisabled:      true,
		DevDefaultCountry: "IN",
		PosturePublicKey:  pubPEM,
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

	pc := policy.NewClient(cfg.OPAURL, 0, 100)
	router, err := NewProxyRouter(cfg, authenticator, pc)
	if err != nil {
		t.Fatalf("failed to init router: %v", err)
	}

	server := httptest.NewServer(router.Handler())
	defer server.Close()

	cookieSecret := "secret-key-that-is-at-least-32-bytes-long!"
	token := rig.signToken(t, auth.Claims{
		Issuer:            rig.fakeOIDC.URL,
		Subject:           "alice",
		Audience:          []string{"zt-proxy"},
		ExpiresAt:         time.Now().Unix() + 3600,
		PreferredUsername: "alice",
		Roles:             []string{"admin"},
	})
	signedCookie := auth.SignValue(token, []byte(cookieSecret))

	// No X-Device-Posture header attached
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	req.AddCookie(&http.Cookie{
		Name:  auth.SessionCookieName,
		Value: signedCookie,
	})

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}

	var res map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res["policy_id"] != "invalid-posture-token" {
		t.Errorf("expected policy_id 'invalid-posture-token', got %q", res["policy_id"])
	}
}
