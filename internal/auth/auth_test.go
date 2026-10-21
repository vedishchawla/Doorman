package auth

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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeOIDCServer struct {
	server      *httptest.Server
	privKey     *rsa.PrivateKey
	kid         string
	mu          sync.Mutex
	rotatedPriv *rsa.PrivateKey
	rotatedKid  string
}

func newFakeOIDCServer(t *testing.T) *fakeOIDCServer {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	fake := &fakeOIDCServer{
		privKey: privKey,
		kid:     "key-1",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := fake.server.URL
		disco := OIDCDiscovery{
			Issuer:                baseURL,
			AuthorizationEndpoint: baseURL + "/protocol/openid-connect/auth",
			TokenEndpoint:         baseURL + "/protocol/openid-connect/token",
			JWKSURI:               baseURL + "/protocol/openid-connect/certs",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(disco)
	})

	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		fake.mu.Lock()
		defer fake.mu.Unlock()

		keys := []JSONWebKey{
			toJWK(fake.privKey.Public().(*rsa.PublicKey), fake.kid),
		}
		if fake.rotatedPriv != nil {
			keys = append(keys, toJWK(fake.rotatedPriv.Public().(*rsa.PublicKey), fake.rotatedKid))
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JSONWebKeySet{Keys: keys})
	})

	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		code := r.Form.Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}

		// Mint a test ID token
		now := time.Now().Unix()
		claims := Claims{
			Issuer:            fake.server.URL,
			Subject:           "user-123",
			Audience:          []string{"zt-proxy"},
			ExpiresAt:         now + 3600,
			IssuedAt:          now,
			PreferredUsername: "alice",
			Email:             "alice@example.com",
			Roles:             []string{"admin"},
		}

		idToken := fake.signToken(t, claims, fake.privKey, fake.kid)

		resp := TokenResponse{
			AccessToken: idToken,
			IDToken:     idToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	fake.server = httptest.NewServer(mux)
	return fake
}

func toJWK(pub *rsa.PublicKey, kid string) JSONWebKey {
	nBytes := pub.N.Bytes()
	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
	// trim leading zeros
	for len(eBytes) > 1 && eBytes[0] == 0 {
		eBytes = eBytes[1:]
	}

	return JSONWebKey{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func (f *fakeOIDCServer) signToken(t *testing.T, claims Claims, key *rsa.PrivateKey, kid string) string {
	t.Helper()

	header := jwtHeader{
		Alg: "RS256",
		Kid: kid,
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("failed to marshal header: %v", err)
	}

	// Helper struct for serializing audience as array
	type fullClaims struct {
		Claims
		Aud []string `json:"aud"`
	}

	claimsJSON, err := json.Marshal(fullClaims{Claims: claims, Aud: claims.Audience})
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	part1 := base64.RawURLEncoding.EncodeToString(headerJSON)
	part2 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := part1 + "." + part2

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	part3 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + part3
}

func TestOIDC_FullBrowserFlow(t *testing.T) {
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")

	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "dev-secret",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	// Protected handler that verifies claims
	protectedHandler := authenticator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			t.Errorf("claims not found in context")
			http.Error(w, "missing claims", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"user":  claims.PreferredUsername,
			"roles": claims.Roles,
		})
	}))

	// Step 1: Unauthenticated browser request -> 302 to /auth/login
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/auth/login?redirect=") {
		t.Fatalf("expected redirect to /auth/login, got %q", loc)
	}

	// Step 2: GET /auth/login -> 302 to Keycloak auth endpoint with state cookie
	loginReq := httptest.NewRequest(http.MethodGet, loc, nil)
	loginRec := httptest.NewRecorder()
	authenticator.HandleLogin(loginRec, loginReq)

	if loginRec.Code != http.StatusFound {
		t.Fatalf("expected status 302 from login, got %d", loginRec.Code)
	}
	keycloakRedirect := loginRec.Header().Get("Location")
	parsedURL, err := url.Parse(keycloakRedirect)
	if err != nil {
		t.Fatalf("invalid redirect URL: %v", err)
	}
	stateParam := parsedURL.Query().Get("state")
	if stateParam == "" {
		t.Fatal("expected state parameter in redirect URL")
	}

	// Find the state cookie
	var stateCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == StateCookieName {
			stateCookie = c
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("expected state cookie to be set")
	}

	// Step 3: Callback with authorization code and state
	callbackReq := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state="+stateParam, nil)
	callbackReq.AddCookie(stateCookie)
	callbackRec := httptest.NewRecorder()
	authenticator.HandleCallback(callbackRec, callbackReq)

	if callbackRec.Code != http.StatusFound {
		t.Fatalf("expected status 302 from callback, got %d body: %s", callbackRec.Code, callbackRec.Body.String())
	}
	if callbackRec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %q", callbackRec.Header().Get("Location"))
	}

	// Verify session cookie was set
	var sessionCookie *http.Cookie
	for _, c := range callbackRec.Result().Cookies() {
		if c.Name == SessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie to be set")
	}

	// Step 4: Access protected route with session cookie -> 200 OK with claims
	authedReq := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	authedReq.AddCookie(sessionCookie)
	authedRec := httptest.NewRecorder()
	protectedHandler.ServeHTTP(authedRec, authedReq)

	if authedRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", authedRec.Code)
	}

	var res map[string]interface{}
	if err := json.NewDecoder(authedRec.Body).Decode(&res); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if res["user"] != "alice" {
		t.Errorf("expected user 'alice', got %v", res["user"])
	}
}

func TestOIDC_APIRequests_401JSON(t *testing.T) {
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")
	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "dev-secret",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	handler := authenticator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// 1. Unauthenticated API request (application/json)
	req := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", rec.Header().Get("Content-Type"))
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("invalid json body: %v", err)
	}
	if body["error"] != "unauthorized" {
		t.Errorf("expected error=unauthorized, got %q", body["error"])
	}

	// 2. Authenticated API request with Bearer token
	now := time.Now().Unix()
	validToken := fake.signToken(t, Claims{
		Issuer:    fake.server.URL,
		Subject:   "api-client",
		Audience:  []string{"zt-proxy"},
		ExpiresAt: now + 300,
	}, fake.privKey, fake.kid)

	req2 := httptest.NewRequest(http.MethodGet, "/api/resource", nil)
	req2.Header.Set("Authorization", "Bearer "+validToken)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec2.Code)
	}
}

func TestOIDC_InvalidTokens(t *testing.T) {
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")
	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "dev-secret",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	handler := authenticator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	now := time.Now().Unix()

	tests := []struct {
		name   string
		claims Claims
	}{
		{
			name: "expired token",
			claims: Claims{
				Issuer:    fake.server.URL,
				Subject:   "test",
				Audience:  []string{"zt-proxy"},
				ExpiresAt: now - 300, // expired 5 mins ago
			},
		},
		{
			name: "wrong issuer",
			claims: Claims{
				Issuer:    "http://rogue-issuer",
				Subject:   "test",
				Audience:  []string{"zt-proxy"},
				ExpiresAt: now + 300,
			},
		},
		{
			name: "wrong audience",
			claims: Claims{
				Issuer:    fake.server.URL,
				Subject:   "test",
				Audience:  []string{"another-client"},
				ExpiresAt: now + 300,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := fake.signToken(t, tc.claims, fake.privKey, fake.kid)
			req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for %s, got %d", tc.name, rec.Code)
			}
		})
	}

	// Test tampered signature
	t.Run("tampered signature", func(t *testing.T) {
		token := fake.signToken(t, Claims{
			Issuer:    fake.server.URL,
			Subject:   "test",
			Audience:  []string{"zt-proxy"},
			ExpiresAt: now + 300,
		}, fake.privKey, fake.kid)

		tampered := token[:len(token)-5] + "AAAAA"
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Authorization", "Bearer "+tampered)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for tampered signature, got %d", rec.Code)
		}
	})

	// Test tampered session cookie
	t.Run("tampered session cookie", func(t *testing.T) {
		validToken := fake.signToken(t, Claims{
			Issuer:    fake.server.URL,
			Subject:   "test",
			Audience:  []string{"zt-proxy"},
			ExpiresAt: now + 300,
		}, fake.privKey, fake.kid)

		signedVal := SignValue(validToken, cookieSecret)
		tamperedVal := signedVal[:len(signedVal)-4] + "dead"

		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.AddCookie(&http.Cookie{
			Name:  SessionCookieName,
			Value: tamperedVal,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for tampered cookie, got %d", rec.Code)
		}
	})
}

func TestJWKS_KeyRotation(t *testing.T) {
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")
	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "dev-secret",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	// Simulate Keycloak rotating keys: generate a second key
	rotatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rotated key: %v", err)
	}

	fake.mu.Lock()
	fake.rotatedPriv = rotatedKey
	fake.rotatedKid = "key-2"
	fake.mu.Unlock()

	// Mint token using key-2
	now := time.Now().Unix()
	claims := Claims{
		Issuer:    fake.server.URL,
		Subject:   "bob",
		Audience:  []string{"zt-proxy"},
		ExpiresAt: now + 300,
	}
	rotatedToken := fake.signToken(t, claims, rotatedKey, "key-2")

	// Validate token: should fetch new key on-demand and succeed
	parsedClaims, err := authenticator.validator.Validate(context.Background(), rotatedToken)
	if err != nil {
		t.Fatalf("validation failed for rotated key: %v", err)
	}
	if parsedClaims.Subject != "bob" {
		t.Errorf("expected subject 'bob', got %q", parsedClaims.Subject)
	}
}
