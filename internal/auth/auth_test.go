package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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
		ClientSecret: "test-client-secret-mock",
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
		ClientSecret: "test-client-secret-mock",
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
		ClientSecret: "test-client-secret-mock",
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
		ClientSecret: "test-client-secret-mock",
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

func TestJWT_UnsupportedAlgorithmsAndUnknownKid(t *testing.T) {
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")
	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "test-client-secret-mock",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	now := time.Now().Unix()
	claims := Claims{
		Issuer:    fake.server.URL,
		Subject:   "attacker",
		Audience:  []string{"zt-proxy"},
		ExpiresAt: now + 300,
	}
	claimsJSON, _ := json.Marshal(claims)
	payloadPart := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// 1. alg: "none"
	t.Run("alg none is rejected", func(t *testing.T) {
		noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"key-1","typ":"JWT"}`))
		noneToken := noneHeader + "." + payloadPart + "."

		_, err := authenticator.validator.Validate(context.Background(), noneToken)
		if err == nil {
			t.Fatal("expected error for alg 'none', got nil")
		}
		if !strings.Contains(err.Error(), "expected RS256") {
			t.Errorf("expected error mentioning RS256, got %v", err)
		}
	})

	// 2. alg: "HS256" signed with the RSA public key (algorithm confusion attack)
	t.Run("alg HS256 signed with public key is rejected", func(t *testing.T) {
		hsHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","kid":"key-1","typ":"JWT"}`))
		signingInput := hsHeader + "." + payloadPart

		pubKeyBytes, err := x509.MarshalPKIXPublicKey(fake.privKey.Public())
		if err != nil {
			t.Fatalf("failed to marshal public key: %v", err)
		}

		mac := hmac.New(sha256.New, pubKeyBytes)
		mac.Write([]byte(signingInput))
		sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

		hsToken := signingInput + "." + sig
		_, err = authenticator.validator.Validate(context.Background(), hsToken)
		if err == nil {
			t.Fatal("expected error for alg 'HS256', got nil")
		}
		if !strings.Contains(err.Error(), "expected RS256") {
			t.Errorf("expected error mentioning RS256, got %v", err)
		}
	})

	// 3. Unknown kid
	t.Run("unknown kid fails closed", func(t *testing.T) {
		unknownKidHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"nonexistent-kid-999","typ":"JWT"}`))
		signingInput := unknownKidHeader + "." + payloadPart

		digest := sha256.Sum256([]byte(signingInput))
		sigBytes, _ := rsa.SignPKCS1v15(rand.Reader, fake.privKey, crypto.SHA256, digest[:])
		sig := base64.RawURLEncoding.EncodeToString(sigBytes)

		unknownKidToken := signingInput + "." + sig
		_, err := authenticator.validator.Validate(context.Background(), unknownKidToken)
		if err == nil {
			t.Fatal("expected error for unknown kid, got nil")
		}
	})

	// 4. Empty kid
	t.Run("empty kid fails closed", func(t *testing.T) {
		emptyKidHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"","typ":"JWT"}`))
		signingInput := emptyKidHeader + "." + payloadPart

		digest := sha256.Sum256([]byte(signingInput))
		sigBytes, _ := rsa.SignPKCS1v15(rand.Reader, fake.privKey, crypto.SHA256, digest[:])
		sig := base64.RawURLEncoding.EncodeToString(sigBytes)

		emptyKidToken := signingInput + "." + sig
		_, err := authenticator.validator.Validate(context.Background(), emptyKidToken)
		if err == nil {
			t.Fatal("expected error for empty kid, got nil")
		}
	})
}

func TestCallback_StateValidation(t *testing.T) {
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")
	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "test-client-secret-mock",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	stateCookieVal := SignValue("expected-state-value|/dashboard", cookieSecret)

	// Case 1: Missing state query parameter
	t.Run("missing state query parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code", nil)
		req.AddCookie(&http.Cookie{
			Name:  StateCookieName,
			Value: stateCookieVal,
		})
		rec := httptest.NewRecorder()
		authenticator.HandleCallback(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing state param, got %d", rec.Code)
		}
	})

	// Case 2: Missing state cookie
	t.Run("missing state cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state=expected-state-value", nil)
		rec := httptest.NewRecorder()
		authenticator.HandleCallback(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for missing state cookie, got %d", rec.Code)
		}
	})

	// Case 3: Mismatched state parameter
	t.Run("mismatched state parameter", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?code=mock-code&state=wrong-state-value", nil)
		req.AddCookie(&http.Cookie{
			Name:  StateCookieName,
			Value: stateCookieVal,
		})
		rec := httptest.NewRecorder()
		authenticator.HandleCallback(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for mismatched state, got %d", rec.Code)
		}
	})
}

func TestLogin_RedirectParameterSanitization(t *testing.T) {
	// Unit tests for SanitizeRedirectURI directly
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"valid relative root", "/", "/"},
		{"valid relative path", "/dashboard", "/dashboard"},
		{"valid relative nested path with query", "/api/v1/resource?id=123", "/api/v1/resource?id=123"},
		{"empty string falls back to /", "", "/"},
		{"protocol relative //host rejected", "//evil.com", "/"},
		{"protocol relative //host/path rejected", "//evil.com/phish", "/"},
		{"backslash /\\host rejected", "/\\evil.com", "/"},
		{"backslash /\\\\host rejected", "/\\\\evil.com", "/"},
		{"absolute http URL rejected", "http://evil.com", "/"},
		{"absolute https URL rejected", "https://evil.com/login", "/"},
		{"javascript scheme rejected", "javascript:alert(1)", "/"},
		{"relative path with no leading slash rejected", "dashboard", "/"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeRedirectURI(tc.input)
			if got != tc.expected {
				t.Errorf("SanitizeRedirectURI(%q) = %q, expected %q", tc.input, got, tc.expected)
			}
		})
	}

	// Integration test with HandleLogin
	fake := newFakeOIDCServer(t)
	defer fake.server.Close()

	cookieSecret := []byte("secret-key-that-is-at-least-32-bytes-long!")
	authCfg := AuthenticatorConfig{
		IssuerURL:    fake.server.URL,
		ClientID:     "zt-proxy",
		ClientSecret: "test-client-secret-mock",
		RedirectURL:  "https://localhost/auth/callback",
		CookieSecret: cookieSecret,
		HTTPClient:   fake.server.Client(),
	}

	authenticator, err := NewAuthenticator(context.Background(), authCfg)
	if err != nil {
		t.Fatalf("failed to init authenticator: %v", err)
	}
	defer authenticator.Close()

	loginTests := []struct {
		name           string
		queryRedirect  string
		expectedTarget string
	}{
		{"protocol relative //attacker.com falls back to /", "//attacker.com", "/"},
		{"protocol relative /\\attacker.com falls back to /", "/\\attacker.com", "/"},
		{"absolute URL falls back to /", "https://attacker.com/steal", "/"},
		{"valid relative path preserved", "/user/profile", "/user/profile"},
	}

	for _, tc := range loginTests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/auth/login?redirect="+url.QueryEscape(tc.queryRedirect), nil)
			rec := httptest.NewRecorder()
			authenticator.HandleLogin(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("expected 302, got %d", rec.Code)
			}

			// Inspect the set state cookie to verify target was sanitized
			var stateCookie *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == StateCookieName {
					stateCookie = c
					break
				}
			}
			if stateCookie == nil {
				t.Fatal("expected state cookie to be set")
			}

			payload, err := VerifyValue(stateCookie.Value, cookieSecret)
			if err != nil {
				t.Fatalf("failed to verify state cookie: %v", err)
			}

			parts := strings.SplitN(payload, "|", 2)
			if len(parts) != 2 {
				t.Fatalf("invalid payload format: %q", payload)
			}
			if parts[1] != tc.expectedTarget {
				t.Errorf("expected target %q in cookie payload, got %q", tc.expectedTarget, parts[1])
			}
		})
	}
}
