package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCDiscovery represents standard OpenID Connect discovery document endpoints.
type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// TokenResponse represents the JSON returned by the OIDC token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// AuthenticatorConfig holds settings for OIDC authentication.
type AuthenticatorConfig struct {
	IssuerURL    string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	CookieSecret []byte
	HTTPClient   *http.Client
}

// Authenticator handles OIDC authentication flows and middleware.
type Authenticator struct {
	cfg        AuthenticatorConfig
	discovery  *OIDCDiscovery
	jwksCache  *JWKSCache
	validator  *Validator
	httpClient *http.Client
}

// NewAuthenticator initializes the Authenticator by fetching the OIDC discovery document
// and configuring the JWKS cache and token validator.
func NewAuthenticator(ctx context.Context, cfg AuthenticatorConfig) (*Authenticator, error) {
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	disco, err := fetchDiscovery(ctx, cfg.HTTPClient, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}

	jwksCache := NewJWKSCache(disco.JWKSURI, 5*time.Minute, cfg.HTTPClient)
	if err := jwksCache.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize JWKS cache: %w", err)
	}

	validator := NewValidator(disco.Issuer, cfg.ClientID, jwksCache)

	return &Authenticator{
		cfg:        cfg,
		discovery:  disco,
		jwksCache:  jwksCache,
		validator:  validator,
		httpClient: cfg.HTTPClient,
	}, nil
}

// Close stops background workers.
func (a *Authenticator) Close() {
	if a.jwksCache != nil {
		a.jwksCache.Close()
	}
}

// HandleLogin initiates the OIDC authorization code flow.
func (a *Authenticator) HandleLogin(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("redirect")
	if target == "" || !strings.HasPrefix(target, "/") {
		target = "/"
	}

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	stateVal := hex.EncodeToString(stateBytes)

	// Combine state and target URL in state cookie payload: "<state>|<target>"
	statePayload := stateVal + "|" + target
	signedState := SignValue(statePayload, a.cfg.CookieSecret)

	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    signedState,
		Path:     "/",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL, err := url.Parse(a.discovery.AuthorizationEndpoint)
	if err != nil {
		http.Error(w, "invalid authorization endpoint", http.StatusInternalServerError)
		return
	}

	q := authURL.Query()
	q.Set("client_id", a.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email roles")
	q.Set("redirect_uri", a.cfg.RedirectURL)
	q.Set("state", stateVal)
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusFound)
}

// HandleCallback processes the authorization response from Keycloak.
func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		slog.Warn("callback received with missing code or state", "code_present", code != "", "state_present", state != "")
		a.writeUnauthorized(w, r, "missing authorization code or state")
		return
	}

	// Verify state cookie
	cookie, err := r.Cookie(StateCookieName)
	if err != nil {
		slog.Warn("missing state cookie in callback")
		a.writeUnauthorized(w, r, "state cookie missing")
		return
	}

	verifiedStatePayload, err := VerifyValue(cookie.Value, a.cfg.CookieSecret)
	if err != nil {
		slog.Warn("tampered or invalid state cookie", "error", err)
		a.writeUnauthorized(w, r, "invalid state cookie")
		return
	}

	parts := strings.SplitN(verifiedStatePayload, "|", 2)
	if len(parts) != 2 || parts[0] != state {
		slog.Warn("state mismatch in callback")
		a.writeUnauthorized(w, r, "state mismatch")
		return
	}
	targetURL := parts[1]

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Exchange code for tokens
	tokenResp, err := a.exchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("token exchange failed", "error", err)
		a.writeUnauthorized(w, r, "token exchange failed")
		return
	}

	// Validate token: prefer ID token if available, fallback to Access token
	tokenToValidate := tokenResp.IDToken
	if tokenToValidate == "" {
		tokenToValidate = tokenResp.AccessToken
	}

	claims, err := a.validator.Validate(r.Context(), tokenToValidate)
	if err != nil {
		slog.Error("token validation failed on callback", "error", err)
		a.writeUnauthorized(w, r, "token validation failed")
		return
	}

	// Set session cookie
	maxAge := time.Duration(tokenResp.ExpiresIn) * time.Second
	if maxAge <= 0 {
		maxAge = 1 * time.Hour
	}
	SetSessionCookie(w, tokenToValidate, a.cfg.CookieSecret, maxAge)

	slog.Info("user successfully authenticated", "sub", claims.Subject, "email", claims.Email, "roles", claims.Roles)
	http.Redirect(w, r, targetURL, http.StatusFound)
}

// Middleware verifies incoming requests: redirects browsers to login, returns 401 JSON for APIs.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := a.extractToken(r)
		if token == "" {
			a.failAuth(w, r, "missing authentication token")
			return
		}

		claims, err := a.validator.Validate(r.Context(), token)
		if err != nil {
			slog.Warn("invalid token", "error", err, "path", r.URL.Path)
			a.failAuth(w, r, "invalid or expired token")
			return
		}

		ctx := ContextWithClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) extractToken(r *http.Request) string {
	// 1. Session cookie
	if tok, err := GetSessionToken(r, a.cfg.CookieSecret); err == nil && tok != "" {
		return tok
	}

	// 2. Authorization header: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}

	return ""
}

func (a *Authenticator) failAuth(w http.ResponseWriter, r *http.Request, msg string) {
	if isBrowserRequest(r) {
		redirectPath := "/auth/login?redirect=" + url.QueryEscape(r.RequestURI)
		http.Redirect(w, r, redirectPath, http.StatusFound)
		return
	}

	a.writeUnauthorized(w, r, msg)
}

func (a *Authenticator) writeUnauthorized(w http.ResponseWriter, r *http.Request, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": msg,
	})
}

func isBrowserRequest(r *http.Request) bool {
	// If explicit Authorization header is passed, treat as API client
	if r.Header.Get("Authorization") != "" {
		return false
	}

	// Browser navigation
	if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
		return true
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") && !strings.Contains(accept, "application/json") {
		return true
	}

	return false
}

func (a *Authenticator) exchangeCode(ctx context.Context, code string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", a.cfg.RedirectURL)
	data.Set("client_id", a.cfg.ClientID)
	data.Set("client_secret", a.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.discovery.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decoding token response failed: %w", err)
	}

	return &tokenResp, nil
}

func fetchDiscovery(ctx context.Context, client *http.Client, issuerURL string) (*OIDCDiscovery, error) {
	wellKnownURL := strings.TrimSuffix(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var disco OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
		return nil, err
	}

	return &disco, nil
}
