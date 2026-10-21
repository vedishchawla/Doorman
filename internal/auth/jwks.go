package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

var (
	ErrKeyNotFound = errors.New("key not found in JWKS")
	ErrUnsupportedKey = errors.New("unsupported key type or algorithm")
)

// JSONWebKey represents a single JWK.
type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JSONWebKeySet represents the JWKS response structure.
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// JWKSCache maintains an in-memory cache of parsed RSA public keys from a JWKS endpoint.
type JWKSCache struct {
	jwksURL         string
	httpClient      *http.Client
	refreshInterval time.Duration

	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
	stopCh chan struct{}
}

// NewJWKSCache initializes a new JWKSCache.
func NewJWKSCache(jwksURL string, refreshInterval time.Duration, httpClient *http.Client) *JWKSCache {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if refreshInterval <= 0 {
		refreshInterval = 5 * time.Minute
	}
	return &JWKSCache{
		jwksURL:         jwksURL,
		httpClient:      httpClient,
		refreshInterval: refreshInterval,
		keys:            make(map[string]*rsa.PublicKey),
		stopCh:          make(chan struct{}),
	}
}

// Start performs the initial key fetch and launches the background refresh worker.
func (c *JWKSCache) Start(ctx context.Context) error {
	if err := c.Refresh(ctx); err != nil {
		return fmt.Errorf("initial JWKS fetch failed: %w", err)
	}

	go c.backgroundRefresh()
	return nil
}

// Close stops the background refresh worker.
func (c *JWKSCache) Close() {
	select {
	case <-c.stopCh:
		// already closed
	default:
		close(c.stopCh)
	}
}

func (c *JWKSCache) backgroundRefresh() {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = c.Refresh(ctx)
			cancel()
		}
	}
}

// Refresh fetches and parses the JWKS from the endpoint.
func (c *JWKSCache) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("jwks request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected jwks status code: %d", resp.StatusCode)
	}

	var jwks JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decoding jwks failed: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "RSA" {
			continue
		}
		pubKey, err := parseRSAPublicKey(jwk.N, jwk.E)
		if err == nil && jwk.Kid != "" {
			newKeys[jwk.Kid] = pubKey
		}
	}

	c.mu.Lock()
	c.keys = newKeys
	c.mu.Unlock()

	return nil
}

// GetKey retrieves a public key by key ID, fetching on-demand if missing.
func (c *JWKSCache) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()

	if ok {
		return key, nil
	}

	// On-demand refresh for potential key rotation
	if err := c.Refresh(ctx); err != nil {
		return nil, fmt.Errorf("on-demand jwks refresh failed: %w", err)
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}

	var eInt int
	if len(eBytes) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(eBytes):], eBytes)
		eInt = int(binary.BigEndian.Uint32(padded))
	} else {
		eInt = int(binary.BigEndian.Uint32(eBytes[:4]))
	}

	n := new(big.Int).SetBytes(nBytes)
	return &rsa.PublicKey{
		N: n,
		E: eInt,
	}, nil
}
