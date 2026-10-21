package auth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMalformedToken  = errors.New("malformed jwt")
	ErrUnsupportedAlg  = errors.New("unsupported jwt algorithm")
	ErrInvalidSignature= errors.New("invalid jwt signature")
	ErrTokenExpired    = errors.New("jwt token is expired")
	ErrTokenNotYetValid= errors.New("jwt token not yet valid (nbf)")
	ErrInvalidIssuer   = errors.New("invalid jwt issuer")
	ErrInvalidAudience = errors.New("invalid jwt audience")
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// Validator validates signed JWTs against JWKS and verification rules.
type Validator struct {
	issuer   string
	audience string
	jwks     *JWKSCache
	clockSkew time.Duration
}

// NewValidator initializes a new JWT Validator.
func NewValidator(issuer, audience string, jwks *JWKSCache) *Validator {
	return &Validator{
		issuer:    issuer,
		audience:  audience,
		jwks:      jwks,
		clockSkew: 1 * time.Minute,
	}
}

// Validate parses, verifies the RS256 signature, and validates claims of a JWT.
func (v *Validator) Validate(ctx context.Context, tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header decode failed", ErrMalformedToken)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: header json unmarshal failed", ErrMalformedToken)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("%w: expected RS256, got %q", ErrUnsupportedAlg, header.Alg)
	}

	if header.Kid == "" {
		return nil, fmt.Errorf("%w: kid cannot be empty", ErrUnsupportedAlg)
	}

	// Fetch public key
	pubKey, err := v.jwks.GetKey(ctx, header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key for kid %q: %w", header.Kid, err)
	}

	// Verify signature
	signedContent := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signedContent))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature decode failed", ErrMalformedToken)
	}

	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return nil, ErrInvalidSignature
	}

	// Parse payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload decode failed", ErrMalformedToken)
	}

	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: payload json unmarshal failed", ErrMalformedToken)
	}

	now := time.Now().Unix()

	// Validate exp
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt+int64(v.clockSkew.Seconds()) {
		return nil, ErrTokenExpired
	}

	// Validate nbf
	if claims.NotBefore > 0 && now < claims.NotBefore-int64(v.clockSkew.Seconds()) {
		return nil, ErrTokenNotYetValid
	}

	// Validate iss
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrInvalidIssuer, v.issuer, claims.Issuer)
	}

	// Validate aud (also accept azp / authorized party, which Keycloak uses for access tokens)
	if v.audience != "" {
		audMatched := false
		for _, aud := range claims.Audience {
			if aud == v.audience {
				audMatched = true
				break
			}
		}
		if !audMatched && claims.AuthorizedParty == v.audience {
			audMatched = true
		}
		if !audMatched {
			return nil, fmt.Errorf("%w: expected %q in aud %v or azp %q", ErrInvalidAudience, v.audience, claims.Audience, claims.AuthorizedParty)
		}
	}

	return &claims, nil
}
