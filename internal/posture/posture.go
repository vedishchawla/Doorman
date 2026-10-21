// Package posture provides ES256 JWT signing and verification for device
// posture attestation tokens sent in the X-Device-Posture header.
package posture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// PostureClaims represents the claims in a device posture JWT.
type PostureClaims struct {
	DeviceID       string `json:"device_id"`
	DiskEncrypted  bool   `json:"disk_encrypted"`
	FirewallOn     bool   `json:"firewall_on"`
	OSPatchAgeDays int    `json:"os_patch_age_days"`
	ExpiresAt      int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
}

var (
	ErrMissingToken     = errors.New("missing posture token")
	ErrMalformedToken   = errors.New("malformed posture token")
	ErrUnsupportedAlg   = errors.New("unsupported posture token algorithm")
	ErrInvalidSignature = errors.New("invalid posture token signature")
	ErrTokenExpired     = errors.New("posture token expired")
	ErrMissingClaim     = errors.New("missing posture claim")
)

// jwtHeader is the JWT header for posture tokens.
type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Verifier verifies ES256-signed posture JWTs against a configured public key.
type Verifier struct {
	pubKey *ecdsa.PublicKey
}

// NewVerifier creates a Verifier from a PEM-encoded EC P-256 public key.
func NewVerifier(publicKeyPEM string) (*Verifier, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode posture public key PEM")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse posture public key: %w", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("posture public key is not an ECDSA key")
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, errors.New("posture public key must use P-256 curve")
	}

	return &Verifier{pubKey: ecPub}, nil
}

// NewVerifierFromKey creates a Verifier directly from an ECDSA public key (for testing).
func NewVerifierFromKey(pub *ecdsa.PublicKey) *Verifier {
	return &Verifier{pubKey: pub}
}

// Verify verifies an ES256 posture JWT and returns the claims.
// Fails closed on any error.
func (v *Verifier) Verify(tokenString string) (*PostureClaims, error) {
	if tokenString == "" {
		return nil, ErrMissingToken
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	// Decode and verify header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header decode failed", ErrMalformedToken)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: header parse failed", ErrMalformedToken)
	}

	if header.Alg != "ES256" {
		return nil, fmt.Errorf("%w: got %q, expected ES256", ErrUnsupportedAlg, header.Alg)
	}

	// Verify signature
	signedContent := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signedContent))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature decode failed", ErrMalformedToken)
	}

	// ES256 signature is r || s, each 32 bytes
	if len(sigBytes) != 64 {
		return nil, fmt.Errorf("%w: invalid ES256 signature length", ErrInvalidSignature)
	}

	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])

	if !ecdsa.Verify(v.pubKey, hash[:], r, s) {
		return nil, ErrInvalidSignature
	}

	// Parse payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload decode failed", ErrMalformedToken)
	}

	var rawClaims map[string]json.RawMessage
	if err := json.Unmarshal(payloadBytes, &rawClaims); err != nil {
		return nil, fmt.Errorf("%w: payload unmarshal failed", ErrMalformedToken)
	}
	for _, name := range []string{"device_id", "disk_encrypted", "firewall_on", "os_patch_age_days", "exp", "iat"} {
		if _, ok := rawClaims[name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingClaim, name)
		}
	}

	var claims PostureClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims unmarshal failed", ErrMalformedToken)
	}

	// Check expiry
	if time.Now().Unix() >= claims.ExpiresAt {
		return nil, ErrTokenExpired
	}

	return &claims, nil
}

// GenerateKeyPair generates a new ECDSA P-256 keypair for posture signing.
func GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// SignToken signs posture claims as an ES256 JWT.
func SignToken(claims PostureClaims, privKey *ecdsa.PrivateKey) (string, error) {
	header := `{"alg":"ES256","typ":"JWT"}`
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal posture claims: %w", err)
	}

	p1 := base64.RawURLEncoding.EncodeToString([]byte(header))
	p2 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signedContent := p1 + "." + p2

	hash := sha256.Sum256([]byte(signedContent))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign posture token: %w", err)
	}

	// Fixed-width r || s encoding (32 bytes each for P-256)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):], sBytes)

	p3 := base64.RawURLEncoding.EncodeToString(sig)
	return signedContent + "." + p3, nil
}

// EncodePublicKeyPEM encodes an ECDSA public key to PEM format.
func EncodePublicKeyPEM(pub *ecdsa.PublicKey) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// EncodePrivateKeyPEM encodes an ECDSA private key to PEM format.
func EncodePrivateKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	derBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// DecodePrivateKeyPEM decodes a PEM-encoded ECDSA private key.
func DecodePrivateKeyPEM(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}
