package posture

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return priv
}

func makeValidClaims() PostureClaims {
	return PostureClaims{
		DeviceID:       "test-device-001",
		DiskEncrypted:  true,
		FirewallOn:     true,
		OSPatchAgeDays: 5,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}
}

func TestVerify_ValidToken(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	token, err := SignToken(makeValidClaims(), priv)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	got, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if got.DeviceID != "test-device-001" {
		t.Errorf("expected device_id 'test-device-001', got %q", got.DeviceID)
	}
	if !got.DiskEncrypted {
		t.Error("expected disk_encrypted=true")
	}
	if !got.FirewallOn {
		t.Error("expected firewall_on=true")
	}
	if got.OSPatchAgeDays != 5 {
		t.Errorf("expected os_patch_age_days=5, got %d", got.OSPatchAgeDays)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	claims := makeValidClaims()
	claims.IssuedAt = time.Now().Add(-10 * time.Minute).Unix()
	claims.ExpiresAt = time.Now().Add(-1 * time.Second).Unix() // already expired

	token, err := SignToken(claims, priv)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = v.Verify(token)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerify_TamperedToken(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	// Sign an unhealthy token
	claims := makeValidClaims()
	claims.DiskEncrypted = false
	claims.FirewallOn = false

	token, err := SignToken(claims, priv)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	// Replace payload with a healthy-looking one but keep original signature
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("unexpected token format")
	}

	fakeClaims := makeValidClaims() // healthy claims
	fakePayload, _ := json.Marshal(fakeClaims)
	tamperedToken := parts[0] + "." + base64.RawURLEncoding.EncodeToString(fakePayload) + "." + parts[2]

	_, err = v.Verify(tamperedToken)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for tampered token, got %v", err)
	}
}

func TestVerify_MissingToken(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	_, err := v.Verify("")
	if !errors.Is(err, ErrMissingToken) {
		t.Errorf("expected ErrMissingToken, got %v", err)
	}
}

func TestVerify_WrongAlgorithm(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	// Craft a token with alg=RS256 in the header
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payload := makeValidClaims()
	payloadJSON, _ := json.Marshal(payload)

	fakeToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + "." +
		base64.RawURLEncoding.EncodeToString(make([]byte, 64))

	_, err := v.Verify(fakeToken)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("expected ErrUnsupportedAlg, got %v", err)
	}

}

func TestVerify_HS256AlgorithmRejected(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	headerJSON, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payloadJSON, _ := json.Marshal(makeValidClaims())
	token := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + ".invalid"

	_, err := v.Verify(token)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("expected ErrUnsupportedAlg, got %v", err)
	}
}

func TestVerify_MissingClaimRejected(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)
	claims := makeValidClaims()
	payload := map[string]interface{}{
		"device_id": claims.DeviceID, "disk_encrypted": claims.DiskEncrypted,
		"firewall_on": claims.FirewallOn, "iat": claims.IssuedAt, "exp": claims.ExpiresAt,
	}
	payloadJSON, _ := json.Marshal(payload)
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString(payloadJSON)
	hash := sha256.Sum256([]byte(header + "." + body))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	copy(sig[32-len(r.Bytes()):32], r.Bytes())
	copy(sig[64-len(s.Bytes()):], s.Bytes())
	token := header + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)

	_, err = v.Verify(token)
	if !errors.Is(err, ErrMissingClaim) {
		t.Errorf("expected ErrMissingClaim, got %v", err)
	}
}

func TestVerify_AlgNone(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	header := map[string]string{"alg": "none", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(makeValidClaims())

	fakeToken := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + "."

	_, err := v.Verify(fakeToken)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Errorf("expected ErrUnsupportedAlg for alg=none, got %v", err)
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	tests := []struct {
		name  string
		token string
	}{
		{"only two parts", "aaa.bbb"},
		{"four parts", "aaa.bbb.ccc.ddd"},
		{"garbage", "notavalidjwt"},
		{"empty parts", ".."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(tc.token)
			if err == nil {
				t.Error("expected error for malformed token")
			}
		})
	}
}

func TestSignToken_Roundtrip_Unhealthy(t *testing.T) {
	priv := generateTestKey(t)
	v := NewVerifierFromKey(&priv.PublicKey)

	claims := PostureClaims{
		DeviceID:       "demo-device",
		DiskEncrypted:  false,
		FirewallOn:     false,
		OSPatchAgeDays: 999,
		IssuedAt:       time.Now().Unix(),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Unix(),
	}

	token, err := SignToken(claims, priv)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	got, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if got.DiskEncrypted {
		t.Error("expected disk_encrypted=false (unhealthy)")
	}
	if got.FirewallOn {
		t.Error("expected firewall_on=false (unhealthy)")
	}
	if got.OSPatchAgeDays != 999 {
		t.Errorf("expected os_patch_age_days=999, got %d", got.OSPatchAgeDays)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	priv1 := generateTestKey(t)
	priv2 := generateTestKey(t)
	v := NewVerifierFromKey(&priv2.PublicKey) // verify with key2

	token, err := SignToken(makeValidClaims(), priv1) // sign with key1
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = v.Verify(token)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature with wrong key, got %v", err)
	}
}

func TestPEMRoundtrip(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	pubPEM, err := EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyPEM failed: %v", err)
	}

	v, err := NewVerifier(pubPEM)
	if err != nil {
		t.Fatalf("NewVerifier from PEM failed: %v", err)
	}

	token, err := SignToken(makeValidClaims(), priv)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	got, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify via PEM verifier failed: %v", err)
	}
	if got.DeviceID != "test-device-001" {
		t.Errorf("expected device_id 'test-device-001', got %q", got.DeviceID)
	}
}

func TestPrivateKeyPEMRoundtrip(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	privPEM, err := EncodePrivateKeyPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyPEM failed: %v", err)
	}

	decoded, err := DecodePrivateKeyPEM(privPEM)
	if err != nil {
		t.Fatalf("DecodePrivateKeyPEM failed: %v", err)
	}

	// Sign with decoded key, verify with original public key
	v := NewVerifierFromKey(&priv.PublicKey)
	token, err := SignToken(makeValidClaims(), decoded)
	if err != nil {
		t.Fatalf("SignToken with decoded key failed: %v", err)
	}

	_, err = v.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}
