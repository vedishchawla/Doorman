package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"
)

const (
	SessionCookieName = "zt_session"
	StateCookieName   = "zt_state"
)

var (
	ErrInvalidCookie = errors.New("invalid or tampered cookie")
	ErrCookieNotFound = errors.New("cookie not found")
)

// SignValue creates a signed string in the format "<payload>.<signature>" using HMAC-SHA256.
func SignValue(payload string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)
	sigEncoded := base64.RawURLEncoding.EncodeToString(sig)
	payloadEncoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	return payloadEncoded + "." + sigEncoded
}

// VerifyValue verifies the signature and returns the original payload.
func VerifyValue(signedValue string, secret []byte) (string, error) {
	parts := strings.Split(signedValue, ".")
	if len(parts) != 2 {
		return "", ErrInvalidCookie
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", ErrInvalidCookie
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ErrInvalidCookie
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(payloadBytes)
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedSig) {
		return "", ErrInvalidCookie
	}

	return string(payloadBytes), nil
}

// SetSessionCookie sets the signed session cookie.
func SetSessionCookie(w http.ResponseWriter, token string, secret []byte, maxAge time.Duration) {
	signedVal := SignValue(token, secret)
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    signedVal,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   false, // Can be true if behind TLS proxy, or dynamically set
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie clears the session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSessionToken extracts and verifies the session token from the request cookie.
func GetSessionToken(r *http.Request, secret []byte) (string, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return "", ErrCookieNotFound
	}
	return VerifyValue(cookie.Value, secret)
}
