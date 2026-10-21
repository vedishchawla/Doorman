package auth

import (
	"context"
	"encoding/json"
	"errors"
)

type contextKey string

const claimsContextKey contextKey = "zt_claims"

// Claims represents the standard and custom OIDC claims extracted from a validated JWT.
type Claims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          []string `json:"-"`
	AuthorizedParty   string   `json:"azp,omitempty"`
	ExpiresAt         int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	NotBefore         int64    `json:"nbf"`
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Roles             []string `json:"roles,omitempty"`
}

// claimsAlias is used for unmarshalling custom Audience formats (single string or []string).
type claimsAlias struct {
	Issuer            string          `json:"iss"`
	Subject           string          `json:"sub"`
	Audience          json.RawMessage `json:"aud"`
	AuthorizedParty   string          `json:"azp,omitempty"`
	ExpiresAt         int64           `json:"exp"`
	IssuedAt          int64           `json:"iat"`
	NotBefore         int64           `json:"nbf"`
	Email             string          `json:"email,omitempty"`
	PreferredUsername string          `json:"preferred_username,omitempty"`
	Roles             []string        `json:"roles,omitempty"`
}

// UnmarshalJSON unmarshals JSON into Claims, handling aud as either a string or string array.
func (c *Claims) UnmarshalJSON(data []byte) error {
	var aux claimsAlias
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.Issuer = aux.Issuer
	c.Subject = aux.Subject
	c.AuthorizedParty = aux.AuthorizedParty
	c.ExpiresAt = aux.ExpiresAt
	c.IssuedAt = aux.IssuedAt
	c.NotBefore = aux.NotBefore
	c.Email = aux.Email
	c.PreferredUsername = aux.PreferredUsername
	c.Roles = aux.Roles

	if len(aux.Audience) == 0 {
		return nil
	}

	// Try single string
	var singleAud string
	if err := json.Unmarshal(aux.Audience, &singleAud); err == nil {
		c.Audience = []string{singleAud}
		return nil
	}

	// Try slice of strings
	var listAud []string
	if err := json.Unmarshal(aux.Audience, &listAud); err == nil {
		c.Audience = listAud
		return nil
	}

	return errors.New("invalid audience claim format")
}

// ContextWithClaims attaches Claims to the context.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext retrieves Claims from the context, if present.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}
