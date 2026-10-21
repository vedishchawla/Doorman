// Package policy provides an OPA REST client for policy evaluation with
// optional in-memory decision caching. It fails closed on any error.
package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

// DevicePosture represents device security posture information.
type DevicePosture struct {
	DiskEncrypted  bool `json:"disk_encrypted"`
	FirewallOn     bool `json:"firewall_on"`
	OSPatchAgeDays int  `json:"os_patch_age_days"`
}

// Input is the policy evaluation input document sent to OPA.
type Input struct {
	User          string         `json:"user"`
	Roles         []string       `json:"roles"`
	Resource      string         `json:"resource"`
	Method        string         `json:"method"`
	IP            string         `json:"ip"`
	Geo           string         `json:"geo"`
	Time          string         `json:"time"`
	DevicePosture *DevicePosture `json:"device_posture"`
}

// Denial represents a single policy denial with a rule ID and message.
type Denial struct {
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
}

// Decision is the result of a policy evaluation.
type Decision struct {
	Allow    bool     `json:"allow"`
	Reason   string   `json:"reason"`
	PolicyID string   `json:"policy_id"`
	Denials  []Denial `json:"denials,omitempty"`
}

// opaRequest wraps the input for the OPA REST API.
type opaRequest struct {
	Input Input `json:"input"`
}

// opaResponse represents the OPA /v1/data response.
type opaResponse struct {
	Result *opaResult `json:"result"`
}

// opaResult maps the Rego output.
type opaResult struct {
	Allow   bool              `json:"allow"`
	Reason  string            `json:"reason"`
	PolicyID string           `json:"policy_id"`
	Denials []Denial          `json:"denials"`
}

// cacheEntry stores a cached decision with its expiry time.
type cacheEntry struct {
	decision  Decision
	expiresAt time.Time
	insertedAt time.Time
}

// Client is an OPA policy evaluation client with optional caching.
type Client struct {
	opaURL       string
	httpClient   *http.Client
	cacheTTL     time.Duration
	cacheMaxSize int

	mu    sync.Mutex
	cache map[string]*cacheEntry
}

// NewClient creates a new OPA policy client.
// cacheTTL of 0 disables caching.
func NewClient(opaURL string, cacheTTL time.Duration, cacheMaxSize int) *Client {
	return &Client{
		opaURL: opaURL,
		httpClient: &http.Client{
			Timeout: 2 * time.Second,
		},
		cacheTTL:     cacheTTL,
		cacheMaxSize: cacheMaxSize,
		cache:        make(map[string]*cacheEntry),
	}
}

// SetHTTPClient replaces the default HTTP client (used for testing).
func (c *Client) SetHTTPClient(hc *http.Client) {
	c.httpClient = hc
}

// Evaluate sends the input to OPA and returns a Decision.
// Fails closed: any error results in Decision{Allow: false}.
func (c *Client) Evaluate(ctx context.Context, input Input) (Decision, error) {
	key := c.cacheKey(input)

	// Check cache
	if c.cacheTTL > 0 {
		if d, ok := c.getCache(key); ok {
			return d, nil
		}
	}

	decision := c.evaluate(ctx, input)

	// Only cache successful evaluations (not error-driven denials)
	if c.cacheTTL > 0 && decision.Reason != "policy evaluation failed" {
		c.putCache(key, decision)
	}

	return decision, nil
}

// evaluate performs the actual OPA call. Returns a deny decision on any failure.
func (c *Client) evaluate(ctx context.Context, input Input) Decision {
	denyDecision := Decision{
		Allow:    false,
		Reason:   "policy evaluation failed",
		PolicyID: "opa-error",
	}

	body, err := json.Marshal(opaRequest{Input: input})
	if err != nil {
		return denyDecision
	}

	reqURL := c.opaURL + "/v1/data/zt/authz"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return denyDecision
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return denyDecision
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return denyDecision
	}

	var opaResp opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&opaResp); err != nil {
		return denyDecision
	}

	// Missing result key means deny
	if opaResp.Result == nil {
		return denyDecision
	}

	result := opaResp.Result

	// Sort denials deterministically by rule_id
	denials := result.Denials
	sort.Slice(denials, func(i, j int) bool {
		return denials[i].RuleID < denials[j].RuleID
	})

	d := Decision{
		Allow:   result.Allow,
		Denials: denials,
	}

	if len(denials) > 0 {
		d.Reason = denials[0].Message
		d.PolicyID = denials[0].RuleID
	} else if result.Reason != "" {
		d.Reason = result.Reason
		d.PolicyID = result.PolicyID
	}

	return d
}

// cacheKey computes a SHA-256 hash of the JSON-serialized input.
func (c *Client) cacheKey(input Input) string {
	b, _ := json.Marshal(input)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// getCache retrieves a non-expired entry from the cache.
func (c *Client) getCache(key string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.cache[key]
	if !ok {
		return Decision{}, false
	}

	if time.Now().After(entry.expiresAt) {
		delete(c.cache, key)
		return Decision{}, false
	}

	return entry.decision, true
}

// putCache stores a decision in the cache, evicting the oldest entry if at capacity.
func (c *Client) putCache(key string, d Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict oldest entry if at max size
	if len(c.cache) >= c.cacheMaxSize {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.cache {
			if oldestKey == "" || v.insertedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.insertedAt
			}
		}
		if oldestKey != "" {
			delete(c.cache, oldestKey)
		}
	}

	c.cache[key] = &cacheEntry{
		decision:   d,
		expiresAt:  time.Now().Add(c.cacheTTL),
		insertedAt: time.Now(),
	}
}

// CleanPath strips a backend routing prefix and cleans the resulting path.
// "/backend-a/admin/x" → "/admin/x"
// "/backend-b/foo"     → "/foo"
// "/other"             → "/other"
func CleanPath(rawPath string) string {
	p := rawPath
	for _, prefix := range []string{"/backend-a", "/backend-b", "/a", "/b"} {
		if p == prefix {
			return "/"
		}
		if len(p) > len(prefix) && p[:len(prefix)+1] == prefix+"/" {
			p = p[len(prefix):]
			break
		}
	}
	return cleanPathOnly(p)
}

// cleanPathOnly is a simple path.Clean equivalent using only the standard library.
func cleanPathOnly(p string) string {
	if p == "" {
		return "/"
	}

	// Use a simple stack-based approach
	parts := splitPath(p)
	var stack []string
	for _, part := range parts {
		if part == ".." {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		} else if part != "." && part != "" {
			stack = append(stack, part)
		}
	}

	result := "/" + joinPath(stack)
	return result
}

func splitPath(p string) []string {
	var parts []string
	current := ""
	for _, c := range p {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func joinPath(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "/"
		}
		result += p
	}
	return result
}

// FormatPolicyTime truncates the current time to the hour in the given timezone.
func FormatPolicyTime(now time.Time, loc *time.Location) string {
	t := now.In(loc)
	return fmt.Sprintf("%02d:00", t.Hour())
}
