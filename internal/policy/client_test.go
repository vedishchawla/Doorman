package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEvaluate_Allow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/zt/authz" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":     true,
				"reason":    "",
				"policy_id": "",
				"denials":   []interface{}{},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	c.SetHTTPClient(srv.Client())

	d, err := c.Evaluate(context.Background(), Input{
		User:     "alice",
		Roles:    []string{"admin"},
		Resource: "/test",
		Method:   "GET",
		IP:       "127.0.0.1",
		Geo:      "IN",
		Time:     "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !d.Allow {
		t.Error("expected allow=true")
	}
}

func TestEvaluate_Deny(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":     false,
				"reason":    "Denied: disk is not encrypted",
				"policy_id": "disk-not-encrypted",
				"denials": []interface{}{
					map[string]interface{}{"rule_id": "disk-not-encrypted", "message": "Denied: disk is not encrypted"},
				},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	c.SetHTTPClient(srv.Client())

	d, _ := c.Evaluate(context.Background(), Input{
		User: "bob", Roles: []string{"viewer"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: false, OSPatchAgeDays: 5},
	})
	if d.Allow {
		t.Error("expected allow=false")
	}
	if d.PolicyID != "disk-not-encrypted" {
		t.Errorf("expected policy_id 'disk-not-encrypted', got %q", d.PolicyID)
	}
	if len(d.Denials) != 1 {
		t.Errorf("expected 1 denial, got %d", len(d.Denials))
	}
}

func TestEvaluate_Timeout_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // exceed 2s timeout
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	// Use a very short timeout for the test
	c.httpClient = &http.Client{Timeout: 50 * time.Millisecond}

	d, _ := c.Evaluate(context.Background(), Input{
		User: "alice", Roles: []string{"admin"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	})
	if d.Allow {
		t.Error("expected fail-closed deny on timeout")
	}
	if d.Reason != "policy evaluation failed" {
		t.Errorf("expected reason 'policy evaluation failed', got %q", d.Reason)
	}
}

func TestEvaluate_BadHTTPResponse_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	c.SetHTTPClient(srv.Client())

	d, _ := c.Evaluate(context.Background(), Input{
		User: "alice", Roles: []string{"admin"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	})
	if d.Allow {
		t.Error("expected fail-closed deny on 500 response")
	}
}

func TestEvaluate_MissingResultKey_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	c.SetHTTPClient(srv.Client())

	d, _ := c.Evaluate(context.Background(), Input{
		User: "alice", Roles: []string{"admin"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	})
	if d.Allow {
		t.Error("expected fail-closed deny on missing result key")
	}
	if d.Reason != "policy evaluation failed" {
		t.Errorf("expected reason 'policy evaluation failed', got %q", d.Reason)
	}
}

func TestEvaluate_BadJSON_FailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	c.SetHTTPClient(srv.Client())

	d, _ := c.Evaluate(context.Background(), Input{
		User: "alice", Roles: []string{"admin"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	})
	if d.Allow {
		t.Error("expected fail-closed deny on bad JSON")
	}
}

func TestCache_HitAndExpiry(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow": true, "reason": "", "policy_id": "", "denials": []interface{}{},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 100*time.Millisecond, 100)
	c.SetHTTPClient(srv.Client())

	input := Input{
		User: "alice", Roles: []string{"admin"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	}

	// First call — cache miss
	_, _ = c.Evaluate(context.Background(), input)
	if callCount != 1 {
		t.Fatalf("expected 1 OPA call, got %d", callCount)
	}

	// Second call — cache hit
	_, _ = c.Evaluate(context.Background(), input)
	if callCount != 1 {
		t.Fatalf("expected 1 OPA call (cached), got %d", callCount)
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Third call — cache expired
	_, _ = c.Evaluate(context.Background(), input)
	if callCount != 2 {
		t.Fatalf("expected 2 OPA calls after expiry, got %d", callCount)
	}
}

func TestCache_NeverCacheErrors(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 5*time.Second, 100)
	c.SetHTTPClient(srv.Client())

	input := Input{
		User: "alice", Roles: []string{"admin"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "10:00",
		DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
	}

	_, _ = c.Evaluate(context.Background(), input)
	_, _ = c.Evaluate(context.Background(), input)

	if callCount != 2 {
		t.Errorf("expected 2 OPA calls (errors should not be cached), got %d", callCount)
	}
}

func TestCache_MaxSizeEviction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow": true, "reason": "", "policy_id": "", "denials": []interface{}{},
			},
		})
	}))
	defer srv.Close()

	maxSize := 3
	c := NewClient(srv.URL, 10*time.Second, maxSize)
	c.SetHTTPClient(srv.Client())

	// Fill cache with maxSize entries
	for i := 0; i < maxSize+2; i++ {
		input := Input{
			User: "alice", Roles: []string{"admin"}, Resource: "/",
			Method: "GET", IP: "1.2.3.4", Geo: "IN",
			Time:          string(rune('0' + i)) + "0:00",
			DevicePosture: &DevicePosture{DiskEncrypted: true, OSPatchAgeDays: 5},
		}
		_, _ = c.Evaluate(context.Background(), input)
	}

	c.mu.Lock()
	size := len(c.cache)
	c.mu.Unlock()

	if size > maxSize {
		t.Errorf("cache size %d exceeds max %d", size, maxSize)
	}
}

func TestCleanPath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/backend-a/admin/x", "/admin/x"},
		{"/backend-b/foo", "/foo"},
		{"/backend-a/admin", "/admin"},
		{"/backend-a", "/"},
		{"/backend-b", "/"},
		{"/other/path", "/other/path"},
		{"/a/test", "/test"},
		{"/b/test", "/test"},
		{"/admin", "/admin"},
		{"/admin/settings", "/admin/settings"},
		{"/", "/"},
		{"/backend-a/../admin", "/admin"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := CleanPath(tc.input)
			if got != tc.expected {
				t.Errorf("CleanPath(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestFormatPolicyTime(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Kolkata")

	// 14:37 should truncate to "14:00"
	now := time.Date(2026, 10, 21, 14, 37, 0, 0, loc)
	got := FormatPolicyTime(now, loc)
	if got != "14:00" {
		t.Errorf("expected 14:00, got %q", got)
	}

	// 09:00 exactly
	now2 := time.Date(2026, 10, 21, 9, 0, 0, 0, loc)
	got2 := FormatPolicyTime(now2, loc)
	if got2 != "09:00" {
		t.Errorf("expected 09:00, got %q", got2)
	}
}

func TestDenialsSortedDeterministically(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Return denials in non-sorted order
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"result": map[string]interface{}{
				"allow":     false,
				"reason":    "",
				"policy_id": "",
				"denials": []interface{}{
					map[string]interface{}{"rule_id": "viewer-time-restricted", "message": "Denied: outside business hours"},
					map[string]interface{}{"rule_id": "disk-not-encrypted", "message": "Denied: disk is not encrypted"},
				},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, 0, 100)
	c.SetHTTPClient(srv.Client())

	d, _ := c.Evaluate(context.Background(), Input{
		User: "bob", Roles: []string{"viewer"}, Resource: "/", Method: "GET",
		IP: "1.2.3.4", Geo: "IN", Time: "22:00",
		DevicePosture: &DevicePosture{DiskEncrypted: false, OSPatchAgeDays: 5},
	})

	// Sorted by rule_id: disk-not-encrypted comes before viewer-time-restricted
	if d.PolicyID != "disk-not-encrypted" {
		t.Errorf("expected first denial by sorted rule_id 'disk-not-encrypted', got %q", d.PolicyID)
	}
	if d.Reason != "Denied: disk is not encrypted" {
		t.Errorf("unexpected reason: %q", d.Reason)
	}
}
