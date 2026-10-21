// Package main implements a dummy backend that returns its name and the
// request headers it received.  It also exposes a /healthz endpoint and
// a "healthcheck" subcommand so the same binary can be used as a Docker
// HEALTHCHECK probe in a distroless image (no shell available).
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
)

func main() {
	// --- healthcheck subcommand (used by Docker HEALTHCHECK) ----------
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		resp, err := http.Get("http://localhost:8080/healthz")
		if err != nil {
			os.Exit(1)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// --- normal server mode ------------------------------------------
	name := os.Getenv("BACKEND_NAME")
	if name == "" {
		name = "unknown"
	}

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		keys := make([]string, 0, len(r.Header))
		for k := range r.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			headers[k] = r.Header.Get(k)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"backend": name,
			"headers": headers,
		})
	})

	fmt.Fprintf(os.Stderr, `{"level":"info","msg":"backend started","name":%q,"addr":":8080"}`+"\n", name)
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Fprintf(os.Stderr, `{"level":"error","msg":"server failed","error":%q}`+"\n", err)
		os.Exit(1)
	}
}
