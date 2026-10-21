package audit

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestLoggerRecordsFlushesAndFilters(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, 4, 10, nil)
	if !logger.Record(Entry{User: "alice", Decision: "allow", Resource: "/a"}) {
		t.Fatal("expected entry to be queued")
	}
	if !logger.Record(Entry{User: "bob", Decision: "deny", Resource: "/b"}) {
		t.Fatal("expected entry to be queued")
	}
	if err := logger.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(output.String(), "\n"); lines != 2 {
		t.Fatalf("expected two JSON lines, got %d: %q", lines, output.String())
	}
	entries := logger.Recent("alice", "allow", "/a")
	if len(entries) != 1 || entries[0].User != "alice" {
		t.Fatalf("unexpected filtered entries: %#v", entries)
	}
}

func TestMetricsExposeCountersAndHistograms(t *testing.T) {
	metrics := NewMetrics()
	metrics.Observe("allow", RequestState{AuthMS: 1, OPAMS: 2, UpstreamMS: 3})
	metrics.Observe("deny", RequestState{AuthMS: 4})
	recorder := httptest.NewRecorder()
	metrics.MetricsHandler(recorder, nil)
	text := recorder.Body.String()
	for _, want := range []string{
		`doorman_requests_total{decision="allow",policy_id=""} 1`,
		`doorman_requests_total{decision="deny",policy_id=""} 1`,
		`doorman_latency_ms_count{decision="allow",stage="auth",policy_id=""} 1`,
		`doorman_latency_ms_count{decision="allow",stage="opa",policy_id=""} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q in %s", want, text)
		}
	}
}

func TestLoggerDropsWhenBufferIsFullAndCountsIt(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	metrics := NewMetrics()
	logger := NewLogger(writer, 1, 10, metrics)
	if !logger.Record(Entry{RequestID: "first"}) {
		t.Fatal("first entry should be accepted")
	}
	<-writer.started
	if !logger.Record(Entry{RequestID: "second"}) {
		t.Fatal("second entry should fit in the buffer")
	}
	if logger.Record(Entry{RequestID: "third"}) {
		t.Fatal("third entry should be dropped")
	}
	close(writer.release)
	if err := logger.Shutdown(); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	metrics.MetricsHandler(recorder, nil)
	if !strings.Contains(recorder.Body.String(), "doorman_audit_dropped_total 1") {
		t.Fatalf("drop counter missing: %s", recorder.Body.String())
	}
}

func TestRecentIsSafeForConcurrentFiltering(t *testing.T) {
	var output bytes.Buffer
	logger := NewLogger(&output, 32, 10, nil)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Record(Entry{User: "alice", Decision: "allow", Resource: "/"})
			_ = logger.Recent("alice", "allow", "/")
		}()
	}
	wg.Wait()
	if err := logger.Shutdown(); err != nil {
		t.Fatal(err)
	}
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}
