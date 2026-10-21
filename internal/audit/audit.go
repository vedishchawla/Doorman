// Package audit provides asynchronous request audit logging and Prometheus
// metrics for the ingress proxy.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry is the JSON-line audit record for one request.
type Entry struct {
	Timestamp  time.Time `json:"timestamp"`
	RequestID  string    `json:"request_id"`
	User       string    `json:"user"`
	Roles      []string  `json:"roles"`
	Resource   string    `json:"resource"`
	Method     string    `json:"method"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason"`
	PolicyID   string    `json:"policy_id"`
	ClientIP   string    `json:"client_ip"`
	Geo        string    `json:"geo"`
	DeviceID   string    `json:"device_id"`
	Step       int       `json:"step"`
	AuthMS     float64   `json:"auth_ms"`
	OPAMS      float64   `json:"opa_ms"`
	UpstreamMS float64   `json:"upstream_ms"`
}

// RequestState carries request metadata across proxy stages.
type RequestState struct {
	RequestID  string
	StartedAt  time.Time
	User       string
	Roles      []string
	Resource   string
	Method     string
	Decision   string
	Reason     string
	PolicyID   string
	ClientIP   string
	Geo        string
	DeviceID   string
	Step       int
	AuthMS     float64
	OPAMS      float64
	UpstreamMS float64
}

type contextKey struct{}

// WithState attaches request audit state to a request context.
func WithState(r *http.Request, state *RequestState) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, state))
}

// StateFromContext retrieves request audit state.
func StateFromContext(ctx context.Context) (*RequestState, bool) {
	state, ok := ctx.Value(contextKey{}).(*RequestState)
	return state, ok
}

// Logger asynchronously writes audit entries and retains recent entries.
type Logger struct {
	ch          chan Entry
	writer      *bufio.Writer
	done        chan struct{}
	wg          sync.WaitGroup
	mu          sync.RWMutex
	recent      []Entry
	maxKeep     int
	lifecycleMu sync.Mutex
	closed      bool
	flushErr    error
	metrics     *Metrics
}

// NewLogger creates a logger with a non-blocking enqueue buffer.
func NewLogger(w io.Writer, bufferSize, maxRecent int, metrics *Metrics) *Logger {
	if bufferSize < 1 {
		bufferSize = 1
	}
	if maxRecent < 1 {
		maxRecent = 1
	}
	l := &Logger{
		ch:      make(chan Entry, bufferSize),
		writer:  bufio.NewWriter(w),
		done:    make(chan struct{}),
		maxKeep: maxRecent,
		metrics: metrics,
	}
	l.wg.Add(1)
	go l.run()
	return l
}

func (l *Logger) run() {
	defer l.wg.Done()
	for entry := range l.ch {
		l.write(entry)
	}
	l.flushErr = l.writer.Flush()
	close(l.done)
}

func (l *Logger) write(entry Entry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = l.writer.Write(data)
	_, _ = l.writer.WriteString("\n")
	if err := l.writer.Flush(); err != nil {
		l.flushErr = err
	}
	l.mu.Lock()
	l.recent = append(l.recent, entry)
	if len(l.recent) > l.maxKeep {
		l.recent = l.recent[len(l.recent)-l.maxKeep:]
	}
	l.mu.Unlock()
}

// Record enqueues an entry without blocking. Entries can be dropped only when
// the bounded buffer is full or shutdown has begun.
func (l *Logger) Record(entry Entry) bool {
	l.lifecycleMu.Lock()
	defer l.lifecycleMu.Unlock()
	if l.closed {
		return false
	}
	select {
	case l.ch <- entry:
		return true
	default:
		if l.metrics != nil {
			l.metrics.ObserveDropped()
		}
		return false
	}
}

// Shutdown flushes all queued entries and closes the logger.
func (l *Logger) Shutdown() error {
	l.lifecycleMu.Lock()
	if l.closed {
		l.lifecycleMu.Unlock()
		return nil
	}
	l.closed = true
	close(l.ch)
	l.lifecycleMu.Unlock()
	l.wg.Wait()
	return l.flushErr
}

// Recent returns entries matching all non-empty filters, newest first.
func (l *Logger) Recent(user, decision, resource string) []Entry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make([]Entry, 0, len(l.recent))
	for i := len(l.recent) - 1; i >= 0; i-- {
		entry := l.recent[i]
		if user != "" && entry.User != user {
			continue
		}
		if decision != "" && entry.Decision != decision {
			continue
		}
		if resource != "" && entry.Resource != resource {
			continue
		}
		result = append(result, entry)
	}
	return result
}

// AuditHandler serves recent audit entries with user, decision, and resource filters.
func (l *Logger) AuditHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	entries := l.Recent(r.URL.Query().Get("user"), r.URL.Query().Get("decision"), r.URL.Query().Get("resource"))
	_ = json.NewEncoder(w).Encode(entries)
}

// Metrics contains Prometheus counters and per-stage latency histograms.
type Metrics struct {
	mu        sync.Mutex
	counters  map[metricKey]uint64
	histogram map[metricKey]*histogram
	dropped   uint64
}

type metricKey struct {
	decision string
	stage    string
	policyID string
}

type histogram struct {
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
}

// NewMetrics creates metrics for allow/deny decisions and request stages.
func NewMetrics() *Metrics {
	return &Metrics{
		counters:  make(map[metricKey]uint64),
		histogram: make(map[metricKey]*histogram),
	}
}

func newHistogram() *histogram {
	buckets := []float64{0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}
	return &histogram{buckets: buckets, counts: make([]uint64, len(buckets))}
}

// Observe records one completed request.
func (m *Metrics) Observe(decision string, state RequestState) {
	m.mu.Lock()
	m.counters[metricKey{decision: decision, policyID: state.PolicyID}]++
	m.observeHistogram(decision, state.PolicyID, "auth", state.AuthMS)
	m.observeHistogram(decision, state.PolicyID, "opa", state.OPAMS)
	m.observeHistogram(decision, state.PolicyID, "upstream", state.UpstreamMS)
	m.mu.Unlock()
}

func (m *Metrics) observeHistogram(decision, policyID, stage string, value float64) {
	key := metricKey{decision: decision, stage: stage, policyID: policyID}
	h := m.histogram[key]
	if h == nil {
		h = newHistogram()
		m.histogram[key] = h
	}
	h.sum += value
	h.count++
	for i, bound := range h.buckets {
		if value <= bound {
			h.counts[i]++
		}
	}
}

// ObserveDropped records an audit entry dropped because the buffer was full.
func (m *Metrics) ObserveDropped() {
	m.mu.Lock()
	m.dropped++
	m.mu.Unlock()
}

// MetricsHandler exposes Prometheus text exposition format.
func (m *Metrics) MetricsHandler(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# TYPE doorman_requests_total counter\n")
	for key, count := range m.counters {
		fmt.Fprintf(w, "doorman_requests_total{decision=%q,policy_id=%q} %d\n", key.decision, key.policyID, count)
	}
	fmt.Fprintf(w, "# TYPE doorman_audit_dropped_total counter\n")
	fmt.Fprintf(w, "doorman_audit_dropped_total %d\n", m.dropped)
	fmt.Fprintf(w, "# TYPE doorman_latency_ms histogram\n")
	for key, h := range m.histogram {
		var cumulative uint64
		for i, bound := range h.buckets {
			cumulative = h.counts[i]
			fmt.Fprintf(w, "doorman_latency_ms_bucket{decision=%q,stage=%q,policy_id=%q,le=%q} %d\n", key.decision, key.stage, key.policyID, strconv.FormatFloat(bound, 'f', -1, 64), cumulative)
		}
		fmt.Fprintf(w, "doorman_latency_ms_bucket{decision=%q,stage=%q,policy_id=%q,le=\"+Inf\"} %d\n", key.decision, key.stage, key.policyID, h.count)
		fmt.Fprintf(w, "doorman_latency_ms_sum{decision=%q,stage=%q,policy_id=%q} %f\n", key.decision, key.stage, key.policyID, h.sum)
		fmt.Fprintf(w, "doorman_latency_ms_count{decision=%q,stage=%q,policy_id=%q} %d\n", key.decision, key.stage, key.policyID, h.count)
	}
}

// NewRequestState initializes request metadata and a stable request ID.
func NewRequestState(r *http.Request) *RequestState {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		id = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return &RequestState{
		RequestID: id,
		StartedAt: time.Now(),
		Resource:  r.URL.Path,
		Method:    r.Method,
		ClientIP:  clientIP(r.RemoteAddr),
		Step:      1,
	}
}

func clientIP(remote string) string {
	if i := strings.LastIndex(remote, ":"); i > 0 && !strings.Contains(remote, "]") {
		return remote[:i]
	}
	return strings.Trim(remote, "[]")
}
