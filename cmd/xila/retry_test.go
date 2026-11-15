package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock replaces sleep/now so retry tests run instantly and record waits.
type fakeClock struct {
	t     time.Time
	waits []time.Duration
}

func (f *fakeClock) sleep(d time.Duration) { f.waits = append(f.waits, d); f.t = f.t.Add(d) }
func (f *fakeClock) now() time.Time        { return f.t }

func testClient(base string, retryFor time.Duration) (*client, *fakeClock, *strings.Builder) {
	clk := &fakeClock{t: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	var log strings.Builder
	c := newClient(base, "tok", retryFor, &log)
	c.sleep, c.now = clk.sleep, clk.now
	c.rnd = func(n int64) int64 { return n - 1 } // jitter at its ceiling: deterministic
	return c, clk, &log
}

// A saturated server answers 429 with Retry-After: the upload waits as asked,
// re-sends the same body, and succeeds.
func TestRetriesHonourRetryAfter(t *testing.T) {
	var calls atomic.Int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "30")
			http.Error(w, `{"error":"ingest queue is saturated"}`, http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"s1"}`))
	}))
	defer srv.Close()

	c, clk, log := testClient(srv.URL, 10*time.Minute)
	status, body, err := c.do(http.MethodPost, "/api/v1/projects/p/scans", "?scanner=trivy", []byte("REPORT"))
	if err != nil || status != http.StatusCreated || string(body) != `{"id":"s1"}` {
		t.Fatalf("do = %d %s %v", status, body, err)
	}
	if calls.Load() != 3 || len(clk.waits) != 2 || clk.waits[0] != 30*time.Second || clk.waits[1] != 30*time.Second {
		t.Errorf("calls=%d waits=%v, want 3 calls and two 30s waits", calls.Load(), clk.waits)
	}
	for i, b := range bodies {
		if b != "REPORT" {
			t.Errorf("attempt %d sent body %q, want the full report again", i+1, b)
		}
	}
	if !strings.Contains(log.String(), "retrying POST /api/v1/projects/p/scans in 30s (HTTP 429)") {
		t.Errorf("retry notice = %q", log.String())
	}
}

// Without Retry-After the waits grow exponentially and are capped; a client
// error (400) is never retried.
func TestBackoffAndNonRetryable(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		http.Error(w, `{"error":"unknown scanner"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c, clk, _ := testClient(srv.URL, time.Hour)
	status, _, err := c.do(http.MethodGet, "/x", "", nil)
	if err != nil || status != http.StatusBadRequest || calls.Load() != 4 {
		t.Fatalf("status=%d err=%v calls=%d, want a single 400 after 3 retries", status, err, calls.Load())
	}
	if want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}; len(clk.waits) != 3 || clk.waits[0] != want[0] || clk.waits[1] != want[1] || clk.waits[2] != want[2] {
		t.Errorf("waits = %v, want %v", clk.waits, want)
	}
	if got := backoff(20, func(n int64) int64 { return n - 1 }); got != retryMaxWait {
		t.Errorf("backoff(20) = %v, want the %v cap", got, retryMaxWait)
	}
}

// When the budget runs out the server's last answer comes back as is (so the
// caller prints its message); --retry-for 0 disables retrying; a dead server
// fails with the connection error once the budget is spent.
func TestRetryBudget(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "50")
		http.Error(w, `{"error":"ingest queue is saturated"}`, http.StatusTooManyRequests)
	}))
	c, _, _ := testClient(srv.URL, 2*time.Minute)
	status, body, err := c.do(http.MethodPost, "/scans", "", []byte("r"))
	if err != nil || status != http.StatusTooManyRequests || !strings.Contains(string(body), "saturated") {
		t.Errorf("after budget: %d %s %v, want the final 429", status, body, err)
	}
	if calls.Load() != 3 { // t=0, t=50s, t=100s; the next wait would pass 120s
		t.Errorf("calls = %d, want 3 within a 2m budget", calls.Load())
	}

	calls.Store(0)
	c0, clk0, _ := testClient(srv.URL, 0)
	if status, _, _ := c0.do(http.MethodGet, "/x", "", nil); status != http.StatusTooManyRequests || calls.Load() != 1 || len(clk0.waits) != 0 {
		t.Errorf("--retry-for 0: status=%d calls=%d waits=%v, want one attempt", status, calls.Load(), clk0.waits)
	}
	srv.Close()

	cd, clkd, _ := testClient(srv.URL, 10*time.Second)
	if _, _, err := cd.do(http.MethodGet, "/x", "", nil); !errors.Is(err, errRetryBudget) || len(clkd.waits) == 0 {
		t.Errorf("dead server: err=%v waits=%v, want errRetryBudget after retrying", err, clkd.waits)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for h, want := range map[string]time.Duration{
		"7":                             7 * time.Second,
		"Sun, 15 Nov 2026 12:00:20 GMT": 20 * time.Second,
		"Sun, 15 Nov 2026 11:00:00 GMT": 0, // in the past
	} {
		if got, ok := retryAfter(h, now); !ok || got != want {
			t.Errorf("retryAfter(%q) = %v %v, want %v", h, got, ok, want)
		}
	}
	for _, h := range []string{"", "soon", "-3"} {
		if _, ok := retryAfter(h, now); ok {
			t.Errorf("retryAfter(%q) accepted", h)
		}
	}
}
