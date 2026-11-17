package observability

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// GuardMetrics reads its token on every request, so a rotated METRICS_TOKEN
// (M10 10.2) takes effect without restarting the listener.
func TestGuardMetricsTokenRotation(t *testing.T) {
	var token atomic.Value
	token.Store("first-token")
	h := GuardMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), func() string { return token.Load().(string) })
	srv := httptest.NewServer(h)
	defer srv.Close()

	get := func(bearer string) int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if got := get("first-token"); got != http.StatusOK {
		t.Fatalf("with the first token: HTTP %d, want 200", got)
	}
	if got := get("wrong"); got != http.StatusUnauthorized {
		t.Fatalf("with a wrong token: HTTP %d, want 401", got)
	}

	token.Store("rotated-token")

	if got := get("first-token"); got != http.StatusUnauthorized {
		t.Fatalf("with the stale token after rotation: HTTP %d, want 401", got)
	}
	if got := get("rotated-token"); got != http.StatusOK {
		t.Fatalf("with the rotated token: HTTP %d, want 200", got)
	}
}

// An empty token disables the check; setting one later enables it live.
func TestGuardMetricsEmptyTokenDisablesCheck(t *testing.T) {
	var token atomic.Value
	token.Store("")
	h := GuardMetrics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), func() string { return token.Load().(string) })
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("no token required: HTTP %d, want 200", resp.StatusCode)
	}

	token.Store("now-required")
	resp, err = http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after setting a token live: HTTP %d, want 401", resp.StatusCode)
	}
}
