package vulnmatch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/secretref"
)

// testdata/github_advisories_lodash.json is a real response of
// GET https://api.github.com/advisories?ecosystem=npm&affects=lodash@4.17.20
// (REST "List global security advisories",
// https://docs.github.com/en/rest/security-advisories/global-advisories),
// trimmed: `credits` dropped and `description` shortened.
func ghFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/github_advisories_lodash.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGitHubSourceQueriesAndMatchesRanges(t *testing.T) {
	page1 := ghFixture(t)
	var calls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if r.URL.Path != "/advisories" {
			t.Errorf("path = %s, want /advisories", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("Authorization = %q, want the configured token", got)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		q := r.URL.Query()
		if q.Get("ecosystem") != "npm" || q.Get("per_page") != "100" {
			t.Errorf("query = %v, want ecosystem=npm per_page=100", q)
		}
		if n == 1 { // the first, batched query carries every npm package
			affects := strings.Split(q.Get("affects"), ",")
			for _, want := range []string{"lodash@4.17.20", "lodash@4.18.0", "lodash-amd@3.0.0", "@babel/core@7.0.0"} {
				if !slices.Contains(affects, want) {
					t.Errorf("affects = %v, missing %s", affects, want)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if q.Get("after") == "" {
			// GitHub paginates with a cursor in the Link header.
			w.Header().Set("Link", `<`+srv.URL+`/advisories?ecosystem=npm&per_page=100&affects=`+q.Get("affects")+`&after=Y3Vyc29y>; rel="next"`)
			w.Write(page1)
			return
		}
		w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	g := NewGitHubSource(srv.URL, secretref.Static("tok"))
	purls := []string{"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.18.0", "pkg:npm/lodash-amd@3.0.0",
		"pkg:npm/%40babel/core@7.0.0", "pkg:generic/openssl@3.0.0"}
	got, err := g.Query(context.Background(), purls)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("requests = %d, want 2 (both pages of one batched npm query; generic purls aren't asked)", calls.Load())
	}

	ids := func(vs []Vuln) []string {
		var out []string
		for _, v := range vs {
			out = append(out, v.ID)
		}
		slices.Sort(out)
		return out
	}
	if g := ids(got["pkg:npm/lodash@4.17.20"]); !slices.Equal(g, []string{"GHSA-f23m-r3pf-42rh", "GHSA-r5fr-rjxr-66jc"}) {
		t.Errorf("lodash@4.17.20 = %v, want both advisories", g)
	}
	if _, ok := got["pkg:npm/lodash@4.18.0"]; ok {
		t.Errorf("lodash@4.18.0 is the patched version, got %v", ids(got["pkg:npm/lodash@4.18.0"]))
	}
	// lodash-amd: one advisory covers "<= 4.17.23", the other ">= 4.0.0, <= 4.17.23".
	if g := ids(got["pkg:npm/lodash-amd@3.0.0"]); !slices.Equal(g, []string{"GHSA-f23m-r3pf-42rh"}) {
		t.Errorf("lodash-amd@3.0.0 = %v, want only GHSA-f23m-r3pf-42rh", g)
	}

	var v Vuln
	for _, x := range got["pkg:npm/lodash@4.17.20"] {
		if x.ID == "GHSA-r5fr-rjxr-66jc" {
			v = x
		}
	}
	if v.Severity != domain.SeverityHigh || v.Fixed != "4.18.0" || !slices.Equal(v.CVEs, []string{"CVE-2026-4800"}) {
		t.Errorf("advisory = %+v, want high, fixed 4.18.0, CVE-2026-4800", v)
	}
	if v.CVSS == nil || *v.CVSS != 8.1 {
		t.Errorf("CVSS = %v, want the v3 score 8.1 (v4 score 0 = absent)", v.CVSS)
	}
	if v.URL != "https://github.com/advisories/GHSA-r5fr-rjxr-66jc" {
		t.Errorf("URL = %q", v.URL)
	}

	// Within the cache TTL the same purls are answered without asking again.
	if _, err := g.Query(context.Background(), purls); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("requests after cached re-query = %d, want still 2", calls.Load())
	}
	g.now = func() time.Time { return time.Now().Add(ghCacheTTL + time.Minute) }
	if _, err := g.Query(context.Background(), purls[:1]); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 4 {
		t.Errorf("requests after TTL = %d, want 4 (cache expired)", calls.Load())
	}
}

// GitHub says how much of the window is left on every response; once it's
// spent the next request waits for X-RateLimit-Reset, and a secondary-limit
// 403 with Retry-After is retried after that delay.
func TestGitHubSourceRespectsRateLimits(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var calls atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		switch n {
		case 1: // page 1: last request of the window
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(20*time.Second).Unix(), 10))
			w.Header().Set("Link", `<`+srv.URL+`/advisories?after=x>; rel="next"`)
			w.Write([]byte(`[]`))
		case 2: // secondary rate limit
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"message":"You have exceeded a secondary rate limit"}`))
		default:
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	g := NewGitHubSource(srv.URL, nil)
	g.now = func() time.Time { return now }
	var slept []time.Duration
	g.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	if _, err := g.Query(context.Background(), []string{"pkg:npm/lodash@4.17.20"}); err != nil {
		t.Fatalf("Query: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("requests = %d, want 3 (page 1, throttled page 2, retried page 2)", calls.Load())
	}
	if !slices.Equal(slept, []time.Duration{21 * time.Second, 7 * time.Second}) {
		t.Errorf("waits = %v, want [21s (until reset) 7s (Retry-After)]", slept)
	}

	// A reset further away than a run should wait fails the source (the other
	// sources' results still apply, without auto-close).
	calls.Store(0)
	g2 := NewGitHubSource(srv.URL, nil)
	g2.now = func() time.Time { return now }
	g2.sleep = func(context.Context, time.Duration) error { return nil }
	g2.resumeAt = now.Add(time.Hour)
	if _, err := g2.Query(context.Background(), []string{"pkg:npm/lodash@4.17.20"}); err == nil ||
		!strings.Contains(err.Error(), "rate limit") {
		t.Errorf("err = %v, want a rate-limit error", err)
	}
	if calls.Load() != 0 {
		t.Errorf("requests while exhausted = %d, want 0", calls.Load())
	}
}

func TestGitHubRange(t *testing.T) {
	cases := []struct {
		rng, v string
		want   bool
	}{
		{">= 4.0.0, < 4.17.21", "4.17.20", true},
		{">= 4.0.0, < 4.17.21", "4.17.21", false},
		{">= 4.0.0, < 4.17.21", "3.9.9", false},
		{"<= 4.17.23", "4.17.23", true},
		{"= 2.0.0", "2.0.0", true},
		{"= 2.0.0", "2.0.1", false},
		{"> 1.0", "1.0", false},
		{"", "1.0.0", true}, // unbounded: GitHub already filtered on our version
	}
	for _, c := range cases {
		if got := inGitHubRange(c.rng, c.v, compareSemver); got != c.want {
			t.Errorf("inGitHubRange(%q, %q) = %v, want %v", c.rng, c.v, got, c.want)
		}
	}
}
