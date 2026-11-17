package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/secretref"
)

// testdata/nvd_cves.json is a real NVD CVE API 2.0 response
// (https://services.nvd.nist.gov/rest/json/cves/2.0?cveIds=CVE-2021-44228,CVE-2023-0001
// plus CVE-2024-7871 from a cvssV4Severity query), trimmed to the cve fields
// we read (id, dates, status, metrics; ssvc dropped).
func nvdFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/nvd_cves.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNVDClientFetchesAndPrefersV31Primary(t *testing.T) {
	body := nvdFixture(t)
	var gotIDs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != "k" {
			t.Errorf("apiKey header = %q, want the configured key", r.Header.Get("apiKey"))
		}
		gotIDs = strings.Split(r.URL.Query().Get("cveIds"), ",")
		w.Write(body)
	}))
	defer srv.Close()

	c := NewNVDClient(srv.URL, secretref.Static("k"))
	got, err := c.Fetch(context.Background(), []string{"CVE-2021-44228", "CVE-2023-0001", "CVE-2024-7871", "CVE-2099-0001"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(gotIDs) != 4 {
		t.Errorf("cveIds = %v, want all four in one request", gotIDs)
	}
	want := map[string]struct {
		score   float64
		vector  string
		version string
	}{
		// v3.1 from NVD (Primary) beats v2 and a CNA's v3.1.
		"CVE-2021-44228": {10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "3.1"},
		// The CNA (Secondary) said 6.0; NVD's own assessment is 6.7.
		"CVE-2023-0001": {6.7, "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", "3.1"},
		// v3.1 is preferred over v4.0 when both exist.
		"CVE-2024-7871": {8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "3.1"},
	}
	for id, w := range want {
		r, ok := got[id]
		if !ok || r.Score == nil || *r.Score != w.score || r.Vector != w.vector || r.Version != w.version {
			t.Errorf("%s = %+v, want %v", id, r, w)
		}
		if r.LastModified == nil {
			t.Errorf("%s: lastModified not parsed", id)
		}
	}
	if _, ok := got["CVE-2099-0001"]; ok {
		t.Error("an id NVD didn't return must be absent")
	}
}

// A CVE with only a CVSS v4.0 metric (newer CNAs publish v4 alone) still
// yields a vector — taken from the real v4.0 block of CVE-2024-7871.
func TestNVDMetricV4Only(t *testing.T) {
	var resp nvdResponse
	if err := json.Unmarshal(nvdFixture(t), &resp); err != nil {
		t.Fatal(err)
	}
	m := resp.Vulnerabilities[2].CVE.Metrics
	m.V31 = nil
	got, ok := m.preferred()
	if !ok || got.CVSSData.Version != "4.0" || got.CVSSData.BaseScore != 8.7 || got.Type != "Primary" ||
		!strings.HasPrefix(got.CVSSData.VectorString, "CVSS:4.0/AV:N/AC:L/AT:N/PR:L") {
		t.Errorf("v4-only metric = %+v, want NVD's primary 4.0 vector at 8.7", got)
	}
}

func TestNVDClientBatchesAndRetriesThrottle(t *testing.T) {
	var calls atomic.Int32
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			// NVD answers 403 when the rolling window is exceeded.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ids := strings.Split(r.URL.Query().Get("cveIds"), ",")
		sizes = append(sizes, len(ids))
		fmt.Fprintf(w, `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}`)
	}))
	defer srv.Close()

	c := NewNVDClient(srv.URL, nil)
	var slept []time.Duration
	c.limit.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	cves := make([]string, 150)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%04d", i)
	}
	if _, err := c.Fetch(context.Background(), cves); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !slices.Equal(sizes, []int{100, 50}) {
		t.Errorf("batch sizes = %v, want [100 50] (NVD's cveIds limit)", sizes)
	}
	if len(slept) == 0 || slept[0] != nvdWindow {
		t.Errorf("waits = %v, want a full window after the 403", slept)
	}
}

// NVD allows 5 requests per rolling 30 s without a key, 50 with one.
func TestRateLimiterRollingWindow(t *testing.T) {
	now := time.Unix(0, 0)
	l := newRateLimiter(nvdRequestsNoKey, nvdWindow)
	l.now = func() time.Time { return now }
	var slept []time.Duration
	l.sleep = func(_ context.Context, d time.Duration) error {
		slept = append(slept, d)
		now = now.Add(d)
		return nil
	}
	for i := range 5 {
		if err := l.wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second * time.Duration(i+1)) // t = 0, 1, 3, 6, 10, then 15
	}
	if len(slept) != 0 {
		t.Fatalf("first 5 requests waited %v", slept)
	}
	// The 6th at t=15 must wait until the first leaves the window (t=30).
	if err := l.wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(slept, []time.Duration{15 * time.Second}) {
		t.Errorf("waits = %v, want [15s]", slept)
	}
	if NewNVDClient("", secretref.Static("key")).limit.n != nvdRequestsKey || NewNVDClient("", nil).limit.n != nvdRequestsNoKey {
		t.Error("an API key raises the limit from 5 to 50 per window")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.sleep = sleepCtx
	if err := l.wait(ctx); err == nil {
		t.Error("a cancelled context must stop the wait")
	}
}

// The API key is read per request: a rotated NVD_API_KEY is sent from the
// next request on, without rebuilding the client.
func TestNVDClientReadsRotatedKey(t *testing.T) {
	body := nvdFixture(t)
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("apiKey"))
		w.Write(body)
	}))
	defer srv.Close()

	key := "old"
	c := NewNVDClient(srv.URL, func() string { return key })
	for _, k := range []string{"old", "new"} {
		key = k
		if _, err := c.Fetch(context.Background(), []string{"CVE-2021-44228"}); err != nil {
			t.Fatalf("Fetch: %v", err)
		}
	}
	if len(got) != 2 || got[0] != "old" || got[1] != "new" {
		t.Errorf("apiKey headers = %v, want [old new]", got)
	}
}
