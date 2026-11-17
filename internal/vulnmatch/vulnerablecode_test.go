package vulnmatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/secretref"
)

// testdata/vulnerablecode/bulk_search_lodash.json is hand-written to
// VulnerableCode's PackageSerializer (vulnerabilities/api.py, the
// /api/packages/bulk_search response): the public instance needs an API key,
// so no live response could be captured. Ids, aliases and scores are lodash's
// real CVE-2021-23337 / CVE-2020-28500 data; the VCIDs are illustrative.
func TestVulnerableCodeBulkSearch(t *testing.T) {
	fixture, err := os.ReadFile("testdata/vulnerablecode/bulk_search_lodash.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/packages/bulk_search" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Token k" {
			t.Errorf("Authorization = %q, want the API key", got)
		}
		var body struct {
			Purls     []string `json:"purls"`
			PlainPurl bool     `json:"plain_purl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		// Qualifiers are dropped, duplicates collapse, version-less purls skipped.
		if !body.PlainPurl || !slices.Equal(body.Purls, []string{"pkg:npm/lodash@4.17.20", "pkg:npm/@babel/core@7.0.0"}) {
			t.Errorf("body = %+v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(fixture)
	}))
	defer srv.Close()

	src := NewVulnerableCodeSource(srv.URL+"/", secretref.Static("k"))
	got, err := src.Query(context.Background(), []string{
		"pkg:npm/lodash@4.17.20", "pkg:npm/lodash@4.17.20?arch=x", "pkg:npm/@babel/core@7.0.0", "pkg:npm/left-pad",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || len(got["pkg:npm/lodash@4.17.20"]) != 2 || len(got["pkg:npm/lodash@4.17.20?arch=x"]) != 2 {
		t.Fatalf("result = %+v, want both lodash purls with 2 advisories", got)
	}
	vs := got["pkg:npm/lodash@4.17.20"]
	v := vs[0]
	// The GHSA is the identity (the same finding OSV/GitHub produce); the VCID
	// and CVE are aliases.
	if v.ID != "GHSA-35jh-r3h4-6jhm" || !slices.Contains(v.Aliases, "VCID-k3m6-7u2b-aaak") ||
		!slices.Equal(v.CVEs, []string{"CVE-2021-23337"}) {
		t.Errorf("identity = %s aliases %v cves %v", v.ID, v.Aliases, v.CVEs)
	}
	if v.CVSS == nil || *v.CVSS != 7.2 || v.Severity != domain.SeverityHigh || v.Fixed != "4.17.21" {
		t.Errorf("scores = cvss %v sev %q fixed %q", v.CVSS, v.Severity, v.Fixed)
	}
	if v.Summary != "Command Injection in lodash" || !strings.HasSuffix(v.URL, "/vulnerabilities/VCID-k3m6-7u2b-aaak") {
		t.Errorf("summary %q url %q", v.Summary, v.URL)
	}
	// Textual severity only; the nearest of two fixes.
	if r := vs[1]; r.ID != "GHSA-29mw-wpgm-hmr9" || r.Severity != domain.SeverityMedium || r.CVSS != nil || r.Fixed != "4.17.21" {
		t.Errorf("second = %+v", r)
	}
}

func TestVulnerableCodeFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"Unauthorized client."}`, http.StatusForbidden)
	}))
	defer srv.Close()
	if _, err := NewVulnerableCodeSource(srv.URL, nil).Query(context.Background(), []string{"pkg:npm/a@1.0.0"}); err == nil {
		t.Fatal("a refused lookup must fail the source (so the run is partial), not report no advisories")
	}
}
