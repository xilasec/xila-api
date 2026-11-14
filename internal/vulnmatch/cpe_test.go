package vulnmatch_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/enrichment"
	"github.com/xilasec/xila-api/internal/vulnmatch"
)

func TestNormalizeCPE(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", true},
		{"cpe:2.3:a:openssl:openssl:1.1.1k", "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", true}, // short form padded
		{"cpe:/a:apache:log4j:2.14.1", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", true},          // CPE 2.2 URI
		{`cpe:2.3:a:vendor:prod\:x:1.0:*:*:*:*:*:*:*`, `cpe:2.3:a:vendor:prod\:x:1.0:*:*:*:*:*:*:*`, true},
		// No concrete version: matching would report every CVE the product had.
		{"cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "", false},
		{"cpe:2.3:a:apache:log4j:-:*:*:*:*:*:*:*", "", false},
		{"cpe:2.3:a:*:log4j:2.14.1:*:*:*:*:*:*:*", "", false},
		{"cpe:2.3:x:apache:log4j:2.14.1", "", false},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "", false},
	}
	for _, c := range cases {
		got, ok := vulnmatch.NormalizeCPE(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("NormalizeCPE(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// Against NVD's real answer for log4j 2.14.1 (testdata/nvd_cpe_log4j.json:
// cpeName=cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*&isVulnerable&noRejected,
// trimmed to the fields we read): every CVE comes back with NVD's severity,
// and "fixed in" is the end of the range 2.14.1 sits in — not the other
// branches' fixes NVD lists alongside it.
func TestNVDCPESourceAgainstRealResponse(t *testing.T) {
	body, err := os.ReadFile("testdata/nvd_cpe_log4j.json")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.URL.Query().Get("cpeName"); got != "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" {
			t.Errorf("cpeName = %q", got)
		}
		// NVD's flags take no value; "isVulnerable=" would be a different request.
		for _, flag := range []string{"isVulnerable", "noRejected"} {
			if !strings.Contains("&"+r.URL.RawQuery+"&", "&"+flag+"&") {
				t.Errorf("query %q lacks the bare %s flag", r.URL.RawQuery, flag)
			}
		}
		w.Write(body)
	}))
	defer srv.Close()

	src := vulnmatch.NewNVDCPESource(enrichment.NewNVDClient(srv.URL, ""))
	const cpe22 = "cpe:/a:apache:log4j:2.14.1" // as some SBOMs carry it
	got, err := src.QueryCPE(context.Background(), []string{cpe22, "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[cpe22]) != 10 {
		t.Fatalf("matched %d keys, %d vulns for log4j; want 1 key (the wildcard skipped) with 10 CVEs", len(got), len(got[cpe22]))
	}
	byID := map[string]vulnmatch.Vuln{}
	for _, v := range got[cpe22] {
		byID[v.ID] = v
	}
	l := byID["CVE-2021-44228"]
	if l.Severity != domain.SeverityCritical || l.CVSS == nil || *l.CVSS != 10 || l.Fixed != "2.15.0" ||
		l.URL != "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" || len(l.CVEs) != 1 || l.Summary == "" {
		t.Errorf("Log4Shell = %+v", l)
	}
	if v := byID["CVE-2021-45105"]; v.Severity != domain.SeverityMedium {
		t.Errorf("CVE-2021-45105 severity = %q, want medium (NVD baseSeverity)", v.Severity)
	}

	// The same CPE again is served from the cache: no second rate-limited request.
	if _, err := src.QueryCPE(context.Background(), []string{"cpe:2.3:a:apache:log4j:2.14.1"}); err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("NVD requests = %d, want 1 (cached)", n)
	}
}
