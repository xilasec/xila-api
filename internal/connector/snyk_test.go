package connector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

const snykOrg = "11111111-1111-1111-1111-111111111111"

// snykIssues is shaped like real GET /orgs/{org_id}/issues responses, per
// Snyk's REST API examples (Open Source, Code and Cloud list-issues
// responses in its published OpenAPI spec): each attributes object carries
// `ignored`/`status` directly.
var snykIssues = []string{
	`{"id": "11111111-aaaa-bbbb-cccc-000000000001", "type": "issue", "attributes": {
	  "title": "Prototype Pollution", "type": "package_vulnerability", "effective_severity_level": "high",
	  "ignored": false, "status": "open", "key": "npm:minimist:20210316",
	  "description": "minimist is vulnerable to Prototype Pollution.",
	  "problems": [{"id": "CVE-2021-44906", "source": "NVD"}, {"id": "CWE-1321", "source": "CWE"}],
	  "severities": [{"score": 9.8, "type": "primary"}],
	  "coordinates": [{"representations": [{"package": {"name": "minimist", "version": "1.2.5",
	                    "type": "npm", "url": "pkg:npm/minimist@1.2.5"}}],
	                    "remedies": [{"details": {"upgrade_package": "minimist@1.2.6"}}]}]
	}}`,
	`{"id": "11111111-aaaa-bbbb-cccc-000000000002", "type": "issue", "attributes": {
	  "title": "Insecure hash function used", "type": "code", "effective_severity_level": "low",
	  "ignored": true, "status": "open", "key": "code-key-2",
	  "description": "SHA-1 is used.",
	  "coordinates": [{"representations": [{"resource_path": "src/hash.js"}]}]
	}}`,
	`{"id": "11111111-aaaa-bbbb-cccc-000000000003", "type": "issue", "attributes": {
	  "title": "Fixed last month", "type": "package_vulnerability", "effective_severity_level": "medium",
	  "ignored": false, "status": "resolved", "key": "resolved-key"
	}}`,
}

func fakeSnyk(t *testing.T, items []string, perPage int) (*httptest.Server, *int) {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "token snyk-key" {
			http.Error(w, `{"errors":[{"detail":"Invalid token"}]}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/rest/orgs/"+snykOrg:
			fmt.Fprint(w, `{"data":{"id":"`+snykOrg+`","attributes":{"name":"Acme Org"}}}`)
		case r.URL.Path == "/rest/orgs/"+snykOrg+"/issues":
			start := 0
			if v := r.URL.Query().Get("starting_after"); v != "" {
				start, _ = strconv.Atoi(v)
			}
			end := min(start+perPage, len(items))
			links := `{}`
			if end < len(items) {
				links = fmt.Sprintf(`{"next":"/orgs/%s/issues?version=2024-10-15&starting_after=%d"}`, snykOrg, end)
			}
			fmt.Fprintf(w, `{"data":[%s],"links":%s}`, strings.Join(items[start:end], ","), links)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newSnyk(base, scope string) *snyk {
	return &snyk{base: base, scope: scope, token: "snyk-key", hc: http.DefaultClient, pageSize: 2}
}

func TestSnykFetch(t *testing.T) {
	srv, calls := fakeSnyk(t, snykIssues, 2)
	fs, err := newSnyk(srv.URL, snykOrg).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *calls != 2 {
		t.Fatalf("requests = %d, want 2 pages", *calls)
	}
	// The resolved issue isn't fetched, so Xila auto-closes it next pull.
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2 (resolved excluded)", len(fs))
	}

	sca := fs[0]
	if sca.Category != domain.CategorySCA || sca.Severity != domain.SeverityHigh || sca.RuleID != "11111111-aaaa-bbbb-cccc-000000000001" ||
		len(sca.CVE) != 1 || sca.CVE[0] != "CVE-2021-44906" || sca.CWE == nil || *sca.CWE != 1321 ||
		sca.PackageName != "minimist" || sca.PackageVersion != "1.2.5" || sca.Purl != "pkg:npm/minimist@1.2.5" ||
		sca.CVSS == nil || *sca.CVSS != 9.8 || !strings.Contains(sca.Description, "Fix: minimist@1.2.6") {
		t.Errorf("sca = %+v", sca)
	}
	if _, ok := sca.Metadata["remote_triage"]; ok {
		t.Error("open, un-ignored issue produced a remote verdict")
	}

	code := fs[1]
	if code.Category != domain.CategorySAST || code.Severity != domain.SeverityLow || code.FilePath != "src/hash.js" {
		t.Errorf("code = %+v", code)
	}
	if code.Metadata["remote_triage"] != string(domain.FindingWontFix) || code.Metadata["remote_triage_reason"] != "Snyk: ignored" {
		t.Errorf("ignored issue metadata = %v", code.Metadata)
	}

	if name, err := newSnyk(srv.URL, snykOrg).Check(context.Background()); err != nil || name != "Acme Org" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestSnykProjectFilter(t *testing.T) {
	proj := "22222222-2222-2222-2222-222222222222"
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()
	if _, err := newSnyk(srv.URL, snykOrg+":"+proj).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "scan_item.id="+proj) || !strings.Contains(gotQuery, "scan_item.type=project") {
		t.Errorf("query = %q, want the project filter", gotQuery)
	}
}

// TestSnykRateLimit covers a 429 that recovers after Retry-After, and one
// that never does.
func TestSnykRateLimit(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()
	if _, err := newSnyk(srv.URL, snykOrg).Fetch(context.Background()); err != nil {
		t.Fatalf("recovered 429 should not fail the pull: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2 (one retry)", attempts)
	}

	alwaysBusy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer alwaysBusy.Close()
	_, err := newSnyk(alwaysBusy.URL, snykOrg).Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("persistent 429 err = %v, want a RemoteError mentioning 429", err)
	}
}

func TestSnykAuthFailure(t *testing.T) {
	srv, _ := fakeSnyk(t, snykIssues, 10)
	bad := newSnyk(srv.URL, snykOrg)
	bad.token = "wrong"
	if _, err := bad.Fetch(context.Background()); !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token err = %v, want a 401 RemoteError", err)
	}
	if _, err := bad.Check(context.Background()); err == nil {
		t.Error("check passed with a bad token")
	}
}
