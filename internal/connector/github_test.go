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

// githubCodeAlerts is shaped like a real GET /repos/{owner}/{repo}/code-scanning/alerts
// response (GitHub's published REST schema for code scanning alerts).
var githubCodeAlerts = []string{
	`{"number": 4, "html_url": "https://github.com/acme/widgets/security/code-scanning/4",
	  "state": "open", "dismissed_reason": null,
	  "rule": {"id": "js/sql-injection", "name": "SQL Injection", "severity": "error",
	           "security_severity_level": "critical", "description": "User input flows into a SQL query.",
	           "tags": ["external/cwe/cwe-89", "security"]},
	  "most_recent_instance": {"commit_sha": "abc123", "message": {"text": "query built from input"},
	                           "location": {"path": "src/db.js", "start_line": 12}}}`,
	`{"number": 7, "html_url": "https://github.com/acme/widgets/security/code-scanning/7",
	  "state": "dismissed", "dismissed_reason": "false positive", "dismissed_comment": "sanitized upstream",
	  "rule": {"id": "js/xss", "name": "Cross-site scripting", "severity": "warning",
	           "tags": ["external/cwe/cwe-79"]},
	  "most_recent_instance": {"commit_sha": "def456", "message": {"text": "unescaped output"},
	                           "location": {"path": "src/view.js", "start_line": 3}}}`,
	`{"number": 2, "state": "fixed", "rule": {"id": "js/old", "name": "Fixed already"},
	  "most_recent_instance": {"location": {"path": "src/old.js"}}}`,
}

// githubDepAlerts is shaped like a real GET /repos/{owner}/{repo}/dependabot/alerts
// response.
var githubDepAlerts = []string{
	`{"number": 11, "state": "open", "html_url": "https://github.com/acme/widgets/security/dependabot/11",
	  "dependency": {"package": {"ecosystem": "npm", "name": "lodash"}, "manifest_path": "package-lock.json"},
	  "security_advisory": {"ghsa_id": "GHSA-jf85-cpcp-j695", "cve_id": "CVE-2021-23337",
	                        "summary": "Command Injection in lodash", "description": "lodash is vulnerable.",
	                        "severity": "high", "cvss_severities": {"cvss_v3": {"score": 7.2}},
	                        "cwes": [{"cwe_id": "CWE-94"}]},
	  "security_vulnerability": {"severity": "high", "vulnerable_version_range": "< 4.17.21",
	                             "first_patched_version": {"identifier": "4.17.21"}}}`,
	`{"number": 12, "state": "dismissed", "html_url": "https://github.com/acme/widgets/security/dependabot/12",
	  "dismissed_reason": "tolerable_risk", "dismissed_comment": "internal tool only",
	  "dependency": {"package": {"ecosystem": "npm", "name": "minimist"}, "manifest_path": "package-lock.json"},
	  "security_advisory": {"ghsa_id": "GHSA-xvch-5gv4-984h", "summary": "Prototype Pollution",
	                        "description": "minimist is vulnerable.", "severity": "critical"},
	  "security_vulnerability": {"severity": "critical", "vulnerable_version_range": "< 1.2.6"}}`,
	`{"number": 13, "state": "fixed", "security_advisory": {"ghsa_id": "GHSA-old"}}`,
	`{"number": 14, "state": "auto_dismissed", "security_advisory": {"ghsa_id": "GHSA-gone"}}`,
}

func fakeGitHub(t *testing.T, scope string, codeAlerts, depAlerts []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-token" || r.Header.Get("X-GitHub-Api-Version") == "" {
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page == 0 {
			page = 1
		}
		switch r.URL.Path {
		case "/repos/" + scope, "/orgs/" + scope:
			fmt.Fprint(w, `{"full_name":"`+scope+`","login":"`+scope+`"}`)
		case "/repos/" + scope + "/code-scanning/alerts", "/orgs/" + scope + "/code-scanning/alerts":
			writeGitHubPage(w, r, codeAlerts, page)
		case "/repos/" + scope + "/dependabot/alerts", "/orgs/" + scope + "/dependabot/alerts":
			writeGitHubPage(w, r, depAlerts, page)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeGitHubPage serves one item per page and a Link: rel="next" header
// until exhausted, like GitHub's classic pagination.
func writeGitHubPage(w http.ResponseWriter, r *http.Request, items []string, page int) {
	if page > len(items) {
		fmt.Fprint(w, "[]")
		return
	}
	if page < len(items) {
		next := *r.URL
		q := next.Query()
		q.Set("page", strconv.Itoa(page+1))
		next.RawQuery = q.Encode()
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s>; rel="next"`, r.Host, next.RequestURI()))
	}
	fmt.Fprint(w, "["+items[page-1]+"]")
}

func newGitHub(base, scope string) *gitHub {
	return &gitHub{base: base, scope: scope, token: "gh-token", hc: http.DefaultClient, pageSize: githubPageSize}
}

func TestGitHubFetchRepoScope(t *testing.T) {
	srv := fakeGitHub(t, "acme/widgets", githubCodeAlerts, githubDepAlerts)
	fs, err := newGitHub(srv.URL, "acme/widgets").Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Fixed (code scanning) and fixed/auto_dismissed (Dependabot) alerts are
	// not fetched, so the next pull auto-closes them.
	if len(fs) != 4 {
		t.Fatalf("findings = %d, want 4 (fixed/auto_dismissed excluded)", len(fs))
	}

	sqlInjection := fs[0]
	if sqlInjection.Category != domain.CategorySAST || sqlInjection.Severity != domain.SeverityCritical ||
		sqlInjection.RuleID != "js/sql-injection" || sqlInjection.CWE == nil || *sqlInjection.CWE != 89 ||
		sqlInjection.FilePath != "src/db.js" || sqlInjection.Line == nil || *sqlInjection.Line != 12 {
		t.Errorf("sql injection = %+v", sqlInjection)
	}
	if _, ok := sqlInjection.Metadata["remote_triage"]; ok {
		t.Error("open code scanning alert produced a remote verdict")
	}

	xssAlert := fs[1]
	if xssAlert.Severity != domain.SeverityMedium || xssAlert.CWE == nil || *xssAlert.CWE != 79 {
		t.Errorf("xss = %+v", xssAlert)
	}
	if xssAlert.Metadata["remote_triage"] != string(domain.FindingFalsePositive) ||
		!strings.Contains(xssAlert.Metadata["remote_triage_reason"].(string), "sanitized upstream") {
		t.Errorf("dismissed code scanning metadata = %v", xssAlert.Metadata)
	}

	dep1 := fs[2]
	if dep1.Category != domain.CategorySCA || dep1.RuleID != "GHSA-jf85-cpcp-j695" || len(dep1.CVE) != 1 ||
		dep1.CVE[0] != "CVE-2021-23337" || dep1.CWE == nil || *dep1.CWE != 94 || dep1.PackageName != "lodash" ||
		!strings.Contains(dep1.Description, "Vulnerable range: < 4.17.21") || !strings.Contains(dep1.Description, "Patched version: 4.17.21") {
		t.Errorf("dependabot lodash = %+v", dep1)
	}

	dep2 := fs[3]
	if dep2.Metadata["remote_triage"] != string(domain.FindingRiskAccepted) ||
		!strings.Contains(dep2.Metadata["remote_triage_reason"].(string), "internal tool only") {
		t.Errorf("dismissed dependabot metadata = %v", dep2.Metadata)
	}

	if name, err := newGitHub(srv.URL, "acme/widgets").Check(context.Background()); err != nil || name != "acme/widgets" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestGitHubOrgScope(t *testing.T) {
	srv := fakeGitHub(t, "acme", githubCodeAlerts[:1], nil)
	g := newGitHub(srv.URL, "org:acme")
	fs, err := g.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	if name, err := g.Check(context.Background()); err != nil || name != "acme" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestGitHubRateLimitThenError(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, err := newGitHub(srv.URL, "acme/widgets").Fetch(context.Background())
	var rerr RemoteError
	if !errors.As(err, &rerr) || !strings.Contains(err.Error(), "429") {
		t.Fatalf("err = %v, want a RemoteError mentioning 429", err)
	}
	if attempts != maxRateLimitRetries+1 {
		t.Fatalf("attempts = %d, want %d (every retry exhausted)", attempts, maxRateLimitRetries+1)
	}
}

func TestGitHubAuthFailure(t *testing.T) {
	srv := fakeGitHub(t, "acme/widgets", githubCodeAlerts, githubDepAlerts)
	bad := newGitHub(srv.URL, "acme/widgets")
	bad.token = "wrong"
	if _, err := bad.Fetch(context.Background()); !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad token err = %v, want a 401 RemoteError", err)
	}
}
