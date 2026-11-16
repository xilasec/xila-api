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
	"github.com/xilasec/xila-api/internal/finding"
)

const dtProject = "ca4f2da9-0fad-4a13-92d7-f627f3168a56"

// dtFindings is shaped like a real GET /api/v1/finding/project/{uuid} response
// (Finding Packaging Format fields, DT 4.x).
var dtFindings = []string{
	`{
	  "component": {"uuid": "b815b581-fec1-4374-a871-68862a8f8d52", "name": "lodash", "version": "4.17.20",
	                "purl": "pkg:npm/lodash@4.17.20", "project": "` + dtProject + `"},
	  "vulnerability": {"uuid": "115b80bb-46c4-41d1-9f10-8a175d4abb46", "source": "NVD", "vulnId": "CVE-2021-23337",
	                    "title": "Command Injection in lodash", "severity": "HIGH", "severityRank": 1,
	                    "cvssV3BaseScore": 7.2, "cweId": 94,
	                    "cwes": [{"cweId": 94, "name": "Improper Control of Generation of Code ('Code Injection')"}],
	                    "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
	                    "recommendation": "Upgrade to 4.17.21 or later."},
	  "analysis": {"state": "NOT_SET", "isSuppressed": false},
	  "attribution": {"analyzerIdentity": "INTERNAL_ANALYZER", "referenceUrl": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
	  "matrix": "` + dtProject + `:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46"
	}`,
	`{
	  "component": {"uuid": "979f87f5-eaf5-4095-9d38-cde17bf9228e", "group": "com.fasterxml.jackson.core", "name": "jackson-databind",
	                "version": "2.9.8", "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"},
	  "vulnerability": {"uuid": "701a3953-666b-4b7a-96ca-e1e6a3e1def3", "source": "GITHUB", "vulnId": "GHSA-57j2-w4cx-62h2",
	                    "aliases": [{"cveId": "CVE-2020-36518", "ghsaId": "GHSA-57j2-w4cx-62h2"}],
	                    "title": "Deeply nested json in jackson-databind", "severity": "UNASSIGNED", "cvssV3BaseScore": 7.5,
	                    "cwes": [{"cweId": 787, "name": "Out-of-bounds Write"}, {"cweId": 121, "name": "Stack-based Buffer Overflow"}],
	                    "description": "jackson-databind is a data-binding package."},
	  "analysis": {"state": "NOT_AFFECTED", "isSuppressed": true},
	  "matrix": "` + dtProject + `:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3"
	}`,
	`{
	  "component": {"uuid": "6d0c2b8e-58ab-4e6f-a3a3-4d0e3b2fd0e1", "name": "minimist", "version": "1.2.5", "purl": "pkg:npm/minimist@1.2.5"},
	  "vulnerability": {"uuid": "0cbd5b6f-2b05-4b6e-8f4e-6b2f3c1d9e11", "source": "NVD", "vulnId": "CVE-2021-44906",
	                    "title": "", "severity": "CRITICAL", "cvssV3BaseScore": 9.8},
	  "analysis": {"isSuppressed": false},
	  "matrix": "` + dtProject + `:6d0c2b8e-58ab-4e6f-a3a3-4d0e3b2fd0e1:0cbd5b6f-2b05-4b6e-8f4e-6b2f3c1d9e11"
	}`,
}

// fakeDT serves the findings in pages of the requested size with X-Total-Count,
// and records each request's query.
func fakeDT(t *testing.T, items []string, total int) (*httptest.Server, *[]string) {
	t.Helper()
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "dt-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/project/" + dtProject:
			fmt.Fprint(w, `{"uuid":"`+dtProject+`","name":"Acme Web","version":"1.0"}`)
		case "/api/v1/finding/project/" + dtProject:
			queries = append(queries, r.URL.RawQuery)
			page, _ := strconv.Atoi(r.URL.Query().Get("pageNumber"))
			size, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
			lo := min((page-1)*size, len(items))
			hi := min(lo+size, len(items))
			w.Header().Set("X-Total-Count", strconv.Itoa(total))
			fmt.Fprint(w, "["+strings.Join(items[lo:hi], ",")+"]")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &queries
}

func newDT(base string, pageSize int) *dependencyTrack {
	return &dependencyTrack{base: base, project: dtProject, token: "dt-key", hc: http.DefaultClient, pageSize: pageSize}
}

func TestDependencyTrackFetch(t *testing.T) {
	srv, queries := fakeDT(t, dtFindings, len(dtFindings))
	fs, err := newDT(srv.URL, 2).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(*queries) != 2 {
		t.Fatalf("requests = %v, want 2 pages", *queries)
	}
	for i, q := range *queries {
		if want := "pageNumber=" + strconv.Itoa(i+1); !strings.Contains(q, want) ||
			!strings.Contains(q, "pageSize=2") || !strings.Contains(q, "suppressed=true") {
			t.Errorf("page %d query = %q", i+1, q)
		}
	}
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3", len(fs))
	}

	lodash := fs[0]
	if lodash.RuleID != "CVE-2021-23337" || lodash.Severity != domain.SeverityHigh ||
		lodash.Category != domain.CategorySCA || lodash.PackageName != "lodash" || lodash.PackageVersion != "4.17.20" ||
		lodash.Purl != "pkg:npm/lodash@4.17.20" || lodash.CWE == nil || *lodash.CWE != 94 ||
		lodash.CVSS == nil || *lodash.CVSS != 7.2 || len(lodash.CVE) != 1 || lodash.CVE[0] != "CVE-2021-23337" {
		t.Errorf("lodash = %+v", lodash)
	}
	if lodash.Title != "Command Injection in lodash (lodash 4.17.20)" ||
		!strings.Contains(lodash.Description, "Recommendation: Upgrade to 4.17.21") ||
		lodash.URL != "https://nvd.nist.gov/vuln/detail/CVE-2021-23337" {
		t.Errorf("lodash text = %q / %q / %q", lodash.Title, lodash.Description, lodash.URL)
	}
	if _, ok := lodash.Metadata["remote_triage"]; ok {
		t.Error("NOT_SET analysis produced a remote verdict")
	}

	// A GHSA with its CVE under aliases: the CVE is lifted (dedup + EPSS key on
	// it), the package is named group:artifact like Maven scanners do, the
	// unassigned severity falls back to the CVSS score, and the NOT_AFFECTED
	// analysis is carried as a verdict.
	jackson := fs[1]
	if jackson.RuleID != "GHSA-57j2-w4cx-62h2" || len(jackson.CVE) != 1 || jackson.CVE[0] != "CVE-2020-36518" ||
		jackson.PackageName != "com.fasterxml.jackson.core:jackson-databind" || jackson.Severity != domain.SeverityHigh ||
		jackson.CWE == nil || *jackson.CWE != 787 {
		t.Errorf("jackson = %+v", jackson)
	}
	if jackson.Metadata["remote_triage"] != string(domain.FindingFalsePositive) ||
		jackson.Metadata["analysis_state"] != "NOT_AFFECTED" || jackson.Metadata["suppressed"] != true {
		t.Errorf("jackson metadata = %v", jackson.Metadata)
	}

	if minimist := fs[2]; minimist.Title != "CVE-2021-44906 (minimist 1.2.5)" || minimist.Severity != domain.SeverityCritical {
		t.Errorf("minimist = %q %s", minimist.Title, minimist.Severity)
	}

	// Fingerprints are stable across pulls and distinct per finding.
	again, err := newDT(srv.URL, 100).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := range fs {
		if fs[i].Fingerprint != again[i].Fingerprint {
			t.Errorf("fingerprint %d changed between pulls", i)
		}
		seen[fs[i].Fingerprint] = true
	}
	if len(seen) != 3 {
		t.Error("fingerprints collide")
	}
}

func TestDependencyTrackFetchRefusesPartial(t *testing.T) {
	// The server claims more findings than it hands out: applying this would
	// auto-close the missing ones, so the fetch must fail.
	srv, _ := fakeDT(t, dtFindings[:2], 5)
	if _, err := newDT(srv.URL, 100).Fetch(context.Background()); !errors.As(err, new(RemoteError)) {
		t.Fatalf("partial fetch err = %v, want RemoteError", err)
	}

	srv, _ = fakeDT(t, dtFindings, 3)
	bad := newDT(srv.URL, 100)
	bad.token = "wrong"
	_, err := bad.Fetch(context.Background())
	if !errors.As(err, new(RemoteError)) || !strings.Contains(err.Error(), "401") {
		t.Fatalf("bad key err = %v, want 401 RemoteError", err)
	}
	if _, err := bad.Check(context.Background()); err == nil {
		t.Error("check passed with a bad key")
	}
	if name, err := newDT(srv.URL, 100).Check(context.Background()); err != nil || name != "Acme Web 1.0" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestDependencyTrackServerIgnoringPaging(t *testing.T) {
	// Older servers return everything on every page and no total: stop once a
	// page brings nothing new instead of looping to maxPages.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, "["+strings.Join(dtFindings, ",")+"]")
	}))
	defer srv.Close()
	fs, err := newDT(srv.URL, 2).Fetch(context.Background())
	if err != nil || len(fs) != 3 || calls != 2 {
		t.Fatalf("fetch = %d findings, %v, %d calls; want 3, nil, 2", len(fs), err, calls)
	}
}

// ddFindings is shaped like GET /api/v2/findings/ results (FindingSerializer).
var ddFindings = []string{
	`{"id": 101, "title": "Prototype Pollution in minimist", "severity": "Critical", "cwe": 1321,
	  "vulnerability_ids": [{"vulnerability_id": "CVE-2021-44906"}, {"vulnerability_id": "GHSA-xvch-5gv4-984h"}],
	  "cvssv3_score": 9.8, "component_name": "minimist", "component_version": "1.2.5",
	  "description": "minimist <=1.2.5 is vulnerable to Prototype Pollution.", "mitigation": "Upgrade to 1.2.6",
	  "unique_id_from_tool": "npm-minimist-1.2.5", "vuln_id_from_tool": "CVE-2021-44906", "hash_code": "aa11",
	  "active": true, "verified": true, "false_p": false, "risk_accepted": false, "out_of_scope": false,
	  "static_finding": false, "test": 7, "file_path": null, "line": null}`,
	`{"id": 102, "title": "SQL Injection", "severity": "High", "cwe": 89, "vulnerability_ids": [],
	  "description": "User input reaches a SQL query.", "mitigation": "", "file_path": "app/db.py", "line": 42,
	  "unique_id_from_tool": "python.sqlalchemy.security.sqli", "hash_code": "bb22",
	  "active": false, "verified": false, "false_p": true, "risk_accepted": false, "out_of_scope": false,
	  "static_finding": true, "test": 8}`,
	`{"id": 103, "title": "Missing HSTS header", "severity": "Info", "cwe": 0, "vulnerability_ids": [],
	  "description": "", "hash_code": "cc33", "active": true, "verified": false, "false_p": false,
	  "risk_accepted": false, "out_of_scope": false, "static_finding": false, "dynamic_finding": true, "test": 9}`,
	`{"id": 104, "title": "Old finding", "severity": "Low", "hash_code": "dd44", "active": false,
	  "verified": false, "false_p": false, "risk_accepted": false, "out_of_scope": false, "test": 9}`,
	`{"id": 105, "title": "Accepted XSS", "severity": "Medium", "cwe": 79, "hash_code": "ee55", "file_path": "web/x.js",
	  "active": false, "verified": true, "false_p": false, "risk_accepted": true, "out_of_scope": false, "test": 8}`,
}

func fakeDD(t *testing.T, items []string, count int) (*httptest.Server, *[]string) {
	t.Helper()
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token dd-key" {
			http.Error(w, `{"detail":"Invalid token."}`, http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v2/products/3/":
			fmt.Fprint(w, `{"id":3,"name":"Acme Shop"}`)
		case "/api/v2/engagements/9/":
			fmt.Fprint(w, `{"id":9,"name":"CI main"}`)
		case "/api/v2/findings/":
			queries = append(queries, r.URL.RawQuery)
			off, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			lim, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			lo := min(off, len(items))
			hi := min(lo+lim, len(items))
			fmt.Fprintf(w, `{"count": %d, "next": null, "previous": null, "results": [%s]}`, count, strings.Join(items[lo:hi], ","))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &queries
}

func newDD(base, scope string, pageSize int) *defectDojo {
	return &defectDojo{base: base, scope: scope, token: "dd-key", hc: http.DefaultClient, pageSize: pageSize}
}

func TestDefectDojoFetch(t *testing.T) {
	srv, queries := fakeDD(t, ddFindings, len(ddFindings))
	dd := newDD(srv.URL, "3", 2)
	fs, err := dd.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(*queries) != 3 {
		t.Fatalf("requests = %v, want 3 pages", *queries)
	}
	for i, q := range *queries {
		for _, want := range []string{"test__engagement__product=3", "duplicate=false", "is_mitigated=false",
			"limit=2", "offset=" + strconv.Itoa(i*2)} {
			if !strings.Contains(q, want) {
				t.Errorf("page %d query %q lacks %s", i, q, want)
			}
		}
	}
	// 104 is inactive and untriaged (resolved in DefectDojo): not reported, so
	// Xila auto-closes it. The false positive and the risk acceptance are kept
	// so their verdicts carry over.
	byID := map[any]finding.Finding{}
	for _, f := range fs {
		byID[f.Metadata["remote_id"]] = f
	}
	if len(fs) != 4 || byID[104].Title != "" {
		t.Fatalf("findings = %d (%v), want 101,102,103,105", len(fs), byID)
	}

	sca := byID[101]
	if sca.Category != domain.CategorySCA || sca.Severity != domain.SeverityCritical || sca.RuleID != "CVE-2021-44906" ||
		len(sca.CVE) != 1 || sca.CVE[0] != "CVE-2021-44906" || sca.PackageName != "minimist" || sca.PackageVersion != "1.2.5" ||
		sca.CWE == nil || *sca.CWE != 1321 || sca.CVSS == nil || *sca.CVSS != 9.8 ||
		!strings.Contains(sca.Description, "Mitigation: Upgrade to 1.2.6") || sca.URL != srv.URL+"/finding/101" {
		t.Errorf("sca = %+v", sca)
	}
	if sca.Metadata["unique_id_from_tool"] != "npm-minimist-1.2.5" || sca.Metadata["remote_triage"] != string(domain.FindingConfirmed) {
		t.Errorf("sca metadata = %v", sca.Metadata)
	}

	sast := byID[102]
	if sast.Category != domain.CategorySAST || sast.FilePath != "app/db.py" || sast.Line == nil || *sast.Line != 42 ||
		sast.Metadata["remote_triage"] != string(domain.FindingFalsePositive) || len(sast.CVE) != 0 || sast.CVE == nil {
		t.Errorf("sast = %+v", sast)
	}
	if dast := byID[103]; dast.Category != domain.CategoryDAST || dast.Severity != domain.SeverityInfo || dast.CWE != nil {
		t.Errorf("dast = %+v", dast)
	}
	if acc := byID[105]; acc.Metadata["remote_triage"] != string(domain.FindingRiskAccepted) {
		t.Errorf("accepted = %v", acc.Metadata)
	}
	if got := dd.Category(fs); got != domain.CategorySAST {
		t.Errorf("category = %s, want the most common (sast)", got)
	}
	if name, err := dd.Check(context.Background()); err != nil || name != "Acme Shop" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestDefectDojoEngagementScope(t *testing.T) {
	srv, queries := fakeDD(t, ddFindings[:1], 1)
	dd := newDD(srv.URL, "engagement:9", 100)
	if _, err := dd.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q := (*queries)[0]; !strings.Contains(q, "test__engagement=9") || strings.Contains(q, "product") {
		t.Errorf("query = %q", q)
	}
	if name, err := dd.Check(context.Background()); err != nil || name != "CI main" {
		t.Errorf("check = %q, %v", name, err)
	}
}

func TestDefectDojoFetchRefusesPartial(t *testing.T) {
	srv, _ := fakeDD(t, ddFindings[:2], 9)
	if _, err := newDD(srv.URL, "3", 100).Fetch(context.Background()); !errors.As(err, new(RemoteError)) {
		t.Fatalf("partial fetch err = %v, want RemoteError", err)
	}
	bad := newDD(srv.URL, "3", 100)
	bad.token = "nope"
	if _, err := bad.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("bad token err = %v", err)
	}
}

func TestInputNormalize(t *testing.T) {
	cases := []struct {
		name, wantErr string
		in            Input
		want          Connector
	}{
		{name: "dt strips api suffix", in: Input{Kind: "Dependency-Track", BaseURL: "https://dt.example.com/api/v1/", RemoteProject: strings.ToUpper(dtProject)},
			want: Connector{Kind: KindDependencyTrack, BaseURL: "https://dt.example.com", RemoteProject: dtProject, Enabled: true}},
		{name: "dd product", in: Input{Kind: "defectdojo", BaseURL: "https://dojo.example.com/api/v2", RemoteProject: "product:42", Version: " release-1 "},
			want: Connector{Kind: KindDefectDojo, BaseURL: "https://dojo.example.com", RemoteProject: "42", Version: "release-1", Enabled: true}},
		{name: "dd engagement", in: Input{Kind: "defectdojo", BaseURL: "http://dojo:8080", RemoteProject: "Engagement:7", Enabled: new(false)},
			want: Connector{Kind: KindDefectDojo, BaseURL: "http://dojo:8080", RemoteProject: "engagement:7"}},
		{name: "bad kind", in: Input{Kind: "snyk", BaseURL: "https://x", RemoteProject: "1"}, wantErr: "kind"}, // "snyk" itself isn't a kind — see KindSnyk's doc comment
		{name: "bad url", in: Input{Kind: "defectdojo", BaseURL: "ftp://x", RemoteProject: "1"}, wantErr: "base_url"},
		{name: "userinfo url", in: Input{Kind: "defectdojo", BaseURL: "https://u:p@x", RemoteProject: "1"}, wantErr: "base_url"},
		{name: "dt needs uuid", in: Input{Kind: "dependency-track", BaseURL: "https://dt", RemoteProject: "acme"}, wantErr: "UUID"},
		{name: "dd needs id", in: Input{Kind: "defectdojo", BaseURL: "https://dd", RemoteProject: "acme"}, wantErr: "product id"},
		{name: "snyk org only", in: Input{Kind: "snyk-api", BaseURL: "https://api.snyk.io/rest", RemoteProject: "11111111-1111-1111-1111-111111111111"},
			want: Connector{Kind: KindSnyk, BaseURL: "https://api.snyk.io", RemoteProject: "11111111-1111-1111-1111-111111111111", Enabled: true}},
		{name: "snyk org and project", in: Input{Kind: "snyk-api", BaseURL: "https://api.snyk.io",
			RemoteProject: "11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222"},
			want: Connector{Kind: KindSnyk, BaseURL: "https://api.snyk.io",
				RemoteProject: "11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222", Enabled: true}},
		{name: "snyk bad org", in: Input{Kind: "snyk-api", BaseURL: "https://api.snyk.io", RemoteProject: "acme"}, wantErr: "org id"},
		{name: "github repo on github.com", in: Input{Kind: "github", BaseURL: "https://github.com", RemoteProject: "Acme/Widgets"},
			want: Connector{Kind: KindGitHub, BaseURL: "https://api.github.com", RemoteProject: "acme/widgets", Enabled: true}},
		{name: "github org scope on GHES", in: Input{Kind: "GitHub", BaseURL: "https://ghe.example.com/api/v3", RemoteProject: "org:Acme"},
			want: Connector{Kind: KindGitHub, BaseURL: "https://ghe.example.com/api/v3", RemoteProject: "org:acme", Enabled: true}},
		{name: "github bad scope", in: Input{Kind: "github", BaseURL: "https://github.com", RemoteProject: "acme"}, wantErr: "owner/repo"},
		{name: "gitlab project path", in: Input{Kind: "gitlab", BaseURL: "https://gitlab.example.com/api/v4", RemoteProject: "Group/Sub/Project"},
			want: Connector{Kind: KindGitLab, BaseURL: "https://gitlab.example.com", RemoteProject: "Group/Sub/Project", Enabled: true}},
		{name: "gitlab bad path", in: Input{Kind: "gitlab", BaseURL: "https://gitlab.com", RemoteProject: "acme"}, wantErr: "project path"},
		{name: "wiz needs auth_url", in: Input{Kind: "wiz", BaseURL: "https://api.us1.app.wiz.io", RemoteProject: ""}, wantErr: "auth_url"},
		{name: "wiz ok", in: Input{Kind: "wiz", BaseURL: "https://api.us1.app.wiz.io", AuthURL: "https://auth.app.wiz.io/oauth/token",
			RemoteProject: "11111111-1111-1111-1111-111111111111"},
			want: Connector{Kind: KindWiz, BaseURL: "https://api.us1.app.wiz.io/graphql", AuthURL: "https://auth.app.wiz.io/oauth/token",
				RemoteProject: "11111111-1111-1111-1111-111111111111", Enabled: true}},
		{name: "wiz bad project list", in: Input{Kind: "wiz", BaseURL: "https://api.us1.app.wiz.io", AuthURL: "https://auth.app.wiz.io/oauth/token",
			RemoteProject: "not-a-uuid"}, wantErr: "project UUIDs"},
		{name: "tenable whole instance", in: Input{Kind: "tenable", BaseURL: "https://cloud.tenable.com", RemoteProject: ""},
			want: Connector{Kind: KindTenable, BaseURL: "https://cloud.tenable.com", RemoteProject: "", Enabled: true}},
		{name: "tenable bad tag filter", in: Input{Kind: "tenable", BaseURL: "https://cloud.tenable.com", RemoteProject: "Location"},
			wantErr: "category=value"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.in.Normalize("p1")
			if c.wantErr != "" {
				if !errors.As(err, new(ValidationError)) || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			c.want.ProjectID = "p1"
			if fmt.Sprintf("%+v", got) != fmt.Sprintf("%+v", c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}
