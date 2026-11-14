package server

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// rawGet fetches a non-JSON response body.
func rawGet(t *testing.T, app *fiber.App, path, token string) (*http.Response, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

// csvColumn reads an export and returns its header and one column's values.
func csvColumn(t *testing.T, body []byte, col string) []string {
	t.Helper()
	recs, err := csv.NewReader(bytes.NewReader(body)).ReadAll()
	if err != nil || len(recs) == 0 {
		t.Fatalf("bad csv (%v): %s", err, body)
	}
	idx := -1
	for i, h := range recs[0] {
		if h == col {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("no %q column in %v", col, recs[0])
	}
	out := []string{}
	for _, r := range recs[1:] {
		out = append(out, r[idx])
	}
	return out
}

// listIDs returns the ids a JSON listing returns under key.
func listIDs(t *testing.T, app *fiber.App, path, token, key string) []string {
	t.Helper()
	resp, body := req(t, app, http.MethodGet, path, token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d", path, resp.StatusCode)
	}
	items, _ := body[key].([]any)
	ids := []string{}
	for _, it := range items {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	return ids
}

// TestExportsAndReports drives the M4.2 surface end to end: exports carry exactly
// the matching listing's rows (filters, RBAC scope, duplicates, default branch),
// CSV neutralizes formulas, XLSX opens as a workbook, and reports are scoped and
// escape what they print.
func TestExportsAndReports(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	carol := rbacUser(t, app, "carol@xila.io")
	_ = admin

	setup := func(token, slug, name string) string {
		t.Helper()
		_, o := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		orgID, _ := o["id"].(string)
		_, tm := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", token, `{"slug":"`+slug+`-t","name":"T"}`)
		teamID, _ := tm["id"].(string)
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", token, `{"slug":"`+slug+`-p","name":"`+name+`"}`)
		projectID, _ := p["id"].(string)
		if projectID == "" {
			t.Fatalf("setup %s failed", slug)
		}
		return projectID
	}
	bobProject := setup(bob, "beta", "Bob Payments")
	carolProject := setup(carol, "gamma", "Carol Ledger")

	malicious := `=HYPERLINK("http://evil.example","x")<script>alert(1)</script>`
	title, _ := json.Marshal(malicious)
	trivy := fmt.Sprintf(`{"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2020-1","PkgName":"pkgA","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"CRITICAL","Title":%s},
		{"VulnerabilityID":"CVE-2020-2","PkgName":"pkgB","InstalledVersion":"2.0","Severity":"HIGH"},
		{"VulnerabilityID":"CVE-2020-3","PkgName":"pkgC","InstalledVersion":"3.0","Severity":"MEDIUM"}]}]}`, title)
	upload := func(token, project, query, body string) {
		t.Helper()
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+project+"/scans?"+query, token, body); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload %s = %d", query, resp.StatusCode)
		}
	}
	upload(bob, bobProject, "scanner=trivy", trivy)
	// Grype reporting the same CVE+package: a cross-tool duplicate.
	upload(bob, bobProject, "scanner=grype", `{"matches":[{"vulnerability":{"id":"CVE-2020-1","severity":"Critical"},"artifact":{"name":"pkgA","version":"1.0"}}]}`)
	// A feature branch carrying an extra issue: not on the default version.
	upload(bob, bobProject, "scanner=trivy&branch=feature-x", `{"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2020-9","PkgName":"pkgZ","InstalledVersion":"9.0","Severity":"CRITICAL"}]}]}`)
	upload(carol, carolProject, "scanner=trivy", `{"Results":[{"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2020-7","PkgName":"carolpkg","InstalledVersion":"7.0","Severity":"LOW","Title":"carol-only"}]}]}`)

	// --- findings export = the listing, filter for filter -------------------
	for _, q := range []string{"", "severity=critical", "include_duplicates=true", "all_versions=true", "sort=priority"} {
		want := listIDs(t, app, "/api/v1/findings?limit=200&"+q, bob, "findings")
		resp, body := rawGet(t, app, "/api/v1/findings/export?"+q, bob)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("export ?%s = %d %s", q, resp.StatusCode, body)
		}
		if got := csvColumn(t, body, "ID"); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("export ?%s rows = %v, list = %v", q, got, want)
		}
	}
	// Spot-check the sets themselves: 3 default-branch primaries; the grype copy
	// only with include_duplicates; the branch issue only with all_versions.
	_, body := rawGet(t, app, "/api/v1/findings/export", bob)
	if n := len(csvColumn(t, body, "ID")); n != 3 {
		t.Errorf("bob's default export has %d rows, want 3", n)
	}
	_, dupBody := rawGet(t, app, "/api/v1/findings/export?include_duplicates=true", bob)
	_, allBody := rawGet(t, app, "/api/v1/findings/export?all_versions=true", bob)
	if n, m := len(csvColumn(t, dupBody, "ID")), len(csvColumn(t, allBody, "ID")); n != 4 || m != 4 {
		t.Errorf("include_duplicates → %d rows, all_versions → %d rows; want 4 each", n, m)
	}
	// Bob's cross-project export never includes Carol's findings.
	if strings.Contains(string(body), "carol-only") || strings.Contains(string(body), "Carol Ledger") {
		t.Error("bob's export leaked carol's project")
	}
	// Formula injection is neutralized; names, not ids, label the rows.
	titles := csvColumn(t, body, "Title")
	if !strings.Contains(strings.Join(titles, "\n"), "'"+malicious) {
		t.Errorf("formula title not escaped: %q", titles)
	}
	if projects := csvColumn(t, body, "Project"); projects[0] != "Bob Payments" {
		t.Errorf("project column = %q", projects)
	}

	// Per-project export: same filters; another team's project is forbidden.
	resp, body := rawGet(t, app, "/api/v1/projects/"+bobProject+"/findings/export?branch=feature-x", bob)
	if resp.StatusCode != http.StatusOK || len(csvColumn(t, body, "ID")) != 1 {
		t.Errorf("project export ?branch=feature-x = %d, %d rows; want 1 row", resp.StatusCode, len(csvColumn(t, body, "ID")))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), `attachment; filename="xila-findings-`) ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "text/csv") {
		t.Errorf("headers = %q / %q", resp.Header.Get("Content-Disposition"), resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Truncated") != "" {
		t.Error("a small export must not be flagged truncated")
	}
	if resp, _ := rawGet(t, app, "/api/v1/projects/"+carolProject+"/findings/export", bob); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob exporting carol's project = %d, want 403", resp.StatusCode)
	}
	// Even naming carol's project explicitly in the cross-project export yields nothing.
	if _, body := rawGet(t, app, "/api/v1/findings/export?project_id="+carolProject, bob); len(csvColumn(t, body, "ID")) != 0 {
		t.Error("bob exported carol's findings via ?project_id=")
	}
	if resp, _ := rawGet(t, app, "/api/v1/findings/export?format=pdf", bob); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("format=pdf = %d, want 400", resp.StatusCode)
	}
	if resp, _ := rawGet(t, app, "/api/v1/findings/export?severity=bogus", bob); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid filter = %d, want 400 (same validation as the list)", resp.StatusCode)
	}

	// XLSX: a workbook with the same rows; the formula title stays inert text.
	resp, body = rawGet(t, app, "/api/v1/findings/export?format=xlsx", bob)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		t.Fatalf("xlsx = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	sheet := xlsxSheet(t, body)
	if n := strings.Count(sheet, "<row "); n != 4 { // header + 3
		t.Errorf("xlsx has %d rows, want 4", n)
	}
	if strings.Contains(sheet, "<f>") || !strings.Contains(sheet, "=HYPERLINK(&#34;http://evil.example&#34;,&#34;x&#34;)&lt;script&gt;") {
		t.Error("xlsx title should be an inline string, never a formula")
	}

	// --- components export -------------------------------------------------
	for _, p := range []struct{ token, project string }{{bob, bobProject}, {carol, carolProject}} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+p.project+"/sboms?artifact=web", p.token, smokeCycloneDX); resp.StatusCode != http.StatusCreated {
			t.Fatalf("sbom upload = %d", resp.StatusCode)
		}
	}
	for _, q := range []string{"", "latest=true", "vulnerable=true", "search=log4j"} {
		want := listIDs(t, app, "/api/v1/components?limit=200&"+q, bob, "components")
		_, body := rawGet(t, app, "/api/v1/components/export?"+q, bob)
		if got := csvColumn(t, body, "Component ID"); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("components export ?%s = %v, list = %v", q, got, want)
		}
		if strings.Contains(string(body), "Carol Ledger") {
			t.Errorf("components export ?%s leaked carol's project", q)
		}
	}
	_, sboms := req(t, app, http.MethodGet, "/api/v1/projects/"+bobProject+"/sboms", bob, "")
	sbomID := sboms["sboms"].([]any)[0].(map[string]any)["id"].(string)
	want := listIDs(t, app, "/api/v1/sboms/"+sbomID+"/components?limit=200", bob, "components")
	_, body = rawGet(t, app, "/api/v1/sboms/"+sbomID+"/components/export", bob)
	if got := csvColumn(t, body, "Component ID"); len(want) != 4 || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sbom export = %v, list = %v", got, want)
	}
	if resp, _ := rawGet(t, app, "/api/v1/sboms/"+sbomID+"/components/export", carol); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol exporting bob's sbom = %d, want 403", resp.StatusCode)
	}
	if resp, _ := rawGet(t, app, "/api/v1/projects/"+bobProject+"/components/export?format=xlsx", carol); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol exporting bob's components = %d, want 403", resp.StatusCode)
	}

	// --- reports -----------------------------------------------------------
	resp, body = rawGet(t, app, "/api/v1/projects/"+bobProject+"/report", bob)
	html := string(body)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("project report = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(resp.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("report should be served with a no-script CSP")
	}
	if strings.Contains(html, "<script>alert(1)") || !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("report must escape the malicious finding title")
	}
	// The report's numbers are the API's: same rollup, same scope. Bob's backlog
	// is the 3 default-branch scanner findings plus the SBOM's copyleft license
	// finding — the grype duplicate and the feature-branch issue don't count.
	kpi := func(v any, label string) string {
		return fmt.Sprintf(`<div class="v">%v</div><div class="l">%s</div>`, v, label)
	}
	_, summary := req(t, app, http.MethodGet, "/api/v1/portfolio", bob, "")
	if summary["total_open"] != float64(4) {
		t.Fatalf("bob's portfolio total_open = %v, want 4", summary["total_open"])
	}
	risk := strconv.FormatFloat(summary["risk_score"].(float64), 'f', 1, 64)
	for _, want := range []string{
		"Bob Payments",
		kpi(risk, "Risk score"),
		kpi(4, "Open findings"),
		"Not included: feature-x",
		"CVE-2020-1",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("project report missing %q", want)
		}
	}
	if strings.Contains(html, "CVE-2020-9") {
		t.Error("project report listed a feature-branch finding")
	}
	if resp, _ := rawGet(t, app, "/api/v1/projects/"+bobProject+"/report", carol); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol reading bob's report = %d, want 403", resp.StatusCode)
	}

	_, carolSummary := req(t, app, http.MethodGet, "/api/v1/portfolio", carol, "")
	resp, body = rawGet(t, app, "/api/v1/portfolio/report", carol)
	html = string(body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(html, "Carol Ledger") || strings.Contains(html, "Bob Payments") ||
		!strings.Contains(html, kpi(carolSummary["total_open"], "Open findings")) {
		t.Errorf("carol's portfolio report should cover only her project (status %d)", resp.StatusCode)
	}
	_, body = rawGet(t, app, "/api/v1/portfolio/report", admin)
	if html := string(body); !strings.Contains(html, "Carol Ledger") || !strings.Contains(html, "Bob Payments") {
		t.Error("the admin's portfolio report should cover every project")
	}
}

// xlsxSheet returns the worksheet XML of an XLSX export.
func xlsxSheet(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("xlsx is not a zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			defer rc.Close()
			s, _ := io.ReadAll(rc)
			return string(s)
		}
	}
	t.Fatal("xlsx has no sheet1")
	return ""
}
