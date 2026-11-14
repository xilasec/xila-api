package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// DefectDojo's workflow over HTTP: an engagement collects scans (its tests)
// and manual findings; a manual finding made from a template runs the normal
// pipeline but no scanner ever auto-closes it; only its write-up is editable;
// and a templated engagement report is the pentest deliverable.
func TestEngagementsManualFindingsAndReports(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io") // first user: instance admin
	lead := rbacUser(t, app, "lead@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	newProject := func(slug string) string {
		t.Helper()
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		id, _ := p["id"].(string)
		return id
	}
	pid, other := newProject("web"), newProject("other")
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"viewer@xila.io","role":"viewer"}`)

	// Engagements: editors create them, viewers read them.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/engagements", viewer, `{"name":"nope"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer creating an engagement = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/engagements", lead,
		`{"name":"bad dates","starts_on":"2025-03-10","ends_on":"2025-03-01"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("ends before it starts = %d, want 400", resp.StatusCode)
	}
	resp, eng := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/engagements", lead,
		`{"name":"Q3 pentest","kind":"interactive","starts_on":"2025-07-01","ends_on":"2025-07-14"}`)
	if resp.StatusCode != http.StatusCreated || eng["status"] != "in_progress" {
		t.Fatalf("create engagement = %d %v", resp.StatusCode, eng)
	}
	engID, _ := eng["id"].(string)
	_, otherEng := req(t, app, http.MethodPost, "/api/v1/projects/"+other+"/engagements", lead, `{"name":"elsewhere"}`)
	otherEngID, _ := otherEng["id"].(string)
	if resp, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/engagements", viewer, ""); resp.StatusCode != http.StatusOK || len(list["engagements"].([]any)) != 1 {
		t.Errorf("viewer listing engagements = %d %v", resp.StatusCode, list)
	}

	// A scan uploaded into the engagement is one of its tests; one of another
	// project's engagements is refused.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy&engagement_id="+otherEngID, lead, smokeTrivyReport); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("scan into another project's engagement = %d, want 400", resp.StatusCode)
	}
	if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy&engagement_id="+engID, lead, smokeTrivyReport); resp.StatusCode != http.StatusCreated || body["engagement_id"] != engID {
		t.Fatalf("scan into the engagement = %d %v", resp.StatusCode, body["engagement_id"])
	}
	_, got := req(t, app, http.MethodGet, "/api/v1/engagements/"+engID, viewer, "")
	stats, _ := got["stats"].(map[string]any)
	if scans, _ := got["scans"].([]any); len(scans) != 1 || stats["scans"] != float64(1) || stats["findings"].(float64) < 1 {
		t.Fatalf("engagement after one scan = scans %v stats %v", got["scans"], stats)
	}
	scannerFindings := stats["findings"].(float64)

	// Finding templates: admins write them, everyone reads them.
	tmplBody := `{"title":"IDOR on order ids","severity":"high","category":"dast","cwe":639,
		"description":"Orders of other customers are readable.","mitigation":"Check ownership server-side.",
		"impact":"Disclosure of every customer's orders.","references":["https://owasp.org/www-community/attacks/IDOR"],"tags":["pentest"]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/finding-templates", lead, tmplBody); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin creating a template = %d, want 403", resp.StatusCode)
	}
	resp, tmpl := req(t, app, http.MethodPost, "/api/v1/finding-templates", admin, tmplBody)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create template = %d %v", resp.StatusCode, tmpl)
	}
	tmplID, _ := tmpl["id"].(string)
	if resp, list := req(t, app, http.MethodGet, "/api/v1/finding-templates", viewer, ""); resp.StatusCode != http.StatusOK || len(list["templates"].([]any)) != 1 {
		t.Errorf("viewer listing templates = %d %v", resp.StatusCode, list)
	}

	// A manual finding from the template, in the engagement.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/findings", viewer, `{"title":"x","severity":"low"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer reporting a finding = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/findings", lead,
		`{"title":"x","severity":"low","engagement_id":"`+otherEngID+`"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("manual finding into another project's engagement = %d, want 400", resp.StatusCode)
	}
	resp, manual := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/findings", lead,
		`{"template_id":"`+tmplID+`","url":"https://shop.example.com/api/orders/42","steps_to_reproduce":"GET /api/orders/42 as another user","engagement_id":"`+engID+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("manual finding = %d %v", resp.StatusCode, manual)
	}
	meta, _ := manual["metadata"].(map[string]any)
	if manual["scanner"] != "manual" || manual["title"] != "IDOR on order ids" || manual["severity"] != "high" ||
		manual["cwe"] != float64(639) || meta["mitigation"] != "Check ownership server-side." ||
		meta["steps_to_reproduce"] != "GET /api/orders/42 as another user" {
		t.Fatalf("manual finding from template = %v", manual)
	}
	if tags, _ := manual["tags"].([]any); len(tags) != 1 || tags[0] != "pentest" {
		t.Errorf("manual finding tags = %v, want the template's", manual["tags"])
	}
	manualID, _ := manual["id"].(string)
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+manualID+"/history", lead, "")
	if evs, _ := hist["events"].([]any); len(evs) == 0 || evs[0].(map[string]any)["kind"] != "created" ||
		evs[0].(map[string]any)["actor_name"] != "lead@xila.io" {
		t.Errorf("manual finding history = %v, want it created by its reporter", hist["events"])
	}
	_, inEng := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings?engagement_id="+engID+"&scanner=manual", viewer, "")
	if fs, _ := inEng["findings"].([]any); len(fs) != 1 {
		t.Errorf("?engagement_id lists %d manual findings, want 1", len(fs))
	}
	_, got = req(t, app, http.MethodGet, "/api/v1/engagements/"+engID, viewer, "")
	if n := got["stats"].(map[string]any)["findings"].(float64); n != scannerFindings+1 {
		t.Errorf("engagement findings = %v, want %v", n, scannerFindings+1)
	}

	// A second manual report and a new scanner run close nothing manual.
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/findings", lead, `{"title":"Verbose errors","severity":"low"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport)
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+manualID, lead, ""); f["status"] != "open" {
		t.Errorf("manual finding after later reports = %v, want open", f["status"])
	}

	// Only a manual finding's write-up is editable, by an editor.
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+manualID+"/details", viewer, `{"impact":"x"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer editing a write-up = %d, want 403", resp.StatusCode)
	}
	resp, edited := req(t, app, http.MethodPatch, "/api/v1/findings/"+manualID+"/details", lead,
		`{"title":"IDOR on /api/orders/{id}","impact":"","references":["https://example.com/a","  "]}`)
	meta, _ = edited["metadata"].(map[string]any)
	if resp.StatusCode != http.StatusOK || edited["title"] != "IDOR on /api/orders/{id}" || meta["references"] != "https://example.com/a" {
		t.Fatalf("edit write-up = %d %v", resp.StatusCode, edited)
	}
	if _, ok := meta["impact"]; ok || meta["mitigation"] != "Check ownership server-side." {
		t.Errorf("cleared impact should drop, untouched mitigation stay: %v", meta)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings?scanner=trivy", lead, "")
	trivyID, _ := list["findings"].([]any)[0].(map[string]any)["id"].(string)
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+trivyID+"/details", lead, `{"title":"x"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("editing a scanner finding's write-up = %d, want 409", resp.StatusCode)
	}

	// Report templates: admin-written; validated; rendered by anyone who can read the project.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/report-templates", lead, `{"name":"x","sections":["summary"]}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin creating a report template = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/report-templates", admin, `{"name":"x","sections":["summary"],"accent_color":"red;}body{"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("CSS-injecting accent colour = %d, want 400", resp.StatusCode)
	}
	resp, rt := req(t, app, http.MethodPost, "/api/v1/report-templates", admin,
		`{"name":"Pentest deliverable","brand":"Acme Offensive Security","classification":"Confidential",
		  "intro":"Scope: shop.example.com","accent_color":"#7c3aed","sections":["details","findings"],"min_severity":"high"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create report template = %d %v", resp.StatusCode, rt)
	}
	rtID, _ := rt["id"].(string)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+pid+"/report?template="+rtID+"&engagement_id="+engID, nil)
	r.Header.Set("Authorization", "Bearer "+viewer)
	res, err := app.Test(r, -1)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("engagement report = %v %v", res.StatusCode, err)
	}
	raw, _ := io.ReadAll(res.Body)
	html := string(raw)
	for _, want := range []string{"Acme Offensive Security", "Confidential", "Scope: shop.example.com", "Engagement: <strong>Q3 pentest</strong>",
		"IDOR on /api/orders/{id}", "Steps to reproduce", "Check ownership server-side.", "#7c3aed"} {
		if !strings.Contains(html, want) {
			t.Errorf("engagement report lacks %q", want)
		}
	}
	if strings.Contains(html, "Verbose errors") {
		t.Error("engagement report lists a finding outside the engagement")
	}
	if strings.Contains(html, "Compliance posture") {
		t.Error("report shows a section its template leaves out")
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "img-src data:") || strings.Contains(csp, "script") {
		t.Errorf("report CSP = %q", csp)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/report?engagement_id="+otherEngID, lead, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("report for another project's engagement = %d, want 400", resp.StatusCode)
	}

	// Archiving the engagement keeps its scans and findings.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/engagements/"+engID, lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete engagement = %d", resp.StatusCode)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+manualID, lead, ""); f["status"] != "open" {
		t.Errorf("manual finding after its engagement was deleted = %v", f)
	}
	if _, scans := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/scans", lead, ""); len(scans["scans"].([]any)) < 2 {
		t.Errorf("scans after deleting the engagement = %v", scans["scans"])
	}
}
