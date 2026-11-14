package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// reqIfMatch is req with an If-Match header.
func reqIfMatch(t *testing.T, app *fiber.App, method, path, token, ifMatch, body string) int {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"`+ifMatch+`"`)
	res, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode
}

// A person's title / severity edit of a scanner finding survives the next
// scan until reset; priority is recomputed from every input; a stale If-Match
// is refused with 412; the planned date round-trips; GET links file:line into
// the repository at the scanned commit; a viewer can't edit.
func TestFindingFieldEdits(t *testing.T) {
	app := newTestApp(t)
	lead := rbacUser(t, app, "founder@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead,
		`{"slug":"web","name":"web","repo_url":"https://github.com/acme/web.git"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"viewer@xila.io","role":"viewer"}`)
	const sha = "4f9c2d1e8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e"
	const semgrep = `{"results":[{"check_id":"go.lang.security.audit.sqli","path":"./internal/db/query.go","start":{"line":42},"end":{"line":42},
		"extra":{"message":"SQL built from user input","severity":"WARNING","metadata":{"cwe":["CWE-89"]}}}]}`
	upload := func() {
		t.Helper()
		if res, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=semgrep&commit="+sha, lead, semgrep); res.StatusCode != http.StatusCreated {
			t.Fatalf("upload: %d %v", res.StatusCode, body)
		}
	}
	upload()
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", lead, "")
	f := list["findings"].([]any)[0].(map[string]any)
	id, scannerTitle, scannerSeverity := f["id"].(string), f["title"].(string), f["severity"].(string)

	_, got := req(t, app, http.MethodGet, "/api/v1/findings/"+id, lead, "")
	if got["source_url"] != "https://github.com/acme/web/blob/"+sha+"/internal/db/query.go#L42" {
		t.Errorf("source_url = %v", got["source_url"])
	}

	if res, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+id+"/fields", viewer, `{"severity":"critical"}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer edit = %d, want 403", res.StatusCode)
	}
	res, got := req(t, app, http.MethodPatch, "/api/v1/findings/"+id+"/fields", lead,
		`{"title":"SQL injection in report export","severity":"critical","planned_remediation_at":"2026-12-15"}`)
	if res.StatusCode != http.StatusOK || got["title"] != "SQL injection in report export" || got["severity"] != "critical" ||
		got["severity_manual"] != true || got["title_manual"] != true || !strings.HasPrefix(got["planned_remediation_at"].(string), "2026-12-15") {
		t.Fatalf("edit: %d %v", res.StatusCode, got)
	}
	if got["priority"].(float64) != 15 {
		t.Errorf("priority after severity → critical = %v, want 15", got["priority"])
	}

	// The next scan keeps the person's values.
	upload()
	_, got = req(t, app, http.MethodGet, "/api/v1/findings/"+id, lead, "")
	if got["title"] != "SQL injection in report export" || got["severity"] != "critical" {
		t.Errorf("a re-scan overwrote the edit: %v / %v", got["title"], got["severity"])
	}

	// If-Match: a stale version is refused with the current finding; the
	// current one goes through — on this endpoint and on tags.
	stale := "2020-01-01T00:00:00Z"
	if code := reqIfMatch(t, app, http.MethodPatch, "/api/v1/findings/"+id+"/fields", lead, stale, `{"severity":"low"}`); code != http.StatusPreconditionFailed {
		t.Errorf("stale If-Match on fields = %d, want 412", code)
	}
	if code := reqIfMatch(t, app, http.MethodPut, "/api/v1/findings/"+id+"/tags", lead, stale, `{"tags":["x"]}`); code != http.StatusPreconditionFailed {
		t.Errorf("stale If-Match on tags = %d, want 412", code)
	}
	if code := reqIfMatch(t, app, http.MethodPut, "/api/v1/findings/"+id+"/tags", lead, got["updated_at"].(string), `{"tags":["pci"]}`); code != http.StatusOK {
		t.Errorf("current If-Match on tags = %d, want 200", code)
	}

	// Reset: the scanner's values return with the next scan; clear the date.
	res, got = req(t, app, http.MethodPatch, "/api/v1/findings/"+id+"/fields", lead,
		`{"reset_title":true,"reset_severity":true,"planned_remediation_at":null}`)
	if res.StatusCode != http.StatusOK || got["severity_manual"] != false || got["planned_remediation_at"] != nil {
		t.Fatalf("reset: %d %v", res.StatusCode, got)
	}
	upload()
	_, got = req(t, app, http.MethodGet, "/api/v1/findings/"+id, lead, "")
	if got["title"] != scannerTitle || got["severity"] != scannerSeverity {
		t.Errorf("after reset + scan = %v / %v, want the scanner's %v / %v", got["title"], got["severity"], scannerTitle, scannerSeverity)
	}

	if res, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+id+"/fields", lead, `{"title":"x","reset_title":true}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("set + reset = %d, want 400", res.StatusCode)
	}
}
