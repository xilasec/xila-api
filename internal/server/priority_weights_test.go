package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/pgtest"
)

// Per-project priority weights: an owner sets them, the project's findings
// are re-ranked at once and new ones are scored with them; an editor can't,
// an override that breaks an invariant is refused, and a reset goes back to
// the defaults. Another project is untouched.
func TestProjectPriorityWeights(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool)
	lead := rbacUser(t, app, "lead@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")
	_, o := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, tm := req(t, app, http.MethodPost, "/api/v1/orgs/"+o["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	project := func(slug string) string {
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+tm["id"].(string)+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		pid := p["id"].(string)
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
			t.Fatalf("scan = %d", resp.StatusCode)
		}
		return pid
	}
	web, other := project("web"), project("other")
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", lead, `{"email":"editor@xila.io","role":"editor"}`)

	// Priority of each finding by severity.
	prios := func(pid string) map[string]float64 {
		t.Helper()
		_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", lead, "")
		out := map[string]float64{}
		for _, f := range list["findings"].([]any) {
			m := f.(map[string]any)
			out[m["severity"].(string)] = m["priority"].(float64)
		}
		return out
	}
	before := prios(web)
	if before["critical"] != 15 {
		t.Fatalf("default critical priority = %v, want 15", before)
	}

	path := "/api/v1/projects/" + web + "/priority-weights"
	if resp, _ := req(t, app, http.MethodPut, path, editor, `{"critical": 30}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor setting weights = %d, want 403", resp.StatusCode)
	}
	resp, body := req(t, app, http.MethodPut, path, lead, `{"dev": 1.5}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body["error"].(string), "dev") {
		t.Errorf("a discount above 1 = %d %v, want 400 naming dev", resp.StatusCode, body)
	}
	if resp, _ := req(t, app, http.MethodPut, path, lead, `{"criticl": 30}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a misspelled factor = %d, want 400", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodPut, path, lead, `{"critical": 30, "high": 10}`)
	if resp.StatusCode != http.StatusOK || body["custom"] != true || body["reprioritized"] == float64(0) {
		t.Fatalf("set weights = %d %v", resp.StatusCode, body)
	}
	after := prios(web)
	if after["critical"] != 30 {
		t.Errorf("critical after critical: 30 = %v, want 30", after["critical"])
	}
	if p, ok := after["high"]; ok && p != 10 {
		t.Errorf("high after high: 10 = %v, want 10", p)
	}
	if prios(other)["critical"] != 15 {
		t.Errorf("another project changed: %v", prios(other))
	}

	// New findings start with the project's weights: a project that set them
	// before its first scan.
	_, fresh := req(t, app, http.MethodPost, "/api/v1/teams/"+tm["id"].(string)+"/projects", lead, `{"slug":"fresh","name":"fresh"}`)
	freshID := fresh["id"].(string)
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/projects/"+freshID+"/priority-weights", lead, `{"critical": 40}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("set weights on an empty project = %d", resp.StatusCode)
	}
	req(t, app, http.MethodPost, "/api/v1/projects/"+freshID+"/scans?scanner=trivy", lead, smokeTrivyReport)
	if p := prios(freshID)["critical"]; p != 40 {
		t.Errorf("a new critical in a project with critical: 40 = %v, want 40", p)
	}

	resp, body = req(t, app, http.MethodDelete, path, lead, "")
	if resp.StatusCode != http.StatusOK || body["custom"] != false || prios(web)["critical"] != 15 {
		t.Errorf("reset = %d %v, priorities %v", resp.StatusCode, body, prios(web))
	}
}
