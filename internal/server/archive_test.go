package server

import (
	"net/http"
	"testing"
)

// Archive instead of delete over HTTP: an archived project vanishes from the
// lists, the summary and the portfolio and comes back intact; archiving needs
// owner (a project) or editor (a finding), restoring owner, purging an
// instance admin.
func TestArchiveRBAC(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", admin, `{"email":"lead@xila.io","role":"owner"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", admin, `{"email":"editor@xila.io","role":"editor"}`)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %d", resp.StatusCode)
	}

	count := func(path, key, token string) int {
		t.Helper()
		resp, body := req(t, app, http.MethodGet, path, token, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, resp.StatusCode)
		}
		return len(body[key].([]any))
	}
	_, sum := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/summary", lead, "")
	openBefore := sum["total_open"]
	if openBefore == float64(0) {
		t.Fatal("summary has nothing open before archiving")
	}

	// Archiving a project is owner-level; purging is admin-only.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+pid, editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor archives project = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+pid+"?purge=true", lead, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("owner purges project = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+pid, lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("owner archives project = %d", resp.StatusCode)
	}

	// Gone from lists, summary, portfolio and the findings inbox.
	if n := count("/api/v1/projects", "projects", lead); n != 0 {
		t.Errorf("projects list after archive = %d, want 0", n)
	}
	if n := count("/api/v1/findings", "findings", lead); n != 0 {
		t.Errorf("findings inbox after archive = %d, want 0", n)
	}
	if _, s := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/summary", lead, ""); s["total_open"] != float64(0) {
		t.Errorf("summary of archived project = %v, want 0 open", s["total_open"])
	}
	if _, pf := req(t, app, http.MethodGet, "/api/v1/portfolio", admin, ""); pf["projects"] != float64(0) || pf["total_open"] != float64(0) {
		t.Errorf("portfolio after archive = %v projects / %v open, want 0 / 0", pf["projects"], pf["total_open"])
	}
	// The archived tab: the owner sees it, the editor (not an owner) doesn't.
	if n := count("/api/v1/projects?archived=true", "projects", lead); n != 1 {
		t.Errorf("owner's archived projects = %d, want 1", n)
	}
	if n := count("/api/v1/projects?archived=true", "projects", editor); n != 0 {
		t.Errorf("editor's archived projects = %d, want 0", n)
	}
	if _, got := req(t, app, http.MethodGet, "/api/v1/projects/"+pid, lead, ""); got["archived_at"] == nil {
		t.Error("archived project has no archived_at")
	}

	// Restore is owner-level and brings everything back intact.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/restore", editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor restores project = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/restore", lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("owner restores project = %d", resp.StatusCode)
	}
	if n := count("/api/v1/projects", "projects", lead); n != 1 {
		t.Errorf("projects list after restore = %d, want 1", n)
	}
	if _, s := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/summary", lead, ""); s["total_open"] != openBefore {
		t.Errorf("summary after restore = %v open, want %v", s["total_open"], openBefore)
	}

	// A finding: editor archives, owner restores, admin purges.
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", lead, "")
	fid := list["findings"].([]any)[0].(map[string]any)["id"].(string)
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/findings/"+fid, editor, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("editor archives finding = %d", resp.StatusCode)
	}
	if n := count("/api/v1/projects/"+pid+"/findings?archived=true", "findings", lead); n != 1 {
		t.Errorf("archived findings = %d, want 1", n)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/findings/"+fid+"/restore", editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor restores finding = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/findings/"+fid+"/restore", lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("owner restores finding = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/findings/"+fid+"?purge=true", lead, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("owner purges finding = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/findings/"+fid+"?purge=true", admin, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("admin purges finding = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, admin, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("purged finding = %d, want 404", resp.StatusCode)
	}
}
