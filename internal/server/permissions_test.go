package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The permission audit is instance-admin only; a project's access list is for
// its owners (not editors, not owners of another project); the export is a
// CSV with one row per contributing grant.
func TestPermissionAuditRBAC(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"web","name":"web"}`)
	web, _ := p["id"].(string)
	_, p = req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"api","name":"api"}`)
	api, _ := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", admin, `{"email":"lead@xila.io","role":"owner"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", admin, `{"email":"editor@xila.io","role":"editor"}`)

	for _, tok := range []string{lead, editor} {
		if res, _ := req(t, app, http.MethodGet, "/api/v1/permissions", tok, ""); res.StatusCode != http.StatusForbidden {
			t.Errorf("non-admin GET /permissions = %d, want 403", res.StatusCode)
		}
	}
	res, body := req(t, app, http.MethodGet, "/api/v1/permissions?user=lead@", admin, "")
	entries, _ := body["entries"].([]any)
	if res.StatusCode != http.StatusOK || len(entries) != 1 {
		t.Fatalf("admin audit for lead: %d %v", res.StatusCode, body)
	}
	if e := entries[0].(map[string]any); e["effective_role"] != "owner" || e["project_id"] != web {
		t.Errorf("lead's entry = %v", e)
	}
	if res, _ := req(t, app, http.MethodGet, "/api/v1/permissions?role=boss", admin, ""); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad role filter = %d", res.StatusCode)
	}

	// The project owner sees who reaches web: the instance admin, lead, editor.
	res, body = req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/access", lead, "")
	entries, _ = body["entries"].([]any)
	if res.StatusCode != http.StatusOK || len(entries) != 3 {
		t.Fatalf("owner's access list: %d %v", res.StatusCode, body)
	}
	if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/access", editor, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("editor GET access = %d, want 403", res.StatusCode)
	}
	if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+api+"/access", lead, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("owner of web reading api's access = %d, want 403", res.StatusCode)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/permissions/export?format=csv&project_id="+web, nil)
	r.Header.Set("Authorization", "Bearer "+admin)
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	csv, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(csv)), "\n")
	// One row per contributing grant: editor 1, lead 1, founder 3 (instance
	// admin, org admin, team owner), plus the header.
	if resp.StatusCode != http.StatusOK || len(lines) != 6 || !strings.HasPrefix(lines[0], "principal,") ||
		!strings.Contains(string(csv), "founder@xila.io,user,false,Acme,Core,web,"+web+",admin,org_admin,owner,manual,Acme") ||
		!strings.Contains(string(csv), "lead@xila.io,user,false,Acme,Core,web,"+web+",owner,project,owner,manual") {
		t.Errorf("export (%d):\n%s", resp.StatusCode, csv)
	}
}
