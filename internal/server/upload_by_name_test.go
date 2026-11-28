package server

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// projectsNamed counts the live projects of the team named name.
func projectsNamed(t *testing.T, app *fiber.App, token, teamID, name string) int {
	t.Helper()
	_, list := req(t, app, http.MethodGet, "/api/v1/projects?team_id="+teamID, token, "")
	n := 0
	ps, _ := list["projects"].([]any)
	for _, p := range ps {
		if p.(map[string]any)["slug"] == name {
			n++
		}
	}
	return n
}

// Uploads by project name (M13 13.3): no project id in the path, so the
// handler itself must enforce what authz.Middleware would.
func TestUploadByProjectName(t *testing.T) {
	app := newTestApp(t)
	owner := rbacUser(t, app, "owner@xila.io")
	editor := rbacUser(t, app, "dev@xila.io")
	uploader := rbacUser(t, app, "ci@xila.io")
	outsider := rbacUser(t, app, "eve@xila.io")

	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", owner, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", owner, `{"slug":"core","name":"Core"}`)
	teamID := team["id"].(string)
	_, web := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", owner, `{"slug":"web","name":"Web"}`)
	webID := web["id"].(string)
	for who, role := range map[string]string{"dev@xila.io": "editor", "ci@xila.io": "uploader"} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/members", owner,
			`{"email":"`+who+`","role":"`+role+`"}`); resp.StatusCode != http.StatusCreated {
			t.Fatalf("add %s = %d", who, resp.StatusCode)
		}
	}
	xml, err := os.ReadFile("../sbom/testdata/valid-bom-1.6.cdx.xml")
	if err != nil {
		t.Fatal(err)
	}

	// An uploader uploads by name, within the team and without one; XML too.
	resp, s := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web&team=core", uploader, string(xml))
	if resp.StatusCode != http.StatusCreated || s["project_id"] != webID {
		t.Fatalf("upload by name = %d %v", resp.StatusCode, s)
	}
	if resp, s := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=WEB", uploader, cyclonedxExpress("")); resp.StatusCode != http.StatusCreated || s["project_id"] != webID {
		t.Errorf("upload by name, no team, other case = %d %v", resp.StatusCode, s)
	}
	if resp, sc := req(t, app, http.MethodPost, "/api/v1/scans?project_name=web&team=core&scanner=sarif&format=sarif", uploader,
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[]}]}`); resp.StatusCode != http.StatusCreated || sc["project_id"] != webID {
		t.Errorf("scan by name = %d %v", resp.StatusCode, sc)
	}

	// The upload's processing finishes and says so.
	var status map[string]any
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var r *http.Response
		r, status = req(t, app, http.MethodGet, "/api/v1/sboms/"+s["id"].(string)+"/status", uploader, "")
		if r.StatusCode != http.StatusOK {
			t.Fatalf("status = %d %v", r.StatusCode, status)
		}
		if status["status"] == "completed" || status["status"] == "failed" {
			break
		}
	}
	if status["status"] != "completed" {
		t.Errorf("processing = %v, want completed", status)
	}

	// Creating needs team editor; an uploader can't, and nothing is created.
	if resp, p := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=api&team=core&auto_create=true", editor, cyclonedxExpress("")); resp.StatusCode != http.StatusCreated {
		t.Fatalf("editor auto-create = %d %v", resp.StatusCode, p)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=api&team=core&auto_create=true", editor, cyclonedxExpress("")); resp.StatusCode != http.StatusCreated || projectsNamed(t, app, owner, teamID, "api") != 1 {
		t.Errorf("auto-create again = %d, want 201 into the same project", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=svc&team=core&auto_create=true", uploader, cyclonedxExpress("")); resp.StatusCode != http.StatusForbidden || projectsNamed(t, app, owner, teamID, "svc") != 0 {
		t.Errorf("uploader auto-create = %d, want 403 and no project", resp.StatusCode)
	}

	// A project-scoped token stays in its project: it can't create one (not
	// even as a team editor), nor upload into another by name.
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", editor, `{"name":"ci","project_id":"`+webID+`"}`)
	scoped, _ := tok["secret"].(string)
	if scoped == "" {
		t.Fatalf("project-scoped token = %v", tok)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=batch&team=core&auto_create=true", scoped, cyclonedxExpress("")); resp.StatusCode != http.StatusForbidden || projectsNamed(t, app, owner, teamID, "batch") != 0 {
		t.Errorf("scoped token auto-create = %d, want 403 and no project", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=api&team=core", scoped, cyclonedxExpress("")); resp.StatusCode != http.StatusForbidden {
		t.Errorf("scoped token into another project = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web&team=core", scoped, cyclonedxExpress("")); resp.StatusCode != http.StatusCreated {
		t.Errorf("scoped token into its project = %d, want 201", resp.StatusCode)
	}

	// Someone outside the team sees nothing: not found, never forbidden.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web", outsider, cyclonedxExpress("")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("outsider by name = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web&team=core", outsider, cyclonedxExpress("")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("outsider with an invisible team = %d, want 400 (team not found)", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=nope", uploader, cyclonedxExpress("")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown project = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web&auto_create=true", editor, cyclonedxExpress("")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("auto_create without team = %d, want 400", resp.StatusCode)
	}

	// An archived project takes no uploads by name, and its name isn't
	// silently reused.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+webID, owner, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("archive web = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web&team=core", uploader, cyclonedxExpress("")); resp.StatusCode != http.StatusNotFound {
		t.Errorf("upload into archived project = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sboms?project_name=web&team=core&auto_create=true", editor, cyclonedxExpress("")); resp.StatusCode != http.StatusConflict {
		t.Errorf("auto-create over an archived name = %d, want 409", resp.StatusCode)
	}
}
