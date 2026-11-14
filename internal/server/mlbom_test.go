package server

import (
	"net/http"
	"os"
	"testing"
)

// The AI inventory over HTTP: an editor uploads an ML-BOM, the AI inventory
// (?kind=ai) lists its model with the model card; a non-member can't read the
// project's inventory and the cross-project search hides it from them; and an
// approved-models policy flags the model.
func TestAIInventoryRBAC(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	carol := rbacUser(t, app, "carol@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", bob, `{"slug":"ml-org","name":"ML"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", bob, `{"slug":"ml","name":"ML"}`)
	teamID, _ := teamBody["id"].(string)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", bob, `{"slug":"chat","name":"Chat"}`)
	projID, _ := projBody["id"].(string)
	if projID == "" {
		t.Fatal("bob could not create the project")
	}

	bom, err := os.ReadFile("../sbom/testdata/mlbom-app.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+projID+"/sboms", bob, string(bom)); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload ML-BOM = %d: %v", resp.StatusCode, body)
	}

	path := "/api/v1/projects/" + projID + "/components?latest=true&kind=model"
	resp, body := req(t, app, http.MethodGet, path, bob, "")
	comps, _ := body["components"].([]any)
	if resp.StatusCode != http.StatusOK || len(comps) != 1 {
		t.Fatalf("bob GET models = %d %v, want the one model", resp.StatusCode, body)
	}
	model := comps[0].(map[string]any)
	ml, _ := model["ml"].(map[string]any)
	if model["kind"] != "model" || model["name"] != "Mistral-7B-Instruct-v0.2" || ml["task"] != "text-generation" || ml["supplier"] != "Hugging Face" {
		t.Errorf("model = %v", model)
	}

	// Carol is no member: the project's inventory is forbidden, and the
	// portfolio search shows her no AI component.
	if resp, _ := req(t, app, http.MethodGet, path, carol, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol GET project models = %d, want 403", resp.StatusCode)
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/components?kind=ai", carol, ""); len(body["components"].([]any)) != 0 {
		t.Errorf("carol's AI inventory = %v, want none", body["components"])
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/components?kind=ai", bob, ""); len(body["components"].([]any)) != 4 {
		t.Errorf("bob's AI inventory = %d, want 4 (model, dataset, 2 AI services)", len(body["components"].([]any)))
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/components?kind=llm", bob, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown kind = %d, want 400", resp.StatusCode)
	}

	// Policies are admin-managed: an approved-models list flags the model and
	// the OpenAI service, neither of which is approved.
	policy := `{"name":"Approved models","operator":"any","violation_state":"fail","scope":"global","versions":"all","enabled":true,
		"conditions":[{"subject":"model.name","operator":"no_match","value":["google/flan-t5-*"]}]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies", bob, policy); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob create policy = %d, want 403", resp.StatusCode)
	}
	if resp, body := req(t, app, http.MethodPost, "/api/v1/policies/preview", admin, policy); resp.StatusCode != http.StatusOK || body["total"] != float64(3) {
		t.Errorf("preview = %d %v, want 3 violations (model, two AI services)", resp.StatusCode, body["total"])
	}
}
