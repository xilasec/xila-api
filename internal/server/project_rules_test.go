package server

import (
	"net/http"
	"slices"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// findingTags returns a finding's tags as lead sees them.
func findingTags(t *testing.T, app *fiber.App, token, id string) []string {
	t.Helper()
	_, f := req(t, app, http.MethodGet, "/api/v1/findings/"+id, token, "")
	var tags []string
	for _, v := range f["tags"].([]any) {
		tags = append(tags, v.(string))
	}
	return tags
}

// M13 13.5 + 13.10: a project owner's own rules, their side actions, the
// finding-event trigger, and the opt-out of global rules and policies.
func TestProjectOwnedRules(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	dana := rbacUser(t, app, "dana@xila.io")
	carol := rbacUser(t, app, "carol@xila.io")
	rbacUser(t, app, "eve@xila.io")

	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID := team["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"alpha","name":"alpha"}`)
	alpha := p["id"].(string)
	_, p = req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"beta","name":"beta"}`)
	beta := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/scans?scanner=trivy", lead, smokeTrivyReport)
	req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/members", lead, `{"email":"dana@xila.io","role":"editor"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/members", lead, `{"email":"carol@xila.io","role":"viewer"}`)
	ids := projectFindingIDs(t, app, lead, alpha)
	danaID, eveID := userIDOf(t, app, admin, "dana@xila.io"), userIDOf(t, app, admin, "eve@xila.io")
	rules := "/api/v1/projects/" + alpha + "/triage-rules"

	// Owner-level: an editor can't add one, a viewer can read them.
	sideOnly := `{"name":"route","enabled":true,"action":"none","assign_user_id":"` + danaID +
		`","add_tags":["routed"],"comment":"Routed to the app team","notify":true}`
	if resp, _ := req(t, app, http.MethodPost, rules, dana, sideOnly); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor creating a project rule = %d, want 403", resp.StatusCode)
	}
	for _, bad := range []string{
		`{"name":"x","enabled":true,"action":"none"}`,                                  // none needs a side action
		`{"name":"x","enabled":true,"action":"none","assign_user_id":"` + eveID + `"}`, // can't see alpha
	} {
		if resp, body := req(t, app, http.MethodPost, rules, lead, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST %s = %d %v, want 400", bad, resp.StatusCode, body)
		}
	}
	resp, rule := req(t, app, http.MethodPost, rules, lead, sideOnly)
	if resp.StatusCode != http.StatusCreated || rule["project_id"] != alpha || rule["only_if_unassigned"] != true {
		t.Fatalf("owner creating a rule = %d %v", resp.StatusCode, rule)
	}
	ruleID := rule["id"].(string)
	if _, list := req(t, app, http.MethodGet, rules, carol, ""); len(list["rules"].([]any)) != 1 {
		t.Errorf("viewer's list = %v", list)
	}
	// The rule is alpha's: not reachable through beta's path.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+beta+"/triage-rules/"+ruleID, lead, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another project's rule through beta = %d, want 404", resp.StatusCode)
	}

	// Applying assigns, tags, comments and notifies; a second run posts no
	// second comment.
	for range 2 {
		if resp, _ := req(t, app, http.MethodPost, rules+"/apply", lead, ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("apply = %d", resp.StatusCode)
		}
	}
	_, f := req(t, app, http.MethodGet, "/api/v1/findings/"+ids[0], lead, "")
	if f["assignee_id"] != danaID || !slices.Contains(findingTags(t, app, lead, ids[0]), "routed") || f["status"] != "open" {
		t.Errorf("after the rule: assignee %v tags %v status %v", f["assignee_id"], f["tags"], f["status"])
	}
	_, cs := req(t, app, http.MethodGet, "/api/v1/findings/"+ids[0]+"/comments", lead, "")
	if n := len(cs["comments"].([]any)); n != 1 {
		t.Errorf("comments after two runs = %d, want 1", n)
	}

	// A person's decision sets off the rules (the finding-event trigger).
	req(t, app, http.MethodPost, rules, lead,
		`{"name":"confirmed","enabled":true,"action":"none","expression":"finding.status == 'confirmed'","add_tags":["confirmed-by-analyst"],"sort_order":-2,"continue":true}`)
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+ids[1], dana, `{"status":"confirmed"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("confirm = %d", resp.StatusCode)
	}
	if tags := findingTags(t, app, lead, ids[1]); !slices.Contains(tags, "confirmed-by-analyst") {
		t.Errorf("tags after a person confirmed it = %v, want the rule's", tags)
	}

	// Opting out of global rules needs an admin's permission, and stops
	// counting when it's withdrawn.
	req(t, app, http.MethodPost, "/api/v1/triage-rules", admin, `{"name":"global","enabled":true,"action":"none","add_tags":["global"],"sort_order":-1,"continue":true}`)
	settings := "/api/v1/projects/" + alpha + "/triage-settings"
	if resp, _ := req(t, app, http.MethodPut, settings, lead, `{"skip_global_rules":true}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("opting out while not allowed = %d, want 403", resp.StatusCode)
	}
	req(t, app, http.MethodPut, "/api/v1/triage-rules/settings", admin, `{"allow_skip_global_rules":true}`)
	if resp, s := req(t, app, http.MethodPut, settings, lead, `{"skip_global_rules":true}`); resp.StatusCode != http.StatusOK || s["skip_global_rules"] != true {
		t.Fatalf("opting out = %d %v", resp.StatusCode, s)
	}
	req(t, app, http.MethodPost, rules+"/apply", lead, "")
	if slices.Contains(findingTags(t, app, lead, ids[0]), "global") {
		t.Error("an opted-out project got a global rule's tag")
	}
	req(t, app, http.MethodPut, "/api/v1/triage-rules/settings", admin, `{"allow_skip_global_rules":false}`)
	req(t, app, http.MethodPost, rules+"/apply", lead, "")
	if !slices.Contains(findingTags(t, app, lead, ids[0]), "global") {
		t.Error("a withdrawn permission must make the opt-out stop counting")
	}

	// Vulnerability policies: pinned to the project, outside the GitOps bundle.
	policies := "/api/v1/projects/" + alpha + "/vuln-policies"
	body := `{"name":"owned","enabled":true,"condition":"true","scope":"global","mode":"log","analysis":{"state":"in_triage"}}`
	if resp, _ := req(t, app, http.MethodPost, policies, dana, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor creating a project policy = %d, want 403", resp.StatusCode)
	}
	resp, pol := req(t, app, http.MethodPost, policies, lead, body)
	if resp.StatusCode != http.StatusCreated || pol["scope"] != "projects" || pol["owner_project_id"] != alpha {
		t.Fatalf("owner creating a policy = %d %v, want it pinned to alpha", resp.StatusCode, pol)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/vuln-policies/bundle", admin, `{"policies":[]}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("bundle import = %d", resp.StatusCode)
	}
	if _, list := req(t, app, http.MethodGet, policies, lead, ""); len(list["policies"].([]any)) != 1 {
		t.Errorf("an empty bundle import removed the project's own policy: %v", list)
	}
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/vuln-policies/"+pol["id"].(string), admin,
		`{"name":"owned","enabled":true,"condition":"true","scope":"global","mode":"log","analysis":{"state":"in_triage"}}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin edit = %d", resp.StatusCode)
	}
	if _, got := req(t, app, http.MethodGet, "/api/v1/vuln-policies/"+pol["id"].(string), admin, ""); got["scope"] != "projects" {
		t.Errorf("an admin edit turned a project's policy %v", got["scope"])
	}
}
