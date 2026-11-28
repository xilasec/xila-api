package server

import (
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// projectFindingIDs returns the project's finding ids as lead sees them.
func projectFindingIDs(t *testing.T, app *fiber.App, token, projectID string) []string {
	t.Helper()
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", token, "")
	var ids []string
	fs, _ := list["findings"].([]any)
	for _, f := range fs {
		ids = append(ids, f.(map[string]any)["id"].(string))
	}
	return ids
}

// M13 13.2: a manual verdict carries a structured analysis, kept in the
// finding's history and cleared when the verdict no longer applies.
func TestStructuredAnalysisOnManualTriage(t *testing.T) {
	app := newTestApp(t)
	lead := rbacUser(t, app, "lead@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", lead, `{"slug":"alpha","name":"alpha"}`)
	projectID := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", lead, smokeTrivyReport)
	id := projectFindingIDs(t, app, lead, projectID)[0]

	for _, bad := range []string{
		`{"status":"false_positive","vex_justification":"because"}`,
		`{"status":"false_positive","vex_response":["shrug"]}`,
	} {
		if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+id, lead, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PATCH %s = %d, want 400", bad, resp.StatusCode)
		}
	}
	resp, f := req(t, app, http.MethodPatch, "/api/v1/findings/"+id, lead,
		`{"status":"false_positive","reason":"behind the gateway","vex_justification":"protected_at_perimeter","vex_response":["workaround_available"]}`)
	if resp.StatusCode != http.StatusOK || f["vex_justification"] != "protected_at_perimeter" {
		t.Fatalf("PATCH with analysis = %d %v", resp.StatusCode, f)
	}
	if r, _ := f["vex_response"].([]any); len(r) != 1 || r[0] != "workaround_available" {
		t.Errorf("vex_response = %v", f["vex_response"])
	}
	// Reopened, the analysis no longer describes anything.
	if _, f := req(t, app, http.MethodPatch, "/api/v1/findings/"+id, lead, `{"status":"open"}`); f["vex_justification"] != "" {
		t.Errorf("after reopen vex_justification = %v, want cleared", f["vex_justification"])
	}

	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+id+"/history", lead, "")
	var vex []string
	for _, raw := range hist["events"].([]any) {
		if e := raw.(map[string]any); e["kind"] == "vex" {
			to, _ := e["to"].(string)
			vex = append(vex, to)
		}
	}
	if len(vex) != 2 || vex[0] != "protected_at_perimeter [workaround_available]" || vex[1] != "" {
		t.Errorf("vex history = %q, want the analysis set then cleared", vex)
	}
}

// M13 13.9: a project's own approval setting and designated approvers. Only
// approvers who can still see the project decide, owners are narrowed out
// while approvers are designated, a project-scoped token decides only in its
// project, and none of it touches the risk-acceptance queue.
func TestAssessmentApprovers(t *testing.T) {
	app := newTestApp(t) // ASSESSMENT_REQUIRES_APPROVAL off: the project opts in
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
	for _, m := range []struct{ project, email, role string }{
		{alpha, "dana@xila.io", "editor"}, {alpha, "carol@xila.io", "viewer"}, {beta, "carol@xila.io", "viewer"},
	} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+m.project+"/members", lead,
			`{"email":"`+m.email+`","role":"`+m.role+`"}`); resp.StatusCode != http.StatusCreated {
			t.Fatalf("add %s = %d", m.email, resp.StatusCode)
		}
	}
	ids := projectFindingIDs(t, app, lead, alpha)
	carolID, eveID := userIDOf(t, app, admin, "carol@xila.io"), userIDOf(t, app, admin, "eve@xila.io")

	// The project opts in; the instance default stays off elsewhere.
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+alpha, lead, `{"assessment_approval":"sometimes"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid assessment_approval = %d, want 400", resp.StatusCode)
	}
	req(t, app, http.MethodPatch, "/api/v1/projects/"+alpha, lead, `{"assessment_approval":"required"}`)
	resp, a := req(t, app, http.MethodPatch, "/api/v1/findings/"+ids[0], dana, `{"status":"confirmed"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("PATCH on a required project = %d %v, want 202", resp.StatusCode, a)
	}
	first := a["id"].(string)

	// Approvers must be able to see the project; malformed ids are refused.
	approvers := "/api/v1/projects/" + alpha + "/assessment-approvers"
	for _, bad := range []string{`{"user_ids":["` + eveID + `"]}`, `{"user_ids":["nope"]}`, `{"group_ids":["` + carolID + `"]}`} {
		if resp, _ := req(t, app, http.MethodPut, approvers, lead, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("PUT approvers %s = %d, want 400", bad, resp.StatusCode)
		}
	}
	if resp, body := req(t, app, http.MethodPut, approvers, dana, `{"user_ids":["`+carolID+`"]}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor setting approvers = %d %v, want 403", resp.StatusCode, body)
	}
	if resp, body := req(t, app, http.MethodPut, approvers, lead, `{"user_ids":["`+carolID+`"]}`); resp.StatusCode != http.StatusOK || len(body["approvers"].([]any)) != 1 {
		t.Fatalf("PUT approvers = %d %v", resp.StatusCode, body)
	}

	actionable := func(token string) int {
		_, q := req(t, app, http.MethodGet, "/api/v1/assessments?actionable=true", token, "")
		as, _ := q["assessments"].([]any)
		return len(as)
	}
	// The owner is narrowed out; the designated viewer is in.
	if n := actionable(lead); n != 0 {
		t.Errorf("owner's actionable queue = %d, want 0 while approvers are designated", n)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/assessments/"+first+"/approve", lead, `{}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("owner approving = %d, want 403", resp.StatusCode)
	}
	if n := actionable(carol); n != 1 {
		t.Errorf("approver's actionable queue = %d, want 1", n)
	}

	// A token carol scoped to beta decides nothing in alpha.
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", carol, `{"name":"ci","project_id":"`+beta+`"}`)
	betaToken, _ := tok["secret"].(string)
	if betaToken == "" {
		t.Fatalf("beta token = %v", tok)
	}
	resp, body := req(t, app, http.MethodPost, "/api/v1/assessments/approve", betaToken, `{"ids":["`+first+`"]}`)
	if approved, _ := body["approved"].([]any); resp.StatusCode == http.StatusOK && len(approved) != 0 {
		t.Errorf("beta-scoped token approved an alpha assessment: %v", body)
	}
	t.Logf("beta-scoped token bulk approve = %d %v", resp.StatusCode, body)

	// Removed from the project, carol decides nothing there, even in bulk
	// (where the middleware can't check), and learns nothing about the id.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+alpha+"/members/"+carolID, lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove carol = %d", resp.StatusCode)
	}
	_, body = req(t, app, http.MethodPost, "/api/v1/assessments/approve", carol, `{"ids":["`+first+`"]}`)
	failed, _ := body["failed"].([]any)
	if len(body["approved"].([]any)) != 0 || len(failed) != 1 || failed[0].(map[string]any)["error"] != "assessment not found" {
		t.Errorf("revoked approver bulk approve = %v, want refused as not found", body)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+ids[0], lead, ""); f["status"] != "open" {
		t.Errorf("finding = %v after refused approvals, want open", f["status"])
	}

	// Back on the project, carol approves.
	req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/members", lead, `{"email":"carol@xila.io","role":"viewer"}`)
	if resp, body := req(t, app, http.MethodPost, "/api/v1/assessments/"+first+"/approve", carol, `{}`); resp.StatusCode != http.StatusOK {
		t.Errorf("approver approve = %d %v", resp.StatusCode, body)
	}

	// Risk acceptances keep their own rule: the owner decides them.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/risk-acceptances", dana,
		`{"title":"WAF","justification":"virtual patch","finding_ids":["`+ids[1]+`"]}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("risk acceptance request = %d", resp.StatusCode)
	}
	for who, want := range map[string]int{lead: 1, carol: 0} {
		_, q := req(t, app, http.MethodGet, "/api/v1/risk-acceptances?actionable=true", who, "")
		if got := len(q["risk_acceptances"].([]any)); got != want {
			t.Errorf("risk-acceptance queue for %s = %d, want %d", who[:8], got, want)
		}
	}

	// Clearing the approvers restores the owner.
	req(t, app, http.MethodPut, approvers, lead, `{"user_ids":[],"group_ids":[]}`)
	_, a = req(t, app, http.MethodPatch, "/api/v1/findings/"+ids[0], dana, `{"status":"open"}`)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/assessments/"+a["id"].(string)+"/approve", lead, `{}`); resp.StatusCode != http.StatusOK {
		t.Errorf("owner approve after clearing approvers = %d", resp.StatusCode)
	}
}
