package server

import (
	"net/http"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/config"
)

// With ASSESSMENT_REQUIRES_APPROVAL an analyst's status / severity change is
// held until a different project owner (or instance admin) approves it, and
// the finding history shows both who asked and who approved.
func TestAssessmentApprovalWorkflow(t *testing.T) {
	app := newTestApp(t, func(c *config.Config) { c.AssessmentRequiresApproval = true })
	admin := rbacUser(t, app, "founder@xila.io") // first user: instance admin
	lead := rbacUser(t, app, "lead@xila.io")
	dana := rbacUser(t, app, "dana@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"alpha","name":"alpha"}`)
	projectID, _ := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", lead, smokeTrivyReport)
	req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/members", lead, `{"email":"dana@xila.io","role":"editor"}`)
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", lead, "")
	fs, _ := list["findings"].([]any)
	if len(fs) != 2 {
		t.Fatalf("seed: %d findings, want 2", len(fs))
	}
	first, _ := fs[0].(map[string]any)["id"].(string)
	second, _ := fs[1].(map[string]any)["id"].(string)

	// An editor's status change is held, not applied.
	resp, a := req(t, app, http.MethodPatch, "/api/v1/findings/"+first, dana, `{"status":"false_positive","reason":"test fixture"}`)
	if resp.StatusCode != http.StatusAccepted || a["state"] != "pending" || a["requester"] != "dana@xila.io" {
		t.Fatalf("PATCH under approval = %d %v, want 202 pending", resp.StatusCode, a)
	}
	assessmentID, _ := a["id"].(string)
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+first, dana, ""); f["status"] != "open" {
		t.Fatalf("finding = %v while its change awaits approval, want open", f["status"])
	}
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+first, dana, `{"status":"confirmed"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("second pending request = %d, want 409", resp.StatusCode)
	}
	// Assignment is never gated.
	danaID := userIDOf(t, app, admin, "dana@xila.io")
	if resp, f := req(t, app, http.MethodPut, "/api/v1/findings/"+first+"/assignee", dana, `{"assignee_id":"`+danaID+`"}`); resp.StatusCode != http.StatusOK || f["assignee_email"] != "dana@xila.io" {
		t.Errorf("assign under approval = %d %v", resp.StatusCode, f["assignee_email"])
	}

	// The queue: visible to the project's members, not to outsiders; only an
	// owner who didn't ask may decide.
	_, q := req(t, app, http.MethodGet, "/api/v1/assessments?state=pending", lead, "")
	if as, _ := q["assessments"].([]any); len(as) != 1 || as[0].(map[string]any)["can_decide"] != true {
		t.Fatalf("lead's queue = %v, want one decidable", q["assessments"])
	}
	_, q = req(t, app, http.MethodGet, "/api/v1/assessments?state=pending", dana, "")
	if as, _ := q["assessments"].([]any); len(as) != 1 || as[0].(map[string]any)["can_decide"] != false {
		t.Errorf("dana's queue = %v, want her own request, not decidable", q["assessments"])
	}
	_, q = req(t, app, http.MethodGet, "/api/v1/assessments?state=pending", outsider, "")
	if as, _ := q["assessments"].([]any); len(as) != 0 {
		t.Errorf("outsider sees %d assessments, want 0", len(as))
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/assessments/"+assessmentID+"/approve", dana, `{}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("requester approving = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/assessments/"+assessmentID+"/approve", outsider, `{}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("outsider approving = %d, want 403", resp.StatusCode)
	}

	resp, approved := req(t, app, http.MethodPost, "/api/v1/assessments/"+assessmentID+"/approve", lead, `{"note":"agreed"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner approve = %d %v", resp.StatusCode, approved)
	}
	if f, _ := approved["finding"].(map[string]any); f["status"] != "false_positive" {
		t.Errorf("finding after approval = %v", f["status"])
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/assessments/"+assessmentID+"/reject", lead, `{}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("deciding twice = %d, want 409", resp.StatusCode)
	}
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+first+"/history", dana, "")
	var trail []string
	for _, raw := range hist["events"].([]any) {
		e := raw.(map[string]any)
		to, _ := e["to"].(string)
		trail = append(trail, e["kind"].(string)+":"+to+":"+e["actor_name"].(string))
	}
	want := "created:open:system,assessment:pending:dana@xila.io,assignee:dana@xila.io:dana@xila.io," +
		"status:false_positive:dana@xila.io,assessment:approved:lead@xila.io"
	if strings.Join(trail, ",") != want {
		t.Errorf("history = %v\nwant      %s", trail, want)
	}

	// The project owner is gated too, and can't approve their own request;
	// the instance admin may approve someone else's.
	resp, own := req(t, app, http.MethodPatch, "/api/v1/findings/"+second, lead, `{"status":"confirmed"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("owner PATCH = %d, want 202", resp.StatusCode)
	}
	ownID, _ := own["id"].(string)
	if resp, body := req(t, app, http.MethodPost, "/api/v1/assessments/"+ownID+"/approve", lead, `{}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("owner self-approval = %d %v, want 403", resp.StatusCode, body)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/assessments/"+ownID+"/reject", admin, `{"note":"not yet"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("admin reject = %d", resp.StatusCode)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+second, lead, ""); f["status"] != "open" {
		t.Errorf("rejected request changed the finding to %v", f["status"])
	}
	if _, list := req(t, app, http.MethodGet, "/api/v1/findings/"+second+"/assessments", dana, ""); len(list["assessments"].([]any)) != 1 {
		t.Errorf("finding assessments = %v", list["assessments"])
	}

	// Bulk: status / severity become pending; the response says so.
	resp, bulk := req(t, app, http.MethodPost, "/api/v1/findings/bulk", dana,
		`{"ids":["`+first+`","`+second+`"],"severity":"low","reason":"bulk"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("bulk under approval = %d %v", resp.StatusCode, bulk)
	}
	if pending, _ := bulk["pending"].([]any); len(pending) != 2 {
		t.Errorf("bulk pending = %v, want 2", bulk["pending"])
	}
	if updated, _ := bulk["updated"].([]any); len(updated) != 0 {
		t.Errorf("bulk updated = %d findings under approval, want 0", len(updated))
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+second, lead, ""); f["severity"] == "low" {
		t.Error("bulk severity applied without approval")
	}
	resp, bulk = req(t, app, http.MethodPost, "/api/v1/findings/bulk", dana, `{"ids":["`+first+`"],"status":"open"}`)
	if failed, _ := bulk["failed"].([]any); resp.StatusCode != http.StatusOK || len(failed) != 1 {
		t.Errorf("bulk on a finding already pending = %d %v, want 200 with it failed", resp.StatusCode, bulk)
	}
}
