package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// Risk acceptances over HTTP with four-eyes on: an editor requests one (the
// finding stays open), viewers and outsiders can't act on it, the requesting
// owner can't approve their own request, a second owner can — and only then
// is the finding risk_accepted. The finding's ledger shows the membership,
// and the approvals queue lists the pending request to whoever may decide it.
func TestRiskAcceptancesRBACAndFourEyes(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool, func(c *config.Config) { c.RiskAcceptanceRequiresApproval = true })
	rbacUser(t, app, "founder@xila.io") // first user: instance admin, not involved
	lead := rbacUser(t, app, "lead@xila.io")
	second := rbacUser(t, app, "second@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"web","name":"web"}`)
	pid, _ := p["id"].(string)
	for email, role := range map[string]string{"second@xila.io": "owner", "editor@xila.io": "editor", "viewer@xila.io": "viewer"} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"`+email+`","role":"`+role+`"}`); resp.StatusCode >= 300 {
			t.Fatalf("grant %s %s = %d", email, role, resp.StatusCode)
		}
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("scan = %d", resp.StatusCode)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", lead, "")
	fs, _ := list["findings"].([]any)
	if len(fs) == 0 {
		t.Fatal("no findings to accept")
	}
	fid := fs[0].(map[string]any)["id"].(string)
	base := "/api/v1/projects/" + pid + "/risk-acceptances"
	body := `{"title":"WAF covers it","justification":"virtual patch in front of the service","finding_ids":["` + fid + `"]}`
	if resp, _ := req(t, app, http.MethodPost, base, viewer, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer requesting = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, base, outsider, body); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("outsider requesting = %d, want 403/404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, base, editor, `{"title":"x","finding_ids":[]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("request without justification = %d, want 400", resp.StatusCode)
	}

	// The lead (an owner) requests: the finding is untouched.
	resp, created := req(t, app, http.MethodPost, base, lead, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("request = %d %v", resp.StatusCode, created)
	}
	ra, _ := created["risk_acceptance"].(map[string]any)
	aid, _ := ra["id"].(string)
	if ra["state"] != "requested" || ra["finding_count"] != float64(1) || ra["can_approve"] != false {
		t.Fatalf("requested acceptance = %v", ra)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, viewer, ""); f["status"] != "open" ||
		f["risk_acceptance"].(map[string]any)["state"] != "requested" {
		t.Fatalf("finding under a request = %v / %v, want open + the request", f["status"], f["risk_acceptance"])
	}

	// Approvals queue: the second owner may decide it, the requester may not,
	// the outsider doesn't see it.
	queue := func(token string) []any {
		_, q := req(t, app, http.MethodGet, "/api/v1/risk-acceptances?state=requested", token, "")
		items, _ := q["risk_acceptances"].([]any)
		return items
	}
	if q := queue(second); len(q) != 1 || q[0].(map[string]any)["can_approve"] != true {
		t.Errorf("second owner's queue = %v, want the request, decidable", q)
	}
	if q := queue(outsider); len(q) != 0 {
		t.Errorf("outsider's queue = %v, want empty", q)
	}

	approve := base + "/" + aid + "/approve"
	if resp, _ := req(t, app, http.MethodPost, approve, editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor approving = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, approve, lead, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("requester approving own request = %d, want 403 (four-eyes)", resp.StatusCode)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, viewer, ""); f["status"] != "open" {
		t.Fatalf("refused approvals changed the finding to %v", f["status"])
	}
	resp, approved := req(t, app, http.MethodPost, approve, second, `{"note":"ok until the upgrade"}`)
	if resp.StatusCode != http.StatusOK || approved["state"] != "approved" || approved["approver"] != "second@xila.io" {
		t.Fatalf("second owner approving = %d %v", resp.StatusCode, approved)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, viewer, ""); f["status"] != "risk_accepted" || f["sla_status"] != "paused" && f["sla_status"] != "none" {
		t.Fatalf("approved finding = %v (sla %v), want risk_accepted, clock paused", f["status"], f["sla_status"])
	}
	if resp, _ := req(t, app, http.MethodPost, approve, second, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("approving twice = %d, want 409", resp.StatusCode)
	}

	// Membership changes: an editor can't extend an approved acceptance (that
	// would accept without review); revoking is owner-level.
	if resp, _ := req(t, app, http.MethodPost, base+"/"+aid+"/findings", editor, `{"finding_ids":["`+fid+`"]}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor adding to an approved acceptance = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, base+"/"+aid+"/revoke", editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor revoking = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, base+"/"+aid+"/findings/"+fid+"?reason=upgraded", editor, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("editor removing a finding = %d", resp.StatusCode)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, viewer, ""); f["status"] != "open" || f["risk_acceptance"] != nil {
		t.Errorf("removed finding = %v / %v, want open, uncovered", f["status"], f["risk_acceptance"])
	}

	// The ledger survives the removal; outsiders can't read it.
	resp, ledger := req(t, app, http.MethodGet, "/api/v1/findings/"+fid+"/risk-acceptances", viewer, "")
	entries, _ := ledger["risk_acceptances"].([]any)
	if resp.StatusCode != http.StatusOK || len(entries) != 1 {
		t.Fatalf("ledger = %d %v", resp.StatusCode, ledger)
	}
	if e := entries[0].(map[string]any); e["acceptance_id"] != aid || e["removed_at"] == nil || e["reason"] != "upgraded" || e["removed_by"] != "editor@xila.io" {
		t.Errorf("ledger entry = %v", e)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/findings/"+fid+"/risk-acceptances", outsider, ""); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("outsider reading the ledger = %d, want 403/404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, base+"/"+aid, outsider, ""); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("outsider reading the acceptance = %d, want 403/404", resp.StatusCode)
	}

	// "Accept risk" in the triage flow requests rather than sets: PATCH and
	// bulk both answer 202 with requests, and the finding stays open.
	resp, viaPatch := req(t, app, http.MethodPatch, "/api/v1/findings/"+fid, editor, `{"status":"risk_accepted","reason":"again"}`)
	if resp.StatusCode != http.StatusAccepted || viaPatch["state"] != "requested" {
		t.Fatalf("PATCH risk_accepted = %d %v, want 202 + request", resp.StatusCode, viaPatch)
	}
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+fid, editor, `{"status":"risk_accepted","reason":"twice"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("second request for the same finding = %d, want 409", resp.StatusCode)
	}
	if _, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, viewer, ""); f["status"] != "open" {
		t.Errorf("finding after PATCH risk_accepted = %v, want open", f["status"])
	}
	if len(fs) > 1 {
		other := fs[1].(map[string]any)["id"].(string)
		resp, bulk := req(t, app, http.MethodPost, "/api/v1/findings/bulk", editor, `{"ids":["`+other+`"],"status":"risk_accepted","reason":"bulk"}`)
		if accs, _ := bulk["acceptances"].([]any); resp.StatusCode != http.StatusAccepted || len(accs) != 1 {
			t.Errorf("bulk risk_accepted = %d %v, want 202 + one request", resp.StatusCode, bulk)
		}
	}

	// The requester (or an owner) withdraws a request; a viewer can't.
	reqID, _ := viaPatch["id"].(string)
	if resp, _ := req(t, app, http.MethodDelete, base+"/"+reqID, viewer, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer deleting = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, base+"/"+reqID, editor, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("requester deleting own request = %d, want 204", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, base+"/"+aid, second, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("deleting an approved acceptance = %d, want 409 (revoke instead)", resp.StatusCode)
	}

}

// The "My work" queues: ?actionable=true keeps only what the caller may
// decide (projects they own, never their own request under four-eyes), and
// owner=me + expires_within_days finds the acceptances they must renew.
func TestMyWorkQueues(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool, func(c *config.Config) {
		c.RiskAcceptanceRequiresApproval = true
		c.AssessmentRequiresApproval = true
	})
	rbacUser(t, app, "founder@xila.io") // instance admin, not involved
	lead := rbacUser(t, app, "lead@xila.io")
	second := rbacUser(t, app, "second@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", lead, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)
	for email, role := range map[string]string{"second@xila.io": "owner", "editor@xila.io": "editor", "viewer@xila.io": "viewer"} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"`+email+`","role":"`+role+`"}`); resp.StatusCode >= 300 {
			t.Fatalf("grant %s %s = %d", email, role, resp.StatusCode)
		}
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("scan = %d", resp.StatusCode)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", lead, "")
	fs, _ := list["findings"].([]any)
	if len(fs) < 2 {
		t.Fatalf("want 2 findings, got %d", len(fs))
	}
	fid := func(i int) string { return fs[i].(map[string]any)["id"].(string) }
	_, me := req(t, app, http.MethodGet, "/api/v1/me", second, "")
	secondID, _ := me["id"].(string)

	count := func(token, path string) int {
		t.Helper()
		resp, body := req(t, app, http.MethodGet, path, token, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d %v", path, resp.StatusCode, body)
		}
		for _, k := range []string{"risk_acceptances", "assessments", "findings"} {
			if items, ok := body[k].([]any); ok {
				return len(items)
			}
		}
		t.Fatalf("GET %s: no list in %v", path, body)
		return 0
	}

	// Two requests: one by the editor (owned by second, expiring in 10 days),
	// one by the lead.
	base := "/api/v1/projects/" + pid + "/risk-acceptances"
	expires := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	resp, created := req(t, app, http.MethodPost, base, editor, `{"title":"WAF","justification":"virtual patch","owner_id":"`+secondID+`","expires_at":"`+expires+`","finding_ids":["`+fid(0)+`"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("editor request = %d %v", resp.StatusCode, created)
	}
	editorReq := created["risk_acceptance"].(map[string]any)["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, base, lead, `{"title":"Legacy","justification":"retiring","finding_ids":["`+fid(1)+`"]}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("lead request = %d", resp.StatusCode)
	}
	actionable := "/api/v1/risk-acceptances?actionable=true"
	for who, want := range map[string]int{lead: 1, second: 2, editor: 0, viewer: 0} {
		if got := count(who, actionable); got != want {
			t.Errorf("actionable acceptances for %s = %d, want %d", who[:8], got, want)
		}
	}

	// Approved: second owns it and it expires within 30 days, not within 5.
	if resp, _ := req(t, app, http.MethodPost, base+"/"+editorReq+"/approve", lead, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("approve = %d", resp.StatusCode)
	}
	expiring := "/api/v1/risk-acceptances?state=approved&owner=me&expires_within_days="
	if got := count(second, expiring+"30"); got != 1 {
		t.Errorf("second's expiring within 30 days = %d, want 1", got)
	}
	if got := count(second, expiring+"5"); got != 0 {
		t.Errorf("second's expiring within 5 days = %d, want 0", got)
	}
	if got := count(lead, expiring+"30"); got != 0 {
		t.Errorf("lead's expiring = %d, want 0 (not the owner)", got)
	}
	if resp, _ := req(t, app, http.MethodGet, expiring+"0", second, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expires_within_days=0 = %d, want 400", resp.StatusCode)
	}

	// An editor's status change is held as an assessment: owners may decide
	// it, the requester and viewers may not.
	if resp, body := req(t, app, http.MethodPatch, "/api/v1/findings/"+fid(1), editor, `{"status":"false_positive","reason":"test fixture"}`); resp.StatusCode >= 300 {
		t.Fatalf("editor status change = %d %v", resp.StatusCode, body)
	}
	for who, want := range map[string]int{lead: 1, second: 1, editor: 0, viewer: 0} {
		if got := count(who, "/api/v1/assessments?actionable=true"); got != want {
			t.Errorf("actionable assessments for %s = %d, want %d", who[:8], got, want)
		}
	}

	// Assigned to me, still active.
	_, meEd := req(t, app, http.MethodGet, "/api/v1/me", editor, "")
	if resp, body := req(t, app, http.MethodPut, "/api/v1/findings/"+fid(1)+"/assignee", lead, `{"assignee_id":"`+meEd["id"].(string)+`"}`); resp.StatusCode >= 300 {
		t.Fatalf("assign = %d %v", resp.StatusCode, body)
	}
	if got := count(editor, "/api/v1/findings?assignee=me&active=true"); got != 1 {
		t.Errorf("editor's active assigned findings = %d, want 1", got)
	}
	if got := count(viewer, "/api/v1/findings?assignee=me&active=true"); got != 0 {
		t.Errorf("viewer's assigned findings = %d, want 0", got)
	}
}
