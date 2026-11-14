package server

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/xilasec/xila-api/internal/database"
)

// TestSmokeTriageRules exercises milestone 3.3 over HTTP: dry-run preview
// (unsaved + stored, mutates nothing), hit metrics after apply, the EPSS/KEV/
// criticality conditions, and the four-eyes approve/reject routes.
func TestSmokeTriageRules(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"tr","name":"TR"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"t","name":"T"}`)
	teamID, _ := teamBody["id"].(string)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin,
		`{"slug":"web","name":"Web","business_criticality":"low"}`)
	projectID, _ := projBody["id"].(string)
	if projectID == "" {
		t.Fatal("project setup failed")
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", admin, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("ingest = %d", resp.StatusCode)
	}

	// Non-admins can't preview or review.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules/preview", bob, `{"action":"wont_fix"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin preview = %d, want 403", resp.StatusCode)
	}

	// Unsaved preview: high severity in a low-criticality project -> the secret.
	ruleBody := `{"name":"mute high","enabled":true,"severities":["high"],"project_criticality":["low"],"action":"wont_fix"}`
	resp, pv := req(t, app, http.MethodPost, "/api/v1/triage-rules/preview?project_id="+projectID, admin, ruleBody)
	if resp.StatusCode != http.StatusOK || pv["total"] != float64(1) {
		t.Fatalf("preview = %d %v, want 1 finding", resp.StatusCode, pv)
	}
	item := pv["findings"].([]any)[0].(map[string]any)
	if item["status"] != "open" || item["new_status"] != "wont_fix" || item["severity"] != "high" {
		t.Errorf("preview item = %v", item)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules/preview", admin, `{"action":"wont_fix","min_epss":2}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid min_epss preview = %d, want 400", resp.StatusCode)
	}
	// Preview mutated nothing.
	if _, fl := req(t, app, http.MethodGet, "/api/v1/findings?project_id="+projectID+"&status=open", admin, ""); len(fl["findings"].([]any)) != 2 {
		t.Errorf("open findings after preview = %v, want 2", len(fl["findings"].([]any)))
	}

	// KEV + EPSS conditions on an unsaved rule: nothing is enriched yet, so an
	// unknown EPSS / non-KEV finding never matches.
	if _, kv := req(t, app, http.MethodPost, "/api/v1/triage-rules/preview", admin, `{"action":"risk_accepted","kev":true}`); kv["total"] != float64(0) {
		t.Errorf("kev preview before enrichment = %v, want 0", kv["total"])
	}
	if _, ep := req(t, app, http.MethodPost, "/api/v1/triage-rules/preview", admin, `{"action":"risk_accepted","min_epss":0}`); ep["total"] != float64(0) {
		t.Errorf("epss preview before enrichment = %v, want 0", ep["total"])
	}
	req(t, app, http.MethodPost, "/api/v1/enrich", admin, "")
	if _, kv := req(t, app, http.MethodPost, "/api/v1/triage-rules/preview", admin, `{"action":"risk_accepted","kev":true,"min_epss":0.9}`); kv["total"] != float64(1) {
		t.Errorf("kev+epss preview after enrichment = %v, want 1", kv["total"])
	}

	// Store it (approval off -> approved), preview the stored rule, apply.
	resp, rule := req(t, app, http.MethodPost, "/api/v1/triage-rules", admin, ruleBody)
	if resp.StatusCode != http.StatusCreated || rule["approval_status"] != "approved" || rule["hit_count"] != float64(0) {
		t.Fatalf("create = %d %v", resp.StatusCode, rule)
	}
	ruleID := rule["id"].(string)
	if _, spv := req(t, app, http.MethodPost, "/api/v1/triage-rules/"+ruleID+"/preview", admin, ""); spv["total"] != float64(1) {
		t.Errorf("stored preview = %v, want 1", spv)
	}
	if _, ap := req(t, app, http.MethodPost, "/api/v1/triage-rules/apply?project_id="+projectID, admin, ""); ap["applied"] != float64(1) {
		t.Errorf("apply = %v, want 1", ap)
	}
	if _, got := req(t, app, http.MethodGet, "/api/v1/triage-rules/"+ruleID, admin, ""); got["hit_count"] != float64(1) || got["last_hit_at"] == nil {
		t.Errorf("after apply hit_count=%v last_hit_at=%v, want 1 + set", got["hit_count"], got["last_hit_at"])
	}
	// Approving an already-approved rule conflicts.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules/"+ruleID+"/approve", admin, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("approve approved = %d, want 409", resp.StatusCode)
	}

	// Four-eyes over HTTP: put the rule up for review as authored by admin
	// (what TRIAGE_RULES_REQUIRE_APPROVAL does on create), then promote bob.
	pool, err := database.Connect(context.Background(), os.Getenv("TEST_DATABASE_URL"), database.DefaultPoolConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(),
		`UPDATE triage_rules SET approval_status='pending', approved_by=NULL, approved_at=NULL WHERE id=$1`, ruleID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules/"+ruleID+"/approve", admin, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("author approve = %d, want 403", resp.StatusCode)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE users SET is_admin=true WHERE email='bob@xila.io'`); err != nil {
		t.Fatal(err)
	}
	resp, approved := req(t, app, http.MethodPost, "/api/v1/triage-rules/"+ruleID+"/approve", bob, "")
	if resp.StatusCode != http.StatusOK || approved["approval_status"] != "approved" || approved["approved_by"] == nil {
		t.Errorf("second-admin approve = %d %v", resp.StatusCode, approved)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules/"+ruleID+"/reject", bob, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("reject approved = %d, want 409", resp.StatusCode)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE triage_rules SET approval_status='pending' WHERE id=$1`, ruleID); err != nil {
		t.Fatal(err)
	}
	if resp, rj := req(t, app, http.MethodPost, "/api/v1/triage-rules/"+ruleID+"/reject", bob, ""); resp.StatusCode != http.StatusOK || rj["approval_status"] != "rejected" {
		t.Errorf("reject = %d %v", resp.StatusCode, rj)
	}
}
