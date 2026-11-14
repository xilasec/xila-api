package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// CRA Article 14 over HTTP: an owner declares the product in scope, a KEV hit
// from enrichment opens a case only there, the case moves through its
// workflow with role checks, exports its draft payload, shows in the evidence
// report, and stays invisible to a viewer of another project.
func TestCRACasesHTTP(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")
	other := rbacUser(t, app, "other@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, a := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"fw","name":"firmware"}`)
	pid, _ := a["id"].(string)
	_, b := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"web","name":"web"}`)
	otherPID, _ := b["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"editor@xila.io","role":"editor"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+otherPID+"/members", lead, `{"email":"other@xila.io","role":"viewer"}`)

	// Declaring the product is owner-level and validated.
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/projects/"+pid+"/cra", editor, `{"cra_in_scope":true}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor declaring CRA scope = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/projects/"+pid+"/cra", lead, `{"cra_in_scope":true,"member_states":["XX"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("non-EU member state = %d, want 400", resp.StatusCode)
	}
	resp, prod := req(t, app, http.MethodPut, "/api/v1/projects/"+pid+"/cra", lead,
		`{"cra_in_scope":true,"product_name":"Widget OS","product_version":"3.2","member_states":["de","fr","DE"]}`)
	if resp.StatusCode != http.StatusOK || prod["cra_in_scope"] != true || len(prod["member_states"].([]any)) != 2 {
		t.Fatalf("declare product = %d %v", resp.StatusCode, prod)
	}

	// Both projects carry the same KEV-listed CVE; only the in-scope one gets a case.
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport)
	req(t, app, http.MethodPost, "/api/v1/projects/"+otherPID+"/scans?scanner=trivy", lead, smokeTrivyReport)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/enrich", admin, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("enrich = %d", resp.StatusCode)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/cra/cases", lead, "")
	cases, _ := list["cases"].([]any)
	if len(cases) != 1 {
		t.Fatalf("lead sees %d cases, want 1: %v", len(cases), list)
	}
	cs := cases[0].(map[string]any)
	caseID, _ := cs["id"].(string)
	if cs["project_id"] != pid || cs["vuln_id"] != "CVE-2020-1" || cs["trigger"] != "kev" || cs["state"] != "open" {
		t.Errorf("case = %v", cs)
	}
	// The fix (1.1) was already known: the final-report clock runs too.
	if cs["final_report_due_at"] == nil {
		t.Errorf("final report due not set although a fixed version exists: %v", cs)
	}

	// A viewer of another project sees neither the case nor its report.
	if _, l := req(t, app, http.MethodGet, "/api/v1/cra/cases", other, ""); len(l["cases"].([]any)) != 0 {
		t.Errorf("viewer of another project lists %v", l["cases"])
	}
	for _, path := range []string{"/api/v1/cra/cases/" + caseID, "/api/v1/cra/cases/" + caseID + "/report?stage=early_warning",
		"/api/v1/projects/" + pid + "/cra"} {
		if resp, _ := req(t, app, http.MethodGet, path, other, ""); resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer of another project GET %s = %d, want 403", path, resp.StatusCode)
		}
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/cra/cases/"+caseID+"/submit", other, `{"stage":"early_warning"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer of another project submitting = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/cra/sweep", lead, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin sweep = %d, want 403", resp.StatusCode)
	}

	// The draft payload.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/cra/cases/"+caseID+"/report?stage=bogus", editor, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bogus stage = %d, want 400", resp.StatusCode)
	}
	resp, payload := req(t, app, http.MethodGet, "/api/v1/cra/cases/"+caseID+"/report?stage=notification", editor, "")
	product, _ := payload["product"].(map[string]any)
	manufacturer, _ := payload["manufacturer"].(map[string]any)
	vuln, _ := payload["vulnerability"].(map[string]any)
	if resp.StatusCode != http.StatusOK || payload["draft"] != true || payload["stage"] != "notification" ||
		product["name"] != "Widget OS" || manufacturer["name"] != "Acme GmbH" || vuln["id"] != "CVE-2020-1" || payload["measures"] == nil {
		t.Errorf("payload = %d %v", resp.StatusCode, payload)
	}

	// Workflow: editors submit, only owners dismiss; each step is recorded.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/cra/cases/"+caseID+"/submit", editor, `{"stage":"notification"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("out-of-order submission = %d, want 409", resp.StatusCode)
	}
	resp, sub := req(t, app, http.MethodPost, "/api/v1/cra/cases/"+caseID+"/submit", editor, `{"stage":"early_warning","reference":"SRP-42"}`)
	if resp.StatusCode != http.StatusOK || sub["state"] != "early_warning_sent" || sub["next_stage"] != "notification" {
		t.Fatalf("submit early warning = %d %v", resp.StatusCode, sub)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/cra/cases/"+caseID+"/dismiss", editor, `{"reason":"x"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor dismissing = %d, want 403", resp.StatusCode)
	}
	resp, dis := req(t, app, http.MethodPost, "/api/v1/cra/cases/"+caseID+"/dismiss", lead, `{"reason":"vulnerable code not shipped in the firmware build"}`)
	if resp.StatusCode != http.StatusOK || dis["state"] != "dismissed" {
		t.Fatalf("dismiss = %d %v", resp.StatusCode, dis)
	}
	_, detail := req(t, app, http.MethodGet, "/api/v1/cra/cases/"+caseID, editor, "")
	events, _ := detail["events"].([]any)
	if len(events) != 3 {
		t.Fatalf("events = %v", detail["events"])
	}
	if e := events[1].(map[string]any); e["stage"] != "early_warning" || e["actor_email"] != "editor@xila.io" || e["reference"] != "SRP-42" || e["payload"] == nil {
		t.Errorf("submission event = %v", e)
	}
	if e := events[2].(map[string]any); e["to_state"] != "dismissed" || e["actor_email"] != "lead@xila.io" {
		t.Errorf("dismiss event = %v", e)
	}

	// Manual opening: editor-level, in-scope projects only.
	_, fl := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", editor, "")
	var secretID string
	for _, f := range fl["findings"].([]any) {
		if m := f.(map[string]any); m["rule_id"] == "aws-key" {
			secretID, _ = m["id"].(string)
		}
	}
	resp, manual := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/cra/cases", editor, `{"finding_id":"`+secretID+`","note":"exploited in the wild"}`)
	if resp.StatusCode != http.StatusCreated || manual["trigger"] != "manual" {
		t.Errorf("manual open = %d %v", resp.StatusCode, manual)
	}

	// The evidence report lists the cases and their deadline compliance.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+pid+"/compliance/eu-cra/report", nil)
	r.Header.Set("Authorization", "Bearer "+editor)
	res, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	html := string(body)
	if !strings.Contains(html, "Reporting of actively exploited vulnerabilities (Art. 14)") || !strings.Contains(html, "CVE-2020-1") ||
		!strings.Contains(html, "vulnerable code not shipped") || !strings.Contains(html, "2 case(s)") {
		t.Errorf("evidence report lacks the CRA cases section")
	}
}
