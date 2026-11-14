package server

import (
	"net/http"
	"testing"
)

// A Trivy report with two CVEs on one log4j version (fixed on different
// release lines), one on jackson, and one with no fix.
const fixPlanTrivy = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2021-44228","PkgName":"org.apache.logging.log4j:log4j-core","PkgIdentifier":{"PURL":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},"InstalledVersion":"2.14.1","FixedVersion":"2.15.0","Severity":"CRITICAL"},
 {"VulnerabilityID":"CVE-2021-45046","PkgName":"org.apache.logging.log4j:log4j-core","PkgIdentifier":{"PURL":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},"InstalledVersion":"2.14.1","FixedVersion":"2.12.2, 2.16.0","Severity":"CRITICAL"},
 {"VulnerabilityID":"CVE-2020-36518","PkgName":"com.fasterxml.jackson.core:jackson-databind","PkgIdentifier":{"PURL":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.1"},"InstalledVersion":"2.12.1","FixedVersion":"2.12.6.1, 2.13.2.1","Severity":"HIGH"},
 {"VulnerabilityID":"CVE-2022-1471","PkgName":"org.yaml:snakeyaml","PkgIdentifier":{"PURL":"pkg:maven/org.yaml/snakeyaml@1.30"},"InstalledVersion":"1.30","Severity":"HIGH"}
]}]}`

// The fix plan ranks upgrades by the risk they remove, picks the one version
// that closes every finding on a package, and — portfolio-wide — shows only
// projects the caller can see.
func TestFixPlan(t *testing.T) {
	app := newTestApp(t)
	_ = rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	project := func(slug string) string {
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		id, _ := p["id"].(string)
		if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+id+"/scans?scanner=trivy", lead, fixPlanTrivy); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload = %d %v", resp.StatusCode, body)
		}
		return id
	}
	web, api := project("web"), project("api")
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", lead, `{"email":"viewer@xila.io","role":"viewer"}`)

	resp, plan := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/fix-plan", viewer, "")
	fixes, _ := plan["fixes"].([]any)
	if resp.StatusCode != http.StatusOK || len(fixes) != 2 {
		t.Fatalf("project fix plan = %d %v", resp.StatusCode, plan)
	}
	top := fixes[0].(map[string]any)
	if top["package"] != "org.apache.logging.log4j:log4j-core" || top["installed"] != "2.14.1" ||
		top["upgrade_to"] != "2.16.0" || top["closes"] != float64(2) || top["ecosystem"] != "maven" {
		t.Errorf("top fix = %v, want log4j 2.14.1 → 2.16.0 closing 2", top)
	}
	if second := fixes[1].(map[string]any); second["upgrade_to"] != "2.12.6.1" {
		t.Errorf("jackson fix = %v, want 2.12.6.1 (the smallest newer release)", second)
	}
	if nf, _ := plan["no_fix"].(map[string]any); nf["findings"] != float64(1) || nf["packages"] != float64(1) {
		t.Errorf("no_fix = %v, want snakeyaml", plan["no_fix"])
	}
	if p, _ := plan["pagination"].(map[string]any); p["has_more"] != false {
		t.Errorf("pagination = %v", plan["pagination"])
	}
	if _, paged := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/fix-plan?limit=1", viewer, ""); len(paged["fixes"].([]any)) != 1 ||
		paged["pagination"].(map[string]any)["has_more"] != true {
		t.Errorf("paged fix plan = %v", paged)
	}

	// Triage removes a finding from the plan.
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/findings?q=CVE-2021-45046", lead, "")
	id := list["findings"].([]any)[0].(map[string]any)["id"].(string)
	req(t, app, http.MethodPatch, "/api/v1/findings/"+id, lead, `{"status":"false_positive","reason":"not reachable"}`)
	_, plan = req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/fix-plan", viewer, "")
	if top := plan["fixes"].([]any)[0].(map[string]any); top["upgrade_to"] != "2.15.0" || top["closes"] != float64(1) {
		t.Errorf("after a false positive, log4j fix = %v, want 2.15.0 closing 1", top)
	}

	// Portfolio: the lead sees both projects; the viewer only web.
	_, all := req(t, app, http.MethodGet, "/api/v1/fix-plan", lead, "")
	if n := len(all["fixes"].([]any)); n != 4 {
		t.Errorf("lead's portfolio fix plan has %d rows, want 4 (2 per project)", n)
	}
	_, mine := req(t, app, http.MethodGet, "/api/v1/fix-plan", viewer, "")
	for _, f := range mine["fixes"].([]any) {
		if f.(map[string]any)["project_id"] == api {
			t.Fatal("viewer's portfolio fix plan includes a project they can't see")
		}
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+api+"/fix-plan", viewer, ""); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Errorf("viewer reading another project's fix plan = %d", resp.StatusCode)
	}
}
