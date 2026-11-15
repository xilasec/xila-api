package server

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// One critical CVE on log4j-core, fixed in 2.15.0 — the same package version
// uploaded to every project, so they all land on the same (kind, key).
const rootCauseTrivy = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"pom","Vulnerabilities":[
 {"VulnerabilityID":"CVE-2021-44228","PkgName":"org.apache.logging.log4j:log4j-core","PkgIdentifier":{"PURL":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},"InstalledVersion":"2.14.1","FixedVersion":"2.15.0","Severity":"CRITICAL"}
]}]}`

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// The same vulnerable package in three projects merges into one root cause
// (projects=3, findings=3); a caller who can only see two of them gets
// projects=2 and can't see the third's details; a non-default-version upload
// doesn't double count; archiving a project drops it; and POST creates the
// missing remediation action only in visible projects where the caller is
// editor, idempotently, never naming a project the caller can't see.
func TestRootCauses(t *testing.T) {
	app := newTestApp(t)
	_ = rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	limited := rbacUser(t, app, "limited@xila.io")
	editorBeta := rbacUser(t, app, "editor-beta@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)

	project := func(slug string) string {
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		id, _ := p["id"].(string)
		if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+id+"/scans?scanner=trivy", lead, rootCauseTrivy); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload to %s = %d %v", slug, resp.StatusCode, body)
		}
		return id
	}
	alpha, beta, gamma := project("alpha"), project("beta"), project("gamma")

	// limited sees alpha and beta only; editorBeta can edit beta only.
	req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/members", lead, `{"email":"limited@xila.io","role":"viewer"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+beta+"/members", lead, `{"email":"limited@xila.io","role":"viewer"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+beta+"/members", lead, `{"email":"editor-beta@xila.io","role":"editor"}`)

	// A non-default-version upload to alpha (a feature branch): must not
	// change the default-version counts.
	if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+alpha+"/scans?scanner=trivy&branch=feature-x", lead, rootCauseTrivy); resp.StatusCode != http.StatusCreated {
		t.Fatalf("branch upload = %d %v", resp.StatusCode, body)
	}

	findRow := func(rows []any) map[string]any {
		for _, r := range rows {
			row := r.(map[string]any)
			if row["kind"] == "package_upgrade" && row["package"] == "org.apache.logging.log4j:log4j-core" {
				return row
			}
		}
		return nil
	}

	// Lead sees all three projects: one merged root cause.
	resp, list := req(t, app, http.MethodGet, "/api/v1/root-causes", lead, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list = %d %v", resp.StatusCode, list)
	}
	row := findRow(list["root_causes"].([]any))
	if row == nil {
		t.Fatalf("log4j root cause missing: %v", list)
	}
	key, _ := row["key"].(string)
	if row["projects"] != float64(3) || row["findings"] != float64(3) {
		t.Fatalf("lead's view = %v, want projects=3 findings=3 (branch upload must not double count)", row)
	}
	if bySev, _ := row["by_severity"].(map[string]any); bySev["critical"] != float64(3) {
		t.Errorf("by_severity = %v, want critical=3", row["by_severity"])
	}
	if row["all_actioned"] != false {
		t.Errorf("all_actioned = %v, want false (no live action yet)", row["all_actioned"])
	}

	// Detail: all three, by name.
	resp, detail := req(t, app, http.MethodGet, "/api/v1/root-causes/package_upgrade/"+b64url(key), lead, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("detail = %d %v", resp.StatusCode, detail)
	}
	projects := detail["affected_projects"].([]any)
	if len(projects) != 3 {
		t.Fatalf("detail affected_projects = %d, want 3: %v", len(projects), projects)
	}

	// limited sees only alpha and beta.
	resp, list = req(t, app, http.MethodGet, "/api/v1/root-causes", limited, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("limited list = %d %v", resp.StatusCode, list)
	}
	row = findRow(list["root_causes"].([]any))
	if row == nil || row["projects"] != float64(2) {
		t.Fatalf("limited's view = %v, want projects=2", row)
	}
	resp, detail = req(t, app, http.MethodGet, "/api/v1/root-causes/package_upgrade/"+b64url(key), limited, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("limited detail = %d %v", resp.StatusCode, detail)
	}
	projects = detail["affected_projects"].([]any)
	if len(projects) != 2 {
		t.Fatalf("limited detail affected_projects = %d, want 2: %v", len(projects), projects)
	}
	for _, p := range projects {
		if p.(map[string]any)["project_id"] == gamma {
			t.Fatal("limited's detail names gamma, which they can't see")
		}
	}

	// Archive gamma: it drops out of the lead's view too.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+gamma, lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("archive gamma = %d", resp.StatusCode)
	}
	resp, list = req(t, app, http.MethodGet, "/api/v1/root-causes", lead, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list after archive = %d %v", resp.StatusCode, list)
	}
	row = findRow(list["root_causes"].([]any))
	if row == nil || row["projects"] != float64(2) {
		t.Fatalf("after archiving gamma = %v, want projects=2", row)
	}

	// limited can see alpha and beta but edit neither: nothing is created and
	// both are reported forbidden (by name: limited can see them).
	resp, created := req(t, app, http.MethodPost, "/api/v1/root-causes/package_upgrade/"+b64url(key)+"/remediation", limited, "")
	if resp.StatusCode != http.StatusOK || created["created"] != float64(0) {
		t.Fatalf("create by limited = %d %v, want created=0", resp.StatusCode, created)
	}
	forbidden := map[string]bool{}
	for _, s := range created["skipped"].([]any) {
		row := s.(map[string]any)
		if row["reason"] == "forbidden" && row["project_name"] != nil {
			forbidden[row["project_id"].(string)] = true
		}
	}
	if !forbidden[alpha] || !forbidden[beta] || len(forbidden) != 2 {
		t.Errorf("limited's skipped = %v, want alpha and beta forbidden by name", created["skipped"])
	}

	// editorBeta can see and edit only beta: creates there, and alpha (which it
	// can't see) is neither touched nor named, not even by id.
	resp, created = req(t, app, http.MethodPost, "/api/v1/root-causes/package_upgrade/"+b64url(key)+"/remediation", editorBeta, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create by editorBeta = %d %v", resp.StatusCode, created)
	}
	if created["created"] != float64(1) {
		t.Fatalf("editorBeta created = %v, want 1 (beta only)", created)
	}
	for _, s := range created["skipped"].([]any) {
		if s.(map[string]any)["project_id"] == alpha {
			t.Errorf("editorBeta's response names alpha, which it can't see: %v", created)
		}
	}

	// Idempotent: a second call from editorBeta creates nothing more.
	resp, created = req(t, app, http.MethodPost, "/api/v1/root-causes/package_upgrade/"+b64url(key)+"/remediation", editorBeta, "")
	if resp.StatusCode != http.StatusOK || created["created"] != float64(0) {
		t.Fatalf("second create by editorBeta = %d %v, want created=0", resp.StatusCode, created)
	}

	// lead (editor everywhere) finishes the job: creates alpha's action too.
	resp, created = req(t, app, http.MethodPost, "/api/v1/root-causes/package_upgrade/"+b64url(key)+"/remediation", lead, "")
	if resp.StatusCode != http.StatusOK || created["created"] != float64(1) {
		t.Fatalf("lead's create = %d %v, want created=1 (alpha)", resp.StatusCode, created)
	}
	resp, created = req(t, app, http.MethodPost, "/api/v1/root-causes/package_upgrade/"+b64url(key)+"/remediation", lead, "")
	if resp.StatusCode != http.StatusOK || created["created"] != float64(0) {
		t.Fatalf("lead's second create = %d %v, want created=0 (idempotent)", resp.StatusCode, created)
	}

	// Now every visible (non-archived) project has a live action: all_actioned.
	resp, list = req(t, app, http.MethodGet, "/api/v1/root-causes", lead, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("final list = %d %v", resp.StatusCode, list)
	}
	row = findRow(list["root_causes"].([]any))
	if row == nil || row["all_actioned"] != true {
		t.Fatalf("after both actions created = %v, want all_actioned=true", row)
	}
}
