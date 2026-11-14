package server

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// CEL conditions over the API: a policy with an expression finds the
// components it describes, and a bad expression is a 400 that says why — for
// policies and triage rules alike.
func TestExpressionConditionsOverHTTP(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "owner@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", admin, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", admin, `{"slug":"web","name":"web"}`)
	projectID := p["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/sboms?artifact=web&version=1.0.0", admin, smokeCycloneDX); resp.StatusCode != http.StatusCreated {
		t.Fatalf("sbom upload = %d", resp.StatusCode)
	}

	policy := `{"name":"no old log4j on the web project","violation_state":"fail",
		"conditions":[{"subject":"expression","operator":"matches",
		"value":"component.name == \"log4j-core\" && component.version.startsWith(\"2.14\") && project.name == \"web\""}]}`
	resp, created := req(t, app, http.MethodPost, "/api/v1/policies", admin, policy)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create expression policy = %d %v", resp.StatusCode, created)
	}
	req(t, app, http.MethodPost, "/api/v1/policies/evaluate", admin, "")
	_, list := req(t, app, http.MethodGet, "/api/v1/findings?scanner=policy&rule_id="+created["id"].(string), admin, "")
	fs, _ := list["findings"].([]any)
	if len(fs) != 1 || fs[0].(map[string]any)["package_name"] != "log4j-core" {
		t.Errorf("expression policy violations = %v, want exactly log4j-core", fs)
	}

	for _, c := range []struct{ path, body, want string }{
		{"/api/v1/policies", `{"name":"x","conditions":[{"subject":"expression","operator":"matches","value":"component.nmae == \"x\""}]}`, "no such key"},
		{"/api/v1/policies", `{"name":"x","conditions":[{"subject":"expression","operator":"matches","value":"component.name"}]}`, "true or false"},
		{"/api/v1/triage-rules", `{"name":"x","action":"false_positive","expression":"finding.cvs > 9"}`, "no such key"},
		{"/api/v1/triage-rules", `{"name":"x","action":"false_positive","expression":"finding.cvss >"}`, "Syntax error"},
	} {
		resp, body := req(t, app, http.MethodPost, c.path, admin, c.body)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body["error"]), c.want) {
			t.Errorf("POST %s %s = %d %v, want 400 mentioning %q", c.path, c.body, resp.StatusCode, body, c.want)
		}
	}
	resp, rule := req(t, app, http.MethodPost, "/api/v1/triage-rules", admin,
		`{"name":"quiet transitive lows","action":"false_positive","expression":"finding.severity == \"low\" && finding.dep_direct == false"}`)
	if resp.StatusCode != http.StatusCreated || rule["expression"] != `finding.severity == "low" && finding.dep_direct == false` {
		t.Errorf("triage rule with expression = %d %v", resp.StatusCode, rule)
	}
}
