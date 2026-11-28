package server

import (
	"net/http"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// osvMaliciousReport has a malicious package reported under its MAL- id (with
// the low severity some feeds state), a GHSA malware record carrying its
// MAL- id only as an alias, and an ordinary vulnerability.
const osvMaliciousReport = `{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[
 {"package":{"name":"evil-pkg","version":"1.0.0","ecosystem":"npm"},
  "vulnerabilities":[{"id":"MAL-2025-4242","summary":"Malicious code in evil-pkg (npm)","database_specific":{"severity":"LOW"}}]},
 {"package":{"name":"sneaky-lib","version":"2.1.0","ecosystem":"npm"},
  "vulnerabilities":[{"id":"GHSA-m4l1-m4l1-m4l1","summary":"Malware in sneaky-lib","aliases":["MAL-2025-9001"]}]},
 {"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm"},
  "vulnerabilities":[{"id":"GHSA-p6mc-m468-83gw","summary":"Prototype pollution in lodash","aliases":["CVE-2020-8203"],
   "database_specific":{"severity":"HIGH"},"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}]}
]}]}`

// M13 follow-up (#1): a malicious package is a critical finding whatever its
// advisory states, ranks at the exploitability ceiling, is filterable, and
// fails the gate (even with no policy) until the policy allows it.
func TestMaliciousPackages(t *testing.T) {
	app := newTestApp(t)
	token := rbacUser(t, app, "secops@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", token, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", token, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)
	if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=osv-scanner", token, osvMaliciousReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("scan = %d %v", resp.StatusCode, body)
	}

	_, all := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", token, "")
	byRule := map[string]map[string]any{}
	for _, x := range all["findings"].([]any) {
		f := x.(map[string]any)
		byRule[f["rule_id"].(string)] = f
	}
	ceiling := domain.Priority(domain.SeverityCritical, domain.Exploitability{Malicious: true}, domain.Reachability{}, "")
	for _, rule := range []string{"MAL-2025-4242", "GHSA-m4l1-m4l1-m4l1"} {
		f := byRule[rule]
		if f == nil || f["malicious"] != true || f["severity"] != "critical" || f["priority"] != ceiling {
			t.Errorf("%s = malicious %v, severity %v, priority %v; want true, critical, %v", rule, f["malicious"], f["severity"], f["priority"], ceiling)
		}
	}
	if f := byRule["GHSA-p6mc-m468-83gw"]; f == nil || f["malicious"] != false || f["severity"] != "high" {
		t.Errorf("ordinary vulnerability = %v", f)
	}
	_, only := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings?malicious=true", token, "")
	if n := len(only["findings"].([]any)); n != 2 {
		t.Errorf("?malicious=true = %d findings, want 2", n)
	}

	// No gate policy at all: still fails, on the malicious rule.
	gate := func() map[string]any {
		t.Helper()
		_, g := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/gate", token, "")
		return g
	}
	g := gate()
	vs, _ := g["violations"].([]any)
	if g["passed"] != false || len(vs) != 1 || vs[0].(map[string]any)["rule"] != "malicious" {
		t.Fatalf("gate with no policy = %v, want one malicious violation", g)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/projects/"+pid+"/gate/policy", token, `{"allow_malicious":true}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("set policy = %d", resp.StatusCode)
	}
	if g := gate(); g["passed"] != true {
		t.Errorf("gate with allow_malicious = %v, want passed", g)
	}
}
