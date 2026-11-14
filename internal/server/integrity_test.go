package server

import (
	"net/http"
	"testing"
)

// cyclonedxExpress is an SBOM shipping express 4.18.2 with the given SHA-1.
func cyclonedxExpress(sha1 string) string {
	return `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2",
		 "hashes":[{"alg":"SHA-1","content":"` + sha1 + `"}]},
		{"type":"library","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0"}]}`
}

// Component integrity end to end: the registry's published digest verifies
// the shipped artifact, a different digest is a mismatch, a component with no
// hash is unknown — filterable, and a policy can fail on a mismatch.
func TestComponentIntegrity(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "owner@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", admin, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", admin, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)

	resp, policy := req(t, app, http.MethodPost, "/api/v1/policies", admin,
		`{"name":"tampered artifacts","violation_state":"fail","conditions":[{"subject":"integrity","operator":"is","value":"mismatch"}]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create integrity policy = %d %v", resp.StatusCode, policy)
	}
	for artifact, sha1 := range map[string]string{
		"web": "3fabe08296e930c796c19e3c516979386ba9fd59", // what npm serves
		"cdn": "3FABE08296E930C796C19E3C516979386BA9FD5A", // one byte off
	} {
		if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/sboms?artifact="+artifact+"&version=1.0.0", admin, cyclonedxExpress(sha1)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("sbom %s upload = %d %v", artifact, resp.StatusCode, body)
		}
	}

	// Fetch registry metadata (an SBOM upload triggers it in production).
	if resp, sweep := req(t, app, http.MethodPost, "/api/v1/pkgmeta/refresh?wait=true", admin, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("pkgmeta refresh = %d %v", resp.StatusCode, sweep)
	}

	byIntegrity := func(q string) []any {
		t.Helper()
		_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/components?integrity="+q, admin, "")
		cs, _ := list["components"].([]any)
		return cs
	}
	if cs := byIntegrity("verified"); len(cs) != 1 || cs[0].(map[string]any)["artifact"] != "web" {
		t.Errorf("integrity=verified = %v, want web's express", cs)
	}
	mismatch := byIntegrity("mismatch")
	if len(mismatch) != 1 || mismatch[0].(map[string]any)["artifact"] != "cdn" || mismatch[0].(map[string]any)["integrity"] != "mismatch" {
		t.Errorf("integrity=mismatch = %v, want cdn's express", mismatch)
	}
	if cs := byIntegrity("unknown"); len(cs) != 2 {
		t.Errorf("integrity=unknown = %d, want the two hashless left-pads", len(cs))
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/components?integrity=maybe", admin, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("integrity=maybe = %d, want 400", resp.StatusCode)
	}

	req(t, app, http.MethodPost, "/api/v1/policies/evaluate", admin, "")
	_, list := req(t, app, http.MethodGet, "/api/v1/findings?scanner=policy&rule_id="+policy["id"].(string), admin, "")
	if fs, _ := list["findings"].([]any); len(fs) != 1 || fs[0].(map[string]any)["package_name"] != "express" {
		t.Errorf("integrity policy violations = %v, want exactly the tampered express", fs)
	}
}
