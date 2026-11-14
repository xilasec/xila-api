package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The CRA pack over HTTP: eu-cra posture is honest (manual requirements are
// neither passing nor scored), and the evidence report renders the evidence,
// is inert, and is only for those who can read the project.
func TestCRAPostureAndEvidenceReport(t *testing.T) {
	app := newTestApp(t)
	_ = rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", lead, `{"slug":"shop","name":"Shop <web>"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/sboms?artifact=web&version=1.0.0", lead, smokeCycloneDX)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, fixPlanTrivy)

	resp, posture := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/compliance/eu-cra", lead, "")
	if resp.StatusCode != http.StatusOK || posture["manual_controls"] != float64(10) || posture["total_controls"] != float64(12) {
		t.Fatalf("eu-cra posture = %d %v", resp.StatusCode, posture)
	}
	status := map[string]string{}
	for _, c := range posture["controls"].([]any) {
		m := c.(map[string]any)
		status[m["code"].(string)] = m["status"].(string)
	}
	if status["II.1"] != "passing" || status["II.4"] != "failing" || status["II.5"] != "manual" {
		t.Errorf("controls = %v (SBOM uploaded; no VEX yet; disclosure policy is manual)", status)
	}

	get := func(token string) (*http.Response, string) {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+pid+"/compliance/eu-cra/report", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		res, err := app.Test(r, -1)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		return res, string(b)
	}
	res, html := get(lead)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("cra report = %d", res.StatusCode)
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script") {
		t.Errorf("csp = %q", csp)
	}
	for _, want := range []string{
		"Shop &lt;web&gt;",                            // escaped project name
		"No known exploitable vulnerabilities",        // I.2(a)
		"Coordinated vulnerability disclosure policy", // manual → attestation table
		"no VEX statement or finding assessment",      // II.4 evidence
		"Controls for attestation",
		"Reporting of actively exploited vulnerabilities (Art. 14)", // eu-cra only
		"web", "1.0.0", // the SBOM row
	} {
		if !strings.Contains(html, want) {
			t.Errorf("cra report lacks %q", want)
		}
	}
	if res, _ := get(outsider); res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusNotFound {
		t.Errorf("outsider cra report = %d", res.StatusCode)
	}

	// The same report renders for every framework; only eu-cra has Art. 14.
	for _, fw := range []string{"owasp-top-10-2021", "owasp-asvs-5.0", "pci-dss-4.0", "iso-27001-2022", "soc2", "nis2"} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+pid+"/compliance/"+fw+"/report", nil)
		r.Header.Set("Authorization", "Bearer "+lead)
		res, err := app.Test(r, -1)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusOK || !strings.Contains(string(b), "Measured controls") || strings.Contains(string(b), "(Art. 14)") {
			t.Errorf("%s report: %d", fw, res.StatusCode)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+pid+"/compliance/no-such-framework/report", nil)
	r.Header.Set("Authorization", "Bearer "+lead)
	if res, _ := app.Test(r, -1); res.StatusCode != http.StatusNotFound {
		t.Errorf("unknown framework report = %d, want 404", res.StatusCode)
	}
}
