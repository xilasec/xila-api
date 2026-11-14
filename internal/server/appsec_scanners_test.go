package server

import (
	"bytes"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/xilasec/xila-api/internal/scanner"
)

// TestSmokeAppSecScanners uploads the real application-security and
// import-format samples through the HTTP API. Every finding a parser produces
// must land as its own finding (two colliding on one fingerprint would silently
// overwrite each other on upsert), under the right scanner name — which also
// proves each parser is registered.
func TestSmokeAppSecScanners(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"appsec","name":"AppSec"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"dev","name":"Dev"}`)
	teamID, _ := teamBody["id"].(string)

	cases := []struct {
		parser  scanner.Parser
		fixture string
	}{
		{scanner.NewDefectDojoGeneric(), "defectdojo_generic_docs.json"},
		{scanner.NewSecObserve(), "secobserve_import.json"},
		{scanner.NewSecObserve(), "secobserve_api.json"},
		{scanner.NewSnyk(), "snyk_all_projects.json"},
		{scanner.NewPipAudit(), "pip_audit.json"},
		{scanner.NewSafety(), "safety_recommended_fix.json"},
		{scanner.NewCargoAudit(), "cargo_audit_cvss.json"},
		{scanner.NewRetireJS(), "retirejs.json"},
		{scanner.NewBundlerAudit(), "bundler_audit.json"},
		{scanner.NewSemgrep(), "semgrep.json"},
		{scanner.NewBandit(), "bandit.json"},
		{scanner.NewGosec(), "gosec.json"},
		{scanner.NewBrakeman(), "brakeman.json"},
		{scanner.NewDetectSecrets(), "detect_secrets.json"},
		{scanner.NewGGShield(), "ggshield.json"},
		{scanner.NewHadolint(), "hadolint_many.json"},
		{scanner.NewESLint(), "eslint_scan.json"},
		{scanner.NewYarnAudit(), "yarn_audit_v1.json"},
		{scanner.NewYarnAudit(), "yarn_audit_berry.json"},
		{scanner.NewNJSScan(), "njsscan_many.json"},
		{scanner.NewSonarQube(), "sonarqube_issues.json"},
		{scanner.NewSonarQube(), "sonarqube_hotspots.json"},
		{scanner.NewCheckmarx(), "checkmarx_multiple.xml"},
		{scanner.NewVeracode(), "veracode_many.xml"},
		{scanner.NewMend(), "mend_api3.json"},
		{scanner.NewMend(), "mend_legacy.json"},
		{scanner.NewBearer(), "bearer_many_vul.json"},
		{scanner.NewMobSF(), "mobsf_android_report.json"},
		{scanner.NewMobSF(), "mobsf_mobsfscan_many.json"},
		{scanner.NewJFrogXray(), "jfrog-xray_many_vulns.json"},
		{scanner.NewNancy(), "nancy_many_findings.json"},
		{scanner.NewSpotBugs(), "spotbugs_version_4.4.0.xml"},
		{scanner.NewFortify(), "fortify_audit_simple.fvdl"},
	}
	for i, tc := range cases {
		name := tc.parser.Scanner()
		t.Run(name+"/"+tc.fixture, func(t *testing.T) {
			body, err := os.ReadFile("../scanner/testdata/" + tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := tc.parser.Parse(bytes.NewReader(body))
			if err != nil || len(parsed) == 0 {
				t.Fatalf("fixture parses to %d findings (%v); want a non-empty sample", len(parsed), err)
			}
			_, proj := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin,
				`{"slug":"p-`+strconv.Itoa(i)+`","name":"`+name+`"}`)
			projectID, _ := proj["id"].(string)
			if resp, sc := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner="+name, admin, string(body)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("upload = %d %v", resp.StatusCode, sc)
			}
			_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?limit=200&include_duplicates=true", admin, "")
			fs, _ := list["findings"].([]any)
			if len(fs) != len(parsed) {
				t.Errorf("stored %d findings, parser produced %d — fingerprints collide", len(fs), len(parsed))
			}
			for _, f := range fs {
				if m, _ := f.(map[string]any); m["scanner"] != name {
					t.Errorf("finding scanner = %v, want %s", m["scanner"], name)
				}
			}
		})
	}
}

// Triage carried by an import format lands on newly created findings through
// the real ingest pipeline — and never overturns a local decision on re-import.
func TestImportedTriageNeverOverridesLocal(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"mig","name":"Mig"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"t","name":"T"}`)
	teamID, _ := teamBody["id"].(string)
	_, proj := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"legacy","name":"Legacy"}`)
	projectID, _ := proj["id"].(string)

	const report = `{"findings":[
		{"title":"Old FP","severity":"High","description":"x","unique_id_from_tool":"a1","false_p":true,"active":false},
		{"title":"Accepted","severity":"Medium","description":"x","unique_id_from_tool":"a2","risk_accepted":true,"active":false},
		{"title":"Real one","severity":"Critical","description":"x","unique_id_from_tool":"a3","active":true}
	]}`
	upload := func() {
		t.Helper()
		if resp, sc := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=defectdojo-generic", admin, report); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload = %d %v", resp.StatusCode, sc)
		}
	}
	statuses := func() map[string]any {
		t.Helper()
		_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?limit=50", admin, "")
		out := map[string]any{}
		for _, f := range list["findings"].([]any) {
			m := f.(map[string]any)
			out[m["title"].(string)] = m
		}
		return out
	}

	upload()
	got := statuses()
	for title, want := range map[string]string{"Old FP": "false_positive", "Accepted": "risk_accepted", "Real one": "open"} {
		if f, ok := got[title].(map[string]any); !ok || f["status"] != want {
			t.Errorf("after import %q status = %v, want %s", title, got[title], want)
		}
	}

	// An analyst reopens the imported false positive; the same export uploaded
	// again must not put it back.
	fp := got["Old FP"].(map[string]any)
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+fp["id"].(string), admin, `{"status":"open"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("reopen = %d", resp.StatusCode)
	}
	upload()
	if f := statuses()["Old FP"].(map[string]any); f["status"] != "open" {
		t.Errorf("re-import overturned the local decision: status = %v, want open", f["status"])
	}
}
