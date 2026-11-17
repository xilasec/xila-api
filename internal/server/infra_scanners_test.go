package server

import (
	"net/http"
	"os"
	"slices"
	"strconv"
	"testing"
)

// TestSmokeInfraScanners uploads the real IaC / container / Kubernetes / DAST
// sample reports from internal/scanner/testdata through the HTTP API and checks
// each one lands as the expected number of findings, keyed by the tool's check
// id. It catches what a parser unit test can't: two parsed findings colliding on
// one fingerprint (and silently overwriting each other on upsert), or a parser
// missing from the registry.
func TestSmokeInfraScanners(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"infra","name":"Infra"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"ops","name":"Ops"}`)
	teamID, _ := teamBody["id"].(string)

	cases := []struct {
		scanner, fixture string
		findings         int
		rule             string // a rule_id that must be among them
	}{
		{"checkov", "checkov_frameworks.json", 3, "CKV_DOCKER_3"},
		{"tfsec", "tfsec.json", 2, "aws-vpc-no-public-egress-sgr"},
		{"terrascan", "terrascan.json", 2, "accurics.gcp.NS.109"},
		{"scoutsuite", "scoutsuite.js", 4, "cloudstorage-bucket-no-logging"},
		{"clair", "clair_v4.json", 2, "RHSA-2023:5837"},
		{"anchore", "anchorectl.json", 2, "CVE-2018-15686"},
		{"docker-scout", "docker_scout.sarif", 1, "CVE-2024-21538"},
		{"polaris", "polaris.json", 6, "cpuLimitsMissing"},
		{"kube-bench", "kubebench_controls.json", 4, "1.1.1"},
		{"burp", "burp.xml", 3, "1049088"},
		{"nikto", "nikto.json", 7, "700007"},
		{"nmap", "nmap_vulners.xml", 3, "CVE-2018-15919"},
		{"wapiti", "wapiti.json", 2, "Reflected Cross Site Scripting"},
		{"kics", "kics_many.json", 15, "f996f3cb-00fc-480c-8973-8ab04d44a8cc"},
		{"nessus", "nessus_cvssv3.nessus", 25, "40984"},
		{"openvas", "openvas_many.xml", 44, "1.3.6.1.4.1.25623.1.0.100111"},
		{"qualys", "qualys_asset_data.xml", 8, "70000"},
		{"acunetix", "acunetix_example.xml", 7, "/Crawler/12-Crawler_Form_NO_CSRF.js"},
		{"invicti", "invicti_issue_10311.json", 3, "CookieNotMarkedAsSecure"},
		{"testssl", "testssl_many_vuln.csv", 4, "cipherlist_AVERAGE"},
		{"cryptolyzer", "cryptolyzer_tls10.json", 6, "weak-protocols"},
		{"drheader", "drheader_multiple_urls.json", 4, "X-Frame-Options"},
		{"aws-inspector2", "aws-inspector2_many_vul.json", 8, "CVE-2024-37021"},
		{"aws-security-hub", "aws-security-hub_config_multiple_resources.json", 5, "aws-foundational-security-best-practices/v/1.0.0/EC2.2"},
		{"aws-security-hub", "aws-security-hub_guardduty.json", 4, "TTPs/Defense Evasion/DefenseEvasion:EC2-UnusualDNSResolver"},
		{"cloudsploit", "cloudsploit_many_vul.json", 4, "flowLogsEnabled"},
		{"arachni", "arachni_xss.json", 1, "xss"},
		{"steampipe", "steampipe_s3_benchmark.json", 2, "aws_compliance.control.s3_bucket_versioning_enabled"},
		{"steampipe", "steampipe_custom_summary.json", 8, "control.INF_001"},
	}
	for i, tc := range cases {
		t.Run(tc.scanner+"/"+tc.fixture, func(t *testing.T) {
			body, err := os.ReadFile("../scanner/testdata/" + tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			_, proj := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin,
				`{"slug":"p-`+strconv.Itoa(i)+`","name":"`+tc.scanner+`"}`)
			projectID, _ := proj["id"].(string)
			if projectID == "" {
				t.Fatalf("project setup failed: %v", proj)
			}
			resp, sc := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner="+tc.scanner, admin, string(body))
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("upload = %d %v", resp.StatusCode, sc)
			}
			_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?limit=100", admin, "")
			fs, _ := list["findings"].([]any)
			var rules []string
			for _, f := range fs {
				m, _ := f.(map[string]any)
				if m["scanner"] != tc.scanner {
					t.Errorf("finding scanner = %v, want %s", m["scanner"], tc.scanner)
				}
				r, _ := m["rule_id"].(string)
				rules = append(rules, r)
			}
			if len(fs) != tc.findings {
				t.Errorf("findings = %d, want %d: %v", len(fs), tc.findings, rules)
			}
			if !slices.Contains(rules, tc.rule) {
				t.Errorf("rule_ids %v lack %q", rules, tc.rule)
			}
		})
	}
}
