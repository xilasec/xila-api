package scanner

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures under testdata/ are real tool output, trimmed (entries dropped,
// long code blocks / request bodies shortened), never invented. Sources:
//
//   - DefectDojo unit-test scans (BSD-3-Clause),
//     https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans:
//     checkov_frameworks.json  ← checkov/checkov-report-multiple-check_type.json
//     checkov_single.json      ← checkov/checkov-report-severity.json
//     tfsec.json               ← tfsec/many_findings_current.json
//     terrascan.json           ← terrascan/many_findings.json
//     scoutsuite.js            ← scout_suite/two_findings.js
//     clair_scanner.json       ← clair/clair_few_vuln.json
//     anchorectl.json          ← anchorectl_vulns/many_vulns.json
//     polaris.json             ← polaris/polaris_many_vuln.json
//     kubebench_controls.json  ← kubebench/kube-bench-controls.json
//     kubebench_list.json      ← kubebench/kube-bench-report-many-vuln.json
//     burp.xml                 ← burp/seven_findings.xml + burp/one_finding_with_cwe.xml
//     nikto.json, nikto.xml    ← nikto/tdh.json, nikto/tdh.xml
//     nmap_vulners.xml         ← nmap/nmap_script_vulners.xml
//   - clair_v4.json: Quay's Clair v4 VulnerabilityReport fixture (Apache-2.0),
//     https://github.com/quay/quay/blob/master/data/secscan_model/test/vulnerabilityreport.json
//   - docker_scout.sarif: `docker scout cves --format sarif` 1.18.0 output (Apache-2.0),
//     https://github.com/Shaston/Actividad3_Grupo13/blob/main/security/reports/scout-cves.sarif
//   - nmap_vulns.xml: `nmap --script vuln` against HTB "Blue",
//     https://github.com/madneal/htb/blob/master/Blue/vulns.xml
//   - wapiti.json: Wapiti's report-generator fixture (GPL-2.0, test data only),
//     https://github.com/wapiti-scanner/wapiti/blob/master/tests/reports/data/report.json

func parseFixture(t *testing.T, p Parser, name string) []ParsedFinding {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := p.Parse(f)
	if err != nil {
		t.Fatalf("%s: Parse(%s): %v", p.Scanner(), name, err)
	}
	return out
}

func ruleIDs(fs []ParsedFinding) []string {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func findRule(t *testing.T, fs []ParsedFinding, rule string) ParsedFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule {
			return f
		}
	}
	t.Fatalf("no finding with rule %q in %v", rule, ruleIDs(fs))
	return ParsedFinding{}
}

func TestCheckovFrameworkList(t *testing.T) {
	out := parseFixture(t, NewCheckov(), "checkov_frameworks.json")
	// Two failed terraform checks + one failed dockerfile check; the passed
	// checks in both frameworks are not findings.
	if got := ruleIDs(out); !slices.Equal(got, []string{"CKV_AWS_161", "CKV_AWS_16", "CKV_DOCKER_3"}) {
		t.Fatalf("rule ids = %v", got)
	}
	tf := out[0]
	if tf.Category != domain.CategoryIaC || tf.FilePath != "aws/db-app.tf" || tf.Line == nil || *tf.Line != 1 {
		t.Errorf("terraform finding = %+v", tf)
	}
	if tf.Title != "Ensure RDS database has IAM authentication enabled" || tf.Severity != domain.SeverityMedium {
		t.Errorf("title/severity = %q/%s (no severity in OSS output → medium)", tf.Title, tf.Severity)
	}
	if out[2].Metadata["check_type"] != "dockerfile" {
		t.Errorf("dockerfile check type = %v", out[2].Metadata["check_type"])
	}
}

func TestCheckovSingleReportKeepsSeverityAndBenchmarks(t *testing.T) {
	out := parseFixture(t, NewCheckov(), "checkov_single.json")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1 (passed check skipped)", len(out))
	}
	f := out[0]
	if f.RuleID != "CKV_GCP_29" || f.Severity != domain.SeverityMedium || f.FilePath != "gcs.tf" {
		t.Errorf("finding = %+v", f)
	}
	b, _ := f.Metadata["benchmarks"].(map[string]any)
	if _, ok := b["CIS GCP V1.1"]; !ok {
		t.Errorf("benchmarks = %v, want the CIS GCP reference kept", f.Metadata["benchmarks"])
	}
}

func TestCheckovEmptyRun(t *testing.T) {
	// `checkov` with nothing to scan prints only the summary counters.
	out, err := NewCheckov().Parse(strings.NewReader(`{"passed":0,"failed":0,"skipped":0,"parsingerrors":0,"resourcecount":0,"checkov_version":"2.1.269"}`))
	if err != nil || len(out) != 0 {
		t.Fatalf("empty run = %v, %v; want no findings and no error", out, err)
	}
}

func TestTfsecParse(t *testing.T) {
	out := parseFixture(t, NewTfsec(), "tfsec.json")
	if got := ruleIDs(out); !slices.Equal(got, []string{"aws-vpc-no-excessive-port-access", "aws-vpc-no-public-egress-sgr"}) {
		t.Fatalf("rule ids = %v", got)
	}
	f := out[1]
	if f.Severity != domain.SeverityCritical || f.FilePath != "/tmp/aws-eks/modules/security-group/main.tf" || *f.Line != 72 {
		t.Errorf("finding = %+v", f)
	}
	if f.Metadata["legacy_rule_id"] != "AWS007" || !strings.HasPrefix(f.URL, "https://tfsec.dev/") {
		t.Errorf("legacy id / link = %v / %q", f.Metadata["legacy_rule_id"], f.URL)
	}
}

func TestTfsecLegacyAndClean(t *testing.T) {
	// Pre-1.0 tfsec: "passed" bool, WARNING severity, prose link.
	legacy := `{"results":[{"rule_id":"GEN003","rule_description":"Potentially sensitive data stored in block attribute.","rule_provider":"general","link":"See https://tfsec.dev/docs/general/GEN003/ for more information.","location":{"filename":"tfsec-test/identity.tf","start_line":226,"end_line":226},"description":"Block 'keycloak_oidc_identity_provider.google' includes a potentially sensitive attribute which is defined within the project.","impact":"Block attribute could be leaking secrets","resolution":"Don't include sensitive data in blocks","severity":"WARNING","passed":false}]}`
	out, err := NewTfsec().Parse(strings.NewReader(legacy))
	if err != nil || len(out) != 1 {
		t.Fatalf("legacy = %v, %v", out, err)
	}
	if out[0].RuleID != "GEN003" || out[0].Severity != domain.SeverityMedium || out[0].URL != "https://tfsec.dev/docs/general/GEN003/" {
		t.Errorf("legacy finding = %+v", out[0])
	}
	if out, err := NewTfsec().Parse(strings.NewReader(`{"results": null}`)); err != nil || len(out) != 0 {
		t.Errorf("clean run = %v, %v", out, err)
	}
}

func TestTerrascanParse(t *testing.T) {
	out := parseFixture(t, NewTerrascan(), "terrascan.json")
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2", len(out))
	}
	f := out[0]
	if f.RuleID != "accurics.gcp.NS.109" || f.Severity != domain.SeverityHigh || f.FilePath != "cluster.tf" || *f.Line != 52 {
		t.Errorf("finding = %+v", f)
	}
	if f.Metadata["resource"] != "google_container_cluster.k8s_cluster" {
		t.Errorf("resource = %v", f.Metadata["resource"])
	}
}

func TestScoutSuiteParse(t *testing.T) {
	out := parseFixture(t, NewScoutSuite(), "scoutsuite.js")
	// Two rules flagged two buckets each; the rule that flagged nothing is a pass.
	if len(out) != 4 {
		t.Fatalf("findings = %d, want 4: %v", len(out), ruleIDs(out))
	}
	f := out[0]
	if f.RuleID != "cloudstorage-bucket-no-logging" || f.Category != domain.CategoryCloud || f.Severity != domain.SeverityMedium {
		t.Errorf("finding = %+v", f)
	}
	if f.FilePath != "cloudstorage.projects.gcp-project-id.buckets.52fc025e81845686d3c9fe5a5dc4f5e7ae740064" {
		t.Errorf("resource path = %q", f.FilePath)
	}
	if f.Metadata["resource"] != "gcp-project-id.appspot.com" {
		t.Errorf("resource name = %v, want the bucket name resolved from the tree", f.Metadata["resource"])
	}
	if c, _ := f.Metadata["compliance"].([]string); len(c) != 1 || !strings.Contains(c[0], "5.3") {
		t.Errorf("compliance = %v", f.Metadata["compliance"])
	}
	if out[0].FilePath == out[1].FilePath {
		t.Error("each flagged bucket must be its own finding")
	}
}

func TestClairV4Parse(t *testing.T) {
	out := parseFixture(t, NewClair(), "clair_v4.json")
	// The RHSA is matched twice for libnghttp2 (AppStream + BaseOS repos): one finding.
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2: %v", len(out), ruleIDs(out))
	}
	rhsa := findRule(t, out, "RHSA-2023:5837")
	if rhsa.Package != "libnghttp2" || rhsa.PackageVersion != "1.33.0-3.el8_2.1" || rhsa.FixedVersion != "0:1.33.0-5.el8_8" {
		t.Errorf("rhsa = %+v", rhsa)
	}
	if !slices.Equal(rhsa.CVE, []string{"CVE-2023-44487"}) {
		t.Errorf("CVE = %v, want the CVE lifted from the RHSA links", rhsa.CVE)
	}
	if rhsa.Severity != domain.SeverityHigh || rhsa.CVSS == nil || *rhsa.CVSS != 7.5 {
		t.Errorf("severity/cvss = %s/%v", rhsa.Severity, rhsa.CVSS)
	}
	cve := findRule(t, out, "CVE-2018-19211")
	if cve.Package != "ncurses-libs" || cve.Severity != domain.SeverityLow || !slices.Equal(cve.CVE, []string{"CVE-2018-19211"}) {
		t.Errorf("ncurses = %+v", cve)
	}
}

func TestClairAdvisoryID(t *testing.T) {
	cases := map[string]string{
		"RHSA-2023:5837: nghttp2 security update (Important)": "RHSA-2023:5837",
		"CVE-2018-19211 ncurses: Null pointer dereference":    "CVE-2018-19211",
		"GHSA-jq35-85cj-fj4p":                                 "GHSA-jq35-85cj-fj4p",
		// Red Hat's unfixed CVEs carry only a title; the CVE is in the links.
		"curl: cookie injection with none file (low)": "CVE-2023-38546",
	}
	for name, want := range cases {
		links := "https://access.redhat.com/security/cve/CVE-2023-38546"
		if strings.Contains(name, "CVE-2018-19211") {
			links = ""
		}
		if got := clairAdvisoryID(name, cvesInText(name, links)); got != want {
			t.Errorf("clairAdvisoryID(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestClairScannerParse(t *testing.T) {
	out := parseFixture(t, NewClair(), "clair_scanner.json")
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2", len(out))
	}
	f := findRule(t, out, "CVE-2019-5094")
	if f.Package != "e2fsprogs" || f.FixedVersion != "1.44.1-1ubuntu1.2" || f.Severity != domain.SeverityMedium || !slices.Equal(f.CVE, []string{"CVE-2019-5094"}) {
		t.Errorf("finding = %+v", f)
	}
	if f.Metadata["image"] == "" {
		t.Error("image should be recorded")
	}
}

func TestAnchoreParse(t *testing.T) {
	out := parseFixture(t, NewAnchore(), "anchorectl.json")
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2", len(out))
	}
	apt := out[0]
	if apt.RuleID != "CVE-2011-3374" || apt.Package != "apt" || apt.PackageVersion != "1.4.9" || apt.Severity != domain.SeverityLow {
		t.Errorf("apt = %+v (Negligible → low)", apt)
	}
	if apt.FixedVersion != "" || apt.FilePath != "" {
		t.Errorf("\"None\" placeholders must read as empty, got fix=%q path=%q", apt.FixedVersion, apt.FilePath)
	}
	systemd := out[1]
	if systemd.FixedVersion != "232-25+deb9u10" || systemd.Severity != domain.SeverityHigh || !slices.Equal(systemd.CVE, []string{"CVE-2018-15686"}) {
		t.Errorf("systemd = %+v", systemd)
	}
}

func TestDockerScoutReadsScoutExtensions(t *testing.T) {
	out := parseFixture(t, NewDockerScout(), "docker_scout.sarif")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	// Everything below is what generic SARIF loses.
	if f.Purl != "pkg:npm/cross-spawn@7.0.3" || f.Package != "cross-spawn" || f.PackageVersion != "7.0.3" || f.FixedVersion != "7.0.5" {
		t.Errorf("package = %+v", f)
	}
	if !slices.Equal(f.CVE, []string{"CVE-2024-21538"}) || f.CVSS == nil || *f.CVSS != 7.5 || f.Severity != domain.SeverityHigh {
		t.Errorf("cve/cvss/severity = %v/%v/%s", f.CVE, f.CVSS, f.Severity)
	}
	if f.Category != domain.CategoryContainer || f.FilePath != "/usr/local/lib/node_modules/npm/node_modules/cross-spawn/package.json" {
		t.Errorf("category/path = %s/%q", f.Category, f.FilePath)
	}
}

func TestDockerScoutLogicalLocationsAndUnspecifiedSeverity(t *testing.T) {
	// Older Scout (0.x) puts the PURL in logicalLocations and often has no CVSS.
	doc := `{"runs":[{"tool":{"driver":{"name":"docker scout","rules":[{"id":"GMS-2018-10","shortDescription":{"text":"Prototype pollution"},"properties":{"affected_version":"<4.17.5","cvssV3_severity":"UNSPECIFIED","fixed_version":"4.17.5","tags":["UNSPECIFIED"]}}]}},
	"results":[{"ruleId":"GMS-2018-10","ruleIndex":0,"kind":"fail","level":"none","message":{"text":"  Vulnerability  : GMS-2018-10\n  Severity       : UNSPECIFIED\n"},
	"locations":[{"logicalLocations":[{"name":"lodash","fullyQualifiedName":"pkg:npm/lodash@3.10.1","kind":"npm"},{"fullyQualifiedName":"/usr/lib/node_modules/npm/node_modules/lodash/package.json"}]}]}]}]}`
	out, err := NewDockerScout().Parse(strings.NewReader(doc))
	if err != nil || len(out) != 1 {
		t.Fatalf("parse = %v, %v", out, err)
	}
	f := out[0]
	if f.Purl != "pkg:npm/lodash@3.10.1" || f.Package != "lodash" || f.FilePath != "/usr/lib/node_modules/npm/node_modules/lodash/package.json" {
		t.Errorf("location = %+v", f)
	}
	if f.Severity != domain.SeverityMedium || len(f.CVE) != 0 {
		t.Errorf("unspecified severity must stay visible (medium), got %s; cve %v", f.Severity, f.CVE)
	}
}

func TestPurlParts(t *testing.T) {
	cases := map[string][2]string{
		"pkg:npm/cross-spawn@7.0.3":                       {"cross-spawn", "7.0.3"},
		"pkg:npm/%40babel/core@7.0.0":                     {"@babel/core", "7.0.0"},
		"pkg:golang/golang.org/x/net@v0.1.0":              {"golang.org/x/net", "v0.1.0"},
		"pkg:deb/debian/openssl@1.1.1k-1?arch=amd64":      {"openssl", "1.1.1k-1"},
		"pkg:maven/org.apache.logging.log4j/log4j@2.14.1": {"log4j", "2.14.1"},
	}
	for purl, want := range cases {
		if n, v := purlParts(purl); n != want[0] || v != want[1] {
			t.Errorf("purlParts(%q) = %q, %q; want %q, %q", purl, n, v, want[0], want[1])
		}
	}
}

func TestPolarisParse(t *testing.T) {
	out := parseFixture(t, NewPolaris(), "polaris.json")
	// Controller, pod and container levels each contribute their two failures.
	want := []string{"deploymentMissingReplicas", "metadataAndInstanceMismatched", "automountServiceAccountToken", "missingNetworkPolicy", "cpuLimitsMissing", "cpuRequestsMissing"}
	if got := ruleIDs(out); !slices.Equal(got, want) {
		t.Fatalf("rule ids = %v, want %v", got, want)
	}
	c := findRule(t, out, "cpuLimitsMissing")
	if c.Category != domain.CategoryKubernetes || c.Severity != domain.SeverityMedium || c.FilePath != "Deployment generic-app container server" {
		t.Errorf("container finding = %+v", c)
	}
	if dangerSeverity("danger") != domain.SeverityHigh {
		t.Error("danger must map to high")
	}
}

func TestKubeBenchParse(t *testing.T) {
	out := parseFixture(t, NewKubeBench(), "kubebench_controls.json")
	// FAIL and WARN are findings; PASS is not.
	if got := ruleIDs(out); !slices.Equal(got, []string{"1.1.1", "1.1.9", "1.2.6", "1.2.1"}) {
		t.Fatalf("rule ids = %v", got)
	}
	fail, warn := out[0], out[1]
	if fail.Severity != domain.SeverityMedium || warn.Severity != domain.SeverityLow {
		t.Errorf("FAIL/WARN severity = %s/%s, want medium/low", fail.Severity, warn.Severity)
	}
	if fail.Category != domain.CategoryKubernetes || fail.FilePath != "master" || fail.Metadata["benchmark_version"] != "1.6" {
		t.Errorf("fail = %+v", fail)
	}
	if !strings.HasPrefix(fail.Title, "Ensure that the API server pod specification file permissions") {
		t.Errorf("title = %q", fail.Title)
	}

	legacy := parseFixture(t, NewKubeBench(), "kubebench_list.json") // pre-0.6 bare array
	if got := ruleIDs(legacy); !slices.Equal(got, []string{"3.1.1"}) {
		t.Errorf("legacy rule ids = %v", got)
	}
}

func TestBurpParse(t *testing.T) {
	out := parseFixture(t, NewBurp(), "burp.xml")
	if len(out) != 3 {
		t.Fatalf("findings = %d, want 3", len(out))
	}
	sqli := out[0]
	if sqli.RuleID != "1049088" || sqli.Title != "SQL injection" || sqli.Severity != domain.SeverityHigh || sqli.Category != domain.CategoryDAST {
		t.Errorf("sqli = %+v", sqli)
	}
	if sqli.FilePath != "http://bwa/bodgeit/basket.jsp [b_id cookie]" || sqli.Metadata["confidence"] != "Firm" {
		t.Errorf("location/confidence = %q/%v", sqli.FilePath, sqli.Metadata["confidence"])
	}
	if strings.Contains(sqli.Description, "<b>") || !strings.Contains(sqli.Description, "b_id cookie appears to be vulnerable") {
		t.Errorf("description should be detail text without HTML: %q", sqli.Description)
	}
	if out[1].Severity != domain.SeverityInfo {
		t.Errorf("Information → info, got %s", out[1].Severity)
	}
	if c := out[2]; c.CWE == nil || *c.CWE != 524 || c.FilePath != "https://example.com/test/v4/public/users/fake" {
		t.Errorf("cwe finding = %+v", c)
	}
}

func TestNiktoJSONAndXMLAgree(t *testing.T) {
	fromJSON := parseFixture(t, NewNikto(), "nikto.json")
	fromXML := parseFixture(t, NewNikto(), "nikto.xml")
	// Two "uncommon header" observations on "/" share test 999100: one finding.
	if len(fromJSON) != 7 {
		t.Fatalf("json findings = %d, want 7 (8 items, 2 folded): %v", len(fromJSON), ruleIDs(fromJSON))
	}
	hdr := fromJSON[0]
	if hdr.RuleID != "999100" || hdr.FilePath != "www.tdh.com/" || !strings.Contains(hdr.Description, "x-cacheable") || !strings.Contains(hdr.Description, "x-cache'") {
		t.Errorf("folded header finding = %+v", hdr)
	}
	creds := findRule(t, fromJSON, "700007")
	if creds.Severity != domain.SeverityLow || creds.FilePath != "www.tdh.com/status" || creds.Category != domain.CategoryDAST {
		t.Errorf("default-creds finding = %+v", creds)
	}
	if len(fromXML) == 0 || fromXML[0].RuleID != "999100" || fromXML[0].FilePath != "www.tdh.com/" {
		t.Errorf("xml findings = %v", ruleIDs(fromXML))
	}
}

func TestNiktoLiftsCVE(t *testing.T) {
	doc := `{"host":"h","ip":"1.2.3.4","port":"8080","banner":"Apache/2.4.49","vulnerabilities":[{"id":"600575","OSVDB":"0","method":"GET","url":"/cgi-bin/","msg":"Apache/2.4.49 is vulnerable to path traversal (CVE-2021-41773)."}]}`
	out, err := NewNikto().Parse(strings.NewReader(doc))
	if err != nil || len(out) != 1 {
		t.Fatalf("parse = %v, %v", out, err)
	}
	if !slices.Equal(out[0].CVE, []string{"CVE-2021-41773"}) || out[0].FilePath != "h:8080/cgi-bin/" {
		t.Errorf("finding = %+v", out[0])
	}
}

func TestNmapVulners(t *testing.T) {
	out := parseFixture(t, NewNmap(), "nmap_vulners.xml")
	if got := ruleIDs(out); !slices.Equal(got, []string{"open-port", "CVE-2018-15919", "CVE-2017-15906"}) {
		t.Fatalf("rule ids = %v", got)
	}
	port := out[0]
	if port.Severity != domain.SeverityInfo || port.FilePath != "192.168.0.1:5022/tcp" || !strings.Contains(port.Title, "OpenSSH 7.4") {
		t.Errorf("open port = %+v", port)
	}
	v := out[1]
	if v.Severity != domain.SeverityMedium || v.CVSS == nil || *v.CVSS != 5.0 || !slices.Equal(v.CVE, []string{"CVE-2018-15919"}) {
		t.Errorf("vulners = %+v", v)
	}
	if v.Package != "OpenSSH" || v.PackageVersion != "7.4" || v.Metadata["match"] != "service-version" {
		t.Errorf("vulners package/match = %q %q %v", v.Package, v.PackageVersion, v.Metadata["match"])
	}
}

func TestNmapVulnScripts(t *testing.T) {
	out := parseFixture(t, NewNmap(), "nmap_vulns.xml")
	// Three open ports + the one VULNERABLE host script; the "false" smb-vuln
	// results and the prescript's "not vulnerable" are skipped.
	if len(out) != 4 {
		t.Fatalf("findings = %d, want 4: %v", len(out), ruleIDs(out))
	}
	ms17 := findRule(t, out, "smb-vuln-ms17-010")
	if ms17.Severity != domain.SeverityHigh || !slices.Equal(ms17.CVE, []string{"CVE-2017-0143"}) || ms17.FilePath != "10.10.10.40" {
		t.Errorf("ms17-010 = %+v", ms17)
	}
	if !strings.Contains(ms17.Title, "SMBv1") || ms17.URL == "" {
		t.Errorf("title/url = %q/%q", ms17.Title, ms17.URL)
	}
}

func TestWapitiParse(t *testing.T) {
	out := parseFixture(t, NewWapiti(), "wapiti.json")
	// One vulnerability + one anomaly; the "additionals" fingerprint is skipped.
	if got := ruleIDs(out); !slices.Equal(got, []string{"Reflected Cross Site Scripting", "Internal Server Error"}) {
		t.Fatalf("rule ids = %v", got)
	}
	xss := out[0]
	if xss.Severity != domain.SeverityLow || xss.CWE == nil || *xss.CWE != 79 || xss.FilePath != "http://perdu.com/riri [foo]" {
		t.Errorf("xss = %+v", xss)
	}
	if out[1].Severity != domain.SeverityMedium || out[1].Metadata["kind"] != "anomaly" {
		t.Errorf("anomaly = %+v", out[1])
	}
	if wapitiSeverity([]byte(`"4"`)) != domain.SeverityCritical || wapitiSeverity([]byte(`0`)) != domain.SeverityInfo {
		t.Error("Wapiti 3.0 string levels and int levels must both map")
	}
}

// Every new parser rejects garbage and wrong-tool JSON rather than returning a
// silent zero-finding scan.
func TestInfraParsersRejectMalformedInput(t *testing.T) {
	parsers := []Parser{
		NewCheckov(), NewTfsec(), NewTerrascan(), NewScoutSuite(), NewClair(), NewAnchore(),
		NewDockerScout(), NewPolaris(), NewKubeBench(), NewBurp(), NewNikto(), NewNmap(), NewWapiti(),
	}
	for _, p := range parsers {
		for _, input := range []string{"this is not json", `{"some":"other tool"}`} {
			if _, err := p.Parse(strings.NewReader(input)); err == nil {
				t.Errorf("%s: expected an error on %q", p.Scanner(), input)
			}
		}
	}
}
