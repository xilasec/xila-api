package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// findByRule locates a parsed finding by its rule id.
func findByRule(t *testing.T, findings []ParsedFinding, ruleID string) ParsedFinding {
	t.Helper()
	for _, f := range findings {
		if f.RuleID == ruleID {
			return f
		}
	}
	t.Fatalf("no finding with rule %q (got %d findings)", ruleID, len(findings))
	return ParsedFinding{}
}

func TestGrypeParse(t *testing.T) {
	const report = `{"matches":[
	  {"vulnerability":{"id":"GHSA-jfh8-c2jp-5v3q","severity":"Critical","description":"Log4Shell",
	    "dataSource":"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
	    "fix":{"versions":["2.15.0"],"state":"fixed"},
	    "cvss":[{"metrics":{"baseScore":10.0}}]},
	   "relatedVulnerabilities":[{"id":"CVE-2021-44228"}],
	   "artifact":{"name":"log4j-core","version":"2.14.1","purl":"pkg:maven/log4j-core@2.14.1",
	     "locations":[{"path":"/app/lib/log4j-core-2.14.1.jar"}]}}]}`

	got, err := Grype{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	// The CVE has to come through even though Grype's primary id is a GHSA —
	// that's what lets this dedup against the same issue from Trivy.
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2021-44228" {
		t.Errorf("CVE = %v, want [CVE-2021-44228] (lifted from relatedVulnerabilities)", f.CVE)
	}
	if f.Severity != domain.SeverityCritical || f.Package != "log4j-core" ||
		f.FixedVersion != "2.15.0" || f.Purl != "pkg:maven/log4j-core@2.14.1" {
		t.Errorf("finding = %+v", f)
	}
	if f.CVSS == nil || *f.CVSS != 10.0 {
		t.Errorf("CVSS = %v, want 10", f.CVSS)
	}
}

func TestOSVScannerParse(t *testing.T) {
	const report = `{"results":[{"source":{"path":"/app/go.mod"},"packages":[
	  {"package":{"name":"golang.org/x/net","version":"0.0.1","ecosystem":"Go"},
	   "vulnerabilities":[{"id":"GHSA-vvpx","summary":"HTTP/2 rapid reset",
	     "aliases":["CVE-2023-44487"],"database_specific":{"severity":"HIGH"},
	     "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]}]}]}]}]}`

	got, err := OSVScanner{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Severity != domain.SeverityHigh || f.Package != "golang.org/x/net" ||
		f.FixedVersion != "0.17.0" || len(f.CVE) != 1 || f.CVE[0] != "CVE-2023-44487" {
		t.Errorf("finding = %+v", f)
	}
}

func TestNpmAuditParse(t *testing.T) {
	// "via" is either an advisory object (this package is the vulnerable one) or a
	// string (this package is only affected *through* a dependency).
	const report = `{"vulnerabilities":{
	  "lodash":{"name":"lodash","severity":"high","range":"<4.17.21","via":[
	    {"source":1065,"name":"lodash","title":"Prototype Pollution in lodash",
	     "url":"https://github.com/advisories/GHSA-p6mc","severity":"high",
	     "cwe":["CWE-1321"],"cvss":{"score":7.4},"range":"<4.17.21"}]},
	  "some-wrapper":{"name":"some-wrapper","severity":"high","range":"*","via":["lodash"]}}}`

	got, err := NpmAudit{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The string-via package must NOT produce its own finding: the advisory is
	// already reported against lodash, and emitting it twice would be the very
	// duplication the platform exists to prevent.
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (the transitive wrapper must not duplicate the advisory)", len(got))
	}
	f := got[0]
	if f.Package != "lodash" || f.Severity != domain.SeverityHigh || f.RuleID != "NPM-1065" {
		t.Errorf("finding = %+v", f)
	}
	if f.CWE == nil || *f.CWE != 1321 {
		t.Errorf("CWE = %v, want 1321", f.CWE)
	}
	if f.CVSS == nil || *f.CVSS != 7.4 {
		t.Errorf("CVSS = %v, want 7.4", f.CVSS)
	}
}

func TestDependencyCheckParse(t *testing.T) {
	const report = `{"dependencies":[
	  {"fileName":"jackson-databind-2.9.8.jar","filePath":"/app/libs/jackson-databind-2.9.8.jar",
	   "packages":[{"id":"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8"}],
	   "vulnerabilities":[{"name":"CVE-2020-36518","severity":"HIGH",
	     "description":"Deeply nested JSON causes a StackOverflow",
	     "cvssv3":{"baseScore":7.5},"cwes":["CWE-787"]}]},
	  {"fileName":"clean.jar","filePath":"/app/libs/clean.jar","packages":[],"vulnerabilities":[]}]}`

	got, err := DependencyCheck{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (the clean dependency contributes none)", len(got))
	}
	f := got[0]
	if f.Package != "jackson-databind" || f.PackageVersion != "2.9.8" {
		t.Errorf("package = %q @ %q, want jackson-databind @ 2.9.8 (parsed out of the PURL)",
			f.Package, f.PackageVersion)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2020-36518" || f.Severity != domain.SeverityHigh {
		t.Errorf("finding = %+v", f)
	}
	if f.CWE == nil || *f.CWE != 787 {
		t.Errorf("CWE = %v, want 787", f.CWE)
	}
}

// govulncheck is the one scanner that knows whether the vulnerable code is
// actually *called*. That distinction has to survive into the finding — it is the
// difference between "upgrade now" and "upgrade whenever".
func TestGoVulnCheckSeparatesCalledFromPresent(t *testing.T) {
	const report = `
{"osv":{"id":"GO-2023-1988","summary":"HTML injection in html/template","aliases":["CVE-2023-39319"],
  "affected":[{"package":{"name":"stdlib"},"ranges":[{"events":[{"fixed":"1.21.1"}]}]}]}}
{"osv":{"id":"GO-2022-0969","summary":"HTTP/2 stream leak","aliases":["CVE-2022-41717"]}}
{"finding":{"osv":"GO-2023-1988","fixed_version":"1.21.1",
  "trace":[{"module":"stdlib","version":"go1.21.0","package":"html/template","function":"Parse",
            "position":{"filename":"/app/render.go","line":42}}]}}
{"finding":{"osv":"GO-2022-0969","fixed_version":"1.20.0",
  "trace":[{"module":"golang.org/x/net","version":"v0.4.0"}]}}
`
	got, err := GoVulnCheck{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}

	called := findByRule(t, got, "GO-2023-1988")
	if called.Severity != domain.SeverityHigh {
		t.Errorf("a vulnerability whose code IS called must stay high, got %q", called.Severity)
	}
	if called.Metadata["called"] != true || called.Metadata["called_symbol"] != "html/template.Parse" {
		t.Errorf("metadata = %v, want the reached symbol recorded", called.Metadata)
	}
	if called.FilePath != "/app/render.go" || called.Line == nil || *called.Line != 42 {
		t.Errorf("the call site in your own code must be reported: %q:%v", called.FilePath, called.Line)
	}
	if len(called.CVE) != 1 || called.CVE[0] != "CVE-2023-39319" {
		t.Errorf("CVE = %v", called.CVE)
	}

	notCalled := findByRule(t, got, "GO-2022-0969")
	if notCalled.Severity != domain.SeverityLow {
		t.Errorf("a vulnerability whose code is never called must be downgraded, got %q", notCalled.Severity)
	}
	if notCalled.Metadata["called"] != false {
		t.Errorf("metadata = %v, want called=false", notCalled.Metadata)
	}
	if !strings.Contains(notCalled.Title, "not called") {
		t.Errorf("title should say the code isn't called, got %q", notCalled.Title)
	}
}

// govulncheck emits several findings per vulnerability, at increasing trace
// depth. The most specific one wins — otherwise a symbol-level (reachable) hit
// could be overwritten by the module-level one that follows it.
func TestGoVulnCheckKeepsMostSpecificTrace(t *testing.T) {
	const report = `
{"osv":{"id":"GO-1","summary":"x"}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1"}]}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1","package":"m/pkg","function":"Vuln"}]}}
`
	got, err := GoVulnCheck{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 (the traces are the same vulnerability)", len(got))
	}
	if got[0].Metadata["called"] != true {
		t.Errorf("the symbol-level trace must win, got metadata %v", got[0].Metadata)
	}
}

func TestGitleaksParse(t *testing.T) {
	const report = `[{"Description":"AWS Access Key","RuleID":"aws-access-token",
	  "File":"config/prod.env","StartLine":12,"Commit":"abc123","Author":"dev",
	  "Email":"dev@example.com","Entropy":4.2}]`

	got, err := Gitleaks{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	// A leaked credential has no "maybe": it's in the history and must be rotated.
	if f.Severity != domain.SeverityHigh || f.Category != domain.CategorySecret {
		t.Errorf("finding = %+v", f)
	}
	if f.FilePath != "config/prod.env" || f.Line == nil || *f.Line != 12 {
		t.Errorf("location = %q:%v", f.FilePath, f.Line)
	}
	// The commit is the triage: who leaked it, and when.
	if f.Metadata["commit"] != "abc123" || f.Metadata["author"] != "dev" {
		t.Errorf("metadata = %v, want the commit provenance", f.Metadata)
	}
}

// TruffleHog verifies credentials against the provider. A verified secret is a
// live, working key — that is categorically worse than a string that looks like one.
func TestTruffleHogVerifiedIsCritical(t *testing.T) {
	const report = `
{"SourceMetadata":{"Data":{"Git":{"file":"src/app.py","line":7,"commit":"deadbeef","repository":"git@github.com:acme/app.git"}}},"DetectorName":"AWS","Verified":true,"Raw":"AKIA…"}
{"SourceMetadata":{"Data":{"Filesystem":{"file":"tests/fixture.json","line":3}}},"DetectorName":"Stripe","Verified":false,"Raw":"sk_test_…"}
`
	got, err := TruffleHog{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2", len(got))
	}

	verified := findByRule(t, got, "AWS")
	if verified.Severity != domain.SeverityCritical {
		t.Errorf("a VERIFIED live credential must be critical, got %q", verified.Severity)
	}
	if verified.FilePath != "src/app.py" || verified.Metadata["verified"] != true {
		t.Errorf("finding = %+v", verified)
	}

	unverified := findByRule(t, got, "Stripe")
	if unverified.Severity != domain.SeverityHigh {
		t.Errorf("an unverified match is high, not critical, got %q", unverified.Severity)
	}
	if unverified.FilePath != "tests/fixture.json" {
		t.Errorf("filesystem source location = %q", unverified.FilePath)
	}
}

func TestZapParse(t *testing.T) {
	const report = `{"site":[{"@name":"https://app.example.com","alerts":[
	  {"pluginid":"40018","alertRef":"40018-1","name":"SQL Injection",
	   "riskdesc":"High (Medium)","desc":"<p>SQL injection may be possible.</p>",
	   "solution":"<p>Use parameterized queries.</p>","cweid":"89",
	   "instances":[{"uri":"https://app.example.com/search?q=1","method":"GET","param":"q"}]}]}]}`

	got, err := Zap{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	// ZAP encodes risk and confidence in one string: "High (Medium)".
	if f.Severity != domain.SeverityHigh || f.Metadata["confidence"] != "Medium" {
		t.Errorf("severity/confidence = %q / %v", f.Severity, f.Metadata["confidence"])
	}
	if f.Category != domain.CategoryDAST || f.CWE == nil || *f.CWE != 89 {
		t.Errorf("finding = %+v", f)
	}
	// The proof URL is what a developer reproduces with.
	if f.FilePath != "https://app.example.com/search?q=1" {
		t.Errorf("evidence URL = %q", f.FilePath)
	}
	// ZAP wraps its prose in HTML; findings should read as text.
	if strings.Contains(f.Description, "<p>") {
		t.Errorf("description still contains HTML: %q", f.Description)
	}
}

func TestNucleiParse(t *testing.T) {
	const report = `
{"template-id":"CVE-2021-44228","type":"http","host":"https://app.example.com","matched-at":"https://app.example.com/api",
 "info":{"name":"Apache Log4j RCE","severity":"critical","description":"JNDI injection",
   "reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],"tags":["cve","rce"],
   "classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-score":10.0}}}
`
	got, err := Nuclei{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.Severity != domain.SeverityCritical || f.Category != domain.CategoryDAST {
		t.Errorf("finding = %+v", f)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2021-44228" || f.CWE == nil || *f.CWE != 502 {
		t.Errorf("CVE = %v CWE = %v", f.CVE, f.CWE)
	}
	if f.FilePath != "https://app.example.com/api" || f.CVSS == nil || *f.CVSS != 10 {
		t.Errorf("finding = %+v", f)
	}
}

// Every parser must reject garbage rather than silently return nothing: a scan
// that "succeeds" with zero findings because the upload was malformed is how a
// broken pipeline looks green for months.
func TestParsersRejectMalformedInput(t *testing.T) {
	parsers := []Parser{
		NewGrype(), NewOSVScanner(), NewNpmAudit(), NewDependencyCheck(),
		NewGitleaks(), NewZap(),
	}
	for _, p := range parsers {
		if _, err := p.Parse(strings.NewReader("this is not json")); err == nil {
			t.Errorf("%s: expected an error on malformed input", p.Scanner())
		}
	}
}

// Severity vocabularies differ wildly between tools; the mapping is central so it
// only has to be right once.
func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]domain.Severity{
		"CRITICAL": domain.SeverityCritical, "Critical": domain.SeverityCritical,
		"High": domain.SeverityHigh, "important": domain.SeverityHigh, "error": domain.SeverityHigh,
		"Medium": domain.SeverityMedium, "moderate": domain.SeverityMedium, "warning": domain.SeverityMedium,
		"Low": domain.SeverityLow, "negligible": domain.SeverityLow, "note": domain.SeverityLow,
		"informational": domain.SeverityInfo, "unknown": domain.SeverityInfo,
		// Anything we don't recognize stays visible as medium rather than being
		// quietly demoted to info.
		"bananas": domain.SeverityMedium,
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}
