package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures from SecObserve backend/unittests/import_observations/parsers/
// cryptolyzer/files (BSD-3-Clause, commit f00df83):
//
//	cryptolyzer_multiple.json ← multiple_observations.json
//	cryptolyzer_tls10.json    ← tls10.json (tls-v1-0.badssl.com)
//	cryptolyzer_modern.json   ← no_observations.json (mozilla-modern.badssl.com)
//
// and DefectDojo unittests/scans/drheader (BSD-3-Clause, commit f6cee25):
//
//	drheader_scan.json, drheader_scan2.json, drheader_scan3.json,
//	drheader_multiple_urls.json, drheader_no_vulns.json (empty)

func TestCryptoLyzerAgainstBSI(t *testing.T) {
	out := parseFixture(t, NewCryptoLyzer(), "cryptolyzer_multiple.json")
	// TLS 1.2/1.3 only and every cipher suite recommended (CryptoLyzer's
	// prefix-less names included); X448 and the SHA-1/SHA-224 signatures
	// aren't, and the server offers suites without forward secrecy.
	if got := ruleIDs(out); !slices.Equal(got, []string{"elliptic-curves", "signature-algorithms", "non_forward_secret"}) {
		t.Fatalf("rules = %v", got)
	}
	curves := findRule(t, out, "elliptic-curves")
	if curves.Severity != domain.SeverityMedium || curves.FilePath != "www.example.org:443" || curves.Category != domain.CategoryDAST ||
		!slices.Equal(curves.Metadata["offered"].([]string), []string{"X448"}) || curves.Metadata["ip"] != "192.168.0.1" {
		t.Errorf("curves = %+v", curves)
	}
	if sig := findRule(t, out, "signature-algorithms"); !slices.Equal(sig.Metadata["offered"].([]string), []string{"RSA_SHA1", "RSA_SHA224"}) {
		t.Errorf("signature algorithms = %v", sig.Metadata["offered"])
	}
}

func TestCryptoLyzerOldTLS(t *testing.T) {
	out := parseFixture(t, NewCryptoLyzer(), "cryptolyzer_tls10.json")
	if got := ruleIDs(out); !slices.Equal(got, []string{"weak-protocols", "tls1_2-cipher-suites", "signature-algorithms", "sweet32", "lucky13", "non_forward_secret"}) {
		t.Fatalf("rules = %v", got)
	}
	weak := findRule(t, out, "weak-protocols")
	if weak.Severity != domain.SeverityHigh || weak.FilePath != "tls-v1-0.badssl.com:443" ||
		!slices.Equal(weak.Metadata["offered"].([]string), []string{"tls1", "tls1_1"}) {
		t.Errorf("weak protocols = %+v", weak)
	}
	// Attack verdicts carry the attack's CVE, so they deduplicate with
	// testssl.sh reporting the same flaw on the same host.
	if f := findRule(t, out, "sweet32"); f.Severity != domain.SeverityMedium || !slices.Equal(f.CVE, []string{"CVE-2016-2183"}) {
		t.Errorf("SWEET32 = %+v", f)
	}
	if f := findRule(t, out, "lucky13"); f.Severity != domain.SeverityLow || !slices.Equal(f.CVE, []string{"CVE-2013-0169"}) {
		t.Errorf("LUCKY13 = %+v", f)
	}
	ciphers := findRule(t, out, "tls1_2-cipher-suites")
	// TLS 1.2 offers static-RSA key exchange (no forward secrecy), which BSI
	// doesn't recommend; its ECDHE suites are fine.
	if !strings.Contains(ciphers.Description, "TLS_RSA_WITH_AES_128_GCM_SHA256") || strings.Contains(ciphers.Description, "TLS_ECDHE_") {
		t.Errorf("TLS 1.2 cipher description = %q", ciphers.Description)
	}
}

func TestCryptoLyzerModernServer(t *testing.T) {
	// Everything offered is BSI-recommended; only the attack verdicts remain.
	out := parseFixture(t, NewCryptoLyzer(), "cryptolyzer_modern.json")
	if got := ruleIDs(out); !slices.Equal(got, []string{"lucky13", "non_forward_secret"}) {
		t.Fatalf("rules = %v", got)
	}
	if _, err := NewCryptoLyzer().Parse(strings.NewReader(`{"findings":[]}`)); err == nil {
		t.Error("a non-CryptoLyzer document must be rejected")
	}
}

func TestDrHeaderSingleURL(t *testing.T) {
	out := parseFixture(t, NewDrHeader(), "drheader_scan.json")
	if got := ruleIDs(out); !slices.Equal(got, []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "Referrer-Policy", "Cache-Control", "Pragma"}) {
		t.Fatalf("rules = %v", got)
	}
	csp := findRule(t, out, "Content-Security-Policy")
	if csp.Severity != domain.SeverityHigh || csp.Category != domain.CategoryDAST || *csp.CWE != 693 ||
		!strings.Contains(csp.Description, "Observed: upgrade-insecure-requests") || !strings.Contains(csp.Description, "default-src 'self'") {
		t.Errorf("CSP = %+v", csp)
	}
	if f := findRule(t, out, "Cache-Control"); *f.CWE != 525 {
		t.Errorf("Cache-Control CWE = %d, want 525", *f.CWE)
	}
}

func TestDrHeaderFoldsOneHeadersProblems(t *testing.T) {
	// scan2: three CSP violations (one high, two medium) are one finding.
	out := parseFixture(t, NewDrHeader(), "drheader_scan2.json")
	if len(out) != 4 {
		t.Fatalf("findings = %d (%v), want 4", len(out), ruleIDs(out))
	}
	csp := findRule(t, out, "Content-Security-Policy")
	if csp.Severity != domain.SeverityHigh || !strings.Contains(csp.Description, "Must-Avoid directive included") {
		t.Errorf("folded CSP = %+v", csp)
	}
	// scan3: three Set-Cookie violations fold too; Server is information exposure.
	out = parseFixture(t, NewDrHeader(), "drheader_scan3.json")
	if len(out) != 9 || *findRule(t, out, "Server").CWE != 200 || *findRule(t, out, "Set-Cookie").CWE != 614 {
		t.Errorf("scan3 = %v", ruleIDs(out))
	}
}

func TestDrHeaderBulkAndEmpty(t *testing.T) {
	out := parseFixture(t, NewDrHeader(), "drheader_multiple_urls.json")
	if len(out) != 4 {
		t.Fatalf("findings = %d, want 4", len(out))
	}
	if f := findRule(t, out, "X-Frame-Options"); f.FilePath != "http://example2.com" || f.URL != "http://example2.com" {
		t.Errorf("bulk location = %q", f.FilePath)
	}
	if out := parseFixture(t, NewDrHeader(), "drheader_no_vulns.json"); out == nil || len(out) != 0 {
		t.Errorf("empty report = %#v, want none", out)
	}
	if _, err := NewDrHeader().Parse(strings.NewReader(`[{"foo":"bar"}]`)); err == nil {
		t.Error("an entry without a rule must be rejected")
	}
}
