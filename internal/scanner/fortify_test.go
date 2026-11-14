package scanner

import (
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture: trimmed from SonarQubeCommunity/sonar-fortify's
// sonar-fortify-plugin/src/test/resources/project/audit-simple.fvdl (a real
// Fortify SCA audit.fvdl, used as that plugin's own parser test fixture),
// kept to 3 <Vulnerability> entries (two sharing one ClassID, one with an
// inactive/unknown rule) plus the matching <Description> for the CWE.
func TestFortifyParseFVDL(t *testing.T) {
	out := parseFixture(t, NewFortify(), "fortify_audit_simple.fvdl")
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	for _, f := range out {
		if f.Category != domain.CategorySAST {
			t.Errorf("category = %s, want sast", f.Category)
		}
	}

	xss := out[0]
	if xss.RuleID != "45BF957F-1A34-4E28-9B34-FEB83EC96792" || xss.Title != "Unreleased Resource: Database" {
		t.Errorf("finding = %+v", xss)
	}
	if xss.FilePath != "WebContent/main.jsp" || xss.Line == nil || *xss.Line != 163 {
		t.Errorf("location = %q:%v", xss.FilePath, xss.Line)
	}
	if xss.CWE == nil || *xss.CWE != 79 {
		t.Errorf("CWE = %v, want 79 (first id in \"CWE ID 79, 80\")", xss.CWE)
	}
	// No EngineData/RuleInfo in this trimmed fixture, so severity falls back to
	// the raw InstanceSeverity score (4.0 -> critical).
	if xss.Severity != domain.SeverityCritical {
		t.Errorf("severity = %s, want critical (InstanceSeverity 4.0)", xss.Severity)
	}

	// The third vulnerability shares the same ClassID but FVDL omits the
	// repeated <ClassInfo> descriptive fields; the parser must still resolve
	// its title/CWE from the first occurrence.
	third := out[2]
	if third.RuleID != xss.RuleID || third.Title != xss.Title || third.CWE == nil || *third.CWE != 79 {
		t.Errorf("third finding = %+v, want same class info as first", third)
	}
	if third.FilePath != "WebContent/foo.jsp" {
		t.Errorf("third location = %q", third.FilePath)
	}

	// The second vulnerability's ClassID ("FOO-BAR") has no matching
	// <Description>, so it gets no CWE and falls back to its own id as title.
	unknown := out[1]
	if unknown.Title != "FOO-BAR" || unknown.CWE != nil {
		t.Errorf("unknown-rule finding = %+v", unknown)
	}
}

// Fortify's own tooling exports a zipped .fpr with audit.fvdl inside; the
// parser must accept that too.
func TestFortifyParseFPRZip(t *testing.T) {
	fvdl, err := os.ReadFile("testdata/fortify_audit_simple.fvdl")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("audit.fvdl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(fvdl); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := NewFortify().Parse(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("parse .fpr: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("got %d findings from .fpr, want 3", len(out))
	}
}

func TestFortifyRejectsMalformed(t *testing.T) {
	if _, err := NewFortify().Parse(strings.NewReader(`<niktoscan/>`)); err == nil {
		t.Error("want error for non-Fortify XML")
	}
	if _, err := NewFortify().Parse(strings.NewReader("not xml")); err == nil {
		t.Error("want error for non-XML input")
	}
	// A zip with no audit.fvdl inside.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("other.txt")
	_, _ = w.Write([]byte("hi"))
	_ = zw.Close()
	if _, err := NewFortify().Parse(bytes.NewReader(buf.Bytes())); err == nil {
		t.Error("want error for .fpr zip without audit.fvdl")
	}
}
