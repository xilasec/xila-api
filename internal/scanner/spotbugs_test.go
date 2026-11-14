package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture: DefectDojo unittests/scans/spotbugs/version_4.4.0.xml (BSD-3-Clause),
// trimmed to 4 BugInstances spanning both priority levels the report uses.
func TestSpotBugsParse(t *testing.T) {
	out := parseFixture(t, NewSpotBugs(), "spotbugs_version_4.4.0.xml")
	if len(out) != 4 {
		t.Fatalf("got %d findings, want 4", len(out))
	}
	for _, f := range out {
		if f.Category != domain.CategorySAST {
			t.Errorf("category = %s, want sast", f.Category)
		}
	}

	hardcoded := findByRule(t, out, "DMI_HARDCODED_ABSOLUTE_FILENAME")
	if hardcoded.Severity != domain.SeverityHigh || hardcoded.FilePath != "Boot.java" ||
		hardcoded.Line == nil || *hardcoded.Line != 23 {
		t.Errorf("DMI finding = %+v", hardcoded)
	}
	if hardcoded.Metadata["category"] != "STYLE" || hardcoded.Metadata["class"] != "Boot" {
		t.Errorf("DMI metadata = %v", hardcoded.Metadata)
	}

	wmi := findByRule(t, out, "WMI_WRONG_MAP_ITERATOR")
	if wmi.Severity != domain.SeverityMedium || wmi.Line == nil || *wmi.Line != 210 {
		t.Errorf("WMI finding = %+v (priority 2 -> medium)", wmi)
	}

	ei := findByRule(t, out, "EI_EXPOSE_REP")
	if ei.FilePath != "Log.java" || ei.Line == nil || *ei.Line != 9 {
		t.Errorf("EI finding = %+v", ei)
	}
}

func TestSpotBugsRejectsMalformed(t *testing.T) {
	if _, err := NewSpotBugs().Parse(strings.NewReader(`<niktoscan/>`)); err == nil {
		t.Error("want error for non-SpotBugs XML")
	}
	if _, err := NewSpotBugs().Parse(strings.NewReader("not xml")); err == nil {
		t.Error("want error for non-XML input")
	}
}
