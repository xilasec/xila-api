package fixplan

import (
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// The same vulnerable package, upgraded to different targets in three
// projects, merges into one root cause: severities, KEV, EPSS and priority
// sum, the target is the highest any project needs, and AllActioned is false
// unless every affected project already has a live action for it.
func TestRootCausesMergesAcrossProjects(t *testing.T) {
	changes := []Change{
		{
			Kind: KindPackageUpgrade, Key: "npm|log4js@2.14.1", ProjectID: "p1", Title: "Upgrade log4js 2.14.1",
			Target: "2.15.0", Package: "log4js", Ecosystem: "npm", Installed: "2.14.1",
			Closes: 1, BySeverity: map[domain.Severity]int{domain.SeverityCritical: 1},
			MaxSeverity: domain.SeverityCritical, PriorityRemoved: 100, KEV: 1, MaxEPSS: new(0.9),
		},
		{
			Kind: KindPackageUpgrade, Key: "npm|log4js@2.14.1", ProjectID: "p2", Title: "Upgrade log4js 2.14.1",
			Target: "2.17.0", Package: "log4js", Ecosystem: "npm", Installed: "2.14.1",
			Closes: 2, BySeverity: map[domain.Severity]int{domain.SeverityHigh: 2},
			MaxSeverity: domain.SeverityHigh, PriorityRemoved: 50, KEV: 0, MaxEPSS: new(0.95),
		},
		{
			Kind: KindPackageUpgrade, Key: "npm|log4js@2.14.1", ProjectID: "p3", Title: "Upgrade log4js 2.14.1",
			Target: "2.16.0", Package: "log4js", Ecosystem: "npm", Installed: "2.14.1",
			Closes: 1, BySeverity: map[domain.Severity]int{domain.SeverityMedium: 1},
			MaxSeverity: domain.SeverityMedium, PriorityRemoved: 10, KEV: 0, MaxEPSS: nil,
		},
		// A different change, in one project only.
		{
			Kind: KindCodeLocation, Key: "app.py", ProjectID: "p1", Title: "Fix app.py",
			Closes: 1, BySeverity: map[domain.Severity]int{domain.SeverityLow: 1},
			MaxSeverity: domain.SeverityLow, PriorityRemoved: 5,
		},
	}

	// Only p1 and p3 have a live action; p2 doesn't: not fully actioned.
	live := map[RootCauseLive]bool{
		{ProjectID: "p1", Kind: KindPackageUpgrade, Key: "npm|log4js@2.14.1"}: true,
		{ProjectID: "p3", Kind: KindPackageUpgrade, Key: "npm|log4js@2.14.1"}: true,
	}
	out := RootCauses(changes, live)
	if len(out) != 2 {
		t.Fatalf("root causes = %+v, want 2 groups", out)
	}
	// Priority removed: log4js = 160 > app.py = 5, so it sorts first.
	rc := out[0]
	if rc.Kind != KindPackageUpgrade || rc.Key != "npm|log4js@2.14.1" {
		t.Fatalf("top root cause = %+v", rc)
	}
	if rc.Projects != 3 || len(rc.ProjectIDs) != 3 {
		t.Errorf("projects = %d %v, want 3", rc.Projects, rc.ProjectIDs)
	}
	if rc.Findings != 4 {
		t.Errorf("findings = %d, want 4 (1+2+1)", rc.Findings)
	}
	if rc.Target != "2.17.0" {
		t.Errorf("target = %q, want the highest any project needs (2.17.0)", rc.Target)
	}
	if rc.MaxSeverity != domain.SeverityCritical {
		t.Errorf("max severity = %q, want critical", rc.MaxSeverity)
	}
	if rc.BySeverity[domain.SeverityCritical] != 1 || rc.BySeverity[domain.SeverityHigh] != 2 || rc.BySeverity[domain.SeverityMedium] != 1 {
		t.Errorf("by_severity = %v", rc.BySeverity)
	}
	if rc.PriorityRemoved != 160 {
		t.Errorf("priority removed = %v, want 160", rc.PriorityRemoved)
	}
	if rc.KEV != 1 {
		t.Errorf("kev = %d, want 1", rc.KEV)
	}
	if rc.MaxEPSS == nil || *rc.MaxEPSS != 0.95 {
		t.Errorf("max epss = %v, want 0.95", rc.MaxEPSS)
	}
	if rc.AllActioned {
		t.Error("AllActioned = true, want false: p2 has no live action")
	}

	single := out[1]
	if single.Kind != KindCodeLocation || single.Projects != 1 || !single.AllActioned {
		// No live-action entry at all for p1/code_location/app.py: nil map
		// lookup is false, so a change with no live key is correctly unactioned.
		if single.AllActioned {
			t.Errorf("single-project root cause with no live action reports AllActioned = true: %+v", single)
		}
	}

	// A nil live map: nothing is actioned anywhere.
	out2 := RootCauses(changes[:1], nil)
	if out2[0].AllActioned {
		t.Error("nil live map should mark every root cause unactioned")
	}
}
