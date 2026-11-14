package vulnmatch

import (
	"context"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
)

// --- fakes ---

type fakeInventory struct {
	items    []sbom.SnapshotComponent
	recorded []sbom.SnapshotVuln
	sboms    []string
	// current overrides a project's current snapshots, simulating an upload that
	// lands while the match is running; default: the Current items.
	current map[string][]string
}

func (f *fakeInventory) ListSnapshotInventory(context.Context, string) ([]sbom.SnapshotComponent, error) {
	return f.items, nil
}

func (f *fakeInventory) RecordMatches(_ context.Context, sbomIDs []string, m []sbom.SnapshotVuln) error {
	f.sboms, f.recorded = sbomIDs, m
	return nil
}

func (f *fakeInventory) LockProject(context.Context, string) (func(), error) { return func() {}, nil }

func (f *fakeInventory) CurrentSnapshots(_ context.Context, projectID, versionID string) ([]string, error) {
	if ids, ok := f.current[projectID]; ok {
		return ids, nil
	}
	var ids []string
	for _, c := range f.items {
		if c.Current && c.ProjectID == projectID && c.VersionID == versionID && !slices.Contains(ids, c.SbomID) {
			ids = append(ids, c.SbomID)
		}
	}
	slices.Sort(ids)
	return ids, nil
}

type fakeSource struct {
	byPurl    map[string][]Vuln
	gotPurls  []string
	callCount int
}

func (f *fakeSource) Query(_ context.Context, purls []string) (map[string][]Vuln, error) {
	f.callCount++
	f.gotPurls = purls
	return f.byPurl, nil
}

type applied struct {
	projectID string
	versionID string
	scanner   string
	findings  []finding.Finding
	additive  bool // AddFindings: nothing auto-closed
}

type fakeApplier struct{ calls []applied }

func (f *fakeApplier) ApplyFindings(_ context.Context, projectID, versionID, scanner string, _ domain.Category, fs []finding.Finding) (scan.Scan, error) {
	f.calls = append(f.calls, applied{projectID: projectID, versionID: versionID, scanner: scanner, findings: fs})
	return scan.Scan{ID: "scan-1"}, nil
}

func (f *fakeApplier) AddFindings(_ context.Context, projectID, versionID, scanner string, _ domain.Category, fs []finding.Finding) (scan.Scan, error) {
	f.calls = append(f.calls, applied{projectID: projectID, versionID: versionID, scanner: scanner, findings: fs, additive: true})
	return scan.Scan{ID: "scan-1"}, nil
}

// Each branch's current SBOM produces findings on that branch only: main
// upgraded qs, feature/x still ships the vulnerable one — so main gets an
// empty (closing) application and feature/x keeps its finding.
func TestMatchAppliesEachVersionSeparately(t *testing.T) {
	inv := &fakeInventory{items: []sbom.SnapshotComponent{
		{SbomID: "main-2", ProjectID: "p1", VersionID: "main", Name: "qs", Version: "6.11.0", Purl: "pkg:npm/qs@6.11.0", Current: true},
		{SbomID: "feat-1", ProjectID: "p1", VersionID: "feature", Name: "qs", Version: "6.7.0", Purl: "pkg:npm/qs@6.7.0", Current: true},
	}}
	src := &fakeSource{byPurl: map[string][]Vuln{"pkg:npm/qs@6.7.0": {{ID: "GHSA-qs", Severity: domain.SeverityHigh}}}}
	app := &fakeApplier{}
	if _, err := NewService(inv, app, src).Match(context.Background()); err != nil {
		t.Fatalf("Match: %v", err)
	}
	got := map[string]int{}
	for _, c := range app.calls {
		got[c.versionID] = len(c.findings)
	}
	if len(app.calls) != 2 || got["main"] != 0 || got["feature"] != 1 {
		t.Errorf("applications per version = %v (calls %d), want main:0 feature:1", got, len(app.calls))
	}
}

func TestMatchBuildsFindingsFromInventory(t *testing.T) {
	inv := &fakeInventory{items: []sbom.SnapshotComponent{
		{SbomID: "s1-old", ProjectID: "p1", Name: "log4j-core", Version: "2.14.0", Purl: "pkg:maven/log4j-core@2.14.0"},
		{SbomID: "s1", ProjectID: "p1", Name: "log4j-core", Version: "2.14.1", Purl: "pkg:maven/log4j-core@2.14.1", Current: true},
		{SbomID: "s2", ProjectID: "p2", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20", Current: true},
	}}
	log4shell := Vuln{
		ID: "GHSA-jfh8-c2jp-5v3q", Summary: "Log4Shell", Severity: domain.SeverityCritical,
		CVEs: []string{"CVE-2021-44228"}, Fixed: "2.15.0",
	}
	src := &fakeSource{byPurl: map[string][]Vuln{
		"pkg:maven/log4j-core@2.14.0": {log4shell},
		"pkg:maven/log4j-core@2.14.1": {log4shell},
		// p2's package has no advisories.
	}}
	app := &fakeApplier{}

	n, err := NewService(inv, app, src).Match(context.Background())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if n != 1 {
		t.Errorf("findings = %d, want 1 — only the current snapshot produces findings", n)
	}
	// One batched lookup covering every distinct purl, history included.
	if src.callCount != 1 || len(src.gotPurls) != 3 {
		t.Errorf("source calls=%d purls=%v, want 1 call with 3 purls", src.callCount, src.gotPurls)
	}
	// Every snapshot's matches are recorded — the old one too, so history stays
	// answerable — and every evaluated snapshot is replaced (incl. the clean s2).
	if len(inv.recorded) != 2 || len(inv.sboms) != 3 {
		t.Errorf("recorded %d matches over %v, want 2 matches over all 3 snapshots", len(inv.recorded), inv.sboms)
	}
	// Both projects are applied — p2 with zero findings, so anything it previously
	// reported gets auto-closed.
	if len(app.calls) != 2 {
		t.Fatalf("applied to %d projects, want 2 (incl. the clean one, so resolved vulns close)", len(app.calls))
	}

	var vuln *finding.Finding
	for i := range app.calls {
		if app.calls[i].projectID == "p1" {
			if len(app.calls[i].findings) != 1 {
				t.Fatalf("p1 findings = %d, want 1", len(app.calls[i].findings))
			}
			vuln = &app.calls[i].findings[0]
		} else if len(app.calls[i].findings) != 0 {
			t.Errorf("p2 should have no findings, got %d", len(app.calls[i].findings))
		}
	}
	if vuln == nil {
		t.Fatal("no finding recorded for p1")
	}
	if vuln.RuleID != "GHSA-jfh8-c2jp-5v3q" || vuln.Severity != domain.SeverityCritical {
		t.Errorf("finding = %+v, want the GHSA at critical", vuln)
	}
	if len(vuln.CVE) != 1 || vuln.CVE[0] != "CVE-2021-44228" {
		t.Errorf("CVE = %v, want [CVE-2021-44228] (so it dedups against scanner reports)", vuln.CVE)
	}
	if vuln.PackageName != "log4j-core" || vuln.PackageVersion != "2.14.1" || vuln.FixedVersion != "2.15.0" {
		t.Errorf("package info wrong: %+v", vuln)
	}
	if vuln.Category != domain.CategorySCA || vuln.Fingerprint == "" {
		t.Errorf("category/fingerprint wrong: %+v", vuln)
	}
}

// Every upload starts a match and runs finish in any order. A run that evaluated
// a release which is no longer current must not apply its findings — it would
// re-open what the newer release's run already closed.
func TestMatchLeavesProjectsThatChangedMidRun(t *testing.T) {
	inv := &fakeInventory{
		items: []sbom.SnapshotComponent{
			{SbomID: "v1", ProjectID: "p1", Name: "qs", Version: "6.7.0", Purl: "pkg:npm/qs@6.7.0", Current: true},
			{SbomID: "w1", ProjectID: "p2", Name: "qs", Version: "6.7.0", Purl: "pkg:npm/qs@6.7.0", Current: true},
		},
		current: map[string][]string{"p1": {"v2"}}, // p1 uploaded v2 while we were querying the feed
	}
	src := &fakeSource{byPurl: map[string][]Vuln{"pkg:npm/qs@6.7.0": {{ID: "GHSA-qs", Severity: domain.SeverityHigh}}}}
	app := &fakeApplier{}

	n, err := NewService(inv, app, src).Match(context.Background())
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(app.calls) != 1 || app.calls[0].projectID != "p2" || n != 1 {
		t.Fatalf("applied %+v (n=%d), want only the unchanged p2", app.calls, n)
	}
	if len(inv.recorded) != 2 {
		t.Errorf("recorded %d snapshot matches, want 2 — history is recorded either way", len(inv.recorded))
	}
}

func TestFingerprintIsStableAndDistinct(t *testing.T) {
	a := fingerprint("CVE-1", "pkg:npm/x@1.0.0")
	if a != fingerprint("CVE-1", "pkg:npm/x@1.0.0") {
		t.Error("fingerprint must be stable so re-runs upsert rather than duplicate")
	}
	if a == fingerprint("CVE-1", "pkg:npm/x@2.0.0") {
		t.Error("different package versions must not share a fingerprint")
	}
	if a == fingerprint("CVE-2", "pkg:npm/x@1.0.0") {
		t.Error("different advisories must not share a fingerprint")
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := map[string]domain.Severity{
		"CRITICAL": domain.SeverityCritical,
		"HIGH":     domain.SeverityHigh,
		"MODERATE": domain.SeverityMedium,
		"LOW":      domain.SeverityLow,
		"":         "", // unknown stays unknown so a merge can't let it outrank a stated severity
	}
	for in, want := range cases {
		if got := severityFrom(in); got != want {
			t.Errorf("severityFrom(%q) = %q, want %q", in, got, want)
		}
	}
	// …but a finding never carries an empty severity: unknown → medium.
	if got := (Vuln{}).severityOrDefault(); got != domain.SeverityMedium {
		t.Errorf("unknown severity on a finding = %q, want medium", got)
	}
}

// The online OSV source reports the fix for the release line the installed
// version is on — log4shell was fixed in 2.15.0, 2.12.2 and 2.3.1 — not just
// the record's first fixed event.
func TestOSVRecordFixForInstalledLine(t *testing.T) {
	rec := loadOSV(t, "GHSA-jfh8-c2jp-5v3q")
	cases := map[string]string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": "2.15.0",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.11.0": "2.12.2",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.1":    "2.3.1",
	}
	for p, want := range cases {
		v := rec.vulnFor(p)
		if v.Fixed != want {
			t.Errorf("%s: fixed = %q, want %q", p, v.Fixed, want)
		}
		if v.Severity != domain.SeverityCritical || !slices.Equal(v.CVEs, []string{"CVE-2021-44228"}) {
			t.Errorf("%s: severity/CVEs = %q/%v, want critical/[CVE-2021-44228]", p, v.Severity, v.CVEs)
		}
	}
}
