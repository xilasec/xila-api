package vulnmatch

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/sbom"
)

type staticSource struct {
	res map[string][]Vuln
	err error
}

func (s staticSource) Query(context.Context, []string) (map[string][]Vuln, error) {
	return s.res, s.err
}

// The same advisory from several sources is ONE vulnerability: OSV's GHSA
// record and GitHub's, a PyPA record aliasing the GHSA, and a private advisory
// aliasing the CVE all collapse; the most specific data wins.
func TestMultiSourceMergesByIDAndAliases(t *testing.T) {
	const p = "pkg:pypi/django@4.0rc1"
	osv := staticSource{res: map[string][]Vuln{p: {
		{ID: "GHSA-53qw-q765-4fww", Aliases: []string{"CVE-2021-45115"}, CVEs: []string{"CVE-2021-45115"},
			Summary: "Denial-of-service in UserAttributeSimilarityValidator", Severity: "", Fixed: "4.0.1"},
		{ID: "PYSEC-2022-1", Aliases: []string{"GHSA-53qw-q765-4fww"}, Fixed: "4.0.1"},
		{ID: "GHSA-other", Severity: domain.SeverityLow},
	}}}
	github := staticSource{res: map[string][]Vuln{p: {
		{ID: "GHSA-53qw-q765-4fww", Aliases: []string{"CVE-2021-45115"}, CVEs: []string{"CVE-2021-45115"},
			Severity: domain.SeverityHigh, CVSS: new(7.5), Fixed: "4.0.1",
			URL: "https://github.com/advisories/GHSA-53qw-q765-4fww"},
	}}}
	private := staticSource{res: map[string][]Vuln{p: {
		{ID: "XILA-2026-0001", Aliases: []string{"CVE-2021-45115"}, Severity: domain.SeverityMedium,
			Fixed: "3.2.11"}, // a fix below the installed version is no use
	}}}
	m := NewMultiSource(
		NamedSource{SourceOSV, osv}, NamedSource{SourceGitHub, github}, NamedSource{SourcePrivate, private})
	got, err := m.Query(context.Background(), []string{p})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	vs := got[p]
	if len(vs) != 2 {
		t.Fatalf("got %d vulns %+v, want 2 (the merged advisory + GHSA-other)", len(vs), vs)
	}
	v := vs[slices.IndexFunc(vs, func(v Vuln) bool { return v.ID == "GHSA-53qw-q765-4fww" })]
	if v.Severity != domain.SeverityHigh || v.CVSS == nil || *v.CVSS != 7.5 {
		t.Errorf("severity/CVSS = %q/%v, want the stated high / 7.5 (unknown never wins)", v.Severity, v.CVSS)
	}
	if v.Fixed != "4.0.1" {
		t.Errorf("fixed = %q, want 4.0.1 (the lowest fix above 4.0rc1)", v.Fixed)
	}
	if !slices.Equal(v.CVEs, []string{"CVE-2021-45115"}) {
		t.Errorf("CVEs = %v", v.CVEs)
	}
	if !slices.Equal(v.Aliases, []string{"CVE-2021-45115", "PYSEC-2022-1", "XILA-2026-0001"}) {
		t.Errorf("aliases = %v, want every other id", v.Aliases)
	}
	if !slices.Equal(v.Sources, []string{"osv", "github", "private"}) {
		t.Errorf("sources = %v, want all three", v.Sources)
	}
	if v.Summary == "" || v.URL != "https://github.com/advisories/GHSA-53qw-q765-4fww" {
		t.Errorf("summary/url = %q/%q, want filled from whichever source had them", v.Summary, v.URL)
	}

	// The canonical id must not depend on which sources answered: with only
	// PyPA's record (which aliases the GHSA) it stays the record's own id, but
	// with the GHSA present the GHSA wins regardless of order.
	m2 := NewMultiSource(NamedSource{SourcePrivate, private}, NamedSource{SourceGitHub, github})
	got2, _ := m2.Query(context.Background(), []string{p})
	if len(got2[p]) != 1 || got2[p][0].ID != "GHSA-53qw-q765-4fww" {
		t.Errorf("merged id = %+v, want GHSA-53qw-q765-4fww", got2[p])
	}
}

func TestMultiSourceFailureSemantics(t *testing.T) {
	ok := staticSource{res: map[string][]Vuln{"pkg:npm/a@1.0.0": {{ID: "GHSA-a"}}}}
	bad := staticSource{err: errors.New("github down")}

	got, err := NewMultiSource(NamedSource{SourceOSV, ok}, NamedSource{SourceGitHub, bad}).
		Query(context.Background(), []string{"pkg:npm/a@1.0.0"})
	var partial *PartialError
	if !errors.As(err, &partial) || !slices.Equal(partial.FailedSources(), []string{"github"}) {
		t.Fatalf("err = %v, want a PartialError naming github", err)
	}
	if len(got["pkg:npm/a@1.0.0"]) != 1 {
		t.Errorf("healthy source's results dropped: %v", got)
	}

	_, err = NewMultiSource(NamedSource{SourceOSV, bad}, NamedSource{SourceGitHub, bad}).
		Query(context.Background(), []string{"pkg:npm/a@1.0.0"})
	if err == nil || errors.As(err, &partial) {
		t.Errorf("err = %v, want a hard error when every source failed", err)
	}
}

// When one source fails, the matcher must not auto-close what only that source
// reported: findings are added (AddFindings), versions with nothing to add are
// left alone, and snapshot history keeps its last complete evaluation.
func TestMatchWithFailedSourceDoesNotAutoClose(t *testing.T) {
	inv := &fakeInventory{items: []sbom.SnapshotComponent{
		{SbomID: "s1", ProjectID: "p1", Name: "a", Version: "1.0.0", Purl: "pkg:npm/a@1.0.0", Current: true},
		{SbomID: "s2", ProjectID: "p2", Name: "b", Version: "1.0.0", Purl: "pkg:npm/b@1.0.0", Current: true},
	}}
	src := NewMultiSource(
		NamedSource{SourceOSV, staticSource{res: map[string][]Vuln{"pkg:npm/a@1.0.0": {{ID: "GHSA-a", Severity: domain.SeverityHigh}}}}},
		NamedSource{SourceGitHub, staticSource{err: errors.New("rate limited")}},
	)
	app := &fakeApplier{}
	n, err := NewService(inv, app, src).Match(context.Background())
	if _, ok := errors.AsType[*PartialError](err); !ok {
		t.Fatalf("err = %v, want the PartialError surfaced", err)
	}
	if n != 1 || len(app.calls) != 1 || !app.calls[0].additive || app.calls[0].projectID != "p1" {
		t.Fatalf("calls = %+v (n=%d), want one additive apply on p1 — p2 (nothing to add) untouched", app.calls, n)
	}
	if inv.sboms != nil {
		t.Errorf("snapshot history rewritten from a partial view: %v", inv.sboms)
	}
	meta := app.calls[0].findings[0].Metadata
	if meta["source"] != "osv" || !slices.Equal(meta["sources"].([]string), []string{"osv"}) {
		t.Errorf("finding metadata = %v, want source osv", meta)
	}

	// Once every source answers again, the complete view applies with auto-close.
	src.sources[1].Source = staticSource{res: map[string][]Vuln{}}
	app.calls = nil
	if _, err := NewService(inv, app, src).Match(context.Background()); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if len(app.calls) != 2 || app.calls[0].additive || app.calls[1].additive {
		t.Errorf("calls = %+v, want two closing applies", app.calls)
	}

	// After an upload, a partial match still counts as done (its findings were
	// added), so what runs after it — policy evaluation — isn't skipped.
	src.sources[1].Source = staticSource{err: errors.New("rate limited")}
	if n, err := NewService(inv, &fakeApplier{}, src).MatchProject(context.Background(), "p1"); err != nil || n != 1 {
		t.Errorf("MatchProject on partial = %d, %v; want 1, nil", n, err)
	}
}
