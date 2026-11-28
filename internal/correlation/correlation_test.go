package correlation

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/sbom"
)

type fakeFindings struct {
	finding finding.Finding
	err     error
}

func (f fakeFindings) Get(context.Context, string) (finding.Finding, error) {
	return f.finding, f.err
}

type fakeComponents struct {
	gotFilter sbom.ComponentFilter
	ret       []sbom.ComponentHit
}

func (f *fakeComponents) ListComponents(_ context.Context, filter sbom.ComponentFilter) ([]sbom.ComponentHit, error) {
	f.gotFilter = filter
	return f.ret, nil
}

func TestComponentsForFindingMatchesByPackage(t *testing.T) {
	comps := &fakeComponents{ret: []sbom.ComponentHit{{Name: "pkgA"}}}
	svc := NewService(fakeFindings{finding: finding.Finding{
		ProjectID:      "proj-1",
		Category:       domain.CategorySCA,
		PackageName:    "pkgA",
		PackageVersion: "1.0",
		Purl:           "pkg:generic/pkgA@1.0",
	}}, comps)

	_, hits, err := svc.ComponentsForFinding(context.Background(), "f1", true)
	if err != nil {
		t.Fatalf("ComponentsForFinding: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("hits = %d, want 1", len(hits))
	}
	// Package name + version take precedence over PURL, scoped to the project.
	if comps.gotFilter.Name != "pkgA" || comps.gotFilter.Version != "1.0" {
		t.Errorf("filter = %+v, want name/version match", comps.gotFilter)
	}
	if comps.gotFilter.ProjectID != "proj-1" || !comps.gotFilter.LatestOnly {
		t.Errorf("filter scope wrong: %+v", comps.gotFilter)
	}
}

func TestComponentsForFindingPurlFallback(t *testing.T) {
	comps := &fakeComponents{}
	svc := NewService(fakeFindings{finding: finding.Finding{
		ProjectID: "proj-1",
		Purl:      "pkg:npm/left-pad@1.0.0",
	}}, comps)

	if _, _, err := svc.ComponentsForFinding(context.Background(), "f1", false); err != nil {
		t.Fatalf("ComponentsForFinding: %v", err)
	}
	if comps.gotFilter.Purl != "pkg:npm/left-pad@1.0.0" || comps.gotFilter.Name != "" {
		t.Errorf("expected PURL fallback, got %+v", comps.gotFilter)
	}
}

func TestComponentsForFindingNonPackageReturnsEmpty(t *testing.T) {
	comps := &fakeComponents{ret: []sbom.ComponentHit{{Name: "should-not-be-returned"}}}
	// A secret finding has no package identity -> no lookup, empty result.
	svc := NewService(fakeFindings{finding: finding.Finding{
		ProjectID: "proj-1",
		Category:  domain.CategorySecret,
	}}, comps)

	_, hits, err := svc.ComponentsForFinding(context.Background(), "f1", false)
	if err != nil {
		t.Fatalf("ComponentsForFinding: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("hits = %d, want 0 for a non-package finding", len(hits))
	}
	if comps.gotFilter.ProjectID != "" {
		t.Error("component lookup should not have run for a non-package finding")
	}
}
