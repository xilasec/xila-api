// Package correlation links vulnerabilities to the software that introduced
// them: given an SCA finding, it locates the exact SBOM component(s) — by PURL,
// or by package name + version — in the same project. This is what makes the
// vulnerability view (DefectDojo-style) and the SBOM view (Dependency-Track
// style) behave like a single tool.
package correlation

import (
	"context"

	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/sbom"
)

// findingGetter reads a finding by id.
type findingGetter interface {
	Get(ctx context.Context, id string) (finding.Finding, error)
}

// componentLister searches SBOM components.
type componentLister interface {
	ListComponents(ctx context.Context, f sbom.ComponentFilter) ([]sbom.ComponentHit, error)
}

// Service correlates findings with SBOM components.
type Service struct {
	findings   findingGetter
	components componentLister
}

// NewService wires the correlation dependencies.
func NewService(findings findingGetter, components componentLister) *Service {
	return &Service{findings: findings, components: components}
}

// ComponentsForFinding returns the finding together with the SBOM components it
// maps to within its project. latestOnly restricts matching to current
// inventory (the newest snapshot per artifact) rather than all history.
//
// Findings that are not package-based (secrets, IaC, most SAST) have no
// component to match and return an empty slice.
func (s *Service) ComponentsForFinding(ctx context.Context, findingID string, latestOnly bool) (finding.Finding, []sbom.ComponentHit, error) {
	f, err := s.findings.Get(ctx, findingID)
	if err != nil {
		return finding.Finding{}, nil, err
	}

	filter, ok := matchFilter(f, latestOnly)
	if !ok {
		return f, []sbom.ComponentHit{}, nil
	}

	hits, err := s.components.ListComponents(ctx, filter)
	if err != nil {
		return finding.Finding{}, nil, err
	}
	return f, hits, nil
}

// matchFilter builds the component query for a finding. It prefers matching by
// package name + version (stable across tools that emit differing PURL types)
// and falls back to PURL. Returns ok=false when the finding carries no package
// identity to match on.
func matchFilter(f finding.Finding, latestOnly bool) (sbom.ComponentFilter, bool) {
	filter := sbom.ComponentFilter{ProjectID: f.ProjectID, LatestOnly: latestOnly}
	switch {
	case f.PackageName != "":
		filter.Name = f.PackageName
		filter.Version = f.PackageVersion // exact when known; empty matches any version
	case f.Purl != "":
		filter.Purl = f.Purl
	default:
		return sbom.ComponentFilter{}, false
	}
	return filter, true
}
