package sbom

import (
	"context"
	"strings"
)

// InternalMatcher returns, for one upload, whether a component (by
// ecosystem, group/namespace and name) is internal: a first-party package
// admin-defined patterns (internal/component.Service.Current) match. Injected
// the same way LicenseResolver is, so this package doesn't depend on package
// component.
type InternalMatcher func(ctx context.Context) func(ecosystem, group, name string) bool

// WithInternalComponents makes every upload mark its components internal
// before they are stored (and before the post-ingest evaluator sees them).
func (s *Service) WithInternalComponents(match InternalMatcher) *Service {
	s.internal = match
	return s
}

// markInternal sets the Internal flag of every component per match.
func markInternal(match func(ecosystem, group, name string) bool, components []Component) {
	for i := range components {
		components[i].Internal = match(purlEcosystem(components[i].Purl), components[i].Group, components[i].Name)
	}
}

// purlEcosystem is a purl's type ("npm", "pypi", …), lower-cased; "" when purl
// isn't one. A minimal extraction — internal/pkgmeta.ParsePURL does the full
// job for registry lookups, which this package has no reason to depend on.
func purlEcosystem(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	if eco, _, ok := strings.Cut(purl[len(prefix):], "/"); ok {
		return strings.ToLower(eco)
	}
	return ""
}
