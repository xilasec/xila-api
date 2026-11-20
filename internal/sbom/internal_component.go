package sbom

import "strings"

// InternalMatcher reports whether a component (by ecosystem, group/namespace
// and name) is internal — a first-party package admin-defined patterns
// (internal/component.Service) match. Injected the same way LicenseResolver
// is, so this package doesn't depend on package component.
type InternalMatcher func(ecosystem, group, name string) bool

// WithInternalComponents makes every upload mark its components internal
// before they are stored (and before the post-ingest evaluator sees them).
func (s *Service) WithInternalComponents(match InternalMatcher) *Service {
	s.internal = match
	return s
}

// markInternal sets the Internal flag of every component per match.
func markInternal(match InternalMatcher, components []Component) {
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
	rest := purl[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}
