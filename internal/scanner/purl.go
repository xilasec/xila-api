package scanner

import (
	"net/url"
	"strings"
)

// ecosystemPurl builds a package URL from a tool's ecosystem name and package
// coordinates, for the tools that name a dependency but don't emit its PURL
// (Snyk, pip-audit, cargo-audit, bundler-audit, Retire.js). The PURL is what
// SBOM correlation and reachability match on, so it's worth reconstructing —
// but only for ecosystems whose PURL shape is unambiguous from name + version.
// Anything else (OS packages need a distro qualifier we don't have) returns "".
func ecosystemPurl(ecosystem, name, version string) string {
	if name == "" {
		return ""
	}
	var typ, path string
	switch strings.ToLower(ecosystem) {
	case "npm", "yarn", "pnpm", "js":
		typ = "npm"
		if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
			path = "%40" + url.PathEscape(scope[1:]) + "/" + url.PathEscape(rest)
		} else {
			path = url.PathEscape(name)
		}
	case "maven", "gradle", "sbt":
		group, artifact, ok := strings.Cut(name, ":")
		if !ok {
			return ""
		}
		typ, path = "maven", url.PathEscape(group)+"/"+url.PathEscape(artifact)
	case "pip", "pypi", "poetry", "pipenv", "python":
		// PEP 503 normalization, which the PURL spec mandates for pypi.
		typ = "pypi"
		path = url.PathEscape(strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name)))
	case "nuget", "paket":
		typ, path = "nuget", url.PathEscape(name)
	case "gomodules", "golangdep", "govendor", "golang", "go":
		typ, path = "golang", name
	case "rubygems", "gem", "bundler":
		typ, path = "gem", url.PathEscape(name)
	case "cargo", "crates.io", "rust":
		typ, path = "cargo", url.PathEscape(name)
	case "composer", "packagist":
		typ, path = "composer", name
	case "hex":
		typ, path = "hex", url.PathEscape(name)
	case "pub":
		typ, path = "pub", url.PathEscape(name)
	case "cocoapods":
		typ, path = "cocoapods", url.PathEscape(name)
	default:
		return ""
	}
	p := "pkg:" + typ + "/" + path
	if version != "" {
		p += "@" + url.PathEscape(version)
	}
	return p
}
