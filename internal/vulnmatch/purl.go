package vulnmatch

import (
	"net/url"
	"regexp"
	"strings"
)

// purl is a parsed package URL (https://github.com/package-url/purl-spec).
type purl struct {
	Type, Namespace, Name, Version string
}

// parsePurl parses "pkg:type/namespace/name@version?qualifiers#subpath".
// Qualifiers and subpath don't identify an advisory's package and are dropped.
func parsePurl(s string) (purl, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return purl{}, false
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimLeft(rest, "/")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" || path == "" {
		return purl{}, false
	}
	var p purl
	p.Type = strings.ToLower(typ)
	// The version follows the last '@' — unless that '@' starts a path segment
	// (an unencoded npm scope, "pkg:npm/@babel/core").
	if i := strings.LastIndexByte(path, '@'); i > 0 && path[i-1] != '/' {
		p.Version, _ = url.PathUnescape(path[i+1:])
		path = path[:i]
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, seg := range segs {
		segs[i], _ = url.PathUnescape(seg)
	}
	p.Name = segs[len(segs)-1]
	p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	if p.Name == "" {
		return purl{}, false
	}
	return p, true
}

// osvEcosystems maps purl types to OSV ecosystem names
// (https://ossf.github.io/osv-schema/#defined-ecosystems). Only language
// ecosystems are mapped: OS distributions (Debian, Alpine, …) key advisories by
// source package and release, which SBOM purls don't carry reliably — those stay
// with the online OSV source.
var osvEcosystems = map[string]string{
	"npm":           "npm",
	"pypi":          "PyPI",
	"maven":         "Maven",
	"golang":        "Go",
	"gem":           "RubyGems",
	"nuget":         "NuGet",
	"composer":      "Packagist",
	"cargo":         "crates.io",
	"hex":           "Hex",
	"pub":           "Pub",
	"swift":         "SwiftURL",
	"hackage":       "Hackage",
	"cran":          "CRAN",
	"conan":         "ConanCenter",
	"bitnami":       "Bitnami",
	"githubactions": "GitHub Actions",
}

// osvEcosystemNames is the inverse of osvEcosystems: the ecosystems a private
// advisory may name.
var osvEcosystemNames = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range osvEcosystems {
		m[e] = true
	}
	return m
}()

// osvPackage is the package an OSV advisory would name for this purl:
// ecosystem + ecosystem-native name ("org.apache.logging.log4j:log4j-core",
// "@babel/core", "golang.org/x/net", "symfony/http-kernel").
func (p purl) osvPackage() (ecosystem, name string, ok bool) {
	eco, ok := osvEcosystems[p.Type]
	if !ok {
		return "", "", false
	}
	switch p.Type {
	case "maven":
		if p.Namespace == "" {
			return "", "", false
		}
		return eco, p.Namespace + ":" + p.Name, true
	case "npm", "golang", "composer", "swift", "githubactions":
		if p.Namespace != "" {
			return eco, p.Namespace + "/" + p.Name, true
		}
	}
	return eco, p.Name, true
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// packageKey is the normalized "<Ecosystem>|<name>" an advisory's affected
// package and a component's purl are joined on: case-insensitive, and PyPI
// names normalized per PEP 503 ("Foo_Bar" == "foo-bar").
func packageKey(ecosystem, name string) string {
	if i := strings.IndexByte(ecosystem, ':'); i >= 0 {
		ecosystem = ecosystem[:i] // "Debian:12" → "Debian"
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if ecosystem == "PyPI" {
		name = pypiSep.ReplaceAllString(name, "-")
	}
	return ecosystem + "|" + name
}

// purlKey is the match key of a purl-named package (private advisories may
// name an internal package by purl rather than ecosystem + name): the purl
// without version, qualifiers or subpath, lowercased.
func purlKey(p purl) string {
	k := "purl:" + p.Type + "/"
	if p.Namespace != "" {
		k += p.Namespace + "/"
	}
	return strings.ToLower(k + p.Name)
}

// componentKeys are every key a component's purl can match on.
func componentKeys(p purl) []string {
	keys := []string{purlKey(p)}
	if eco, name, ok := p.osvPackage(); ok {
		keys = append(keys, packageKey(eco, name))
	}
	return keys
}

// ecosystemOf is the OSV ecosystem a purl belongs to ("" when unmapped) — the
// version ordering its ranges use.
func ecosystemOf(p purl) string { return osvEcosystems[p.Type] }
