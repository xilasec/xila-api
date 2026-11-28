package pkgmeta

import (
	"errors"
	"net/url"
	"slices"
	"strings"
)

// Ecosystems this package can look up, named by their purl type
// (https://github.com/package-url/purl-spec/blob/main/PURL-TYPES.rst).
const (
	NPM      = "npm"
	PyPI     = "pypi"
	Maven    = "maven"
	Golang   = "golang"
	Cargo    = "cargo"
	NuGet    = "nuget"
	Gem      = "gem"
	Composer = "composer"
)

// Ecosystems lists every supported purl type.
var Ecosystems = []string{NPM, PyPI, Maven, Golang, Cargo, NuGet, Gem, Composer}

// Supported reports whether a purl type has a registry client.
func Supported(ecosystem string) bool {
	return slices.Contains(Ecosystems, ecosystem)
}

// ErrBadPurl is returned for a string that isn't a package URL.
var ErrBadPurl = errors.New("invalid package url")

// PURL is the part of a package URL a registry lookup needs. Qualifiers and
// subpath are dropped: they select an artifact of a version (a classifier, a
// platform build), never a different package.
type PURL struct {
	Type      string
	Namespace string // decoded; segments joined with "/"
	Name      string // decoded
	Version   string // decoded; "" when the purl has none
}

// ParsePURL parses pkg:type/namespace/name@version?qualifiers#subpath per the
// purl spec, normalizing the names the spec says are case-insensitive so the
// same package always gets the same Base.
func ParsePURL(s string) (PURL, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return PURL{}, ErrBadPurl
	}
	rest = strings.TrimLeft(rest, "/")
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest = rest[:i]
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" {
		return PURL{}, ErrBadPurl
	}
	var p PURL
	p.Type = strings.ToLower(typ)
	// The version follows the last '@' of the final path segment; an '@'
	// earlier is an unencoded npm scope ("@babel/core").
	lastSlash := strings.LastIndexByte(path, '/')
	if at := strings.LastIndexByte(path, '@'); at > lastSlash {
		v, err := url.PathUnescape(path[at+1:])
		if err != nil {
			return PURL{}, ErrBadPurl
		}
		p.Version, path = v, path[:at]
	}
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, seg := range segs {
		d, err := url.PathUnescape(seg)
		if err != nil {
			return PURL{}, ErrBadPurl
		}
		segs[i] = d
	}
	p.Name = segs[len(segs)-1]
	p.Namespace = strings.Join(segs[:len(segs)-1], "/")
	if p.Name == "" {
		return PURL{}, ErrBadPurl
	}
	switch p.Type {
	case NPM, Composer, NuGet:
		// Registry names are case-insensitive (npm and Packagist only allow
		// lowercase; NuGet ids are matched case-insensitively).
		p.Namespace, p.Name = strings.ToLower(p.Namespace), strings.ToLower(p.Name)
	case PyPI:
		// PEP 503 normalization: runs of -, _ and . are equivalent.
		p.Name = pep503(p.Name)
	}
	return p, nil
}

// pep503 normalizes a Python project name (https://peps.python.org/pep-0503/#normalized-names).
func pep503(name string) string {
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteRune(r)
	}
	return b.String()
}

// Base is the package's identity without version, qualifiers or subpath:
// pkg:type/namespace/name, canonically encoded. It keys package_meta.
func (p PURL) Base() string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(p.Type)
	b.WriteByte('/')
	if p.Namespace != "" {
		for seg := range strings.SplitSeq(p.Namespace, "/") {
			b.WriteString(escape(seg))
			b.WriteByte('/')
		}
	}
	b.WriteString(escape(p.Name))
	return b.String()
}

// escape percent-encodes a purl segment; '@' is always encoded so an npm
// scope can't be mistaken for a version separator.
func escape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}

// fullName is the registry's name for the package: "@scope/name" for npm,
// "group:artifact" style pieces are handled by each client.
func (p PURL) fullName(sep string) string {
	if p.Namespace == "" {
		return p.Name
	}
	return p.Namespace + sep + p.Name
}
