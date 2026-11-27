package vulnmatch

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// purl is a parsed package URL (https://github.com/package-url/purl-spec).
// Distro is the `distro` qualifier (deb/rpm/apk types carry their OS release
// there); every other qualifier is dropped — purl must stay comparable (it's
// used as a map key), so only the one qualifier matching needs is kept.
type purl struct {
	Type, Namespace, Name, Version, Distro string
}

// parsePurl parses "pkg:type/namespace/name@version?qualifiers#subpath".
// Qualifiers (besides `distro`) and subpath don't identify an advisory's
// package and are dropped.
func parsePurl(s string) (purl, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "pkg:")
	if !ok {
		return purl{}, false
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	var qualifiers string
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		qualifiers = rest[i+1:]
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
	p.Distro = purlQualifier(qualifiers, "distro")
	return p, true
}

// purlQualifier reads one qualifier value from a purl's "key=value&…" query
// string by name.
func purlQualifier(qualifiers, key string) string {
	for pair := range strings.SplitSeq(qualifiers, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			return dv
		}
		return v
	}
	return ""
}

// osvEcosystems maps purl types to OSV ecosystem names
// (https://ossf.github.io/osv-schema/#defined-ecosystems) for language
// ecosystems, where a purl's own type+namespace+name always names the same
// package. OS distributions (deb, rpm, apk) are release-qualified instead —
// see distroEcosystem — because the same package name means something
// different in each release.
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

// osvEcosystemNames is the inverse of osvEcosystems: the plain (language)
// ecosystems a private advisory may name without a release qualifier.
var osvEcosystemNames = func() map[string]bool {
	m := map[string]bool{}
	for _, e := range osvEcosystems {
		m[e] = true
	}
	return m
}()

// distroEcosystemFamilies are the OS distributions distroEcosystem resolves —
// the ecosystem family a private advisory may also name generically (no
// release) to mean "every release".
var distroEcosystemFamilies = map[string]bool{
	"Debian": true, "Ubuntu": true, "Alpine": true,
	"Red Hat": true, "Rocky Linux": true, "AlmaLinux": true,
}

var (
	debianEcosystemRe = regexp.MustCompile(`^Debian:\d+$`)
	ubuntuEcosystemRe = regexp.MustCompile(`^Ubuntu:\d{2}\.\d{2}(:LTS)?$`)
	alpineEcosystemRe = regexp.MustCompile(`^Alpine:v\d+\.\d+$`)
	rpmDistroEcoRe    = regexp.MustCompile(`^(Red Hat|Rocky Linux|AlmaLinux):.+$`)
)

// validEcosystemName accepts a mapped language ecosystem ("npm", "PyPI", …), a
// distro family name meaning "every release" ("Debian", "Alpine", …), or a
// release-qualified distro ecosystem in the exact form distroEcosystem
// produces ("Debian:12", "Ubuntu:22.04:LTS", "Alpine:v3.18", "Red Hat:9",
// "Rocky Linux:9", "AlmaLinux:9") — what a private advisory's Package.Ecosystem
// may be set to.
func validEcosystemName(eco string) bool {
	if osvEcosystemNames[eco] || distroEcosystemFamilies[eco] {
		return true
	}
	switch packageFamily(eco) {
	case "Debian":
		return debianEcosystemRe.MatchString(eco)
	case "Ubuntu":
		return ubuntuEcosystemRe.MatchString(eco)
	case "Alpine":
		return alpineEcosystemRe.MatchString(eco)
	case "Red Hat", "Rocky Linux", "AlmaLinux":
		return rpmDistroEcoRe.MatchString(eco)
	}
	return false
}

// debianCodenames maps Debian release codenames to their release number
// (https://www.debian.org/releases/): a scanner's `distro` qualifier may carry
// either ("bookworm" or "12" both resolve to Debian:12, matching how OSV's own
// Debian-OSV export names a purl's distro qualifier by codename but its
// ecosystem by number — see testdata/osv/DEBIAN-CVE-2024-4603.json).
var debianCodenames = map[string]string{
	"wheezy": "7", "jessie": "8", "stretch": "9", "buster": "10",
	"bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

func debianRelease(distro string) (string, bool) {
	distro = strings.ToLower(strings.TrimSpace(distro))
	if distro == "" {
		return "", false
	}
	if _, err := strconv.Atoi(distro); err == nil {
		return distro, true
	}
	rel, ok := debianCodenames[distro]
	return rel, ok
}

// ubuntuCodenames maps Ubuntu release codenames to their version number
// (https://wiki.ubuntu.com/Releases); a scanner's `distro` qualifier may carry
// either form.
var ubuntuCodenames = map[string]string{
	"warty": "4.10", "hoary": "5.04", "breezy": "5.10", "dapper": "6.06",
	"edgy": "6.10", "feisty": "7.04", "gutsy": "7.10", "hardy": "8.04",
	"intrepid": "8.10", "jaunty": "9.04", "karmic": "9.10", "lucid": "10.04",
	"maverick": "10.10", "natty": "11.04", "oneiric": "11.10", "precise": "12.04",
	"quantal": "12.10", "raring": "13.04", "saucy": "13.10", "trusty": "14.04",
	"utopic": "14.10", "vivid": "15.04", "wily": "15.10", "xenial": "16.04",
	"yakkety": "16.10", "zesty": "17.04", "artful": "17.10", "bionic": "18.04",
	"cosmic": "18.10", "disco": "19.04", "eoan": "19.10", "focal": "20.04",
	"groovy": "20.10", "hirsute": "21.04", "impish": "21.10", "jammy": "22.04",
	"kinetic": "22.10", "lunar": "23.04", "mantic": "23.10", "noble": "24.04",
	"oracular": "24.10", "plucky": "25.04",
}

var ubuntuVersionRe = regexp.MustCompile(`^\d{2}\.\d{2}$`)

// ubuntuRelease resolves a `distro` qualifier to its release number and
// whether that release is LTS.
func ubuntuRelease(distro string) (release string, lts bool, ok bool) {
	distro = strings.ToLower(strings.TrimSpace(distro))
	if distro == "" {
		return "", false, false
	}
	v, known := ubuntuCodenames[distro]
	if !known {
		if !ubuntuVersionRe.MatchString(distro) {
			return "", false, false
		}
		v = distro
	}
	return v, isUbuntuLTS(v), true
}

// isUbuntuLTS: Ubuntu ships an LTS release every two years in April (even
// year, ".04") since 8.04; 6.06 ("dapper"), the first LTS, is the one
// exception to that pattern (https://wiki.ubuntu.com/Releases).
func isUbuntuLTS(version string) bool {
	if version == "6.06" {
		return true
	}
	yy, mm, ok := strings.Cut(version, ".")
	if !ok || mm != "04" {
		return false
	}
	n, err := strconv.Atoi(yy)
	return err == nil && n%2 == 0
}

// debEcosystem resolves a deb-type purl's Debian or Ubuntu release from its
// `distro` qualifier.
func debEcosystem(p purl) (string, bool) {
	switch strings.ToLower(p.Namespace) {
	case "debian":
		if rel, ok := debianRelease(p.Distro); ok {
			return "Debian:" + rel, true
		}
	case "ubuntu":
		if rel, lts, ok := ubuntuRelease(p.Distro); ok {
			if lts {
				return "Ubuntu:" + rel + ":LTS", true
			}
			return "Ubuntu:" + rel, true
		}
	}
	return "", false
}

// alpineMajorMinor reads the major.minor Alpine version an apk purl's
// `distro` qualifier carries ("3.18.4" or "v3.18" → "3", "18").
func alpineMajorMinor(distro string) (major, minor string, ok bool) {
	distro = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(distro)), "v")
	parts := strings.Split(distro, ".")
	if len(parts) < 2 {
		return "", "", false
	}
	if _, err := strconv.Atoi(parts[0]); err != nil {
		return "", "", false
	}
	if _, err := strconv.Atoi(parts[1]); err != nil {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// apkEcosystem resolves an apk-type purl's Alpine release from its `distro`
// qualifier (https://ossf.github.io/osv-schema/#defined-ecosystems: "Alpine:v3.16").
func apkEcosystem(p purl) (string, bool) {
	if !strings.EqualFold(p.Namespace, "alpine") {
		return "", false
	}
	major, minor, ok := alpineMajorMinor(p.Distro)
	if !ok {
		return "", false
	}
	return "Alpine:v" + major + "." + minor, true
}

// rpmVendorRelease reads the vendor and release an rpm purl's `distro`
// qualifier names: purl-spec's own rpm examples give it as "<vendor>-<release>"
// ("fedora-25", "rhel-9"); a bare release number falls back to the purl's
// namespace as the vendor.
func rpmVendorRelease(p purl) (vendor, release string, ok bool) {
	distro := strings.ToLower(strings.TrimSpace(p.Distro))
	if distro == "" {
		return "", "", false
	}
	if name, rel, found := strings.Cut(distro, "-"); found && rel != "" {
		return name, rel, true
	}
	if p.Namespace != "" {
		return strings.ToLower(p.Namespace), distro, true
	}
	return "", "", false
}

// rpmEcosystem resolves an rpm-type purl's RHEL/Rocky Linux/AlmaLinux release.
func rpmEcosystem(p purl) (string, bool) {
	vendor, release, ok := rpmVendorRelease(p)
	if !ok {
		return "", false
	}
	switch vendor {
	case "rhel", "redhat", "red hat":
		return "Red Hat:" + release, true
	case "rocky", "rockylinux":
		return "Rocky Linux:" + release, true
	case "almalinux", "alma":
		return "AlmaLinux:" + release, true
	}
	return "", false
}

// distroEcosystem resolves the OSV ecosystem of a deb/rpm/apk purl from its
// `distro` qualifier (the OS release, e.g. "bookworm", "rhel-9", "3.18.4") —
// "" when the type isn't a recognized distro, the namespace names an
// unsupported vendor, or the qualifier is missing or unrecognized (an SBOM
// purl doesn't always carry it, per the OSV schema's own ecosystem list:
// https://ossf.github.io/osv-schema/#defined-ecosystems).
func distroEcosystem(p purl) (string, bool) {
	switch p.Type {
	case "deb":
		return debEcosystem(p)
	case "rpm":
		return rpmEcosystem(p)
	case "apk":
		return apkEcosystem(p)
	}
	return "", false
}

// purlEcosystem is the OSV ecosystem a purl belongs to: the mapped language
// ecosystem, or a release-qualified distro ecosystem.
func purlEcosystem(p purl) (string, bool) {
	if eco, ok := osvEcosystems[p.Type]; ok {
		return eco, true
	}
	return distroEcosystem(p)
}

// osvPackage is the package an OSV advisory would name for this purl:
// ecosystem + ecosystem-native name ("org.apache.logging.log4j:log4j-core",
// "@babel/core", "golang.org/x/net", "symfony/http-kernel", "Debian:12"
// + "openssl").
func (p purl) osvPackage() (ecosystem, name string, ok bool) {
	eco, ok := purlEcosystem(p)
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

// packageFamily drops a distro ecosystem's release ("Debian:12" → "Debian"):
// the ordering its ranges use, and the fallback match key an advisory written
// for "any release" (no colon) is found by.
func packageFamily(ecosystem string) string {
	if i := strings.IndexByte(ecosystem, ':'); i >= 0 {
		return ecosystem[:i]
	}
	return ecosystem
}

// packageKey is the normalized "<Ecosystem>|<name>" an advisory's affected
// package and a component's purl are joined on: case-insensitive, and PyPI
// names normalized per PEP 503 ("Foo_Bar" == "foo-bar"). A distro ecosystem
// keeps its release ("Debian:12"), so a Debian 12 advisory doesn't also claim
// a Debian 13 component; componentKeys additionally looks up the release-less
// family key ("Debian") so an advisory written for "any release" still
// matches every one.
func packageKey(ecosystem, name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if packageFamily(ecosystem) == "PyPI" {
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

// componentKeys are every key a component's purl can match on: the purl key,
// the ecosystem+name key (release-qualified for a distro purl), and — for a
// distro purl — also the release-less family key, so a generic advisory still
// matches.
func componentKeys(p purl) []string {
	keys := []string{purlKey(p)}
	if eco, name, ok := p.osvPackage(); ok {
		keys = append(keys, packageKey(eco, name))
		if fam := packageFamily(eco); fam != eco {
			keys = append(keys, packageKey(fam, name))
		}
	}
	return keys
}

// ecosystemOf is the OSV ecosystem a purl belongs to ("" when unmapped),
// release-qualified for a distro purl — the key componentKeys indexes on.
func ecosystemOf(p purl) string {
	eco, _ := purlEcosystem(p)
	return eco
}
