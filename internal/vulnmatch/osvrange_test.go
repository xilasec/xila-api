package vulnmatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadOSV reads a real OSV record (fetched verbatim from
// https://api.osv.dev/v1/vulns/<id>, pretty-printed) from testdata/osv.
func loadOSV(t *testing.T, id string) osvRecord {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "osv", id+".json"))
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	var rec osvRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		t.Fatalf("decode %s: %v", id, err)
	}
	return rec
}

type rangeCase struct {
	purl     string
	affected bool
	fixed    string // expected "fixed in" when affected ("" = none)
}

func checkRecord(t *testing.T, id string, cases []rangeCase) {
	t.Helper()
	rec := loadOSV(t, id)
	for _, c := range cases {
		p, ok := parsePurl(c.purl)
		if !ok {
			t.Fatalf("bad purl %q", c.purl)
		}
		hit, fixed := rec.evaluate(p)
		if hit != c.affected {
			t.Errorf("%s %s: affected = %v, want %v", id, c.purl, hit, c.affected)
			continue
		}
		if hit && fixed != c.fixed {
			t.Errorf("%s %s: fixed = %q, want %q", id, c.purl, fixed, c.fixed)
		}
	}
}

// Maven ECOSYSTEM ranges over three release lines, a last_affected range with
// a versions list, and an entry that is a versions list only (no ranges).
func TestEvaluateLog4Shell(t *testing.T) {
	checkRecord(t, "GHSA-jfh8-c2jp-5v3q", []rangeCase{
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", true, "2.15.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0", false, ""},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", false, ""},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.12.1", true, "2.12.2"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.12.2", false, ""},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.0-beta9", true, "2.3.1"}, // introduced is inclusive
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.0-beta8", false, ""},     // pre-release before it
		{"pkg:maven/org.apache.logging.log4j/log4j-core@1.2.17", false, ""},
		// last_affected is inclusive, and there's no fix to suggest.
		{"pkg:maven/com.guicedee.services/log4j-core@1.2.1.2-jre17", true, ""},
		{"pkg:maven/com.guicedee.services/log4j-core@1.2.1.3", false, ""},
		// versions list only.
		{"pkg:maven/org.xbib.elasticsearch/log4j@6.3.2.1", true, ""},
		{"pkg:maven/org.xbib.elasticsearch/log4j@6.3.2.2", false, ""},
		// Qualifiers don't change the package.
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar", true, "2.15.0"},
	})
}

// Go SEMVER: two introduced/fixed pairs in one range (the second introduced at
// a pre-release, "1.19.0-0"), and pseudo-versions compared as SemVer
// pre-releases.
func TestEvaluateGoStdlibAndPseudoVersions(t *testing.T) {
	checkRecord(t, "GO-2022-0969", []rangeCase{
		{"pkg:golang/stdlib@1.18.5", true, "1.18.6"},
		{"pkg:golang/stdlib@1.18.6", false, ""},
		{"pkg:golang/stdlib@1.19.0", true, "1.19.1"},
		{"pkg:golang/stdlib@1.19.0-rc.1", true, "1.19.1"}, // above "1.19.0-0"
		{"pkg:golang/stdlib@1.19.1", false, ""},
		{"pkg:golang/golang.org/x/net@v0.0.0-20220826154423-83b083e8dc8b", true, "0.0.0-20220906165146-f3363e06e74c"},
		{"pkg:golang/golang.org/x/net@v0.0.0-20220906165146-f3363e06e74c", false, ""},
		{"pkg:golang/golang.org/x/net@v0.1.0", false, ""},
	})
	checkRecord(t, "GHSA-c3h9-896r-86jm", []rangeCase{
		{"pkg:golang/github.com/gogo/protobuf@v1.3.1", true, "1.3.2"},
		{"pkg:golang/github.com/gogo/protobuf@v1.3.2", false, ""},
	})
}

// PyPI: a GIT range (ignored — commit hashes need the repository) next to an
// ECOSYSTEM range, plus PEP 440 pre-release ordering.
func TestEvaluatePyPI(t *testing.T) {
	checkRecord(t, "PYSEC-2021-19", []rangeCase{
		{"pkg:pypi/lxml@4.6.2", true, "4.6.3"},
		{"pkg:pypi/LXML@4.6.2", true, "4.6.3"}, // names are case-insensitive
		{"pkg:pypi/lxml@2.0alpha1", true, "4.6.3"},
		{"pkg:pypi/lxml@4.6.3", false, ""},
		{"pkg:pypi/lxml@5.0.0", false, ""},
	})
	checkRecord(t, "GHSA-53qw-q765-4fww", []rangeCase{
		{"pkg:pypi/django@4.0a1", true, "4.0.1"},
		{"pkg:pypi/django@4.0rc1", true, "4.0.1"},
		{"pkg:pypi/django@4.0", true, "4.0.1"},
		{"pkg:pypi/django@4.0.1", false, ""},
		{"pkg:pypi/django@4.0.dev1", false, ""}, // PEP 440: dev releases precede alphas
		{"pkg:pypi/django@3.2", true, "3.2.11"},
		{"pkg:pypi/django@3.1.14", false, ""},
		{"pkg:pypi/django@2.2.25", true, "2.2.26"},
	})
}

// npm SEMVER and last_affected; crates.io with two ranges in one events list.
func TestEvaluateNpmAndCargo(t *testing.T) {
	checkRecord(t, "GHSA-29mw-wpgm-hmr9", []rangeCase{
		{"pkg:npm/lodash@4.17.20", true, "4.17.21"},
		{"pkg:npm/lodash@4.17.21", false, ""},
		{"pkg:npm/lodash@3.10.1", false, ""},
		{"pkg:npm/lodash.trimend@4.5.1", true, ""}, // last_affected: inclusive
		{"pkg:npm/lodash.trimend@4.5.2", false, ""},
	})
	checkRecord(t, "RUSTSEC-2021-0124", []rangeCase{
		{"pkg:cargo/tokio@0.1.13", false, ""},
		{"pkg:cargo/tokio@0.1.14", true, "1.8.4"},
		{"pkg:cargo/tokio@1.8.3", true, "1.8.4"},
		{"pkg:cargo/tokio@1.8.4", false, ""},
		{"pkg:cargo/tokio@1.9.0", true, "1.13.1"},
		{"pkg:cargo/tokio@1.13.0", true, "1.13.1"},
		{"pkg:cargo/tokio@1.13.1", false, ""},
	})
}

// limit events: no real advisory uses them outside GIT ranges, so this is the
// OSV schema's own semantics on a SEMVER range — a version must be below at
// least one limit, and "*" means unbounded.
func TestEvaluateLimitEvents(t *testing.T) {
	a := Affected{
		Package: Package{Ecosystem: "npm", Name: "x"},
		Ranges: []Range{{Type: "SEMVER", Events: []Event{
			{Introduced: "1.0.0"}, {Limit: "1.5.0"}, {Limit: "3.0.0"}, {Fixed: "2.0.0"},
		}}},
	}
	for v, want := range map[string]bool{"0.9.0": false, "1.0.0": true, "1.4.9": true, "1.9.9": true, "2.0.0": false, "3.0.0": false} {
		if got, _ := a.affects(v); got != want {
			t.Errorf("limits: %s affected = %v, want %v", v, got, want)
		}
	}
	a.Ranges[0].Events = []Event{{Introduced: "1.0.0"}, {Limit: "1.2.0"}}
	if got, _ := a.affects("1.3.0"); got {
		t.Error("a version at/above every limit is outside the range")
	}
	a.Ranges[0].Events = []Event{{Introduced: "1.0.0"}, {Limit: "*"}}
	if got, _ := a.affects("99.0.0"); !got {
		t.Error(`limit "*" is unbounded`)
	}
	// Unsorted events are sorted before replay (the schema only recommends order).
	a.Ranges[0].Events = []Event{{Fixed: "2.0.0"}, {Introduced: "1.0.0"}}
	if got, _ := a.affects("1.5.0"); !got {
		t.Error("events must be replayed in version order")
	}
}

func TestVersionOrderings(t *testing.T) {
	type c struct{ a, b string }
	less := map[string][]c{
		"semver": {{"1.0.0-alpha", "1.0.0-alpha.1"}, {"1.0.0-alpha.1", "1.0.0-alpha.beta"}, {"1.0.0-beta.2", "1.0.0-beta.11"},
			{"1.0.0-rc.1", "1.0.0"}, {"1.9.0", "1.10.0"}, {"v1.2.3", "1.2.4"}},
		"pep440": {{"1.0.dev1", "1.0a1"}, {"1.0a1", "1.0b1"}, {"1.0b2", "1.0rc1"}, {"1.0rc1", "1.0"}, {"1.0", "1.0.post1"},
			{"1.0", "1!0.1"}, {"2.0alpha1", "2.0"}},
		"gem": {{"1.0.0.pre", "1.0.0"}, {"1.0.0.rc1", "1.0.0"}, {"1.9", "1.10"}},
	}
	cmps := map[string]versionCmp{"semver": compareSemver, "pep440": comparePEP440, "gem": compareGem}
	for name, pairs := range less {
		for _, p := range pairs {
			if cmps[name](p.a, p.b) >= 0 || cmps[name](p.b, p.a) <= 0 {
				t.Errorf("%s: want %q < %q", name, p.a, p.b)
			}
		}
	}
	if comparePEP440("1.0", "1.0.0") != 0 || compareGem("1.0", "1.0.0") != 0 {
		t.Error("trailing zeros are insignificant in PEP 440 and RubyGems")
	}
}

func TestParsePurl(t *testing.T) {
	cases := map[string]purl{
		"pkg:npm/%40babel/core@7.0.0":                    {Type: "npm", Namespace: "@babel", Name: "core", Version: "7.0.0"},
		"pkg:npm/@babel/core@7.0.0":                      {Type: "npm", Namespace: "@babel", Name: "core", Version: "7.0.0"},
		"pkg:maven/org.apache/x@1.0?type=jar#sub":        {Type: "maven", Namespace: "org.apache", Name: "x", Version: "1.0"},
		"pkg:golang/golang.org/x/net@v0.1.0":             {Type: "golang", Namespace: "golang.org/x", Name: "net", Version: "v0.1.0"},
		"pkg:internal/acme/billing-core":                 {Type: "internal", Namespace: "acme", Name: "billing-core"},
		"pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=x": {Type: "deb", Namespace: "debian", Name: "openssl", Version: "3.0.11-1~deb12u2"},
	}
	for in, want := range cases {
		got, ok := parsePurl(in)
		if !ok || got != want {
			t.Errorf("parsePurl(%q) = %+v (%v), want %+v", in, got, ok, want)
		}
	}
	p, _ := parsePurl("pkg:npm/%40babel/core@7.0.0")
	if eco, name, _ := p.osvPackage(); eco != "npm" || name != "@babel/core" {
		t.Errorf("osvPackage = %s %s, want npm @babel/core", eco, name)
	}
	p, _ = parsePurl("pkg:pypi/Foo_Bar@1.0")
	if k := componentKeys(p); k[1] != packageKey("PyPI", "foo-bar") {
		t.Errorf("PyPI names normalize per PEP 503: %v", k)
	}
}
