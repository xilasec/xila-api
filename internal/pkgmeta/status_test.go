package pkgmeta

import (
	"testing"
	"time"
)

func TestParsePURL(t *testing.T) {
	cases := []struct {
		in            string
		base, version string
	}{
		{"pkg:npm/left-pad@1.1.0", "pkg:npm/left-pad", "1.1.0"},
		{"pkg:npm/%40babel/core@7.0.0", "pkg:npm/%40babel/core", "7.0.0"},
		{"pkg:npm/@babel/core@7.0.0", "pkg:npm/%40babel/core", "7.0.0"}, // unencoded scope
		{"pkg:npm/Left-Pad@1.0.0", "pkg:npm/left-pad", "1.0.0"},
		{"pkg:pypi/Django_REST.framework@3.14.0", "pkg:pypi/django-rest-framework", "3.14.0"},
		{"pkg:maven/com.google.guava/guava@33.0.0-jre?type=jar&classifier=sources", "pkg:maven/com.google.guava/guava", "33.0.0-jre"},
		{"pkg:golang/github.com/BurntSushi/toml@v1.3.0#cmd/tomlv", "pkg:golang/github.com/BurntSushi/toml", "v1.3.0"},
		{"pkg:nuget/Newtonsoft.Json@13.0.1", "pkg:nuget/newtonsoft.json", "13.0.1"},
		{"pkg:composer/Monolog/Monolog@3.9.0", "pkg:composer/monolog/monolog", "3.9.0"},
		{"pkg:gem/nokogiri@1.18.10?platform=x86_64-linux", "pkg:gem/nokogiri", "1.18.10"},
		{"pkg:cargo/libc", "pkg:cargo/libc", ""},
		{"PKG:NPM/x@1%2B2", "", ""}, // scheme is case-sensitive "pkg:"
	}
	for _, c := range cases {
		p, err := ParsePURL(c.in)
		if c.base == "" {
			if err == nil {
				t.Errorf("ParsePURL(%q) = %+v, want error", c.in, p)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePURL(%q): %v", c.in, err)
			continue
		}
		if p.Base() != c.base || p.Version != c.version {
			t.Errorf("ParsePURL(%q) = base %q version %q, want %q %q", c.in, p.Base(), p.Version, c.base, c.version)
		}
	}
	for _, bad := range []string{"", "npm/x@1", "pkg:", "pkg:npm", "pkg:npm/"} {
		if _, err := ParsePURL(bad); err == nil {
			t.Errorf("ParsePURL(%q) succeeded", bad)
		}
	}
}

func ts(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func meta(eco string, latest string, versions ...Version) Meta {
	now := time.Now()
	m := newMeta("pkg:"+eco+"/x", eco, Package{Latest: latest, Versions: versions}, now, time.Hour)
	return m
}

func v(s string) Version { return Version{Version: s} }

func TestEvaluate(t *testing.T) {
	npm := meta(NPM, "2.1.0",
		Version{Version: "1.0.0", Published: ts("2020-01-01T00:00:00Z")},
		v("1.1.0"), v("1.2.0"), Version{Version: "1.3.0", Yanked: true},
		v("2.0.0"), Version{Version: "2.1.0", Published: ts("2023-05-01T00:00:00Z")},
		v("3.0.0-rc.1"), v("3.0.0-rc.2"))

	cases := []struct {
		name     string
		m        Meta
		current  string
		latest   string
		outdated bool
		behind   int
	}{
		// 1.1.0, 1.2.0, 2.0.0, 2.1.0 are newer; 1.3.0 is yanked, 3.0.0-rc.* pre-releases.
		{"stable behind", npm, "1.0.0", "2.1.0", true, 4},
		{"on latest", npm, "2.1.0", "2.1.0", false, 0},
		// A pre-release user compares within pre-releases too.
		{"prerelease behind", npm, "3.0.0-rc.1", "3.0.0-rc.2", true, 1},
		{"prerelease on newest", npm, "3.0.0-rc.2", "3.0.0-rc.2", false, 0},
		// A pre-release of an old line: everything newer counts, up to the newest pre-release.
		{"old prerelease", npm, "2.0.0-beta.1", "3.0.0-rc.2", true, 4},
		// Ahead of the registry (a fork / unpublished build): not outdated.
		{"ahead", npm, "9.0.0", "2.1.0", false, 0},
		// On a yanked version: still compared, and newer ones count.
		{"on yanked", npm, "1.3.0", "2.1.0", true, 2},
		// npm's dist-tag can point below the highest number (backport line).
		{"dist-tag below max", meta(NPM, "1.5.0", v("1.4.0"), v("1.5.0"), v("2.0.0")), "1.4.0", "1.5.0", true, 1},
		// A pre-release dist-tag is never "latest stable".
		{"prerelease dist-tag", meta(NPM, "2.0.0-beta.1", v("1.0.0"), v("1.1.0"), v("2.0.0-beta.1")), "1.0.0", "1.1.0", true, 1},
		// PEP 440: 2.32.0 / 2.32.1 yanked, the .dev1 build is a pre-release.
		{"pypi yanked + dev", meta(PyPI, "2.34.2", v("2.31.0"), Version{Version: "2.32.0", Yanked: true},
			Version{Version: "2.32.1", Yanked: true}, v("2.32.2"), v("2.34.0.dev1"), v("2.34.2")), "2.31.0", "2.34.2", true, 2},
		// "1.0" and "1.0.0" are the same Python version.
		{"pypi equal spelling", meta(PyPI, "1.0", v("0.9"), v("1.0")), "1.0.0", "1.0", false, 0},
		// Maven: stay within the -android variant.
		{"maven flavor", meta(Maven, "33.7.2-jre", v("32.1.3-android"), v("32.1.3-jre"), v("33.7.1-android"),
			v("33.7.1-jre"), v("33.7.2-android"), v("33.7.2-jre")), "32.1.3-android", "33.7.2-android", true, 2},
		// Maven's <release> may be a release candidate; it's not stable.
		{"maven rc release tag", meta(Maven, "2.0-rc1", v("1.0"), v("1.1"), v("2.0-rc1")), "1.0", "1.1", true, 1},
	}
	for _, c := range cases {
		info, ok := evaluate(c.m.Ecosystem, c.m, c.current)
		if !ok {
			t.Errorf("%s: not evaluated", c.name)
			continue
		}
		if info.Latest != c.latest || info.Outdated != c.outdated || info.VersionsBehind == nil || *info.VersionsBehind != c.behind {
			behind := -1
			if info.VersionsBehind != nil {
				behind = *info.VersionsBehind
			}
			t.Errorf("%s: got latest %q outdated %v behind %d, want %q %v %d",
				c.name, info.Latest, info.Outdated, behind, c.latest, c.outdated, c.behind)
		}
	}

	info, _ := evaluate(NPM, npm, "1.0.0")
	if info.Published == nil || !info.Published.Equal(*ts("2020-01-01T00:00:00Z")) {
		t.Errorf("published = %v, want 2020-01-01", info.Published)
	}
	if info.LatestPublished == nil || !info.LatestPublished.Equal(*ts("2023-05-01T00:00:00Z")) {
		t.Errorf("latest published = %v, want 2023-05-01", info.LatestPublished)
	}
	if info.FetchedAt == nil {
		t.Error("fetched_at missing")
	}
}

// Unknown is never "up to date": no metadata, no version, or nothing stable to
// compare a stable version with all yield no verdict.
func TestEvaluateUnknown(t *testing.T) {
	if _, ok := evaluate(NPM, Meta{Ecosystem: NPM, LatestVersion: "1.0.0", Versions: []Version{v("1.0.0")}}, "1.0.0"); ok {
		t.Error("never-fetched metadata produced a verdict")
	}
	m := meta(NPM, "", v("1.0.0-beta.1"))
	if _, ok := evaluate(NPM, m, "0.9.0"); ok {
		t.Error("a package with no stable release judged a stable version")
	}
	if _, ok := evaluate(NPM, meta(NPM, "1.0.0", v("1.0.0")), ""); ok {
		t.Error("a component without a version got a verdict")
	}
	if _, ok := evaluate(NPM, meta(NPM, "", Version{Version: "1.0.0", Yanked: true}), "1.0.0"); ok {
		t.Error("only yanked releases produced a latest version")
	}
}

func TestNextAfterFailure(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ttl := 24 * time.Hour
	cases := []struct {
		n        int
		notFound bool
		want     time.Duration
	}{
		{1, false, time.Hour},
		{2, false, 2 * time.Hour},
		{4, false, 8 * time.Hour},
		{1, true, 24 * time.Hour},
		{2, true, 48 * time.Hour},
		{20, false, maxBackoff},
		{1000, true, maxBackoff},
	}
	for _, c := range cases {
		if got := nextAfterFailure(now, ttl, c.n, c.notFound).Sub(now); got != c.want {
			t.Errorf("nextAfterFailure(n=%d, notFound=%v) = %v, want %v", c.n, c.notFound, got, c.want)
		}
	}
}
