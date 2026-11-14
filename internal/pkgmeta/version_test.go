package pkgmeta

import "testing"

// orderCase asserts compare(a, b) == want (and the mirror image).
type orderCase struct {
	a, b string
	want int
}

func checkOrder(t *testing.T, eco string, cases []orderCase) {
	t.Helper()
	sch := schemeFor(eco)
	for _, c := range cases {
		if got := sch.compare(c.a, c.b); sign(got) != c.want {
			t.Errorf("%s: compare(%q, %q) = %d, want %d", eco, c.a, c.b, got, c.want)
		}
		if got := sch.compare(c.b, c.a); sign(got) != -c.want {
			t.Errorf("%s: compare(%q, %q) = %d, want %d", eco, c.b, c.a, got, -c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}

func TestSemverOrdering(t *testing.T) {
	// The precedence example of https://semver.org/#spec-item-11, in order.
	chain := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"}
	var cases []orderCase
	for i := 1; i < len(chain); i++ {
		cases = append(cases, orderCase{chain[i-1], chain[i], -1})
	}
	cases = append(cases,
		orderCase{"1.0.0-1", "1.0.0-alpha", -1}, // numeric identifiers sort below words
		orderCase{"1.10.0", "1.9.0", 1},         // numerically, not lexically
		orderCase{"v1.2.3", "1.2.3", 0},         // Go's v prefix
		orderCase{"1.2.3+build.5", "1.2.3", 0},  // build metadata never orders
		orderCase{"v2.0.0+incompatible", "v1.9.9", 1},
		orderCase{"v0.0.0-20191109021931-daa7c04131f5", "v0.0.1", -1},        // Go pseudo-version
		orderCase{"18446744073709551616.0.0", "18446744073709551615.0.0", 1}, // beyond uint64
	)
	checkOrder(t, NPM, cases)
	checkOrder(t, Cargo, cases)
	checkOrder(t, Golang, cases)

	for v, want := range map[string]bool{"1.0.0": false, "1.0.0-rc.1": true, "v0.0.0-20191109021931-daa7c04131f5": true,
		"v2.0.0+incompatible": false} {
		if got := schemeFor(NPM).prerelease(v); got != want {
			t.Errorf("semver prerelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestNuGetOrdering(t *testing.T) {
	checkOrder(t, NuGet, []orderCase{
		{"4.0.102.14", "4.0.102.13", 1}, // four-part versions
		{"4.0.7", "4.0.7.1", -1},
		{"4.0.7.0", "4.0.7", 0},
		{"1.0.0-Beta", "1.0.0-beta", 0}, // labels are case-insensitive
		{"13.0.5-beta1", "13.0.4", 1},
		{"13.0.5-beta1", "13.0.5", -1},
	})
}

func TestPEP440Ordering(t *testing.T) {
	// The ordering example of https://peps.python.org/pep-0440/#summary-of-permitted-suffixes-and-relative-ordering.
	chain := []string{"1.dev0", "1.0.dev456", "1.0a1", "1.0a2.dev456", "1.0a12.dev456", "1.0a12",
		"1.0b1.dev456", "1.0b2", "1.0b2.post345.dev456", "1.0b2.post345", "1.0rc1.dev456", "1.0rc1",
		"1.0", "1.0+abc.5", "1.0.post456.dev34", "1.0.post456", "1.0.15", "1.1.dev1"}
	var cases []orderCase
	for i := 1; i < len(chain); i++ {
		cases = append(cases, orderCase{chain[i-1], chain[i], -1})
	}
	cases = append(cases,
		orderCase{"1.0", "1.0.0", 0},
		orderCase{"1.0.ALPHA1", "1.0a1", 0}, // normalized spellings
		orderCase{"1.0-rc.1", "1.0rc1", 0},
		orderCase{"1.0c1", "1.0rc1", 0},
		orderCase{"1.0-1", "1.0.post1", 0},
		orderCase{"1!0.5", "2.0", 1}, // epoch wins
		orderCase{"2.34.0.dev1", "2.34.0", -1},
		orderCase{"2.10", "2.9", 1},
	)
	checkOrder(t, PyPI, cases)

	for v, want := range map[string]bool{"2.34.2": false, "2.34.0.dev1": true, "1.0rc1": true, "1.0.post1": false,
		"1.0b2.post3": true} {
		if got := schemeFor(PyPI).prerelease(v); got != want {
			t.Errorf("pep440 prerelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestMavenOrdering(t *testing.T) {
	// Qualifier order of https://maven.apache.org/pom.html#version-order-specification.
	chain := []string{"1.0-alpha1", "1.0-alpha2", "1.0-beta1", "1.0-milestone1", "1.0-rc1", "1.0-SNAPSHOT",
		"1.0", "1.0-sp1", "1.0-whatever", "1.0.1"}
	var cases []orderCase
	for i := 1; i < len(chain); i++ {
		cases = append(cases, orderCase{chain[i-1], chain[i], -1})
	}
	cases = append(cases,
		orderCase{"1.0", "1", 0},
		orderCase{"1.0.0", "1", 0},
		orderCase{"1-ga", "1", 0},
		orderCase{"1.0.Final", "1.0", 0},
		orderCase{"1.0.RELEASE", "1.0", 0},
		orderCase{"1.0-cr1", "1.0-rc1", 0},
		orderCase{"1.0a1", "1.0-alpha-1", 0},
		orderCase{"1.0-m1", "1.0-milestone-1", 0},
		orderCase{"1.10", "1.9", 1},
		orderCase{"33.7.2-jre", "33.7.1-jre", 1},
		orderCase{"33.7.2-android", "33.7.2-jre", -1}, // unknown qualifiers: alphabetical
		orderCase{"10.0", "r09", 1},                   // a number outranks a word
	)
	checkOrder(t, Maven, cases)

	for v, want := range map[string]bool{"33.7.2-jre": false, "10.0-rc1": true, "1.0-SNAPSHOT": true, "1.0.M2": true,
		"23.0-rc1-android": true, "2.0.0.RELEASE": false, "1.0-sp1": false, "21-ea": true} {
		if got := schemeFor(Maven).prerelease(v); got != want {
			t.Errorf("maven prerelease(%q) = %v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]string{"33.7.2-jre": "jre", "32.1.3-android": "android", "1.0.Final": "",
		"1.0": "", "10.0-rc1": "", "2.0.0.RELEASE": ""} {
		if got := mavenFlavor(v); got != want {
			t.Errorf("mavenFlavor(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestGemOrdering(t *testing.T) {
	checkOrder(t, Gem, []orderCase{
		{"1.19.0.rc1", "1.19.0", -1},
		{"1.19.0.rc1", "1.18.10", 1},
		{"1.0.a", "1.0", -1},
		{"1.0.0", "1.0", 0},
		{"1.0.b1", "1.0.a2", 1},
		{"1.10", "1.9", 1},
		{"3.0.0.beta1", "3.0.0.rc1", -1},
	})
	for v, want := range map[string]bool{"1.19.4": false, "1.19.0.rc1": true, "2.0.0.alpha": true} {
		if got := schemeFor(Gem).prerelease(v); got != want {
			t.Errorf("gem prerelease(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestComposerOrdering(t *testing.T) {
	checkOrder(t, Composer, []orderCase{
		{"3.0.0-RC1", "3.0.0", -1},
		{"2.0.0-beta1", "2.0.0-beta2", -1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-RC1", "1.0.0-beta9", 1},
		{"1.0.0-patch1", "1.0.0", 1}, // a patch release follows the release
		{"v1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0.0", 0},
		{"3.10.0", "3.9.0", 1},
	})
	for v, want := range map[string]bool{"3.12.1": false, "3.0.0-RC1": true, "2.0.0-beta2": true, "1.0.0-p1": false,
		"dev-main": true} {
		if got := schemeFor(Composer).prerelease(v); got != want {
			t.Errorf("composer prerelease(%q) = %v, want %v", v, got, want)
		}
	}
}
