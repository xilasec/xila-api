package vulnmatch

import "testing"

// TestCompareDpkg checks Debian Policy Manual §5.6.12's own worked example for
// tilde ordering (https://www.debian.org/doc/debian-policy/ch-controlfields.html#version),
// plus epoch and debian_revision precedence.
func TestCompareDpkg(t *testing.T) {
	// "~~", "~~a", "~", the empty part, "a" — each strictly less than the next.
	chain := []string{"1.0~~", "1.0~~a", "1.0~", "1.0", "1.0a"}
	for i := range len(chain) - 1 {
		a, b := chain[i], chain[i+1]
		if compareDpkg(a, b) >= 0 || compareDpkg(b, a) <= 0 {
			t.Errorf("want %q < %q", a, b)
		}
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1:1.0", "2.0", 1},     // an epoch outranks any upstream_version
		{"1.0-1", "1.0", 1},     // missing debian_revision is "0"
		{"1.0-2", "1.0-10", -1}, // revisions compare numerically, not lexically
		{"3.0.11-1~deb12u2", "3.0.11-1", -1},
		{"1.18.0-6.1+deb11u3", "1.18.0-6.1+deb11u1", 1},
		{"7.0.4-2", "7.0.10-1", -1}, // "4" vs "10" numerically, not as strings
	}
	for _, c := range cases {
		if got := compareDpkg(c.a, c.b); sign(got) != sign(c.want) {
			t.Errorf("compareDpkg(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// TestCompareRpm is rpm's own version comparison test suite
// (https://github.com/rpm-software-management/rpm/blob/master/tests/rpmvercmp.at),
// a representative subset covering basic ordering, the leading-zero-digit
// quirks, and tilde/caret sorting.
func TestCompareRpm(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"2.0.1", "2.0.1", 0},
		{"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1},
		{"2.0.1a", "2.0.1a", 0},
		{"2.0.1a", "2.0.1", 1},
		{"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0},
		{"5.5p1", "5.5p2", -1},
		{"5.5p2", "5.5p1", 1},
		{"5.5p10", "5.5p10", 0},
		{"5.5p1", "5.5p10", -1},
		{"5.5p10", "5.5p1", 1},
		{"10xyz", "10.1xyz", -1},
		{"10.1xyz", "10xyz", 1},
		{"xyz10", "xyz10", 0},
		{"xyz10", "xyz10.1", -1},
		{"xyz10.1", "xyz10", 1},
		{"xyz.4", "xyz.4", 0},
		{"xyz.4", "8", -1},
		{"8", "xyz.4", 1},
		{"xyz.4", "2", -1},
		{"2", "xyz.4", 1},
		{"5.5p2", "5.6p1", -1},
		{"5.6p1", "5.5p2", 1},
		{"5.6p1", "6.5p1", -1},
		{"6.5p1", "5.6p1", 1},
		{"6.0.rc1", "6.0", 1},
		{"6.0", "6.0.rc1", -1},
		{"10b2", "10a1", 1},
		{"10a2", "10b2", -1},
		{"1.0aa", "1.0aa", 0},
		{"1.0a", "1.0aa", -1},
		{"1.0aa", "1.0a", 1},
		{"10.0001", "10.0001", 0},
		{"10.0001", "10.1", 0},
		{"10.1", "10.0001", 0},
		{"10.0001", "10.0039", -1},
		{"10.0039", "10.0001", 1},
		{"4.999.9", "5.0", -1},
		{"5.0", "4.999.9", 1},
		{"20101121", "20101121", 0},
		{"20101121", "20101122", -1},
		{"20101122", "20101121", 1},
		{"2_0", "2_0", 0},
		{"2.0", "2_0", 0},
		{"2_0", "2.0", 0},
		{"a", "a", 0},
		{"a+", "a+", 0},
		{"a+", "a_", 0},
		{"a_", "a+", 0},
		{"+a", "+a", 0},
		{"+a", "_a", 0},
		{"_a", "+a", 0},
		{"+_", "+_", 0},
		{"_+", "+_", 0},
		{"_+", "_+", 0},
		{"+", "_", 0},
		{"_", "+", 0},
		// Tilde sorting.
		{"1.0~rc1", "1.0~rc1", 0},
		{"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~rc2", "1.0~rc1", 1},
		{"1.0~rc1~git123", "1.0~rc1~git123", 0},
		{"1.0~rc1~git123", "1.0~rc1", -1},
		{"1.0~rc1", "1.0~rc1~git123", 1},
		// Caret sorting.
		{"1.0^", "1.0^", 0},
		{"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1},
		{"1.0^git1", "1.0^git1", 0},
		{"1.0^git1", "1.0", 1},
		{"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1},
		{"1.0^git2", "1.0^git1", 1},
		{"1.0^git1", "1.01", -1},
		{"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0^20160101", 0},
		{"1.0^20160101", "1.0.1", -1},
		{"1.0.1", "1.0^20160101", 1},
		{"1.0^20160101^git1", "1.0^20160101^git1", 0},
		{"1.0^20160102", "1.0^20160101^git1", 1},
		{"1.0^20160101^git1", "1.0^20160102", -1},
		// Tilde and caret together.
		{"1.0~rc1^git1", "1.0~rc1^git1", 0},
		{"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc1^git1", -1},
		{"1.0^git1~pre", "1.0^git1~pre", 0},
		{"1.0^git1", "1.0^git1~pre", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
	}
	for _, c := range cases {
		if got := rpmvercmp(c.a, c.b); sign(got) != c.want {
			t.Errorf("rpmvercmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	// Epoch and release: RPM's NEVR (epoch:version-release).
	evr := []struct {
		a, b string
		want int
	}{
		{"1:1.0-1", "2.0-1", 1}, // epoch outranks version
		{"1.0-1", "1.0-2", -1},  // release breaks a version tie
		{"0:1.0-1", "1.0-1", 0}, // an explicit epoch 0 is the same as none
	}
	for _, c := range evr {
		if got := compareRpm(c.a, c.b); sign(got) != c.want {
			t.Errorf("compareRpm(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestCompareApk checks apk-tools' documented suffix ordering
// (doc/apk-package.5.scd: "alpha, beta, pre, rc, <no suffix>, cvs, svn, git,
// hg, p") and the -r revision / numeric segment rules, with reference cases
// from the apkversion library's own examples
// (https://github.com/typesafe-docs/apkversion): compare("1.0_rc1","1.0") < 0,
// compare("1.0-r1","1.0") > 0, compare("1.0_p1","1.0-r5") > 0.
func TestCompareApk(t *testing.T) {
	// The full suffix order, low to high, each strictly increasing.
	order := []string{
		"1.0_alpha1", "1.0_beta1", "1.0_pre1", "1.0_rc1", "1.0",
		"1.0_cvs1", "1.0_svn1", "1.0_git1", "1.0_hg1", "1.0_p1",
	}
	for i := range len(order) - 1 {
		a, b := order[i], order[i+1]
		if compareApk(a, b) >= 0 || compareApk(b, a) <= 0 {
			t.Errorf("want %q < %q", a, b)
		}
	}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0.1", -1},
		{"1.2.3", "1.3.0", -1},
		{"1.0_rc1", "1.0", -1},
		{"1.0-r1", "1.0", 1},
		{"1.0_p1", "1.0-r5", 1},
		{"1.0-r1", "1.0-r2", -1},
		{"3.0.9-r0", "3.0.9-r1", -1},
		{"1.1.1n-r0", "1.1.1t-r0", -1},
	}
	for _, c := range cases {
		if got := compareApk(c.a, c.b); sign(got) != c.want {
			t.Errorf("compareApk(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestDistroEcosystem checks the OSV ecosystem names resolved from deb/rpm/apk
// purls' `distro` qualifier, including the exact codenames a real Debian-OSV
// advisory uses (testdata/osv/DEBIAN-CVE-2024-4603.json: distro=bookworm /
// trixie / forky for ecosystems Debian:12 / 13 / 14).
func TestDistroEcosystem(t *testing.T) {
	cases := []struct {
		purlStr string
		want    string
		ok      bool
	}{
		{"pkg:deb/debian/openssl@3.0.9-1?arch=source&distro=bookworm", "Debian:12", true},
		{"pkg:deb/debian/openssl@3.2.2-1?arch=source&distro=trixie", "Debian:13", true},
		{"pkg:deb/debian/openssl@3.2.2-1?arch=source&distro=forky", "Debian:14", true},
		{"pkg:deb/debian/openssl@3.0.9-1?distro=12", "Debian:12", true},
		{"pkg:deb/debian/openssl@3.0.9-1", "", false}, // no distro qualifier: unmapped
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=22.04", "Ubuntu:22.04:LTS", true},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=jammy", "Ubuntu:22.04:LTS", true},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=23.04", "Ubuntu:23.04", false}, // non-LTS, checked below
		{"pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64&distro=3.18.4", "Alpine:v3.18", true},
		{"pkg:apk/alpine/openssl@3.1.4-r5?distro=v3.16", "Alpine:v3.16", true},
		{"pkg:rpm/rhel/bash@5.1.8-6.el9?distro=rhel-9", "Red Hat:9", true},
		{"pkg:rpm/rocky/bash@5.1.8-4.el9_1?distro=rocky-9", "Rocky Linux:9", true},
		{"pkg:rpm/almalinux/bash@5.1.8-4.el9_1?distro=almalinux-9", "AlmaLinux:9", true},
	}
	for _, c := range cases {
		p, ok := parsePurl(c.purlStr)
		if !ok {
			t.Fatalf("parsePurl(%q) failed", c.purlStr)
		}
		eco := ecosystemOf(p)
		if c.want == "Ubuntu:23.04" {
			// non-LTS: the release without ":LTS", checked for real here.
			if eco != "Ubuntu:23.04" {
				t.Errorf("ecosystemOf(%q) = %q, want Ubuntu:23.04 (non-LTS)", c.purlStr, eco)
			}
			continue
		}
		if c.ok && eco != c.want {
			t.Errorf("ecosystemOf(%q) = %q, want %q", c.purlStr, eco, c.want)
		}
		if !c.ok && eco != "" {
			t.Errorf("ecosystemOf(%q) = %q, want unmapped", c.purlStr, eco)
		}
	}
}

// TestValidEcosystemName checks the ecosystem names a private advisory may be
// saved with: plain language ecosystems, a distro family ("any release"), and
// a release-qualified distro ecosystem in distroEcosystem's exact form.
func TestValidEcosystemName(t *testing.T) {
	valid := []string{"npm", "PyPI", "Debian", "Alpine", "Red Hat",
		"Debian:12", "Ubuntu:22.04:LTS", "Ubuntu:23.04", "Alpine:v3.18", "Red Hat:9", "Rocky Linux:9", "AlmaLinux:9"}
	for _, e := range valid {
		if !validEcosystemName(e) {
			t.Errorf("validEcosystemName(%q) = false, want true", e)
		}
	}
	invalid := []string{"debian", "Debian:bookworm", "Ubuntu:22.04:lts", "Alpine:3.18", "Fedora", "Fedora:38"}
	for _, e := range invalid {
		if validEcosystemName(e) {
			t.Errorf("validEcosystemName(%q) = true, want false", e)
		}
	}
}
