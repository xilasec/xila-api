package vulnmatch

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/sbom"
)

// versionCmp orders two versions of one package: <0, 0, >0.
type versionCmp func(a, b string) int

// comparatorFor picks the ordering an OSV range is evaluated with. SEMVER
// ranges use Semantic Versioning 2.0 precedence whatever the ecosystem (that's
// what the type promises); ECOSYSTEM ranges use the ecosystem's own rules where
// they differ from the repo-wide best-effort ordering (sbom.CompareVersions):
// PEP 440 for PyPI ("4.0a1" < "4.0rc1" < "4.0" < "4.0.post1") and RubyGems'
// "a letter makes it a pre-release" ("1.0.0.pre" < "1.0.0").
func comparatorFor(rangeType, ecosystem string) versionCmp {
	if strings.EqualFold(rangeType, "SEMVER") {
		return compareSemver
	}
	switch ecosystem {
	case "PyPI":
		return comparePEP440
	case "RubyGems":
		return compareGem
	case "npm", "crates.io", "Go", "Hex":
		return compareSemver
	default:
		return sbom.CompareVersions
	}
}

// --- Semantic Versioning 2.0 ---

type semver struct {
	core [3]uint64
	pre  []string
}

// parseSemver accepts "1.2.3", "v1.2.3-rc.1+build", and leniently "1.2" (missing
// parts are 0), which OSV/GitHub data occasionally carries.
func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var v semver
	core := s
	if i := strings.IndexByte(s, '-'); i >= 0 {
		core = s[:i]
		v.pre = strings.Split(s[i+1:], ".")
	}
	parts := strings.Split(core, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return v, false
		}
		v.core[i] = n
	}
	return v, true
}

// compareSemver implements SemVer 2.0 §11 precedence; versions that don't parse
// fall back to the repo's best-effort ordering.
func compareSemver(a, b string) int {
	va, okA := parseSemver(a)
	vb, okB := parseSemver(b)
	if !okA || !okB {
		return sbom.CompareVersions(a, b)
	}
	for i := range 3 {
		if c := cmp.Compare(va.core[i], vb.core[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(va.pre) == 0 && len(vb.pre) == 0:
		return 0
	case len(va.pre) == 0:
		return 1 // a release outranks its pre-releases
	case len(vb.pre) == 0:
		return -1
	}
	for i := range min(len(va.pre), len(vb.pre)) {
		x, y := va.pre[i], vb.pre[i]
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if c := cmp.Compare(nx, ny); c != 0 {
				return c
			}
		case ex == nil:
			return -1 // numeric identifiers have lower precedence
		case ey == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmp.Compare(len(va.pre), len(vb.pre))
}

// --- PEP 440 (PyPI) ---

var pep440Re = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
	`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
	`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d*))?` +
	`(?:[-_.]?(dev)[-_.]?(\d*))?` +
	`(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

// pep440Key is packaging's comparison key: (epoch, release with trailing zeros
// dropped, pre, post, dev), with the sentinel ranks PEP 440 prescribes.
type pep440Key struct {
	epoch   uint64
	release []uint64
	// preRank: -2 = dev-only release (sorts before its pre-releases), 0 = a/b/rc
	// (with preKind/preNum), 1 = no pre-release.
	preRank int
	preKind int // a=0, b=1, rc=2
	preNum  uint64
	post    int64 // -1 = none
	dev     int64 // math.MaxInt64 stand-in: devNone
}

const devNone = int64(1) << 62

func parsePEP440(s string) (pep440Key, bool) {
	m := pep440Re.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return pep440Key{}, false
	}
	k := pep440Key{preRank: 1, post: -1, dev: devNone}
	if m[1] != "" {
		k.epoch, _ = strconv.ParseUint(m[1], 10, 64)
	}
	for p := range strings.SplitSeq(m[2], ".") {
		n, _ := strconv.ParseUint(p, 10, 64)
		k.release = append(k.release, n)
	}
	for len(k.release) > 1 && k.release[len(k.release)-1] == 0 {
		k.release = k.release[:len(k.release)-1]
	}
	if m[3] != "" {
		k.preRank = 0
		switch m[3] {
		case "a", "alpha":
			k.preKind = 0
		case "b", "beta":
			k.preKind = 1
		default: // c, rc, pre, preview
			k.preKind = 2
		}
		k.preNum, _ = strconv.ParseUint(m[4], 10, 64)
	}
	switch {
	case m[5] != "":
		k.post, _ = strconv.ParseInt(m[5], 10, 64)
	case m[6] != "":
		k.post, _ = strconv.ParseInt(m[7], 10, 64)
	}
	if m[8] != "" {
		k.dev, _ = strconv.ParseInt(m[9], 10, 64)
		if m[3] == "" && k.post < 0 {
			k.preRank = -2 // 1.0.dev1 < 1.0a1
		}
	}
	return k, true
}

// comparePEP440 orders PyPI versions per PEP 440; unparseable input (legacy
// versions) falls back to the best-effort ordering.
func comparePEP440(a, b string) int {
	ka, okA := parsePEP440(a)
	kb, okB := parsePEP440(b)
	if !okA || !okB {
		return sbom.CompareVersions(a, b)
	}
	if c := cmp.Compare(ka.epoch, kb.epoch); c != 0 {
		return c
	}
	for i := range max(len(ka.release), len(kb.release)) {
		var x, y uint64
		if i < len(ka.release) {
			x = ka.release[i]
		}
		if i < len(kb.release) {
			y = kb.release[i]
		}
		if c := cmp.Compare(x, y); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(ka.preRank, kb.preRank); c != 0 {
		return c
	}
	if ka.preRank == 0 {
		if c := cmp.Compare(ka.preKind, kb.preKind); c != 0 {
			return c
		}
		if c := cmp.Compare(ka.preNum, kb.preNum); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(ka.post, kb.post); c != 0 {
		return c
	}
	return cmp.Compare(ka.dev, kb.dev)
}

// --- RubyGems (Gem::Version) ---

// gemSegments splits "1.0.0.pre2" into [1 0 0 pre 2], as Gem::Version does.
func gemSegments(v string) []string {
	v = strings.TrimSpace(strings.ReplaceAll(v, "-", ".pre."))
	var out []string
	for part := range strings.SplitSeq(v, ".") {
		cur := ""
		for _, r := range part {
			if cur != "" && isDigit(rune(cur[len(cur)-1])) != isDigit(r) {
				out = append(out, cur)
				cur = ""
			}
			cur += string(r)
		}
		if cur != "" {
			out = append(out, cur)
		}
	}
	// Trailing zeros are insignificant ("1.0" == "1.0.0").
	for len(out) > 1 && out[len(out)-1] == "0" {
		out = out[:len(out)-1]
	}
	return out
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// compareGem implements Gem::Version#<=>: numeric segments compare as numbers, a
// string segment sorts below any number (so it marks a pre-release), and a
// missing segment counts as 0.
func compareGem(a, b string) int {
	sa, sb := gemSegments(a), gemSegments(b)
	for i := range max(len(sa), len(sb)) {
		x, y := "0", "0"
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		nx, ex := strconv.ParseUint(x, 10, 64)
		ny, ey := strconv.ParseUint(y, 10, 64)
		switch {
		case ex == nil && ey == nil:
			if c := cmp.Compare(nx, ny); c != 0 {
				return c
			}
		case ex == nil:
			return 1
		case ey == nil:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}
