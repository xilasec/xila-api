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
// PEP 440 for PyPI ("4.0a1" < "4.0rc1" < "4.0" < "4.0.post1"), RubyGems'
// "a letter makes it a pre-release" ("1.0.0.pre" < "1.0.0"), and the native
// package-manager orderings of the distro ecosystems (dpkg for Debian/Ubuntu,
// rpmvercmp for Red Hat/Rocky Linux/AlmaLinux, apk for Alpine).
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
	case "Debian", "Ubuntu":
		return compareDpkg
	case "Alpine":
		return compareApk
	case "Red Hat", "Rocky Linux", "AlmaLinux":
		return compareRpm
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

// --- dpkg (Debian Policy Manual §5.6.12; dpkg's lib/dpkg/version.c verrevcmp) ---

// splitDpkg splits "[epoch:]upstream_version[-debian_revision]" into its three
// parts. Epoch defaults to 0, debian_revision to "0" when there is no hyphen —
// both per Debian Policy §5.6.12 ("missing is equivalent to 0").
func splitDpkg(v string) (epoch uint64, upstream, revision string) {
	revision = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch, _ = strconv.ParseUint(v[:i], 10, 64)
		v = v[i+1:]
	}
	upstream = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	}
	return
}

// dpkgOrder ranks one byte as dpkg's order(): '~' lowest (sorts before even
// the end of a part), then digits, then letters, then the end of the part (the
// zero byte, used here as the "past the end" sentinel), then every other byte.
func dpkgOrder(b byte) int {
	switch {
	case b == 0:
		// The end of a part ranks with digits: below every letter and above
		// only a tilde (Debian's own version.c test chain is
		// "~~" < "~~a" < "~" < "" < "a").
		return 0
	case b == '~':
		return -1
	case b >= '0' && b <= '9':
		return 0
	case (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'):
		return int(b)
	default:
		return int(b) + 256
	}
}

func byteAt(s string, i int) byte {
	if i < len(s) {
		return s[i]
	}
	return 0
}

// isDigitByte is isDigit for a byte, used throughout the distro comparators
// below, which work on ASCII version strings byte by byte.
func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

// compareDpkgPart implements dpkg's verrevcmp: alternating runs of non-digits
// (compared with dpkgOrder, one byte at a time) and digits (compared
// numerically, leading zeros ignored).
func compareDpkgPart(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigitByte(a[i])) || (j < len(b) && !isDigitByte(b[j])) {
			if ac, bc := dpkgOrder(byteAt(a, i)), dpkgOrder(byteAt(b, j)); ac != bc {
				return cmp.Compare(ac, bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && j < len(b) && isDigitByte(a[i]) && isDigitByte(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigitByte(a[i]) {
			return 1
		}
		if j < len(b) && isDigitByte(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return cmp.Compare(firstDiff, 0)
		}
	}
	return 0
}

// compareDpkg orders Debian/Ubuntu package versions per Debian Policy
// §5.6.12: epoch (numeric), then upstream_version and debian_revision, each by
// compareDpkgPart.
func compareDpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if c := cmp.Compare(ea, eb); c != 0 {
		return c
	}
	if c := compareDpkgPart(ua, ub); c != 0 {
		return c
	}
	return compareDpkgPart(ra, rb)
}

// --- rpm (rpmvercmp; rpm-software-management/rpm rpmio/rpmvercmp.cc) ---

// splitRpm splits "[epoch:]version[-release]" (RPM's NEVR). Epoch defaults to
// 0; release is "" when there is no hyphen (an OSV event may give a bare
// upstream version with no RPM release attached).
func splitRpm(v string) (epoch uint64, version, release string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if n, err := strconv.ParseUint(v[:i], 10, 64); err == nil {
			epoch = n
			v = v[i+1:]
		}
	}
	version = v
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		version, release = v[:i], v[i+1:]
	}
	return
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func isAlnum(c byte) bool { return isAlpha(c) || isDigitByte(c) }

// rpmvercmp is a direct port of RPM's own comparator (same structure,
// identifiers and comments as rpmio/rpmvercmp.cc, the upstream reference
// implementation): equal strings compare equal; otherwise alternating
// alphabetic/numeric segments compare (digits numerically, after stripping
// leading zeros; letters by ASCII), '~' sorts before anything including the
// end of a segment, '^' sorts after anything including the end of a segment,
// and whichever string still has characters left after the common prefix is
// newer. Reference cases: tests/rpmvercmp.at in the same repository.
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	isSep := func(c byte) bool { return isAlnum(c) || c == '~' || c == '^' }
	for i < len(a) || j < len(b) {
		for i < len(a) && !isSep(a[i]) {
			i++
		}
		for j < len(b) && !isSep(b[j]) {
			j++
		}
		ac, aEnd := byteAt(a, i), i >= len(a)
		bc, bEnd := byteAt(b, j), j >= len(b)

		// handle the tilde separator, it sorts before everything else
		if ac == '~' || bc == '~' {
			if ac != '~' {
				return 1
			}
			if bc != '~' {
				return -1
			}
			i++
			j++
			continue
		}
		// Handle caret separator. Concept is the same as tilde, except that if
		// one of the strings ends (base version), the other is considered as
		// higher version.
		if ac == '^' || bc == '^' {
			if aEnd {
				return -1
			}
			if bEnd {
				return 1
			}
			if ac != '^' {
				return 1
			}
			if bc != '^' {
				return -1
			}
			i++
			j++
			continue
		}
		// If we ran to the end of either, we are finished with the loop.
		if aEnd || bEnd {
			break
		}

		// grab first completely alpha or completely numeric segment
		si, sj := i, j
		var isNum bool
		if isDigitByte(a[i]) {
			for i < len(a) && isDigitByte(a[i]) {
				i++
			}
			for j < len(b) && isDigitByte(b[j]) {
				j++
			}
			isNum = true
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
			isNum = false
		}
		segA, segB := a[si:i], b[sj:j]

		// take care of the case where the two version segments are different
		// types: one numeric, the other alpha (i.e. empty) — numeric segments
		// are always newer than alpha segments
		if segB == "" {
			if isNum {
				return 1
			}
			return -1
		}
		if isNum {
			// throw away any leading zeros - it's a number, right?
			segA = strings.TrimLeft(segA, "0")
			segB = strings.TrimLeft(segB, "0")
			// whichever number has more digits wins
			if len(segA) != len(segB) {
				return cmp.Compare(len(segA), len(segB))
			}
		}
		// strcmp (byte-wise) decides which one is greater, whether the
		// segments are alpha or numeric.
		if c := strings.Compare(segA, segB); c != 0 {
			return c
		}
	}
	// this catches the case where all numeric and alpha segments have compared
	// identically but the segment separating characters were different
	if i >= len(a) && j >= len(b) {
		return 0
	}
	// whichever version still has characters left over wins
	if i >= len(a) {
		return -1
	}
	return 1
}

// compareRpm orders Red Hat/Rocky Linux/AlmaLinux package versions per RPM's
// NEVR: epoch (numeric), then version and release, each by rpmvercmp.
func compareRpm(a, b string) int {
	ea, va, ra := splitRpm(a)
	eb, vb, rb := splitRpm(b)
	if c := cmp.Compare(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 {
		return c
	}
	return rpmvercmp(ra, rb)
}

// --- apk (Alpine Package Keeper; apk-tools doc/apk-package.5.scd "PACKAGE
// NAMES AND VERSIONS": number{.number}...{letter}{_suffix{number}}...{-r#}) ---

// apkSuffixRank orders apk's suffix names, per the format doc: alpha, beta,
// pre, rc sort below a plain release; cvs, svn, git, hg, p sort above one. ""
// stands for "no suffix" at this position.
var apkSuffixRank = map[string]int{
	"alpha": 0, "beta": 1, "pre": 2, "rc": 3, "": 4,
	"cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9,
}

type apkSuffix struct {
	name string
	num  int64
}

type apkVersion struct {
	nums     []int64
	letter   string
	suffixes []apkSuffix
	revision int64
}

var (
	apkRevisionRe = regexp.MustCompile(`-r(\d+)$`)
	apkSuffixRe   = regexp.MustCompile(`^_([a-z]+)(\d*)`)
)

// parseApk reads an apk version into its numeric segments, optional trailing
// letter, ordered suffix groups and -r revision (0 when absent). A trailing
// "~hash" build-commit tag (apk-package.5.scd) carries no ordering rule in
// apk-tools' own comparator and is dropped — rare in advisory version
// strings, where it would only ever tie-break an otherwise identical version.
func parseApk(v string) apkVersion {
	out := apkVersion{}
	if m := apkRevisionRe.FindStringSubmatch(v); m != nil {
		out.revision, _ = strconv.ParseInt(m[1], 10, 64)
		v = v[:len(v)-len(m[0])]
	}
	if i := strings.IndexByte(v, '~'); i >= 0 {
		v = v[:i]
	}
	for {
		j := 0
		for j < len(v) && isDigitByte(v[j]) {
			j++
		}
		if j == 0 {
			break
		}
		n, _ := strconv.ParseInt(v[:j], 10, 64)
		out.nums = append(out.nums, n)
		v = v[j:]
		if !strings.HasPrefix(v, ".") {
			break
		}
		v = v[1:]
	}
	if len(v) > 0 && v[0] >= 'a' && v[0] <= 'z' {
		out.letter = string(v[0])
		v = v[1:]
	}
	for v != "" {
		m := apkSuffixRe.FindStringSubmatch(v)
		if m == nil {
			break
		}
		n := int64(0)
		if m[2] != "" {
			n, _ = strconv.ParseInt(m[2], 10, 64)
		}
		out.suffixes = append(out.suffixes, apkSuffix{name: m[1], num: n})
		v = v[len(m[0]):]
	}
	return out
}

// compareApk orders Alpine package versions: numeric segments (a shorter,
// terminating sequence sorts below one that continues — apk_version_compare_blob_fuzzy
// treats "ran out" as lower than any further digit), the optional letter,
// each suffix group by apkSuffixRank then its number, and finally the -r
// revision.
func compareApk(a, b string) int {
	va, vb := parseApk(a), parseApk(b)
	for i := range max(len(va.nums), len(vb.nums)) {
		switch {
		case i >= len(va.nums):
			return -1
		case i >= len(vb.nums):
			return 1
		}
		if c := cmp.Compare(va.nums[i], vb.nums[i]); c != 0 {
			return c
		}
	}
	if c := strings.Compare(va.letter, vb.letter); c != 0 {
		return c
	}
	for i := range max(len(va.suffixes), len(vb.suffixes)) {
		var sa, sb apkSuffix
		if i < len(va.suffixes) {
			sa = va.suffixes[i]
		}
		if i < len(vb.suffixes) {
			sb = vb.suffixes[i]
		}
		if c := cmp.Compare(apkSuffixRank[sa.name], apkSuffixRank[sb.name]); c != 0 {
			return c
		}
		if c := cmp.Compare(sa.num, sb.num); c != 0 {
			return c
		}
	}
	return cmp.Compare(va.revision, vb.revision)
}
