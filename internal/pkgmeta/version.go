package pkgmeta

import (
	"cmp"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/xilasec/xila-api/internal/sbom"
)

// scheme orders one ecosystem's versions and recognises its pre-releases. Every
// ecosystem has its own rules — "1.0.0-1" sorts before "1.0.0-alpha" in semver,
// "1.0.post1" after "1.0" in PEP 440, "1.0-sp1" after "1.0" in Maven — so the
// generic sbom.CompareVersions is only the fallback for strings a scheme can't
// parse.
type scheme struct {
	compare    func(a, b string) int
	prerelease func(v string) bool
}

// schemeFor returns the version rules of a purl type.
func schemeFor(ecosystem string) scheme {
	switch ecosystem {
	case NPM, Cargo, Golang:
		return scheme{compare: func(a, b string) int { return compareSemver(a, b, false) }, prerelease: semverPre}
	case NuGet:
		// NuGet is SemVer 2.0 with up to four numeric parts and
		// case-insensitive labels (https://learn.microsoft.com/en-us/nuget/concepts/package-versioning).
		return scheme{compare: func(a, b string) int { return compareSemver(a, b, true) }, prerelease: semverPre}
	case PyPI:
		return scheme{compare: comparePEP440, prerelease: pep440Pre}
	case Maven:
		return scheme{compare: compareMaven, prerelease: mavenPre}
	case Gem:
		return scheme{compare: compareGem, prerelease: gemPre}
	case Composer:
		return scheme{compare: compareComposer, prerelease: composerPre}
	}
	return scheme{compare: sbom.CompareVersions, prerelease: func(v string) bool { return strings.Contains(v, "-") }}
}

// CompareVersions orders two versions of one ecosystem (a purl type) by its
// own rules: negative when a < b, zero when equal, positive when a > b. An
// unknown ecosystem uses the generic comparison.
func CompareVersions(ecosystem, a, b string) int {
	return schemeFor(ecosystem).compare(a, b)
}

// cmpNum compares two digit strings of any length numerically.
func cmpNum(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if c := cmp.Compare(len(a), len(b)); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- semver

// splitSemver splits "v1.2.3-rc.1+build" into core ["1","2","3"] and
// pre-release "rc.1". ok is false when the core isn't dot-separated numbers.
func splitSemver(v string) (core []string, pre string, ok bool) {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "=vV")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // build metadata (incl. Go's +incompatible) never orders
	}
	c, pre, _ := strings.Cut(v, "-")
	core = strings.Split(c, ".")
	for _, s := range core {
		if !isDigits(s) {
			return nil, "", false
		}
	}
	return core, pre, true
}

func semverPre(v string) bool {
	if _, pre, ok := splitSemver(v); ok {
		return pre != ""
	}
	return strings.Contains(v, "-")
}

// compareSemver implements SemVer 2.0 precedence (https://semver.org/#spec-item-11):
// numeric core parts (any count; missing parts are 0), then a version without a
// pre-release outranks one with; pre-release identifiers compare numerically
// when both are numbers, a number sorts below a word, words compare in ASCII
// order, and a longer identifier list wins a tie on the shared prefix.
func compareSemver(a, b string, foldCase bool) int {
	ca, pa, oka := splitSemver(a)
	cb, pb, okb := splitSemver(b)
	if !oka || !okb {
		return sbom.CompareVersions(a, b)
	}
	for i := range max(len(ca), len(cb)) {
		x, y := "0", "0"
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	switch {
	case pa == pb:
		return 0
	case pa == "":
		return 1
	case pb == "":
		return -1
	}
	if foldCase {
		pa, pb = strings.ToLower(pa), strings.ToLower(pb)
	}
	ia, ib := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := range min(len(ia), len(ib)) {
		na, nb := isDigits(ia[i]), isDigits(ib[i])
		var c int
		switch {
		case na && nb:
			c = cmpNum(ia[i], ib[i])
		case na:
			c = -1
		case nb:
			c = 1
		default:
			c = strings.Compare(ia[i], ib[i])
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(ia), len(ib))
}

// ---------------------------------------------------------------- PEP 440

// pep440Re is the canonical version pattern from PEP 440 appendix B
// (https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions).
var pep440Re = regexp.MustCompile(`(?i)^\s*v?(?:(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)` +
	`(?P<pre>[-_\.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_\.]?(?P<pre_n>[0-9]+)?)?` +
	`(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?` +
	`(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*$`)

// pep440 is a parsed version reduced to its sort key (packaging's _cmpkey).
type pep440 struct {
	epoch   string
	release []string // trailing zeros removed: 1.0 == 1.0.0
	// pre/post/dev ranks use -1 / +1 sentinels for "sorts before / after any
	// value", mirroring packaging's NegativeInfinity / Infinity.
	preRank int // -2: dev-only release, 0..2: a/b/rc, 3: none
	preNum  string
	hasPost bool
	postNum string
	hasDev  bool
	devNum  string
	local   string
}

func parsePEP440(v string) (pep440, bool) {
	m := pep440Re.FindStringSubmatch(v)
	if m == nil {
		return pep440{}, false
	}
	g := func(name string) string { return m[pep440Re.SubexpIndex(name)] }
	p := pep440{epoch: cmp.Or(g("epoch"), "0"), local: strings.ToLower(g("local"))}
	p.release = strings.Split(g("release"), ".")
	for len(p.release) > 1 && strings.TrimLeft(p.release[len(p.release)-1], "0") == "" {
		p.release = p.release[:len(p.release)-1]
	}
	p.hasDev = g("dev") != ""
	p.devNum = cmp.Or(g("dev_n"), "0")
	p.hasPost = g("post") != ""
	p.postNum = cmp.Or(g("post_n1"), g("post_n2"), "0")
	switch strings.ToLower(g("pre_l")) {
	case "a", "alpha":
		p.preRank = 0
	case "b", "beta":
		p.preRank = 1
	case "c", "rc", "pre", "preview":
		p.preRank = 2
	default:
		// 1.0.dev1 sorts before 1.0a1; a plain release after every pre-release.
		p.preRank = 3
		if p.hasDev && !p.hasPost {
			p.preRank = -2
		}
	}
	p.preNum = cmp.Or(g("pre_n"), "0")
	return p, true
}

func pep440Pre(v string) bool {
	p, ok := parsePEP440(v)
	if !ok {
		return strings.ContainsAny(strings.ToLower(v), "abcdefghijklmnopqrstuvwxyz")
	}
	return (p.preRank >= 0 && p.preRank <= 2) || p.preRank == -2 || p.hasDev
}

// comparePEP440 orders Python versions per PEP 440
// (https://peps.python.org/pep-0440/#summary-of-permitted-suffixes-and-relative-ordering):
// epoch, release, then .devN < aN < bN < rcN < release < .postN, with a
// local version label ("+ubuntu1") sorting after the same public version.
func comparePEP440(a, b string) int {
	pa, oka := parsePEP440(a)
	pb, okb := parsePEP440(b)
	if !oka || !okb {
		return sbom.CompareVersions(a, b)
	}
	if c := cmpNum(pa.epoch, pb.epoch); c != 0 {
		return c
	}
	for i := range max(len(pa.release), len(pb.release)) {
		x, y := "0", "0"
		if i < len(pa.release) {
			x = pa.release[i]
		}
		if i < len(pb.release) {
			y = pb.release[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(pa.preRank, pb.preRank); c != 0 {
		return c
	}
	if pa.preRank >= 0 && pa.preRank <= 2 {
		if c := cmpNum(pa.preNum, pb.preNum); c != 0 {
			return c
		}
	}
	switch {
	case pa.hasPost != pb.hasPost:
		if pa.hasPost {
			return 1
		}
		return -1
	case pa.hasPost:
		if c := cmpNum(pa.postNum, pb.postNum); c != 0 {
			return c
		}
	}
	switch {
	case pa.hasDev != pb.hasDev:
		if pa.hasDev {
			return -1
		}
		return 1
	case pa.hasDev:
		if c := cmpNum(pa.devNum, pb.devNum); c != 0 {
			return c
		}
	}
	return strings.Compare(pa.local, pb.local)
}

// ---------------------------------------------------------------- Maven

// mavenQualifiers is Maven's well-known qualifier order; "" is the release.
// Unknown qualifiers sort after all of them, alphabetically
// (https://maven.apache.org/pom.html#version-order-specification,
// org.apache.maven.artifact.versioning.ComparableVersion).
var mavenQualifiers = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

const mavenReleaseIndex = "5"

type mvKind int

const (
	mvInt mvKind = iota
	mvString
	mvList
)

type mvItem struct {
	kind mvKind
	num  string // mvInt, leading zeros trimmed
	str  string // mvString, aliased qualifier
	list []*mvItem
}

func mvIntItem(s string) *mvItem {
	return &mvItem{kind: mvInt, num: strings.TrimLeft(s, "0")}
}

func mvStringItem(s string, followedByDigit bool) *mvItem {
	if followedByDigit && len(s) == 1 {
		switch s {
		case "a":
			s = "alpha"
		case "b":
			s = "beta"
		case "m":
			s = "milestone"
		}
	}
	switch s {
	case "ga", "final", "release":
		s = ""
	case "cr":
		s = "rc"
	}
	return &mvItem{kind: mvString, str: s}
}

func (it *mvItem) isNull() bool {
	switch it.kind {
	case mvInt:
		return it.num == ""
	case mvString:
		return it.str == ""
	}
	return len(it.list) == 0
}

func mvComparable(q string) string {
	for i, k := range mavenQualifiers {
		if k == q {
			return strconv.Itoa(i)
		}
	}
	return strconv.Itoa(len(mavenQualifiers)) + "-" + q
}

// compareTo mirrors ComparableVersion's Item.compareTo; other == nil is
// "nothing there" (the shorter version ran out).
func (it *mvItem) compareTo(other *mvItem) int {
	switch it.kind {
	case mvInt:
		if other == nil {
			if it.num == "" {
				return 0
			}
			return 1
		}
		if other.kind == mvInt {
			return cmpNum(it.num, other.num)
		}
		return 1 // a number outranks a qualifier or a sub-list
	case mvString:
		if other == nil {
			return strings.Compare(mvComparable(it.str), mavenReleaseIndex)
		}
		switch other.kind {
		case mvInt:
			return -1
		case mvString:
			return strings.Compare(mvComparable(it.str), mvComparable(other.str))
		}
		return -1
	}
	if other == nil {
		if len(it.list) == 0 {
			return 0
		}
		return it.list[0].compareTo(nil)
	}
	switch other.kind {
	case mvInt:
		return -1
	case mvString:
		return 1
	}
	for i := range max(len(it.list), len(other.list)) {
		var l, r *mvItem
		if i < len(it.list) {
			l = it.list[i]
		}
		if i < len(other.list) {
			r = other.list[i]
		}
		var c int
		switch {
		case l == nil && r == nil:
		case l == nil:
			c = -r.compareTo(nil)
		default:
			c = l.compareTo(r)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

func (it *mvItem) normalize() {
	for i := len(it.list) - 1; i >= 0; i-- {
		last := it.list[i]
		if last.isNull() {
			it.list = append(it.list[:i], it.list[i+1:]...)
		} else if last.kind != mvList {
			break
		}
	}
}

// parseMaven is ComparableVersion.parseVersion: '.' separates items, '-' (and
// a switch between digits and letters) opens a nested list, and trailing
// "null" items (0, "", ga/final/release) are dropped, so 1.0 == 1 == 1-ga.
func parseMaven(v string) *mvItem {
	v = strings.ToLower(strings.TrimSpace(v))
	root := &mvItem{kind: mvList}
	list := root
	stack := []*mvItem{root}
	push := func() {
		l := &mvItem{kind: mvList}
		list.list = append(list.list, l)
		list = l
		stack = append(stack, l)
	}
	parseItem := func(digit bool, s string) *mvItem {
		if digit {
			return mvIntItem(s)
		}
		return mvStringItem(s, false)
	}
	digit := false
	start := 0
	for i := range len(v) {
		c := v[i]
		switch {
		case c == '.':
			if i == start {
				list.list = append(list.list, mvIntItem("0"))
			} else {
				list.list = append(list.list, parseItem(digit, v[start:i]))
			}
			start = i + 1
		case c == '-':
			if i == start {
				list.list = append(list.list, mvIntItem("0"))
			} else {
				list.list = append(list.list, parseItem(digit, v[start:i]))
			}
			start = i + 1
			push()
		case c >= '0' && c <= '9':
			if !digit && i > start {
				list.list = append(list.list, mvStringItem(v[start:i], true))
				start = i
				push()
			}
			digit = true
		default:
			if digit && i > start {
				list.list = append(list.list, parseItem(true, v[start:i]))
				start = i
				push()
			}
			digit = false
		}
	}
	if len(v) > start {
		list.list = append(list.list, parseItem(digit, v[start:]))
	}
	for i := len(stack) - 1; i >= 0; i-- {
		stack[i].normalize()
	}
	return root
}

func compareMaven(a, b string) int {
	return parseMaven(a).compareTo(parseMaven(b))
}

// mavenPreWords are qualifiers that mark a build as not-yet-released. Maven's
// ordering puts alpha/beta/milestone/rc/snapshot before the release; preview,
// ea and dev are common conventions ComparableVersion doesn't know.
var mavenPreWords = map[string]bool{"alpha": true, "beta": true, "milestone": true, "rc": true, "snapshot": true,
	"preview": true, "ea": true, "dev": true, "pre": true}

func mavenPre(v string) bool {
	var walk func(*mvItem) bool
	walk = func(it *mvItem) bool {
		switch it.kind {
		case mvString:
			return mavenPreWords[it.str]
		case mvList:
			for _, c := range it.list {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(parseMaven(v))
}

// mavenFlavor is a stable trailing qualifier that names a build variant rather
// than a stage — Guava's "33.0.0-jre" vs "33.0.0-android". Comparing across
// variants would call every -android user "behind" the -jre twin.
func mavenFlavor(v string) string {
	v = strings.ToLower(v)
	i := strings.LastIndexAny(v, "-.")
	if i < 0 {
		return ""
	}
	q := v[i+1:]
	if q == "" || strings.IndexFunc(q, func(r rune) bool { return !unicode.IsLetter(r) }) >= 0 {
		return ""
	}
	if mavenPreWords[q] || q == "ga" || q == "final" || q == "release" || q == "sp" || q == "cr" {
		return ""
	}
	return q
}

// ---------------------------------------------------------------- RubyGems

var gemSegRe = regexp.MustCompile(`[0-9]+|[a-zA-Z]+`)

// gemSegments is Gem::Version#canonical_segments: the numeric release part
// and the pre-release part (from the first letter on), each with trailing
// zeros dropped.
func gemSegments(v string) []string {
	segs := gemSegRe.FindAllString(v, -1)
	split := len(segs)
	for i, s := range segs {
		if !isDigits(s) {
			split = i
			break
		}
	}
	trim := func(p []string) []string {
		for len(p) > 0 && isDigits(p[len(p)-1]) && strings.TrimLeft(p[len(p)-1], "0") == "" {
			p = p[:len(p)-1]
		}
		return p
	}
	rel := trim(append([]string(nil), segs[:split]...))
	pre := trim(append([]string(nil), segs[split:]...))
	return append(rel, pre...)
}

func gemPre(v string) bool {
	return strings.IndexFunc(v, unicode.IsLetter) >= 0
}

// compareGem is Gem::Version#<=> (https://github.com/rubygems/rubygems/blob/master/lib/rubygems/version.rb):
// segments pairwise, a missing segment counts as 0, and a letter segment sorts
// below a number — so 1.0.a < 1.0 < 1.0.1.
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
		if x == y {
			continue
		}
		nx, ny := isDigits(x), isDigits(y)
		switch {
		case nx && ny:
			if c := cmpNum(x, y); c != 0 {
				return c
			}
		case nx:
			return 1
		case ny:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return 0
}

// ---------------------------------------------------------------- Composer

// composerRe is Composer's VersionParser modifier grammar
// (https://github.com/composer/semver/blob/main/src/VersionParser.php):
// numeric release, an optional stability suffix and an optional -dev.
var composerRe = regexp.MustCompile(`(?i)^v?(\d+(?:\.\d+)*)(?:[._-]?(stable|beta|b|rc|alpha|a|patch|pl|p)((?:[.-]?\d+)*))?([.-]?dev)?$`)

type composerVersion struct {
	release []string
	rank    int // alpha 1, beta 2, RC 3, stable 4, patch 5
	num     []string
	dev     bool
}

func parseComposer(v string) (composerVersion, bool) {
	m := composerRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return composerVersion{}, false
	}
	cv := composerVersion{release: strings.Split(m[1], "."), rank: 4, dev: m[4] != ""}
	switch strings.ToLower(m[2]) {
	case "alpha", "a":
		cv.rank = 1
	case "beta", "b":
		cv.rank = 2
	case "rc":
		cv.rank = 3
	case "patch", "pl", "p":
		cv.rank = 5
	}
	cv.num = strings.FieldsFunc(m[3], func(r rune) bool { return r == '.' || r == '-' })
	return cv, true
}

func composerPre(v string) bool {
	cv, ok := parseComposer(v)
	if !ok {
		return true // dev branches and other non-releases
	}
	return cv.rank < 4 || cv.dev
}

// compareComposer orders Packagist versions: release numbers (padded), then
// stability alpha < beta < RC < stable < patch, then the stability's number;
// a -dev suffix sorts before the same version without one.
func compareComposer(a, b string) int {
	ca, oka := parseComposer(a)
	cb, okb := parseComposer(b)
	if !oka || !okb {
		return sbom.CompareVersions(a, b)
	}
	for i := range max(len(ca.release), len(cb.release), 4) {
		x, y := "0", "0"
		if i < len(ca.release) {
			x = ca.release[i]
		}
		if i < len(cb.release) {
			y = cb.release[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	if c := cmp.Compare(ca.rank, cb.rank); c != 0 {
		return c
	}
	for i := range max(len(ca.num), len(cb.num)) {
		x, y := "0", "0"
		if i < len(ca.num) {
			x = ca.num[i]
		}
		if i < len(cb.num) {
			y = cb.num[i]
		}
		if c := cmpNum(x, y); c != 0 {
			return c
		}
	}
	switch {
	case ca.dev == cb.dev:
		return 0
	case ca.dev:
		return -1
	}
	return 1
}
