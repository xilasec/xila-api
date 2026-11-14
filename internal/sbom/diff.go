package sbom

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Change classifies how a package differs between two snapshots.
type Change string

const (
	ChangeAdded      Change = "added"
	ChangeRemoved    Change = "removed"
	ChangeUpgraded   Change = "upgraded"
	ChangeDowngraded Change = "downgraded"
	// ChangeChanged: the version moved but the direction isn't decidable — the
	// versions don't compare (e.g. two git hashes), or several versions of the
	// package are present on a side.
	ChangeChanged Change = "changed"
)

// PackageDiff is one package that differs between base and head. A package is
// identified by its purl without version/qualifiers, or type/group/name when it
// has no purl, so "lodash 4.17.20 → 4.17.21" is one upgrade, not a removal plus
// an addition.
type PackageDiff struct {
	Key    string   `json:"key"`
	Name   string   `json:"name"`
	Group  string   `json:"group"`
	Change Change   `json:"change"`
	From   []string `json:"from"` // versions in base
	To     []string `json:"to"`   // versions in head
	Scope  string   `json:"scope"`
	Direct *bool    `json:"direct"`
	// Vulnerabilities this change removed / brought in for this package.
	FixedVulns      []string `json:"fixed_vulns"`
	IntroducedVulns []string `json:"introduced_vulns"`
}

// Diff is how a snapshot (head) differs from an earlier one (base).
type Diff struct {
	Base      *Sbom         `json:"base"` // nil: head is the first snapshot of its artifact
	Head      Sbom          `json:"head"`
	Changes   []PackageDiff `json:"changes"`
	Unchanged int           `json:"unchanged"`
	// Services that differ (added/removed/changed), by DiffServices.
	Services []ServiceDiff `json:"services"`
	Summary  DiffSummary   `json:"summary"`
}

// DiffSummary counts the changes and the snapshot-wide vulnerability movement:
// what head carries that base didn't (introduced) and the reverse (fixed).
type DiffSummary struct {
	Added           int      `json:"added"`
	Removed         int      `json:"removed"`
	Upgraded        int      `json:"upgraded"`
	Downgraded      int      `json:"downgraded"`
	Changed         int      `json:"changed"`
	VulnsIntroduced []string `json:"vulns_introduced"`
	VulnsFixed      []string `json:"vulns_fixed"`
	ServicesAdded   int      `json:"services_added"`
	ServicesRemoved int      `json:"services_removed"`
	ServicesChanged int      `json:"services_changed"`
}

// packageKey identifies a package across versions.
func packageKey(c Component) string {
	if c.Purl != "" {
		p := c.Purl
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			p = p[:i]
		}
		// The version follows the last '@' after the type ("pkg:npm/%40scope/x@1"
		// encodes the scope's '@', so a literal one only ever marks the version).
		if i := strings.LastIndex(p, "@"); i > strings.Index(p, "/") {
			p = p[:i]
		}
		return strings.ToLower(p)
	}
	return strings.ToLower(c.Type + "/" + c.Group + "/" + c.Name)
}

type side struct {
	versions []string
	vulns    []string
	sample   ComponentHit
}

func collect(cs []ComponentHit) (map[string]*side, []string) {
	out := map[string]*side{}
	var all []string
	for _, c := range cs {
		k := packageKey(c.Component)
		s := out[k]
		if s == nil {
			s = &side{sample: c}
			out[k] = s
		}
		if !slices.Contains(s.versions, c.Version) {
			s.versions = append(s.versions, c.Version)
		}
		for _, v := range c.Vulns {
			if !slices.Contains(s.vulns, v) {
				s.vulns = append(s.vulns, v)
			}
			if !slices.Contains(all, v) {
				all = append(all, v)
			}
		}
	}
	for _, s := range out {
		slices.SortFunc(s.versions, CompareVersions)
		slices.Sort(s.vulns)
	}
	slices.Sort(all)
	return out, all
}

// minus returns the elements of a not in b (both sorted inputs not required).
func minus(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// DiffComponents compares two snapshots' components. Pure.
func DiffComponents(base, head []ComponentHit) ([]PackageDiff, int, DiffSummary) {
	b, bVulns := collect(base)
	h, hVulns := collect(head)

	keys := make([]string, 0, len(b)+len(h))
	for k := range b {
		keys = append(keys, k)
	}
	for k := range h {
		if _, ok := b[k]; !ok {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)

	var (
		changes   = []PackageDiff{}
		unchanged int
		sum       = DiffSummary{VulnsIntroduced: minus(hVulns, bVulns), VulnsFixed: minus(bVulns, hVulns)}
	)
	for _, k := range keys {
		bs, hs := b[k], h[k]
		d := PackageDiff{Key: k, From: []string{}, To: []string{}}
		switch {
		case bs == nil:
			d.Change, d.To = ChangeAdded, hs.versions
		case hs == nil:
			d.Change, d.From = ChangeRemoved, bs.versions
		case slices.Equal(bs.versions, hs.versions):
			unchanged++
			continue
		default:
			d.From, d.To = bs.versions, hs.versions
			d.Change = ChangeChanged
			if len(bs.versions) == 1 && len(hs.versions) == 1 {
				switch c := CompareVersions(bs.versions[0], hs.versions[0]); {
				case c < 0:
					d.Change = ChangeUpgraded
				case c > 0:
					d.Change = ChangeDowngraded
				}
			}
		}
		sample := cmp.Or(hs, bs).sample
		d.Name, d.Group, d.Scope, d.Direct = sample.Name, sample.Group, string(sample.Scope), sample.Direct
		var bv, hv []string
		if bs != nil {
			bv = bs.vulns
		}
		if hs != nil {
			hv = hs.vulns
		}
		d.FixedVulns, d.IntroducedVulns = minus(bv, hv), minus(hv, bv)
		switch d.Change {
		case ChangeAdded:
			sum.Added++
		case ChangeRemoved:
			sum.Removed++
		case ChangeUpgraded:
			sum.Upgraded++
		case ChangeDowngraded:
			sum.Downgraded++
		default:
			sum.Changed++
		}
		changes = append(changes, d)
	}
	return changes, unchanged, sum
}

// CompareVersions orders two version strings, best-effort across ecosystems:
// a leading "v" is ignored; the release part (before the first '-') compares
// segment by segment, numbers numerically and words lexically, with a number
// outranking a word; on a tie, a pre-release ("1.0.0-rc1") sorts before the
// release ("1.0.0"). Build metadata after '+' is ignored. Returns 0 only when
// no ordering is found, which callers treat as "changed, direction unknown".
func CompareVersions(a, b string) int {
	if a == b {
		return 0
	}
	ra, pa := splitPre(a)
	rb, pb := splitPre(b)
	if c := compareSegments(ra, rb); c != 0 {
		return c
	}
	switch {
	case pa == "" && pb != "":
		return 1
	case pa != "" && pb == "":
		return -1
	}
	return compareSegments(pa, pb)
}

func splitPre(v string) (release, pre string) {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// segments splits "1.10rc2" into ["1", "10", "rc", "2"].
func segments(v string) []string {
	var out []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range v {
		switch {
		case r == '.' || r == '-' || r == '_' || r == '~':
			flush()
		case len(cur) > 0 && unicode.IsDigit(r) != unicode.IsDigit(cur[len(cur)-1]):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}

func compareSegments(a, b string) int {
	sa, sb := segments(a), segments(b)
	for i := range max(len(sa), len(sb)) {
		switch {
		case i >= len(sa):
			return -1 // 1.2 < 1.2.1
		case i >= len(sb):
			return 1
		}
		na, ea := strconv.ParseUint(sa[i], 10, 64)
		nb, eb := strconv.ParseUint(sb[i], 10, 64)
		switch {
		case ea == nil && eb == nil:
			if c := cmp.Compare(na, nb); c != 0 {
				return c
			}
		case ea == nil:
			return 1 // a number outranks a word ("1.0.1" > "1.0.beta")
		case eb == nil:
			return -1
		default:
			if c := strings.Compare(strings.ToLower(sa[i]), strings.ToLower(sb[i])); c != 0 {
				return c
			}
		}
	}
	return 0
}
