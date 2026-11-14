package vulnmatch

import (
	"slices"
	"strings"
)

// Package is an OSV affected[].package: ecosystem + name, or a purl (without
// version) — private advisories often name an internal package by purl.
type Package struct {
	Ecosystem string `json:"ecosystem,omitempty"`
	Name      string `json:"name,omitempty"`
	Purl      string `json:"purl,omitempty"`
}

// Event is one OSV range event. Exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Range is an OSV affected[].ranges[] entry: SEMVER, ECOSYSTEM or GIT.
type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Affected is an OSV affected[] entry: which package, and which of its versions
// (ranges and/or an explicit list).
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// key is the match key this entry's package is indexed under ("" when it names
// no usable package).
func (a Affected) key() string {
	if a.Package.Ecosystem != "" && a.Package.Name != "" {
		return packageKey(a.Package.Ecosystem, a.Package.Name)
	}
	if p, ok := parsePurl(a.Package.Purl); ok {
		return purlKey(p)
	}
	return ""
}

// ecosystem is the OSV ecosystem whose version ordering applies.
func (a Affected) ecosystem() string {
	if e := a.Package.Ecosystem; e != "" {
		if i := strings.IndexByte(e, ':'); i >= 0 {
			e = e[:i]
		}
		return e
	}
	if p, ok := parsePurl(a.Package.Purl); ok {
		return ecosystemOf(p)
	}
	return ""
}

// affects implements the OSV schema's evaluation algorithm
// (https://ossf.github.io/osv-schema/#evaluation) for one affected entry:
// version v is affected when it is listed in `versions` or falls in one of the
// ranges. It also returns the best "fixed in" for v: the lowest `fixed` event
// above v in a range that covers it.
//
// GIT ranges are skipped — their events are commit hashes, answerable only with
// a clone of the repository; OSV requires such records to enumerate `versions`
// as well, which is what matches them here.
func (a Affected) affects(v string) (bool, string) {
	eco := a.ecosystem()
	hit := slices.ContainsFunc(a.Versions, func(listed string) bool { return sameVersion(listed, v) })
	fixed := ""
	for _, r := range a.Ranges {
		if strings.EqualFold(r.Type, "GIT") {
			continue
		}
		cmpV := comparatorFor(r.Type, eco)
		inRange := includedInRange(r, v, cmpV)
		if !inRange && !hit {
			continue
		}
		hit = hit || inRange
		// "Fixed in": the lowest fixed event above v in a range that covers it.
		for _, e := range r.Events {
			if e.Fixed != "" && cmpV(e.Fixed, v) > 0 && (fixed == "" || cmpV(e.Fixed, fixed) < 0) {
				fixed = e.Fixed
			}
		}
	}
	if !hit {
		return false, ""
	}
	return true, fixed
}

// sameVersion is OSV's `v == version`, tolerating Go's "v" prefix (purls carry
// "v1.2.3", OSV records "1.2.3").
func sameVersion(a, b string) bool {
	return a == b || strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// includedInRange is OSV's IncludedInRanges for a single range: inside the
// limits, then replay the events in version order — introduced switches the
// version vulnerable, fixed (v >= fixed) and last_affected (v > last_affected)
// switch it back.
func includedInRange(r Range, v string, cmpV versionCmp) bool {
	if !beforeLimits(r, v, cmpV) {
		return false
	}
	events := slices.Clone(r.Events)
	slices.SortStableFunc(events, func(x, y Event) int {
		if c := compareEventVersions(x, y, cmpV); c != 0 {
			return c
		}
		return eventRank(x) - eventRank(y)
	})
	vulnerable := false
	for _, e := range events {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || cmpV(v, e.Introduced) >= 0 {
				vulnerable = true
			}
		case e.Fixed != "":
			if cmpV(v, e.Fixed) >= 0 {
				vulnerable = false
			}
		case e.LastAffected != "":
			if cmpV(v, e.LastAffected) > 0 {
				vulnerable = false
			}
		}
	}
	return vulnerable
}

// beforeLimits: with no limit events an implicit "*" (infinity) applies;
// otherwise v must be below at least one limit.
func beforeLimits(r Range, v string, cmpV versionCmp) bool {
	limited := false
	for _, e := range r.Events {
		if e.Limit == "" {
			continue
		}
		limited = true
		if strings.Contains(e.Limit, "*") || cmpV(v, e.Limit) < 0 {
			return true
		}
	}
	return !limited
}

// eventVersion is the version an event sits at.
func eventVersion(e Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

// compareEventVersions sorts events by version, "0" (introduced) lowest and a
// "*" limit highest.
func compareEventVersions(x, y Event, cmpV versionCmp) int {
	vx, vy := eventVersion(x), eventVersion(y)
	switch {
	case vx == vy:
		return 0
	case x.Introduced == "0":
		return -1
	case y.Introduced == "0":
		return 1
	case strings.Contains(vx, "*"):
		return 1
	case strings.Contains(vy, "*"):
		return -1
	}
	return cmpV(vx, vy)
}

// eventRank breaks version ties so a version introduced and fixed at the same
// point ends up not vulnerable, as the timeline intends.
func eventRank(e Event) int {
	switch {
	case e.Introduced != "":
		return 0
	case e.LastAffected != "":
		return 1
	case e.Fixed != "":
		return 2
	}
	return 3
}
