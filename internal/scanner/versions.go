package scanner

import (
	"strconv"
	"strings"
)

// nearestFix picks the remediation for an installed version from an advisory's
// list of fixed versions, which spans every maintained branch (Django's
// "2.2.26, 3.2.11, 4.0.1"). The useful answer for 3.2.9 is 3.2.11 — the lowest
// fix above what's installed — not the first in the list. Falls back to the
// first entry when the versions don't compare (non-numeric schemes).
func nearestFix(installed string, fixes []string) string {
	best := ""
	for _, f := range fixes {
		if f == "" {
			continue
		}
		c, ok := compareVersions(f, installed)
		if !ok || c <= 0 {
			continue
		}
		if best == "" {
			best = f
		} else if c2, ok := compareVersions(f, best); ok && c2 < 0 {
			best = f
		}
	}
	if best != "" {
		return best
	}
	for _, f := range fixes {
		if f != "" {
			return f
		}
	}
	return ""
}

// compareVersions compares dotted numeric versions ("1.26.19" vs "2.2.2"),
// ignoring a leading "v" and treating a pre-release suffix ("20.3.0rc1") as
// lower than the release. ok is false when either side has no numeric prefix.
func compareVersions(a, b string) (int, bool) {
	pa, sa, oka := versionParts(a)
	pb, sb, okb := versionParts(b)
	if !oka || !okb {
		return 0, false
	}
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	switch {
	case sa == sb:
		return 0, true
	case sa == "":
		return 1, true // release > pre-release
	case sb == "":
		return -1, true
	}
	return strings.Compare(sa, sb), true
}

func versionParts(v string) ([]int, string, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	var parts []int
	for v != "" {
		end := 0
		for end < len(v) && v[end] >= '0' && v[end] <= '9' {
			end++
		}
		if end == 0 {
			break
		}
		n, err := strconv.Atoi(v[:end])
		if err != nil {
			return nil, "", false
		}
		parts = append(parts, n)
		v = v[end:]
		if !strings.HasPrefix(v, ".") {
			break
		}
		v = v[1:]
	}
	if len(parts) == 0 {
		return nil, "", false
	}
	return parts, strings.TrimLeft(v, ".-+"), true
}
