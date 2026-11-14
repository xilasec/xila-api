package pkgmeta

import "time"

// Version is one published release of a package.
type Version struct {
	Version   string     `json:"version"`
	Published *time.Time `json:"published_at,omitempty"` // nil when the registry doesn't say
	Yanked    bool       `json:"yanked,omitempty"`       // yanked / unlisted: never a candidate
	// Hashes are the digests the registry publishes for this version's
	// artifacts (algorithm → lowercase hex; several artifacts, several
	// digests). Empty when the registry publishes none.
	Hashes map[string][]string `json:"hashes,omitempty"`
}

// Package is what a registry reports about one package.
type Package struct {
	// Latest is the registry's own notion of the newest stable release (npm
	// dist-tags.latest, PyPI info.version, crates.io max_stable_version…);
	// "" when it has none. It is only trusted when it is itself stable.
	Latest   string
	Versions []Version
}

// Info is the freshness of one package version — the policy engine's view.
// It exists only for packages whose registry metadata was fetched; an unknown
// package is absent, never "up to date".
type Info struct {
	Latest string `json:"latest_version"`
	// Outdated: a newer release (stable, unless the current version is itself a
	// pre-release) exists.
	Outdated bool `json:"outdated"`
	// VersionsBehind counts the candidate releases newer than the current one,
	// up to and including Latest. Nil when unknown.
	VersionsBehind  *int       `json:"versions_behind"`
	Published       *time.Time `json:"published_at"`        // this version's release date
	LatestPublished *time.Time `json:"latest_published_at"` // Latest's release date
	FetchedAt       *time.Time `json:"fetched_at"`
}

// latestStable is the newest stable, non-yanked release: the registry's own
// pick when it names a stable version it hasn't yanked (npm's dist-tag can
// deliberately point below the highest number), else the highest by the
// ecosystem's ordering. "" when nothing stable was ever released.
func latestStable(ecosystem string, p Package) string {
	sch := schemeFor(ecosystem)
	if p.Latest != "" && !sch.prerelease(p.Latest) {
		yanked := false
		for _, v := range p.Versions {
			if v.Version == p.Latest && v.Yanked {
				yanked = true
			}
		}
		if !yanked {
			return p.Latest
		}
	}
	best := ""
	for _, v := range p.Versions {
		if v.Yanked || sch.prerelease(v.Version) {
			continue
		}
		if best == "" || sch.compare(v.Version, best) > 0 {
			best = v.Version
		}
	}
	return best
}

// evaluate judges version `current` of a package against its metadata. A
// stable version is compared with stable releases only; a pre-release is
// compared within pre-releases too (someone on 2.0.0-rc.1 wants to hear about
// 2.0.0-rc.2). ok is false when there is nothing to compare against.
func evaluate(ecosystem string, meta Meta, current string) (Info, bool) {
	if current == "" || meta.FetchedAt == nil {
		return Info{}, false
	}
	sch := schemeFor(ecosystem)
	pre := sch.prerelease(current)

	var candidates []Version
	for _, v := range meta.Versions {
		if v.Yanked || (!pre && sch.prerelease(v.Version)) {
			continue
		}
		candidates = append(candidates, v)
	}
	latest := meta.LatestVersion
	if ecosystem == Maven {
		// Stay within the build variant (-jre / -android) when the registry
		// publishes it; the variant's newest stable is then "latest".
		if fl := mavenFlavor(current); fl != "" {
			var same []Version
			for _, v := range candidates {
				if mavenFlavor(v.Version) == fl {
					same = append(same, v)
				}
			}
			if len(same) > 0 {
				candidates = same
				latest = latestStable(ecosystem, Package{Versions: same})
			}
		}
	}
	if pre {
		for _, v := range candidates {
			if latest == "" || sch.compare(v.Version, latest) > 0 {
				latest = v.Version
			}
		}
	}
	if latest == "" {
		return Info{}, false
	}

	info := Info{Latest: latest, FetchedAt: meta.FetchedAt}
	info.Outdated = sch.compare(latest, current) > 0
	behind := 0
	if info.Outdated {
		seen := map[string]bool{}
		for _, v := range candidates {
			if seen[v.Version] {
				continue
			}
			seen[v.Version] = true
			if sch.compare(v.Version, current) > 0 && sch.compare(v.Version, latest) <= 0 {
				behind++
			}
		}
	}
	info.VersionsBehind = &behind
	info.Published = publishedAt(sch, meta.Versions, current)
	info.LatestPublished = publishedAt(sch, meta.Versions, latest)
	return info, true
}

// publishedAt finds a version's release date: the exact string first, else a
// version that orders equal ("1.0" for "1.0.0").
func publishedAt(sch scheme, versions []Version, version string) *time.Time {
	var equal *time.Time
	for _, v := range versions {
		if v.Version == version {
			return v.Published
		}
		if equal == nil && v.Published != nil && sch.compare(v.Version, version) == 0 {
			equal = v.Published
		}
	}
	return equal
}
