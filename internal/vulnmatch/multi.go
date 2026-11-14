package vulnmatch

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/xilasec/xila-api/internal/domain"
)

// Source names accepted by VULNMATCH_SOURCES.
const (
	SourceOSV      = "osv"       // OSV.dev API (online)
	SourceGitHub   = "github"    // GitHub Advisory Database REST API (online)
	SourceOSVLocal = "osv-local" // the local OSV mirror (osv_advisories) — air-gapped
	SourcePrivate  = "private"   // private_advisories — internal advisories
	// SourceVulnerableCode is a VulnerableCode instance's bulk purl search
	// (public.vulnerablecode.io or self-hosted).
	SourceVulnerableCode = "vulnerablecode"
	// SourceJVN enriches matched advisories with JVN iPedia ids (alias
	// enrichment from the jvn_advisories mirror; it matches nothing itself).
	SourceJVN = "jvn"
)

// KnownSources are every name VULNMATCH_SOURCES accepts.
var KnownSources = []string{SourceOSV, SourceGitHub, SourceOSVLocal, SourcePrivate, SourceNVD, SourceVulnerableCode, SourceJVN}

// Enricher adds identifiers to advisories other sources matched. It never
// adds or removes advisories, so it can't change which findings exist.
type Enricher interface {
	Enrich(ctx context.Context, vulns map[string][]Vuln) map[string][]Vuln
}

// NamedSource is one configured advisory source.
type NamedSource struct {
	Name   string
	Source Source
}

// MultiSource queries every configured source and merges their answers per
// purl, so the same advisory reported by several sources (OSV's GHSA record and
// GitHub's, a PYSEC record aliasing it, a private advisory aliasing its CVE)
// becomes ONE vulnerability — one finding — rather than one per source.
//
// Failure semantics: when every source fails, Query fails. When only some fail,
// it returns the healthy sources' merged results together with a
// *PartialError. The matcher then applies those findings additively — new
// vulnerabilities appear, but nothing is auto-closed — because a finding only
// the failed source reported would otherwise be "missing" from the run and
// closed as if the dependency had been fixed. The next complete run closes
// what's really gone.
type MultiSource struct {
	sources []NamedSource
	cpe     CPESource   // nvd, when configured: components with a CPE and no purl
	alias   aliasSource // jvn, when configured: CVE → JVNDB ids
}

// NewMultiSource merges the given sources. Order is the configured order; it
// only decides which source's wording wins on equal footing.
func NewMultiSource(sources ...NamedSource) *MultiSource {
	return &MultiSource{sources: sources}
}

// Names lists the configured sources.
func (m *MultiSource) Names() []string {
	out := make([]string, len(m.sources))
	for i, s := range m.sources {
		out[i] = s.Name
	}
	if m.cpe != nil {
		out = append(out, SourceNVD)
	}
	if m.alias != nil {
		out = append(out, SourceJVN)
	}
	return out
}

// Enrich adds the jvn source's ids to every advisory with a CVE it knows.
// Without jvn configured it returns vulns unchanged.
func (m *MultiSource) Enrich(ctx context.Context, vulns map[string][]Vuln) map[string][]Vuln {
	if m.alias == nil {
		return vulns
	}
	return enrichAliases(ctx, m.alias, vulns)
}

// QueryCPE resolves CPE-only components through the nvd source. Without it
// configured, nothing matches (and nothing fails).
func (m *MultiSource) QueryCPE(ctx context.Context, cpes []string) (map[string][]Vuln, error) {
	if m.cpe == nil {
		return map[string][]Vuln{}, nil
	}
	return m.cpe.QueryCPE(ctx, cpes)
}

// SourceDeps carries what the configurable sources need.
type SourceDeps struct {
	OSVURL      string
	GitHubURL   string
	GitHubToken string
	Mirror      *OSVRepository
	Private     *AdvisoryRepository
	NVD         cpeMatcher // the shared NVD client (one rate-limit budget with CVSS enrichment)
	// VulnerableCode base URL (public.vulnerablecode.io or self-hosted) and
	// optional API key.
	VulnerableCodeURL    string
	VulnerableCodeAPIKey string
	JVN                  *JVNRepository
}

// NewSources builds the MultiSource for VULNMATCH_SOURCES.
func NewSources(names []string, d SourceDeps) (*MultiSource, error) {
	var out []NamedSource
	var cpe CPESource
	var alias aliasSource
	for _, name := range names {
		var s Source
		switch name {
		case SourceNVD:
			cpe = NewNVDCPESource(d.NVD)
			continue
		case SourceJVN:
			if d.JVN == nil {
				return nil, errors.New("the jvn source needs the JVN mirror")
			}
			alias = d.JVN
			continue
		case SourceVulnerableCode:
			s = NewVulnerableCodeSource(d.VulnerableCodeURL, d.VulnerableCodeAPIKey)
		case SourceOSV:
			s = NewOSVSource(d.OSVURL)
		case SourceGitHub:
			s = NewGitHubSource(d.GitHubURL, d.GitHubToken)
		case SourceOSVLocal:
			s = NewLocalSource(d.Mirror)
		case SourcePrivate:
			s = NewPrivateSource(d.Private)
		default:
			return nil, fmt.Errorf("unknown advisory source %q", name)
		}
		if slices.ContainsFunc(out, func(n NamedSource) bool { return n.Name == name }) {
			continue
		}
		out = append(out, NamedSource{Name: name, Source: s})
	}
	if len(out) == 0 && cpe == nil {
		return nil, errors.New("VULNMATCH_SOURCES needs at least one matching source (jvn only enriches)")
	}
	m := NewMultiSource(out...)
	m.cpe, m.alias = cpe, alias
	return m, nil
}

// PartialError reports the sources that failed while others answered.
type PartialError struct {
	Failed map[string]error
}

func (e *PartialError) Error() string {
	names := e.FailedSources()
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s: %v", n, e.Failed[n])
	}
	return "advisory sources failed (partial results): " + strings.Join(parts, "; ")
}

// FailedSources lists the failed source names, sorted.
func (e *PartialError) FailedSources() []string {
	names := make([]string, 0, len(e.Failed))
	for n := range e.Failed {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// Query fans out to every source concurrently and merges the results.
func (m *MultiSource) Query(ctx context.Context, purls []string) (map[string][]Vuln, error) {
	if len(m.sources) == 0 {
		if m.cpe != nil {
			return map[string][]Vuln{}, nil // CPE-only matching (nvd alone)
		}
		return nil, errors.New("no advisory sources configured")
	}
	results := make([]map[string][]Vuln, len(m.sources))
	errs := make([]error, len(m.sources))
	var wg sync.WaitGroup
	for i, s := range m.sources {
		wg.Go(func() {
			res, err := s.Source.Query(ctx, purls)
			if err != nil {
				errs[i] = err
				return
			}
			// Stamp a copy: a source may hand out slices it caches.
			stamped := make(map[string][]Vuln, len(res))
			for p, vs := range res {
				cp := slices.Clone(vs)
				for j := range cp {
					cp[j].Sources = []string{s.Name}
				}
				stamped[p] = cp
			}
			results[i] = stamped
		})
	}
	wg.Wait()

	failed := map[string]error{}
	for i, err := range errs {
		if err != nil {
			failed[m.sources[i].Name] = err
		}
	}
	if len(failed) == len(m.sources) {
		all := make([]error, 0, len(failed))
		for i, err := range errs {
			all = append(all, fmt.Errorf("%s: %w", m.sources[i].Name, err))
		}
		return nil, errors.Join(all...)
	}

	byPurl := map[string][]Vuln{}
	for _, res := range results {
		for p, vs := range res {
			byPurl[p] = append(byPurl[p], vs...)
		}
	}
	out := make(map[string][]Vuln, len(byPurl))
	for p, vs := range byPurl {
		out[p] = mergeVulns(p, vs)
	}
	if len(failed) > 0 {
		return out, &PartialError{Failed: failed}
	}
	return out, nil
}

// mergeVulns collapses the vulnerabilities reported for one purl into one per
// advisory. Two reports are the same advisory when their id sets ({id} ∪
// aliases) intersect — transitively, so GHSA ↔ CVE ↔ PYSEC chains collapse.
func mergeVulns(purlStr string, vs []Vuln) []Vuln {
	if len(vs) == 0 {
		return nil
	}
	// Union-find over report indexes, joined through shared ids.
	parent := make([]int, len(vs))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	owner := map[string]int{}
	for i, v := range vs {
		for _, id := range v.idSet() {
			if j, ok := owner[id]; ok {
				if ri, rj := find(i), find(j); ri != rj {
					parent[max(ri, rj)] = min(ri, rj)
				}
			} else {
				owner[id] = i
			}
		}
	}
	groups := map[int][]Vuln{}
	var roots []int
	for i, v := range vs {
		r := find(i)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], v)
	}
	p, _ := parsePurl(purlStr)
	cmpV := comparatorFor("ECOSYSTEM", ecosystemOf(p))
	out := make([]Vuln, 0, len(roots))
	for _, r := range roots {
		out = append(out, mergeGroup(groups[r], p.Version, cmpV))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// idSet is every identifier this report is known by.
func (v Vuln) idSet() []string {
	ids := append([]string{v.ID}, v.Aliases...)
	return append(ids, v.CVEs...)
}

// idRank orders candidate canonical ids: GHSA first (both OSV and GitHub use
// it, so the merged id — and the finding's fingerprint — doesn't depend on
// which sources answered), then ecosystem ids (PYSEC, GO, RUSTSEC, private
// ids…), CVE last.
func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return 0
	case strings.HasPrefix(id, "CVE-"):
		return 2
	default:
		return 1
	}
}

// mergeGroup folds reports of one advisory into one Vuln. The canonical id is
// picked among the reports' own ids (never a bare alias, which no source
// returned as a record), by idRank then lexically — deterministic whatever the
// source order. The most specific data wins: the highest stated severity and
// CVSS (unknown never beats known), the lowest fixed version above the
// installed one.
func mergeGroup(group []Vuln, installed string, cmpV versionCmp) Vuln {
	canon := slices.MinFunc(group, func(a, b Vuln) int {
		if c := cmp.Compare(idRank(a.ID), idRank(b.ID)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	out := Vuln{ID: canon.ID, Summary: canon.Summary, Details: canon.Details, URL: canon.URL}
	ids, cves, sources := map[string]bool{}, map[string]bool{}, map[string]bool{}
	var fixes []string
	for _, v := range group {
		for _, id := range v.idSet() {
			ids[id] = true
			if strings.HasPrefix(id, "CVE-") {
				cves[id] = true
			}
		}
		for _, s := range v.Sources {
			if !sources[s] {
				sources[s] = true
				out.Sources = append(out.Sources, s)
			}
		}
		if out.Summary == "" {
			out.Summary = v.Summary
		}
		if out.Details == "" {
			out.Details = v.Details
		}
		if out.URL == "" {
			out.URL = v.URL
		}
		if v.Severity != "" && (out.Severity == "" || v.Severity.Weight() > out.Severity.Weight()) {
			out.Severity = v.Severity
		}
		if v.CVSS != nil && (out.CVSS == nil || *v.CVSS > *out.CVSS) {
			out.CVSS = v.CVSS
		}
		if v.Fixed != "" && !slices.Contains(fixes, v.Fixed) {
			fixes = append(fixes, v.Fixed)
		}
	}
	delete(ids, out.ID)
	for id := range ids {
		out.Aliases = append(out.Aliases, id)
	}
	slices.Sort(out.Aliases)
	for c := range cves {
		out.CVEs = append(out.CVEs, c)
	}
	slices.Sort(out.CVEs)
	out.Fixed = bestFix(fixes, installed, cmpV)
	return out
}

// bestFix is the smallest fixed version above the installed one — the nearest
// upgrade that resolves it; failing that (unparseable versions), the first.
func bestFix(fixes []string, installed string, cmpV versionCmp) string {
	best := ""
	for _, f := range fixes {
		if installed != "" && cmpV(f, installed) <= 0 {
			continue
		}
		if best == "" || cmpV(f, best) < 0 {
			best = f
		}
	}
	if best == "" && len(fixes) > 0 {
		return fixes[0]
	}
	return best
}

// severityOrDefault is what a finding records: unknown → medium (EPSS/KEV and
// NVD CVSS drive priority anyway).
func (v Vuln) severityOrDefault() domain.Severity {
	if v.Severity == "" {
		return domain.SeverityMedium
	}
	return v.Severity
}
