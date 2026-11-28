// Package vulnmatch keeps stored SBOMs alive: it re-evaluates the current
// component inventory against advisory sources on a schedule, so a
// vulnerability disclosed *after* an SBOM was uploaded still lights up — with
// no re-scan. Generation stays with the user's tool (Syft); this is pure
// vulnerability management over an inventory we already hold.
//
// Sources (VULNMATCH_SOURCES): OSV.dev online, the GitHub Advisory Database, a
// local OSV mirror imported from OSV's ecosystem exports (air-gapped), and a
// private advisory database. MultiSource merges them into one deduplicated set
// per package.
package vulnmatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
)

// Scanner is the source name recorded on findings this matcher produces —
// whichever advisory sources contributed. Every source shares it: a merged
// advisory is one finding (no per-source duplicates), and findings recorded
// before there were several sources keep their scanner and fingerprint
// (changing either would auto-close and recreate them). Which sources reported
// a finding is in its metadata ("sources"). A name distinct from the scanners
// means the per-scanner lifecycle applies: when a dependency is upgraded and no
// source matches anymore, the finding auto-closes.
const Scanner = "osv"

// Vuln is a vulnerability affecting a package.
type Vuln struct {
	ID       string // advisory id (GHSA-…, PYSEC-…, CVE-…, XILA-…)
	Aliases  []string
	Summary  string
	Details  string
	Severity domain.Severity // "" when the source doesn't state one
	CVSS     *float64        // base score, when the source gives one
	CVEs     []string
	Fixed    string // "fixed in" for the matched version, best effort
	URL      string // advisory page ("" → osv.dev)
	Sources  []string

	// Set by feed rules (applyFeedRules), never by a source: the tags to add
	// to the finding, the rules that acted, and the stated severity a
	// set_severity rule replaced ("" = unknown, or unchanged).
	Tags             []string
	FeedRules        []FeedRuleRef
	FeedSeverityFrom domain.Severity
}

// Source resolves PURLs to the vulnerabilities affecting them (MultiSource in
// prod; a fake in tests).
type Source interface {
	Query(ctx context.Context, purls []string) (map[string][]Vuln, error)
}

// inventoryStore yields snapshot inventory and records advisory matches per
// snapshot (sbom.Repository).
type inventoryStore interface {
	ListSnapshotInventory(ctx context.Context, projectID string) ([]sbom.SnapshotComponent, error)
	RecordMatches(ctx context.Context, sbomIDs []string, matches []sbom.SnapshotVuln) error
	// LockProject + CurrentSnapshots let a run apply findings only if the
	// snapshots it evaluated are still the version's current ones.
	LockProject(ctx context.Context, projectID string) (func(), error)
	CurrentSnapshots(ctx context.Context, projectID, versionID string) ([]string, error)
}

// findingApplier records a producer's findings through the normal ingest
// pipeline — upsert, auto-close, auto-triage, cross-tool dedup, alert
// (scan.Service). AddFindings is the same minus auto-close, for a run that
// knows its view is incomplete.
type findingApplier interface {
	ApplyFindings(ctx context.Context, projectID, versionID, scanner string, category domain.Category, findings []finding.Finding) (scan.Scan, error)
	AddFindings(ctx context.Context, projectID, versionID, scanner string, category domain.Category, findings []finding.Finding) (scan.Scan, error)
}

// target is one project version the current inventory produces findings on.
type target struct{ project, version string }

// partitionKeys splits the components' distinct match keys three ways: purls
// for every advisory source, internal purls for private sources only (an
// internal component's name never reaches an online one, M13 13.11), and
// CPEs of purl-less external components for NVD. A key internal in any row
// counts as internal; an internal CPE-only component is asked of no one.
func partitionKeys(components []sbom.SnapshotComponent) (purls, internalPurls, cpes []string) {
	internal := map[string]bool{}
	isPurl := map[string]bool{}
	var keys []string
	for _, c := range components {
		key := c.MatchKey()
		if _, seen := internal[key]; !seen {
			keys = append(keys, key)
		}
		internal[key] = internal[key] || c.Internal
		isPurl[key] = isPurl[key] || c.Purl != ""
	}
	purls = make([]string, 0, len(keys))
	for _, key := range keys {
		switch {
		case isPurl[key] && internal[key]:
			internalPurls = append(internalPurls, key)
		case isPurl[key]:
			purls = append(purls, key)
		case !internal[key]:
			cpes = append(cpes, key)
		}
	}
	return purls, internalPurls, cpes
}

// queryInternal adds the private sources' answers for the internal purls to
// vulns (a new map: vulns may be a source's own). A failure there counts as
// a partial lookup, like any failed source: what only it would report must
// not be closed as fixed.
func (s *Service) queryInternal(ctx context.Context, internalPurls []string, vulns map[string][]Vuln, partial *PartialError) (map[string][]Vuln, *PartialError) {
	pq, ok := s.source.(privateQuerier)
	if !ok || len(internalPurls) == 0 {
		return vulns, partial
	}
	pv, err := pq.QueryPrivate(ctx, internalPurls)
	var failed *PartialError
	if err != nil && !errors.As(err, &failed) {
		failed = &PartialError{Failed: map[string]error{"private sources": err}}
	}
	merged := make(map[string][]Vuln, len(vulns)+len(pv))
	maps.Copy(merged, vulns)
	maps.Copy(merged, pv)
	if failed != nil {
		if partial == nil {
			partial = &PartialError{Failed: map[string]error{}}
		}
		maps.Copy(partial.Failed, failed.Failed)
	}
	return merged, partial
}

// privateQuerier is a source that can answer from private sources alone
// (MultiSource). Without it, internal components are never matched.
type privateQuerier interface {
	QueryPrivate(ctx context.Context, purls []string) (map[string][]Vuln, error)
}

// Service re-evaluates SBOM inventory against the advisory sources.
type Service struct {
	inventory inventoryStore
	apply     findingApplier
	source    Source
	rules     feedRuleStore // nil: no feed rules
	tagger    feedTagger

	kickMu      sync.Mutex
	kickRunning bool
	kickPending bool
}

// NewService constructs the matcher.
func NewService(inventory inventoryStore, apply findingApplier, source Source) *Service {
	return &Service{inventory: inventory, apply: apply, source: source}
}

// WithFeedRules applies the admin feed rules to every run (before matches
// and findings are built) and lets add_tags rules tag the findings.
func (s *Service) WithFeedRules(rules feedRuleStore, tagger feedTagger) *Service {
	s.rules, s.tagger = rules, tagger
	return s
}

// Match re-evaluates every project against the advisory sources. Returns how
// many findings were recorded. When only some sources failed it returns the
// count together with a *PartialError (findings were added, none closed).
func (s *Service) Match(ctx context.Context) (int, error) {
	return s.match(ctx, "")
}

// MatchProject re-evaluates one project — run after an SBOM upload so it shows
// its vulnerabilities immediately (sbom.AdvisoryMatcher). A partial lookup
// (some sources failed; already logged by match) still recorded the healthy
// sources' findings, so it counts as success here: what runs after the match
// (policy evaluation) should see them.
func (s *Service) MatchProject(ctx context.Context, projectID string) (int, error) {
	n, err := s.match(ctx, projectID)
	if _, partial := errors.AsType[*PartialError](err); partial {
		return n, nil
	}
	return n, err
}

// match evaluates every snapshot in scope against today's advisories:
//
//   - each snapshot's matches are recorded (sbom_vulns), so an old release
//     answers "was this vulnerable?" after the project moved on;
//   - the current snapshot per artifact becomes findings: newly-disclosed
//     vulnerabilities appear, and ones that no longer apply (dependency upgraded
//     or removed) auto-close.
//
// A partial lookup (some sources failed) only adds: snapshot history keeps its
// last complete evaluation, and findings are applied without auto-close — a
// vulnerability only the failed source knows must not be closed as "fixed".
func (s *Service) match(ctx context.Context, projectID string) (int, error) {
	components, err := s.inventory.ListSnapshotInventory(ctx, projectID)
	if err != nil {
		return 0, err
	}
	if len(components) == 0 {
		return 0, nil
	}

	// One batched advisory lookup for every distinct match key in scope,
	// history included (partitionKeys).
	purls, internalPurls, cpes := partitionKeys(components)
	vulns, err := s.source.Query(ctx, purls)
	var partial *PartialError
	switch {
	case errors.As(err, &partial):
	case err != nil:
		return 0, fmt.Errorf("advisory lookup: %w", err)
	}
	vulns, partial = s.queryInternal(ctx, internalPurls, vulns, partial)
	if cs, ok := s.source.(CPESource); ok && len(cpes) > 0 {
		cv, cerr := cs.QueryCPE(ctx, cpes)
		// Merge into a new map: the purl answer may be a source's own (cached)
		// map, which must not grow CPE entries. CPE and purl keys never collide.
		merged := make(map[string][]Vuln, len(vulns)+len(cv))
		maps.Copy(merged, vulns)
		maps.Copy(merged, cv)
		vulns = merged
		if cerr != nil {
			// Like a failed purl source: what NVD alone reported must not be
			// closed as fixed because this run couldn't ask.
			if partial == nil {
				partial = &PartialError{Failed: map[string]error{}}
			}
			partial.Failed[SourceNVD] = cerr
		}
	}
	if partial != nil {
		slog.WarnContext(ctx, "vulnmatch: some advisory sources failed; adding matches without auto-close",
			"failed", partial.FailedSources(), "error", partial)
	}
	// Alias enrichment (jvn) only adds identifiers; its failure is logged by
	// the enricher and changes neither which findings exist nor their ids.
	if e, ok := s.source.(Enricher); ok {
		vulns = e.Enrich(ctx, vulns)
	}
	// Feed rules decide what the matcher sees, for every source alike. A
	// rule store that can't be read fails the run: running without the mutes
	// would reopen what an admin muted.
	if s.rules != nil {
		rules, err := s.rules.Active(ctx)
		if err != nil {
			return 0, fmt.Errorf("feed rules: %w", err)
		}
		vulns = applyFeedRules(ctx, rules, vulns)
	}

	var (
		sbomIDs  []string
		seenSbom = map[string]bool{}
		matches  []sbom.SnapshotVuln
		// Findings per project version from its current inventory only. Versions
		// with inventory but zero matches are still applied, so previously-reported
		// vulns that are now resolved get auto-closed.
		byTarget    = map[target][]finding.Finding{}
		targets     []target
		evaluated   = map[target][]string{} // the current snapshots this run saw
		seenFinding = map[string]bool{}     // project|version|purl: two artifacts can ship the same package
	)
	for _, c := range components {
		if !seenSbom[c.SbomID] {
			seenSbom[c.SbomID] = true
			sbomIDs = append(sbomIDs, c.SbomID)
		}
		key := c.MatchKey()
		for _, v := range vulns[key] {
			matches = append(matches, sbom.SnapshotVuln{
				SbomID: c.SbomID, Purl: key, VulnID: v.ID, CVEs: v.CVEs,
				Severity: v.severityOrDefault(), Summary: v.Summary, FixedVersion: v.Fixed,
			})
		}
		if !c.Current {
			continue
		}
		t := target{c.ProjectID, c.VersionID}
		if _, seen := evaluated[t]; !seen {
			targets = append(targets, t)
		}
		if !slices.Contains(evaluated[t], c.SbomID) {
			evaluated[t] = append(evaluated[t], c.SbomID)
		}
		if fk := c.ProjectID + "|" + c.VersionID + "|" + key; !seenFinding[fk] {
			seenFinding[fk] = true
			for _, v := range vulns[key] {
				byTarget[t] = append(byTarget[t], toFinding(c, v))
			}
		}
	}
	// History records the complete view only: RecordMatches replaces a
	// snapshot's matches, which would drop what the failed source reported.
	if partial == nil {
		if err := s.inventory.RecordMatches(ctx, sbomIDs, matches); err != nil {
			return 0, err
		}
	}

	total := 0
	for _, t := range targets {
		applied, err := s.applyIfCurrent(ctx, t, evaluated[t], byTarget[t], partial == nil)
		if err != nil {
			// One bad project shouldn't abort the whole sweep.
			slog.WarnContext(ctx, "vulnmatch: applying findings failed",
				"project_id", t.project, "version_id", t.version, "error", err)
			continue
		}
		total += applied
	}
	slog.InfoContext(ctx, "vulnerability match complete",
		"snapshots", len(sbomIDs), "purls", len(purls), "cpes", len(cpes), "snapshot_matches", len(matches),
		"versions", len(targets), "findings", total, "partial", partial != nil)
	if partial != nil {
		return total, partial
	}
	return total, nil
}

// applyIfCurrent records a project version's findings — unless a newer SBOM
// landed on it while this run was talking to the sources. Matches run
// concurrently (every upload starts one, plus the schedule) and finish in any
// order; without this check a slow run over the previous release would re-open
// findings the newer release already closed. The newer upload's own run
// applies instead. The lock makes check-then-apply atomic across instances; it
// is never held over the network. complete=false applies without auto-close.
func (s *Service) applyIfCurrent(ctx context.Context, t target, evaluated []string, found []finding.Finding, complete bool) (int, error) {
	if !complete && len(found) == 0 {
		return 0, nil // nothing to add, and nothing may be closed
	}
	unlock, err := s.inventory.LockProject(ctx, t.project)
	if err != nil {
		return 0, err
	}
	defer unlock()
	current, err := s.inventory.CurrentSnapshots(ctx, t.project, t.version)
	if err != nil {
		return 0, err
	}
	slices.Sort(evaluated)
	if !slices.Equal(current, evaluated) {
		slog.InfoContext(ctx, "vulnmatch: project changed during the match; leaving it to the newer run",
			"project_id", t.project, "version_id", t.version)
		return 0, nil
	}
	apply := s.apply.ApplyFindings
	if !complete {
		apply = s.apply.AddFindings
	}
	sc, err := apply(ctx, t.project, t.version, Scanner, domain.CategorySCA, found)
	if err != nil {
		return 0, err
	}
	if s.tagger != nil && slices.ContainsFunc(found, func(f finding.Finding) bool { return f.Metadata["feed_tags"] != nil }) {
		if err := s.tagger.ApplyFeedTags(ctx, sc.ID); err != nil {
			return 0, fmt.Errorf("feed rule tags: %w", err)
		}
	}
	return len(found), nil
}

// toFinding turns one (component, advisory) pair into a finding. ProjectID,
// Scanner and the scan id are stamped by ApplyFindings.
func toFinding(c sbom.SnapshotComponent, v Vuln) finding.Finding {
	title := v.Summary
	if title == "" {
		title = v.ID
	}
	url := v.URL
	if url == "" {
		url = "https://osv.dev/vulnerability/" + v.ID
	}
	key := c.MatchKey()
	source := SourceOSV
	if len(v.Sources) > 0 {
		source = v.Sources[0]
	}
	meta := map[string]any{"source": source, "vuln_id": v.ID}
	if c.Purl == "" && c.Cpe != "" {
		meta["cpe"] = c.Cpe // matched by CPE (no purl to show)
	}
	if len(v.Sources) > 0 {
		meta["sources"] = v.Sources
	}
	if len(v.Aliases) > 0 {
		meta["aliases"] = v.Aliases
	}
	if len(v.FeedRules) > 0 {
		meta["feed_rules"] = v.FeedRules
	}
	if len(v.Tags) > 0 {
		meta["feed_tags"] = v.Tags
	}
	if v.FeedSeverityFrom != "" {
		meta["advisory_severity"] = v.FeedSeverityFrom
	}
	return finding.Finding{
		Fingerprint:    fingerprint(v.ID, key),
		Category:       domain.CategorySCA,
		RuleID:         v.ID,
		Title:          fmt.Sprintf("%s (%s %s)", title, c.Name, c.Version),
		Description:    v.Details,
		Severity:       v.severityOrDefault(),
		CVE:            v.CVEs,
		CVSS:           v.CVSS,
		PackageName:    c.Name,
		PackageVersion: c.Version,
		FixedVersion:   v.Fixed,
		Purl:           c.Purl,
		URL:            url,
		Metadata:       meta,
	}
}

// fingerprint is stable per (advisory, exact package version), so repeated runs
// upsert the same finding rather than duplicating it.
func fingerprint(vulnID, purl string) string {
	sum := sha256.Sum256([]byte(Scanner + "|sca|" + vulnID + "|" + purl))
	return hex.EncodeToString(sum[:])
}
