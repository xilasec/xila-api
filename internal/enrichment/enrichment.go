// Package enrichment attaches exploit-aware signals (EPSS, KEV catalogs) to findings
// and recomputes their priority, so the backlog can be ordered by real risk
// rather than raw severity.
package enrichment

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
)

// exploitableEPSS is the EPSS probability at/above which a finding is considered
// newly exploitable (matching the portfolio threshold).
const exploitableEPSS = 0.5

// EPSSSource returns EPSS probabilities (0–1) for the given CVEs.
type EPSSSource interface {
	Scores(ctx context.Context, cves []string) (map[string]float64, error)
}

// kevStore keeps each KEV catalog's last successful download (KEVRepository).
type kevStore interface {
	Replace(ctx context.Context, source string, ids []string) error
	Failed(ctx context.Context, source string, cause error) error
	Assertions(ctx context.Context, sources []string) (map[string][]string, error)
	Status(ctx context.Context) ([]KEVCatalogStatus, error)
}

// findingStore is the slice of the finding repository enrichment needs.
type findingStore interface {
	ListEnrichable(ctx context.Context) ([]finding.Enrichable, error)
	SetEnrichment(ctx context.Context, id string, epss *float64, kevSources []string, priority float64) error
}

// eventNotifier dispatches events (notify.Service satisfies it). Optional.
type eventNotifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// exploitedOpener opens EU CRA Article 14 reporting cases for findings that
// became actively exploited (cra.Service). Optional.
type exploitedOpener interface {
	OpenExploited(ctx context.Context, projectID string) (int, error)
}

// Service enriches findings from the configured exploit-intel sources.
type Service struct {
	findings findingStore
	epss     EPSSSource
	catalogs []KEVCatalog // the configured KEV catalogs (KEV_SOURCES)
	kev      kevStore
	notifier eventNotifier   // optional
	cra      exploitedOpener // optional
}

// NewService wires the enrichment dependencies. notifier may be nil.
func NewService(findings findingStore, epss EPSSSource, catalogs []KEVCatalog, kev kevStore, notifier eventNotifier) *Service {
	return &Service{findings: findings, epss: epss, catalogs: catalogs, kev: kev, notifier: notifier}
}

// WithCRA opens CRA reporting cases as soon as a finding lands on the KEV list.
func (s *Service) WithCRA(o exploitedOpener) *Service {
	s.cra = o
	return s
}

// Result reports one enrichment run.
type Result struct {
	Findings  int               `json:"enriched"`
	KEV       map[string]int    `json:"kev_sources"` // ids stored per catalog downloaded this run
	KEVFailed map[string]string `json:"kev_failed"`  // error per catalog that failed (its last list kept)
}

// KEVStatus lists each KEV catalog's sync state.
func (s *Service) KEVStatus(ctx context.Context) ([]KEVCatalogStatus, error) {
	return s.kev.Status(ctx)
}

// syncKEV downloads every configured catalog and replaces the ones that
// succeeded. A failed catalog keeps the ids it last delivered: an outage
// never silently clears a finding's KEV flag.
func (s *Service) syncKEV(ctx context.Context, res *Result) error {
	for _, c := range s.catalogs {
		list, err := c.Fetch(ctx)
		if err == nil {
			err = s.kev.Replace(ctx, c.Name(), list)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			res.KEVFailed[c.Name()] = err.Error()
			if ferr := s.kev.Failed(ctx, c.Name(), err); ferr != nil {
				return ferr
			}
			slog.WarnContext(ctx, "kev catalog failed", "source", c.Name(), "error", err)
			continue
		}
		res.KEV[c.Name()] = len(list)
	}
	return nil
}

// Enrich downloads the KEV catalogs, fetches EPSS for every CVE referenced by
// a finding, and updates each finding's signals and priority.
func (s *Service) Enrich(ctx context.Context) (Result, error) {
	res := Result{KEV: map[string]int{}, KEVFailed: map[string]string{}}
	if err := s.syncKEV(ctx, &res); err != nil {
		return res, err
	}
	findings, err := s.findings.ListEnrichable(ctx)
	if err != nil {
		return res, err
	}
	if len(findings) == 0 {
		return res, nil
	}

	cveSet := map[string]struct{}{}
	for _, f := range findings {
		for _, cve := range f.CVE {
			cveSet[cve] = struct{}{}
		}
	}
	cves := make([]string, 0, len(cveSet))
	for cve := range cveSet {
		cves = append(cves, cve)
	}

	epssMap, err := s.epss.Scores(ctx, cves)
	if err != nil {
		return res, err
	}
	names := make([]string, len(s.catalogs))
	for i, c := range s.catalogs {
		names[i] = c.Name()
	}
	assertions, err := s.kev.Assertions(ctx, names)
	if err != nil {
		return res, err
	}

	var newlyExploitable []finding.Enrichable
	anyKEV := false
	for _, f := range findings {
		var epss *float64
		var maxEPSS float64
		for _, cve := range f.CVE {
			if v, ok := epssMap[cve]; ok && v > maxEPSS {
				maxEPSS = v
			}
		}
		kevSources := KEVSourcesFor(f.IDs, assertions)
		kev := len(kevSources) > 0
		if kev {
			anyKEV = true
		}
		if maxEPSS > 0 {
			epss = &maxEPSS
		}

		// A finding "becomes exploitable" when it newly lands on the KEV list or
		// crosses the high-EPSS threshold.
		oldEPSS := 0.0
		if f.EPSS != nil {
			oldEPSS = *f.EPSS
		}
		becameKEV := kev && !f.KEV
		becameHighEPSS := maxEPSS >= exploitableEPSS && oldEPSS < exploitableEPSS
		if becameKEV || becameHighEPSS {
			newlyExploitable = append(newlyExploitable, f)
		}

		x := domain.Exploitability{EPSS: maxEPSS, KEV: kev, Maturity: f.ExploitMaturity}
		if err := s.findings.SetEnrichment(ctx, f.ID, epss, kevSources, domain.Priority(f.Severity, x, f.Reachability(), f.AssetExposure)); err != nil {
			return res, err
		}
		res.Findings++
	}

	s.notifyExploitable(ctx, newlyExploitable)
	// KEV-listed findings of in-scope products start the CRA reporting clock
	// now, not at the next sweep (a case already open is left alone).
	if s.cra != nil && anyKEV {
		if _, err := s.cra.OpenExploited(ctx, ""); err != nil {
			return res, fmt.Errorf("open cra cases: %w", err)
		}
	}
	return res, nil
}

// KEVSourcesFor returns the catalogs (sorted) asserting any of a finding's
// vulnerability ids — its CVEs, its rule id and their known aliases — so a
// CISA entry for a CVE also flags the GHSA record of the same flaw.
func KEVSourcesFor(ids []string, assertions map[string][]string) []string {
	set := map[string]bool{}
	for _, id := range ids {
		for _, src := range assertions[strings.ToUpper(id)] {
			set[src] = true
		}
	}
	return sortedSources(set)
}

// notifyExploitable fires one summary alert when findings newly become
// exploitable (KEV / high EPSS). Best-effort, async, portfolio-wide (global).
func (s *Service) notifyExploitable(ctx context.Context, findings []finding.Enrichable) {
	if s.notifier == nil || len(findings) == 0 {
		return
	}
	titles := make([]string, 0, 3)
	for _, f := range findings {
		if len(titles) < 3 {
			titles = append(titles, f.Title)
		}
	}
	go s.notifier.Notify(context.Background(), notify.Event{
		Type:     notify.EventExploitable,
		Title:    fmt.Sprintf("%d finding(s) newly exploitable (KEV / high EPSS)", len(findings)),
		Text:     strings.Join(titles, "\n"),
		Severity: "critical",
		Fields:   map[string]string{"count": strconv.Itoa(len(findings))},
	})
}
