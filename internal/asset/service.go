package asset

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// prioritizer recomputes finding priorities and regroups (finding.Repository).
type prioritizer interface {
	Reprioritize(ctx context.Context, s finding.PriorityScope) ([]string, int, error)
	Deduplicate(ctx context.Context, projectID string) (int, error)
}

// Service owns asset exposure: manual assessments, inference from scans, and
// carrying either into the priority of the asset's findings.
type Service struct {
	repo     *Repository
	findings prioritizer
}

// NewService wires the exposure service.
func NewService(repo *Repository, findings prioritizer) *Service {
	return &Service{repo: repo, findings: findings}
}

// Name identifies the ingest pass.
func (s *Service) Name() string { return "exposure" }

// ApplyToScan is the ingest pass: it infers exposure from the findings the scan
// reported (Infer), raises the exposure of the assets they name, and recomputes
// the priority of this scan's findings from every input. It runs after the
// triage rules, so a severity a rule reset regains its exposure, exploit and
// reachability factors before dedup elects primaries.
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	evidence, err := s.repo.ScanEvidence(ctx, scanID)
	if err != nil {
		return 0, err
	}

	type claim struct {
		exposure domain.Exposure
		reason   string
	}
	claims := map[string]claim{}
	var idents map[string]string
	for _, e := range evidence {
		exp, reason := Infer(e)
		if exp == domain.ExposureUnknown {
			continue
		}
		targets := []string{}
		if e.AssetID != nil {
			targets = append(targets, *e.AssetID)
		}
		// A cloud finding names its resource: the asset registered for that
		// resource (identifier = resource id or ARN) is exposed too.
		if e.Category == domain.CategoryCloud {
			if idents == nil {
				if idents, err = s.repo.IdentifierIndex(ctx, projectID); err != nil {
					return 0, err
				}
			}
			for _, key := range []string{e.ResourceARN, e.Resource} {
				if id, ok := idents[key]; ok && key != "" && !slices.Contains(targets, id) {
					targets = append(targets, id)
				}
			}
		}
		for _, id := range targets {
			if c, ok := claims[id]; !ok || exp.Rank() > c.exposure.Rank() {
				claims[id] = claim{exp, reason}
			}
		}
	}

	moved := map[string]bool{}
	changed := 0
	for _, id := range slices.Sorted(maps.Keys(claims)) {
		c := claims[id]
		raised, err := s.repo.RaiseExposure(ctx, id, c.exposure, c.reason)
		if err != nil {
			return changed, err
		}
		if !raised {
			continue
		}
		projects, n, err := s.findings.Reprioritize(ctx, finding.PriorityScope{AssetID: id})
		if err != nil {
			return changed, err
		}
		changed += n
		for _, p := range projects {
			moved[p] = true
		}
	}

	_, n, err := s.findings.Reprioritize(ctx, finding.PriorityScope{ScanID: scanID})
	if err != nil {
		return changed, err
	}
	changed += n
	// An exposure change moves findings from earlier scans too: their groups are
	// outside this scan's dedup, so regroup those projects whole.
	for _, p := range slices.Sorted(maps.Keys(moved)) {
		if _, err := s.findings.Deduplicate(ctx, p); err != nil {
			return changed, fmt.Errorf("regroup after exposure: %w", err)
		}
	}
	return changed, nil
}

// SetExposure records a manual exposure assessment (ExposureUnknown clears it)
// and re-ranks the asset's findings.
func (s *Service) SetExposure(ctx context.Context, id string, e domain.Exposure, reason string) (Asset, error) {
	a, err := s.repo.SetExposure(ctx, id, e, reason)
	if err != nil {
		return Asset{}, err
	}
	projects, _, err := s.findings.Reprioritize(ctx, finding.PriorityScope{AssetID: id})
	if err != nil {
		return a, err
	}
	for _, p := range projects {
		if _, err := s.findings.Deduplicate(ctx, p); err != nil {
			return a, fmt.Errorf("regroup after exposure: %w", err)
		}
	}
	return a, nil
}
