package correlation

import (
	"context"
	"fmt"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// reachabilityStore matches findings against the SBOM inventory and stores the
// result (finding.Repository satisfies it).
type reachabilityStore interface {
	MatchInventory(ctx context.Context, projectID, scanID string) ([]finding.ReachTarget, error)
	SetReachability(ctx context.Context, targets []finding.ReachTarget, priorities []float64) (int, error)
}

// deduper regroups a project after priorities move (finding.Repository satisfies
// it). Optional.
type deduper interface {
	Deduplicate(ctx context.Context, projectID string) (int, error)
}

// Reacher applies SBOM-derived reachability to findings: it looks up the
// component each package finding came from in the project's current inventory and
// carries that component's depth and scope onto the finding, then recomputes
// priority.
//
// This is the cheapest large win in vulnerability management, and it costs no new
// analysis: most of a dependency backlog is vulnerabilities in packages that are
// build-only, or that sit deep in a transitive tree nobody chose. Both facts are
// already written down in the SBOM the project uploaded — we simply stopped
// throwing them away.
//
// It is deliberately not "reachability" in the call-graph sense (is the vulnerable
// *function* invoked). That needs program analysis, i.e. a scanner, which this
// product does not build. This is the 80% you get for free.
type Reacher struct {
	findings reachabilityStore
	dedup    deduper // optional
}

// NewReacher wires the reachability applier. dedup may be nil.
func NewReacher(findings reachabilityStore, dedup deduper) *Reacher {
	return &Reacher{findings: findings, dedup: dedup}
}

// ApplyToScan applies reachability to the findings one scan reported. It satisfies
// the ingest pipeline's applier seam, so it runs on every upload alongside
// auto-triage — before dedup, because priority is what elects a group's primary.
func (r *Reacher) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	return r.apply(ctx, projectID, scanID)
}

// ApplyToProject re-applies reachability to a project's whole backlog. A new SBOM
// upload rewrites the dependency graph — a package can go from direct to
// transitive, or from runtime to dev — so every existing finding for that project
// may now be worth more or less than it was.
func (r *Reacher) ApplyToProject(ctx context.Context, projectID string) (int, error) {
	n, err := r.apply(ctx, projectID, "")
	if err != nil || n == 0 || r.dedup == nil {
		return n, err
	}
	// Priority decides which tool's report of a CVE leads its correlation group,
	// so a project-wide priority shift has to regroup.
	if _, derr := r.dedup.Deduplicate(ctx, projectID); derr != nil {
		return n, fmt.Errorf("regroup after reachability: %w", derr)
	}
	return n, nil
}

func (r *Reacher) apply(ctx context.Context, projectID, scanID string) (int, error) {
	targets, err := r.findings.MatchInventory(ctx, projectID, scanID)
	if err != nil {
		return 0, err
	}
	if len(targets) == 0 {
		return 0, nil // no SBOM for this project, or no package findings
	}

	priorities := make([]float64, len(targets))
	for i, t := range targets {
		epss := 0.0
		if t.EPSS != nil {
			epss = *t.EPSS
		}
		priorities[i] = domain.Priority(t.Severity, domain.Exploitability{EPSS: epss, KEV: t.KEV, Maturity: t.ExploitMaturity},
			t.Reachability(), t.AssetExposure)
	}
	return r.findings.SetReachability(ctx, targets, priorities)
}

// Name identifies this pass in the ingest pipeline.
func (r *Reacher) Name() string { return "reachability" }
