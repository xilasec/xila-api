package finding_test

import (
	"context"
	"maps"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// countingTrigger records every OnFindingsChanged call.
type countingTrigger struct{ calls [][]string }

func (c *countingTrigger) OnFindingsChanged(_ context.Context, _ string, ids []string, _ string) {
	c.calls = append(c.calls, ids)
}

// Only a person's decision sets the triage rules off: an automated writer
// (VEX, a vulnerability policy, a rule itself) never does, or one VEX
// document would rerun the rules once per finding it touched. A bulk edit is
// one call with all its findings, not one per finding.
func TestChangeTriggerFiresOnDecisionsOnly(t *testing.T) {
	pool := pgtest.Pool(t)
	trig := &countingTrigger{}
	repo := finding.NewRepository(pool).WithChangeTrigger(trig)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	mk := func(fp string) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint = fp
		out, err := repo.Upsert(ctx, f)
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		return out
	}
	a, b := mk("fp-a"), mk("fp-b")

	if _, err := repo.SetStatus(ctx, a.ID, finding.Triage{Status: domain.FindingFalsePositive, Reason: "vex", Actor: "vex"}); err != nil {
		t.Fatalf("system status: %v", err)
	}
	if _, err := repo.SetSeverity(ctx, b.ID, domain.SeverityLow); err != nil {
		t.Fatalf("system severity: %v", err)
	}
	if len(trig.calls) != 0 {
		t.Fatalf("automated writes fired the trigger %d times", len(trig.calls))
	}

	if _, err := repo.SetStatusManual(ctx, a.ID, finding.Triage{Status: domain.FindingOpen, Actor: "bob"}); err != nil {
		t.Fatalf("manual status: %v", err)
	}
	sev := domain.SeverityHigh
	if _, err := repo.Apply(ctx, []string{a.ID, b.ID}, finding.Change{Severity: &sev}, "bob"); err != nil {
		t.Fatalf("bulk: %v", err)
	}
	if len(trig.calls) != 2 || len(trig.calls[1]) != 2 {
		t.Errorf("trigger calls = %v, want the manual change, then the bulk edit as one call of 2", trig.calls)
	}
	// An assignment isn't a status or severity decision.
	if _, err := repo.Apply(ctx, []string{a.ID}, finding.Change{SetAssignee: true}, "bob"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if len(trig.calls) != 2 {
		t.Errorf("an assignment fired the trigger")
	}
}

// DeduplicateFindings (after a decision on some findings) regroups exactly as
// a full recompute would.
func TestDeduplicateFindingsMatchesFullRun(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scan := seedScan(t, pool, projectID)
	mk := func(fp, tool, cve string, sev domain.Severity) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Severity = fp, tool, sev
		f.PackageName, f.Category, f.CVE, f.LastScanID = "log4j-core", domain.CategorySCA, []string{cve}, &scan
		out, err := repo.Upsert(ctx, f)
		if err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
		return out
	}
	primary := mk("fp-grype", "grype", "CVE-1111", domain.SeverityCritical)
	mk("fp-trivy", "trivy", "CVE-1111", domain.SeverityHigh)
	mk("fp-other", "grype", "CVE-2222", domain.SeverityLow)
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}

	// The primary is triaged away: its group must re-elect.
	if _, err := repo.SetStatus(ctx, primary.ID, finding.Triage{Status: domain.FindingFalsePositive, Reason: "r", Actor: "bob"}); err != nil {
		t.Fatalf("triage: %v", err)
	}
	if _, err := repo.DeduplicateFindings(ctx, projectID, []string{primary.ID}); err != nil {
		t.Fatalf("scoped dedup: %v", err)
	}
	scoped := grouping(t, pool, projectID)
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("full dedup: %v", err)
	}
	if full := grouping(t, pool, projectID); !maps.Equal(scoped, full) {
		t.Errorf("scoped dedup diverged from a full recompute:\n scoped: %v\n full:   %v", scoped, full)
	}
	for id, dup := range scoped {
		if dup != "" {
			t.Errorf("%s still a duplicate of %s after its primary was triaged away", id, dup)
		}
	}
}
