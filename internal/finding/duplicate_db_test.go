package finding_test

import (
	"errors"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// TestMarkDuplicateManual covers the happy path and its guards (M13 13.15).
func TestMarkDuplicateManual(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := t.Context()
	projectID := seedProject(t, pool)

	a := sampleFinding(projectID)
	a.Fingerprint, a.RuleID = "fp-a", "rule-a"
	primary, err := repo.Upsert(ctx, a)
	if err != nil {
		t.Fatalf("seed primary: %v", err)
	}
	b := sampleFinding(projectID)
	b.Fingerprint, b.RuleID = "fp-b", "rule-b"
	dup, err := repo.Upsert(ctx, b)
	if err != nil {
		t.Fatalf("seed dup: %v", err)
	}

	got, err := repo.MarkDuplicateManual(ctx, dup.ID, primary.ID, "alice")
	if err != nil {
		t.Fatalf("mark duplicate: %v", err)
	}
	if got.DuplicateOf == nil || *got.DuplicateOf != primary.ID || !got.DuplicateManual {
		t.Fatalf("marked finding = %+v, want duplicate_of=%s duplicate_manual=true", got, primary.ID)
	}

	// Excluded from counts/lists exactly like an automatic duplicate.
	if list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 1 {
		t.Errorf("default list = %d, want 1 (manual duplicate hidden)", len(list))
	}
	if dups, _ := repo.ListDuplicatesOf(ctx, primary.ID); len(dups) != 1 || dups[0].ID != dup.ID {
		t.Errorf("duplicates of primary = %+v, want [%s]", dups, dup.ID)
	}

	// History records the hand-made mark.
	events, err := repo.History(ctx, dup.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Kind == "duplicate" && e.Actor == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("history = %+v, want a 'duplicate' event attributed to alice", events)
	}

	// Self-duplicate is refused.
	if _, err := repo.MarkDuplicateManual(ctx, primary.ID, primary.ID, "alice"); !errors.Is(err, finding.ErrSelfDuplicate) {
		t.Errorf("self duplicate = %v, want ErrSelfDuplicate", err)
	}

	// A different version (same project) is refused.
	var otherVersion string
	if err := pool.QueryRow(ctx, `SELECT project_version($1, 'feature-x', 'branch')`, projectID).Scan(&otherVersion); err != nil {
		t.Fatalf("seed other version: %v", err)
	}
	c := sampleFinding(projectID)
	c.Fingerprint, c.VersionID = "fp-c", otherVersion
	elsewhere, _ := repo.Upsert(ctx, c)
	if _, err := repo.MarkDuplicateManual(ctx, elsewhere.ID, primary.ID, "alice"); !errors.Is(err, finding.ErrDuplicateScope) {
		t.Errorf("cross-version duplicate = %v, want ErrDuplicateScope", err)
	}

	// Chaining onto a finding that is itself a duplicate is refused.
	d := sampleFinding(projectID)
	d.Fingerprint = "fp-d"
	third, _ := repo.Upsert(ctx, d)
	if _, err := repo.MarkDuplicateManual(ctx, third.ID, dup.ID, "alice"); !errors.Is(err, finding.ErrDuplicateChain) {
		t.Errorf("chained duplicate = %v, want ErrDuplicateChain", err)
	}

	// Unmark hands it back to automatic grouping.
	unmarked, err := repo.UnmarkDuplicateManual(ctx, dup.ID, "alice")
	if err != nil {
		t.Fatalf("unmark: %v", err)
	}
	if unmarked.DuplicateOf != nil || unmarked.DuplicateManual {
		t.Errorf("unmarked finding = %+v, want no duplicate_of and duplicate_manual=false", unmarked)
	}

	// Unmarking again (not currently a manual duplicate) is refused.
	if _, err := repo.UnmarkDuplicateManual(ctx, dup.ID, "alice"); !errors.Is(err, finding.ErrNotManualDuplicate) {
		t.Errorf("re-unmark = %v, want ErrNotManualDuplicate", err)
	}

	// An unknown finding id is reported as not found, both ways.
	if _, err := repo.MarkDuplicateManual(ctx, "00000000-0000-0000-0000-000000000000", primary.ID, "alice"); !errors.Is(err, finding.ErrNotFound) {
		t.Errorf("mark on unknown finding = %v, want ErrNotFound", err)
	}
	if _, err := repo.UnmarkDuplicateManual(ctx, "00000000-0000-0000-0000-000000000000", "alice"); !errors.Is(err, finding.ErrNotFound) {
		t.Errorf("unmark on unknown finding = %v, want ErrNotFound", err)
	}
}

// TestDeduplicateNeverRewritesManualDuplicate is the override invariant M13
// 13.15 requires: automatic dedup must skip any row flagged duplicate_manual,
// even when its own correlation grouping would place it elsewhere.
func TestDeduplicateNeverRewritesManualDuplicate(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := t.Context()
	projectID := seedProject(t, pool)

	mk := func(fp, scanner string, sev domain.Severity) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Severity = fp, scanner, sev
		f.CVE, f.PackageName = []string{"CVE-2021-44228"}, "log4j-core"
		f.Category = domain.CategorySCA
		return f
	}
	// trivy and grype share a correlation key: automatic dedup would normally
	// elect grype (critical) as primary and point trivy at it.
	trivy, _ := repo.Upsert(ctx, mk("fp-trivy", "trivy", domain.SeverityHigh))
	grype, _ := repo.Upsert(ctx, mk("fp-grype", "grype", domain.SeverityCritical))
	// An unrelated finding a person decided trivy actually duplicates instead.
	unrelated := sampleFinding(projectID)
	unrelated.Fingerprint, unrelated.Scanner, unrelated.CVE, unrelated.PackageName = "fp-unrelated", "semgrep", nil, ""
	unrelated.Category = domain.CategorySAST
	third, _ := repo.Upsert(ctx, unrelated)

	if _, err := repo.MarkDuplicateManual(ctx, trivy.ID, third.ID, "alice"); err != nil {
		t.Fatalf("mark manual duplicate: %v", err)
	}

	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}

	// trivy keeps the hand-made link, not grype's automatic one.
	gotTrivy, _ := repo.Get(ctx, trivy.ID)
	if gotTrivy.DuplicateOf == nil || *gotTrivy.DuplicateOf != third.ID || !gotTrivy.DuplicateManual {
		t.Fatalf("trivy = %+v, want duplicate_of=%s (manual, untouched by dedup)", gotTrivy, third.ID)
	}
	// grype has no electable sibling left in its CVE group (trivy is excluded
	// from automatic grouping), so it stays its own primary.
	gotGrype, _ := repo.Get(ctx, grype.ID)
	if gotGrype.DuplicateOf != nil {
		t.Errorf("grype = %+v, want no duplicate_of (sole electable member of its group)", gotGrype)
	}

	// A second run is idempotent and still leaves the manual link alone.
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("re-dedup: %v", err)
	}
	if gotTrivy, _ := repo.Get(ctx, trivy.ID); gotTrivy.DuplicateOf == nil || *gotTrivy.DuplicateOf != third.ID {
		t.Errorf("trivy after re-dedup = %+v, want duplicate_of=%s", gotTrivy, third.ID)
	}
}
