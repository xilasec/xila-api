package triage_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/triage"
)

func TestApplyRulesIntegration(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)
	rrepo := triage.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-tr','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	seed := func(fp string, cat domain.Category, sev domain.Severity, path string) finding.Finding {
		f, err := frepo.Upsert(ctx, finding.Finding{
			ProjectID: projectID, Fingerprint: fp, Scanner: "trivy", Category: cat,
			RuleID: fp, Title: fp, Severity: sev, FilePath: path,
		})
		if err != nil {
			t.Fatalf("seed finding %s: %v", fp, err)
		}
		return f
	}
	testIaC := seed("a", domain.CategoryIaC, domain.SeverityLow, "test/main.tf")
	prodIaC := seed("b", domain.CategoryIaC, domain.SeverityLow, "prod/main.tf")
	highSCA := seed("c", domain.CategorySCA, domain.SeverityHigh, "go.mod")

	// A global rule: mute low IaC findings under test/.
	if _, err := rrepo.Create(ctx, triage.Rule{
		Name: "mute test IaC", Enabled: true,
		Category: domain.CategoryIaC, Severities: []domain.Severity{domain.SeverityLow},
		PathRegex: "^test/", Action: triage.ActionFalsePositive,
	}, "", false); err != nil {
		t.Fatalf("create rule: %v", err)
	}

	changed, err := triage.NewService(rrepo, frepo, frepo).ApplyToProject(ctx, projectID)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed != 1 {
		t.Fatalf("changed = %d, want 1 (only the test/ IaC finding)", changed)
	}

	assertStatus := func(id string, want domain.FindingStatus) {
		got, err := frepo.Get(ctx, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if got.Status != want {
			t.Errorf("finding %s status = %q, want %q", id, got.Status, want)
		}
	}
	assertStatus(testIaC.ID, domain.FindingFalsePositive) // suppressed
	assertStatus(prodIaC.ID, domain.FindingOpen)          // wrong path
	assertStatus(highSCA.ID, domain.FindingOpen)          // wrong category + severity

	// The suppression is auditable (actor records the rule).
	if excs, _ := frepo.ListExceptions(ctx, testIaC.ID); len(excs) == 0 {
		t.Error("expected an exception audit row for the auto-triaged finding")
	}

	// A second apply is a no-op (already suppressed / not in the active set).
	if changed, _ := triage.NewService(rrepo, frepo, frepo).ApplyToProject(ctx, projectID); changed != 0 {
		t.Errorf("re-apply changed = %d, want 0 (idempotent)", changed)
	}
}

// TestBackfillRegroupsDuplicates covers the interaction between the two halves of
// noise reduction. Severity decides which tool's report of a CVE leads its
// correlation group, and a triage rule can change severity across the whole
// backlog — so a rule applied after the fact has to leave the grouping consistent
// with the severities it just wrote, not the ones from ingest time.
func TestBackfillRegroupsDuplicates(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)
	rrepo := triage.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-bf','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	seed := func(fp, scanner string, sev domain.Severity) finding.Finding {
		f, err := frepo.Upsert(ctx, finding.Finding{
			ProjectID: projectID, Fingerprint: fp, Scanner: scanner, Category: domain.CategorySCA,
			RuleID: fp, Title: fp, Severity: sev,
			CVE: []string{"CVE-2021-44228"}, PackageName: "log4j-core",
		})
		if err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
		return f
	}
	// Same CVE from two tools: grype calls it critical, so it leads the group.
	trivy := seed("fp-trivy", "trivy", domain.SeverityHigh)
	grype := seed("fp-grype", "grype", domain.SeverityCritical)
	if _, err := frepo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}
	if got, _ := frepo.Get(ctx, trivy.ID); got.DuplicateOf == nil || *got.DuplicateOf != grype.ID {
		t.Fatalf("precondition: trivy should point at the critical grype report")
	}

	// Now a rule downgrades grype's noisy criticals to low. Trivy's high report is
	// the more severe view of the CVE, so it must take over as primary.
	if _, err := rrepo.Create(ctx, triage.Rule{
		Name: "downgrade grype", Enabled: true, Scanner: "grype",
		Severities: []domain.Severity{domain.SeverityCritical},
		Action:     triage.ActionSetSeverity, NewSeverity: domain.SeverityLow,
	}, "", false); err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if _, err := triage.NewService(rrepo, frepo, frepo).ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("apply: %v", err)
	}

	gotTrivy, _ := frepo.Get(ctx, trivy.ID)
	gotGrype, _ := frepo.Get(ctx, grype.ID)
	if gotTrivy.DuplicateOf != nil {
		t.Errorf("trivy (now the most severe report) should be primary, got duplicate_of=%v", *gotTrivy.DuplicateOf)
	}
	if gotGrype.DuplicateOf == nil || *gotGrype.DuplicateOf != trivy.ID {
		t.Errorf("downgraded grype report should now point at trivy, got %v", gotGrype.DuplicateOf)
	}
}
