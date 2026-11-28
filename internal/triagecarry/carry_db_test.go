package triagecarry_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/triagecarry"
)

// seedProject creates an org + team + project and returns the project id.
func seedProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var projectID string
	if err := pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id),
		     tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, $1, $1 FROM tm RETURNING id`, slug).
		Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

// newVersion creates (or finds) a named branch version of projectID.
func newVersion(t *testing.T, pool *pgxpool.Pool, projectID, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `SELECT project_version($1, $2, 'branch')`, projectID, name).
		Scan(&id); err != nil {
		t.Fatalf("seed version %s: %v", name, err)
	}
	return id
}

// seedFinding upserts an open finding at fp on versionID.
func seedFinding(t *testing.T, repo *finding.Repository, projectID, versionID, fp string) finding.Finding {
	t.Helper()
	f, err := repo.Upsert(context.Background(), finding.Finding{
		ProjectID: projectID, VersionID: versionID, Fingerprint: fp, Scanner: "trivy",
		Category: domain.CategorySCA, RuleID: fp, Title: fp, Severity: domain.SeverityHigh,
		Metadata: map[string]any{},
	})
	if err != nil {
		t.Fatalf("seed finding %s: %v", fp, err)
	}
	return f
}

// wire builds the finding/project repos and a carry Service wired as the
// finding repository's Carrier, as cmd/api/main.go does.
func wire(pool *pgxpool.Pool) (*finding.Repository, *project.Repository, *triagecarry.Service) {
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	svc := triagecarry.NewService(triagecarry.NewRepository(pool), projects, findings)
	findings.WithCarrier(svc)
	return findings, projects, svc
}

// TestCarryPropagatesAcrossBranchesAndReopens is 13.1's core behavior: a
// manual false_positive on one branch reaches a matching open finding on
// another in-scope branch, attributed to the actor with a "carried from"
// note, and reopening the source carries the reopen too.
func TestCarryPropagatesAcrossBranchesAndReopens(t *testing.T) {
	pool := pgtest.Pool(t)
	findings, projects, _ := wire(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "carry-basic")
	vMain := newVersion(t, pool, projectID, "main")
	vFeat := newVersion(t, pool, projectID, "feature-x")

	if err := projects.SetTriageCarrySettings(ctx, projectID, true, ""); err != nil {
		t.Fatalf("enable carry: %v", err)
	}

	f1 := seedFinding(t, findings, projectID, vMain, "fp-1")
	f2 := seedFinding(t, findings, projectID, vFeat, "fp-1")

	if _, err := findings.SetStatusManual(ctx, f1.ID, finding.Triage{
		Status: domain.FindingFalsePositive, Reason: "not exploitable in our config", Actor: "alice",
		VexJustification: domain.VexJustificationRequiresConfiguration,
		VexResponse:      []domain.VexResponse{domain.VexResponseWorkaroundAvailable},
	}); err != nil {
		t.Fatalf("triage source: %v", err)
	}

	got2, err := findings.Get(ctx, f2.ID)
	if err != nil {
		t.Fatalf("get target: %v", err)
	}
	if got2.Status != domain.FindingFalsePositive || got2.ExceptionReason != "not exploitable in our config" {
		t.Fatalf("target = %+v, want carried false_positive", got2)
	}
	// The analysis travels with the decision (13.2), so the other branch's
	// not_affected is still a justified one.
	if got2.VexJustification != domain.VexJustificationRequiresConfiguration ||
		len(got2.VexResponse) != 1 || got2.VexResponse[0] != domain.VexResponseWorkaroundAvailable {
		t.Errorf("target analysis = %q %v, want the source's", got2.VexJustification, got2.VexResponse)
	}

	events, err := findings.History(ctx, f2.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var sawCarry bool
	for _, e := range events {
		if e.Kind == "status" && e.Actor == "alice" && e.Note == "carried from main" {
			sawCarry = true
		}
	}
	if !sawCarry {
		t.Errorf("history = %+v, want a status event noted 'carried from main' by alice", events)
	}

	// Reopening the source carries the reopen too.
	if _, err := findings.SetStatusManual(ctx, f1.ID, finding.Triage{Status: domain.FindingOpen, Actor: "alice"}); err != nil {
		t.Fatalf("reopen source: %v", err)
	}
	if got2, err = findings.Get(ctx, f2.ID); err != nil || got2.Status != domain.FindingOpen {
		t.Fatalf("target after reopen = %+v, err %v, want open", got2, err)
	}
}

// TestCarryAtIngestOnNewBranch covers inheriting a decision on a brand-new
// version's first scan — no separate clone step.
func TestCarryAtIngestOnNewBranch(t *testing.T) {
	pool := pgtest.Pool(t)
	findings, projects, carry := wire(pool)
	scans := scan.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "carry-ingest")
	vMain := newVersion(t, pool, projectID, "main")

	if err := projects.SetTriageCarrySettings(ctx, projectID, true, ""); err != nil {
		t.Fatalf("enable carry: %v", err)
	}

	f1 := seedFinding(t, findings, projectID, vMain, "fp-2")
	if _, err := findings.SetStatusManual(ctx, f1.ID, finding.Triage{
		Status: domain.FindingWontFix, Reason: "accepted via waiver", Actor: "alice",
		VexResponse: []domain.VexResponse{domain.VexResponseCanNotFix},
	}); err != nil {
		t.Fatalf("triage source: %v", err)
	}

	newScan, err := scans.Create(ctx, scan.Scan{ProjectID: projectID, Scanner: "trivy", Category: domain.CategorySCA, Branch: "release-2.0"})
	if err != nil {
		t.Fatalf("create scan on new branch: %v", err)
	}
	scanID := newScan.ID
	f3, err := findings.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-2", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "fp-2", Title: "fp-2", Severity: domain.SeverityHigh, LastScanID: &scanID, Metadata: map[string]any{},
	})
	if err != nil {
		t.Fatalf("ingest finding on new branch: %v", err)
	}
	if f3.Status != domain.FindingOpen {
		t.Fatalf("freshly ingested finding status = %q, want open before carry applies", f3.Status)
	}

	changed, err := carry.ApplyToScan(ctx, projectID, newScan.ID)
	if err != nil {
		t.Fatalf("apply to scan: %v", err)
	}
	if changed != 1 {
		t.Fatalf("changed = %d, want 1", changed)
	}
	got3, err := findings.Get(ctx, f3.ID)
	if err != nil || got3.Status != domain.FindingWontFix || got3.ExceptionReason != "accepted via waiver" {
		t.Fatalf("new-branch finding = %+v, err %v, want carried wont_fix", got3, err)
	}
	// Read back from the stored decision, the analysis survives too.
	if len(got3.VexResponse) != 1 || got3.VexResponse[0] != domain.VexResponseCanNotFix {
		t.Errorf("new-branch analysis = %v, want [can_not_fix]", got3.VexResponse)
	}
}

// TestCarryBranchRegexScope: a decision on an out-of-scope branch never
// carries, and an in-scope decision never reaches an out-of-scope target.
func TestCarryBranchRegexScope(t *testing.T) {
	pool := pgtest.Pool(t)
	findings, projects, _ := wire(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "carry-regex")
	vMain := newVersion(t, pool, projectID, "main")
	vFeat := newVersion(t, pool, projectID, "feature-z")
	vHotfix := newVersion(t, pool, projectID, "hotfix")

	if err := projects.SetTriageCarrySettings(ctx, projectID, true, "^main$"); err != nil {
		t.Fatalf("enable scoped carry: %v", err)
	}

	// In-scope source (main), out-of-scope target (feature-z): no propagation.
	f1 := seedFinding(t, findings, projectID, vMain, "fp-3")
	f2 := seedFinding(t, findings, projectID, vFeat, "fp-3")
	if _, err := findings.SetStatusManual(ctx, f1.ID, finding.Triage{Status: domain.FindingFalsePositive, Actor: "alice"}); err != nil {
		t.Fatalf("triage in-scope source: %v", err)
	}
	if got2, err := findings.Get(ctx, f2.ID); err != nil || got2.Status != domain.FindingOpen {
		t.Fatalf("out-of-scope target = %+v, err %v, want untouched (open)", got2, err)
	}

	// Out-of-scope source (hotfix): never recorded, so even an in-scope
	// target (main) sharing the fingerprint is untouched.
	f4 := seedFinding(t, findings, projectID, vHotfix, "fp-3b")
	f5 := seedFinding(t, findings, projectID, vMain, "fp-3b")
	if _, err := findings.SetStatusManual(ctx, f4.ID, finding.Triage{Status: domain.FindingFalsePositive, Actor: "alice"}); err != nil {
		t.Fatalf("triage out-of-scope source: %v", err)
	}
	if got5, err := findings.Get(ctx, f5.ID); err != nil || got5.Status != domain.FindingOpen {
		t.Fatalf("in-scope target of an out-of-scope source = %+v, err %v, want untouched (open)", got5, err)
	}
}

// TestCarryNeverOverturnsNewerDecision: a targeted, more recent decision on
// one instance survives a later re-ingest that would otherwise reapply an
// older carried decision from elsewhere in the project.
func TestCarryNeverOverturnsNewerDecision(t *testing.T) {
	pool := pgtest.Pool(t)
	findings, projects, carry := wire(pool)
	scans := scan.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "carry-no-overturn")
	vMain := newVersion(t, pool, projectID, "main")
	vFeat := newVersion(t, pool, projectID, "feature-x")

	if err := projects.SetTriageCarrySettings(ctx, projectID, true, ""); err != nil {
		t.Fatalf("enable carry: %v", err)
	}

	f1 := seedFinding(t, findings, projectID, vMain, "fp-4")
	f2 := seedFinding(t, findings, projectID, vFeat, "fp-4")

	// T1: main is triaged false_positive, carries to feature-x.
	if _, err := findings.SetStatusManual(ctx, f1.ID, finding.Triage{Status: domain.FindingFalsePositive, Actor: "alice"}); err != nil {
		t.Fatalf("triage source: %v", err)
	}
	if got2, _ := findings.Get(ctx, f2.ID); got2.Status != domain.FindingFalsePositive {
		t.Fatalf("target after carry = %q, want false_positive", got2.Status)
	}
	time.Sleep(5 * time.Millisecond)

	// T2 (> T1): a person looks at feature-x specifically and confirms it's real.
	if _, err := findings.SetStatusManual(ctx, f2.ID, finding.Triage{Status: domain.FindingConfirmed, Actor: "bob"}); err != nil {
		t.Fatalf("targeted override: %v", err)
	}

	// The same finding is reported again by a later scan on feature-x (a
	// realistic re-ingest): still the project's T1 decision on file, but this
	// instance now has its own, newer (T2) decision.
	newScan, err := scans.Create(ctx, scan.Scan{ProjectID: projectID, Scanner: "trivy", Category: domain.CategorySCA, Branch: "feature-x"})
	if err != nil {
		t.Fatalf("re-scan feature-x: %v", err)
	}
	scanID := newScan.ID
	if _, err := findings.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-4", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "fp-4", Title: "fp-4", Severity: domain.SeverityHigh, LastScanID: &scanID, Metadata: map[string]any{},
	}); err != nil {
		t.Fatalf("re-ingest: %v", err)
	}

	changed, err := carry.ApplyToScan(ctx, projectID, newScan.ID)
	if err != nil {
		t.Fatalf("apply to scan: %v", err)
	}
	if changed != 0 {
		t.Errorf("changed = %d, want 0 (newer targeted decision must not be overturned)", changed)
	}
	if got2, err := findings.Get(ctx, f2.ID); err != nil || got2.Status != domain.FindingConfirmed {
		t.Fatalf("target after re-ingest = %+v, err %v, want still confirmed", got2, err)
	}
}

// TestCarryExcludesRiskAcceptance: a risk acceptance never carries — it is a
// decision about one version's exposure, not a statement about the finding.
func TestCarryExcludesRiskAcceptance(t *testing.T) {
	pool := pgtest.Pool(t)
	findings, projects, _ := wire(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "carry-risk-accept")
	vMain := newVersion(t, pool, projectID, "main")
	vFeat := newVersion(t, pool, projectID, "feature-x")

	if err := projects.SetTriageCarrySettings(ctx, projectID, true, ""); err != nil {
		t.Fatalf("enable carry: %v", err)
	}

	f1 := seedFinding(t, findings, projectID, vMain, "fp-5")
	f2 := seedFinding(t, findings, projectID, vFeat, "fp-5")

	ra, _, err := findings.CreateAcceptance(ctx, finding.AcceptanceInput{
		ProjectID: projectID, Title: "WAF", Justification: "virtual patch", FindingIDs: []string{f1.ID},
	}, "alice")
	if err != nil {
		t.Fatalf("request acceptance: %v", err)
	}
	if _, _, err := findings.ApproveAcceptance(ctx, projectID, ra.ID, "carol", "fine", true); err != nil {
		t.Fatalf("approve acceptance: %v", err)
	}
	if got1, _ := findings.Get(ctx, f1.ID); got1.Status != domain.FindingRiskAccepted {
		t.Fatalf("source status = %q, want risk_accepted", got1.Status)
	}
	if got2, err := findings.Get(ctx, f2.ID); err != nil || got2.Status != domain.FindingOpen {
		t.Fatalf("target = %+v, err %v, want untouched (open): risk acceptance must not carry", got2, err)
	}
}

// TestCarryDisabledHasNoEffect: the project setting defaults off, and a
// manual triage decision never leaves its own version until it's turned on.
func TestCarryDisabledHasNoEffect(t *testing.T) {
	pool := pgtest.Pool(t)
	findings, _, _ := wire(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "carry-off")
	vMain := newVersion(t, pool, projectID, "main")
	vFeat := newVersion(t, pool, projectID, "feature-x")

	f1 := seedFinding(t, findings, projectID, vMain, "fp-6")
	f2 := seedFinding(t, findings, projectID, vFeat, "fp-6")

	if _, err := findings.SetStatusManual(ctx, f1.ID, finding.Triage{Status: domain.FindingFalsePositive, Actor: "alice"}); err != nil {
		t.Fatalf("triage source: %v", err)
	}
	if got2, err := findings.Get(ctx, f2.ID); err != nil || got2.Status != domain.FindingOpen {
		t.Fatalf("target = %+v, err %v, want untouched (carry is off)", got2, err)
	}
}

// TestEligible is a pure unit test of which statuses carry.
func TestEligible(t *testing.T) {
	cases := map[domain.FindingStatus]bool{
		domain.FindingFalsePositive: true,
		domain.FindingWontFix:       true,
		domain.FindingOpen:          true,
		domain.FindingConfirmed:     false,
		domain.FindingRemediated:    false,
		domain.FindingRiskAccepted:  false,
	}
	for status, want := range cases {
		if got := triagecarry.Eligible(status); got != want {
			t.Errorf("Eligible(%q) = %v, want %v", status, got, want)
		}
	}
}
