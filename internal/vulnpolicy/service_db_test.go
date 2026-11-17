package vulnpolicy_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/vulnpolicy"

	"github.com/jackc/pgx/v5/pgxpool"
)

const trivyLog4Shell = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"jar","Vulnerabilities":[
	{"VulnerabilityID":"CVE-2021-44228","PkgName":"log4j-core","InstalledVersion":"2.14.1","Severity":"CRITICAL"}]}]}`

func seedProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var projectID string
	if err := pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ($1,$1) RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,$1,$1 FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,$1,$1 FROM tm RETURNING id`, slug).
		Scan(&projectID); err != nil {
		t.Fatalf("seed project %s: %v", slug, err)
	}
	return projectID
}

func eventActor(t *testing.T, pool *pgxpool.Pool, findingID string) string {
	t.Helper()
	var actor string
	if err := pool.QueryRow(context.Background(), `
		SELECT actor FROM finding_events WHERE finding_id = $1 ORDER BY id DESC LIMIT 1`, findingID).Scan(&actor); err != nil {
		t.Fatalf("read finding_events actor: %v", err)
	}
	return actor
}

// TestNotAffectedPolicyAppliesAtIngestAndHistoryShowsActor: a not_affected
// policy claims a matching package finding the moment a scan reports it, and
// the audit trail attributes the change to the policy, not a person.
func TestNotAffectedPolicyAppliesAtIngestAndHistoryShowsActor(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	policyRepo := vulnpolicy.NewRepository(pool)
	policySvc := vulnpolicy.NewService(policyRepo, findingRepo, findingRepo)

	projectID := seedProject(t, pool, "vp-ingest")

	p := vulnpolicy.Draft()
	p.Name = "log4shell not affected"
	p.Condition = `vulnerability.id == "CVE-2021-44228"`
	p.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisNotAffected, Justification: "not reachable", Details: "no JNDI lookup in our build"}
	if err := p.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := policyRepo.Create(ctx, p, "admin"); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	ingest := scan.NewService(scanRepo, findingRepo, projectRepo,
		scanner.NewRegistry(scanner.NewTrivy()), nil, []scan.Applier{policySvc}, scanRepo)
	if _, err := ingest.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy"},
		strings.NewReader(trivyLog4Shell)); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	findings, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil || len(findings) != 1 {
		t.Fatalf("list: %v findings=%d", err, len(findings))
	}
	f := findings[0]
	if f.Status != domain.FindingFalsePositive {
		t.Fatalf("status = %q, want false_positive", f.Status)
	}
	if f.ExceptionBy != "vuln-policy:log4shell not affected" {
		t.Errorf("exception_by = %q, want the policy's actor", f.ExceptionBy)
	}
	if actor := eventActor(t, pool, f.ID); actor != "vuln-policy:log4shell not affected" {
		t.Errorf("finding_events actor = %q, want the policy's actor", actor)
	}
}

// TestExpiredPolicyRevertsOnNextEvaluation: once a policy's validity window
// closes, the next evaluation puts the finding back where it was before the
// policy ever touched it — the same way an expired triage exception reopens.
func TestExpiredPolicyRevertsOnNextEvaluation(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	policyRepo := vulnpolicy.NewRepository(pool)
	policySvc := vulnpolicy.NewService(policyRepo, findingRepo, findingRepo)

	projectID := seedProject(t, pool, "vp-expiry")
	f, err := findingRepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-expiry", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "CVE-2021-44228", Title: "Log4Shell", Severity: domain.SeverityCritical,
		CVE: []string{"CVE-2021-44228"}, PackageName: "log4j-core", PackageVersion: "2.14.1",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	until := time.Now().Add(time.Hour)
	p := vulnpolicy.Draft()
	p.Name = "temporary suppression"
	p.Condition = `vulnerability.id == "CVE-2021-44228"`
	p.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisNotAffected}
	p.ValidUntil = &until
	if err := p.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate: %v", err)
	}
	created, err := policyRepo.Create(ctx, p, "admin")
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	if _, err := policySvc.ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got, err := findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingFalsePositive {
		t.Fatalf("status after apply = %q, want false_positive", got.Status)
	}

	// The window closes.
	expired := time.Now().Add(-time.Minute)
	created.ValidUntil = &expired
	if _, err := policyRepo.Update(ctx, created); err != nil {
		t.Fatalf("expire policy: %v", err)
	}
	if _, err := policySvc.ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	got, err = findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingOpen {
		t.Errorf("status after expiry = %q, want reverted to open", got.Status)
	}
}

// TestPersonsLaterStatusChangeIsNotOverturned: once a person moves a finding
// away from what a policy set, the next evaluation must leave it exactly
// where the person put it — never reclaim it, never revert it either.
func TestPersonsLaterStatusChangeIsNotOverturned(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	policyRepo := vulnpolicy.NewRepository(pool)
	policySvc := vulnpolicy.NewService(policyRepo, findingRepo, findingRepo)

	projectID := seedProject(t, pool, "vp-overturn")
	f, err := findingRepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-overturn", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "CVE-2021-44228", Title: "Log4Shell", Severity: domain.SeverityCritical,
		CVE: []string{"CVE-2021-44228"}, PackageName: "log4j-core", PackageVersion: "2.14.1",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	p := vulnpolicy.Draft()
	p.Name = "auto suppress"
	p.Condition = `vulnerability.id == "CVE-2021-44228"`
	p.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisNotAffected}
	if err := p.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := policyRepo.Create(ctx, p, "admin"); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if _, err := policySvc.ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got, _ := findingRepo.Get(ctx, f.ID); got.Status != domain.FindingFalsePositive {
		t.Fatalf("precondition: status = %q, want false_positive", got.Status)
	}

	// A security analyst disagrees and confirms it's real.
	if _, err := findingRepo.SetStatus(ctx, f.ID, finding.Triage{
		Status: domain.FindingConfirmed, Reason: "actually exploitable in our build", Actor: "alice@example.com",
	}); err != nil {
		t.Fatalf("person override: %v", err)
	}

	// The policy still matches on re-evaluation, but must not reclaim it.
	if _, err := policySvc.ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	got, err := findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingConfirmed {
		t.Errorf("status = %q after re-evaluation, want the person's confirmed to stand", got.Status)
	}

	// And the policy must not keep "owning" the finding — deleting it later
	// must not try to revert a status it no longer actually holds.
	if _, err := policySvc.ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("third apply: %v", err)
	}
	got, err = findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingConfirmed {
		t.Errorf("status = %q after a further evaluation, want confirmed to keep standing", got.Status)
	}
}

// TestPriorityBetweenTwoMatchingPolicies: when two apply-mode policies both
// match the same pair, the higher-priority one wins.
func TestPriorityBetweenTwoMatchingPolicies(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	policyRepo := vulnpolicy.NewRepository(pool)
	policySvc := vulnpolicy.NewService(policyRepo, findingRepo, findingRepo)

	projectID := seedProject(t, pool, "vp-priority")
	f, err := findingRepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-priority", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "CVE-2021-44228", Title: "Log4Shell", Severity: domain.SeverityCritical,
		CVE: []string{"CVE-2021-44228"}, PackageName: "log4j-core", PackageVersion: "2.14.1",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	low := vulnpolicy.Draft()
	low.Name, low.Priority = "low priority exploitable", 1
	low.Condition = `vulnerability.id == "CVE-2021-44228"`
	low.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisExploitable}
	if err := low.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate low: %v", err)
	}
	if _, err := policyRepo.Create(ctx, low, "admin"); err != nil {
		t.Fatalf("create low: %v", err)
	}

	high := vulnpolicy.Draft()
	high.Name, high.Priority = "high priority not affected", 10
	high.Condition = `vulnerability.id == "CVE-2021-44228"`
	high.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisNotAffected}
	if err := high.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate high: %v", err)
	}
	if _, err := policyRepo.Create(ctx, high, "admin"); err != nil {
		t.Fatalf("create high: %v", err)
	}

	if _, err := policySvc.ApplyToProject(ctx, projectID); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got, err := findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingFalsePositive {
		t.Errorf("status = %q, want the higher-priority policy's not_affected (false_positive) to win", got.Status)
	}
	if got.ExceptionBy != "vuln-policy:high priority not affected" {
		t.Errorf("exception_by = %q, want the higher-priority policy", got.ExceptionBy)
	}
}

// TestLogOnlyModeChangesNothing: a log-only policy records nothing and
// mutates nothing, even when its condition matches.
func TestLogOnlyModeChangesNothing(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	policyRepo := vulnpolicy.NewRepository(pool)
	policySvc := vulnpolicy.NewService(policyRepo, findingRepo, findingRepo)

	projectID := seedProject(t, pool, "vp-logonly")
	f, err := findingRepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-logonly", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "CVE-2021-44228", Title: "Log4Shell", Severity: domain.SeverityCritical,
		CVE: []string{"CVE-2021-44228"}, PackageName: "log4j-core", PackageVersion: "2.14.1",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	p := vulnpolicy.Draft()
	p.Name, p.Mode = "would suppress", vulnpolicy.ModeLog
	p.Condition = `vulnerability.id == "CVE-2021-44228"`
	p.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisNotAffected}
	if err := p.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := policyRepo.Create(ctx, p, "admin"); err != nil {
		t.Fatalf("create: %v", err)
	}

	changed, err := policySvc.ApplyToProject(ctx, projectID)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed != 0 {
		t.Errorf("changed = %d, want 0 for a log-only policy", changed)
	}
	got, err := findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingOpen {
		t.Errorf("status = %q, a log-only policy must never mutate a finding", got.Status)
	}

	// Preview still reports what it would have done.
	preview, err := policySvc.Preview(ctx, p, projectID)
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if preview.Total != 1 || len(preview.Findings) != 1 || preview.Findings[0].SetStatus != domain.FindingFalsePositive {
		t.Errorf("preview = %+v, want one match that would set false_positive", preview)
	}
}

// TestBundleRoundTripAndDryRun: exporting then importing a bundle reproduces
// the same policies, and dry_run reports the result without writing it.
func TestBundleRoundTripAndDryRun(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	policyRepo := vulnpolicy.NewRepository(pool)
	policySvc := vulnpolicy.NewService(policyRepo, findingRepo, findingRepo)

	a := vulnpolicy.Draft()
	a.Name, a.Priority = "alpha", 5
	a.Condition = `vulnerability.kev == true`
	a.Analysis = &vulnpolicy.Analysis{State: vulnpolicy.AnalysisInTriage}
	if err := a.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate a: %v", err)
	}
	b := vulnpolicy.Draft()
	b.Name = "beta"
	b.Condition = `vulnerability.epss >= 0.5`
	b.Rating = &vulnpolicy.Rating{Severity: domain.SeverityHigh}
	if err := b.Validate(vulnpolicy.Schema); err != nil {
		t.Fatalf("validate b: %v", err)
	}
	if _, err := policyRepo.Create(ctx, a, "admin"); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if _, err := policyRepo.Create(ctx, b, "admin"); err != nil {
		t.Fatalf("create b: %v", err)
	}

	exported, err := policySvc.List(ctx)
	if err != nil || len(exported) != 2 {
		t.Fatalf("list: %v (%d)", err, len(exported))
	}
	raw, err := vulnpolicy.EncodeBundle(exported, "yaml")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	bundle, err := vulnpolicy.DecodeBundle(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(bundle.Policies) != 2 {
		t.Fatalf("decoded %d policies, want 2", len(bundle.Policies))
	}

	// dry_run: reports the set without writing it.
	before, err := policyRepo.List(ctx)
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	if _, err := policySvc.ImportBundle(ctx, bundle.Policies, vulnpolicy.Schema, "importer", true); err != nil {
		t.Fatalf("dry-run import: %v", err)
	}
	after, err := policyRepo.List(ctx)
	if err != nil {
		t.Fatalf("list after dry run: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("dry_run changed the stored set: before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i].ID != after[i].ID {
			t.Errorf("dry_run must not touch existing rows: id changed for %s", before[i].Name)
		}
	}

	// Real import: replaces the set (fresh ids, same names/content).
	out, err := policySvc.ImportBundle(ctx, bundle.Policies, vulnpolicy.Schema, "importer", false)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("imported %d policies, want 2", len(out))
	}
	names := map[string]bool{}
	for _, p := range out {
		names[p.Name] = true
		if p.CreatedBy != "importer" {
			t.Errorf("%s: created_by = %q, want importer", p.Name, p.CreatedBy)
		}
	}
	if !names["alpha"] || !names["beta"] {
		t.Errorf("round-tripped names = %+v, want alpha and beta", names)
	}

	// Duplicate names in the bundle must be rejected before anything is written.
	dup := []vulnpolicy.Policy{a, a}
	if _, err := policySvc.ImportBundle(ctx, dup, vulnpolicy.Schema, "importer", false); err == nil {
		t.Error("expected a duplicate-name bundle to be rejected")
	}
}
