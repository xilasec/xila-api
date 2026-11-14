package vex_test

import (
	"context"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/vex"
)

// The team analysed Log4Shell and concluded they never call the vulnerable path.
const analysis = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [{
    "vulnerability": {"name": "CVE-2021-44228"},
    "products": [{"@id": "pkg:maven/log4j-core@2.14.1"}],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path",
    "impact_statement": "JNDI lookups are disabled at startup."
  }]
}`

// Trivy will keep reporting the CVE forever: the vulnerable package really is
// there. That is the point — the scanner cannot know what the team knows.
const trivyReport = `{"Results":[{"Target":"pom.xml","Class":"lang-pkgs","Type":"jar","Vulnerabilities":[
	{"VulnerabilityID":"CVE-2021-44228","PkgName":"log4j-core","InstalledVersion":"2.14.1","Severity":"CRITICAL"}]}]}`

// TestVexAnalysisSurvivesRescans is the whole value of VEX: you analyse a
// vulnerability once, and it stays analysed. Without it, every scan puts the same
// CVE back on the queue and someone re-derives the same conclusion forever.
func TestVexAnalysisSurvivesRescans(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	vexRepo := vex.NewRepository(pool)
	vexSvc := vex.NewService(vexRepo, findingRepo, projectRepo)

	ingest := scan.NewService(scanRepo, findingRepo, projectRepo,
		scanner.NewRegistry(scanner.NewTrivy()), nil, []scan.Applier{vexSvc}, scanRepo)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-vx','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// Scan 1: the CVE lands on the queue like any other critical.
	if _, err := ingest.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy"},
		strings.NewReader(trivyReport)); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	open, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID, Status: domain.FindingOpen})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(open) != 1 {
		t.Fatalf("open findings after first scan = %d, want 1", len(open))
	}
	findingID := open[0].ID

	// The team uploads its analysis. It takes effect immediately on the backlog —
	// not on some future scan.
	stmts, resolved, err := vexSvc.Ingest(ctx, projectID, strings.NewReader(analysis))
	if err != nil {
		t.Fatalf("vex ingest: %v", err)
	}
	if len(stmts) != 1 || resolved != 1 {
		t.Fatalf("stored %d statements, resolved %d findings; want 1 and 1", len(stmts), resolved)
	}
	f, err := findingRepo.Get(ctx, findingID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if f.Status != domain.FindingFalsePositive {
		t.Fatalf("status = %q, want false_positive", f.Status)
	}
	if !strings.Contains(f.ExceptionReason, "vulnerable_code_not_in_execute_path") || f.ExceptionBy != "vex" {
		t.Errorf("the audit trail must record the VEX rationale and actor, got reason=%q by=%q",
			f.ExceptionReason, f.ExceptionBy)
	}

	// Scan 2, next day. Trivy reports the very same CVE again — the package is
	// still there. The finding must NOT come back to the queue.
	if _, err := ingest.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy"},
		strings.NewReader(trivyReport)); err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	f, err = findingRepo.Get(ctx, findingID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if f.Status != domain.FindingFalsePositive {
		t.Errorf("status = %q after a re-scan, want it to stay false_positive — an analysis made once must stay made", f.Status)
	}
	stillOpen, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID, Status: domain.FindingOpen})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stillOpen) != 0 {
		t.Errorf("the analysed CVE is back on the queue (%d open findings)", len(stillOpen))
	}

	// Deleting the statement means the analysis no longer holds: the next scan is
	// free to reopen it. (The finding stays triaged until something reopens it —
	// what matters is that we stop asserting a verdict we no longer have.)
	if err := vexRepo.Delete(ctx, stmts[0].ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if remaining, _ := vexRepo.ListByProject(ctx, projectID); len(remaining) != 0 {
		t.Errorf("statements after delete = %d, want 0", len(remaining))
	}
}

// TestVexAffectedConfirms: a VEX document is not only a suppression tool. An
// upstream "yes, this affects you" is the strongest possible triage signal.
func TestVexAffectedConfirms(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	vexRepo := vex.NewRepository(pool)
	vexSvc := vex.NewService(vexRepo, findingRepo, projectRepo)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-vy','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	f, err := findingRepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp-1", Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: "CVE-2022-22965", Title: "Spring4Shell", Severity: domain.SeverityCritical,
		CVE: []string{"CVE-2022-22965"}, PackageName: "spring-beans", PackageVersion: "5.3.0",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	const affected = `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[
		{"vulnerability":{"name":"CVE-2022-22965"},"status":"affected",
		 "action_statement":"Upgrade to 5.3.18 immediately."}]}`
	if _, n, err := vexSvc.Ingest(ctx, projectID, strings.NewReader(affected)); err != nil || n != 1 {
		t.Fatalf("vex ingest: n=%d err=%v", n, err)
	}
	got, err := findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingConfirmed {
		t.Errorf("status = %q, want confirmed — an upstream 'affected' is the strongest triage signal there is", got.Status)
	}
}
