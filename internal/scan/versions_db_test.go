package scan_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
)

const emptyTrivy = `{"Results":[]}`

// The M3.1 contract: the same CVE on main and feature/x is two findings with
// independent lifecycles — scanning one branch never closes or triages the
// other — while metrics, alerts and the default gate read only the default
// branch, which is whichever branch the project scanned first.
func TestBranchesHaveIndependentLifecycles(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	svc := scan.NewService(scan.NewRepository(pool), findings, projects,
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-v','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	ingest := func(branch, report string) scan.Scan {
		t.Helper()
		sc, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", Branch: branch, CloseMissing: true},
			strings.NewReader(report))
		if err != nil {
			t.Fatalf("ingest %s: %v", branch, err)
		}
		return sc
	}
	only := func(versionID string) finding.Finding {
		t.Helper()
		list, err := findings.List(ctx, finding.Filter{ProjectID: projectID, VersionID: versionID, AllVersions: true})
		if err != nil || len(list) != 1 {
			t.Fatalf("findings on version %s = %d (%v), want 1", versionID, len(list), err)
		}
		return list[0]
	}

	// The first branch scanned becomes the default; a second branch gets its
	// own version and its own copy of the finding.
	mainScan := ingest("master", trivyReport)
	featScan := ingest("feature/x", trivyReport)
	if mainScan.VersionID == featScan.VersionID || mainScan.VersionID == "" {
		t.Fatalf("versions = %q / %q, want two distinct versions", mainScan.VersionID, featScan.VersionID)
	}
	versions, err := projects.ListVersions(ctx, projectID)
	if err != nil || len(versions) != 2 || versions[0].Name != "master" || !versions[0].IsDefault || versions[1].IsDefault {
		t.Fatalf("versions = %+v (%v), want master (default) then feature/x", versions, err)
	}
	onMain, onFeat := only(mainScan.VersionID), only(featScan.VersionID)
	if onMain.ID == onFeat.ID {
		t.Fatal("the same CVE on two branches must be two findings")
	}

	// Triage on one branch doesn't touch the other.
	if _, err := findings.SetStatus(ctx, onFeat.ID, finding.Triage{Status: domain.FindingWontFix, Reason: "PR only"}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got := only(mainScan.VersionID); got.Status != domain.FindingOpen {
		t.Errorf("accepting on feature/x changed main's finding to %q", got.Status)
	}

	// Fixing it on the feature branch closes only the feature branch's finding;
	// main still ships it.
	if _, err := findings.SetStatus(ctx, onFeat.ID, finding.Triage{Status: domain.FindingOpen}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	ingest("feature/x", emptyTrivy)
	if got := only(featScan.VersionID); got.Status != domain.FindingRemediated {
		t.Errorf("feature/x finding = %q, want remediated after its fix", got.Status)
	}
	if got := only(mainScan.VersionID); got.Status != domain.FindingOpen {
		t.Errorf("main's finding = %q after a feature-branch fix, want still open", got.Status)
	}

	// Metrics and the default listing read the default branch only; a new
	// branch with the CVE doesn't double-count it.
	ingest("feature/y", trivyReport)
	if list, _ := findings.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 1 || list[0].VersionID != mainScan.VersionID {
		t.Errorf("default listing = %d findings, want only main's", len(list))
	}
	ov, err := portfolio.NewRepository(pool).Overview(ctx, nil)
	if err != nil {
		t.Fatalf("portfolio: %v", err)
	}
	if ov.TotalOpen != 1 {
		t.Errorf("portfolio total open = %d, want 1 (default branch only, feature/y excluded)", ov.TotalOpen)
	}
	if s, _ := findings.ComputeGateStats(ctx, projectID, "", false, ""); s.OpenCritical != 1 {
		t.Errorf("default gate open critical = %d, want 1", s.OpenCritical)
	}
	if s, _ := findings.ComputeGateStats(ctx, projectID, featScan.VersionID, false, ""); s.OpenCritical != 0 {
		t.Errorf("feature/x gate open critical = %d, want 0 (fixed there)", s.OpenCritical)
	}

	// A scan without a branch goes to the default version.
	if sc := ingest("", trivyReport); sc.VersionID != mainScan.VersionID {
		t.Errorf("branch-less scan landed on %q, want the default %q", sc.VersionID, mainScan.VersionID)
	}

	// Switching the default moves what metrics report.
	if err := projects.SetDefaultVersion(ctx, projectID, featScan.VersionID); err != nil {
		t.Fatalf("set default: %v", err)
	}
	if s, _ := findings.ComputeGateStats(ctx, projectID, "", false, ""); s.OpenCritical != 0 {
		t.Errorf("after switching the default to feature/x, open critical = %d, want 0", s.OpenCritical)
	}
	if err := projects.DeleteVersion(ctx, projectID, featScan.VersionID); err != project.ErrDefaultVersion {
		t.Errorf("deleting the default version = %v, want ErrDefaultVersion", err)
	}

	// Housekeeping prunes stale branches with their findings, never the default.
	if _, err := pool.Exec(ctx, `UPDATE scans SET created_at = now() - interval '200 days' WHERE project_id = $1`, projectID); err != nil {
		t.Fatalf("age scans: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE project_versions SET created_at = now() - interval '200 days' WHERE project_id = $1`, projectID); err != nil {
		t.Fatalf("age versions: %v", err)
	}
	n, err := projects.PruneStaleVersions(ctx, project.KindBranch, 90*24*time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d (%v), want master and feature/y (feature/x is the default)", n, err)
	}
	if list, _ := findings.List(ctx, finding.Filter{ProjectID: projectID, AllVersions: true}); len(list) != 1 || list[0].VersionID != featScan.VersionID {
		t.Errorf("after pruning, findings = %d, want only feature/x's", len(list))
	}
}
