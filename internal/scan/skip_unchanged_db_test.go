package scan_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
)

// Two reports whose parsed findings are identical, differing only in a
// scanner-embedded timestamp Xila never extracts (Trivy's top-level
// CreatedAt) — the case 11.4 exists for: most CI reruns report exactly what
// they did last time.
const (
	skipReportV1 = `{"CreatedAt":"2024-01-01T00:00:00Z","Results":[{"Target":"go.mod","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2021-44228","PkgName":"log4j","InstalledVersion":"2.14.0","Severity":"CRITICAL"}]}]}`
	skipReportV1SameButStamped = `{"CreatedAt":"2030-06-15T10:30:00Z","Results":[{"Target":"go.mod","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2021-44228","PkgName":"log4j","InstalledVersion":"2.14.0","Severity":"CRITICAL"}]}]}`
	// A genuinely different report: a different CVE/package entirely.
	skipReportV2 = `{"CreatedAt":"2024-01-02T00:00:00Z","Results":[{"Target":"go.mod","Vulnerabilities":[
		{"VulnerabilityID":"CVE-2022-9999","PkgName":"other-pkg","InstalledVersion":"1.0","Severity":"HIGH"}]}]}`
)

func TestSkipUnchangedIgnoresEmbeddedTimestamp(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su1','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	scanA, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1))
	if err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if scanA.UnchangedOf != nil {
		t.Fatalf("first scan of a target must not be unchanged, got %v", scanA.UnchangedOf)
	}
	list, err := findings.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil || len(list) != 1 {
		t.Fatalf("findings after A = %d (%v), want 1", len(list), err)
	}
	f1 := list[0]
	if f1.FirstScanID == nil || *f1.FirstScanID != scanA.ID || f1.LastScanID == nil || *f1.LastScanID != scanA.ID {
		t.Fatalf("finding after A: first=%v last=%v, want both %s", f1.FirstScanID, f1.LastScanID, scanA.ID)
	}

	// B repeats A's content (different embedded timestamp only): short-circuit.
	scanB, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1SameButStamped))
	if err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	if scanB.Status != domain.ScanCompleted {
		t.Errorf("scan B status = %q, want completed", scanB.Status)
	}
	if scanB.UnchangedOf == nil || *scanB.UnchangedOf != scanA.ID {
		t.Errorf("scan B unchanged_of = %v, want %s", scanB.UnchangedOf, scanA.ID)
	}
	if scanB.ContentHash == nil || scanA.ContentHash == nil || *scanB.ContentHash != *scanA.ContentHash {
		t.Errorf("scan B content_hash = %v, want A's %v", scanB.ContentHash, scanA.ContentHash)
	}
	if len(scanB.Summary) != len(scanA.Summary) || scanB.Summary["critical"] != scanA.Summary["critical"] {
		t.Errorf("scan B summary = %v, want copied from A %v", scanB.Summary, scanA.Summary)
	}

	// No new finding row; the existing one's last_scan_id moved to B, first_scan_id untouched.
	list2, err := findings.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil || len(list2) != 1 {
		t.Fatalf("findings after B = %d (%v), want still 1 (no new rows)", len(list2), err)
	}
	f2 := list2[0]
	if f2.ID != f1.ID {
		t.Fatalf("finding id changed from %s to %s", f1.ID, f2.ID)
	}
	if f2.FirstScanID == nil || *f2.FirstScanID != scanA.ID {
		t.Errorf("first_scan_id = %v, want unchanged at %s", f2.FirstScanID, scanA.ID)
	}
	if f2.LastScanID == nil || *f2.LastScanID != scanB.ID {
		t.Errorf("last_scan_id = %v, want moved to %s", f2.LastScanID, scanB.ID)
	}
	if !f2.LastSeenAt.After(f1.LastSeenAt) && !f2.LastSeenAt.Equal(f1.LastSeenAt) {
		t.Errorf("last_seen_at did not advance: before=%v after=%v", f1.LastSeenAt, f2.LastSeenAt)
	}

	// The skipped scan introduced nothing: new=true on it returns empty.
	newList, err := findings.List(ctx, finding.Filter{ProjectID: projectID, ScanID: scanB.ID, NewOnly: true, AllVersions: true})
	if err != nil {
		t.Fatalf("list new: %v", err)
	}
	if len(newList) != 0 {
		t.Errorf("new findings for skipped scan = %d, want 0", len(newList))
	}
}

// Not a strict benchmark, but 11.4's whole point is cheapness: a skipped scan
// does one UPDATE per side (findings, scan row) instead of upsert + auto-close
// + dedup over every finding, so for a report with many findings the skip
// path should noticeably beat a full reprocess of the same size.
func TestSkipUnchangedIsCheaperThanFullReprocess(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su8','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	const n = 300
	var b strings.Builder
	b.WriteString(`{"Results":[{"Target":"go.mod","Vulnerabilities":[`)
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"VulnerabilityID":"CVE-2024-%05d","PkgName":"pkg%d","InstalledVersion":"1.0","Severity":"HIGH"}`, i, i)
	}
	b.WriteString(`]}]}`)
	report := b.String()

	// First upload: cold (creates the project version, etc.) — not timed.
	if _, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(report)); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}

	// Second upload: content differs by one finding (not unchanged) -> full pipeline.
	full := strings.Replace(report, "HIGH", "CRITICAL", 1)
	fullStart := time.Now()
	scFull, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(full))
	fullElapsed := time.Since(fullStart)
	if err != nil {
		t.Fatalf("ingest full: %v", err)
	}
	if scFull.UnchangedOf != nil {
		t.Fatalf("expected a full reprocess, got unchanged_of=%v", scFull.UnchangedOf)
	}

	// Third upload: repeats the second one's content exactly (timestamp differs
	// only) -> skip path.
	skipStart := time.Now()
	scSkip, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(strings.Replace(full, `"Results"`, `"CreatedAt":"2030-01-01T00:00:00Z","Results"`, 1)))
	skipElapsed := time.Since(skipStart)
	if err != nil {
		t.Fatalf("ingest skip: %v", err)
	}
	if scSkip.UnchangedOf == nil {
		t.Fatalf("expected the repeat to be skipped")
	}

	t.Logf("full reprocess of %d findings: %v; skipped repeat: %v (%.1fx faster)",
		n, fullElapsed, skipElapsed, float64(fullElapsed)/float64(max(skipElapsed, 1)))
	if skipElapsed > fullElapsed {
		t.Errorf("skip-unchanged (%v) was slower than a full reprocess (%v) of %d findings", skipElapsed, fullElapsed, n)
	}
}

// A report that genuinely differs (a different CVE/package) must reprocess,
// never short-circuit.
func TestSkipUnchangedReprocessesChangedFinding(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su2','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	if _, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1)); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	sc2, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV2))
	if err != nil {
		t.Fatalf("ingest 2: %v", err)
	}
	if sc2.UnchangedOf != nil {
		t.Errorf("a genuinely different report must reprocess, got unchanged_of=%v", sc2.UnchangedOf)
	}
	list, err := findings.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil || len(list) != 2 {
		t.Fatalf("findings = %d (%v), want 2 (both CVEs persist)", len(list), err)
	}
}

// A,B,A: the third upload must compare against the latest completed scan (B),
// not any earlier one — so repeating the *first* report's content after a
// different second report reprocesses rather than skipping.
func TestSkipUnchangedABAReprocessesThird(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su3','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	scanA, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1))
	if err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	scanB, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV2))
	if err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	if scanB.UnchangedOf != nil {
		t.Fatalf("B differs from A, must not be unchanged")
	}
	scanC, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1))
	if err != nil {
		t.Fatalf("ingest C (repeats A): %v", err)
	}
	if scanC.UnchangedOf != nil {
		t.Errorf("C repeats A's content but the latest completed scan is B (different): must reprocess, got unchanged_of=%v", scanC.UnchangedOf)
	}
	_ = scanA
}

// A scan only vouches for its own target (project version + asset) — the same
// scoping CloseMissing uses. A report that matches content-wise but targets a
// different branch or asset must never be treated as unchanged.
func TestSkipUnchangedScopedToTarget(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su4','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	var assetID string
	if err := pool.QueryRow(ctx, `INSERT INTO assets (project_id, type, name) VALUES ($1, 'host', 'asset-x') RETURNING id`,
		projectID).Scan(&assetID); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	// Default branch, no asset.
	scanMain, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1))
	if err != nil {
		t.Fatalf("ingest main: %v", err)
	}

	// Same content on a different branch: a different target, must not be unchanged.
	scanFeature, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", Branch: "feature/x", CloseMissing: true},
		strings.NewReader(skipReportV1SameButStamped))
	if err != nil {
		t.Fatalf("ingest feature branch: %v", err)
	}
	if scanFeature.UnchangedOf != nil {
		t.Errorf("a different branch must never short-circuit against another target, got unchanged_of=%v", scanFeature.UnchangedOf)
	}

	// Same content, same branch, but a different asset: also a different target.
	scanAsset, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", AssetID: assetID, CloseMissing: true},
		strings.NewReader(skipReportV1SameButStamped))
	if err != nil {
		t.Fatalf("ingest asset scan: %v", err)
	}
	if scanAsset.UnchangedOf != nil {
		t.Errorf("a different asset must never short-circuit against another target, got unchanged_of=%v", scanAsset.UnchangedOf)
	}
	_ = scanMain

	// Repeating the asset-scoped content for the SAME target (same branch, same
	// asset) does short-circuit.
	scanAsset2, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", AssetID: assetID, CloseMissing: true},
		strings.NewReader(skipReportV1))
	if err != nil {
		t.Fatalf("ingest asset scan 2: %v", err)
	}
	if scanAsset2.UnchangedOf == nil || *scanAsset2.UnchangedOf != scanAsset.ID {
		t.Errorf("repeating the same asset target's content: unchanged_of = %v, want %s", scanAsset2.UnchangedOf, scanAsset.ID)
	}
}

// force=true always processes in full, even when the content hash matches.
func TestSkipUnchangedForceReprocesses(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su5','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	if _, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1)); err != nil {
		t.Fatalf("ingest 1: %v", err)
	}
	sc2, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true, Force: true},
		strings.NewReader(skipReportV1SameButStamped))
	if err != nil {
		t.Fatalf("ingest 2 (forced): %v", err)
	}
	if sc2.UnchangedOf != nil {
		t.Errorf("force=true must bypass skip-unchanged, got unchanged_of=%v", sc2.UnchangedOf)
	}
	if sc2.ContentHash == nil {
		t.Error("a forced (fully processed) scan should still record its content hash for the next upload")
	}
}

// The async path (Enqueue + a worker's ProcessJob) gets the same treatment.
func TestSkipUnchangedAsyncPath(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, scanRepo).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su6','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	runAsync := func(report string) scan.Scan {
		t.Helper()
		sc, err := svc.Enqueue(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true}, []byte(report))
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		job, err := scanRepo.ClaimJob(ctx, 5*time.Minute)
		if err != nil || job == nil {
			t.Fatalf("claim: job=%v err=%v", job, err)
		}
		if err := svc.ProcessJob(ctx, *job); err != nil {
			t.Fatalf("process: %v", err)
		}
		if err := scanRepo.CompleteJob(ctx, job.ID); err != nil {
			t.Fatalf("complete: %v", err)
		}
		got, err := scanRepo.Get(ctx, sc.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return got
	}

	scanA := runAsync(skipReportV1)
	if scanA.UnchangedOf != nil {
		t.Fatalf("first async scan must not be unchanged")
	}
	scanB := runAsync(skipReportV1SameButStamped)
	if scanB.UnchangedOf == nil || *scanB.UnchangedOf != scanA.ID {
		t.Errorf("async repeat: unchanged_of = %v, want %s", scanB.UnchangedOf, scanA.ID)
	}
	if scanB.Status != domain.ScanCompleted {
		t.Errorf("async skipped scan status = %q, want completed", scanB.Status)
	}
}

// A scan that only carried findings forward (skipped) must not break the NEXT
// different scan's auto-close: CloseMissing keys off last_scan_id's asset, and
// carrying forward moves that pointer onto the skipped scan.
func TestSkipUnchangedLaterScanStillAutoCloses(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	svc := scan.NewService(scanRepo, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).
		WithSkipUnchanged(true)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su7','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	if _, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1)); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	scanB, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(skipReportV1SameButStamped))
	if err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	if scanB.UnchangedOf == nil {
		t.Fatalf("B should have been skipped")
	}

	// C reports nothing: the scanner's complete current view is now empty, so
	// the live finding (last reported by the skipped scan B) must auto-close.
	if _, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true},
		strings.NewReader(`{"Results":[]}`)); err != nil {
		t.Fatalf("ingest C: %v", err)
	}

	list, err := findings.List(ctx, finding.Filter{ProjectID: projectID, AllVersions: true})
	if err != nil || len(list) != 1 {
		t.Fatalf("findings = %d (%v), want 1", len(list), err)
	}
	if list[0].Status != domain.FindingRemediated {
		t.Errorf("finding status = %q, want remediated after the scan following a skipped one reports nothing", list[0].Status)
	}
}

// A finding someone closed by hand, still in the identical next report, must
// reopen as the full pipeline would: a manual change after the previous scan
// rules out the skip. Likewise a finding deleted meanwhile is re-created.
func TestSkipUnchangedNotAfterManualChange(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	svc := scan.NewService(scan.NewRepository(pool), findings, project.NewRepository(pool),
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil).WithSkipUnchanged(true)
	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-su-manual','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	ingest := func() scan.Scan {
		t.Helper()
		sc, err := svc.Ingest(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy", CloseMissing: true}, strings.NewReader(skipReportV1))
		if err != nil {
			t.Fatal(err)
		}
		return sc
	}
	ingest()
	if sc := ingest(); sc.UnchangedOf == nil {
		t.Fatal("identical second report was not skipped")
	}

	// Closed by hand after the last scan: the identical report reopens it.
	if _, err := pool.Exec(ctx, `UPDATE findings SET status = 'remediated' WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if sc := ingest(); sc.UnchangedOf != nil {
		t.Errorf("report after a manual close was skipped (unchanged_of %v)", *sc.UnchangedOf)
	}
	list, err := findings.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil || len(list) != 1 || list[0].Status != domain.FindingOpen {
		t.Fatalf("after the re-scan: %v %v, want one open finding", list, err)
	}

	// Settled again, so the next identical report skips...
	if sc := ingest(); sc.UnchangedOf == nil {
		t.Error("identical report after the reopen was not skipped")
	}
	// ...unless a finding vanished meanwhile: then it is re-created.
	if _, err := pool.Exec(ctx, `DELETE FROM findings WHERE project_id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	if sc := ingest(); sc.UnchangedOf != nil {
		t.Error("report after a deletion was skipped")
	}
	if list, _ := findings.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 1 {
		t.Errorf("deleted finding not re-created: %d findings", len(list))
	}
}
