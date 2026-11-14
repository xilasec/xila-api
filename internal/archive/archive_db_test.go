package archive_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/retention"
)

// The same CVE in the same package from two tools is one correlation group:
// an archived finding is never its primary, and the gate doesn't count it.
func TestArchivedFindingLeavesGateAndDedup(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)
	arch := archive.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-a','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	add := func(scanner string, sev domain.Severity) finding.Finding {
		f, err := frepo.Upsert(ctx, finding.Finding{
			ProjectID: projectID, Fingerprint: scanner + "-fp", Scanner: scanner, Category: domain.CategorySCA,
			RuleID: "CVE-2024-1", Title: "boom", Severity: sev, CVE: []string{"CVE-2024-1"}, PackageName: "lib",
		})
		if err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		return f
	}
	trivy := add("trivy", domain.SeverityCritical) // higher priority: elected primary
	grype := add("grype", domain.SeverityHigh)
	if _, err := frepo.Deduplicate(ctx, projectID); err != nil {
		t.Fatal(err)
	}
	dupOf := func(id string) *string {
		f, err := frepo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return f.DuplicateOf
	}
	if d := dupOf(grype.ID); d == nil || *d != trivy.ID {
		t.Fatalf("before archiving, grype duplicate_of = %v, want trivy %s", d, trivy.ID)
	}

	if _, err := arch.Archive(ctx, archive.KindFinding, trivy.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := frepo.Deduplicate(ctx, projectID); err != nil {
		t.Fatal(err)
	}
	if d := dupOf(grype.ID); d != nil {
		t.Errorf("grype still a duplicate of %s after its primary was archived", *d)
	}
	if d := dupOf(trivy.ID); d != nil {
		t.Errorf("archived trivy finding points at %s", *d)
	}
	stats, err := frepo.ComputeGateStats(ctx, projectID, "", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.OpenCritical != 0 || stats.OpenHigh != 1 {
		t.Errorf("gate stats = %d critical / %d high, want 0 / 1 (the archived critical is out)", stats.OpenCritical, stats.OpenHigh)
	}

	// Archiving the project takes the remaining finding with it, through the
	// project alone; restoring the project brings it back.
	if _, err := arch.Archive(ctx, archive.KindProject, projectID, ""); err != nil {
		t.Fatal(err)
	}
	if stats, _ := frepo.ComputeGateStats(ctx, projectID, "", false, ""); stats.OpenHigh != 0 {
		t.Errorf("archived project's gate counts %d high", stats.OpenHigh)
	}
	var written int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE archived_at IS NOT NULL`).Scan(&written); err != nil || written != 1 {
		t.Errorf("finding rows stamped by the project archive = %d (want only the one archived itself), %v", written, err)
	}
	if _, err := arch.Restore(ctx, archive.KindProject, projectID, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if stats, _ := frepo.ComputeGateStats(ctx, projectID, "", false, ""); stats.OpenHigh != 1 {
		t.Errorf("restored project's gate counts %d high, want 1", stats.OpenHigh)
	}
	if _, err := arch.Restore(ctx, archive.KindProject, projectID, 0); !errors.Is(err, archive.ErrNotArchived) {
		t.Errorf("restoring a live project = %v, want ErrNotArchived", err)
	}
}

// Archiving a scan archives the findings only it reported; restoring brings
// them back; the retention job purges only what is past the window.
func TestScanArchiveAndPurge(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)
	arch := archive.NewRepository(pool)

	var projectID, scanA, scanB string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-s','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []*string{&scanA, &scanB} {
		if err := pool.QueryRow(ctx, `INSERT INTO scans (project_id, scanner, category, status) VALUES ($1, 'trivy', 'sca', 'completed') RETURNING id`,
			projectID).Scan(id); err != nil {
			t.Fatal(err)
		}
	}
	up := func(fp, first, last string) string {
		f, err := frepo.Upsert(ctx, finding.Finding{ProjectID: projectID, Fingerprint: fp, Scanner: "trivy",
			Category: domain.CategorySCA, Title: fp, Severity: domain.SeverityHigh, LastScanID: &first})
		if err != nil {
			t.Fatal(err)
		}
		if last != first {
			if _, err := pool.Exec(ctx, `UPDATE findings SET last_scan_id = $2 WHERE id = $1`, f.ID, last); err != nil {
				t.Fatal(err)
			}
		}
		return f.ID
	}
	onlyB := up("only-b", scanB, scanB) // reported by scan B alone
	both := up("both", scanA, scanB)    // first reported by A, last by B

	if _, err := arch.Archive(ctx, archive.KindScan, scanB, ""); err != nil {
		t.Fatal(err)
	}
	archived := func(id string) bool {
		f, err := frepo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return f.ArchivedAt != nil
	}
	if !archived(onlyB) || archived(both) {
		t.Errorf("after archiving scan B: only-b archived=%v (want true), both archived=%v (want false: scan A still reports it)",
			archived(onlyB), archived(both))
	}
	if _, err := arch.Restore(ctx, archive.KindScan, scanB, time.Hour); err != nil {
		t.Fatal(err)
	}
	if archived(onlyB) {
		t.Error("restoring scan B left its finding archived")
	}

	// Purge: scan B archived 40 days ago (past a 30-day window), scan A 10 days ago.
	if _, err := arch.Archive(ctx, archive.KindScan, scanB, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := arch.Archive(ctx, archive.KindScan, scanA, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET archived_at = now() - CASE WHEN id = $1 THEN interval '40 days' ELSE interval '10 days' END`, scanB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE findings SET archived_at = now() - interval '40 days' WHERE id = $1`, onlyB); err != nil {
		t.Fatal(err)
	}
	if _, err := arch.Restore(ctx, archive.KindScan, scanB, 30*24*time.Hour); !errors.Is(err, archive.ErrExpired) {
		t.Errorf("restore past the window = %v, want ErrExpired", err)
	}
	svc := retention.NewService(pool, nil, retention.Policy{ArchiveAge: 30 * 24 * time.Hour})
	res, err := svc.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.ArchivedScans != 1 || res.ArchivedFindings != 1 {
		t.Errorf("purged %d scans / %d findings, want 1 / 1", res.ArchivedScans, res.ArchivedFindings)
	}
	var scans, findings int
	_ = pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM scans), (SELECT count(*) FROM findings)`).Scan(&scans, &findings)
	if scans != 1 || findings != 1 {
		t.Errorf("left %d scans / %d findings, want scan A and the finding it reported", scans, findings)
	}
	if _, err := frepo.Get(ctx, onlyB); !errors.Is(err, finding.ErrNotFound) {
		t.Errorf("purged finding still readable: %v", err)
	}
}
