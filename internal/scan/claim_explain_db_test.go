package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/pgtest"
)

// explainNode is the subset of Postgres's EXPLAIN (FORMAT JSON) plan node
// shape this test cares about.
type explainNode struct {
	NodeType        string        `json:"Node Type"`
	RelationName    string        `json:"Relation Name"`
	ActualTotalTime float64       `json:"Actual Total Time"`
	Plans           []explainNode `json:"Plans"`
}

func (n explainNode) walk(f func(explainNode)) {
	f(n)
	for _, p := range n.Plans {
		p.walk(f)
	}
}

// TestClaimQueryScalesToDeepQueue seeds 100,000 pending jobs spread across 100
// projects in 20 orgs — the realistic shape of a deep multi-tenant backlog —
// and EXPLAINs the real fair claim (fairClaimSQL). Its cost is one index
// probe per org with pending work plus orgLookahead rows per org, never the
// depth of the queue: the plan must use indexes, not a sequential scan of all
// 100,000 rows, and run in a few milliseconds.
func TestClaimQueryScalesToDeepQueue(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()

	const (
		orgs           = 20
		projectsPerOrg = 5
		totalJobs      = 100_000
	)

	type seeded struct{ orgID, projectID string }
	targets := make([]seeded, 0, orgs*projectsPerOrg)
	for i := range orgs {
		var orgID, teamID string
		if err := pool.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id`,
			fmt.Sprintf("o-explain-%d", i)).Scan(&orgID); err != nil {
			t.Fatalf("seed org: %v", err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO teams (org_id, slug, name) VALUES ($1, $2, $2) RETURNING id`,
			orgID, fmt.Sprintf("t-explain-%d", i)).Scan(&teamID); err != nil {
			t.Fatalf("seed team: %v", err)
		}
		for j := range projectsPerOrg {
			var projectID string
			if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1, $2, $2) RETURNING id`,
				teamID, fmt.Sprintf("p-explain-%d-%d", i, j)).Scan(&projectID); err != nil {
				t.Fatalf("seed project: %v", err)
			}
			targets = append(targets, seeded{orgID, projectID})
		}
	}

	// Bulk-insert the scans the jobs will reference, round-robin across every
	// seeded project.
	scanRows := make([][]any, totalJobs)
	for i := range scanRows {
		scanRows[i] = []any{targets[i%len(targets)].projectID, "trivy", "sca"}
	}
	if _, err := pool.CopyFrom(ctx, pgx.Identifier{"scans"}, []string{"project_id", "scanner", "category"},
		pgx.CopyFromRows(scanRows)); err != nil {
		t.Fatalf("seed scans: %v", err)
	}

	projectToOrg := make(map[string]string, len(targets))
	for _, s := range targets {
		projectToOrg[s.projectID] = s.orgID
	}
	rows, err := pool.Query(ctx, `SELECT id, project_id FROM scans ORDER BY created_at`)
	if err != nil {
		t.Fatalf("read back scans: %v", err)
	}
	jobRows := make([][]any, 0, totalJobs)
	for rows.Next() {
		var scanID, projectID string
		if err := rows.Scan(&scanID, &projectID); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		jobRows = append(jobRows, []any{scanID, []byte("{}"), projectID, projectToOrg[projectID]})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read back scans: %v", err)
	}
	if _, err := pool.CopyFrom(ctx, pgx.Identifier{"scan_jobs"}, []string{"scan_id", "payload", "project_id", "org_id"},
		pgx.CopyFromRows(jobRows)); err != nil {
		t.Fatalf("seed scan_jobs: %v", err)
	}

	if _, err := pool.Exec(ctx, `ANALYZE scan_jobs`); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	var plan []struct {
		Plan explainNode `json:"Plan"`
	}
	explainRows, err := pool.Query(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+fairClaimSQL, orgLookahead)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	var raw string
	for explainRows.Next() {
		if err := explainRows.Scan(&raw); err != nil {
			t.Fatalf("scan explain row: %v", err)
		}
	}
	explainRows.Close()
	if err := explainRows.Err(); err != nil {
		t.Fatalf("explain rows: %v", err)
	}
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		t.Fatalf("parse explain json: %v\n%s", err, raw)
	}
	if len(plan) != 1 {
		t.Fatalf("explain plan = %d entries, want 1", len(plan))
	}

	var seqScannedScanJobs bool
	var totalTime float64
	plan[0].Plan.walk(func(n explainNode) {
		if n.RelationName == "scan_jobs" && strings.Contains(n.NodeType, "Seq Scan") {
			seqScannedScanJobs = true
		}
		totalTime = plan[0].Plan.ActualTotalTime
	})
	if seqScannedScanJobs {
		t.Error("claim query sequentially scanned scan_jobs with 100,000 pending rows; it must reach them through indexes")
	}
	// Generous bound: one probe per org (20) and orgLookahead rows each, plus a
	// handful of NOT EXISTS / org_load lookups, not the 100,000-row backlog.
	// On a dev machine this runs in low single-digit milliseconds; 500ms is a
	// wide margin for a loaded CI runner while still catching an accidental
	// full-table scan (which would be seconds at this size).
	const maxMillis = 500
	if totalTime > maxMillis {
		t.Errorf("claim query took %.2fms against 100,000 pending rows, want < %dms (see docs/SCALE.md)", totalTime, maxMillis)
	}
	t.Logf("claim query against %d pending rows in %d orgs: %.3fms", totalJobs, orgs, totalTime)

	// Sanity: the query still actually claims a real job (the plan wasn't
	// trivially empty).
	job, err := NewRepository(pool).ClaimJob(ctx, 5*time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim after seeding = %v, err %v", job, err)
	}
}
