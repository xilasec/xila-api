package finding_test

// Benchmarks for the hot paths of ingestion: UpsertBatch (every scan upload),
// CloseMissing (auto-remediation on every ingest), DeduplicateScan vs the full
// Deduplicate (cross-tool grouping — scoped on every ingest, full on backfills),
// and List with the filter shapes the UI's findings page and gates actually use.
// Gated on TEST_DATABASE_URL like the rest of this package's DB tests (pgtest.Pool
// skips without it). Run with:
//
//	TEST_DATABASE_URL=... go test ./internal/finding/ -run '^$' -bench . -benchtime=3x
//
// Measured numbers at dataset scale (not just these small benchmark fixtures)
// live in docs/SCALE.md.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// benchSeq makes every benchmark's seeded org/team/project slug unique across
// sub-benchmarks sharing one pool (b.Loop's internal re-runs for calibration
// call the Benchmark function more than once).
var benchSeq int

// seedProjectB is seedProject, callable from a benchmark (testing.TB).
func seedProjectB(b testing.TB, pool *pgxpool.Pool) string {
	b.Helper()
	benchSeq++
	ctx := context.Background()
	var teamID string
	slug := fmt.Sprintf("o-bench-%d", benchSeq)
	if err := pool.QueryRow(ctx,
		`WITH o AS (INSERT INTO organizations (slug, name) VALUES ($1,'o') RETURNING id)
		 INSERT INTO teams (org_id, slug, name) SELECT id, 't', 'Team' FROM o RETURNING id`,
		slug).Scan(&teamID); err != nil {
		b.Fatalf("seed team: %v", err)
	}
	var projectID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name) VALUES ($1, 'p', 'Project') RETURNING id`,
		teamID).Scan(&projectID); err != nil {
		b.Fatalf("seed project: %v", err)
	}
	return projectID
}

func seedScanB(b testing.TB, pool *pgxpool.Pool, projectID, scanner string) string {
	b.Helper()
	var scanID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scans (project_id, scanner, category, status) VALUES ($1, $2, 'sca', 'completed') RETURNING id`,
		projectID, scanner).Scan(&scanID); err != nil {
		b.Fatalf("seed scan: %v", err)
	}
	return scanID
}

var benchScanners = []string{"trivy", "grype", "osv"}

// genFindings builds n findings against cvePoolSize distinct CVE+package
// identities, round-robined across scanners so ~1/len(scanners) of them
// collide on (cve, package) across tools — exactly the shape Deduplicate
// groups. seed selects a disjoint fingerprint/package range so repeated calls
// (one per benchmark iteration) never collide with earlier ones.
func genFindings(projectID string, n, cvePoolSize, seed int) []finding.Finding {
	rnd := rand.New(rand.NewPCG(uint64(seed), uint64(seed)^0x9E3779B97F4A7C15))
	sevs := []domain.Severity{domain.SeverityLow, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityCritical}
	fs := make([]finding.Finding, n)
	for i := range n {
		pkgIdx := rnd.IntN(cvePoolSize)
		scanner := benchScanners[i%len(benchScanners)]
		cve := fmt.Sprintf("CVE-2024-%06d", pkgIdx)
		pkg := fmt.Sprintf("pkg-%06d", pkgIdx)
		fs[i] = finding.Finding{
			ProjectID:   projectID,
			Fingerprint: fmt.Sprintf("seed-%d-%s-%d", seed, scanner, i),
			Scanner:     scanner,
			Category:    domain.CategorySCA,
			RuleID:      cve,
			Title:       "Vulnerable dependency " + pkg,
			Severity:    sevs[rnd.IntN(len(sevs))],
			CVE:         []string{cve},
			PackageName: pkg,
			Metadata:    map[string]any{},
		}
	}
	return fs
}

// BenchmarkUpsertBatch measures the ingestion write path: pipelined batched
// upserts of a scan's findings (500/chunk, see Repository.UpsertBatch).
func BenchmarkUpsertBatch(b *testing.B) {
	pool := pgtest.Pool(b)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProjectB(b, pool)
	const batch = 1000
	i := 0
	for b.Loop() {
		i++
		fs := genFindings(projectID, batch, batch*10, i)
		if err := repo.UpsertBatch(ctx, fs, ""); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(batch*b.N)/b.Elapsed().Seconds(), "findings/sec")
}

// BenchmarkCloseMissing measures auto-close: a scan's findings from the
// previous run that the new scan no longer reports. Setup (seeding the
// closeable findings and the two scan rows) is excluded from the timer.
func BenchmarkCloseMissing(b *testing.B) {
	pool := pgtest.Pool(b)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProjectB(b, pool)
	const n = 500
	i := 0
	for b.Loop() {
		b.StopTimer()
		i++
		prevScan := seedScanB(b, pool, projectID, "trivy")
		fs := genFindings(projectID, n, n*10, 1_000_000+i)
		for j := range fs {
			fs[j].LastScanID = &prevScan
		}
		if err := repo.UpsertBatch(ctx, fs, ""); err != nil {
			b.Fatal(err)
		}
		curScan := seedScanB(b, pool, projectID, "trivy")
		b.StartTimer()
		if _, err := repo.CloseMissing(ctx, projectID, "trivy", curScan); err != nil {
			b.Fatal(err)
		}
	}
}

// seedDedupBacklog seeds a steady-state backlog of n findings (cross-tool CVE
// overlap already settled by one full Deduplicate) — the shape a mature
// project accumulates over many scans.
func seedDedupBacklog(b testing.TB, ctx context.Context, repo *finding.Repository, projectID string, n int) {
	b.Helper()
	fs := genFindings(projectID, n, n/4, 0)
	if err := repo.UpsertBatch(ctx, fs, ""); err != nil {
		b.Fatalf("seed backlog: %v", err)
	}
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		b.Fatalf("settle backlog: %v", err)
	}
}

// BenchmarkDeduplicateScan measures the ingest-path dedup: scoped to the
// groups one new scan could have disturbed, independent of backlog size.
func BenchmarkDeduplicateScan(b *testing.B) {
	pool := pgtest.Pool(b)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProjectB(b, pool)
	const backlog = 20000
	seedDedupBacklog(b, ctx, repo, projectID, backlog)

	i := 0
	for b.Loop() {
		b.StopTimer()
		i++
		scanID := seedScanB(b, pool, projectID, "trivy")
		fs := genFindings(projectID, 200, backlog/4, 2_000_000+i)
		for j := range fs {
			fs[j].LastScanID = &scanID
		}
		if err := repo.UpsertBatch(ctx, fs, ""); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		if _, err := repo.DeduplicateScan(ctx, projectID, scanID, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDeduplicateFull measures the backfill path: a full project
// recompute, which scans the whole backlog regardless of how little changed —
// the cost DeduplicateScan exists to avoid on every ingest.
func BenchmarkDeduplicateFull(b *testing.B) {
	pool := pgtest.Pool(b)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProjectB(b, pool)
	const backlog = 20000
	seedDedupBacklog(b, ctx, repo, projectID, backlog)

	for b.Loop() {
		if _, err := repo.Deduplicate(ctx, projectID); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkList measures the filter shapes the findings page, gates and
// exports actually issue, over a mixed-severity/status backlog.
func BenchmarkList(b *testing.B) {
	pool := pgtest.Pool(b)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProjectB(b, pool)
	const n = 20000
	fs := genFindings(projectID, n, n/4, 0)
	for i := range fs {
		if i%7 == 0 {
			fs[i].Status = domain.FindingRemediated
		}
	}
	if err := repo.UpsertBatch(ctx, fs, ""); err != nil {
		b.Fatalf("seed list dataset: %v", err)
	}
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		b.Fatalf("settle list dataset: %v", err)
	}

	cases := []struct {
		name string
		f    finding.Filter
	}{
		{"default", finding.Filter{ProjectID: projectID}},
		{"priority-sort-active", finding.Filter{ProjectID: projectID, OpenOnly: true, Sort: "priority"}},
		{"severity-scanner", finding.Filter{ProjectID: projectID, Severity: domain.SeverityCritical, Scanner: "trivy"}},
		{"search", finding.Filter{ProjectID: projectID, Query: "pkg-000123"}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := repo.List(ctx, tc.f); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
