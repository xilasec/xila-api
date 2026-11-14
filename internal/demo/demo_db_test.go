package demo_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/demo"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/org"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/team"
	"github.com/xilasec/xila-api/internal/user"
)

func newDemoDeps(pool *pgxpool.Pool) demo.Deps {
	scanRepo := scan.NewRepository(pool)
	findingRepo := finding.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	sbomRepo := sbom.NewRepository(pool)
	parsers := scanner.NewRegistry(scanner.NewTrivy(), scanner.NewSemgrep())
	return demo.Deps{
		Users:    user.NewRepository(pool),
		Orgs:     org.NewRepository(pool),
		Teams:    team.NewRepository(pool),
		Projects: projectRepo,
		Scans:    scanRepo,
		Scan:     scan.NewService(scanRepo, findingRepo, projectRepo, parsers, nil, nil, scanRepo),
		Sbom:     sbom.NewService(sbomRepo, projectRepo, nil, nil),
	}
}

func count(t *testing.T, pool *pgxpool.Pool, ctx context.Context, table, projectID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE project_id = $1`, projectID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestSeedIsIdempotent runs demo.Seed twice against a fresh database: the
// first run must create the project with findings and an SBOM through the
// real scan/SBOM pipeline and bootstrap the owner account; the second run
// must change nothing.
func TestSeedIsIdempotent(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	deps := newDemoDeps(pool)

	first, err := demo.Seed(ctx, deps)
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if first.ProjectID == "" {
		t.Fatal("first run: want a project id")
	}
	if !first.Ingested {
		t.Error("first run: want Ingested=true")
	}
	if first.AdminEmail == "" || first.AdminPassword == "" {
		t.Error("first run: want a bootstrapped admin login")
	}

	findingCount := count(t, pool, ctx, "findings", first.ProjectID)
	if findingCount == 0 {
		t.Error("want findings after seeding")
	}
	sbomCount := count(t, pool, ctx, "sboms", first.ProjectID)
	if sbomCount != 1 {
		t.Errorf("sbom count = %d, want 1", sbomCount)
	}
	versionCount := count(t, pool, ctx, "project_versions", first.ProjectID)
	if versionCount != 2 {
		t.Errorf("project_versions count = %d, want 2 (main + feature branch)", versionCount)
	}
	scanCount := count(t, pool, ctx, "scans", first.ProjectID)
	if scanCount != 2 {
		t.Errorf("scan count = %d, want 2 (trivy + semgrep)", scanCount)
	}

	// Running again must not duplicate anything.
	second, err := demo.Seed(ctx, deps)
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if second.ProjectID != first.ProjectID {
		t.Errorf("second run project id = %q, want %q (same demo project)", second.ProjectID, first.ProjectID)
	}
	if second.Ingested {
		t.Error("second run: want Ingested=false (already seeded)")
	}
	if second.AdminPassword != "" {
		t.Error("second run: want no new admin credential (instance already has a user)")
	}

	if got := count(t, pool, ctx, "findings", first.ProjectID); got != findingCount {
		t.Errorf("finding count after second run = %d, want unchanged %d", got, findingCount)
	}
	if got := count(t, pool, ctx, "sboms", first.ProjectID); got != sbomCount {
		t.Errorf("sbom count after second run = %d, want unchanged %d", got, sbomCount)
	}
	if got := count(t, pool, ctx, "scans", first.ProjectID); got != scanCount {
		t.Errorf("scan count after second run = %d, want unchanged %d", got, scanCount)
	}
}
