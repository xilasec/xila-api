package loadtest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/org"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/team"
	"github.com/xilasec/xila-api/internal/user"
)

// ProjectSpec is one seeded project: its id and how many findings it carries.
type ProjectSpec struct {
	ID        string
	VersionID string
	Findings  int
	Big       bool
}

// SeedResult is what Seed produced, for the CLI to report and for later
// commands (ingest-bench, http-bench) to target.
type SeedResult struct {
	AdminEmail      string
	AdminPassword   string
	Projects        []ProjectSpec
	TotalFindings   int
	TotalComponents int
	Elapsed         time.Duration
}

// Logf is a progress callback; nil is a valid no-op logger.
type Logf func(format string, args ...any)

// Seed builds the structural entities (orgs/teams/projects/admin user) through
// their own repositories, then bulk-loads findings and SBOM components.
// Idempotency: structural entities use slugs scoped to a fresh database (the
// harness is meant to run once against a disposable load DB); re-running
// against the same DB will fail on the first duplicate org slug.
func Seed(ctx context.Context, pool *pgxpool.Pool, cfg Config, logf Logf) (SeedResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	start := time.Now()

	// The harness creates an admin with a known password: only ever on a
	// fresh, disposable database, never on an instance someone uses.
	var hasUsers bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&hasUsers); err != nil {
		return SeedResult{}, fmt.Errorf("check target database: %w", err)
	}
	if hasUsers {
		return SeedResult{}, errors.New("refusing to seed: the database already has users — the load test seeds only a fresh, disposable database")
	}

	users := user.NewRepository(pool)
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.MinCost)
	if err != nil {
		return SeedResult{}, fmt.Errorf("hash admin password: %w", err)
	}
	if _, err := users.Create(ctx, cfg.AdminEmail, string(hash)); err != nil && !errors.Is(err, user.ErrDuplicate) {
		return SeedResult{}, fmt.Errorf("create admin: %w", err)
	}

	orgs := org.NewRepository(pool)
	teams := team.NewRepository(pool)
	projects := project.NewRepository(pool)

	// Plan project sizes, then round-robin them across every team as it's
	// created so big and small projects are spread across the portfolio
	// rather than piled onto the first team.
	sizes := make([]int, 0, cfg.TotalProjects())
	for range cfg.BigProjects {
		sizes = append(sizes, cfg.BigProjectFindings)
	}
	for range cfg.SmallProjects {
		sizes = append(sizes, cfg.SmallProjectFindings)
	}

	var teamIDs []string
	for o := range cfg.Orgs {
		organization, err := orgs.Create(ctx, fmt.Sprintf("lt-org-%03d", o), fmt.Sprintf("Load Org %d", o))
		if err != nil {
			return SeedResult{}, fmt.Errorf("create org %d: %w", o, err)
		}
		for t := range cfg.TeamsPerOrg {
			tm, err := teams.Create(ctx, organization.ID, fmt.Sprintf("lt-team-%03d-%03d", o, t), fmt.Sprintf("Load Team %d.%d", o, t), "")
			if err != nil {
				return SeedResult{}, fmt.Errorf("create team %d/%d: %w", o, t, err)
			}
			teamIDs = append(teamIDs, tm.ID)
		}
	}
	if len(teamIDs) == 0 {
		return SeedResult{}, errors.New("config seeds zero teams")
	}

	criticalities := []domain.Criticality{domain.CriticalityLow, domain.CriticalityMedium, domain.CriticalityMedium, domain.CriticalityHigh, domain.CriticalityCritical}
	specs := make([]ProjectSpec, len(sizes))
	for i, n := range sizes {
		teamID := teamIDs[i%len(teamIDs)]
		p, err := projects.Create(ctx, project.Project{
			TeamID:              teamID,
			Slug:                fmt.Sprintf("lt-proj-%05d", i),
			Name:                fmt.Sprintf("Load Project %05d", i),
			BusinessCriticality: criticalities[i%len(criticalities)],
			Tags:                []string{},
		})
		if err != nil {
			return SeedResult{}, fmt.Errorf("create project %d: %w", i, err)
		}
		var versionID string
		if err := pool.QueryRow(ctx, `SELECT project_version($1, NULL, NULL)`, p.ID).Scan(&versionID); err != nil {
			return SeedResult{}, fmt.Errorf("resolve default version for project %d: %w", i, err)
		}
		specs[i] = ProjectSpec{ID: p.ID, VersionID: versionID, Findings: n, Big: n == cfg.BigProjectFindings}
	}
	logf("seeded %d orgs, %d teams, %d projects", cfg.Orgs, len(teamIDs), len(specs))

	total := 0
	for i, spec := range specs {
		if err := seedProjectFindings(ctx, pool, spec, cfg.Scanners, cfg.BatchSize, uint64(i)); err != nil {
			return SeedResult{}, fmt.Errorf("seed findings for project %d: %w", i, err)
		}
		total += spec.Findings
		if (i+1)%50 == 0 || i == len(specs)-1 {
			logf("findings: %d/%d projects seeded, %d findings so far", i+1, len(specs), total)
		}
	}

	comps := sbom.NewRepository(pool)
	totalComponents := 0
	for i, spec := range specs {
		n, err := seedProjectComponents(ctx, comps, spec, cfg.ComponentsPerProject, uint64(i))
		if err != nil {
			return SeedResult{}, fmt.Errorf("seed components for project %d: %w", i, err)
		}
		totalComponents += n
	}
	logf("components: %d seeded across %d projects", totalComponents, len(specs))

	return SeedResult{
		AdminEmail:      cfg.AdminEmail,
		AdminPassword:   cfg.AdminPassword,
		Projects:        specs,
		TotalFindings:   total,
		TotalComponents: totalComponents,
		Elapsed:         time.Since(start),
	}, nil
}

// seedProjectFindings bulk-loads one project's findings via COPY, chunked so
// a 100k-finding project doesn't build one enormous in-memory batch. cvePool
// is sized to the project so big projects still get real cross-tool overlap
// density rather than every row being its own group.
func seedProjectFindings(ctx context.Context, pool *pgxpool.Pool, spec ProjectSpec, scanners []string, batch int, seed uint64) error {
	cvePool := max(spec.Findings/4, 50)
	for start := 0; start < spec.Findings; start += batch {
		n := min(batch, spec.Findings-start)
		rows := findingRows(spec.ID, spec.VersionID, n, cvePool, scanners, seed*1_000_000+uint64(start))
		if _, err := pool.CopyFrom(ctx, pgx.Identifier{"findings"}, findingColumns, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("copy findings [%d:%d): %w", start, start+n, err)
		}
	}
	return nil
}

// seedProjectComponents seeds one SBOM snapshot of n components through the
// real sbom.Repository.Ingest (itself COPY-backed), with enough shared
// package names across projects that the global /components search has real
// row counts to match.
func seedProjectComponents(ctx context.Context, repo *sbom.Repository, spec ProjectSpec, n int, seed uint64) (int, error) {
	if n <= 0 {
		return 0, nil
	}
	components := make([]sbom.Component, n)
	for i := range n {
		idx := (int(seed%50_000)*131 + i) % 50_000
		direct := i%3 != 0
		depth := i % 5
		components[i] = sbom.Component{
			BomRef:  fmt.Sprintf("comp-%d", i),
			Type:    "library",
			Name:    fmt.Sprintf("pkg-%07d", idx),
			Version: fmt.Sprintf("1.%d.%d", idx%20, i%10),
			Purl:    fmt.Sprintf("pkg:generic/pkg-%07d@1.%d.%d", idx, idx%20, i%10),
			License: licenseFor(i),
			Direct:  &direct,
			Depth:   &depth,
			Scope:   depScopePool[i%len(depScopePool)],
		}
	}
	_, err := repo.Ingest(ctx, sbom.Sbom{
		ProjectID: spec.ID,
		Artifact:  "app",
		Version:   "1.0.0",
		Format:    "cyclonedx",
		Source:    "loadtest",
	}, components, nil, nil)
	if err != nil {
		return 0, err
	}
	return n, nil
}

var licensePool = []string{"MIT", "Apache-2.0", "BSD-3-Clause", "GPL-3.0-only", "ISC"}

func licenseFor(i int) string { return licensePool[i%len(licensePool)] }
