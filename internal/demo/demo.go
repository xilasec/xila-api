// Package demo seeds a demo org/team/project and ingests real sample scanner
// and SBOM reports through the production scan and SBOM services, so a fresh
// instance has a populated project (findings, dedup, priority, compliance
// posture, SBOM views) to explore within minutes — the "first finding in 5
// minutes" onboarding path. Driven by the `xila-api demo-seed` subcommand.
//
// Seed is idempotent: it looks its org/team/project up by a fixed slug before
// creating them, and skips re-ingesting a project that already has scans. The
// sample reports are copies of real fixtures also used by internal/scanner and
// internal/sbom's own tests (trivy_image.json, semgrep.json,
// licenses-maven.cdx.json) — kept here, rather than read from those packages'
// testdata, because Go's //go:embed cannot reach outside this package's
// directory tree.
package demo

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/org"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/team"
	"github.com/xilasec/xila-api/internal/user"
)

//go:embed testdata
var fixturesFS embed.FS

func fixture(name string) []byte {
	b, err := fixturesFS.ReadFile("testdata/" + name)
	if err != nil {
		// Embedded at build time; a missing file is a programming error, not a
		// runtime condition callers can handle.
		panic(fmt.Sprintf("demo: embedded fixture %q missing: %v", name, err))
	}
	return b
}

// Identity of the seeded demo tenant. Fixed so repeated runs are idempotent:
// Seed looks these up by slug before creating them.
const (
	OrgSlug     = "demo"
	OrgName     = "Demo Org"
	TeamSlug    = "demo"
	TeamName    = "Demo Team"
	ProjectSlug = "juice-shop"
	ProjectName = "Demo App"

	// AdminEmail is the login Seed bootstraps when the instance has no users
	// yet. It never overwrites or logs in as an existing account.
	AdminEmail = "admin@demo.local"
)

// mainBranch and featureBranch are the two project_versions Seed's scans
// create (the first a project uses becomes its default version).
const (
	mainBranch    = "main"
	featureBranch = "feature/login-fix"
)

// ErrProductionRefused is returned by CheckEnvironment when seeding demo data
// into a production instance was not explicitly requested.
var ErrProductionRefused = errors.New("refusing to seed demo data in production (APP_ENV=production); pass --force to override")

// CheckEnvironment refuses to seed a production instance — demo org/team/
// project/findings are plausible enough to be mistaken for real tenant data —
// unless the caller explicitly overrides it.
func CheckEnvironment(isProduction, force bool) error {
	if isProduction && !force {
		return ErrProductionRefused
	}
	return nil
}

// Deps are the repositories and services Seed drives. Scan and Sbom are the
// same *scan.Service / *sbom.Service construction the API server uses for
// real uploads, so seeded data goes through the real fingerprinting, dedup
// and priority pipeline.
type Deps struct {
	Users    *user.Repository
	Orgs     *org.Repository
	Teams    *team.Repository
	Projects *project.Repository
	Scans    *scan.Repository
	Scan     *scan.Service
	Sbom     *sbom.Service
}

// Result reports what Seed did or found already done, for the CLI to print.
type Result struct {
	OrgID, TeamID, ProjectID string
	// Ingested is true only when this call just ran the sample scans/SBOM
	// through the pipeline (false on a repeat call against an already-seeded
	// project).
	Ingested bool
	// AdminEmail/AdminPassword are set only when Seed just bootstrapped the
	// instance's first (owner) account; empty on every later call.
	AdminEmail, AdminPassword string
}

// Seed idempotently creates the demo org/team/project with two branches and,
// the first time, ingests sample scanner + SBOM reports through the real
// pipeline. Safe to call repeatedly.
func Seed(ctx context.Context, d Deps) (Result, error) {
	var res Result

	o, err := getOrCreateOrg(ctx, d.Orgs)
	if err != nil {
		return res, fmt.Errorf("demo org: %w", err)
	}
	res.OrgID = o.ID

	t, err := getOrCreateTeam(ctx, d.Teams, o.ID)
	if err != nil {
		return res, fmt.Errorf("demo team: %w", err)
	}
	res.TeamID = t.ID

	p, isNewProject, err := getOrCreateProject(ctx, d.Projects, t.ID)
	if err != nil {
		return res, fmt.Errorf("demo project: %w", err)
	}
	res.ProjectID = p.ID

	needsIngest := isNewProject
	if !needsIngest {
		existing, err := d.Scans.List(ctx, p.ID, false)
		if err != nil {
			return res, fmt.Errorf("list existing demo scans: %w", err)
		}
		needsIngest = len(existing) == 0
	}

	if needsIngest {
		if err := ingestSamples(ctx, d, p.ID); err != nil {
			return res, err
		}
		res.Ingested = true
	}

	hasUsers, err := d.Users.HasUsers(ctx)
	if err != nil {
		return res, fmt.Errorf("check existing users: %w", err)
	}
	if !hasUsers {
		email, password, err := bootstrapAdmin(ctx, d.Users)
		if err != nil {
			return res, err
		}
		res.AdminEmail, res.AdminPassword = email, password
	}

	return res, nil
}

// ingestSamples runs the bundled sample reports through the real scan and SBOM
// services: a container-image SCA scan on main, a SAST scan on a feature
// branch (so the two branches exist independently, per CLAUDE's branch
// model), and a CycloneDX SBOM on main.
func ingestSamples(ctx context.Context, d Deps, projectID string) error {
	if _, err := d.Scan.Ingest(ctx, scan.IngestRequest{
		ProjectID: projectID, Scanner: "trivy", Branch: mainBranch, CloseMissing: true,
	}, bytes.NewReader(fixture("trivy_image.json"))); err != nil {
		return fmt.Errorf("seed trivy scan: %w", err)
	}
	if _, err := d.Scan.Ingest(ctx, scan.IngestRequest{
		ProjectID: projectID, Scanner: "semgrep", Branch: featureBranch, CloseMissing: true,
	}, bytes.NewReader(fixture("semgrep.json"))); err != nil {
		return fmt.Errorf("seed semgrep scan: %w", err)
	}
	if _, err := d.Sbom.Ingest(ctx, sbom.IngestRequest{
		ProjectID: projectID, Branch: mainBranch,
	}, bytes.NewReader(fixture("licenses-maven.cdx.json"))); err != nil {
		return fmt.Errorf("seed sbom: %w", err)
	}
	return nil
}

func getOrCreateOrg(ctx context.Context, repo *org.Repository) (org.Organization, error) {
	o, err := repo.Create(ctx, OrgSlug, OrgName)
	if errors.Is(err, org.ErrDuplicate) {
		return repo.GetBySlug(ctx, OrgSlug)
	}
	return o, err
}

func getOrCreateTeam(ctx context.Context, repo *team.Repository, orgID string) (team.Team, error) {
	t, err := repo.Create(ctx, orgID, TeamSlug, TeamName, "Seeded by `xila-api demo-seed`.")
	if errors.Is(err, team.ErrDuplicate) {
		return repo.GetBySlug(ctx, orgID, TeamSlug)
	}
	return t, err
}

// getOrCreateProject returns the demo project and whether it was just created.
func getOrCreateProject(ctx context.Context, repo *project.Repository, teamID string) (project.Project, bool, error) {
	p, err := repo.Create(ctx, project.Project{
		TeamID:              teamID,
		Slug:                ProjectSlug,
		Name:                ProjectName,
		Description:         "Seeded by `xila-api demo-seed` — safe to delete.",
		BusinessCriticality: domain.CriticalityMedium,
		Tags:                []string{},
	})
	if errors.Is(err, project.ErrDuplicate) {
		existing, gerr := repo.GetBySlug(ctx, teamID, ProjectSlug)
		return existing, false, gerr
	}
	return p, err == nil, err
}

// bootstrapAdmin creates the instance's first user (which becomes owner+admin
// on an empty instance, per user.Repository.Create) with a freshly generated
// password, returned once for the caller to print.
func bootstrapAdmin(ctx context.Context, repo *user.Repository) (email, password string, err error) {
	password, err = randomPassword()
	if err != nil {
		return "", "", fmt.Errorf("generate demo admin password: %w", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hash demo admin password: %w", err)
	}
	if _, err := repo.Create(ctx, AdminEmail, string(hash)); err != nil {
		return "", "", fmt.Errorf("create demo admin: %w", err)
	}
	return AdminEmail, password, nil
}

// randomPassword generates a 24-character URL-safe random password.
func randomPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
