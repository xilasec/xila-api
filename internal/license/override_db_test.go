package license_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

func seedLOProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	ctx := context.Background()
	var teamID string
	if err := pool.QueryRow(ctx,
		`WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o-'||$1, $1) RETURNING id) INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id`, "team-"+slug).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	var projectID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name) VALUES ($1, $2, $2) RETURNING id`, teamID, slug).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

// cycloneDXWithLicense is a minimal CycloneDX document naming one component's
// license, small enough to inline rather than reaching for a fixture.
func cycloneDXWithLicense(name, version, lic string) []byte {
	return []byte(`{
		"bomFormat": "CycloneDX", "specVersion": "1.5",
		"metadata": {"component": {"type": "application", "name": "app", "version": "1.0"}},
		"components": [{"type": "library", "name": "` + name + `", "version": "` + version + `",
			"purl": "pkg:npm/` + name + `@` + version + `",
			"licenses": [{"license": {"id": "` + lic + `"}}]}]
	}`)
}

// A curated override replaces a component's SBOM-declared license at
// ingest, keeps the declared value visible, and re-applies itself to a
// project's current snapshots (and re-runs component policies) the instant
// it is created, changed, or deleted, without a new upload.
func TestLicenseOverrideAppliesAtIngestAndReapply(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	projectRepo := project.NewRepository(pool)
	projectID := seedLOProject(t, pool, "lo1")

	overrideRepo := license.NewOverrideRepository(pool)
	loadMatcher := func(ctx context.Context) (*license.Matcher, error) {
		all, err := overrideRepo.ListAll(ctx)
		if err != nil {
			return nil, err
		}
		return license.NewMatcher(all, sbom.CompareVersions), nil
	}

	sbomRepo := sbom.NewRepository(pool)
	svc := sbom.NewService(sbomRepo, projectRepo, nil, nil).
		WithLicenses(license.Resolve).
		WithLicenseOverrides(func(ctx context.Context) (sbom.LicenseOverrideMatcher, error) { return loadMatcher(ctx) })

	// No override yet: the declared license (GPL-3.0-only) is what's stored.
	snap, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, bytes.NewReader(cycloneDXWithLicense("leftpad", "1.0.0", "GPL-3.0-only")))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	hits, err := sbomRepo.ListComponents(ctx, sbom.ComponentFilter{SbomID: snap.ID, Limit: 10})
	if err != nil || len(hits) != 1 {
		t.Fatalf("list components: %v %d", err, len(hits))
	}
	if hits[0].LicenseExpression != "GPL-3.0-only" || hits[0].LicenseOverrideID != nil {
		t.Fatalf("before override: expression=%q overrideID=%v", hits[0].LicenseExpression, hits[0].LicenseOverrideID)
	}

	// Curate a concluded license for this package, and reapply WITHOUT a new
	// upload: the existing (only) current snapshot's component must update
	// in place, keeping the SBOM's own declared value visible separately.
	ov, err := overrideRepo.Create(ctx, projectID, license.OverrideInput{Purl: "pkg:npm/leftpad", License: "MIT", Comment: "vendor confirmed re-license"}, "")
	if err != nil {
		t.Fatalf("create override: %v", err)
	}
	n, err := sbomRepo.ReapplyLicenseOverrides(ctx, projectID, sbom.LicenseResolver(license.Resolve), mustMatcher(t, ctx, loadMatcher))
	if err != nil {
		t.Fatalf("reapply: %v", err)
	}
	if n != 1 {
		t.Fatalf("reapply changed %d rows, want 1", n)
	}
	reapplied, err := sbomRepo.ListComponents(ctx, sbom.ComponentFilter{SbomID: snap.ID, Limit: 10})
	if err != nil || len(reapplied) != 1 {
		t.Fatalf("list after reapply: %v %d", err, len(reapplied))
	}
	r := reapplied[0]
	if r.LicenseExpression != "MIT" || r.LicenseDeclaredExpression != "GPL-3.0-only" || r.LicenseOverrideID == nil || *r.LicenseOverrideID != ov.ID {
		t.Fatalf("after reapply: expr=%q declared=%q overrideID=%v", r.LicenseExpression, r.LicenseDeclaredExpression, r.LicenseOverrideID)
	}

	// A later ingest of the SAME package (a new artifact, so a new current
	// snapshot) picks up the override straight at ingest time too.
	snap2, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, bytes.NewReader(bytes.ReplaceAll(cycloneDXWithLicense("leftpad", "1.0.1", "GPL-3.0-only"), []byte(`"app"`), []byte(`"app2"`))))
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	hits2, err := sbomRepo.ListComponents(ctx, sbom.ComponentFilter{SbomID: snap2.ID, Limit: 10})
	if err != nil || len(hits2) != 1 {
		t.Fatalf("list components 2: %v %d", err, len(hits2))
	}
	h2 := hits2[0]
	if h2.LicenseExpression != "MIT" || h2.LicenseDeclaredExpression != "GPL-3.0-only" || h2.LicenseOverrideID == nil {
		t.Fatalf("at ingest with an existing override: expr=%q declared=%q overrideID=%v", h2.LicenseExpression, h2.LicenseDeclaredExpression, h2.LicenseOverrideID)
	}

	// Removing the override and reapplying reverts both current snapshots
	// to their declared value.
	if err := overrideRepo.Delete(ctx, projectID, ov.ID); err != nil {
		t.Fatalf("delete override: %v", err)
	}
	if _, err := sbomRepo.ReapplyLicenseOverrides(ctx, projectID, sbom.LicenseResolver(license.Resolve), mustMatcher(t, ctx, loadMatcher)); err != nil {
		t.Fatalf("reapply after delete: %v", err)
	}
	for _, id := range []string{snap.ID, snap2.ID} {
		reverted, err := sbomRepo.ListComponents(ctx, sbom.ComponentFilter{SbomID: id, Limit: 10})
		if err != nil || len(reverted) != 1 {
			t.Fatalf("list after revert (%s): %v %d", id, err, len(reverted))
		}
		if g := reverted[0]; g.LicenseExpression != "GPL-3.0-only" || g.LicenseOverrideID != nil {
			t.Fatalf("after reverting the override (%s): expr=%q overrideID=%v", id, g.LicenseExpression, g.LicenseOverrideID)
		}
	}
}

func mustMatcher(t *testing.T, ctx context.Context, load func(context.Context) (*license.Matcher, error)) *license.Matcher {
	t.Helper()
	m, err := load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A version range scopes an override to the versions it names; a version
// outside the range keeps its declared license.
func TestLicenseOverrideVersionRange(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	projectID := seedLOProject(t, pool, "lo2")

	overrideRepo := license.NewOverrideRepository(pool)
	if _, err := overrideRepo.Create(ctx, projectID, license.OverrideInput{
		Purl: "pkg:npm/widget", VersionRange: ">=2.0.0", License: "Apache-2.0", Comment: "re-licensed in v2",
	}, ""); err != nil {
		t.Fatalf("create ranged override: %v", err)
	}
	all, err := overrideRepo.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m := license.NewMatcher(all, sbom.CompareVersions)

	if _, _, _, _, _, ok := m.MatchLicense(projectID, "pkg:npm/widget@1.9.0", "1.9.0"); ok {
		t.Error("1.9.0 matched a >=2.0.0 override")
	}
	expr, _, _, resolved, _, ok := m.MatchLicense(projectID, "pkg:npm/widget@2.0.0", "2.0.0")
	if !ok || expr != "Apache-2.0" || !resolved {
		t.Errorf("2.0.0 = %q %v %v, want Apache-2.0 resolved", expr, resolved, ok)
	}
}

// Validate rejects a malformed license expression and a malformed range,
// catching a mistake before it's stored and silently never matches anything.
func TestOverrideInputValidate(t *testing.T) {
	cases := []struct {
		name string
		in   license.OverrideInput
		ok   bool
	}{
		{"valid", license.OverrideInput{Purl: "pkg:npm/x", License: "MIT"}, true},
		{"valid with range", license.OverrideInput{Purl: "pkg:npm/x", License: "MIT OR Apache-2.0", VersionRange: ">=1.0.0, <2.0.0"}, true},
		{"empty purl", license.OverrideInput{License: "MIT"}, false},
		{"empty license", license.OverrideInput{Purl: "pkg:npm/x"}, false},
		{"bad license", license.OverrideInput{Purl: "pkg:npm/x", License: "Not A License(("}, false},
		{"bad range", license.OverrideInput{Purl: "pkg:npm/x", License: "MIT", VersionRange: "bogus"}, false},
		{"strips version from purl", license.OverrideInput{Purl: "pkg:npm/x@1.2.3", License: "MIT"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if (err == nil) != c.ok {
				t.Errorf("Validate() error = %v, want ok=%v", err, c.ok)
			}
		})
	}
	in := license.OverrideInput{Purl: "pkg:npm/x@1.2.3?a=b#sub", License: "MIT"}
	if err := in.Validate(); err != nil || in.Purl != "pkg:npm/x" {
		t.Errorf("BasePurl not stripped: purl=%q err=%v", in.Purl, err)
	}
}
