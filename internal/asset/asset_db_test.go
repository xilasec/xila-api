package asset_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/asset"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func seedProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var teamID, projectID string
	if err := pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-as','o') RETURNING id) INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id`).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1,'p','p') RETURNING id`, teamID).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

func TestAssetCRUDAndConstraints(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := asset.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	a, err := repo.Create(ctx, asset.Asset{
		ProjectID:  projectID,
		Type:       domain.AssetContainerImage,
		Name:       "web:1.0",
		Identifier: "registry/web@sha256:abc",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.ID == "" || a.Metadata == nil {
		t.Errorf("asset not initialized: %+v", a)
	}

	// Same (project, type, identifier) -> duplicate.
	_, err = repo.Create(ctx, asset.Asset{
		ProjectID: projectID, Type: domain.AssetContainerImage, Name: "dupe", Identifier: "registry/web@sha256:abc",
	})
	if err != asset.ErrDuplicate {
		t.Errorf("duplicate err = %v, want ErrDuplicate", err)
	}

	// Unknown project -> ErrNoProject.
	_, err = repo.Create(ctx, asset.Asset{
		ProjectID: "00000000-0000-0000-0000-000000000000", Type: domain.AssetHost, Name: "h",
	})
	if err != asset.ErrNoProject {
		t.Errorf("no-project err = %v, want ErrNoProject", err)
	}

	// Filter by type.
	hosts, err := repo.List(ctx, asset.Filter{ProjectID: projectID, Type: domain.AssetHost})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("host assets = %d, want 0", len(hosts))
	}
	images, _ := repo.List(ctx, asset.Filter{ProjectID: projectID, Type: domain.AssetContainerImage})
	if len(images) != 1 {
		t.Errorf("image assets = %d, want 1", len(images))
	}

	name := "web:2.0"
	updated, err := repo.Update(ctx, a.ID, &name, nil)
	if err != nil || updated.Name != "web:2.0" {
		t.Errorf("update = %+v, %v", updated, err)
	}

	if err := repo.Delete(ctx, a.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := repo.Delete(ctx, a.ID); err != asset.ErrNotFound {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

func TestDeletingAssetNullsFindingReference(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := asset.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	a, err := repo.Create(ctx, asset.Asset{ProjectID: projectID, Type: domain.AssetHost, Name: "h1", Identifier: "host-1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// A finding attributed to the asset.
	if _, err := pool.Exec(ctx,
		`INSERT INTO findings (project_id, asset_id, fingerprint, scanner, category, title, severity)
		 VALUES ($1, $2, 'fp-1', 'trivy', 'sca', 'v', 'high')`, projectID, a.ID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	// Deleting the asset must preserve the finding, nulling its asset_id.
	if err := repo.Delete(ctx, a.ID); err != nil {
		t.Fatalf("delete asset: %v", err)
	}
	var count int
	var assetID *string
	if err := pool.QueryRow(ctx, `SELECT count(*), max(asset_id::text) FROM findings WHERE fingerprint='fp-1'`).Scan(&count, &assetID); err != nil {
		t.Fatalf("query finding: %v", err)
	}
	if count != 1 || assetID != nil {
		t.Errorf("finding count=%d asset_id=%v, want 1 / nil", count, assetID)
	}
}

// Blast-radius traversal follows built_from backwards and deployed_as forwards,
// keeps each asset's shallowest depth, ignores depends_on and survives cycles.
func TestDownstreamTraversal(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := asset.NewRepository(pool)
	ctx := context.Background()
	pid := seedProject(t, pool)
	mk := func(name string) string {
		t.Helper()
		a, err := repo.Create(ctx, asset.Asset{ProjectID: pid, Type: domain.AssetContainerImage, Name: name, Identifier: name})
		if err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	base, mid, app, wl, db := mk("base"), mk("mid"), mk("app"), mk("workload"), mk("db")
	link := func(from, to string, kind asset.RelationKind) {
		t.Helper()
		if _, err := repo.CreateRelation(ctx, asset.Relation{FromAssetID: from, ToAssetID: to, Kind: kind}); err != nil {
			t.Fatalf("relate: %v", err)
		}
	}
	link(mid, base, asset.BuiltFrom)
	link(app, mid, asset.BuiltFrom)
	link(app, base, asset.BuiltFrom) // a shortcut: app is depth 1, not 2
	link(app, wl, asset.DeployedAs)
	link(app, db, asset.DependsOn)   // informational, not inherited
	link(base, app, asset.BuiltFrom) // a (wrong) cycle back to the root

	down, err := repo.Downstream(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]asset.Downstream{}
	for _, d := range down {
		got[d.Asset.ID] = d
	}
	if len(got) != 3 || got[app].Depth != 1 || got[mid].Depth != 1 || got[wl].Depth != 2 || got[wl].Via != asset.DeployedAs {
		t.Errorf("downstream of base = %+v, want app/mid at 1, workload at 2 via deployed_as, no db, no base", down)
	}

	if _, err := repo.CreateRelation(ctx, asset.Relation{FromAssetID: app, ToAssetID: app, Kind: asset.BuiltFrom}); err != asset.ErrSelfRelation {
		t.Errorf("self relation err = %v", err)
	}
	if err := repo.Delete(ctx, mid); err != nil {
		t.Fatal(err)
	}
	if rels, _ := repo.ListRelations(ctx, base); len(rels) != 2 { // mid's edge cascaded away
		t.Errorf("relations after deleting an asset = %+v", rels)
	}
}

// Base-image inference reads OS packages (deb/apk/rpm purls) from the newest
// default-version SBOM whose artifact names each image.
func TestOSPackageOverlap(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := asset.NewRepository(pool)
	ctx := context.Background()
	pid := seedProject(t, pool)
	image := func(name string, debs int, extra ...string) string {
		t.Helper()
		a, err := repo.Create(ctx, asset.Asset{ProjectID: pid, Type: domain.AssetContainerImage, Name: name, Identifier: "reg/" + name})
		if err != nil {
			t.Fatal(err)
		}
		var sbomID string
		if err := pool.QueryRow(ctx, `INSERT INTO sboms (project_id, artifact) VALUES ($1, $2) RETURNING id`, pid, "reg/"+name).Scan(&sbomID); err != nil {
			t.Fatal(err)
		}
		purls := extra
		for i := range debs {
			purls = append(purls, fmt.Sprintf("pkg:deb/debian/lib%d@1.%d?distro=debian-12", i, i))
		}
		for _, p := range purls {
			if _, err := pool.Exec(ctx, `INSERT INTO sbom_components (sbom_id, project_id, name, purl) VALUES ($1, $2, $3, $3)`, sbomID, pid, p); err != nil {
				t.Fatal(err)
			}
		}
		return a.ID
	}
	base := image("debian", 8)
	app := image("app", 12, "pkg:npm/left-pad@1.0.0") // the base's 8 debs + 4 more; npm doesn't count
	other := image("alpine", 0, "pkg:apk/alpine/musl@1.2", "pkg:apk/alpine/busybox@1.36")

	mine, overlaps, err := repo.OSPackageOverlap(ctx, app, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mine != 12 || len(overlaps) != 1 || overlaps[0] != (asset.Overlap{AssetID: base, Total: 8, Shared: 8}) {
		t.Fatalf("overlap = %d %+v, want 12 and the base 8/8 (alpine %s shares nothing)", mine, overlaps, other)
	}
	if p := asset.ProposeBuiltFrom(mine, overlaps); len(p) != 1 || !p[0].Base || p[0].Other.AssetID != base {
		t.Errorf("proposals = %+v, want app built_from debian", p)
	}
	// Out of scope: a caller who sees no other project gets nothing to compare.
	if _, overlaps, _ := repo.OSPackageOverlap(ctx, app, false, []string{}); len(overlaps) != 0 {
		t.Errorf("scoped overlap = %+v, want none", overlaps)
	}
}

// Risk per asset: the same weighted formula as the project risk score
// (severity weight x count, scaled by the project's business criticality),
// scoped to the asset's own open, non-duplicate, default-version findings.
func TestAttachRisk(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := asset.NewRepository(pool)
	ctx := context.Background()
	pid := seedProject(t, pool) // default business_criticality = 'medium', multiplier 1.5

	a1, err := repo.Create(ctx, asset.Asset{ProjectID: pid, Type: domain.AssetHost, Name: "h1", Identifier: "host-1"})
	if err != nil {
		t.Fatalf("create a1: %v", err)
	}
	a2, err := repo.Create(ctx, asset.Asset{ProjectID: pid, Type: domain.AssetHost, Name: "h2", Identifier: "host-2"})
	if err != nil {
		t.Fatalf("create a2: %v", err)
	}

	insert := func(assetID, fingerprint, severity, status string) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO findings (project_id, asset_id, fingerprint, scanner, category, title, severity, status)
			 VALUES ($1, $2, $3, 'trivy', 'sca', 'v', $4, $5) RETURNING id`,
			pid, assetID, fingerprint, severity, status).Scan(&id); err != nil {
			t.Fatalf("insert finding %s: %v", fingerprint, err)
		}
		return id
	}
	// a1: 2 open high + 1 open critical count; a false positive and a
	// duplicate of one of them must not.
	insert(a1.ID, "fp-1", "high", "open")
	fp2 := insert(a1.ID, "fp-2", "high", "open")
	insert(a1.ID, "fp-3", "critical", "confirmed")
	insert(a1.ID, "fp-4", "critical", "false_positive")
	dupID := insert(a1.ID, "fp-5", "high", "open")
	if _, err := pool.Exec(ctx, `UPDATE findings SET duplicate_of = $1 WHERE id = $2`, fp2, dupID); err != nil {
		t.Fatalf("mark duplicate: %v", err)
	}
	// a2: a single open low.
	insert(a2.ID, "fp-6", "low", "open")

	assets, err := repo.List(ctx, asset.Filter{ProjectID: pid})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	assets, err = repo.AttachRisk(ctx, assets)
	if err != nil {
		t.Fatalf("attach risk: %v", err)
	}
	byID := map[string]asset.Asset{}
	for _, a := range assets {
		byID[a.ID] = a
	}

	got1 := byID[a1.ID]
	if got1.TotalOpen != 3 {
		t.Errorf("a1 total_open = %d, want 3", got1.TotalOpen)
	}
	if got1.OpenBySeverity[domain.SeverityHigh] != 2 || got1.OpenBySeverity[domain.SeverityCritical] != 1 {
		t.Errorf("a1 open_by_severity = %+v, want high:2 critical:1", got1.OpenBySeverity)
	}
	// (7*2 + 15*1) * 1.5 = 43.5
	if got1.RiskScore != 43.5 {
		t.Errorf("a1 risk_score = %v, want 43.5", got1.RiskScore)
	}

	got2 := byID[a2.ID]
	if got2.TotalOpen != 1 || got2.OpenBySeverity[domain.SeverityLow] != 1 {
		t.Errorf("a2 totals = %d / %+v, want 1 / low:1", got2.TotalOpen, got2.OpenBySeverity)
	}
	// 1*1.5 = 1.5
	if got2.RiskScore != 1.5 {
		t.Errorf("a2 risk_score = %v, want 1.5", got2.RiskScore)
	}

	if got1.RiskScore <= got2.RiskScore {
		t.Errorf("a1 risk %v should outrank a2 risk %v (?sort=risk ordering)", got1.RiskScore, got2.RiskScore)
	}
}
