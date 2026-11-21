package component_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/component"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func TestComponentPatternCRUD(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := component.NewRepository(pool)

	p := component.Pattern{Ecosystem: "npm", GroupPattern: "@acme/*", PatternType: component.PatternGlob}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	created, err := repo.Create(ctx, p, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected an id")
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("expected one pattern, got %+v", list)
	}

	got, err := repo.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.GroupPattern != "@acme/*" {
		t.Errorf("group pattern = %q", got.GroupPattern)
	}

	created.NamePattern = "widgets-*"
	updated, err := repo.Update(ctx, created)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.NamePattern != "widgets-*" {
		t.Errorf("name pattern = %q", updated.NamePattern)
	}

	if err := repo.Delete(ctx, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.Get(ctx, created.ID); err != component.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestComponentPatternRecompute(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := component.NewRepository(pool)

	var projectID, sbomID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-cp','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO sboms (project_id, artifact, version) VALUES ($1,'web','1') RETURNING id`,
		projectID).Scan(&sbomID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO sbom_components (sbom_id, project_id, "group", name, version, purl)
		VALUES ($1,$2,'@acme','widgets','1.0.0','pkg:npm/%40acme/widgets@1.0.0'),
		       ($1,$2,'@other','lib','1.0.0','pkg:npm/%40other/lib@1.0.0')`,
		sbomID, projectID); err != nil {
		t.Fatal(err)
	}

	match := func(eco, group, name string) bool { return eco == "npm" && group == "@acme" }
	n, err := repo.Recompute(ctx, match)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row changed, got %d", n)
	}

	var acmeInternal, otherInternal bool
	if err := pool.QueryRow(ctx, `SELECT internal FROM sbom_components WHERE "group" = '@acme'`).Scan(&acmeInternal); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT internal FROM sbom_components WHERE "group" = '@other'`).Scan(&otherInternal); err != nil {
		t.Fatal(err)
	}
	if !acmeInternal {
		t.Error("expected @acme/widgets to be internal")
	}
	if otherInternal {
		t.Error("expected @other/lib to stay external")
	}

	// A second recompute with the same matcher changes nothing.
	n, err = repo.Recompute(ctx, match)
	if err != nil {
		t.Fatalf("recompute again: %v", err)
	}
	if n != 0 {
		t.Errorf("expected a no-op recompute, got %d rows changed", n)
	}
}
