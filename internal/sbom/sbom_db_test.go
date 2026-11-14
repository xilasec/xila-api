package sbom_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/sbom"
)

func seedProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
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

func comp(name, version, purl string) sbom.Component {
	return sbom.Component{Type: "library", Name: name, Version: version, Purl: purl, Hashes: map[string]string{}}
}

func TestIngestAndHistory(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool, "web")

	first, err := repo.Ingest(ctx,
		sbom.Sbom{ProjectID: projectID, Artifact: "web", Version: "1.0.0", Format: "CycloneDX"},
		[]sbom.Component{comp("lodash", "4.17.15", "pkg:npm/lodash@4.17.15")}, nil, nil)
	if err != nil {
		t.Fatalf("ingest first: %v", err)
	}
	if first.ComponentCount != 1 {
		t.Errorf("component_count = %d, want 1", first.ComponentCount)
	}

	time.Sleep(5 * time.Millisecond) // guarantee a distinct created_at ordering

	if _, err := repo.Ingest(ctx,
		sbom.Sbom{ProjectID: projectID, Artifact: "web", Version: "1.1.0", Format: "CycloneDX"},
		[]sbom.Component{comp("lodash", "4.17.21", "pkg:npm/lodash@4.17.21"), comp("express", "4.18.2", "pkg:npm/express@4.18.2")}, nil, nil); err != nil {
		t.Fatalf("ingest second: %v", err)
	}

	// History keeps both snapshots, newest first.
	history, err := repo.ListByProject(ctx, projectID, "")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 2 || history[0].Version != "1.1.0" {
		t.Fatalf("history wrong: %+v", history)
	}

	// All lodash occurrences across history.
	all, err := repo.ListComponents(ctx, sbom.ComponentFilter{ProjectID: projectID, Name: "lodash"})
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("lodash occurrences = %d, want 2 (both snapshots)", len(all))
	}

	// Latest inventory only: the newest snapshot's lodash (4.17.21), not the old one.
	latest, err := repo.ListComponents(ctx, sbom.ComponentFilter{ProjectID: projectID, Name: "lodash", LatestOnly: true})
	if err != nil {
		t.Fatalf("list latest: %v", err)
	}
	if len(latest) != 1 || latest[0].Version != "4.17.21" {
		t.Errorf("latest lodash = %+v, want single 4.17.21", latest)
	}
}

func TestGlobalComponentSearchAcrossProjects(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	ctx := context.Background()

	projA := seedProject(t, pool, "svc-a")
	projB := seedProject(t, pool, "svc-b")

	vulnerable := comp("log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	for _, pid := range []string{projA, projB} {
		if _, err := repo.Ingest(ctx,
			sbom.Sbom{ProjectID: pid, Artifact: "app", Format: "CycloneDX"},
			[]sbom.Component{vulnerable, comp("guava", "31.0", "pkg:maven/com.google.guava/guava@31.0")}, nil, nil); err != nil {
			t.Fatalf("ingest: %v", err)
		}
	}

	// "Which projects contain log4j-core 2.14.1?" -> both, with project context.
	hits, err := repo.ListComponents(ctx, sbom.ComponentFilter{
		Name:    "log4j-core",
		Version: "2.14.1",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("global hits = %d, want 2", len(hits))
	}
	slugs := map[string]bool{}
	for _, h := range hits {
		slugs[h.ProjectSlug] = true
		if h.Purl == "" || h.ProjectName == "" {
			t.Errorf("hit missing context: %+v", h)
		}
	}
	if !slugs["svc-a"] || !slugs["svc-b"] {
		t.Errorf("expected both projects, got %v", slugs)
	}

	// Substring search on the "filter by package" box.
	partial, err := repo.ListComponents(ctx, sbom.ComponentFilter{Search: "log4j"})
	if err != nil {
		t.Fatalf("substring search: %v", err)
	}
	if len(partial) != 2 {
		t.Errorf("substring hits = %d, want 2", len(partial))
	}
}
