package sbom_test

import (
	"bytes"
	"context"
	"os"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

func TestIngestResolvesLicensesAndFilters(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sbom.NewRepository(pool)
	svc := sbom.NewService(repo, project.NewRepository(pool), nil, nil).WithLicenses(license.Resolve)
	projectID := seedProject(t, pool, "lic")

	data, err := os.ReadFile("testdata/licenses-maven.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	hits, err := repo.ListComponents(ctx, sbom.ComponentFilter{SbomID: snap.ID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]sbom.ComponentHit{}
	for _, h := range hits {
		byName[h.Name] = h
		if h.LicenseResolved == nil {
			t.Errorf("%s: license_resolved not computed on ingest", h.Name)
		}
	}
	rs := byName["javax.ws.rs-api"]
	if rs.LicenseExpression != "CDDL-1.1 AND GPL-2.0-with-classpath-exception" ||
		!slices.Equal(rs.LicenseIDs, []string{"CDDL-1.1", "GPL-2.0-with-classpath-exception"}) ||
		!slices.Equal(rs.LicenseCategories, []string{license.CategoryCopyleftLimited}) ||
		!*rs.LicenseResolved || rs.License != "CDDL-1.1, GPL-2.0-with-classpath-exception" {
		t.Errorf("javax.ws.rs-api = %q %v %v %v (raw %q)", rs.LicenseExpression, rs.LicenseIDs,
			rs.LicenseCategories, *rs.LicenseResolved, rs.License)
	}
	if bc := byName["bcprov-jdk15on"]; bc.LicenseExpression != "" || *bc.LicenseResolved || bc.LicenseIDs == nil {
		t.Errorf("bcprov = %q %v %v", bc.LicenseExpression, *bc.LicenseResolved, bc.LicenseIDs)
	}

	names := func(f sbom.ComponentFilter) []string {
		t.Helper()
		f.SbomID = snap.ID
		f.Limit = 100
		hits, err := repo.ListComponents(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, h := range hits {
			out = append(out, h.Name)
		}
		return out
	}
	// ?license= matches a resolved id, any case — including the known id of an
	// otherwise unresolved component (logback-core).
	if got := names(sbom.ComponentFilter{License: "epl-1.0"}); !slices.Equal(got, []string{"logback-core"}) {
		t.Errorf("license=epl-1.0 → %v", got)
	}
	if got := names(sbom.ComponentFilter{License: "Apache-2.0"}); !slices.Equal(got, []string{"jackson-annotations", "jboss-dmr"}) {
		t.Errorf("license=Apache-2.0 → %v", got)
	}
	if got := names(sbom.ComponentFilter{LicenseCategory: "public domain"}); !slices.Equal(got, []string{"reactive-streams"}) {
		t.Errorf("license_category=public domain → %v", got)
	}
	// A component with several licenses matches each of their categories, an
	// unresolved one by its known ids (checker-compat-qual's MIT).
	if got := names(sbom.ComponentFilter{LicenseCategory: license.CategoryPermissive}); !slices.Equal(got,
		[]string{"antlr", "checker-compat-qual", "jackson-annotations", "jboss-dmr"}) {
		t.Errorf("license_category=Permissive → %v", got)
	}
}

func TestBackfillLicenses(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sbom.NewRepository(pool)
	projectID := seedProject(t, pool, "legacy")

	// Rows stored the way they were before license resolution: raw column only
	// (no resolver on the path → license_resolved NULL).
	legacy := []sbom.Component{
		{Name: "a", License: "MIT"},
		{Name: "b", License: "MIT"},
		{Name: "c", License: "CDDL-1.1, GPL-2.0-with-classpath-exception"},
		{Name: "d", License: "Apache License, Version 2.0"},
		{Name: "e", License: "Bouncy Castle Licence"},
		{Name: "f", License: ""},
	}
	if _, err := repo.Ingest(ctx, sbom.Sbom{ProjectID: projectID, Artifact: "old", Format: "CycloneDX"}, legacy, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A component resolved on ingest must not be touched by the backfill.
	fresh := []sbom.Component{{Name: "g", License: "MIT", LicenseExpression: "MIT", LicenseIDs: []string{"MIT"},
		LicenseCategories: []string{"Permissive"}, LicenseResolved: new(true)}}
	if _, err := repo.Ingest(ctx, sbom.Sbom{ProjectID: projectID, Artifact: "new", Format: "CycloneDX"}, fresh, nil, nil); err != nil {
		t.Fatal(err)
	}
	calls := 0
	resolve := func(terms []string) (string, []string, []string, bool) {
		calls++
		return license.Resolve(terms)
	}

	n, err := repo.BackfillLicenses(ctx, resolve)
	if err != nil || n != len(legacy) {
		t.Fatalf("backfill = %d, %v; want %d", n, err, len(legacy))
	}
	hits, err := repo.ListComponents(ctx, sbom.ComponentFilter{ProjectID: projectID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		expr     string
		resolved bool
	}{
		"a": {"MIT", true}, "b": {"MIT", true},
		"c": {"CDDL-1.1 AND GPL-2.0-with-classpath-exception", true},
		"d": {"Apache-2.0", true}, // the comma is part of the name, not a separator
		"e": {"", false}, "f": {"", false}, "g": {"MIT", true},
	}
	for _, h := range hits {
		w := want[h.Name]
		if h.LicenseResolved == nil || h.LicenseExpression != w.expr || *h.LicenseResolved != w.resolved {
			t.Errorf("%s: %q resolved=%v, want %q %v", h.Name, h.LicenseExpression, h.LicenseResolved, w.expr, w.resolved)
		}
	}

	// Idempotent: nothing left, nothing resolved, nothing rewritten.
	calls = 0
	if n, err := repo.BackfillLicenses(ctx, resolve); err != nil || n != 0 || calls != 0 {
		t.Errorf("re-run = %d rows, %d resolver calls, %v; want 0, 0", n, calls, err)
	}
}
