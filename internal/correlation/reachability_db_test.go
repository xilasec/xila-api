package correlation_test

import (
	"context"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/correlation"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

// The SBOM says: express is a direct runtime dependency, ms is buried three
// levels down, and jest never ships. All three have a critical CVE.
const bom = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "metadata": {"component": {"bom-ref": "app", "name": "web", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "e", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
    {"bom-ref": "b", "name": "body-parser", "version": "1.20.1", "purl": "pkg:npm/body-parser@1.20.1"},
    {"bom-ref": "m", "name": "ms", "version": "2.1.3", "purl": "pkg:npm/ms@2.1.3"},
    {"bom-ref": "j", "name": "jest", "version": "29.0.0", "purl": "pkg:npm/jest@29.0.0", "scope": "excluded"}
  ],
  "dependencies": [
    {"ref": "app", "dependsOn": ["e", "j"]},
    {"ref": "e", "dependsOn": ["b"]},
    {"ref": "b", "dependsOn": ["m"]}
  ]
}`

// TestReachabilityRanksTheBacklog is the whole feature in one test: three
// identical critical vulnerabilities, ranked by whether they can actually hurt
// you — using nothing but the dependency graph the SBOM already carried.
func TestReachabilityRanksTheBacklog(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	sbomRepo := sbom.NewRepository(pool)
	projectRepo := project.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-re','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	reacher := correlation.NewReacher(findingRepo, findingRepo)
	sbomSvc := sbom.NewService(sbomRepo, projectRepo, nil, reacher)

	seed := func(pkg, version, purl string) finding.Finding {
		f, err := findingRepo.Upsert(ctx, finding.Finding{
			ProjectID: projectID, Fingerprint: "fp-" + pkg, Scanner: "trivy",
			Category: domain.CategorySCA, RuleID: "CVE-2024-0001", Title: "RCE in " + pkg,
			Severity: domain.SeverityCritical, CVE: []string{"CVE-2024-0001"},
			PackageName: pkg, PackageVersion: version, Purl: purl,
		})
		if err != nil {
			t.Fatalf("seed %s: %v", pkg, err)
		}
		return f
	}
	express := seed("express", "4.18.2", "pkg:npm/express@4.18.2")
	ms := seed("ms", "2.1.3", "pkg:npm/ms@2.1.3")
	jest := seed("jest", "29.0.0", "pkg:npm/jest@29.0.0")

	// Before the SBOM lands, all three look identical: critical, priority 15.
	for _, f := range []finding.Finding{express, ms, jest} {
		if f.Priority != 15 || f.DepDirect != nil || f.DepScope != domain.DepScopeUnknown {
			t.Fatalf("precondition: %s should start at priority 15 with no reachability, got %+v",
				f.PackageName, f)
		}
	}

	// Uploading the SBOM re-scores the existing backlog.
	if _, err := sbomSvc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(bom)); err != nil {
		t.Fatalf("ingest sbom: %v", err)
	}

	got := func(f finding.Finding) finding.Finding {
		out, err := findingRepo.Get(ctx, f.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		return out
	}
	gotExpress, gotMs, gotJest := got(express), got(ms), got(jest)

	// The one you'd actually fix: a direct dependency that ships. Undiscounted.
	if gotExpress.Priority != 15 || gotExpress.DepDirect == nil || !*gotExpress.DepDirect {
		t.Errorf("express (direct, ships) = priority %v direct %v, want 15 / true",
			gotExpress.Priority, gotExpress.DepDirect)
	}
	// Buried three levels deep in the transitive tree: discounted.
	if gotMs.Priority != 12 || *gotMs.DepDepth != 3 || *gotMs.DepDirect {
		t.Errorf("ms (transitive, depth 3) = priority %v depth %v, want 12 / 3",
			gotMs.Priority, gotMs.DepDepth)
	}
	// Test-only: it never reaches production. 15 × 0.25 = 3.75.
	if gotJest.Priority != 3.75 || gotJest.DepScope != domain.DepScopeDev {
		t.Errorf("jest (dev-only) = priority %v scope %q, want 3.75 / dev",
			gotJest.Priority, gotJest.DepScope)
	}

	// And the backlog is now filterable down to what matters.
	reachable, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID, ReachableOnly: true})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(reachable) != 1 || reachable[0].PackageName != "express" {
		names := make([]string, len(reachable))
		for i, f := range reachable {
			names[i] = f.PackageName
		}
		t.Errorf("reachable backlog = %v, want just [express]", names)
	}

	// Re-running is free: nothing changed, so nothing is written.
	if n, err := reacher.ApplyToProject(ctx, projectID); err != nil || n != 0 {
		t.Errorf("re-apply wrote %d rows (err %v), want 0 — reachability must be idempotent", n, err)
	}
}
