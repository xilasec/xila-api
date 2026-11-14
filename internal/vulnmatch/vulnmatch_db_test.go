package vulnmatch_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/vulnmatch"
)

// stubSource returns whatever advisories the test wants for a PURL.
type stubSource struct{ byPurl map[string][]vulnmatch.Vuln }

func (s *stubSource) Query(_ context.Context, _ []string) (map[string][]vulnmatch.Vuln, error) {
	return s.byPurl, nil
}

// TestSBOMStaysAlive is the whole promise: an SBOM uploaded once keeps producing
// current risk. A newly-disclosed advisory becomes a finding with no re-scan, and
// once the dependency is upgraded the finding auto-resolves.
func TestSBOMStaysAlive(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	sbomRepo := sbom.NewRepository(pool)
	findingRepo := finding.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	ingest := scan.NewService(scanRepo, findingRepo, projectRepo,
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, scanRepo)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-vm','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// An SBOM uploaded a while ago (e.g. by Syft), shipping a vulnerable log4j.
	const purl = "pkg:maven/log4j-core@2.14.1"
	var sbomID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO sboms (project_id, artifact, version) VALUES ($1,'web','1.0') RETURNING id`,
		projectID).Scan(&sbomID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sbom_components (sbom_id, project_id, name, version, purl) VALUES ($1,$2,'log4j-core','2.14.1',$3)`,
		sbomID, projectID, purl); err != nil {
		t.Fatalf("seed component: %v", err)
	}

	// --- A new advisory drops for a package we already have. No re-scan happens. ---
	src := &stubSource{byPurl: map[string][]vulnmatch.Vuln{
		purl: {{ID: "GHSA-jfh8", Summary: "Log4Shell", Severity: domain.SeverityCritical,
			CVEs: []string{"CVE-2021-44228"}, Fixed: "2.15.0"}},
	}}
	svc := vulnmatch.NewService(sbomRepo, ingest, src)

	n, err := svc.Match(ctx)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if n != 1 {
		t.Fatalf("recorded %d findings, want 1", n)
	}

	list, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("findings = %d, want 1", len(list))
	}
	f := list[0]
	if f.Scanner != "osv" || f.Status != domain.FindingOpen || f.Severity != domain.SeverityCritical {
		t.Errorf("finding = scanner %q status %q sev %q, want osv/open/critical", f.Scanner, f.Status, f.Severity)
	}
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2021-44228" || f.PackageName != "log4j-core" {
		t.Errorf("finding not linked to the CVE/package: %+v", f)
	}

	// --- Running again is idempotent (upsert, not duplicate). ---
	if _, err := svc.Match(ctx); err != nil {
		t.Fatalf("re-match: %v", err)
	}
	if again, _ := findingRepo.List(ctx, finding.Filter{ProjectID: projectID}); len(again) != 1 {
		t.Fatalf("after re-match findings = %d, want still 1 (idempotent)", len(again))
	}

	// --- The team upgrades log4j: the advisory no longer matches. The finding
	// must auto-resolve without anyone touching it. ---
	src.byPurl = map[string][]vulnmatch.Vuln{} // nothing affected anymore
	if _, err := svc.Match(ctx); err != nil {
		t.Fatalf("match after upgrade: %v", err)
	}
	resolved, err := findingRepo.Get(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resolved.Status != domain.FindingRemediated {
		t.Errorf("status = %q, want remediated (auto-closed once no longer affected)", resolved.Status)
	}
}
