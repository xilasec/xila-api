package vulnmatch_test

import (
	"context"
	"errors"
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

// cpeStub answers purls and CPEs separately, the way MultiSource does with
// the nvd source configured.
type cpeStub struct {
	byPurl, byCPE map[string][]vulnmatch.Vuln
	cpeErr        error
	gotPurls      []string
	gotCPEs       []string
}

func (s *cpeStub) Query(_ context.Context, purls []string) (map[string][]vulnmatch.Vuln, error) {
	s.gotPurls = purls
	return s.byPurl, nil
}

func (s *cpeStub) QueryCPE(_ context.Context, cpes []string) (map[string][]vulnmatch.Vuln, error) {
	s.gotCPEs = cpes
	return s.byCPE, s.cpeErr
}

// A component no package ecosystem names — here a vendored OpenSSL known only
// by its CPE — gets the same lifecycle as a purl component: the CVE becomes a
// finding, the component reads as vulnerable, and a failed NVD lookup never
// closes it as "fixed".
func TestCPEOnlyComponentsAreMatched(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	sbomRepo := sbom.NewRepository(pool)
	findingRepo := finding.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	ingest := scan.NewService(scanRepo, findingRepo, project.NewRepository(pool),
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, scanRepo)

	var projectID, sbomID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-cpe','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'fw','fw' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO sboms (project_id, artifact, version) VALUES ($1,'firmware','4.2') RETURNING id`,
		projectID).Scan(&sbomID); err != nil {
		t.Fatal(err)
	}
	const (
		cpe  = "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
		purl = "pkg:npm/lodash@4.17.20"
	)
	// One CPE-only component, one with both (its purl wins — no double match).
	if _, err := pool.Exec(ctx, `INSERT INTO sbom_components (sbom_id, project_id, name, version, purl, cpe) VALUES
		($1,$2,'openssl','1.1.1k','',$3),
		($1,$2,'lodash','4.17.20',$4,'cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*')`,
		sbomID, projectID, cpe, purl); err != nil {
		t.Fatal(err)
	}

	src := &cpeStub{
		byPurl: map[string][]vulnmatch.Vuln{purl: {{ID: "GHSA-35jh", CVEs: []string{"CVE-2021-23337"}, Severity: domain.SeverityHigh}}},
		byCPE: map[string][]vulnmatch.Vuln{cpe: {{ID: "CVE-2021-3711", CVEs: []string{"CVE-2021-3711"}, Summary: "SM2 decryption overflow",
			Severity: domain.SeverityCritical, Fixed: "1.1.1l", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-3711", Sources: []string{"nvd"}}}},
	}
	svc := vulnmatch.NewService(sbomRepo, ingest, src)
	if n, err := svc.Match(ctx); err != nil || n != 2 {
		t.Fatalf("match = %d, %v; want 2 findings", n, err)
	}
	if len(src.gotCPEs) != 1 || src.gotCPEs[0] != cpe || len(src.gotPurls) != 1 || src.gotPurls[0] != purl {
		t.Errorf("asked purls %v and CPEs %v; a component with a purl must not also be looked up by CPE", src.gotPurls, src.gotCPEs)
	}

	list, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID, RuleID: "CVE-2021-3711"})
	if err != nil || len(list) != 1 {
		t.Fatalf("openssl findings = %d, %v", len(list), err)
	}
	f := list[0]
	if f.Severity != domain.SeverityCritical || f.FixedVersion != "1.1.1l" || f.PackageName != "openssl" || f.PackageVersion != "1.1.1k" ||
		f.Purl != "" || f.Metadata["cpe"] != cpe || f.Status != domain.FindingOpen {
		t.Errorf("CPE finding = %+v", f)
	}

	// The component reads as vulnerable (VulnState), and the snapshot lists it.
	comps, err := sbomRepo.ListComponents(ctx, sbom.ComponentFilter{SbomID: sbomID, Name: "openssl"})
	if err != nil || len(comps) != 1 || comps[0].VulnCount != 1 {
		t.Fatalf("openssl component = %+v, %v; want vuln_count 1", comps, err)
	}
	vulns, err := sbomRepo.SnapshotVulnerabilities(ctx, sbomID)
	if err != nil {
		t.Fatal(err)
	}
	var sawOpenSSL bool
	for _, v := range vulns {
		if v.Key == "CVE-2021-3711" && len(v.Components) == 1 && v.Components[0].Name == "openssl" {
			sawOpenSSL = true
		}
	}
	if !sawOpenSSL {
		t.Errorf("snapshot vulnerabilities miss the CPE match: %+v", vulns)
	}

	// NVD is down on the next run: the finding must stay open.
	src.byCPE, src.cpeErr = nil, errors.New("nvd: 503 Service Unavailable")
	if _, err := svc.Match(ctx); err == nil {
		t.Error("a failed NVD lookup should surface as a partial error")
	}
	if got, _ := findingRepo.Get(ctx, f.ID); got.Status != domain.FindingOpen {
		t.Errorf("after a failed NVD lookup the CPE finding is %q, want still open", got.Status)
	}

	// NVD answers again and no longer lists it (e.g. the CPE was upgraded): closed.
	src.byCPE, src.cpeErr = map[string][]vulnmatch.Vuln{}, nil
	if _, err := svc.Match(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := findingRepo.Get(ctx, f.ID); got.Status != domain.FindingRemediated {
		t.Errorf("after a complete run without the CVE the finding is %q, want remediated", got.Status)
	}
}
