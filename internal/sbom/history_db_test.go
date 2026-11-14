package sbom_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/vulnmatch"
)

type stubFeed map[string][]vulnmatch.Vuln

func (s stubFeed) Query(context.Context, []string) (map[string][]vulnmatch.Vuln, error) {
	return s, nil
}

func release(version string, deps map[string]string, graph string) string {
	var comps []string
	for name, v := range deps {
		comps = append(comps, `{"bom-ref":"`+name+`","name":"`+name+`","version":"`+v+`","purl":"pkg:npm/`+name+`@`+v+`"}`)
	}
	slices.Sort(comps)
	return `{"bomFormat":"CycloneDX","specVersion":"1.5",
		"metadata":{"component":{"bom-ref":"web","name":"web","version":"` + version + `"}},
		"components":[` + strings.Join(comps, ",") + `],"dependencies":[` + graph + `]}`
}

// The questions M2 exists to answer, against real uploads: which packages in a
// release are vulnerable, what a release changed, which releases ever shipped a
// CVE, and why a vulnerable package is in the tree at all. History must survive
// the project moving on — after an upgrade closes the findings, the old release
// still reports what it shipped.
func TestSnapshotHistoryAnswers(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sbom.NewRepository(pool)
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	ingest := scan.NewService(scan.NewRepository(pool), findings, projects,
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil)
	svc := sbom.NewService(repo, projects, nil, nil)
	projectID := seedProject(t, pool, "web")

	upload := func(doc string) sbom.Sbom {
		t.Helper()
		s, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: projectID}, strings.NewReader(doc))
		if err != nil {
			t.Fatalf("upload: %v", err)
		}
		time.Sleep(5 * time.Millisecond) // distinct created_at ordering
		return s
	}
	v1 := upload(release("1.0.0",
		map[string]string{"express": "4.17.0", "qs": "6.5.2", "lodash": "4.17.20"},
		`{"ref":"web","dependsOn":["express","lodash"]},{"ref":"express","dependsOn":["qs"]}`))
	v2 := upload(release("1.1.0",
		map[string]string{"express": "4.18.2", "qs": "6.11.0", "lodash": "4.17.21", "axios": "1.6.0"},
		`{"ref":"web","dependsOn":["express","lodash","axios"]},{"ref":"express","dependsOn":["qs"]}`))

	// An advisory for the old qs (OSV), and a scanner's report on the old lodash
	// that has since been closed by the upgrade.
	feed := stubFeed{"pkg:npm/qs@6.5.2": {{ID: "GHSA-hrpp", Summary: "qs prototype pollution",
		Severity: domain.SeverityHigh, CVEs: []string{"CVE-2022-24999"}, Fixed: "6.10.3"}}}
	if _, err := vulnmatch.NewService(repo, ingest, feed).Match(ctx); err != nil {
		t.Fatalf("match: %v", err)
	}
	lodash, err := findings.Upsert(ctx, finding.Finding{ProjectID: projectID, Fingerprint: "trivy-lodash",
		Scanner: "trivy", Category: domain.CategorySCA, RuleID: "CVE-2021-23337", Title: "lodash command injection",
		Severity: domain.SeverityCritical, CVE: []string{"CVE-2021-23337"},
		PackageName: "lodash", PackageVersion: "4.17.20", Metadata: map[string]any{}})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if _, err := findings.SetStatus(ctx, lodash.ID, finding.Triage{Status: domain.FindingRemediated}); err != nil {
		t.Fatalf("remediate: %v", err)
	}

	// --- Which packages in each release are vulnerable? ---
	vulnerable := func(s sbom.Sbom, want bool) []string {
		t.Helper()
		hits, err := repo.ListComponents(ctx, sbom.ComponentFilter{SbomID: s.ID, Vulnerable: &want})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		var out []string
		for _, h := range hits {
			out = append(out, h.Name+"@"+h.Version+":"+strings.Join(h.Vulns, "+"))
		}
		return out
	}
	if got := vulnerable(v1, true); !slices.Equal(got, []string{"lodash@4.17.20:CVE-2021-23337", "qs@6.5.2:CVE-2022-24999"}) {
		t.Errorf("v1 vulnerable = %v; the old release keeps its history after the upgrade", got)
	}
	if got := vulnerable(v2, true); len(got) != 0 {
		t.Errorf("v2 vulnerable = %v, want none", got)
	}
	if got := vulnerable(v2, false); len(got) != 4 {
		t.Errorf("v2 clean = %v, want all 4", got)
	}

	vulns, err := repo.SnapshotVulnerabilities(ctx, v1.ID)
	if err != nil {
		t.Fatalf("snapshot vulns: %v", err)
	}
	if len(vulns) != 2 || vulns[0].Key != "CVE-2021-23337" || vulns[0].Severity != domain.SeverityCritical ||
		!slices.Equal(vulns[0].Sources, []string{"trivy"}) || !slices.Equal(vulns[0].Statuses, []string{"remediated"}) {
		t.Fatalf("v1 vulnerabilities = %+v; want the critical lodash finding first", vulns)
	}
	if q := vulns[1]; q.Key != "CVE-2022-24999" || !slices.Equal(q.IDs, []string{"CVE-2022-24999", "GHSA-hrpp"}) ||
		q.FixedVersion != "6.10.3" || len(q.Components) != 1 || q.Components[0].Name != "qs" ||
		q.Statuses == nil { // advisory-only: an empty list, never JSON null (the UI iterates it)
		t.Errorf("qs vulnerability = %+v", q)
	}

	// --- What did 1.1.0 change? (base defaults to the previous release) ---
	prev, ok, err := repo.Previous(ctx, v2)
	if err != nil || !ok || prev.ID != v1.ID {
		t.Fatalf("previous of v2 = %v %v %v, want v1", prev.ID, ok, err)
	}
	head, _ := repo.SnapshotComponents(ctx, v2.ID)
	base, _ := repo.SnapshotComponents(ctx, v1.ID)
	_, unchanged, sum := sbom.DiffComponents(base, head)
	if sum.Upgraded != 3 || sum.Added != 1 || unchanged != 0 ||
		!slices.Equal(sum.VulnsFixed, []string{"CVE-2021-23337", "CVE-2022-24999"}) || len(sum.VulnsIntroduced) != 0 {
		t.Errorf("v1→v2 summary = %+v", sum)
	}

	// --- Which releases ever shipped CVE-2022-24999? Asked by CVE or by advisory id. ---
	for _, id := range []string{"CVE-2022-24999", "GHSA-hrpp"} {
		tl, err := repo.VulnerabilityTimeline(ctx, id, nil)
		if err != nil {
			t.Fatalf("timeline: %v", err)
		}
		if len(tl) != 1 || len(tl[0].Snapshots) != 2 || tl[0].IntroducedIn == nil || tl[0].IntroducedIn.SbomID != v1.ID ||
			tl[0].FixedIn == nil || tl[0].FixedIn.SbomID != v2.ID || tl[0].CurrentlyAffected ||
			!slices.Equal(tl[0].Snapshots[0].Packages, []string{"qs@6.5.2"}) {
			t.Errorf("timeline(%s) = %+v; want introduced in 1.0.0, fixed in 1.1.0", id, tl)
		}
	}
	if tl, _ := repo.VulnerabilityTimeline(ctx, "CVE-2022-24999", []string{}); len(tl) != 0 {
		t.Errorf("timeline outside the caller's projects leaked: %+v", tl)
	}

	// --- Why is the vulnerable qs in 1.0.0? ---
	edges, err := repo.Edges(ctx, v1.ID)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	g := sbom.BuildGraph(v1, base, nil, edges)
	if paths := g.Paths("qs", sbom.MaxPaths); len(paths) != 1 || !slices.Equal(paths[0], []string{"web", "express", "qs"}) {
		t.Errorf("paths to qs = %v, want [[web express qs]]", paths)
	}
	for _, n := range g.Nodes {
		if n.Ref == "qs" && (n.VulnCount != 1 || n.MaxSeverity == nil || *n.MaxSeverity != domain.SeverityHigh) {
			t.Errorf("qs node vuln state = %+v", n.VulnState)
		}
	}

	// --- A withdrawn advisory disappears from history on the next run. ---
	if _, err := vulnmatch.NewService(repo, ingest, stubFeed{}).Match(ctx); err != nil {
		t.Fatalf("re-match: %v", err)
	}
	if got := vulnerable(v1, true); !slices.Equal(got, []string{"lodash@4.17.20:CVE-2021-23337"}) {
		t.Errorf("after withdrawal v1 vulnerable = %v, want only the scanner-reported lodash", got)
	}
}

// The current release is where an advisory becomes a finding. When the advisory
// is withdrawn (or its affected range is narrowed past the shipped version) the
// finding closes — and the component must stop counting as vulnerable: the
// closed advisory finding is not evidence the package is affected.
func TestWithdrawnAdvisoryClearsCurrentRelease(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sbom.NewRepository(pool)
	findings := finding.NewRepository(pool)
	projects := project.NewRepository(pool)
	ingest := scan.NewService(scan.NewRepository(pool), findings, projects,
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil)
	projectID := seedProject(t, pool, "api")
	s, err := sbom.NewService(repo, projects, nil, nil).Ingest(ctx, sbom.IngestRequest{ProjectID: projectID},
		strings.NewReader(release("2.0.0", map[string]string{"billing": "3.1.0"}, `{"ref":"web","dependsOn":["billing"]}`)))
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	vulnerable := func() []string {
		t.Helper()
		hits, err := repo.ListComponents(ctx, sbom.ComponentFilter{SbomID: s.ID, Vulnerable: new(true)})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		var out []string
		for _, h := range hits {
			out = append(out, h.Name+":"+strings.Join(h.Vulns, "+"))
		}
		return out
	}

	feed := stubFeed{"pkg:npm/billing@3.1.0": {{ID: "XILA-2026-0001", Summary: "leaks card numbers", Severity: domain.SeverityHigh}}}
	if _, err := vulnmatch.NewService(repo, ingest, feed).Match(ctx); err != nil {
		t.Fatalf("match: %v", err)
	}
	if got := vulnerable(); !slices.Equal(got, []string{"billing:XILA-2026-0001"}) {
		t.Fatalf("while the advisory applies, vulnerable = %v", got)
	}

	if _, err := vulnmatch.NewService(repo, ingest, stubFeed{}).Match(ctx); err != nil {
		t.Fatalf("re-match: %v", err)
	}
	open, _ := findings.List(ctx, finding.Filter{ProjectID: projectID, Status: domain.FindingOpen})
	if len(open) != 0 {
		t.Fatalf("advisory finding still open after withdrawal: %+v", open)
	}
	if got := vulnerable(); len(got) != 0 {
		t.Errorf("after withdrawal vulnerable = %v; a closed advisory finding kept the package flagged", got)
	}
	if vulns, _ := repo.SnapshotVulnerabilities(ctx, s.ID); len(vulns) != 0 {
		t.Errorf("snapshot still lists %+v", vulns)
	}
}
