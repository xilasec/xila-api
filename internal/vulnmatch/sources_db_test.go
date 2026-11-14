package vulnmatch_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/vulnmatch"
)

// exportZip builds an OSV ecosystem export (all.zip: one OSV JSON per entry,
// named <id>.json, as osv-vulnerabilities.storage.googleapis.com serves it)
// from the real records in testdata/osv, optionally rewriting `modified`.
func exportZip(t *testing.T, modified map[string]string, ids ...string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, id := range ids {
		b, err := os.ReadFile(filepath.Join("testdata", "osv", id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if m, ok := modified[id]; ok {
			var doc map[string]any
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			doc["modified"] = m
			doc["summary"] = "updated summary"
			b, _ = json.Marshal(doc)
		}
		w, err := zw.Create(id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		w.Write(b)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func importZip(t *testing.T, repo *vulnmatch.OSVRepository, r *bytes.Reader) vulnmatch.ImportResult {
	t.Helper()
	res, err := repo.ImportZip(context.Background(), r, r.Size())
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	return res
}

func TestOSVImportIsIdempotent(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := vulnmatch.NewOSVRepository(pool)
	all := []string{"GHSA-jfh8-c2jp-5v3q", "GO-2022-0969", "PYSEC-2021-19", "GHSA-29mw-wpgm-hmr9", "RUSTSEC-2021-0124"}

	first := importZip(t, repo, exportZip(t, nil, all...))
	if first.Records != 5 || first.Inserted != 5 || first.Updated != 0 {
		t.Fatalf("first import = %+v, want 5 inserted", first)
	}
	again := importZip(t, repo, exportZip(t, nil, all...))
	if again.Inserted != 0 || again.Updated != 0 || again.Unchanged != 5 {
		t.Errorf("re-import = %+v, want all 5 unchanged", again)
	}
	// An older `modified` never replaces a newer one; a newer one does.
	older := importZip(t, repo, exportZip(t, map[string]string{"GO-2022-0969": "2020-01-01T00:00:00Z"}, "GO-2022-0969"))
	newer := importZip(t, repo, exportZip(t, map[string]string{"PYSEC-2021-19": "2030-01-01T00:00:00Z"}, "PYSEC-2021-19"))
	if older.Updated != 0 || newer.Updated != 1 {
		t.Errorf("older/newer re-import = %+v / %+v, want 0 / 1 updated", older, newer)
	}
	var summary string
	if err := pool.QueryRow(context.Background(), `SELECT summary FROM osv_advisories WHERE id = 'PYSEC-2021-19'`).Scan(&summary); err != nil || summary != "updated summary" {
		t.Errorf("summary = %q (%v), want the newer record's", summary, err)
	}
	st, err := repo.Stats(context.Background())
	if err != nil || st.Advisories != 5 {
		t.Fatalf("stats = %+v, %v", st, err)
	}
	ecos := []string{}
	for _, e := range st.Ecosystems {
		ecos = append(ecos, e.Ecosystem)
	}
	if !slices.Equal(ecos, []string{"Go", "Maven", "PyPI", "RubyGems", "crates.io", "npm"}) {
		t.Errorf("ecosystems = %v", ecos)
	}
	// Not a zip at all.
	if _, err := repo.ImportZip(context.Background(), bytes.NewReader([]byte("nope")), 4); err == nil {
		t.Error("garbage must be rejected")
	}
}

// harness wires the real repositories + ingest pipeline with one project that
// has an SBOM.
type harness struct {
	pool      *pgxpool.Pool
	findings  *finding.Repository
	sboms     *sbom.Repository
	ingest    *scan.Service
	projectID string
	sbomID    string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := pgtest.Pool(t)
	ctx := context.Background()
	h := &harness{pool: pool, findings: finding.NewRepository(pool), sboms: sbom.NewRepository(pool)}
	scanRepo := scan.NewRepository(pool)
	h.ingest = scan.NewService(scanRepo, h.findings, project.NewRepository(pool),
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, scanRepo)
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-src','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&h.projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO sboms (project_id, artifact, version) VALUES ($1,'web','1.0') RETURNING id`,
		h.projectID).Scan(&h.sbomID); err != nil {
		t.Fatalf("seed sbom: %v", err)
	}
	return h
}

func (h *harness) component(t *testing.T, name, version, purl string) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(),
		`INSERT INTO sbom_components (sbom_id, project_id, name, version, purl) VALUES ($1,$2,$3,$4,$5)`,
		h.sbomID, h.projectID, name, version, purl); err != nil {
		t.Fatalf("seed component: %v", err)
	}
}

func (h *harness) open(t *testing.T) map[string]finding.Finding {
	t.Helper()
	list, err := h.findings.List(context.Background(), finding.Filter{ProjectID: h.projectID})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]finding.Finding{}
	for _, f := range list {
		if f.Status == domain.FindingOpen {
			out[f.RuleID] = f
		}
	}
	return out
}

// Air-gapped: an imported OSV export matches SBOM inventory with no network.
func TestLocalMirrorMatchesInventory(t *testing.T) {
	h := newHarness(t)
	repo := vulnmatch.NewOSVRepository(h.pool)
	importZip(t, repo, exportZip(t, nil, "GHSA-jfh8-c2jp-5v3q", "PYSEC-2021-19", "RUSTSEC-2021-0124"))
	h.component(t, "log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	h.component(t, "lxml", "4.6.3", "pkg:pypi/lxml@4.6.3") // the fixed version
	h.component(t, "tokio", "1.9.0", "pkg:cargo/tokio@1.9.0")

	svc := vulnmatch.NewService(h.sboms, h.ingest, vulnmatch.NewLocalSource(repo))
	if _, err := svc.Match(context.Background()); err != nil {
		t.Fatalf("match: %v", err)
	}
	open := h.open(t)
	if len(open) != 2 {
		t.Fatalf("findings = %v, want log4shell + the tokio advisory", keys(open))
	}
	l := open["GHSA-jfh8-c2jp-5v3q"]
	if l.Severity != domain.SeverityCritical || l.FixedVersion != "2.15.0" || !slices.Equal(l.CVE, []string{"CVE-2021-44228"}) {
		t.Errorf("log4shell finding = sev %s fixed %s cve %v", l.Severity, l.FixedVersion, l.CVE)
	}
	if tk := open["RUSTSEC-2021-0124"]; tk.FixedVersion != "1.13.1" || tk.Scanner != vulnmatch.Scanner {
		t.Errorf("tokio finding = fixed %s scanner %s, want 1.13.1 / osv", tk.FixedVersion, tk.Scanner)
	}
}

// The private advisory database end to end: an advisory against an internal
// package becomes a finding, editing it updates the finding, and withdrawing
// it auto-closes the finding.
func TestPrivateAdvisoryLifecycle(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	repo := vulnmatch.NewAdvisoryRepository(h.pool, "https://xila.example")
	h.component(t, "billing-core", "2.3.0", "pkg:maven/com.acme/billing-core@2.3.0")
	h.component(t, "acme-auth", "1.0.0", "pkg:generic/acme/acme-auth@1.0.0")

	adv := vulnmatch.Advisory{
		Summary: "Billing core leaks invoices", Severity: domain.SeverityHigh, Aliases: []string{"CVE-2026-1111"},
		Affected: []vulnmatch.Affected{{
			Package: vulnmatch.Package{Ecosystem: "Maven", Name: "com.acme:billing-core"},
			Ranges: []vulnmatch.Range{{Type: "ECOSYSTEM", Events: []vulnmatch.Event{
				{Introduced: "2.0.0"}, {Fixed: "2.4.0"},
			}}},
		}},
	}
	if err := adv.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	created, err := repo.Create(ctx, adv, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	wantID := "XILA-" + time.Now().Format("2006") + "-0001"
	if created.ID != wantID {
		t.Errorf("id = %q, want %q", created.ID, wantID)
	}
	// A second one, by purl with an explicit versions list, gets the next number.
	second, err := repo.Create(ctx, vulnmatch.Advisory{
		Summary: "Auth bypass", Severity: domain.SeverityCritical,
		Affected: []vulnmatch.Affected{{Package: vulnmatch.Package{Purl: "pkg:generic/acme/acme-auth"},
			Versions: []string{"1.0.0", "1.0.1"}}},
	}, nil)
	if err != nil || second.ID != "XILA-"+time.Now().Format("2006")+"-0002" {
		t.Fatalf("second = %q, %v", second.ID, err)
	}

	svc := vulnmatch.NewService(h.sboms, h.ingest, vulnmatch.NewPrivateSource(repo))
	if _, err := svc.Match(ctx); err != nil {
		t.Fatalf("match: %v", err)
	}
	open := h.open(t)
	f, ok := open[created.ID]
	if !ok || len(open) != 2 {
		t.Fatalf("findings = %v, want both advisories", keys(open))
	}
	if f.Severity != domain.SeverityHigh || f.FixedVersion != "2.4.0" || !slices.Equal(f.CVE, []string{"CVE-2026-1111"}) ||
		f.URL != "https://xila.example/advisories/"+created.ID || f.Scanner != "osv" {
		t.Errorf("finding = %+v", f)
	}

	// The fix turns out to be 2.3.0 — already shipped: the finding closes.
	created.Affected[0].Ranges[0].Events[1] = vulnmatch.Event{Fixed: "2.3.0"}
	if err := created.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Update(ctx, created); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := svc.Match(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.findings.Get(ctx, f.ID); got.Status != domain.FindingRemediated {
		t.Errorf("after the range moved past the shipped version: status = %s, want remediated", got.Status)
	}

	// Withdrawing the other one closes its finding too.
	now := time.Now()
	second.Withdrawn = &now
	if _, err := repo.Update(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Match(ctx); err != nil {
		t.Fatal(err)
	}
	if open := h.open(t); len(open) != 0 {
		t.Errorf("open after withdrawal = %v, want none", keys(open))
	}
	// Withdrawn advisories are hidden from the default list, kept on request.
	if l, _ := repo.List(ctx, vulnmatch.AdvisoryFilter{Limit: 10}); len(l) != 1 {
		t.Errorf("default list = %d, want 1 (withdrawn hidden)", len(l))
	}
	if l, _ := repo.List(ctx, vulnmatch.AdvisoryFilter{Limit: 10, IncludeWithdrawn: true, Query: "acme-auth"}); len(l) != 1 {
		t.Errorf("search by package incl. withdrawn = %d, want 1", len(l))
	}
	if err := repo.Delete(ctx, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx, second.ID); err != vulnmatch.ErrAdvisoryNotFound {
		t.Errorf("get after delete = %v, want not found", err)
	}
}

// A private advisory aliasing a public one merges with it (one finding), and
// existing osv findings keep their identity when more sources are added.
func TestMultiSourceKeepsExistingFindings(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	const purl = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	h.component(t, "log4j-core", "2.14.1", purl)

	online := &stubSource{byPurl: map[string][]vulnmatch.Vuln{purl: {{
		ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"}, CVEs: []string{"CVE-2021-44228"},
		Severity: domain.SeverityCritical, Fixed: "2.15.0",
	}}}}
	if _, err := vulnmatch.NewService(h.sboms, h.ingest, online).Match(ctx); err != nil {
		t.Fatal(err)
	}
	before := h.open(t)["GHSA-jfh8-c2jp-5v3q"]

	advisories := vulnmatch.NewAdvisoryRepository(h.pool, "")
	if _, err := advisories.Create(ctx, vulnmatch.Advisory{
		ID: "XILA-2026-0100", Summary: "Internal tracking of log4shell", Severity: domain.SeverityCritical,
		Aliases: []string{"CVE-2021-44228"},
		Affected: []vulnmatch.Affected{{Package: vulnmatch.Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"},
			Ranges: []vulnmatch.Range{{Type: "ECOSYSTEM", Events: []vulnmatch.Event{{Introduced: "2.0"}, {Fixed: "2.17.1"}}}}}},
	}, nil); err != nil {
		t.Fatal(err)
	}
	multi := vulnmatch.NewMultiSource(
		vulnmatch.NamedSource{Name: vulnmatch.SourceOSV, Source: online},
		vulnmatch.NamedSource{Name: vulnmatch.SourcePrivate, Source: vulnmatch.NewPrivateSource(advisories)})
	if _, err := vulnmatch.NewService(h.sboms, h.ingest, multi).Match(ctx); err != nil {
		t.Fatal(err)
	}
	open := h.open(t)
	after, ok := open["GHSA-jfh8-c2jp-5v3q"]
	if len(open) != 1 || !ok {
		t.Fatalf("open = %v, want the one merged log4shell finding", keys(open))
	}
	if after.ID != before.ID || after.FirstSeenAt != before.FirstSeenAt {
		t.Errorf("finding was recreated (%s → %s); adding a source must keep it", before.ID, after.ID)
	}
	if after.FixedVersion != "2.15.0" {
		t.Errorf("fixed = %q, want the nearest fix 2.15.0", after.FixedVersion)
	}
	if src, _ := after.Metadata["sources"].([]any); len(src) != 2 {
		t.Errorf("metadata sources = %v, want osv + private", after.Metadata["sources"])
	}
}

func keys(m map[string]finding.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
