package enrichment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// End to end against Postgres with the real catalog samples: findings get the
// catalogs asserting them through aliases (scanner CVE list, rule id, the
// local OSV mirror's aliases), and an ENISA outage keeps ENISA's assertions.
func TestKEVCatalogsOnFindings(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := finding.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-kev','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// The local OSV mirror knows GHSA-jfh8-c2jp-5v3q is Log4Shell.
	if _, err := pool.Exec(ctx, `INSERT INTO osv_advisories (id, modified, aliases)
		VALUES ('GHSA-jfh8-c2jp-5v3q', now(), '{CVE-2021-44228}')`); err != nil {
		t.Fatal(err)
	}
	mk := func(fp, rule string, cves ...string) string {
		f, err := repo.Upsert(ctx, finding.Finding{
			ProjectID: projectID, Fingerprint: fp, Scanner: "trivy", Category: domain.CategorySCA,
			RuleID: rule, Title: fp, Severity: domain.SeverityHigh, CVE: cves,
		})
		if err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
		return f.ID
	}
	php := mk("php", "CVE-2024-4577", "CVE-2024-4577")                       // CISA
	ghsaCVE := mk("hugegraph", "GHSA-29rc-vq7f-x335", "CVE-2024-27348")      // CISA, via the lifted CVE
	ghsaOnly := mk("outlook", "GHSA-69hg-ppjj-gg27")                         // ENISA lists the GHSA alias
	mirror := mk("log4j", "GHSA-jfh8-c2jp-5v3q")                             // CISA, via the OSV mirror alias
	both := mk("both", "CVE-2026-20320", "CVE-2026-20320", "CVE-2021-44228") // ENISA + CISA
	quiet := mk("quiet", "CVE-1999-0001", "CVE-1999-0001")

	var enisaDown atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cisa":
			http.ServeFile(w, r, "testdata/cisa_kev.json")
		case "/euvd":
			if enisaDown.Load() {
				http.Error(w, "down", http.StatusServiceUnavailable)
				return
			}
			switch r.URL.Query().Get("page") {
			case "0":
				http.ServeFile(w, r, "testdata/euvd_exploited_page0.json")
			case "1":
				http.ServeFile(w, r, "testdata/euvd_exploited_page1.json")
			default:
				_, _ = w.Write([]byte(`{"items":[],"total":1796}`))
			}
		}
	}))
	defer srv.Close()
	catalogs := []KEVCatalog{
		&cisaCatalog{url: srv.URL + "/cisa", client: srv.Client()},
		&euvdCatalog{url: srv.URL + "/euvd?exploited=true", pageSize: 2, client: srv.Client()},
	}
	svc := NewService(repo, fakeEPSS{}, catalogs, NewKEVRepository(pool), nil)

	check := func(when string) {
		t.Helper()
		want := map[string][]string{
			php: {"cisa"}, ghsaCVE: {"cisa"}, ghsaOnly: {"enisa"}, mirror: {"cisa"},
			both: {"cisa", "enisa"}, quiet: {},
		}
		for id, w := range want {
			f, err := repo.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(f.KEVSources, w) || f.KEV != (len(w) > 0) {
				t.Errorf("%s: %s kev=%v kev_sources=%v, want %v", when, f.Title, f.KEV, f.KEVSources, w)
			}
		}
	}

	res, err := svc.Enrich(ctx)
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if res.KEV["cisa"] != 3 || res.KEV["enisa"] != 12 || len(res.KEVFailed) != 0 {
		t.Errorf("result = %+v", res)
	}
	check("first sync")

	enisaDown.Store(true)
	res, err = svc.Enrich(ctx)
	if err != nil {
		t.Fatalf("Enrich with ENISA down: %v", err)
	}
	if res.KEVFailed["enisa"] == "" {
		t.Errorf("result = %+v, want enisa reported failed", res)
	}
	check("ENISA outage")

	status, err := svc.KEVStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(status) != 2 || status[1].Source != "enisa" || status[1].Entries != 12 ||
		status[1].FailedAt == nil || status[1].SyncedAt == nil || status[1].LastError == "" {
		t.Errorf("status = %+v, want enisa failed with its 12 entries kept", status)
	}

	// A catalog dropped from KEV_SOURCES stops asserting.
	only := NewService(repo, fakeEPSS{}, catalogs[:1], NewKEVRepository(pool), nil)
	if _, err := only.Enrich(ctx); err != nil {
		t.Fatal(err)
	}
	if f, _ := repo.Get(ctx, ghsaOnly); f.KEV || len(f.KEVSources) != 0 {
		t.Errorf("enisa no longer configured: %s kev=%v sources=%v, want cleared", f.Title, f.KEV, f.KEVSources)
	}
}
