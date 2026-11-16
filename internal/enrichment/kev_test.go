package enrichment

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// Real CISA catalog excerpt (known_exploited_vulnerabilities.json).
func TestParseCISAKEV(t *testing.T) {
	list, err := ParseCISAKEV(open(t, "cisa_kev.json"))
	if err != nil {
		t.Fatal(err)
	}
	ids := slices.Sorted(slices.Values(list.IDs))
	want := []string{"CVE-2021-44228", "CVE-2024-27348", "CVE-2024-4577"}
	if !slices.Equal(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
	// knownRansomwareCampaignUse: Known for Log4Shell and the PHP-CGI flaw,
	// Unknown for the Apache HugeGraph one.
	if !list.Ransomware["CVE-2021-44228"] || !list.Ransomware["CVE-2024-4577"] || list.Ransomware["CVE-2024-27348"] {
		t.Errorf("ransomware = %v, want CVE-2021-44228 and CVE-2024-4577 only", list.Ransomware)
	}
}

// Real EUVD search API pages (/api/search?exploited=true): each item asserts
// its EUVD id and every alias (CVE and GHSA), newline-separated.
func TestParseEUVDPage(t *testing.T) {
	p, err := ParseEUVDPage(open(t, "euvd_exploited_page0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Items != 2 || p.Total != 1796 {
		t.Errorf("items/total = %d/%d, want 2/1796", p.Items, p.Total)
	}
	want := []string{"EUVD-2026-122310", "CVE-2026-124194", "GHSA-69HG-PPJJ-GG27",
		"EUVD-2026-30514", "CVE-2026-8398", "GHSA-RM3R-35X9-JV93"}
	if !slices.Equal(p.IDs, want) {
		t.Errorf("ids = %v, want %v", p.IDs, want)
	}
}

// VulnCheck's documented vulncheck-kev record shape, cursor-paged.
func TestParseVulnCheckKEVPage(t *testing.T) {
	p, err := ParseVulnCheckKEVPage(open(t, "vulncheck_kev_page1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.IDs, []string{"CVE-2024-4577"}) || p.NextCursor == "" {
		t.Errorf("page 1 = %+v, want CVE-2024-4577 and a next cursor", p)
	}
	if !slices.Equal(p.Ransomware, []string{"CVE-2024-4577"}) {
		t.Errorf("page 1 ransomware = %v, want CVE-2024-4577", p.Ransomware)
	}
	p, err = ParseVulnCheckKEVPage(open(t, "vulncheck_kev_page2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.IDs, []string{"CVE-2024-27348"}) || p.NextCursor != "" || len(p.Ransomware) != 0 {
		t.Errorf("page 2 = %+v, want CVE-2024-27348, no ransomware use and no cursor", p)
	}
}

// The HTTP catalogs walk their pagination: EUVD by page number until an empty
// page, VulnCheck by cursor with the bearer token.
func TestKEVCatalogPaging(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/euvd":
			if r.URL.Query().Get("exploited") != "true" {
				http.Error(w, "filter lost", http.StatusBadRequest)
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
		case r.URL.Path == "/vc":
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.URL.Query().Get("cursor") == "" {
				http.ServeFile(w, r, "testdata/vulncheck_kev_page1.json")
			} else {
				http.ServeFile(w, r, "testdata/vulncheck_kev_page2.json")
			}
		}
	}))
	defer srv.Close()

	euvd := &euvdCatalog{url: srv.URL + "/euvd?exploited=true", pageSize: 2, client: srv.Client()}
	list, err := euvd.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ids := list.IDs
	if len(ids) != 12 || !slices.Contains(ids, "GHSA-9W8J-FG77-WHW7") || !slices.Contains(ids, "CVE-2026-8398") {
		t.Errorf("euvd ids = %v, want both pages' 4 items × 3 ids", ids)
	}

	cats, err := KEVCatalogs([]string{"vulncheck"}, map[string]string{"vulncheck": srv.URL + "/vc"}, "tok", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	list, err = cats[0].Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(list.IDs, []string{"CVE-2024-4577", "CVE-2024-27348"}) {
		t.Errorf("vulncheck ids = %v", list.IDs)
	}
	if len(list.Ransomware) != 1 || !list.Ransomware["CVE-2024-4577"] {
		t.Errorf("vulncheck ransomware = %v, want only CVE-2024-4577 (across pages)", list.Ransomware)
	}

	if _, err := KEVCatalogs([]string{"vulncheck"}, nil, "", srv.Client()); err == nil {
		t.Error("vulncheck without a token must be a configuration error")
	}
	if _, err := KEVCatalogs([]string{"cisa", "nvd"}, nil, "", srv.Client()); err == nil {
		t.Error("an unknown catalog must be a configuration error")
	}
}

// A catalog's entry matches through aliases: a CISA CVE flags the GHSA
// finding carrying it, ENISA's GHSA alias flags a GHSA-only finding, case
// insensitively.
func TestKEVSourcesForAliases(t *testing.T) {
	assertions := map[string][]string{
		"CVE-2024-27348":      {"cisa", "vulncheck"},
		"GHSA-29RC-VQ7F-X335": {"enisa"},
		"CVE-2021-44228":      {"cisa"},
	}
	cases := []struct {
		ids  []string
		want []string
	}{
		{[]string{"GHSA-29rc-vq7f-x335", "CVE-2024-27348"}, []string{"cisa", "enisa", "vulncheck"}},
		{[]string{"GHSA-29rc-vq7f-x335"}, []string{"enisa"}},
		{[]string{"CVE-2099-0001"}, []string{}},
	}
	for _, c := range cases {
		if got := KEVSourcesFor(c.ids, assertions); !slices.Equal(got, c.want) {
			t.Errorf("KEVSourcesFor(%v) = %v, want %v", c.ids, got, c.want)
		}
	}
}

// A catalog that fails keeps asserting its last list: the finding stays KEV
// (from that catalog too) and the failure is reported, not fatal.
func TestEnrichFailedCatalogKeepsAssertions(t *testing.T) {
	kev := &fakeKEVStore{}
	store := &fakeStore{items: []finding.Enrichable{
		{ID: "a", Severity: domain.SeverityHigh, CVE: []string{"CVE-1"}, IDs: []string{"CVE-1"}},
	}}
	run := func(enisa KEVCatalog) Result {
		t.Helper()
		svc := NewService(store, fakeEPSS{}, []KEVCatalog{fakeCatalog{name: "cisa", ids: []string{"CVE-9"}}, enisa}, kev, nil)
		res, err := svc.Enrich(context.Background())
		if err != nil {
			t.Fatalf("Enrich: %v", err)
		}
		return res
	}
	run(fakeCatalog{name: "enisa", ids: []string{"CVE-1"}})
	if got := store.set["a"].sources; !slices.Equal(got, []string{"enisa"}) {
		t.Fatalf("first run sources = %v, want [enisa]", got)
	}

	res := run(fakeCatalog{name: "enisa", err: errors.New("HTTP 503")})
	if !strings.Contains(res.KEVFailed["enisa"], "503") || res.KEV["cisa"] != 1 {
		t.Errorf("result = %+v, want enisa failed and cisa synced", res)
	}
	if a := store.set["a"]; !a.kev || !slices.Equal(a.sources, []string{"enisa"}) {
		t.Errorf("after enisa outage a = %+v, want still KEV via enisa", a)
	}
}

// A finding is flagged as ransomware-used when a catalog asserting any of its
// ids (aliases included) marks that id; other findings on KEV are not.
func TestEnrichRansomwareFlag(t *testing.T) {
	store := &fakeStore{items: []finding.Enrichable{
		{ID: "used", Severity: domain.SeverityHigh, CVE: []string{"CVE-1"}, IDs: []string{"GHSA-xxxx", "CVE-1"}},
		{ID: "kev-only", Severity: domain.SeverityHigh, CVE: []string{"CVE-2"}, IDs: []string{"CVE-2"}},
		{ID: "none", Severity: domain.SeverityHigh, CVE: []string{"CVE-3"}, IDs: []string{"CVE-3"}},
	}}
	cats := []KEVCatalog{fakeCatalog{name: "cisa", ids: []string{"CVE-1", "CVE-2"}, ransomware: []string{"CVE-1"}}}
	if _, err := NewService(store, fakeEPSS{}, cats, &fakeKEVStore{}, nil).Enrich(context.Background()); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]bool{"used": true, "kev-only": false, "none": false} {
		if got := store.set[id].ransomware; got != want {
			t.Errorf("%s ransomware = %v, want %v", id, got, want)
		}
	}
}
