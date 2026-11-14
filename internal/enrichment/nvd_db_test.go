package enrichment_test

import (
	"context"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/enrichment"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

type fakeNVD struct {
	data  map[string]enrichment.CVSS
	asked [][]string
}

func (f *fakeNVD) Fetch(_ context.Context, cves []string) (map[string]enrichment.CVSS, error) {
	f.asked = append(f.asked, slices.Clone(cves))
	out := map[string]enrichment.CVSS{}
	for _, c := range cves {
		if r, ok := f.data[c]; ok {
			out[c] = r
		}
	}
	return out, nil
}

// NVD CVSS lands on findings: the vector always, the score only where the
// scanner gave none — and a scanner's score keeps winning across re-ingests.
func TestNVDEnrichmentPrecedence(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := finding.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-nvd','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	mk := func(fp string, cves []string, cvss *float64) finding.Finding {
		f, err := repo.Upsert(ctx, finding.Finding{
			ProjectID: projectID, Fingerprint: fp, Scanner: "trivy", Category: domain.CategorySCA,
			RuleID: cves[0], Title: fp, Severity: domain.SeverityHigh, CVE: cves, CVSS: cvss,
		})
		if err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
		return f
	}
	noScore := mk("a", []string{"CVE-2021-44228"}, nil)
	scanner := mk("b", []string{"CVE-2023-0001"}, new(5.5))
	multi := mk("c", []string{"CVE-2023-0001", "CVE-2021-44228", "CVE-2099-0001"}, nil)

	src := &fakeNVD{data: map[string]enrichment.CVSS{
		"CVE-2021-44228": {CVE: "CVE-2021-44228", Score: new(10.0),
			Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Version: "3.1"},
		"CVE-2023-0001": {CVE: "CVE-2023-0001", Score: new(6.7),
			Vector: "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"},
	}}
	nvd := enrichment.NewNVD(repo, src)
	n, err := nvd.Refresh(ctx)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if n != 3 {
		t.Errorf("findings updated = %d, want 3", n)
	}
	if len(src.asked) != 1 || len(src.asked[0]) != 3 {
		t.Errorf("asked = %v, want the 3 distinct CVEs once", src.asked)
	}

	get := func(id string) finding.Finding {
		f, err := repo.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	a := get(noScore.ID)
	if a.CVSS == nil || *a.CVSS != 10 || a.CVSSSource == nil || *a.CVSSSource != "nvd" ||
		a.CVSSVector == nil || *a.CVSSVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" || *a.CVSSVersion != "3.1" {
		t.Errorf("scanner-less finding = cvss %v source %v vector %v, want NVD's 10 / nvd / vector", a.CVSS, a.CVSSSource, a.CVSSVector)
	}
	b := get(scanner.ID)
	if b.CVSS == nil || *b.CVSS != 5.5 || b.CVSSSource != nil || b.CVSSVector == nil {
		t.Errorf("scanner-scored finding = cvss %v source %v vector %v, want the scanner's 5.5 kept + NVD vector", b.CVSS, b.CVSSSource, b.CVSSVector)
	}
	if c := get(multi.ID); c.CVSS == nil || *c.CVSS != 10 {
		t.Errorf("multi-CVE finding cvss = %v, want the highest NVD score (10)", c.CVSS)
	}

	// Nothing stale now (the unknown CVE is cached too): no NVD calls, no writes.
	if n, err := nvd.Refresh(ctx); err != nil || n != 0 || len(src.asked) != 1 {
		t.Errorf("second refresh = %d, %v, asked %d times; want 0 changes and no new requests", n, err, len(src.asked))
	}

	// Re-ingest without a score: the NVD-filled score stays (no flap to NULL).
	mk("a", []string{"CVE-2021-44228"}, nil)
	if a := get(noScore.ID); a.CVSS == nil || *a.CVSS != 10 || a.CVSSSource == nil {
		t.Errorf("after re-ingest cvss = %v source %v, want NVD's 10 kept", a.CVSS, a.CVSSSource)
	}
	// The scanner starts reporting a score: it takes over, and NVD won't overwrite it.
	mk("a", []string{"CVE-2021-44228"}, new(9.0))
	if _, err := repo.ApplyNVD(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if a := get(noScore.ID); a.CVSS == nil || *a.CVSS != 9 || a.CVSSSource != nil {
		t.Errorf("after scanner score cvss = %v source %v, want the scanner's 9 with no NVD source", a.CVSS, a.CVSSSource)
	}

	// At ingest the applier stamps a new finding from the cache (no network).
	d := mk("d", []string{"CVE-2023-0001"}, nil)
	scanID := "00000000-0000-0000-0000-000000000000"
	if _, err := pool.Exec(ctx, `INSERT INTO scans (id, project_id, scanner, category) VALUES ($1,$2,'trivy','sca')`, scanID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE findings SET last_scan_id = $1 WHERE id = $2`, scanID, d.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := nvd.ApplyToScan(ctx, projectID, scanID); err != nil || n != 1 {
		t.Fatalf("ApplyToScan = %d, %v; want 1", n, err)
	}
	// cvss is a REAL column: compare at float32 precision.
	if got := get(d.ID); got.CVSS == nil || float32(*got.CVSS) != 6.7 || got.CVSSVector == nil {
		t.Errorf("new finding = cvss %v vector %v, want NVD's 6.7 + vector", got.CVSS, got.CVSSVector)
	}
}
