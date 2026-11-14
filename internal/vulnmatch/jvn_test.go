package vulnmatch

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
)

// testdata/jvn/jvndb_2024_excerpt.rdf is three entries cut, unchanged, from
// JVN iPedia's real English feed https://jvndb.jvn.jp/en/rss/years/jvndb_2024.rdf
// (the channel header kept, its item list reduced to those three).
func TestParseJVNRSS(t *testing.T) {
	f, err := os.Open("testdata/jvn/jvndb_2024_excerpt.rdf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := ParseJVNRSS(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3", len(entries))
	}
	z := entries[0]
	if z.ID != "JVNDB-2020-013805" || z.Title != "Zeroshell vulnerable to OS command injection" ||
		!slices.Equal(z.CVEs, []string{"CVE-2020-29390"}) { // CVE and NVD reference: one CVE
		t.Errorf("entry = %+v", z)
	}
	// The newest CVSS version the entry states (3.0 over 2.0).
	if z.CVSSScore == nil || *z.CVSSScore != 9.8 || z.Severity != "critical" ||
		z.CVSSVector != "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("cvss = %v %q %q", z.CVSSScore, z.Severity, z.CVSSVector)
	}
	if !slices.Equal(z.CPEs, []string{"cpe:/o:zeroshell:zeroshell"}) || z.Published == nil ||
		z.Published.Format("2006-01-02T15:04") != "2024-02-07T04:38" {
		t.Errorf("cpes %v published %v", z.CPEs, z.Published)
	}
	if len(entries[1].CVEs) != 6 {
		t.Errorf("multi-CVE entry cves = %v, want 6", entries[1].CVEs)
	}
	if last := entries[2]; last.CVSSScore != nil || len(last.CVEs) != 1 {
		t.Errorf("entry without CVSS = %+v", last)
	}
}

type fakeAliases struct {
	m   map[string][]JVNEntry
	err error
}

func (f fakeAliases) ByCVE(context.Context, []string) (map[string][]JVNEntry, error) {
	return f.m, f.err
}

func TestEnrichAliasesAddsJVNIDsOnly(t *testing.T) {
	in := map[string][]Vuln{
		"pkg:npm/a@1": {{ID: "GHSA-1", CVEs: []string{"CVE-2024-1"}, Sources: []string{SourceOSV}}, {ID: "GHSA-2"}},
	}
	out := enrichAliases(context.Background(), fakeAliases{m: map[string][]JVNEntry{
		"CVE-2024-1": {{ID: "JVNDB-2024-000001"}},
	}}, in)
	got := out["pkg:npm/a@1"]
	if len(got) != 2 || got[0].ID != "GHSA-1" || !slices.Equal(got[0].Aliases, []string{"JVNDB-2024-000001"}) ||
		!slices.Equal(got[0].Sources, []string{SourceOSV, SourceJVN}) || len(got[1].Aliases) != 0 {
		t.Errorf("enriched = %+v", got)
	}
	if len(in["pkg:npm/a@1"][0].Aliases) != 0 || len(in["pkg:npm/a@1"][0].Sources) != 1 {
		t.Error("the input map was modified")
	}
	// A failed lookup leaves every advisory as it was.
	failed := enrichAliases(context.Background(), fakeAliases{err: errors.New("down")}, in)
	if len(failed["pkg:npm/a@1"]) != 2 || len(failed["pkg:npm/a@1"][0].Aliases) != 0 {
		t.Errorf("after failure = %+v", failed)
	}
}
