package vulnmatch

import (
	"context"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/sbom"
)

// recordingCPE is a CPESource recording what it was asked.
type recordingCPE struct{ got []string }

func (r *recordingCPE) QueryCPE(_ context.Context, cpes []string) (map[string][]Vuln, error) {
	r.got = append(r.got, cpes...)
	return map[string][]Vuln{}, nil
}

// An internal (first-party) component's name never reaches an online source
// (M13 13.11): its purl only goes to private sources, and an internal
// CPE-only component isn't sent to NVD at all. A key internal in any row
// counts as internal.
func TestInternalComponentsStayPrivate(t *testing.T) {
	online := &fakeSource{byPurl: map[string][]Vuln{}}
	private := &fakeSource{byPurl: map[string][]Vuln{
		"pkg:npm/%40acme/billing@1.0.0": {{ID: "ACME-2026-1", Severity: domain.SeverityHigh}},
	}}
	cpe := &recordingCPE{}
	m := NewMultiSource(NamedSource{Name: SourceOSV, Source: online}, NamedSource{Name: SourcePrivate, Source: private, Private: true})
	m.cpe = cpe

	inv := &fakeInventory{items: []sbom.SnapshotComponent{
		{SbomID: "s1", ProjectID: "p1", Name: "billing", Version: "1.0.0", Purl: "pkg:npm/%40acme/billing@1.0.0", Internal: true, Current: true},
		// The same key, not marked internal in an older snapshot: still internal.
		{SbomID: "s0", ProjectID: "p1", Name: "billing", Version: "1.0.0", Purl: "pkg:npm/%40acme/billing@1.0.0"},
		{SbomID: "s1", ProjectID: "p1", Name: "lodash", Version: "4.17.20", Purl: "pkg:npm/lodash@4.17.20", Current: true},
		{SbomID: "s1", ProjectID: "p1", Name: "firmware", Cpe: "cpe:2.3:a:acme:firmware:2.0:*:*:*:*:*:*:*", Internal: true, Current: true},
		{SbomID: "s1", ProjectID: "p1", Name: "openssl", Cpe: "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", Current: true},
	}}
	app := &fakeApplier{}
	if _, err := NewService(inv, app, m).Match(context.Background()); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !slices.Equal(online.gotPurls, []string{"pkg:npm/lodash@4.17.20"}) {
		t.Errorf("online source asked about %v, want only the external purl", online.gotPurls)
	}
	if !slices.Contains(private.gotPurls, "pkg:npm/%40acme/billing@1.0.0") {
		t.Errorf("private source asked about %v, want the internal purl too", private.gotPurls)
	}
	if !slices.Equal(cpe.got, []string{"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}) {
		t.Errorf("NVD asked about %v, want only the external CPE", cpe.got)
	}
	var found bool
	for _, c := range app.calls {
		for _, f := range c.findings {
			found = found || slices.Contains([]string{f.RuleID}, "ACME-2026-1")
		}
	}
	if !found {
		t.Errorf("the private advisory on the internal component made no finding: %+v", app.calls)
	}
}
