package rootcause

import (
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/fixplan"
)

func TestFilterRootCauses(t *testing.T) {
	in := []fixplan.RootCause{
		{Kind: fixplan.KindPackageUpgrade, Title: "Upgrade log4js", Package: "log4js", Ecosystem: "npm",
			MaxSeverity: domain.SeverityCritical, KEV: 1},
		{Kind: fixplan.KindCodeLocation, Title: "Fix app.py", FilePath: "app.py",
			MaxSeverity: domain.SeverityLow, KEV: 0},
		{Kind: fixplan.KindPackageUpgrade, Title: "Upgrade requests", Package: "requests", Ecosystem: "pypi",
			MaxSeverity: domain.SeverityMedium, KEV: 0},
	}

	cases := []struct {
		name string
		f    Filter
		want []string // titles
	}{
		{"no filter", Filter{}, []string{"Upgrade log4js", "Fix app.py", "Upgrade requests"}},
		{"kind", Filter{Kind: fixplan.KindCodeLocation}, []string{"Fix app.py"}},
		{"ecosystem", Filter{Ecosystem: "npm"}, []string{"Upgrade log4js"}},
		{"kev only", Filter{KEVOnly: true}, []string{"Upgrade log4js"}},
		{"min severity", Filter{MinSeverity: domain.SeverityHigh}, []string{"Upgrade log4js"}},
		{"query matches package", Filter{Query: "REQUESTS"}, []string{"Upgrade requests"}},
		{"query matches file", Filter{Query: "app.py"}, []string{"Fix app.py"}},
		{"query matches nothing", Filter{Query: "nope"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := filterRootCauses(in, c.f)
			if len(got) != len(c.want) {
				t.Fatalf("filterRootCauses(%+v) = %d rows, want %d: %+v", c.f, len(got), len(c.want), got)
			}
			for i, w := range c.want {
				if got[i].Title != w {
					t.Errorf("row %d = %q, want %q", i, got[i].Title, w)
				}
			}
		})
	}
}
