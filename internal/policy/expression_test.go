package policy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/license"
)

func exprCond(t *testing.T, src string) (compiled, error) {
	t.Helper()
	v, _ := json.Marshal(src)
	return compile(Condition{Subject: SubjectExpression, Operator: OpMatches, Value: v}, nil, ComponentSchema)
}

func TestExpressionConditions(t *testing.T) {
	crit := domain.SeverityCritical
	behind := 4
	gpl, _ := license.ParseExpression("GPL-3.0-only OR MIT")
	known := &Component{
		Group: "org.apache.logging.log4j", Name: "log4j-core", Version: "2.14.1", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		VulnIDs: []string{"CVE-2021-44228"}, MaxSeverity: &crit, KEV: true, ProjectName: "web",
		License: gpl,
		Meta:    &PackageInfo{Latest: "2.24.0", Outdated: true, VersionsBehind: &behind},
	}
	// Nothing known beyond its name: no vulns, no license, no registry data.
	unknown := &Component{Name: "mystery", Version: "0.1"}

	cases := []struct {
		src            string
		known, unknown bool
	}{
		{`component.name == "log4j-core" && vulns.kev`, true, false},
		{`vulns.max_severity_rank >= 4 && component.purl.startsWith("pkg:maven/")`, true, false},
		{`"GPL-3.0-only" in component.license.ids`, true, false},
		{`pkg.versions_behind >= 3`, true, false},
		{`vulns.count == 0`, false, true},
		{`project.name == "web"`, true, false},
		// Unknown never matches — whichever way the expression is phrased.
		{`pkg.outdated`, true, false},
		{`!pkg.outdated`, false, false}, // not "up to date" either
		{`pkg.versions_behind < 1`, false, false},
		{`vulns.epss >= 0.5`, false, false}, // no EPSS on either
		{`component.license.resolved == false`, false, false},
	}
	now := time.Now()
	for _, c := range cases {
		cc, err := exprCond(t, c.src)
		if err != nil {
			t.Errorf("%s: %v", c.src, err)
			continue
		}
		if got, _ := cc.match(known, now); got != c.known {
			t.Errorf("%s on log4j = %v, want %v", c.src, got, c.known)
		}
		if got, _ := cc.match(unknown, now); got != c.unknown {
			t.Errorf("%s on an unknown component = %v, want %v", c.src, got, c.unknown)
		}
	}
}

// Mistakes are caught when the policy is saved, with a message that says what.
func TestExpressionRejectedOnSave(t *testing.T) {
	for src, want := range map[string]string{
		`component.name ==`:                "Syntax error",
		`component.name`:                   "true or false",
		`component.nmae == "x"`:            "no such key",
		`vulns.kev && compnent.name == ""`: "undeclared reference",
		``:                                 "empty",
		strings.Repeat("a", 5000):          "longer than",
	} {
		_, err := exprCond(t, src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.40q: %v, want an error mentioning %q", src, err, want)
		}
	}
}
