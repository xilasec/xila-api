package policy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/policy"
	"github.com/xilasec/xila-api/internal/sbom"
)

// The dependency-graph functions (M13 13.20) judge each component in its own
// snapshot's graph: app -> express -> qs, app -> @babel/core.
func TestGraphFunctionsInPolicies(t *testing.T) {
	e := setup(t)
	p := e.project()
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5",
	  "metadata":{"component":{"bom-ref":"app","name":"app","version":"1"}},
	  "components":[
	    {"bom-ref":"express","type":"library","name":"express","version":"4.18.0","purl":"pkg:npm/express@4.18.0"},
	    {"bom-ref":"qs","type":"library","name":"qs","version":"6.7.0","purl":"pkg:npm/qs@6.7.0"},
	    {"bom-ref":"babel","type":"library","group":"@babel","name":"core","version":"7.0.0","purl":"pkg:npm/%40babel/core@7.0.0"}],
	  "dependencies":[
	    {"ref":"app","dependsOn":["express","babel"]},
	    {"ref":"express","dependsOn":["qs"]}]}`
	upload := func() {
		t.Helper()
		if _, err := e.sboms.Ingest(e.ctx, sbom.IngestRequest{ProjectID: p, Artifact: "app"}, strings.NewReader(doc)); err != nil {
			t.Fatalf("upload: %v", err)
		}
	}
	hits := func(expression string) []string {
		t.Helper()
		pol := e.create(draft("graph", cond(policy.SubjectExpression, policy.OpMatches, `"`+strings.ReplaceAll(expression, `"`, `\"`)+`"`)))
		defer func() { _ = e.policies.Delete(e.ctx, pol.ID) }()
		upload()
		var names []string
		for _, v := range open(e.violations(p)) {
			if v.RuleID == pol.ID {
				names = append(names, v.PackageName)
			}
		}
		slices.Sort(names)
		return names
	}
	for _, tc := range []struct {
		expression string
		want       []string
	}{
		{`is_dependency_of("pkg:npm/express")`, []string{"qs"}},
		{`is_direct_dependency_of("re:^pkg:npm/express@")`, []string{"qs"}},
		{`depends_on("pkg:npm/qs")`, []string{"express"}},
		// Exact patterns compare the package without percent-encoding.
		{`component.name == "core" && !depends_on("pkg:npm/@babel/core")`, []string{"core"}},
		{`is_exclusive_dependency_of("pkg:npm/express")`, []string{"qs"}},
		{`component.direct == true`, []string{"core", "express"}},
	} {
		if got := hits(tc.expression); !slices.Equal(got, tc.want) {
			t.Errorf("%s matched %v, want %v", tc.expression, got, tc.want)
		}
	}
}
