package sbom

import (
	"slices"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.10", -1}, // numeric, not lexical
		{"4.17.21", "4.17.20", 1},
		{"v2.0.0", "2.0.0", 0}, // leading v ignored
		{"1.2", "1.2.1", -1},
		{"1.0.0-rc1", "1.0.0", -1}, // pre-release before release
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0+build5", "1.0.0+build9", 0}, // build metadata ignored
		{"1.10rc2", "1.10rc10", -1},
		{"2.0.0.Final", "2.0.0.1", -1}, // a number outranks a word
		{"1:2.3-4ubuntu1", "1:2.3-4ubuntu2", -1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareVersions(tc.b, tc.a); got != -tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d (antisymmetric)", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestPackageKeyIgnoresVersionAndQualifiers(t *testing.T) {
	cases := map[string]Component{
		"pkg:npm/lodash":                  {Purl: "pkg:npm/lodash@4.17.21"},
		"pkg:npm/%40babel/core":           {Purl: "pkg:npm/%40babel/core@7.0.0"},
		"pkg:maven/org.apache/log4j-core": {Purl: "pkg:maven/org.apache/log4j-core@2.14.1?type=jar#sub"},
		"pkg:golang/example.com/m/v2":     {Purl: "pkg:golang/example.com/m/v2@v2.1.0"},
		"library/org.acme/thing":          {Type: "library", Group: "org.acme", Name: "Thing", Version: "1"},
	}
	for want, c := range cases {
		if got := packageKey(c); got != want {
			t.Errorf("packageKey(%+v) = %q, want %q", c, got, want)
		}
	}
}

func hit(name, version string, vulns ...string) ComponentHit {
	return ComponentHit{
		Component: Component{Name: name, Version: version, Purl: "pkg:npm/" + name + "@" + version},
		VulnState: VulnState{Vulns: vulns},
	}
}

func TestDiffComponents(t *testing.T) {
	base := []ComponentHit{
		hit("express", "4.17.0"),
		hit("qs", "6.5.2", "CVE-2022-24999"),
		hit("lodash", "4.17.21"),
		hit("left-pad", "1.0.0"),
		hit("react", "18.2.0"),
		hit("tslib", "1.14.1"), hit("tslib", "2.6.0"),
	}
	head := []ComponentHit{
		hit("express", "4.18.2"),
		hit("qs", "6.11.0"),                        // upgrade fixes the CVE
		hit("lodash", "4.17.20", "CVE-2021-23337"), // downgrade brings one in
		hit("axios", "1.6.0"),
		hit("react", "18.2.0"),
		hit("tslib", "2.6.0"), // several versions → one: direction undecidable
	}
	changes, unchanged, sum := DiffComponents(base, head)

	got := map[string]PackageDiff{}
	for _, c := range changes {
		got[c.Name] = c
	}
	want := map[string]Change{
		"express": ChangeUpgraded, "qs": ChangeUpgraded, "lodash": ChangeDowngraded,
		"axios": ChangeAdded, "left-pad": ChangeRemoved, "tslib": ChangeChanged,
	}
	if len(got) != len(want) || unchanged != 1 {
		t.Fatalf("changes = %v, unchanged = %d; want %d changes and react unchanged", changes, unchanged, len(want))
	}
	for name, change := range want {
		if got[name].Change != change {
			t.Errorf("%s: change = %q, want %q", name, got[name].Change, change)
		}
	}
	if q := got["qs"]; !slices.Equal(q.From, []string{"6.5.2"}) || !slices.Equal(q.To, []string{"6.11.0"}) ||
		!slices.Equal(q.FixedVulns, []string{"CVE-2022-24999"}) || len(q.IntroducedVulns) != 0 {
		t.Errorf("qs diff = %+v, want 6.5.2 → 6.11.0 fixing CVE-2022-24999", q)
	}
	if l := got["lodash"]; !slices.Equal(l.IntroducedVulns, []string{"CVE-2021-23337"}) {
		t.Errorf("lodash introduced = %v, want the downgrade's CVE", l.IntroducedVulns)
	}
	if !slices.Equal(sum.VulnsFixed, []string{"CVE-2022-24999"}) || !slices.Equal(sum.VulnsIntroduced, []string{"CVE-2021-23337"}) {
		t.Errorf("summary vulns = fixed %v introduced %v", sum.VulnsFixed, sum.VulnsIntroduced)
	}
	if sum.Added != 1 || sum.Removed != 1 || sum.Upgraded != 2 || sum.Downgraded != 1 || sum.Changed != 1 {
		t.Errorf("summary counts = %+v", sum)
	}

	// First snapshot of an artifact: everything is added.
	changes, _, sum = DiffComponents(nil, head)
	if len(changes) != 6 || sum.Added != 6 || len(sum.VulnsIntroduced) != 1 {
		t.Errorf("diff against nothing = %d changes, summary %+v; want all 6 packages added", len(changes), sum)
	}
}

func TestGraphPaths(t *testing.T) {
	s := Sbom{ID: "s", RootRef: "app", Artifact: "app"}
	comps := []ComponentHit{
		{Component: Component{ID: "1", BomRef: "express", Name: "express"}},
		{Component: Component{ID: "2", BomRef: "body-parser", Name: "body-parser"}},
		{Component: Component{ID: "3", BomRef: "qs", Name: "qs"}},
		{Component: Component{ID: "4", Name: "unlisted"}}, // no bom-ref: present, unconnected
	}
	svcs := []BomService{{ID: "s1", BomRef: "payments-api", Name: "Payments API"}}
	edges := []Edge{
		{"app", "express"}, {"express", "qs"}, {"express", "body-parser"},
		{"body-parser", "qs"}, {"qs", "express"}, // a cycle must not loop
		{"app", "ghost"},        // a ref no component declares
		{"app", "payments-api"}, // a service, not a missing component
	}
	g := BuildGraph(s, comps, svcs, edges)

	byRef := map[string]Node{}
	for _, n := range g.Nodes {
		byRef[n.Ref] = n
	}
	if !byRef["app"].Root || byRef["app"].Name != "app" || byRef["app"].ComponentID != nil {
		t.Errorf("root node = %+v, want synthesized from the artifact", byRef["app"])
	}
	if !byRef["ghost"].Missing || byRef[unrefPrefix+"4"].Name != "unlisted" {
		t.Errorf("missing/unreferenced nodes not represented: %+v / %+v", byRef["ghost"], byRef[unrefPrefix+"4"])
	}
	if n := byRef["payments-api"]; n.Kind != "service" || n.Missing || n.ServiceID == nil || *n.ServiceID != "s1" ||
		n.Name != "Payments API" || byRef["express"].Kind != "component" {
		t.Errorf("service node = %+v, express kind %q; want a typed service node", n, byRef["express"].Kind)
	}

	paths := g.Paths("qs", MaxPaths)
	want := [][]string{{"app", "express", "qs"}, {"app", "express", "body-parser", "qs"}}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if !slices.Equal(paths[i], want[i]) {
			t.Errorf("path %d = %v, want %v (shortest first)", i, paths[i], want[i])
		}
	}
	if p := g.Paths("qs", 1); len(p) != 1 {
		t.Errorf("limit not honored: %v", p)
	}

	// No root named: entry points are the nodes nothing depends on.
	g = BuildGraph(Sbom{ID: "s"}, comps, nil, []Edge{{"express", "qs"}})
	if p := g.Paths("qs", MaxPaths); len(p) != 1 || !slices.Equal(p[0], []string{"express", "qs"}) {
		t.Errorf("rootless paths = %v, want [[express qs]]", p)
	}
}

func TestTimelineSettle(t *testing.T) {
	tl := func(affected ...bool) ArtifactTimeline {
		var a ArtifactTimeline
		for i, x := range affected {
			a.Snapshots = append(a.Snapshots, TimelineSnapshot{Version: string(rune('a' + i)), Affected: x})
		}
		a.settle()
		return a
	}
	ver := func(s *TimelineSnapshot) string {
		if s == nil {
			return "-"
		}
		return s.Version
	}
	cases := []struct {
		affected          []bool
		introduced, fixed string
		current           bool
	}{
		{[]bool{false, true, true, false}, "b", "d", false},
		{[]bool{true, true}, "a", "-", true},        // shipped from the first release, never fixed
		{[]bool{true, false, true}, "c", "-", true}, // reintroduced: the latest introduction counts
		{[]bool{false, true, false, false}, "b", "c", false},
	}
	for _, tc := range cases {
		got := tl(tc.affected...)
		if ver(got.IntroducedIn) != tc.introduced || ver(got.FixedIn) != tc.fixed || got.CurrentlyAffected != tc.current {
			t.Errorf("%v: introduced %s fixed %s current %v, want %s %s %v", tc.affected,
				ver(got.IntroducedIn), ver(got.FixedIn), got.CurrentlyAffected, tc.introduced, tc.fixed, tc.current)
		}
	}
}

func TestParsersKeepTheGraph(t *testing.T) {
	cdx, err := Parse([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5",
		"metadata":{"component":{"bom-ref":"app","name":"app"}},
		"components":[{"bom-ref":"a","name":"a"},{"bom-ref":"b","name":"b"}],
		"dependencies":[{"ref":"app","dependsOn":["a"]},{"ref":"a","dependsOn":["b"]}]}`))
	if err != nil {
		t.Fatalf("cyclonedx: %v", err)
	}
	if cdx.RootRef != "app" || len(cdx.Edges) != 2 || cdx.Components[0].BomRef != "a" {
		t.Errorf("cyclonedx graph = root %q edges %v refs %q", cdx.RootRef, cdx.Edges, cdx.Components[0].BomRef)
	}

	// Two described packages: the document itself becomes the root.
	spdx, err := Parse([]byte(`{"spdxVersion":"SPDX-2.3","name":"doc",
		"packages":[{"SPDXID":"SPDXRef-app","name":"app"},{"SPDXID":"SPDXRef-cli","name":"cli"},{"SPDXID":"SPDXRef-x","name":"x"}],
		"relationships":[
			{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-app"},
			{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-cli"},
			{"spdxElementId":"SPDXRef-x","relationshipType":"DEV_DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-app"}]}`))
	if err != nil {
		t.Fatalf("spdx: %v", err)
	}
	var edges []string
	for _, e := range spdx.Edges {
		edges = append(edges, e.Parent+">"+e.Child)
	}
	slices.Sort(edges)
	if spdx.RootRef != spdxRoot || strings.Join(edges, ",") !=
		"SPDXRef-DOCUMENT>SPDXRef-app,SPDXRef-DOCUMENT>SPDXRef-cli,SPDXRef-app>SPDXRef-x" {
		t.Errorf("spdx graph = root %q edges %v", spdx.RootRef, edges)
	}
}
