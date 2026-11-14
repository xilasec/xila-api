package sbom_test

import (
	"os"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/sbom"
)

// licenseCase is the resolution expected for one component of a sample.
type licenseCase struct {
	expr     string
	ids      []string
	resolved bool
}

// resolveSample parses a real SBOM and resolves each component's license
// terms the way an upload does.
func resolveSample(t *testing.T, path string) map[string]licenseCase {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbom.Parse(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]licenseCase{}
	for _, c := range doc.Components {
		expr, ids, _, ok := license.Resolve(c.LicenseTerms)
		out[c.Name] = licenseCase{expr, ids, ok}
	}
	return out
}

func checkLicenses(t *testing.T, got, want map[string]licenseCase) {
	t.Helper()
	for name, w := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("%s: not in sample", name)
			continue
		}
		if g.expr != w.expr || !slices.Equal(g.ids, w.ids) || g.resolved != w.resolved {
			t.Errorf("%s: got %q %v resolved=%v, want %q %v resolved=%v", name, g.expr, g.ids, g.resolved, w.expr, w.ids, w.resolved)
		}
	}
}

// Components copied verbatim from the CycloneDX bom-examples dropwizard-1.3.15
// and keycloak-10.0.2 BOMs (cyclonedx-maven-plugin output,
// https://github.com/CycloneDX/bom-examples): every license shape Maven
// projects really emit — SPDX ids, free-text names, an expression, several
// entries, none.
func TestLicenseResolutionCycloneDX(t *testing.T) {
	checkLicenses(t, resolveSample(t, "testdata/licenses-maven.cdx.json"), map[string]licenseCase{
		"jackson-annotations": {"Apache-2.0", []string{"Apache-2.0"}, true},
		// Several entries all apply: AND.
		"javax.ws.rs-api": {"CDDL-1.1 AND GPL-2.0-with-classpath-exception",
			[]string{"CDDL-1.1", "GPL-2.0-with-classpath-exception"}, true},
		// A deprecated id still resolves.
		"jboss-dmr": {"LGPL-2.1 AND Apache-2.0", []string{"LGPL-2.1", "Apache-2.0"}, true},
		// The expression entry is taken as-is (normalized).
		"osgi-resource-locator": {"CDDL-1.0 OR GPL-2.0-with-classpath-exception",
			[]string{"CDDL-1.0", "GPL-2.0-with-classpath-exception"}, true},
		// Names resolved by the explicit alias table.
		"antlr":                {"BSD-3-Clause", []string{"BSD-3-Clause"}, true},
		"reactive-streams":     {"CC0-1.0", []string{"CC0-1.0"}, true},
		"junit-jupiter-engine": {"EPL-2.0", []string{"EPL-2.0"}, true},
		// Names we can't map are unresolved — never guessed — but the known
		// ids of a mixed list are kept.
		"bcprov-jdk15on":  {"", []string{}, false},
		"hibernate-core":  {"", []string{}, false},
		"logback-core":    {"", []string{"EPL-1.0"}, false},
		"dropwizard-util": {"", []string{}, false},
	})
}

// The SPDX 2.3 JSON example of spdx/tools-java (testResources/
// SPDXJSONExample-v2.3.spdx.json): concluded is preferred over declared,
// LicenseRef-* is kept, NOASSERTION is unresolved.
func TestLicenseResolutionSPDX(t *testing.T) {
	checkLicenses(t, resolveSample(t, "testdata/SPDXJSONExample-v2.3.spdx.json"), map[string]licenseCase{
		"glibc":               {"LGPL-2.0-only OR LicenseRef-3", []string{"LGPL-2.0-only", "LicenseRef-3"}, true},
		"Saxon":               {"MPL-1.0", []string{"MPL-1.0"}, true},
		"Apache Commons Lang": {"", []string{}, false},
		"Jena":                {"", []string{}, false},
	})
}

// CycloneDX 1.6 acknowledgements: concluded entries win over declared ones.
func TestLicenseTermsConcludedWins(t *testing.T) {
	doc, err := sbom.Parse([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
		{"name":"a","licenses":[
			{"license":{"id":"GPL-3.0-only","acknowledgement":"declared"}},
			{"expression":"MIT OR Apache-2.0","acknowledgement":"concluded"}]},
		{"name":"b","licenses":[{"license":{"id":"MIT"}},{"license":{"name":"Apache 2.0"}}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := doc.Components[0].LicenseTerms; !slices.Equal(got, []string{"MIT OR Apache-2.0"}) {
		t.Errorf("concluded terms = %q", got)
	}
	if got := doc.Components[1].LicenseTerms; !slices.Equal(got, []string{"MIT", "Apache 2.0"}) {
		t.Errorf("terms = %q", got)
	}
	// The raw column is unchanged.
	if doc.Components[0].License != "GPL-3.0-only, MIT OR Apache-2.0" {
		t.Errorf("raw license = %q", doc.Components[0].License)
	}
}

// SPDX carries a package's CPE as a SECURITY external ref; it's what NVD
// matching keys on for packages without a purl.
func TestSPDXCarriesCPE(t *testing.T) {
	b, err := os.ReadFile("testdata/SPDXJSONExample-v2.3.spdx.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := sbom.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range doc.Components {
		got[c.Name] = c.Cpe
	}
	if got["glibc"] != "cpe:2.3:a:pivotal_software:spring_framework:4.1.0:*:*:*:*:*:*:*" || got["Saxon"] != "" {
		t.Errorf("CPEs = %v", got)
	}
}
