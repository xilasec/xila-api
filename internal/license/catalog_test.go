package license

import (
	"slices"
	"testing"
)

func TestLookup(t *testing.T) {
	cases := []struct {
		in   string
		want Info
	}{
		{"mit", Info{ID: "MIT", Name: "MIT License", OSIApproved: true, FSFLibre: true, Category: CategoryPermissive}},
		{" APACHE-2.0 ", Info{ID: "Apache-2.0", Name: "Apache License 2.0", OSIApproved: true, FSFLibre: true, Category: CategoryPermissive}},
		{"gpl-3.0-only", Info{ID: "GPL-3.0-only", Name: "GNU General Public License v3.0 only", OSIApproved: true, FSFLibre: true, Category: CategoryCopyleft}},
		// Deprecated ids resolve, flagged, and keep a category via ScanCode's
		// alternative SPDX keys.
		{"gpl-2.0", Info{ID: "GPL-2.0", Name: "GNU General Public License v2.0 only", OSIApproved: true, FSFLibre: true, Deprecated: true, Category: CategoryCopyleft}},
		{"LGPL-2.1-only", Info{ID: "LGPL-2.1-only", Name: "GNU Lesser General Public License v2.1 only", OSIApproved: true, FSFLibre: true, Category: CategoryCopyleftLimited}},
	}
	for _, tc := range cases {
		got, ok := Lookup(tc.in)
		got.Terms = nil // asserted in TestTerms
		if !ok || got != tc.want {
			t.Errorf("Lookup(%q) = %+v, %v; want %+v", tc.in, got, ok, tc.want)
		}
	}
	if info, ok := Lookup("licenseref-scancode-public-domain"); !ok || info.ID != "LicenseRef-scancode-public-domain" || info.Category != CategoryPublicDomain {
		t.Errorf("ScanCode key = %+v, %v", info, ok)
	}
	for _, missing := range []string{"", "Not-A-License", "Classpath-exception-2.0"} {
		if _, ok := Lookup(missing); ok {
			t.Errorf("Lookup(%q) found something", missing)
		}
	}
	if e, ok := LookupException("classpath-exception-2.0"); !ok || e.ID != "Classpath-exception-2.0" {
		t.Errorf("LookupException = %+v, %v", e, ok)
	}
}

func TestCatalog(t *testing.T) {
	if CatalogVersion() == "" {
		t.Error("no list version")
	}
	all := Search(CatalogFilter{})
	if len(all) < 600 {
		t.Fatalf("catalog has %d licenses", len(all))
	}
	if !slices.IsSortedFunc(all, func(a, b Info) int {
		if a.ID < b.ID {
			return -1
		}
		return 1
	}) {
		t.Error("catalog not sorted by id")
	}
	osi := true
	for _, l := range Search(CatalogFilter{Query: "gpl", Category: "copyleft", OSI: &osi}) {
		if l.Category != CategoryCopyleft || !l.OSIApproved {
			t.Errorf("filtered result %+v", l)
		}
	}
	if got := Search(CatalogFilter{Query: "zero clause"}); len(got) == 0 || got[0].ID != "0BSD" {
		t.Errorf("name search = %v", got)
	}
}

func TestCategoryMembers(t *testing.T) {
	perm := CategoryMembers("permissive")
	for _, id := range []string{"MIT", "Apache-2.0", "BSD-3-Clause"} {
		if !slices.Contains(perm, id) {
			t.Errorf("Permissive lacks %s", id)
		}
	}
	if slices.Contains(perm, "GPL-3.0-only") {
		t.Error("Permissive contains GPL-3.0-only")
	}
	if !slices.Contains(CategoryMembers(CategoryCopyleft), "GPL-2.0") {
		t.Error("Copyleft lacks the deprecated GPL-2.0")
	}
	if CategoryMembers("Nope") != nil {
		t.Error("unknown category has members")
	}
	// Every member resolves back to its category.
	for _, cat := range Categories() {
		for _, id := range CategoryMembers(cat) {
			if info, ok := Lookup(id); !ok || info.Category != cat {
				t.Fatalf("%s in %s, but Lookup = %+v, %v", id, cat, info, ok)
			}
		}
	}
}

func TestResolve(t *testing.T) {
	cases := []struct {
		name     string
		terms    []string
		expr     string
		ids      []string
		cats     []string
		resolved bool
	}{
		{"none", nil, "", []string{}, []string{}, false},
		{"noassertion", []string{"NOASSERTION"}, "", []string{}, []string{}, false},
		{"single id", []string{"mit"}, "MIT", []string{"MIT"}, []string{CategoryPermissive}, true},
		{"several entries combine with AND", []string{"MIT", "GPL-3.0-or-later OR Apache-2.0"},
			"MIT AND (GPL-3.0-or-later OR Apache-2.0)", []string{"MIT", "GPL-3.0-or-later", "Apache-2.0"},
			[]string{CategoryPermissive, CategoryCopyleft}, true},
		{"license name", []string{"Apache License, Version 2.0"}, "Apache-2.0", []string{"Apache-2.0"}, []string{CategoryPermissive}, true},
		{"unknown id", []string{"Foo-1.0"}, "Foo-1.0", []string{"Foo-1.0"}, []string{}, false},
		{"unparseable term keeps the known ids", []string{"MIT", "My Company Proprietary"}, "", []string{"MIT"},
			[]string{CategoryPermissive}, false},
	}
	for _, tc := range cases {
		expr, ids, cats, ok := Resolve(tc.terms)
		if expr != tc.expr || !slices.Equal(ids, tc.ids) || !slices.Equal(cats, tc.cats) || ok != tc.resolved {
			t.Errorf("%s: Resolve(%q) = %q %v %v %v; want %q %v %v %v", tc.name, tc.terms,
				expr, ids, cats, ok, tc.expr, tc.ids, tc.cats, tc.resolved)
		}
	}
}

func TestNormalizeIDs(t *testing.T) {
	got, err := NormalizeIDs([]string{"mit", "MIT", " apache-2.0", "LicenseRef-internal", ""})
	if err != nil || !slices.Equal(got, []string{"Apache-2.0", "LicenseRef-internal", "MIT"}) {
		t.Errorf("NormalizeIDs = %v, %v", got, err)
	}
	if _, err := NormalizeIDs([]string{"MIT", "Bogus-1", "Classpath-exception-2.0"}); err == nil {
		t.Error("unknown ids accepted")
	}
}

// choosealicense.com's terms reach the catalog, also for licenses it names by
// a deprecated SPDX id (its GPL-3.0 is GPL-3.0-only and -or-later).
func TestTerms(t *testing.T) {
	mit, _ := Lookup("MIT")
	if mit.Terms == nil || !slices.Contains(mit.Terms.Permissions, "commercial-use") ||
		!slices.Equal(mit.Terms.Conditions, []string{"include-copyright"}) || !slices.Contains(mit.Terms.Limitations, "liability") {
		t.Errorf("MIT terms = %+v", mit.Terms)
	}
	for _, id := range []string{"GPL-3.0-only", "GPL-3.0-or-later"} {
		gpl, _ := Lookup(id)
		if gpl.Terms == nil || !slices.Contains(gpl.Terms.Conditions, "disclose-source") || !slices.Contains(gpl.Terms.Conditions, "same-license") {
			t.Errorf("%s terms = %+v", id, gpl.Terms)
		}
	}
	if odd, ok := Lookup("Beerware"); !ok || odd.Terms != nil {
		t.Errorf("Beerware (not on choosealicense.com) = %+v, %v; want found without terms", odd, ok)
	}
}
