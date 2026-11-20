package component

import "testing"

func TestMatcherGlob(t *testing.T) {
	m, err := Compile([]Pattern{
		{Ecosystem: "npm", GroupPattern: "@acme/*", PatternType: PatternGlob},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !m.Match("npm", "@acme/widgets", "core") {
		t.Error("expected @acme/* to match @acme/widgets")
	}
	if m.Match("npm", "@other/widgets", "core") {
		t.Error("expected @acme/* not to match @other/widgets")
	}
	if m.Match("pypi", "@acme/widgets", "core") {
		t.Error("expected ecosystem npm not to match pypi")
	}
}

func TestMatcherRegexNameOnly(t *testing.T) {
	m, err := Compile([]Pattern{
		{NamePattern: `^internal-.*`, PatternType: PatternRegex},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !m.Match("maven", "com.example", "internal-lib") {
		t.Error("expected internal-* name to match regardless of ecosystem/group")
	}
	if m.Match("maven", "com.example", "public-lib") {
		t.Error("expected public-lib not to match")
	}
}

func TestMatcherAnyEcosystemBothPatterns(t *testing.T) {
	m, err := Compile([]Pattern{
		{GroupPattern: "com.acme.*", NamePattern: "*", PatternType: PatternGlob},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !m.Match("maven", "com.acme.payments", "service") {
		t.Error("expected group pattern to match")
	}
	if m.Match("maven", "com.other", "service") {
		t.Error("expected non-matching group not to match")
	}
}

func TestMatcherNilNeverMatches(t *testing.T) {
	var m *Matcher
	if m.Match("npm", "x", "y") {
		t.Error("a nil matcher should never match")
	}
}

func TestPatternValidate(t *testing.T) {
	cases := []struct {
		name string
		p    Pattern
		ok   bool
	}{
		{"both empty", Pattern{}, false},
		{"name only", Pattern{NamePattern: "foo-*"}, true},
		{"bad regex", Pattern{NamePattern: "foo-[", PatternType: PatternRegex}, false},
		{"bad type", Pattern{NamePattern: "foo", PatternType: "fnmatch"}, false},
		{"default type is glob", Pattern{NamePattern: "foo-*"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if tc.ok && err != nil {
				t.Errorf("expected valid, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("expected an error")
			}
		})
	}
}
