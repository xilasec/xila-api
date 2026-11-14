package license

import (
	"errors"
	"slices"
	"testing"
)

// Cases from SPDX 2.3 Annex D ("SPDX License Expressions") plus the
// normalizations Xila applies.
func TestParseExpression(t *testing.T) {
	cases := []struct {
		in, want string
		ids      []string
		resolved bool
	}{
		// D.2 simple expressions.
		{"CDDL-1.0", "CDDL-1.0", []string{"CDDL-1.0"}, true},
		{"CDDL-1.0+", "CDDL-1.0+", []string{"CDDL-1.0"}, true},
		{"LicenseRef-23", "LicenseRef-23", []string{"LicenseRef-23"}, true},
		{"LicenseRef-MIT-Style-1", "LicenseRef-MIT-Style-1", []string{"LicenseRef-MIT-Style-1"}, true},
		{"DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2", "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2",
			[]string{"DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2"}, true},
		// D.4 composite expressions.
		{"LGPL-2.1-only OR MIT", "LGPL-2.1-only OR MIT", []string{"LGPL-2.1-only", "MIT"}, true},
		{"LGPL-2.1-only OR MIT OR BSD-3-Clause", "LGPL-2.1-only OR MIT OR BSD-3-Clause",
			[]string{"LGPL-2.1-only", "MIT", "BSD-3-Clause"}, true},
		{"LGPL-2.1-only AND MIT", "LGPL-2.1-only AND MIT", []string{"LGPL-2.1-only", "MIT"}, true},
		{"LGPL-2.1-only AND MIT AND BSD-2-Clause", "LGPL-2.1-only AND MIT AND BSD-2-Clause",
			[]string{"LGPL-2.1-only", "MIT", "BSD-2-Clause"}, true},
		{"GPL-2.0-or-later WITH Bison-exception-2.2", "GPL-2.0-or-later WITH Bison-exception-2.2",
			[]string{"GPL-2.0-or-later"}, true},
		// Precedence: WITH > AND > OR, so these need no parentheses…
		{"LGPL-2.1-only OR BSD-3-Clause AND MIT", "LGPL-2.1-only OR BSD-3-Clause AND MIT",
			[]string{"LGPL-2.1-only", "BSD-3-Clause", "MIT"}, true},
		// …while an OR inside an AND keeps them.
		{"MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)", "MIT AND (LGPL-2.1-or-later OR BSD-3-Clause)",
			[]string{"MIT", "LGPL-2.1-or-later", "BSD-3-Clause"}, true},
		// Redundant parentheses and same-operator nesting are flattened.
		{"((MIT))", "MIT", []string{"MIT"}, true},
		{"(MIT AND Apache-2.0) AND ISC", "MIT AND Apache-2.0 AND ISC", []string{"MIT", "Apache-2.0", "ISC"}, true},
		{"(MIT AND Apache-2.0) OR ISC", "MIT AND Apache-2.0 OR ISC", []string{"MIT", "Apache-2.0", "ISC"}, true},
		// Case-insensitive ids and operators, canonical output; whitespace.
		{"  mit   or apache-2.0 ", "MIT OR Apache-2.0", []string{"MIT", "Apache-2.0"}, true},
		{"gpl-2.0-only with classpath-exception-2.0", "GPL-2.0-only WITH Classpath-exception-2.0", []string{"GPL-2.0-only"}, true},
		// Deprecated ids are recognized (and flagged by Lookup).
		{"GPL-2.0", "GPL-2.0", []string{"GPL-2.0"}, true},
		{"GPL-2.0+", "GPL-2.0+", []string{"GPL-2.0"}, true},
		// Ids repeat once in IDs().
		{"MIT OR (MIT AND ISC)", "MIT OR MIT AND ISC", []string{"MIT", "ISC"}, true},
		// Well-formed but unknown: parses, unresolved.
		{"Foo-1.0 OR MIT", "Foo-1.0 OR MIT", []string{"Foo-1.0", "MIT"}, false},
		{"MIT WITH Not-An-Exception", "MIT WITH Not-An-Exception", []string{"MIT"}, false},
		{"MIT WITH AdditionRef-mine", "MIT WITH AdditionRef-mine", []string{"MIT"}, true},
		// ScanCode keys resolve with their canonical case.
		{"licenseref-scancode-public-domain", "LicenseRef-scancode-public-domain", []string{"LicenseRef-scancode-public-domain"}, true},
		// Whole-string aliases and SPDX full names.
		{"Apache 2.0", "Apache-2.0", []string{"Apache-2.0"}, true},
		{"The Apache Software License, Version 2.0", "Apache-2.0", []string{"Apache-2.0"}, true},
		{"MIT License", "MIT", []string{"MIT"}, true},
		{"Apache License 2.0", "Apache-2.0", []string{"Apache-2.0"}, true},
		{"BSD", "BSD-3-Clause", []string{"BSD-3-Clause"}, true},
		{"GNU General Public License v3 (GPLv3)", "GPL-3.0", []string{"GPL-3.0"}, true},
	}
	for _, tc := range cases {
		e, err := ParseExpression(tc.in)
		if err != nil {
			t.Errorf("ParseExpression(%q): %v", tc.in, err)
			continue
		}
		if got := e.String(); got != tc.want {
			t.Errorf("ParseExpression(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
		if got := e.IDs(); !slices.Equal(got, tc.ids) {
			t.Errorf("ParseExpression(%q).IDs() = %v, want %v", tc.in, got, tc.ids)
		}
		if got := e.Resolved(); got != tc.resolved {
			t.Errorf("ParseExpression(%q).Resolved() = %v, want %v (unknown %v)", tc.in, got, tc.resolved, e.Unknown())
		}
		// Normalized output re-parses to itself.
		again, err := ParseExpression(e.String())
		if err != nil || again.String() != e.String() {
			t.Errorf("re-parse of %q = %q, %v", e.String(), again.String(), err)
		}
	}
}

func TestParseExpressionErrors(t *testing.T) {
	for _, in := range []string{
		"", "   ", "MIT AND", "AND MIT", "MIT OR OR ISC", "(MIT", "MIT)", "()", "MIT ISC",
		"MIT WITH", "MIT WITH (ISC)", "(MIT) WITH Classpath-exception-2.0", "MIT WITH A WITH B",
		"Some Custom License", "MIT/ISC", "LicenseRef-a+", "GPL-2.0++", "+",
	} {
		if e, err := ParseExpression(in); !errors.Is(err, ErrInvalidExpression) {
			t.Errorf("ParseExpression(%q) = %q, %v; want ErrInvalidExpression", in, e.String(), err)
		}
	}
	for _, in := range []string{"NONE", "NOASSERTION", "noassertion"} {
		if _, err := ParseExpression(in); !errors.Is(err, ErrNoAssertion) {
			t.Errorf("ParseExpression(%q) err = %v, want ErrNoAssertion", in, err)
		}
	}
	deep := ""
	for range maxDepth + 1 {
		deep += "("
	}
	if _, err := ParseExpression(deep + "MIT"); !errors.Is(err, ErrInvalidExpression) {
		t.Errorf("deeply nested: err = %v", err)
	}
}

func TestExceptionsAndUnknown(t *testing.T) {
	e, err := ParseExpression("GPL-2.0-only WITH classpath-exception-2.0 OR LicenseRef-x OR Weird-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := e.Exceptions(); !slices.Equal(got, []string{"Classpath-exception-2.0"}) {
		t.Errorf("Exceptions() = %v", got)
	}
	if got := e.Unknown(); !slices.Equal(got, []string{"Weird-1"}) {
		t.Errorf("Unknown() = %v", got)
	}
}

func TestSatisfies(t *testing.T) {
	allow := func(ids ...string) func(string) bool {
		return func(id string) bool { return slices.Contains(ids, id) }
	}
	cases := []struct {
		expr    string
		allowed []string
		want    bool
	}{
		{"MIT", []string{"MIT"}, true},
		{"MIT", []string{"ISC"}, false},
		// OR: any one branch is enough.
		{"GPL-3.0-only OR MIT", []string{"MIT"}, true},
		{"GPL-3.0-only OR MIT", []string{"Apache-2.0"}, false},
		// AND: every branch must be allowed.
		{"MIT AND GPL-3.0-only", []string{"MIT"}, false},
		{"MIT AND GPL-3.0-only", []string{"MIT", "GPL-3.0-only"}, true},
		// Precedence: MIT OR (ISC AND GPL-3.0-only).
		{"MIT OR ISC AND GPL-3.0-only", []string{"ISC"}, false},
		{"MIT OR ISC AND GPL-3.0-only", []string{"MIT"}, true},
		{"(MIT OR ISC) AND GPL-3.0-only", []string{"MIT"}, false},
		{"(MIT OR ISC) AND Apache-2.0", []string{"ISC", "Apache-2.0"}, true},
		// WITH and "+" are judged by the license id.
		{"GPL-2.0-only WITH Classpath-exception-2.0", []string{"GPL-2.0-only"}, true},
		{"GPL-2.0-only WITH Classpath-exception-2.0", []string{"Classpath-exception-2.0"}, false},
		{"LGPL-2.1+", []string{"LGPL-2.1"}, true},
	}
	for _, tc := range cases {
		e, err := ParseExpression(tc.expr)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.expr, err)
		}
		if got := e.Satisfies(allow(tc.allowed...)); got != tc.want {
			t.Errorf("%q.Satisfies(%v) = %v, want %v", tc.expr, tc.allowed, got, tc.want)
		}
	}
	if (Expr{}).Satisfies(func(string) bool { return true }) {
		t.Error("the empty expression satisfied a policy")
	}
}

func TestAnd(t *testing.T) {
	a, _ := ParseExpression("MIT OR ISC")
	b, _ := ParseExpression("Apache-2.0 AND BSD-2-Clause")
	if got := And(a, Expr{}, b).String(); got != "(MIT OR ISC) AND Apache-2.0 AND BSD-2-Clause" {
		t.Errorf("And = %q", got)
	}
	if !And().IsZero() || And(a).String() != "MIT OR ISC" {
		t.Error("And of none / one")
	}
}

// FuzzParseExpression: no input panics, and whatever parses normalizes to a
// fixed point. The seed corpus runs as a normal test.
func FuzzParseExpression(f *testing.F) {
	for _, s := range []string{
		"MIT", "MIT OR Apache-2.0", "(MIT AND (ISC OR BSD-3-Clause)) WITH x", "GPL-2.0+ WITH Classpath-exception-2.0",
		"DocumentRef-a:LicenseRef-b", "((((", "))", "AND", "with with", "MIT\tOR\nISC", "Apache 2.0", "ü+", "a:b",
		"LicenseRef-", "NOASSERTION", "MIT OR (ISC AND (BSD-2-Clause OR (Zlib AND 0BSD)))",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseExpression(s)
		if err != nil {
			return
		}
		norm := e.String()
		again, err := ParseExpression(norm)
		if err != nil {
			t.Fatalf("normalized %q (from %q) doesn't parse: %v", norm, s, err)
		}
		if again.String() != norm {
			t.Fatalf("normalization not idempotent: %q -> %q -> %q", s, norm, again.String())
		}
		_ = e.IDs()
		_ = e.Satisfies(func(string) bool { return true })
	})
}
