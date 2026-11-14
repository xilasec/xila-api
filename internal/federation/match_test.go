package federation

import (
	"errors"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	for _, tc := range []struct {
		pattern, value string
		want           bool
	}{
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/main", "refs/heads/main2", false},
		{"refs/heads/*", "refs/heads/main", true},
		{"refs/heads/*", "refs/heads/feature/x", false}, // * stays within a segment
		{"refs/heads/**", "refs/heads/feature/x", true},
		{"refs/tags/v?.*", "refs/tags/v1.2", true},
		{"refs/tags/v?.*", "refs/tags/v10.2", false},
		{"acme/*", "acme/web", true},
		{"acme/*", "acme-evil/web", false},
		{"a.b", "axb", false}, // regexp metacharacters are literal
		{"repo:acme/web:ref:refs/heads/*", "repo:acme/web:ref:refs/heads/main", true},
		{"repo:acme/web:ref:refs/heads/*", "repo:acme/web:ref:refs/pull/1/merge", false},
	} {
		if got := globMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestMatchesClaimTypes(t *testing.T) {
	claims := map[string]any{"repository": "acme/web", "ref_protected": true, "run_attempt": float64(2), "groups": []any{"x"}}
	for _, tc := range []struct {
		conds map[string]string
		want  bool
	}{
		{map[string]string{"repository": "acme/web"}, true},
		{map[string]string{"repository": "acme/web", "ref_protected": "true"}, true},
		{map[string]string{"run_attempt": "2"}, true},
		{map[string]string{"repository": "acme/web", "environment": "production"}, false}, // missing claim
		{map[string]string{"groups": "x"}, false},                                         // arrays never match
	} {
		if got := matches(tc.conds, claims); got != tc.want {
			t.Errorf("matches(%v) = %v, want %v", tc.conds, got, tc.want)
		}
	}
}

func TestValidateConditions(t *testing.T) {
	for _, tc := range []struct {
		conds map[string]string
		ok    bool
	}{
		{map[string]string{"repository": "acme/web", "ref": "refs/heads/main"}, true},
		{map[string]string{"sub": "system:serviceaccount:ci:deployer"}, true},
		{map[string]string{"project_path": "group/app"}, true},
		{nil, false},
		{map[string]string{"ref": "refs/heads/main"}, false},             // nothing pins the workload
		{map[string]string{"repository": "*/web"}, false},                // leading wildcard pins nothing
		{map[string]string{"repository": "acme/web", "ref": " "}, false}, // empty pattern
		{map[string]string{"repository_owner": "acme", "ref": "refs/*"}, true},
	} {
		err := validateConditions(tc.conds)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrInvalidConditions)) {
			t.Errorf("validateConditions(%v) = %v, want ok=%v", tc.conds, err, tc.ok)
		}
	}
}

func TestPickRefusesAmbiguousBindings(t *testing.T) {
	p1, p2 := "p1", "p2"
	claims := map[string]any{"repository": "acme/web"}
	b := func(id, sa string, project *string) Binding {
		return Binding{ID: id, ServiceAccountID: sa, ProjectID: project, Conditions: map[string]string{"repository": "acme/*"}}
	}
	if got, err := pick([]Binding{b("1", "sa", &p1), b("2", "sa", &p1)}, claims); err != nil || got.ID != "1" {
		t.Errorf("agreeing bindings: %v %v, want the oldest", got, err)
	}
	if _, err := pick([]Binding{b("1", "sa", &p1), b("2", "sa", &p2)}, claims); !errors.Is(err, ErrAmbiguousBinding) {
		t.Errorf("different projects: %v", err)
	}
	if _, err := pick([]Binding{b("1", "sa", nil), b("2", "other", nil)}, claims); !errors.Is(err, ErrAmbiguousBinding) {
		t.Errorf("different accounts: %v", err)
	}
	if _, err := pick([]Binding{b("1", "sa", nil)}, map[string]any{"repository": "evil/web"}); !errors.Is(err, ErrNoBinding) {
		t.Errorf("no match: %v", err)
	}
}
