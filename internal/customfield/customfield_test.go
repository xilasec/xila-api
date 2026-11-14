package customfield

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	enum := Definition{Key: "tier", Type: TypeEnum, Options: []string{"gold", "silver"}}
	cases := []struct {
		def  Definition
		in   any
		want any
		ok   bool
	}{
		{Definition{Key: "n", Type: TypeNumber}, 7.5, 7.5, true},
		{Definition{Key: "n", Type: TypeNumber}, "7", nil, false},
		{Definition{Key: "t", Type: TypeText}, "  hi ", "hi", true},
		{Definition{Key: "t", Type: TypeText}, "   ", nil, true}, // blank clears
		{Definition{Key: "t", Type: TypeText}, 3.0, nil, false},
		{Definition{Key: "t", Type: TypeText}, strings.Repeat("x", MaxTextLength+1), nil, false},
		{Definition{Key: "d", Type: TypeDate}, "2026-02-28", "2026-02-28", true},
		{Definition{Key: "d", Type: TypeDate}, "2026-02-30", nil, false},
		{enum, "gold", "gold", true},
		{enum, "bronze", nil, false},
		{enum, "Gold", nil, false},
		{Definition{Key: "u", Type: TypeUser}, "0D1A3C4E-0000-4000-8000-000000000001", "0d1a3c4e-0000-4000-8000-000000000001", true},
		{Definition{Key: "u", Type: TypeUser}, "alice", nil, false},
		{enum, nil, nil, true},
	}
	for _, c := range cases {
		got, err := c.def.Normalize(c.in)
		var v *ValidationError
		if c.ok != (err == nil) || (err != nil && !errors.As(err, &v)) || got != c.want {
			t.Errorf("%s(%v) = %v, %v; want %v ok=%v", c.def.Type, c.in, got, err, c.want, c.ok)
		}
	}
}

func TestDefinitionValidate(t *testing.T) {
	for name, d := range map[string]Definition{
		"enum without options": {Entity: EntityFinding, Key: "a", Label: "A", Type: TypeEnum},
		"options on text":      {Entity: EntityFinding, Key: "a", Label: "A", Type: TypeText, Options: []string{"x"}},
		"reserved key":         {Entity: EntityFinding, Key: "in", Label: "A", Type: TypeText},
		"uppercase key":        {Entity: EntityFinding, Key: "Team", Label: "A", Type: TypeText},
		"no label":             {Entity: EntityFinding, Key: "a", Label: " ", Type: TypeText},
		"bad entity":           {Entity: "scan", Key: "a", Label: "A", Type: TypeText},
	} {
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := Definition{Entity: EntityFinding, Key: "tier", Label: " Tier ", Type: TypeEnum, Options: []string{" gold", "gold", "silver"}}
	if err := d.Validate(); err != nil || d.Label != "Tier" || len(d.Options) != 2 {
		t.Errorf("normalized = %+v (%v)", d, err)
	}
}

func TestParseFilters(t *testing.T) {
	conds, err := ParseFilters(map[string]string{"cf.score.gte": "5", "cf.team": "web", "status": "open", "cf.due.lt": "2027-01-01"})
	if err != nil || len(conds) != 3 {
		t.Fatalf("ParseFilters = %v, %v", conds, err)
	}
	// Sorted, so the SQL is stable.
	if conds[0].Key != "due" || conds[1].Key != "score" || conds[2].Key != "team" {
		t.Errorf("order = %+v", conds)
	}
	sql, args := AppendSQL(conds, "custom", []any{"p"})
	// Placeholders continue after the caller's; a text equality is one
	// containment test, a numeric one also matches the stored number.
	if !strings.Contains(sql, ") < $3::text") || !strings.Contains(sql, ">= $5::numeric") || len(args) != 7 {
		t.Errorf("sql %q args %v", sql, args)
	}
	numeric, _ := ParseFilters(map[string]string{"cf.score": "7"})
	if sql, args := AppendSQL(numeric, "custom", nil); !strings.Contains(sql, " OR custom @> jsonb_build_object($1::text, $3::numeric)") || len(args) != 3 {
		t.Errorf("numeric equality: %q %v", sql, args)
	}
	for _, bad := range []map[string]string{
		{"cf.score.between": "1"}, {"cf.score.gte": "soon"}, {"cf.Team": "x"}, {"cf.team": ""}, {"cf.team.set": "maybe"},
	} {
		if _, err := ParseFilters(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
