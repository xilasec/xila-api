package customfield

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
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

func TestFit(t *testing.T) {
	enum := Definition{Key: "tier", Type: TypeEnum, Options: []string{"gold", "silver"}}
	ts, _ := time.Parse(time.RFC3339, "2026-06-15T12:00:00Z")
	cases := []struct {
		def  Definition
		in   any
		want any
		ok   bool
	}{
		{Definition{Type: TypeNumber}, 7.5, 7.5, true},
		{Definition{Type: TypeNumber}, int64(7), 7.0, true},
		{Definition{Type: TypeNumber}, uint64(7), 7.0, true},
		{Definition{Type: TypeNumber}, "7", nil, false}, // CEL never hands back a string here; still never a guess
		{Definition{Type: TypeNumber}, math.NaN(), nil, false},
		{Definition{Type: TypeText}, "urgent", "urgent", true},
		{Definition{Type: TypeText}, true, "true", true},  // a number/bool renders as text
		{Definition{Type: TypeText}, int64(3), "3", true}, //
		{Definition{Type: TypeText}, "  ", nil, false},    // blank never fits (vs. Normalize, which clears)
		{Definition{Type: TypeText}, strings.Repeat("x", MaxTextLength+1), nil, false},
		{enum, "gold", "gold", true},
		{enum, "bronze", nil, false}, // not one of the options: unset, never a guess
		{enum, 1.0, nil, false},      // wrong native type for an enum
		{Definition{Type: TypeDate}, ts, "2026-06-15", true},
		{Definition{Type: TypeDate}, "2026-06-15T12:00:00Z", "2026-06-15", true},
		{Definition{Type: TypeDate}, "2026-06-15", "2026-06-15", true},
		{Definition{Type: TypeDate}, "not a date", nil, false},
		{Definition{Type: TypeUser}, "00000000-0000-4000-8000-000000000000", nil, false}, // never computed
		{Definition{Type: TypeNumber}, nil, nil, false},                                  // CEL's null (an unknown fact) never fits
	}
	for _, c := range cases {
		got, ok := c.def.Fit(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("%s.Fit(%v) = %v, %v; want %v, %v", c.def.Type, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestFitsOutputType(t *testing.T) {
	cases := []struct {
		typ    Type
		output string
		want   bool
	}{
		{TypeNumber, "double", true},
		{TypeNumber, "int", true},
		{TypeNumber, "string", false},
		{TypeText, "string", true},
		{TypeText, "bool", true}, // renders as text
		{TypeEnum, "string", true},
		{TypeEnum, "double", false},
		{TypeDate, "string", true},
		{TypeDate, "bool", false},
		{TypeUser, "string", false}, // never computed
		{TypeNumber, "dyn", true},   // CEL couldn't tell statically: always allowed
		{TypeEnum, "null_type", true},
	}
	for _, c := range cases {
		if got := c.typ.FitsOutputType(c.output); got != c.want {
			t.Errorf("%s.FitsOutputType(%q) = %v, want %v", c.typ, c.output, got, c.want)
		}
	}
}

func TestFilterComputed(t *testing.T) {
	defs := []Definition{{Key: "a", Computed: true}, {Key: "b"}}
	out := FilterComputed(map[string]any{"a": "x", "b": "y", "c": "z"}, defs)
	if _, had := out["a"]; had {
		t.Error("computed key a not stripped")
	}
	if out["b"] != "y" || out["c"] != "z" {
		t.Errorf("non-computed keys dropped: %+v", out)
	}
}

func TestValidateComputed(t *testing.T) {
	for name, d := range map[string]Definition{
		"computed without expression":  {Entity: EntityFinding, Key: "a", Label: "A", Type: TypeText, Computed: true},
		"expression on a non-computed": {Entity: EntityFinding, Key: "a", Label: "A", Type: TypeText, Expression: "1"},
		"computed and required":        {Entity: EntityFinding, Key: "a", Label: "A", Type: TypeText, Computed: true, Expression: "1", Required: true},
		"computed user field":          {Entity: EntityFinding, Key: "a", Label: "A", Type: TypeUser, Computed: true, Expression: "1"},
	} {
		if err := d.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	d := Definition{Entity: EntityFinding, Key: "urgency", Label: "Urgency", Type: TypeText, Computed: true,
		Expression: ` finding.kev ? "urgent" : "normal" `}
	if err := d.Validate(); err != nil || d.Expression != `finding.kev ? "urgent" : "normal"` {
		t.Errorf("valid computed field rejected: %v (expr %q)", err, d.Expression)
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
