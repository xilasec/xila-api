package expr

import (
	"context"
	"testing"
	"time"
)

func schema() Schema {
	return Schema{Vars: []string{"finding"}, Sample: map[string]any{
		"finding": map[string]any{"kev": true, "severity": "high", "score": 1.0},
	}}
}

func TestCompileValueAndEval(t *testing.T) {
	cases := []struct {
		src  string
		want any
	}{
		{`finding.kev && finding.severity == "critical" ? "urgent" : "normal"`, "normal"},
		{`finding.score + 1.0`, 2.5},
		{`finding.severity`, "high"},
		{`finding.kev`, true},
	}
	for _, c := range cases {
		p, err := CompileValue(schema(), c.src)
		if err != nil {
			t.Fatalf("%s: compile: %v", c.src, err)
		}
		got, err := p.Eval(context.Background(), map[string]any{
			"finding": map[string]any{"kev": true, "severity": "high", "score": 1.5},
		})
		if err != nil {
			t.Fatalf("%s: eval: %v", c.src, err)
		}
		if got != c.want {
			t.Errorf("%s = %v, want %v", c.src, got, c.want)
		}
	}
}

// Eval on a missing fact returns CEL's null as a nil Go value, not an error —
// callers (customfield.Definition.Fit) treat that as "leave it unset".
func TestEvalUnknownFactIsNil(t *testing.T) {
	p, err := CompileValue(schema(), `has(finding.unknown) ? "x" : finding.score > 0.0 ? "y" : "z"`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := p.Eval(context.Background(), map[string]any{"finding": map[string]any{"score": 1.0}})
	if err != nil || got != "y" {
		t.Errorf("eval = %v, %v; want y, nil", got, err)
	}
}

func TestEvalTimestamp(t *testing.T) {
	s := Schema{Vars: []string{"finding"}, Sample: map[string]any{"finding": map[string]any{"seen": "2026-01-01T00:00:00Z"}}}
	p, err := CompileValue(s, `timestamp("2026-06-15T12:00:00Z")`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := p.Eval(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	tm, ok := got.(time.Time)
	if !ok || tm.UTC().Format(time.RFC3339) != "2026-06-15T12:00:00Z" {
		t.Errorf("eval = %v (%T), want a matching time.Time", got, got)
	}
}

func TestCompileValueOutputType(t *testing.T) {
	cases := []struct {
		src  string
		want string
	}{
		{`"x"`, "string"},
		{`1.5`, "double"},
		{`1`, "int"},
		{`true`, "bool"},
		{`finding.score`, "dyn"}, // read from a dyn-typed document fact
		{`finding.kev ? "a" : "b"`, "string"},
	}
	for _, c := range cases {
		p, err := CompileValue(schema(), c.src)
		if err != nil {
			t.Fatalf("%s: compile: %v", c.src, err)
		}
		if p.OutputType != c.want {
			t.Errorf("%s OutputType = %q, want %q", c.src, p.OutputType, c.want)
		}
	}
}

// Compile (boolean mode) still requires a boolean result; CompileValue does
// not, and permits the same expression for a computed field's value.
func TestCompileStillRequiresBool(t *testing.T) {
	if _, err := Compile(schema(), `finding.severity`); err == nil {
		t.Error("Compile accepted a non-boolean result")
	}
	if _, err := CompileValue(schema(), `finding.severity`); err != nil {
		t.Errorf("CompileValue rejected a value expression: %v", err)
	}
}

func TestLoadValue(t *testing.T) {
	p, err := LoadValue([]string{"finding"}, `finding.score * 2.0`)
	if err != nil {
		t.Fatalf("LoadValue: %v", err)
	}
	got, err := p.Eval(context.Background(), map[string]any{"finding": map[string]any{"score": 3.0}})
	if err != nil || got != 6.0 {
		t.Errorf("eval = %v, %v; want 6.0, nil", got, err)
	}
}
