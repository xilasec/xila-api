package domain

import (
	"strings"
	"testing"
)

func TestDefaultWeightsValidate(t *testing.T) {
	if err := DefaultWeights.Validate(); err != nil {
		t.Fatalf("defaults don't validate: %v", err)
	}
}

// A project's override changes exactly the factors it names; the zero value
// and a stored null mean the defaults; an override that broke an invariant
// falls back to the defaults instead of computing nonsense.
func TestWeightsFromJSON(t *testing.T) {
	direct := true
	runtime := Reachability{Direct: &direct, Scope: DepScopeRuntime}
	w := WeightsFromJSON([]byte(`{"critical": 20, "kev": 4}`))
	if got := w.Priority(SeverityCritical, Exploitability{KEV: true}, runtime, ExposureUnknown); got != 80 {
		t.Errorf("critical + KEV with critical 20, kev 4 = %v, want 80", got)
	}
	if got := w.Priority(SeverityHigh, Exploitability{}, runtime, ExposureInternet); got != 7*1.25 {
		t.Errorf("unchanged factors = %v, want the defaults (8.75)", got)
	}
	for _, raw := range []string{"", "null", `{"isolated": 0}`, `{"critical": 1}`, `not json`} {
		if WeightsFromJSON([]byte(raw)) != DefaultWeights {
			t.Errorf("WeightsFromJSON(%q) is not the defaults", raw)
		}
	}
	if got := (Weights{}).Priority(SeverityCritical, Exploitability{}, runtime, ExposureUnknown); got != 15 {
		t.Errorf("zero Weights = %v, want the default 15", got)
	}
}

func TestWeightsValidate(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Weights)
		want string // substring of the error; "" = valid
	}{
		{"stronger KEV", func(w *Weights) { w.KEV = 5; w.Weaponized = 4 }, ""},
		{"severity order", func(w *Weights) { w.Medium = 10 }, "order"},
		{"discount raises", func(w *Weights) { w.Dev = 1.5 }, "dev"},
		{"discount zeroes", func(w *Weights) { w.Transitive = 0 }, "transitive"},
		{"KEV lowers", func(w *Weights) { w.KEV = 0.5 }, "kev"},
		{"PoC above weaponized", func(w *Weights) { w.PoC = 3; w.Weaponized = 2 }, "poc ≤ weaponized"},
		// Each factor is legal on its own, but together they'd bury an
		// exploited critical under a quiet medium.
		{"buries an emergency", func(w *Weights) { w.Dev = 0.05; w.Isolated = 0.2; w.Transitive = 0.3; w.Internet = 2 }, "outrank"},
	}
	for _, c := range cases {
		w := DefaultWeights
		c.edit(&w)
		err := w.Validate()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v, want valid", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want an error about %q", c.name, err, c.want)
		}
	}
}
