package gate

import (
	"testing"

	"github.com/xilasec/xila-api/internal/finding"
)

func intp(n int) *int         { return &n }
func f64p(f float64) *float64 { return &f }

func TestEvaluate(t *testing.T) {
	stats := finding.GateStats{OpenCritical: 2, OpenHigh: 5, OpenMedium: 4, OpenLow: 5, OpenInfo: 2, OpenKEV: 1, OpenLicense: 1, MaxEPSS: 0.7, SLABreached: 3, RiskScore: 50}

	cases := []struct {
		name      string
		policy    Policy
		wantPass  bool
		wantRules []string
	}{
		{"empty policy passes", Policy{}, true, nil},
		{"max_critical exceeded", Policy{MaxCritical: intp(0)}, false, []string{"max_critical"}},
		{"max_critical within limit", Policy{MaxCritical: intp(5)}, true, nil},
		{"max_high exceeded", Policy{MaxHigh: intp(3)}, false, []string{"max_high"}},
		{"max_medium exceeded", Policy{MaxMedium: intp(1)}, false, []string{"max_medium"}},
		{"max_low at the limit", Policy{MaxLow: intp(5)}, true, nil},
		{"max_info exceeded", Policy{MaxInfo: intp(0)}, false, []string{"max_info"}},
		{"block_kev fails", Policy{BlockKEV: true}, false, []string{"block_kev"}},
		{"epss over threshold", Policy{MaxEPSS: f64p(0.5)}, false, []string{"max_epss"}},
		{"epss boundary is inclusive", Policy{MaxEPSS: f64p(0.7)}, false, []string{"max_epss"}},
		{"epss under threshold", Policy{MaxEPSS: f64p(0.9)}, true, nil},
		{"license blocked", Policy{BlockLicense: true}, false, []string{"block_license"}},
		{"sla breach blocked", Policy{BlockSLABreach: true}, false, []string{"block_sla_breach"}},
		{"multiple violations", Policy{MaxCritical: intp(0), BlockKEV: true}, false, []string{"max_critical", "block_kev"}},
		{"max_risk_score exceeded", Policy{MaxRiskScore: f64p(49)}, false, []string{"max_risk_score"}},
		{"max_risk_score boundary is exclusive", Policy{MaxRiskScore: f64p(50)}, true, nil},
		{"max_risk_score within limit", Policy{MaxRiskScore: f64p(100)}, true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Evaluate(tc.policy, stats, nil)
			if r.Passed != tc.wantPass {
				t.Errorf("passed = %v, want %v (violations: %+v)", r.Passed, tc.wantPass, r.Violations)
			}
			got := map[string]bool{}
			for _, v := range r.Violations {
				got[v.Rule] = true
			}
			if len(r.Violations) != len(tc.wantRules) {
				t.Errorf("violations = %+v, want rules %v", r.Violations, tc.wantRules)
			}
			for _, rule := range tc.wantRules {
				if !got[rule] {
					t.Errorf("missing violation %q", rule)
				}
			}
		})
	}
}

func TestEvaluateEmptyStatsAlwaysPasses(t *testing.T) {
	clean := finding.GateStats{}
	strict := Policy{MaxCritical: intp(0), MaxHigh: intp(0), BlockKEV: true, MaxEPSS: f64p(0.1), BlockLicense: true, BlockSLABreach: true, MaxRiskScore: f64p(0)}
	if r := Evaluate(strict, clean, nil); !r.Passed {
		t.Errorf("a clean backlog should pass even the strictest policy, got %+v", r.Violations)
	}
}

// require_expected_scans fails only when the policy opts in and the caller
// reports at least one missing expectation (pre-computed, since Evaluate is
// pure and does no I/O).
func TestEvaluateRequireExpectedScans(t *testing.T) {
	stats := finding.GateStats{}
	if r := Evaluate(Policy{RequireExpectedScans: true}, stats, []string{"trivy on main: none has ever completed"}); r.Passed {
		t.Errorf("want fail with a missing expectation, got %+v", r)
	}
	if r := Evaluate(Policy{RequireExpectedScans: true}, stats, nil); !r.Passed {
		t.Errorf("no missing expectations should pass, got %+v", r.Violations)
	}
	if r := Evaluate(Policy{}, stats, []string{"trivy on main: none has ever completed"}); !r.Passed {
		t.Errorf("the flag off should ignore missing expectations, got %+v", r.Violations)
	}
}
