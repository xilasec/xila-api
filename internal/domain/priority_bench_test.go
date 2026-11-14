package domain

import "testing"

// BenchmarkPriority covers the pure hot path every finding write recomputes
// (Upsert, Reprioritize, triage rules, enrichment, reachability match) —
// internal/finding never calls domain.Priority in bulk across more than one
// finding at a time, so this is the per-finding cost in isolation. See
// docs/SCALE.md for measured ns/op at the dataset's scale.
func BenchmarkPriority(b *testing.B) {
	direct := true
	cases := []struct {
		name string
		sev  Severity
		x    Exploitability
		r    Reachability
		exp  Exposure
	}{
		{"plain/medium", SeverityMedium, Exploitability{}, Reachability{}, ExposureUnknown},
		{"kev-critical/internet", SeverityCritical, Exploitability{EPSS: 0.9, KEV: true, Maturity: ExploitWeaponized},
			Reachability{Direct: &direct, Scope: DepScopeRuntime}, ExposureInternet},
		{"transitive-dev/isolated", SeverityCritical, Exploitability{EPSS: 0.9, KEV: true},
			Reachability{Direct: new(bool), Scope: DepScopeDev}, ExposureIsolated},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			var sink float64
			for b.Loop() {
				sink = Priority(tc.sev, tc.x, tc.r, tc.exp)
			}
			_ = sink
		})
	}
}
