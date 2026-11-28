package domain

import "testing"

func TestIsMaliciousAdvisory(t *testing.T) {
	for id, want := range map[string]bool{
		"MAL-2025-1234": true, "mal-2025-1234": true, "MAL-": false, "MAL": false,
		"GHSA-xxxx-yyyy-zzzz": false, "CVE-2024-1": false, "": false, "SMAL-1": false,
	} {
		if got := IsMaliciousAdvisory(id); got != want {
			t.Errorf("IsMaliciousAdvisory(%q) = %v, want %v", id, got, want)
		}
	}
}

// A malicious package takes the exploitability ceiling and is never
// discounted: it runs wherever it is installed, dev and transitive included.
func TestPriorityMalicious(t *testing.T) {
	no := false
	dev := Reachability{Direct: &no, Scope: DepScopeDev}
	plain := Priority(SeverityCritical, Exploitability{}, dev, ExposureIsolated)
	bad := Priority(SeverityCritical, Exploitability{Malicious: true}, dev, ExposureIsolated)
	kev := Priority(SeverityCritical, Exploitability{KEV: true}, Reachability{}, "")
	if bad != kev {
		t.Errorf("malicious transitive dev dependency on an isolated asset = %v, want the undiscounted KEV ceiling %v", bad, kev)
	}
	if bad <= plain {
		t.Errorf("malicious = %v, not above the same finding without it (%v)", bad, plain)
	}
	if up, base := Priority(SeverityCritical, Exploitability{Malicious: true}, Reachability{}, ExposureInternet), kev; up <= base {
		t.Errorf("an internet-facing malicious package = %v, want the exposure uplift over %v", up, base)
	}
}
