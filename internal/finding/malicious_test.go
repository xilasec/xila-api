package finding

import (
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

func TestIsMalicious(t *testing.T) {
	tests := []struct {
		name string
		f    Finding
		want bool
	}{
		{"rule id", Finding{RuleID: "MAL-2025-1"}, true},
		{"cve list", Finding{RuleID: "x", CVE: []string{"CVE-2024-1", "MAL-2025-1"}}, true},
		{"aliases as strings", Finding{RuleID: "GHSA-a", Metadata: map[string]any{"aliases": []string{"MAL-2025-1"}}}, true},
		{"aliases decoded from JSON", Finding{RuleID: "GHSA-a", Metadata: map[string]any{"aliases": []any{"PYSEC-1", "MAL-2025-1"}}}, true},
		{"already flagged", Finding{Malicious: true}, true},
		{"a plain vulnerability", Finding{RuleID: "GHSA-a", CVE: []string{"CVE-2024-1"}, Metadata: map[string]any{"aliases": []any{"PYSEC-1"}}}, false},
		{"aliases of the wrong type", Finding{RuleID: "GHSA-a", Metadata: map[string]any{"aliases": "MAL-2025-1"}}, false},
	}
	for _, tt := range tests {
		if got := isMalicious(tt.f); got != tt.want {
			t.Errorf("%s: isMalicious = %v, want %v", tt.name, got, tt.want)
		}
	}
	// The upsert raises its severity to critical.
	if args := upsertArgs(Finding{RuleID: "MAL-2025-1", Severity: "low"}); args[7] != domain.SeverityCritical || args[22] != true {
		t.Errorf("upsert args severity/malicious = %v/%v, want critical/true", args[7], args[22])
	}
}
