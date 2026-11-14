package project

import (
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func TestComputeSummary(t *testing.T) {
	counts := []finding.StatusSeverityCount{
		{Status: domain.FindingOpen, Severity: domain.SeverityCritical, Criticality: domain.CriticalityHigh, Count: 2},  // 2 * 15 = 30
		{Status: domain.FindingConfirmed, Severity: domain.SeverityHigh, Criticality: domain.CriticalityHigh, Count: 1}, // 1 * 7  = 7
		{Status: domain.FindingRiskAccepted, Severity: domain.SeverityHigh, Criticality: domain.CriticalityHigh, Count: 3},
		{Status: domain.FindingRemediated, Severity: domain.SeverityLow, Criticality: domain.CriticalityHigh, Count: 5},
	}

	// High criticality doubles the weighted risk: (30 + 7) * 2 = 74.
	s := computeSummary("proj-1", counts)

	if s.RiskScore != 74 {
		t.Errorf("RiskScore = %v, want 74", s.RiskScore)
	}
	if s.TotalOpen != 3 { // only open + confirmed
		t.Errorf("TotalOpen = %d, want 3", s.TotalOpen)
	}
	if s.Total != 11 {
		t.Errorf("Total = %d, want 11", s.Total)
	}
	if s.BySeverity[domain.SeverityCritical] != 2 {
		t.Errorf("open critical = %d, want 2", s.BySeverity[domain.SeverityCritical])
	}
	// Resolved statuses are excluded from the live severity breakdown.
	if _, ok := s.BySeverity[domain.SeverityLow]; ok {
		t.Error("remediated low should not appear in open severity breakdown")
	}
	if s.ByStatus[domain.FindingRiskAccepted] != 3 {
		t.Errorf("risk_accepted count = %d, want 3", s.ByStatus[domain.FindingRiskAccepted])
	}
}

// A rollup weighs each project's findings by that project's own criticality:
// a high-criticality child's criticals count double, a low one's once.
func TestComputeSummaryMixedCriticality(t *testing.T) {
	s := computeSummary("parent", []finding.StatusSeverityCount{
		{Status: domain.FindingOpen, Severity: domain.SeverityCritical, Criticality: domain.CriticalityHigh, Count: 1}, // 15 * 2 = 30
		{Status: domain.FindingOpen, Severity: domain.SeverityCritical, Criticality: domain.CriticalityLow, Count: 2},  // 30 * 1 = 30
	})
	if s.RiskScore != 60 || s.BySeverity[domain.SeverityCritical] != 3 {
		t.Errorf("summary = %+v, want risk 60 and 3 open criticals", s)
	}
}

func TestComputeSummaryEmpty(t *testing.T) {
	s := computeSummary("proj-1", nil)
	if s.RiskScore != 0 || s.Total != 0 || s.TotalOpen != 0 {
		t.Errorf("empty summary should be zero-valued, got %+v", s)
	}
}
