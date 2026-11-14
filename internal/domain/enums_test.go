package domain

import (
	"testing"
	"time"
)

func TestSeverityWeight(t *testing.T) {
	cases := map[Severity]float64{
		SeverityInfo:      0,
		SeverityLow:       1,
		SeverityMedium:    3,
		SeverityHigh:      7,
		SeverityCritical:  15,
		Severity("bogus"): 0, // unknown severities carry no weight
	}
	for sev, want := range cases {
		if got := sev.Weight(); got != want {
			t.Errorf("%q.Weight() = %v, want %v", sev, got, want)
		}
	}
}

func TestCriticalityMultiplier(t *testing.T) {
	cases := map[Criticality]float64{
		CriticalityLow:       1,
		CriticalityMedium:    1.5,
		CriticalityHigh:      2,
		CriticalityCritical:  3,
		Criticality("bogus"): 1, // unknown defaults to the low multiplier
	}
	for crit, want := range cases {
		if got := crit.Multiplier(); got != want {
			t.Errorf("%q.Multiplier() = %v, want %v", crit, got, want)
		}
	}
}

func TestValid(t *testing.T) {
	if !SeverityHigh.Valid() || Severity("nope").Valid() {
		t.Error("severity Valid() is wrong")
	}
	if !CategorySCA.Valid() || Category("nope").Valid() {
		t.Error("category Valid() is wrong")
	}
	if !FindingOpen.Valid() || FindingStatus("nope").Valid() {
		t.Error("finding status Valid() is wrong")
	}
	if !CriticalityHigh.Valid() || Criticality("nope").Valid() {
		t.Error("criticality Valid() is wrong")
	}
}

func TestCountsRisk(t *testing.T) {
	live := []FindingStatus{FindingOpen, FindingConfirmed}
	resolved := []FindingStatus{FindingFalsePositive, FindingRiskAccepted, FindingRemediated, FindingWontFix}

	for _, s := range live {
		if !s.CountsRisk() {
			t.Errorf("%q should count toward risk", s)
		}
	}
	for _, s := range resolved {
		if s.CountsRisk() {
			t.Errorf("%q should not count toward risk", s)
		}
	}
}

func TestSLAStatusAt(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	const day = 24 * time.Hour

	cases := []struct {
		name     string
		status   FindingStatus
		days     *int
		due      *time.Time
		resolved *time.Time
		want     SLAStatus
	}{
		{"no SLA for this severity", FindingOpen, nil, nil, nil, SLANone},
		{"plenty of time left", FindingOpen, new(30), new(now.Add(20 * day)), nil, SLAOnTrack},
		// 30-day window: the last 25% is 7.5 days.
		{"just outside the due-soon tail", FindingOpen, new(30), new(now.Add(7*day + 13*time.Hour)), nil, SLAOnTrack},
		{"due-soon tail is inclusive", FindingOpen, new(30), new(now.Add(7*day + 12*time.Hour)), nil, SLADueSoon},
		{"confirmed counts like open", FindingConfirmed, new(30), new(now.Add(time.Hour)), nil, SLADueSoon},
		{"exactly at the deadline is not yet breached", FindingOpen, new(7), new(now), nil, SLADueSoon},
		{"past the deadline", FindingOpen, new(7), new(now.Add(-time.Second)), nil, SLABreached},
		{"an exception pauses even when overdue", FindingRiskAccepted, new(7), new(now.Add(-10 * day)), nil, SLAPaused},
		{"false positive pauses", FindingFalsePositive, new(7), new(now.Add(day)), nil, SLAPaused},
		{"wont fix pauses", FindingWontFix, new(7), new(now.Add(day)), nil, SLAPaused},
		{"fixed on the deadline is met", FindingRemediated, new(7), new(now.Add(-day)), new(now.Add(-day)), SLAMet},
		{"fixed after the deadline is missed", FindingRemediated, new(7), new(now.Add(-2 * day)), new(now.Add(-day)), SLAMissed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SLAStatusAt(tc.status, tc.days, tc.due, tc.resolved, now); got != tc.want {
				t.Errorf("SLAStatusAt = %q, want %q", got, tc.want)
			}
		})
	}
}
