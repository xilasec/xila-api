package connector

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

type fakeCandidates []triageCandidate

func (f fakeCandidates) RemoteTriageCandidates(context.Context, string, string) ([]triageCandidate, error) {
	return f, nil
}

type recordTriage map[string]finding.Triage

func (r recordTriage) SetStatus(_ context.Context, id string, t finding.Triage) (finding.Finding, error) {
	r[id] = t
	return finding.Finding{}, nil
}

// AcceptBySystem records a carried risk acceptance as the triage it stands for.
func (r recordTriage) AcceptBySystem(_ context.Context, s finding.SystemAcceptance, ids []string) ([]string, error) {
	for _, id := range ids {
		r[id] = finding.Triage{Status: domain.FindingRiskAccepted, Reason: s.Justification, Actor: s.Actor, ExpiresAt: s.ExpiresAt}
	}
	return ids, nil
}

func TestRemoteTriageVerdicts(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	got := recordTriage{}
	pass := &RemoteTriage{
		store: fakeCandidates{
			{ID: "fp", Scanner: "defectdojo", Status: domain.FindingFalsePositive, Reason: "DefectDojo: false positive"},
			{ID: "accepted", Scanner: "secobserve", Status: domain.FindingRiskAccepted, Expires: "2027-01-01T00:00:00Z"},
			{ID: "lapsed", Scanner: "secobserve", Status: domain.FindingRiskAccepted, Expires: "2026-10-27T12:00:00Z"},
			{ID: "garbled", Scanner: "secobserve", Status: domain.FindingRiskAccepted, Expires: "next year"},
			{ID: "remediated", Scanner: "x", Status: domain.FindingRemediated},
			{ID: "bogus", Scanner: "x", Status: "ignored"},
		},
		findings: got,
		now:      func() time.Time { return now },
	}
	n, err := pass.ApplyToScan(context.Background(), "p", "s")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(got) != 2 {
		t.Fatalf("applied %d (%v), want fp + accepted only", n, got)
	}
	if fp := got["fp"]; fp.Status != domain.FindingFalsePositive || fp.Actor != "defectdojo" || fp.ExpiresAt != nil {
		t.Errorf("fp = %+v", fp)
	}
	// An acceptance keeps its expiry, so the acceptance it joins expires on time;
	// one that already lapsed (or can't be read) is not imported as accepted.
	if acc := got["accepted"]; acc.ExpiresAt == nil || !acc.ExpiresAt.Equal(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("accepted = %+v", acc)
	}
}
