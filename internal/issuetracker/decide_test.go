package issuetracker

import (
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

func TestDecide(t *testing.T) {
	const (
		open   = StateOpen
		closed = StateClosed
	)
	cases := []struct {
		name    string
		stored  State
		status  domain.FindingStatus
		tracker State
		want    Decision
	}{
		// No-op: both sides still agree with the stored state.
		{"open, untouched", open, domain.FindingOpen, open, Decision{ActNone, open}},
		{"confirmed, untouched", open, domain.FindingConfirmed, open, Decision{ActNone, open}},
		{"closed, untouched", closed, domain.FindingRemediated, closed, Decision{ActNone, closed}},
		{"accepted, untouched", closed, domain.FindingRiskAccepted, closed, Decision{ActNone, closed}},

		// Xila → tracker: the finding left the backlog.
		{"remediated in xila", open, domain.FindingRemediated, open, Decision{ActCloseIssue, closed}},
		{"risk accepted in xila", open, domain.FindingRiskAccepted, open, Decision{ActCloseIssue, closed}},
		{"false positive in xila", open, domain.FindingFalsePositive, open, Decision{ActCloseIssue, closed}},
		{"wont fix in xila", open, domain.FindingWontFix, open, Decision{ActCloseIssue, closed}},
		// Xila → tracker: the finding came back (scan reopened it, exception ended).
		{"reopened in xila", closed, domain.FindingOpen, closed, Decision{ActReopenIssue, open}},
		{"confirmed in xila", closed, domain.FindingConfirmed, closed, Decision{ActReopenIssue, open}},

		// Tracker → Xila: issue closed while the finding is live.
		{"closed in tracker", open, domain.FindingOpen, closed, Decision{ActResolveFinding, closed}},
		{"closed in tracker (confirmed)", open, domain.FindingConfirmed, closed, Decision{ActResolveFinding, closed}},
		// Tracker → Xila: issue reopened while the finding is remediated.
		{"reopened in tracker", closed, domain.FindingRemediated, open, Decision{ActReopenFinding, open}},
		// …but not over an exception: that triage decision stands, the issue is re-closed.
		{"reopened in tracker over exception", closed, domain.FindingRiskAccepted, open, Decision{ActCloseIssue, closed}},
		{"reopened in tracker over false positive", closed, domain.FindingFalsePositive, open, Decision{ActCloseIssue, closed}},

		// Both moved the same way since the last sync: just record it.
		{"both closed", open, domain.FindingRemediated, closed, Decision{ActRecord, closed}},
		{"both closed (exception)", open, domain.FindingWontFix, closed, Decision{ActRecord, closed}},
		{"both reopened", closed, domain.FindingOpen, open, Decision{ActRecord, open}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Decide(c.stored, c.status, c.tracker); got != c.want {
				t.Errorf("Decide(%s, %s, %s) = %+v, want %+v", c.stored, c.status, c.tracker, got, c.want)
			}
		})
	}
}

// Applying a decision and deciding again must be a no-op: the two directions
// never undo each other.
func TestDecideConverges(t *testing.T) {
	statuses := []domain.FindingStatus{domain.FindingOpen, domain.FindingConfirmed, domain.FindingRemediated,
		domain.FindingRiskAccepted, domain.FindingFalsePositive, domain.FindingWontFix}
	for _, stored := range []State{StateOpen, StateClosed} {
		for _, status := range statuses {
			for _, tracker := range []State{StateOpen, StateClosed} {
				d := Decide(stored, status, tracker)
				// Apply it to both sides.
				st, tr := status, tracker
				switch d.Action {
				case ActCloseIssue:
					tr = StateClosed
				case ActReopenIssue:
					tr = StateOpen
				case ActResolveFinding:
					st = domain.FindingRemediated
				case ActReopenFinding:
					st = domain.FindingOpen
				}
				if again := Decide(d.State, st, tr); again.Action != ActNone {
					t.Errorf("after %+v from (%s,%s,%s): next decision %+v, want none", d, stored, status, tracker, again)
				}
			}
		}
	}
}
