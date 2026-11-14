package issuetracker

import "github.com/xilasec/xila-api/internal/domain"

// Action is what one sync step does to reconcile a link.
type Action string

// Sync actions.
const (
	ActNone           Action = "none"            // both sides agree with the stored state
	ActRecord         Action = "record"          // both moved the same way: just store the new state
	ActCloseIssue     Action = "close_issue"     // Xila resolved the finding → close the issue
	ActReopenIssue    Action = "reopen_issue"    // the finding is live again → reopen the issue
	ActResolveFinding Action = "resolve_finding" // issue closed in the tracker → finding remediated
	ActReopenFinding  Action = "reopen_finding"  // issue reopened in the tracker → finding open
)

// Decision is the action to take and the state both sides will agree on after.
type Decision struct {
	Action Action
	State  State
}

// xilaState maps a finding status onto the issue's two states: the backlog
// (open/confirmed) is an open issue; anything else is closed.
func xilaState(s domain.FindingStatus) State {
	if s == domain.FindingOpen || s == domain.FindingConfirmed {
		return StateOpen
	}
	return StateClosed
}

// Decide reconciles one link. stored is the state both sides last agreed on;
// comparing it with each side tells which one changed since, so a change is
// always carried from the side that made it to the side that didn't, and the
// two directions never undo each other.
//
//   - neither changed            → nothing
//   - only the tracker changed   → apply it to the finding
//   - only Xila changed          → apply it to the issue
//   - both changed (necessarily the same way, states being binary) → record it
//
// One exception: an issue reopened in the tracker while the finding is in an
// exception state (risk accepted, false positive, won't fix). That is a triage
// decision made in Xila, with a reason and an audit row; a reopen in the
// tracker doesn't overturn it, so the issue is closed again.
func Decide(stored State, status domain.FindingStatus, tracker State) Decision {
	xila := xilaState(status)
	switch {
	case xila == stored && tracker == stored:
		return Decision{ActNone, stored}
	case xila == stored: // only the tracker moved
		if tracker == StateClosed {
			return Decision{ActResolveFinding, StateClosed}
		}
		if status == domain.FindingRemediated {
			return Decision{ActReopenFinding, StateOpen}
		}
		return Decision{ActCloseIssue, StateClosed}
	case tracker == stored: // only Xila moved
		if xila == StateClosed {
			return Decision{ActCloseIssue, StateClosed}
		}
		return Decision{ActReopenIssue, StateOpen}
	default: // both moved, and so agree
		return Decision{ActRecord, xila}
	}
}
