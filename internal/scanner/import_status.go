package scanner

import (
	"time"

	"github.com/xilasec/xila-api/internal/domain"
)

// Carried triage. Some uploads are not raw scanner output but a decision
// somebody already made: another platform's export (a DefectDojo false positive,
// a SecObserve risk acceptance), an audited detect-secrets baseline, a gosec
// `#nosec` with a justification. ParsedFinding deliberately has no status — a
// scan reports what exists, not what we decided about it — so a parser records
// the verdict in Metadata under the remote_triage keys, the same convention the
// pull connectors use, and the ingest pipeline's last pass
// (connector.RemoteTriage) applies it.
//
// That pass is conservative by design: it only touches findings the scan
// *created* that are still open after VEX and the triage rules. A decision made
// in Xila always wins over one carried in a file, and re-uploading the same
// export never overturns a later local triage (a reopened finding stays open).
const (
	// metaRemoteTriage holds the domain.FindingStatus the source assigned.
	metaRemoteTriage = "remote_triage"
	// metaRemoteTriageReason is the justification recorded with the status.
	metaRemoteTriageReason = "remote_triage_reason"
	// metaRemoteTriageExpires is an RFC 3339 time at which a carried acceptance
	// lapses; one already in the past is not applied.
	metaRemoteTriageExpires = "remote_triage_expires"
)

// zeroTime is the "does not lapse" expiry for setImportedStatus.
var zeroTime time.Time

// setImportedStatus records a carried verdict on a finding's metadata. Only
// verdicts the pipeline honors are recorded (open is the default, remediated is
// not a verdict about something being reported right now). A zero expires means
// the verdict does not lapse; expiry only applies to risk acceptance.
func setImportedStatus(meta map[string]any, status domain.FindingStatus, reason string, expires time.Time) {
	switch status {
	case domain.FindingConfirmed, domain.FindingFalsePositive, domain.FindingRiskAccepted, domain.FindingWontFix:
	default:
		return
	}
	meta[metaRemoteTriage] = string(status)
	if reason != "" {
		meta[metaRemoteTriageReason] = reason
	}
	if !expires.IsZero() && status == domain.FindingRiskAccepted {
		meta[metaRemoteTriageExpires] = expires.UTC().Format(time.RFC3339)
	}
}

// parseLooseTime accepts the date shapes exports use: RFC 3339 or a bare date.
func parseLooseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
