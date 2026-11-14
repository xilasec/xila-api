package cra

import (
	"slices"
	"testing"
	"time"
)

func TestDeadlineStatus(t *testing.T) {
	due := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	before, after := due.Add(-time.Minute), due.Add(time.Minute)
	for _, tc := range []struct {
		name      string
		due, sent *time.Time
		active    bool
		now       time.Time
		want      string
	}{
		{"sent on time", &due, &before, true, after, DeadlineMet},
		{"sent exactly at the deadline", &due, &due, true, after, DeadlineMet},
		{"sent late", &due, &after, true, after, DeadlineLate},
		{"late stays late once closed", &due, &after, false, after, DeadlineLate},
		{"unsent, passed", &due, nil, true, due, DeadlineMissed},
		{"unsent, 6 h to go", &due, nil, true, due.Add(-DueSoonLead), DeadlineDueSoon},
		{"unsent, 6 h 1 m to go", &due, nil, true, due.Add(-DueSoonLead - time.Minute), DeadlinePending},
		{"no clock yet", nil, nil, true, after, DeadlineNotStarted},
		{"dismissed before sending", &due, nil, false, after, DeadlineWaived},
	} {
		if got := DeadlineStatus(tc.due, tc.sent, tc.active, tc.now); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Each stage carries what Article 14(2) asks of it, and names what's missing.
func TestBuildPayloadStages(t *testing.T) {
	aware := time.Date(2026, 9, 12, 8, 0, 0, 0, time.UTC)
	c := Case{ID: "c1", ProjectName: "web", ProductName: "Widget", ProductVersion: "2.1", MemberStates: []string{"DE", "FR"},
		VulnID: "CVE-2026-1", Title: "RCE", Severity: "critical", Trigger: TriggerKEV, AwareAt: aware,
		EarlyWarningDueAt: aware.Add(EarlyWarningWindow), NotificationDueAt: aware.Add(NotificationWindow),
		Exploitation: "RCE via header", Impact: "full takeover",
		Finding: &CaseFinding{CVE: []string{"CVE-2026-1", "CVE-2026-2"}, Description: "desc", PackageName: "lib",
			PackageVersion: "1.0", FixedVersion: "1.1", KEV: true, KEVSources: []string{"cisa", "enisa"}}}
	m := Manufacturer{Name: "Acme", Contact: "psirt@acme.test", MainEstablishment: "DE"}

	ew := BuildPayload(c, StageEarlyWarning, m, aware)
	if !ew.Draft || ew.Schema != PayloadSchema || ew.Recipients.CSIRTCoordinatorState != "DE" || !ew.Recipients.ENISA ||
		!slices.Equal(ew.Product.MemberStates, []string{"DE", "FR"}) || !slices.Equal(ew.Vulnerability.Aliases, []string{"CVE-2026-2"}) ||
		!slices.Equal(ew.Exploitation.Evidence, []string{"Listed in the CISA Known Exploited Vulnerabilities catalog", "Listed in the ENISA (EU) Known Exploited Vulnerabilities catalog"}) ||
		!ew.DueAt.Equal(aware.Add(24*time.Hour)) {
		t.Errorf("early warning = %+v", ew)
	}
	if ew.Measures != nil || ew.Impact != nil || ew.Vulnerability.Description != "" || len(ew.Missing) != 0 {
		t.Errorf("early warning carries later stages' content: %+v", ew)
	}

	n := BuildPayload(c, StageNotification, m, aware)
	if n.Exploitation.Nature != "RCE via header" || n.Measures == nil || n.Vulnerability.Component == nil || n.Impact != nil {
		t.Errorf("notification = %+v", n)
	}
	if want := []string{"measures.corrective", "measures.user_mitigations", "sensitivity"}; !slices.Equal(n.Missing, want) {
		t.Errorf("notification missing = %v, want %v", n.Missing, want)
	}

	f := BuildPayload(c, StageFinal, m, aware)
	if f.Impact == nil || f.Impact.Description != "full takeover" || f.Measures.FixedVersion != "1.1" || f.DueAt != nil ||
		!slices.Contains(f.Missing, "measures.corrective_available_at") {
		t.Errorf("final = %+v", f)
	}
}
