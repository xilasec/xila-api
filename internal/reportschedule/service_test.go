package reportschedule

import (
	"testing"
	"time"
)

func TestIsDue(t *testing.T) {
	now := time.Date(2026, time.January, 6, 8, 0, 0, 0, time.UTC) // a Tuesday

	cases := []struct {
		name string
		sch  Schedule
		want bool
	}{
		{"daily, right hour, never run", Schedule{Enabled: true, Cadence: CadenceDaily, Hour: 8}, true},
		{"daily, wrong hour", Schedule{Enabled: true, Cadence: CadenceDaily, Hour: 9}, false},
		{"daily, already ran today", Schedule{Enabled: true, Cadence: CadenceDaily, Hour: 8,
			LastRunAt: new(now.Add(-time.Hour))}, false},
		{"daily, ran yesterday", Schedule{Enabled: true, Cadence: CadenceDaily, Hour: 8,
			LastRunAt: new(now.AddDate(0, 0, -1))}, true},
		{"disabled", Schedule{Enabled: false, Cadence: CadenceDaily, Hour: 8}, false},
		{"weekly, matching weekday", Schedule{Enabled: true, Cadence: CadenceWeekly, Hour: 8, Weekday: new(2)}, true},
		{"weekly, wrong weekday", Schedule{Enabled: true, Cadence: CadenceWeekly, Hour: 8, Weekday: new(3)}, false},
		{"weekly, already ran this week", Schedule{Enabled: true, Cadence: CadenceWeekly, Hour: 8, Weekday: new(2),
			LastRunAt: new(now.AddDate(0, 0, -1))}, false},
		{"weekly, ran last week", Schedule{Enabled: true, Cadence: CadenceWeekly, Hour: 8, Weekday: new(2),
			LastRunAt: new(now.AddDate(0, 0, -7))}, true},
		{"monthly, matching day", Schedule{Enabled: true, Cadence: CadenceMonthly, Hour: 8, DayOfMonth: new(6)}, true},
		{"monthly, wrong day", Schedule{Enabled: true, Cadence: CadenceMonthly, Hour: 8, DayOfMonth: new(7)}, false},
		{"monthly, already ran this month", Schedule{Enabled: true, Cadence: CadenceMonthly, Hour: 8, DayOfMonth: new(6),
			LastRunAt: new(now.AddDate(0, 0, -5))}, false},
		{"monthly, ran last month", Schedule{Enabled: true, Cadence: CadenceMonthly, Hour: 8, DayOfMonth: new(6),
			LastRunAt: new(now.AddDate(0, -1, 0))}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isDue(c.sch, now); got != c.want {
				t.Errorf("isDue() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestInputNormalize(t *testing.T) {
	pid := "11111111-1111-1111-1111-111111111111"
	cases := []struct {
		name    string
		in      Input
		wantErr bool
	}{
		{"missing name", Input{Kind: KindPortfolio, Cadence: CadenceDaily, Hour: 8,
			RecipientEmails: []string{"a@x.io"}}, true},
		{"project without project_id", Input{Name: "x", Kind: KindProject, Cadence: CadenceDaily, Hour: 8,
			RecipientEmails: []string{"a@x.io"}}, true},
		{"evidence without framework", Input{Name: "x", Kind: KindEvidence, ProjectID: &pid, Cadence: CadenceDaily,
			Hour: 8, RecipientEmails: []string{"a@x.io"}}, true},
		{"weekly without weekday", Input{Name: "x", Kind: KindPortfolio, Cadence: CadenceWeekly, Hour: 8,
			RecipientEmails: []string{"a@x.io"}}, true},
		{"monthly without day", Input{Name: "x", Kind: KindPortfolio, Cadence: CadenceMonthly, Hour: 8,
			RecipientEmails: []string{"a@x.io"}}, true},
		{"bad hour", Input{Name: "x", Kind: KindPortfolio, Cadence: CadenceDaily, Hour: 24,
			RecipientEmails: []string{"a@x.io"}}, true},
		{"no recipients", Input{Name: "x", Kind: KindPortfolio, Cadence: CadenceDaily, Hour: 8}, true},
		{"bad email", Input{Name: "x", Kind: KindPortfolio, Cadence: CadenceDaily, Hour: 8,
			RecipientEmails: []string{"not-an-email"}}, true},
		{"valid portfolio daily", Input{Name: "x", Kind: KindPortfolio, Cadence: CadenceDaily, Hour: 8,
			RecipientEmails: []string{"a@x.io"}}, false},
		{"valid project weekly", Input{Name: "x", Kind: KindProject, ProjectID: &pid, Cadence: CadenceWeekly,
			Hour: 8, Weekday: new(1), RecipientEmails: []string{"a@x.io"}}, false},
		{"valid evidence monthly, channel recipient", Input{Name: "x", Kind: KindEvidence, ProjectID: &pid,
			FrameworkKey: "eu-cra", Cadence: CadenceMonthly, Hour: 8, DayOfMonth: new(1),
			RecipientChannelIDs: []string{"chan"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.in.Normalize()
			if (err != nil) != c.wantErr {
				t.Errorf("Normalize() error = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}
