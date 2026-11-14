package notify

import (
	"strings"
	"testing"
	"time"
)

func TestSummarySlot(t *testing.T) {
	at := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	// Wednesday 2026-11-11.
	cases := []struct {
		name string
		c    Channel
		now  string
		want string
	}{
		{"daily, after today's hour", Channel{Summary: SummaryDaily, SummaryHour: 8}, "2026-11-11T09:30:00Z", "2026-11-11T08:00:00Z"},
		{"daily, before today's hour", Channel{Summary: SummaryDaily, SummaryHour: 8}, "2026-11-11T07:59:00Z", "2026-11-10T08:00:00Z"},
		{"daily, exactly on the hour", Channel{Summary: SummaryDaily, SummaryHour: 8}, "2026-11-11T08:00:00Z", "2026-11-11T08:00:00Z"},
		{"weekly Monday, on Wednesday", Channel{Summary: SummaryWeekly, SummaryHour: 8, SummaryWeekday: 1}, "2026-11-11T12:00:00Z", "2026-11-09T08:00:00Z"},
		{"weekly Wednesday, before the hour", Channel{Summary: SummaryWeekly, SummaryHour: 8, SummaryWeekday: 3}, "2026-11-11T06:00:00Z", "2026-11-04T08:00:00Z"},
		{"weekly Thursday, on Wednesday", Channel{Summary: SummaryWeekly, SummaryHour: 0, SummaryWeekday: 4}, "2026-11-11T23:00:00Z", "2026-11-05T00:00:00Z"},
		{"non-UTC clock", Channel{Summary: SummaryDaily, SummaryHour: 8}, "2026-11-11T10:30:00+02:00", "2026-11-11T08:00:00Z"},
	}
	for _, c := range cases {
		slot, _, ok := SummarySlot(c.c, at(c.now))
		if !ok || !slot.Equal(at(c.want)) {
			t.Errorf("%s: slot = %v (%v), want %s", c.name, slot, ok, c.want)
		}
	}
	if _, _, ok := SummarySlot(Channel{Summary: SummaryNone}, time.Now()); ok {
		t.Error("no schedule must have no slot")
	}
}

func TestSummaryEventText(t *testing.T) {
	pid := "p1"
	e := summaryEvent(Channel{ProjectID: &pid}, SummaryData{
		New: map[string]int{"critical": 1, "low": 2}, Fixed: 3, Open: map[string]int{"high": 4},
		Breached: 1, KEV: 2, TopTitles: []string{"Log4Shell"},
	}, time.Date(2026, 11, 9, 8, 0, 0, 0, time.UTC), 7*24*time.Hour)
	if e.Type != EventSummary || e.ProjectID != "p1" || e.Title != "Weekly security summary — this project" {
		t.Errorf("event = %+v", e)
	}
	for _, want := range []string{"New: 1 critical, 2 low · Fixed: 3", "Open: 4 high", "SLA breached: 1 · Known exploited (KEV): 2", "• Log4Shell"} {
		if !strings.Contains(e.Text, want) {
			t.Errorf("text %q lacks %q", e.Text, want)
		}
	}
	if e.Fields["new"] != "3" || e.Fields["period_start"] != "2026-11-02T08:00:00Z" {
		t.Errorf("fields = %v", e.Fields)
	}
}
