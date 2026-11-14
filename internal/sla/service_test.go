package sla

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/notify"
)

type fakeMarker struct{ breached, dueSoon []Hit }

func (f fakeMarker) MarkBreached(context.Context) ([]Hit, error) { return f.breached, nil }
func (f fakeMarker) MarkDueSoon(context.Context, float64) ([]Hit, error) {
	return f.dueSoon, nil
}

type captureNotifier struct{ events []notify.Event }

func (c *captureNotifier) Notify(_ context.Context, e notify.Event) { c.events = append(c.events, e) }

// A sweep sends one alert per project per kind, listing the worst first and
// capping the list — 300 overdue findings must be one message, not 300.
func TestSweepGroupsAlertsPerProject(t *testing.T) {
	due := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var breached []Hit
	for i := range 7 {
		breached = append(breached, Hit{FindingID: "a", ProjectID: "p1", ProjectName: "web", Severity: "low",
			Title: "low-" + string(rune('a'+i)), DueAt: due})
	}
	breached = append(breached, Hit{FindingID: "crit", ProjectID: "p1", ProjectName: "web", Severity: "critical",
		Title: "the critical one", DueAt: due.Add(48 * time.Hour)})
	single := Hit{FindingID: "only", ProjectID: "p2", ProjectName: "api", Severity: "high", Title: "lone", DueAt: due}

	n := &captureNotifier{}
	svc := NewService(fakeMarker{breached: breached, dueSoon: []Hit{single}}, n)
	res, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if res.Breached != 8 || res.DueSoon != 1 {
		t.Errorf("result = %+v, want 8 breached / 1 due soon", res)
	}
	if len(n.events) != 2 {
		t.Fatalf("events = %d, want one per (project, kind) = 2", len(n.events))
	}

	web := n.events[0]
	if web.Type != notify.EventSLABreach || web.ProjectID != "p1" {
		t.Fatalf("first event = %s/%s, want breach for p1", web.Type, web.ProjectID)
	}
	if web.Fields["count"] != "8" || web.Severity != "critical" {
		t.Errorf("count/severity = %s/%s, want 8/critical", web.Fields["count"], web.Severity)
	}
	lines := strings.Split(web.Text, "\n")
	if !strings.Contains(lines[0], "the critical one") {
		t.Errorf("worst severity must lead, got %q", lines[0])
	}
	if last := lines[len(lines)-1]; last != "…and 3 more" {
		t.Errorf("list must cap at %d and summarize the rest, last line %q", maxListed, last)
	}
	if web.FindingID != "" {
		t.Errorf("a grouped alert must not point at one finding, got %q", web.FindingID)
	}

	api := n.events[1]
	if api.Type != notify.EventSLADueSoon || api.FindingID != "only" {
		t.Errorf("single-finding alert = %s/%q, want due-soon linking its finding", api.Type, api.FindingID)
	}
}
