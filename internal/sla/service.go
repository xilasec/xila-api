package sla

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/notify"
)

// Notifier delivers events.
type Notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// marker is the part of Repository the sweep needs (faked in tests).
type marker interface {
	MarkBreached(ctx context.Context) ([]Hit, error)
	MarkDueSoon(ctx context.Context, fraction float64) ([]Hit, error)
}

// Service runs the SLA sweep.
type Service struct {
	repo     marker
	notifier Notifier
}

// NewService constructs a Service. notifier may be nil (sweep still records).
func NewService(repo marker, notifier Notifier) *Service {
	return &Service{repo: repo, notifier: notifier}
}

// SweepResult is how many findings a sweep newly alerted about.
type SweepResult struct {
	Breached int `json:"breached"`
	DueSoon  int `json:"due_soon"`
}

// maxListed caps how many findings one alert names; the count covers the rest.
const maxListed = 5

// Sweep finds findings that newly breached their SLA or entered the due-soon
// tail, and sends one alert per project per kind — a backlog of 300 overdue
// findings is one message, not 300. Each finding is alerted once per deadline.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	breached, err := s.repo.MarkBreached(ctx)
	if err != nil {
		return SweepResult{}, err
	}
	dueSoon, err := s.repo.MarkDueSoon(ctx, domain.SLADueSoonFraction)
	if err != nil {
		return SweepResult{}, err
	}
	if s.notifier != nil {
		for _, e := range events(notify.EventSLABreach, breached) {
			s.notifier.Notify(ctx, e)
		}
		for _, e := range events(notify.EventSLADueSoon, dueSoon) {
			s.notifier.Notify(ctx, e)
		}
	}
	return SweepResult{Breached: len(breached), DueSoon: len(dueSoon)}, nil
}

// events groups hits into one event per project, worst severity first. Pure.
func events(kind string, hits []Hit) []notify.Event {
	byProject := map[string][]Hit{}
	var order []string
	for _, h := range hits {
		if _, seen := byProject[h.ProjectID]; !seen {
			order = append(order, h.ProjectID)
		}
		byProject[h.ProjectID] = append(byProject[h.ProjectID], h)
	}
	slices.Sort(order)

	out := make([]notify.Event, 0, len(order))
	for _, pid := range order {
		group := byProject[pid]
		slices.SortStableFunc(group, func(a, b Hit) int {
			if c := cmp.Compare(domain.Severity(b.Severity).Weight(), domain.Severity(a.Severity).Weight()); c != 0 {
				return c
			}
			return a.DueAt.Compare(b.DueAt)
		})

		verb := "breached their remediation SLA"
		if kind == notify.EventSLADueSoon {
			verb = "are approaching their remediation SLA"
		}
		var b strings.Builder
		for i, h := range group {
			if i == maxListed {
				fmt.Fprintf(&b, "…and %d more", len(group)-maxListed)
				break
			}
			fmt.Fprintf(&b, "• [%s] %s (due %s)\n", h.Severity, h.Title, h.DueAt.UTC().Format("2006-01-02"))
		}
		e := notify.Event{
			Type:      kind,
			Title:     fmt.Sprintf("%s: %d finding(s) %s", group[0].ProjectName, len(group), verb),
			Text:      strings.TrimSpace(b.String()),
			Severity:  group[0].Severity,
			ProjectID: pid,
			Fields:    map[string]string{"count": fmt.Sprintf("%d", len(group)), "project": group[0].ProjectName},
		}
		if len(group) == 1 {
			e.FindingID = group[0].FindingID
		}
		out = append(out, e)
	}
	return out
}
