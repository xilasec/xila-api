package triage

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// scheduledRules is staticRules with due schedules, recording which got stamped.
type scheduledRules struct {
	staticRules
	due    []Rule
	marked []string
}

func (s *scheduledRules) DueSchedules(context.Context, time.Time) ([]Rule, error) { return s.due, nil }
func (s *scheduledRules) MarkScheduleRun(_ context.Context, id string, _ time.Time) error {
	s.marked = append(s.marked, id)
	return nil
}

// failingFindings can't load the backlog.
type failingFindings struct{ *recordingFindings }

func (failingFindings) ListForTriage(context.Context, string) ([]finding.Finding, error) {
	return nil, errors.New("db down")
}

// A due rule runs over its project and is stamped only once that run
// succeeded, so a failed run is retried on the next tick rather than skipped
// for a day.
func TestRunSchedules(t *testing.T) {
	ctx := context.Background()
	pid := "p1"
	old := Rule{ID: "r-age", Name: "aged", Action: ActionSetSeverity, NewSeverity: domain.SeverityCritical,
		Schedule: ScheduleDaily, ProjectID: &pid, Severities: []domain.Severity{domain.SeverityHigh}}
	src := &scheduledRules{staticRules: staticRules{old}, due: []Rule{old}}
	store := newRecording(finding.Finding{ID: "f1", ProjectID: pid, Severity: domain.SeverityHigh, Status: domain.FindingOpen})

	changed, err := NewService(src, store, nil).RunSchedules(ctx, time.Now())
	if err != nil || changed != 1 || store.severities["f1"] != domain.SeverityCritical {
		t.Fatalf("run = %d, %v, severities %v", changed, err, store.severities)
	}
	if !slices.Equal(src.marked, []string{"r-age"}) {
		t.Errorf("marked = %v, want the rule stamped", src.marked)
	}

	src.marked = nil
	if _, err := NewService(src, failingFindings{store}, nil).RunSchedules(ctx, time.Now()); err == nil {
		t.Fatal("a failed run must report its error")
	}
	if len(src.marked) != 0 {
		t.Errorf("a failed run stamped %v; it must be retried", src.marked)
	}
}
