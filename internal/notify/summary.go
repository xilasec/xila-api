package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Summary schedules.
const (
	SummaryNone   = "none"
	SummaryDaily  = "daily"
	SummaryWeekly = "weekly"
)

// ValidSummary reports whether s is a summary schedule.
func ValidSummary(s string) bool {
	return s == SummaryNone || s == SummaryDaily || s == SummaryWeekly
}

// SummarySlot is the most recent scheduled time at or before now for a
// channel's schedule (UTC), and the period it covers. ok is false for "none".
func SummarySlot(c Channel, now time.Time) (slot time.Time, period time.Duration, ok bool) {
	now = now.UTC()
	day := time.Date(now.Year(), now.Month(), now.Day(), c.SummaryHour, 0, 0, 0, time.UTC)
	switch c.Summary {
	case SummaryDaily:
		if day.After(now) {
			day = day.AddDate(0, 0, -1)
		}
		return day, 24 * time.Hour, true
	case SummaryWeekly:
		back := (int(now.Weekday()) - c.SummaryWeekday + 7) % 7
		day = day.AddDate(0, 0, -back)
		if day.After(now) {
			day = day.AddDate(0, 0, -7)
		}
		return day, 7 * 24 * time.Hour, true
	}
	return time.Time{}, 0, false
}

// SummaryData is what a summary reports for one scope over one period.
type SummaryData struct {
	New       map[string]int // findings first seen in the period, by severity
	Fixed     int            // findings resolved as remediated in the period
	Open      map[string]int // open findings now, by severity
	Breached  int            // open findings past their SLA
	KEV       int            // open findings in CISA KEV
	Expiring  int            // risk acceptances ending in the next 30 days
	TopTitles []string       // the highest-priority open findings
}

// SummaryStore computes summary figures (finding.Repository). projectID ""
// means the whole portfolio.
type SummaryStore interface {
	SummaryData(ctx context.Context, projectID string, since time.Time) (SummaryData, error)
}

var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// summaryEvent renders the figures as an event: a readable text plus the
// figures as fields (for webhooks and email tables).
func summaryEvent(c Channel, d SummaryData, slot time.Time, period time.Duration) Event {
	scope := "all projects"
	if c.ProjectID != nil {
		scope = "this project"
	}
	label := "Daily"
	if period > 24*time.Hour {
		label = "Weekly"
	}
	sum := func(m map[string]int) int {
		n := 0
		for _, v := range m {
			n += v
		}
		return n
	}
	bySev := func(m map[string]int) string {
		var parts []string
		for _, s := range severityOrder {
			if m[s] > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", m[s], s))
			}
		}
		if len(parts) == 0 {
			return "none"
		}
		return strings.Join(parts, ", ")
	}
	var text strings.Builder
	fmt.Fprintf(&text, "New: %s · Fixed: %d\n", bySev(d.New), d.Fixed)
	fmt.Fprintf(&text, "Open: %s\n", bySev(d.Open))
	fmt.Fprintf(&text, "SLA breached: %d · Known exploited (KEV): %d · Acceptances expiring (30d): %d",
		d.Breached, d.KEV, d.Expiring)
	if len(d.TopTitles) > 0 {
		text.WriteString("\n\nTop open:\n• " + strings.Join(d.TopTitles, "\n• "))
	}
	fields := map[string]string{
		"period_start":  slot.Add(-period).Format(time.RFC3339),
		"period_end":    slot.Format(time.RFC3339),
		"new":           strconv.Itoa(sum(d.New)),
		"new_critical":  strconv.Itoa(d.New["critical"]),
		"new_high":      strconv.Itoa(d.New["high"]),
		"fixed":         strconv.Itoa(d.Fixed),
		"open":          strconv.Itoa(sum(d.Open)),
		"open_critical": strconv.Itoa(d.Open["critical"]),
		"open_high":     strconv.Itoa(d.Open["high"]),
		"sla_breached":  strconv.Itoa(d.Breached),
		"kev":           strconv.Itoa(d.KEV),
		"expiring":      strconv.Itoa(d.Expiring),
	}
	e := Event{
		Type:      EventSummary,
		Title:     fmt.Sprintf("%s security summary — %s", label, scope),
		Text:      text.String(),
		Fields:    fields,
		Timestamp: slot,
	}
	if c.ProjectID != nil {
		e.ProjectID = *c.ProjectID
	}
	return e
}

// listSummaryChannels returns enabled channels with a summary schedule.
func (r *Repository) listSummaryChannels(ctx context.Context) ([]Channel, error) {
	rows, err := r.db.Query(ctx, `SELECT `+channelColumns+` FROM notification_channels
		WHERE enabled AND summary <> 'none' AND owner_user_id IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list summary channels: %w", err)
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// claimSummary records slot as sent for the channel and queues the event, in
// one transaction: the slot is claimed only if no one sent it yet, so two
// leaders (a handover) can't both send it.
func (r *Repository) claimSummary(ctx context.Context, channelID string, slot time.Time, e Event) (bool, error) {
	ev, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var id string
	err = tx.QueryRow(ctx, `UPDATE notification_channels SET last_summary_at = $2
		WHERE id = $1 AND (last_summary_at IS NULL OR last_summary_at < $2) RETURNING id`, channelID, slot).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim summary: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notification_outbox (channel_id, event) VALUES ($1, $2)`, channelID, ev); err != nil {
		return false, fmt.Errorf("enqueue summary: %w", err)
	}
	return true, tx.Commit(ctx)
}

// SendDueSummaries queues every channel's summary whose slot has come and
// hasn't been sent, returning how many were queued. Leader-only.
func (s *Service) SendDueSummaries(ctx context.Context, store SummaryStore, now time.Time) (int, error) {
	channels, err := s.summaries.listSummaryChannels(ctx)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, c := range channels {
		slot, period, ok := SummarySlot(c, now)
		if !ok || (c.LastSummaryAt != nil && !c.LastSummaryAt.Before(slot)) {
			continue
		}
		scope := ""
		if c.ProjectID != nil {
			scope = *c.ProjectID
		}
		d, err := store.SummaryData(ctx, scope, slot.Add(-period))
		if err != nil {
			slog.WarnContext(ctx, "notify: summary figures failed", "channel", c.Name, "error", err)
			continue
		}
		claimed, err := s.summaries.claimSummary(ctx, c.ID, slot, summaryEvent(c, d, slot, period))
		if err != nil {
			slog.WarnContext(ctx, "notify: queue summary failed", "channel", c.Name, "error", err)
			continue
		}
		if claimed {
			sent++
		}
	}
	if sent > 0 {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
	return sent, nil
}

// RunSummaries checks summary schedules every minute until ctx ends.
func (s *Service) RunSummaries(ctx context.Context, store SummaryStore) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		if _, err := s.SendDueSummaries(ctx, store, time.Now()); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "notify: summaries failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
