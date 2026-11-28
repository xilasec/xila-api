package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/expr"
)

// A channel's filter is a CEL expression over the event (internal/expr): the
// channel gets the event only when it holds, on top of its event types,
// project scope and minimum severity. Unknown facts are null and never match,
// and an expression that can't be evaluated is "no match" for that channel
// only — it never blocks the others.

// EventFacts are what a filter can know beyond the event itself: the project
// and the finding it names. Either is nil when the event names none (or it is
// gone).
type EventFacts struct {
	Project map[string]any
	Finding map[string]any
}

// factsLoader loads EventFacts; the Postgres Repository implements it.
type factsLoader interface {
	EventFacts(ctx context.Context, projectID, findingID string) (EventFacts, error)
}

// eventDoc is the document a filter reads.
func eventDoc(e Event, f EventFacts) map[string]any {
	fields := make(map[string]any, len(e.Fields))
	for k, v := range e.Fields {
		fields[k] = v
	}
	var severity, projectID, findingID, project, finding any
	if e.Severity != "" {
		severity = e.Severity
	}
	if e.ProjectID != "" {
		projectID = e.ProjectID
	}
	if e.FindingID != "" {
		findingID = e.FindingID
	}
	if f.Project != nil {
		project = f.Project
	}
	if f.Finding != nil {
		finding = f.Finding
	}
	return map[string]any{"event": map[string]any{
		"type": e.Type, "title": e.Title, "severity": severity,
		"project_id": projectID, "finding_id": findingID, "fields": fields,
		"project": project, "finding": finding,
	}}
}

// EventSchema is what channel filters are checked against when saved, built
// by eventDoc itself so the two can't drift.
var EventSchema = func() expr.Schema {
	return expr.Schema{Vars: []string{"event"}, Sample: eventDoc(
		Event{Type: EventCriticalFinding, Title: "t", Severity: "critical", ProjectID: "p", FindingID: "f",
			Fields: map[string]string{"count": "1"}},
		EventFacts{
			Project: map[string]any{"name": "web", "slug": "web", "tags": []any{"pci"}, "criticality": "high"},
			Finding: map[string]any{
				"scanner": "trivy", "category": "sca", "rule_id": "CVE-2021-44228", "title": "t",
				"severity": "critical", "status": "open", "cve": []any{"CVE-2021-44228"},
				"cvss": 10.0, "epss": 0.9, "kev": true, "kev_sources": []any{"cisa"}, "kev_ransomware": true,
				"package": "log4j-core", "fixed_version": "2.15.0", "file_path": "pom.xml", "tags": []any{"pci"},
			},
		})}
}()

// CompileFilter validates a channel filter; "" means none.
func CompileFilter(src string) error {
	if src == "" {
		return nil
	}
	_, err := expr.Compile(EventSchema, src)
	return err
}

// filterCache keeps compiled filters by source: Notify runs on every event.
var filterCache sync.Map // string → *expr.Program

func compiledFilter(src string) (*expr.Program, error) {
	if p, ok := filterCache.Load(src); ok {
		if prog, ok := p.(*expr.Program); ok {
			return prog, nil
		}
	}
	p, err := expr.Compile(EventSchema, src)
	if err != nil {
		return nil, err
	}
	filterCache.Store(src, p)
	return p, nil
}

// applyFilters keeps the channels whose filter holds for e. Facts are loaded
// only when some channel has a filter.
func (s *Service) applyFilters(ctx context.Context, e Event, channels []Channel) []Channel {
	var doc map[string]any
	out := channels[:0:0]
	for _, ch := range channels {
		if ch.Filter == "" {
			out = append(out, ch)
			continue
		}
		if doc == nil {
			var facts EventFacts
			if l, ok := s.channels.(factsLoader); ok {
				var err error
				if facts, err = l.EventFacts(ctx, e.ProjectID, e.FindingID); err != nil {
					// The filters see only the event; facts they need are null
					// and so don't match.
					slog.WarnContext(ctx, "notify: load event facts failed", "error", err, "event", e.Type)
				}
			}
			doc = eventDoc(e, facts)
		}
		p, err := compiledFilter(ch.Filter)
		if err != nil {
			// Saved before a schema change: skip this channel, keep the rest.
			slog.WarnContext(ctx, "notify: channel filter no longer compiles", "channel", ch.ID, "error", err)
			continue
		}
		if p.Match(ctx, doc) {
			out = append(out, ch)
		}
	}
	return out
}

// EventFacts loads the project and finding an event names.
func (r *Repository) EventFacts(ctx context.Context, projectID, findingID string) (EventFacts, error) {
	var f EventFacts
	if projectID != "" {
		var name, slug, crit string
		var tags []string
		err := r.db.QueryRow(ctx, `SELECT name, slug, tags, COALESCE(business_criticality, '')
			FROM projects WHERE id::text = $1`, projectID).Scan(&name, &slug, &tags, &crit)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return f, fmt.Errorf("load project facts: %w", err)
		default:
			var critVal any
			if crit != "" {
				critVal = crit
			}
			f.Project = map[string]any{"name": name, "slug": slug, "tags": anyList(tags), "criticality": critVal}
		}
	}
	if findingID != "" {
		var scanner, category, ruleID, title, severity, status, pkg, fixed, path string
		var cve, kevSources, tags []string
		var cvss, epss *float64
		var kev, ransomware bool
		err := r.db.QueryRow(ctx, `SELECT scanner, category, rule_id, title, severity, status, cve, cvss, epss, kev,
				kev_sources, kev_ransomware, package_name, fixed_version, file_path, tags
			FROM findings WHERE id::text = $1`, findingID).Scan(&scanner, &category, &ruleID, &title, &severity,
			&status, &cve, &cvss, &epss, &kev, &kevSources, &ransomware, &pkg, &fixed, &path, &tags)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return f, fmt.Errorf("load finding facts: %w", err)
		default:
			var cvssVal, epssVal any
			if cvss != nil {
				cvssVal = *cvss
			}
			if epss != nil {
				// A REAL: round to EPSS's 5 decimals so `epss >= 0.9` holds for 0.9.
				epssVal = math.Round(*epss*1e5) / 1e5
			}
			f.Finding = map[string]any{
				"scanner": scanner, "category": category, "rule_id": ruleID, "title": title,
				"severity": severity, "status": status, "cve": anyList(cve), "cvss": cvssVal, "epss": epssVal,
				"kev": kev, "kev_sources": anyList(kevSources), "kev_ransomware": ransomware, "package": pkg, "fixed_version": fixed,
				"file_path": path, "tags": anyList(tags),
			}
		}
	}
	return f, nil
}

func anyList(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
