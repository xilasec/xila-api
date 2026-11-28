// Package metrics keeps daily snapshots of security posture — open findings by
// severity, new, closed, risk, SLA and MTTR — per project, team, org and the
// whole portfolio, and serves them as trends.
//
// A snapshot is computed from the findings' lifecycle timestamps, so any past
// day can be (re)built, with these approximations:
//
//   - A finding counts as open at the end of day D when it was first seen before
//     D ended and it is open/confirmed now, or its resolved_at is after D. A
//     finding reopened and closed again counts by its latest resolution only.
//   - Findings in an exception state (risk accepted, false positive, won't fix)
//     are not open from the moment the exception was set (resolved_at).
//   - Severity, SLA due date and duplicate status are the finding's current
//     ones; only each project's current default version counts.
//
// Snapshots taken on (or just after) the day they describe are close to exact;
// the first-run backfill marks the days it rebuilt as reconstructed.
package metrics

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

const (
	// BackfillDays is how many days (today included) the first run rebuilds, so
	// trend charts are populated on day one.
	BackfillDays = 90
	// DefaultTrendDays and MaxTrendDays bound the ?days= window of a trend.
	DefaultTrendDays = 90
	MaxTrendDays     = 365
)

// ScopeKind names what a snapshot row rolls up.
type ScopeKind string

const (
	ScopePortfolio ScopeKind = "portfolio"
	ScopeOrg       ScopeKind = "org"
	ScopeTeam      ScopeKind = "team"
	ScopeProject   ScopeKind = "project"
)

// Point is one day of a trend. Days without a snapshot are omitted, not
// zero-filled: a gap means "not measured", which a zero would misreport.
type Point struct {
	Date           string                  `json:"date"` // YYYY-MM-DD (UTC)
	OpenBySeverity map[domain.Severity]int `json:"open_by_severity"`
	OpenTotal      int                     `json:"open_total"`
	New            int                     `json:"new"`    // first seen that day
	Closed         int                     `json:"closed"` // remediated that day
	RiskScore      float64                 `json:"risk_score"`
	SLABreached    int                     `json:"sla_breached"` // open past their deadline at day end
	SLAMet         int                     `json:"sla_met"`      // fixed that day on time
	SLAMissed      int                     `json:"sla_missed"`   // fixed that day late
	// SLACompliance is met / (met + missed), 0–1; nil when nothing with an SLA
	// was fixed that day.
	SLACompliance *float64 `json:"sla_compliance"`
	// MTTRDays is the mean days from first seen to fixed over the day's closed
	// findings; nil when none closed.
	MTTRDays      *float64 `json:"mttr_days"`
	Reconstructed bool     `json:"reconstructed"`
}

// RunResult reports what a snapshot run wrote.
type RunResult struct {
	Backfilled int      `json:"backfilled"` // reconstructed days written (first run only)
	Days       []string `json:"days"`       // days snapshotted live
}

// counts is one scope's additive figures for a day.
type counts struct {
	open               [5]int // indexed like severityOrder
	newCount, closed   int
	risk               float64
	breached, met      int
	missed             int
	remediationDaysSum float64
	// The portfolio's other figures (PORTFOLIO_FROM_SNAPSHOTS).
	kev, exploitable, expiring int
	byCategory                 map[string]int
}

var severityOrder = [5]domain.Severity{
	domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium,
	domain.SeverityLow, domain.SeverityInfo,
}

func (c *counts) add(o counts) {
	for i := range c.open {
		c.open[i] += o.open[i]
	}
	c.newCount += o.newCount
	c.closed += o.closed
	c.risk += o.risk
	c.breached += o.breached
	c.met += o.met
	c.missed += o.missed
	c.remediationDaysSum += o.remediationDaysSum
	c.kev += o.kev
	c.exploitable += o.exploitable
	c.expiring += o.expiring
	for k, n := range o.byCategory {
		if c.byCategory == nil {
			c.byCategory = map[string]int{}
		}
		c.byCategory[k] += n
	}
}

// ExploitableEPSS is the EPSS at or above which an open finding not on a KEV
// list still counts as exploitable in the portfolio (live and snapshots).
const ExploitableEPSS = 0.5

// ExpiringSoonDays is the window of "exceptions expiring soon".
const ExpiringSoonDays = 30

// Repository reads and writes metric snapshots.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// utcDay truncates t to the start of its UTC day.
func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Run is the periodic job: on the very first run (no snapshots at all) it
// reconstructs the last BackfillDays, then it snapshots yesterday — so the day
// closes out with its final numbers — and today.
func (r *Repository) Run(ctx context.Context, now time.Time) (RunResult, error) {
	today := utcDay(now)
	yesterday := today.AddDate(0, 0, -1)
	out := RunResult{Days: []string{}}

	var exists bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM metric_snapshots)`).Scan(&exists); err != nil {
		return out, fmt.Errorf("check snapshots: %w", err)
	}
	if !exists {
		// Yesterday and today are written live below.
		for d := today.AddDate(0, 0, -(BackfillDays - 1)); d.Before(yesterday); d = d.AddDate(0, 0, 1) {
			if err := r.snapshot(ctx, d, true); err != nil {
				return out, err
			}
			out.Backfilled++
		}
	}
	for _, d := range []time.Time{yesterday, today} {
		if err := r.Snapshot(ctx, d); err != nil {
			return out, err
		}
		out.Days = append(out.Days, d.Format(time.DateOnly))
	}
	return out, nil
}

// Snapshot computes every scope's figures for the UTC day containing day and
// replaces whatever was stored for that day.
func (r *Repository) Snapshot(ctx context.Context, day time.Time) error {
	return r.snapshot(ctx, day, false)
}

// projectDaySQL computes each project's figures for one day. $1/$2 bound the
// day [start, end); breaches are judged at the earlier of day end and now, so
// today's row matches the live SLA view. Archived projects and findings are
// left out, like everywhere else.
var projectDaySQL = `
	WITH f AS (
		SELECT project_id, severity, first_seen_at, resolved_at, sla_due_at, kev, epss, category,
		       ` + finding.ExceptionExpirySQL + ` AS exception_expiry,
		       (status IN ('open', 'confirmed') OR resolved_at >= $2) AS is_open,
		       (status = 'remediated' AND resolved_at >= $1 AND resolved_at < $2) AS is_closed
		FROM findings
		WHERE duplicate_of IS NULL AND first_seen_at < $2
		  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
		  AND` + archive.Finding("") + `
	),
	cats AS (
		SELECT project_id, jsonb_object_agg(category, n) AS cats
		FROM (SELECT project_id, category, count(*) AS n FROM f WHERE is_open GROUP BY project_id, category) g
		GROUP BY project_id
	)
	SELECT m.*, COALESCE(c.cats, '{}') FROM (
	SELECT p.id, p.team_id, t.org_id, p.business_criticality,
		count(f.project_id) FILTER (WHERE f.is_open AND f.severity = 'critical'),
		count(f.project_id) FILTER (WHERE f.is_open AND f.severity = 'high'),
		count(f.project_id) FILTER (WHERE f.is_open AND f.severity = 'medium'),
		count(f.project_id) FILTER (WHERE f.is_open AND f.severity = 'low'),
		count(f.project_id) FILTER (WHERE f.is_open AND f.severity = 'info'),
		count(f.project_id) FILTER (WHERE f.first_seen_at >= $1),
		count(f.project_id) FILTER (WHERE f.is_closed),
		count(f.project_id) FILTER (WHERE f.is_open AND f.sla_due_at < LEAST($2, now())),
		count(f.project_id) FILTER (WHERE f.is_closed AND f.resolved_at <= f.sla_due_at),
		count(f.project_id) FILTER (WHERE f.is_closed AND f.resolved_at > f.sla_due_at),
		COALESCE(sum(extract(epoch FROM f.resolved_at - f.first_seen_at) / 86400) FILTER (WHERE f.is_closed), 0)::float8,
		count(f.project_id) FILTER (WHERE f.is_open AND f.kev),
		count(f.project_id) FILTER (WHERE f.is_open AND (f.kev OR f.epss >= $3)),
		count(f.project_id) FILTER (WHERE f.exception_expiry > LEAST($2, now())
		                            AND f.exception_expiry <= LEAST($2, now()) + make_interval(days => $4))
	FROM projects p
	JOIN teams t ON t.id = p.team_id
	LEFT JOIN f ON f.project_id = p.id
	WHERE` + archive.Project("p") + `
	GROUP BY p.id, t.org_id
	) m
	-- Joined outside the grouped query: as a scalar subquery per project the
	-- planner rescans the whole CTE for each project (minutes at 10M).
	LEFT JOIN cats c ON c.project_id = m.id`

type scopeKey struct {
	kind ScopeKind
	id   string // "" for the portfolio
}

func (r *Repository) snapshot(ctx context.Context, day time.Time, reconstructed bool) error {
	start := utcDay(day)
	end := start.AddDate(0, 0, 1)

	scopes := map[scopeKey]*counts{{kind: ScopePortfolio}: {}}
	order := []scopeKey{{kind: ScopePortfolio}}
	get := func(k scopeKey) *counts {
		c, ok := scopes[k]
		if !ok {
			c = &counts{}
			scopes[k] = c
			order = append(order, k)
		}
		return c
	}

	// Teams and orgs without projects still get a (zero) row, so their trend
	// starts the day they exist rather than with their first project.
	rows, err := r.db.Query(ctx, `SELECT o.id, t.id FROM organizations o LEFT JOIN teams t ON t.org_id = o.id`)
	if err != nil {
		return fmt.Errorf("list scopes: %w", err)
	}
	for rows.Next() {
		var orgID string
		var teamID *string
		if err := rows.Scan(&orgID, &teamID); err != nil {
			rows.Close()
			return fmt.Errorf("scan scope: %w", err)
		}
		get(scopeKey{ScopeOrg, orgID})
		if teamID != nil {
			get(scopeKey{ScopeTeam, *teamID})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("list scopes: %w", err)
	}

	rows, err = r.db.Query(ctx, projectDaySQL, start, end, ExploitableEPSS, ExpiringSoonDays)
	if err != nil {
		return fmt.Errorf("compute day %s: %w", start.Format(time.DateOnly), err)
	}
	for rows.Next() {
		var (
			projectID, teamID, orgID string
			crit                     domain.Criticality
			c                        counts
		)
		if err := rows.Scan(&projectID, &teamID, &orgID, &crit,
			&c.open[0], &c.open[1], &c.open[2], &c.open[3], &c.open[4],
			&c.newCount, &c.closed, &c.breached, &c.met, &c.missed, &c.remediationDaysSum,
			&c.kev, &c.exploitable, &c.expiring, &c.byCategory); err != nil {
			rows.Close()
			return fmt.Errorf("scan day row: %w", err)
		}
		c.risk = projectRisk(c.open, crit)
		*get(scopeKey{ScopeProject, projectID}) = c
		get(scopeKey{ScopeTeam, teamID}).add(c)
		get(scopeKey{ScopeOrg, orgID}).add(c)
		get(scopeKey{kind: ScopePortfolio}).add(c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("compute day %s: %w", start.Format(time.DateOnly), err)
	}

	snapRows := make([][]any, 0, len(order))
	for _, k := range order {
		c := scopes[k]
		var id any
		if k.id != "" {
			id = k.id
		}
		total := 0
		for _, n := range c.open {
			total += n
		}
		snapRows = append(snapRows, []any{
			start, string(k.kind), id,
			c.open[0], c.open[1], c.open[2], c.open[3], c.open[4], total,
			c.newCount, c.closed, roundTenth(c.risk),
			c.breached, c.met, c.missed, c.remediationDaysSum, reconstructed,
			c.kev, c.exploitable, categoryMap(c.byCategory), c.expiring,
		})
	}

	// Replace the whole day atomically: rows of scopes deleted since the last
	// run go too. The advisory lock serializes concurrent runs (replicas).
	return pgx.BeginFunc(ctx, r.db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('metric_snapshots'))`); err != nil {
			return fmt.Errorf("lock snapshots: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM metric_snapshots WHERE day = $1`, start); err != nil {
			return fmt.Errorf("clear day: %w", err)
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"metric_snapshots"}, []string{
			"day", "scope_kind", "scope_id",
			"open_critical", "open_high", "open_medium", "open_low", "open_info", "open_total",
			"new_count", "closed_count", "risk_score",
			"sla_breached", "sla_met", "sla_missed", "remediation_days_sum", "reconstructed",
			"open_kev", "open_exploitable", "open_by_category", "expiring_soon",
		}, pgx.CopyFromRows(snapRows))
		if err != nil {
			return fmt.Errorf("write snapshots: %w", err)
		}
		return nil
	})
}

// projectRisk is the project summary's risk score: severity weight × open
// count, scaled by business criticality (rounded like the portfolio rollup).
func projectRisk(open [5]int, crit domain.Criticality) float64 {
	var weighted float64
	for i, n := range open {
		weighted += severityOrder[i].Weight() * float64(n)
	}
	return roundTenth(weighted * crit.Multiplier())
}

func roundTenth(v float64) float64 { return math.Round(v*10) / 10 }

// trendSelect sums snapshot rows per day; with one scope it is that scope's
// series, with many project rows it is their aggregate.
const trendSelect = `
	SELECT day,
		sum(open_critical), sum(open_high), sum(open_medium), sum(open_low), sum(open_info),
		sum(open_total), sum(new_count), sum(closed_count), sum(risk_score),
		sum(sla_breached), sum(sla_met), sum(sla_missed), sum(remediation_days_sum),
		bool_or(reconstructed)
	FROM metric_snapshots`

// Trend returns one stored scope's daily series covering the last `days` days
// (today included), oldest first. id is ignored for the portfolio.
func (r *Repository) Trend(ctx context.Context, kind ScopeKind, id string, days int, now time.Time) ([]Point, error) {
	var scopeID any
	if kind != ScopePortfolio {
		scopeID = id
	}
	q := trendSelect + `
		WHERE scope_kind = $1 AND scope_id IS NOT DISTINCT FROM $2::uuid AND day >= $3
		GROUP BY day ORDER BY day`
	return r.trend(ctx, q, string(kind), scopeID, since(now, days))
}

// ProjectsTrend aggregates the project rows of projectIDs — the RBAC-scoped
// view of the portfolio (or, with orgID set, of one org), which must not
// include projects the caller cannot see.
func (r *Repository) ProjectsTrend(ctx context.Context, projectIDs []string, orgID string, days int, now time.Time) ([]Point, error) {
	if projectIDs == nil {
		projectIDs = []string{}
	}
	var org any
	if orgID != "" {
		org = orgID
	}
	q := trendSelect + `
		WHERE scope_kind = 'project' AND scope_id = ANY($1::uuid[]) AND day >= $2
		  AND scope_id IN (SELECT id FROM projects WHERE` + archive.Project("") + `)
		  AND ($3::uuid IS NULL OR scope_id IN (
		      SELECT p.id FROM projects p JOIN teams t ON t.id = p.team_id WHERE t.org_id = $3))
		GROUP BY day ORDER BY day`
	return r.trend(ctx, q, projectIDs, since(now, days), org)
}

// since is the first day of a days-long window ending today.
func since(now time.Time, days int) time.Time {
	return utcDay(now).AddDate(0, 0, -(days - 1))
}

func (r *Repository) trend(ctx context.Context, q string, args ...any) ([]Point, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("trend: %w", err)
	}
	defer rows.Close()
	out := []Point{}
	for rows.Next() {
		var (
			day         time.Time
			c           counts
			total       int
			reconstruct bool
		)
		if err := rows.Scan(&day, &c.open[0], &c.open[1], &c.open[2], &c.open[3], &c.open[4],
			&total, &c.newCount, &c.closed, &c.risk,
			&c.breached, &c.met, &c.missed, &c.remediationDaysSum, &reconstruct); err != nil {
			return nil, fmt.Errorf("scan trend: %w", err)
		}
		out = append(out, toPoint(day, c, total, reconstruct))
	}
	return out, rows.Err()
}

func toPoint(day time.Time, c counts, total int, reconstructed bool) Point {
	p := Point{
		Date:           day.Format(time.DateOnly),
		OpenBySeverity: make(map[domain.Severity]int, len(severityOrder)),
		OpenTotal:      total,
		New:            c.newCount,
		Closed:         c.closed,
		RiskScore:      roundTenth(c.risk),
		SLABreached:    c.breached,
		SLAMet:         c.met,
		SLAMissed:      c.missed,
		Reconstructed:  reconstructed,
	}
	for i, sev := range severityOrder {
		p.OpenBySeverity[sev] = c.open[i]
	}
	if n := c.met + c.missed; n > 0 {
		p.SLACompliance = new(float64(c.met) / float64(n))
	}
	if c.closed > 0 {
		p.MTTRDays = new(math.Round(c.remediationDaysSum/float64(c.closed)*10) / 10)
	}
	return p
}

// categoryMap is a snapshot's open_by_category (never NULL).
func categoryMap(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}
