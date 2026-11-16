// Package portfolio aggregates security posture across every project: risk,
// findings by severity/category (appsec, SCA, cloud, k8s…), exploitability, and
// average compliance — the executive rollup.
package portfolio

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/metrics"
)

// The portfolio's exploitable and expiring-soon rules, shared with the
// snapshots that can serve it (PORTFOLIO_FROM_SNAPSHOTS).
const (
	exploitableEPSS  = metrics.ExploitableEPSS
	expiringSoonDays = metrics.ExpiringSoonDays
)

// ProjectRisk is a single project's contribution, for the "top risk" list.
type ProjectRisk struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Slug      string  `json:"slug"`
	RiskScore float64 `json:"risk_score"`
	TotalOpen int     `json:"total_open"`
	Critical  int     `json:"critical"`
}

// FrameworkAverage is a framework's mean compliance score across projects.
type FrameworkAverage struct {
	Framework        string  `json:"framework"`
	Name             string  `json:"name"`
	AvgScore         float64 `json:"avg_score"`
	ProjectsAssessed int     `json:"projects_assessed"`
}

// Overview is the whole-portfolio posture.
type Overview struct {
	Projects        int                     `json:"projects"`
	TotalOpen       int                     `json:"total_open"`
	RiskScore       float64                 `json:"risk_score"`
	KEVOpen         int                     `json:"kev_open"`
	ExploitableOpen int                     `json:"exploitable_open"`
	ExpiringSoon    int                     `json:"expiring_soon"` // risk acceptances lapsing within 30d
	OpenBySeverity  map[domain.Severity]int `json:"open_by_severity"`
	OpenByCategory  map[domain.Category]int `json:"open_by_category"`
	Compliance      []FrameworkAverage      `json:"compliance"`
	TopProjects     []ProjectRisk           `json:"top_projects"`
	// SLA is the estate's posture against its remediation deadlines.
	SLA finding.SLAStats `json:"sla"`
	// Source is "live" (computed from findings now) or "snapshots" (the
	// latest metric snapshots, PORTFOLIO_FROM_SNAPSHOTS); AsOf is when those
	// snapshots were taken. Compliance and SLA are always live.
	Source string     `json:"source"`
	AsOf   *time.Time `json:"as_of,omitempty"`
}

// Repository computes portfolio aggregates.
type Repository struct {
	db       *pgxpool.Pool
	findings *finding.Repository
	// snapshots serves the counts, risk and top projects from the latest
	// metric snapshots instead of scanning findings (PORTFOLIO_FROM_SNAPSHOTS).
	snapshots bool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db, findings: finding.NewRepository(db)}
}

// WithSnapshots serves the portfolio's finding counts from the latest metric
// snapshots (as of the last METRICS_SNAPSHOT_INTERVAL run) rather than
// scanning every finding on each request: past 100M findings the live scans
// are the slow part. Compliance and SLA stay live.
func (r *Repository) WithSnapshots(on bool) *Repository {
	r.snapshots = on
	return r
}

// Overview builds the rollup. pids restricts to a set of projects for RBAC; a
// nil slice means unrestricted (admin / whole instance).
//
// Its aggregates each scan the portfolio's findings and write disjoint fields
// of the result, so they run concurrently: the response takes as long as the
// slowest one rather than their sum (docs/SCALE.md). The first error cancels
// the rest.
func (r *Repository) Overview(ctx context.Context, pids []string) (Overview, error) {
	out := Overview{
		OpenBySeverity: map[domain.Severity]int{},
		OpenByCategory: map[domain.Category]int{},
		TopProjects:    []ProjectRisk{},
		Compliance:     []FrameworkAverage{},
		Source:         "live",
	}
	var snapDay *time.Time
	if r.snapshots {
		var day *time.Time
		if err := r.db.QueryRow(ctx, `SELECT max(day) FROM metric_snapshots WHERE scope_kind = 'project'`).Scan(&day); err != nil {
			return Overview{}, fmt.Errorf("latest snapshot: %w", err)
		}
		snapDay = day // nil (no snapshot yet): computed live
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	run := func(f func() error) {
		wg.Go(func() {
			if err := f(); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
					cancel()
				}
				mu.Unlock()
			}
		})
	}
	run(func() error {
		if err := r.db.QueryRow(ctx,
			`SELECT count(*) FROM projects WHERE`+archive.Project("")+` AND ($1::uuid[] IS NULL OR id = ANY($1))`, pids).Scan(&out.Projects); err != nil {
			return fmt.Errorf("count projects: %w", err)
		}
		return nil
	})
	if snapDay != nil {
		run(func() error { return r.fromSnapshots(ctx, &out, pids, *snapDay) })
	} else {
		run(func() error { return r.aggregateRisk(ctx, &out, pids) })
		run(func() error { return r.aggregateCategory(ctx, &out, pids) })
		run(func() error { return r.aggregateExploit(ctx, &out, pids) })
		run(func() error { return r.aggregateExpiring(ctx, &out, pids) })
	}
	run(func() error { return r.aggregateCompliance(ctx, &out, pids) })
	run(func() error {
		sla, err := r.findings.SLAStats(ctx, pids)
		if err != nil {
			return err
		}
		out.SLA = sla
		return nil
	})
	wg.Wait()
	if firstErr != nil {
		return Overview{}, firstErr
	}
	return out, nil
}

// aggregateExpiring counts exceptions and risk acceptances lapsing soon.
func (r *Repository) aggregateExpiring(ctx context.Context, out *Overview, pids []string) error {
	if err := r.db.QueryRow(ctx, `
		SELECT count(*) FROM findings
		WHERE `+finding.ExceptionExpirySQL+` > now()
		  AND `+finding.ExceptionExpirySQL+` <= now() + make_interval(days => $1)
		  AND duplicate_of IS NULL
		  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
		  AND`+archive.Finding("")+`
		  AND ($2::uuid[] IS NULL OR project_id = ANY($2))`,
		expiringSoonDays, pids).Scan(&out.ExpiringSoon); err != nil {
		return fmt.Errorf("aggregate expiring: %w", err)
	}
	return nil
}

// fromSnapshots fills the finding counts, risk, top projects and expiring
// from day's project snapshot rows: the same rules as the live aggregates
// (metrics.projectDaySQL), as of the snapshot run.
func (r *Repository) fromSnapshots(ctx context.Context, out *Overview, pids []string, day time.Time) error {
	rows, err := r.db.Query(ctx, `
		SELECT p.id, p.name, p.slug, s.open_critical, s.open_high, s.open_medium, s.open_low, s.open_info,
		       s.open_total, s.risk_score, s.open_kev, s.open_exploitable, s.open_by_category, s.expiring_soon, s.created_at
		FROM metric_snapshots s JOIN projects p ON p.id = s.scope_id
		WHERE s.day = $1 AND s.scope_kind = 'project' AND`+archive.Project("p")+`
		  AND ($2::uuid[] IS NULL OR p.id = ANY($2))`, day, pids)
	if err != nil {
		return fmt.Errorf("portfolio snapshots: %w", err)
	}
	defer rows.Close()
	sevs := [5]domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow, domain.SeverityInfo}
	var risk float64
	for rows.Next() {
		var (
			pr       ProjectRisk
			open     [5]int
			kev, exp int
			cats     map[string]int
			expiring int
			at       time.Time
		)
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Slug, &open[0], &open[1], &open[2], &open[3], &open[4],
			&pr.TotalOpen, &pr.RiskScore, &kev, &exp, &cats, &expiring, &at); err != nil {
			return fmt.Errorf("scan portfolio snapshot: %w", err)
		}
		for i, n := range open {
			if n > 0 {
				out.OpenBySeverity[sevs[i]] += n
			}
		}
		pr.Critical = open[0]
		out.TotalOpen += pr.TotalOpen
		out.KEVOpen += kev
		out.ExploitableOpen += exp
		out.ExpiringSoon += expiring
		for k, n := range cats {
			out.OpenByCategory[domain.Category(k)] += n
		}
		risk += pr.RiskScore
		if pr.TotalOpen > 0 {
			out.TopProjects = append(out.TopProjects, pr)
		}
		if out.AsOf == nil || at.After(*out.AsOf) {
			out.AsOf = &at
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out.RiskScore = math.Round(risk*10) / 10
	sortTopProjects(out.TopProjects)
	if len(out.TopProjects) > 5 {
		out.TopProjects = out.TopProjects[:5]
	}
	out.Source = "snapshots"
	return nil
}

// aggregateRisk builds severity totals, the weighted risk score (per-project
// weight × business-criticality multiplier, kept in Go so weights live in one
// place), and the top-risk project list.
func (r *Repository) aggregateRisk(ctx context.Context, out *Overview, pids []string) error {
	q := `
		SELECT p.id, p.name, p.slug, p.business_criticality, f.severity, count(*)
		FROM findings f
		JOIN projects p ON p.id = f.project_id
		WHERE f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
		  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
		  AND` + archive.Finding("f") + `
		  AND ($1::uuid[] IS NULL OR f.project_id = ANY($1))
		GROUP BY p.id, p.name, p.slug, p.business_criticality, f.severity`
	rows, err := r.db.Query(ctx, q, pids)
	if err != nil {
		return fmt.Errorf("aggregate risk: %w", err)
	}
	defer rows.Close()

	type acc struct {
		risk ProjectRisk
		crit domain.Criticality
	}
	projects := map[string]*acc{}
	for rows.Next() {
		var (
			id, name, slug string
			crit           domain.Criticality
			sev            domain.Severity
			n              int
		)
		if err := rows.Scan(&id, &name, &slug, &crit, &sev, &n); err != nil {
			return fmt.Errorf("scan risk row: %w", err)
		}
		a := projects[id]
		if a == nil {
			a = &acc{risk: ProjectRisk{ID: id, Name: name, Slug: slug}, crit: crit}
			projects[id] = a
		}
		out.OpenBySeverity[sev] += n
		out.TotalOpen += n
		a.risk.TotalOpen += n
		a.risk.RiskScore += sev.Weight() * float64(n)
		if sev == domain.SeverityCritical {
			a.risk.Critical += n
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, a := range projects {
		a.risk.RiskScore = math.Round(a.risk.RiskScore*a.crit.Multiplier()*10) / 10
		out.RiskScore += a.risk.RiskScore
		out.TopProjects = append(out.TopProjects, a.risk)
	}
	out.RiskScore = math.Round(out.RiskScore*10) / 10
	sortTopProjects(out.TopProjects)
	if len(out.TopProjects) > 5 {
		out.TopProjects = out.TopProjects[:5]
	}
	return nil
}

func (r *Repository) aggregateCategory(ctx context.Context, out *Overview, pids []string) error {
	q := `SELECT category, count(*) FROM findings WHERE status IN ('open','confirmed') AND duplicate_of IS NULL
		AND version_id IN (SELECT id FROM project_versions WHERE is_default) AND` + archive.Finding("") + `
		AND ($1::uuid[] IS NULL OR project_id = ANY($1)) GROUP BY category`
	rows, err := r.db.Query(ctx, q, pids)
	if err != nil {
		return fmt.Errorf("aggregate category: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cat domain.Category
		var n int
		if err := rows.Scan(&cat, &n); err != nil {
			return fmt.Errorf("scan category: %w", err)
		}
		out.OpenByCategory[cat] = n
	}
	return rows.Err()
}

func (r *Repository) aggregateExploit(ctx context.Context, out *Overview, pids []string) error {
	q := `
		SELECT count(*) FILTER (WHERE kev),
		       count(*) FILTER (WHERE kev OR epss >= $1)
		FROM findings WHERE status IN ('open','confirmed') AND duplicate_of IS NULL
		  AND version_id IN (SELECT id FROM project_versions WHERE is_default) AND` + archive.Finding("") + `
		  AND ($2::uuid[] IS NULL OR project_id = ANY($2))`
	return r.db.QueryRow(ctx, q, exploitableEPSS, pids).Scan(&out.KEVOpen, &out.ExploitableOpen)
}

// aggregateCompliance computes each framework's mean score across all projects.
// A control fails when an open finding maps to it (by CWE or scanner rule) — the
// same rule as compliance.Evaluate, here rolled up across the portfolio.
func (r *Repository) aggregateCompliance(ctx context.Context, out *Overview, pids []string) error {
	// Same rule as compliance.Evaluate (its shared SQL); manual controls are
	// scored (as met) only while attested, and a framework with nothing
	// scored has no score.
	q := `
		WITH failing_by_finding AS (
			SELECT project_id, control_id
			FROM ` + compliance.ProjectFailingControlsSQL("($1::uuid[] IS NULL OR f.project_id = ANY($1))") + ` x
		),
		proj_control AS (
			SELECT p.id AS project_id, fw.key, fw.name, c.id AS control_id,
			       bool_or(ff.control_id IS NOT NULL) OR COALESCE(bool_or(` + fmt.Sprintf(compliance.ProjectFactFailingSQL, "p.id") + `), false) AS failing
			FROM projects p
			CROSS JOIN frameworks fw
			JOIN controls c ON c.framework_id = fw.id
				AND (c.assessment = 'automatic' OR ` + fmt.Sprintf(compliance.AttestedSQL, "p.id", "c.id") + `)
			LEFT JOIN ` + compliance.FactMappingsSQL + ` m ON m.control_id = c.id
			LEFT JOIN failing_by_finding ff ON ff.project_id = p.id AND ff.control_id = c.id
			WHERE` + archive.Project("p") + ` AND ($1::uuid[] IS NULL OR p.id = ANY($1))
			GROUP BY p.id, fw.key, fw.name, c.id
		),
		proj_score AS (
			SELECT project_id, key, name,
			       count(*) FILTER (WHERE NOT failing)::float / count(*) * 100 AS score
			FROM proj_control GROUP BY project_id, key, name
		)
		SELECT key, name, round(avg(score)::numeric, 1)::float, count(*)
		FROM proj_score GROUP BY key, name ORDER BY name`
	rows, err := r.db.Query(ctx, q, pids)
	if err != nil {
		return fmt.Errorf("aggregate compliance: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var fa FrameworkAverage
		if err := rows.Scan(&fa.Framework, &fa.Name, &fa.AvgScore, &fa.ProjectsAssessed); err != nil {
			return fmt.Errorf("scan compliance avg: %w", err)
		}
		out.Compliance = append(out.Compliance, fa)
	}
	return rows.Err()
}

// sortTopProjects orders by risk score descending (simple insertion sort — the
// list is tiny).
func sortTopProjects(ps []ProjectRisk) {
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && ps[j].RiskScore > ps[j-1].RiskScore; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
}
