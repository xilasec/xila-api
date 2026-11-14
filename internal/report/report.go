// Package report renders printable security reports — one per project and an
// executive portfolio report — as self-contained HTML. A PDF is the browser's
// print-to-PDF of that page: no headless browser or PDF library on the server.
package report

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/engagement"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
)

// topN is how many findings a report lists.
const topN = 20

// Report is everything one rendered report shows.
type Report struct {
	Title       string
	GeneratedAt time.Time
	// Project is set for a project report, nil for the portfolio report.
	Project *project.Project
	// Branch is the project's default version (what every number reports);
	// OtherBranches are the versions the report deliberately leaves out.
	Branch        string
	OtherBranches []string

	Overview   portfolio.Overview
	Severities []SeverityCount // open findings, critical first
	MTTR       []SeverityDays  // mean days to remediate, critical first
	Compliance []ComplianceRow
	Top        []TopFinding
	// Projects is the portfolio report's per-project table.
	Projects []ProjectRow

	// Template is the branding and section layout (DefaultTemplate if none).
	Template Template
	// Engagement is set when the report covers one engagement's findings.
	Engagement *engagement.Engagement
}

// SeverityCount is one severity's open-finding count, with its share of the
// largest bucket (for the bar).
type SeverityCount struct {
	Severity domain.Severity
	Count    int
	BarPct   float64
}

// SeverityDays is a per-severity duration in days.
type SeverityDays struct {
	Severity domain.Severity
	Days     float64
}

// ComplianceRow is one framework's posture line.
type ComplianceRow struct {
	Name   string
	Score  float64
	Detail string
}

// TopFinding is a finding in the report's priority list, with its project name.
type TopFinding struct {
	finding.Finding
	ProjectName string
}

// ProjectRow is one project's line in the portfolio table: its open backlog on
// the default version and the same risk score the portfolio rollup sums.
type ProjectRow struct {
	ID            string
	Name          string
	Slug          string
	Criticality   domain.Criticality
	DefaultBranch string
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
	TotalOpen     int
	KEVOpen       int
	SLABreached   int
	RiskScore     float64
}

// Repository reads the report's per-project table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ProjectRows returns every project in pids (nil = all) with its open,
// non-duplicate findings on the default version, ordered by risk (highest
// first) then name. Projects with nothing open are included.
func (r *Repository) ProjectRows(ctx context.Context, pids []string) ([]ProjectRow, error) {
	q := `
		SELECT p.id, p.name, p.slug, p.business_criticality,
		       COALESCE((SELECT v.name FROM project_versions v WHERE v.project_id = p.id AND v.is_default), ''),
		       count(f.id) FILTER (WHERE f.severity = 'critical'),
		       count(f.id) FILTER (WHERE f.severity = 'high'),
		       count(f.id) FILTER (WHERE f.severity = 'medium'),
		       count(f.id) FILTER (WHERE f.severity = 'low'),
		       count(f.id) FILTER (WHERE f.severity = 'info'),
		       count(f.id) FILTER (WHERE f.kev),
		       count(f.id) FILTER (WHERE f.sla_due_at < now())
		FROM projects p
		LEFT JOIN findings f
		  ON f.project_id = p.id AND f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
		 AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
		 AND` + archive.Finding("f") + `
		WHERE` + archive.Project("p") + ` AND ($1::uuid[] IS NULL OR p.id = ANY($1))
		GROUP BY p.id, p.name, p.slug, p.business_criticality
		ORDER BY p.name`
	rows, err := r.db.Query(ctx, q, pids)
	if err != nil {
		return nil, fmt.Errorf("report project rows: %w", err)
	}
	defer rows.Close()
	out := []ProjectRow{}
	for rows.Next() {
		var p ProjectRow
		if err := rows.Scan(&p.ID, &p.Name, &p.Slug, &p.Criticality, &p.DefaultBranch,
			&p.Critical, &p.High, &p.Medium, &p.Low, &p.Info, &p.KEVOpen, &p.SLABreached); err != nil {
			return nil, fmt.Errorf("scan report project row: %w", err)
		}
		p.TotalOpen = p.Critical + p.High + p.Medium + p.Low + p.Info
		p.RiskScore = riskScore(p)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortByRisk(out)
	return out, nil
}

// riskScore is the project's weighted open backlog scaled by business
// criticality, rounded like the portfolio rollup (which sums these values).
func riskScore(p ProjectRow) float64 {
	raw := domain.SeverityCritical.Weight()*float64(p.Critical) +
		domain.SeverityHigh.Weight()*float64(p.High) +
		domain.SeverityMedium.Weight()*float64(p.Medium) +
		domain.SeverityLow.Weight()*float64(p.Low) +
		domain.SeverityInfo.Weight()*float64(p.Info)
	return math.Round(raw*p.Criticality.Multiplier()*10) / 10
}

// sortByRisk orders rows by risk descending, keeping name order among ties.
func sortByRisk(rows []ProjectRow) {
	slices.SortStableFunc(rows, func(a, b ProjectRow) int { return cmp.Compare(b.RiskScore, a.RiskScore) })
}
