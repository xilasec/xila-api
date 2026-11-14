package report

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/engagement"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
)

// Report errors.
var (
	ErrProjectNotFound = errors.New("project not found")
	// ErrEngagementMismatch is returned for an engagement report whose
	// engagement isn't one of the project's.
	ErrEngagementMismatch = errors.New("engagement_id is not an engagement of this project")
)

// Options shape one report: its template and, for a project report, an
// optional engagement whose findings it covers.
type Options struct {
	Template     Template
	EngagementID string
}

// The service's dependencies, satisfied by the domain repositories.
type (
	overviewSource interface {
		Overview(ctx context.Context, pids []string) (portfolio.Overview, error)
	}
	findingSource interface {
		List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	}
	complianceSource interface {
		ListFrameworks(ctx context.Context) ([]compliance.Framework, error)
		Evaluate(ctx context.Context, projectID, frameworkKey string) (compliance.Result, error)
	}
	projectSource interface {
		Get(ctx context.Context, id string) (project.Project, error)
		ListVersions(ctx context.Context, projectID string) ([]project.Version, error)
	}
	rowSource interface {
		ProjectRows(ctx context.Context, pids []string) ([]ProjectRow, error)
	}
	engagementSource interface {
		Get(ctx context.Context, id string) (engagement.Engagement, error)
	}
)

// Service assembles reports from the portfolio rollup, findings, compliance
// and projects — every number is the one the matching API/UI view shows
// (default version only, cross-tool duplicates collapsed).
type Service struct {
	overview   overviewSource
	findings   findingSource
	compliance complianceSource
	projects   projectSource
	rows       rowSource
	engs       engagementSource
	now        func() time.Time
}

// NewService constructs a Service.
func NewService(overview overviewSource, findings findingSource, comp complianceSource, projects projectSource, rows rowSource) *Service {
	return &Service{overview: overview, findings: findings, compliance: comp, projects: projects, rows: rows, now: time.Now}
}

// WithEngagements enables engagement reports.
func (s *Service) WithEngagements(engs engagementSource) *Service {
	s.engs = engs
	return s
}

// Project builds one project's report; with opts.EngagementID, its findings
// sections cover what that engagement found, on every branch.
func (s *Service) Project(ctx context.Context, projectID string, opts Options) (Report, error) {
	p, err := s.projects.Get(ctx, projectID)
	if errors.Is(err, project.ErrNotFound) {
		return Report{}, ErrProjectNotFound
	}
	if err != nil {
		return Report{}, err
	}
	pids := []string{projectID}
	ov, err := s.overview.Overview(ctx, pids)
	if err != nil {
		return Report{}, err
	}
	rep := s.base("Security report — "+p.Name, ov, opts.Template)
	rep.Project = &p
	if opts.EngagementID != "" {
		e, err := s.engagement(ctx, opts.EngagementID)
		if err != nil || e.ProjectID != projectID {
			return Report{}, ErrEngagementMismatch
		}
		rep.Engagement = &e
		rep.Title = e.Name + " — " + p.Name
	}

	versions, err := s.projects.ListVersions(ctx, projectID)
	if err != nil {
		return Report{}, err
	}
	for _, v := range versions {
		if v.IsDefault {
			rep.Branch = v.Name
		} else {
			rep.OtherBranches = append(rep.OtherBranches, v.Name)
		}
	}

	frameworks, err := s.compliance.ListFrameworks(ctx)
	if err != nil {
		return Report{}, err
	}
	for _, fw := range frameworks {
		res, err := s.compliance.Evaluate(ctx, projectID, fw.Key)
		if errors.Is(err, compliance.ErrFrameworkNotFound) {
			continue // a framework without controls has no posture
		}
		if err != nil {
			return Report{}, err
		}
		rep.Compliance = append(rep.Compliance, ComplianceRow{
			Name:   fullName(res.Name, res.Version),
			Score:  res.Score,
			Detail: controlsDetail(res),
		})
	}

	var top []finding.Finding
	if rep.Engagement != nil {
		top, err = s.engagementFindings(ctx, projectID, rep.Engagement.ID, rep.Template)
		if err == nil {
			rep.Severities = severityCounts(rep.Engagement.Stats.Open)
		}
	} else {
		top, err = s.top(ctx, finding.Filter{ProjectID: projectID}, rep.Template)
	}
	if err != nil {
		return Report{}, err
	}
	for _, f := range top {
		rep.Top = append(rep.Top, TopFinding{Finding: f, ProjectName: p.Name})
	}
	return rep, nil
}

func (s *Service) engagement(ctx context.Context, id string) (engagement.Engagement, error) {
	if s.engs == nil {
		return engagement.Engagement{}, engagement.ErrNotFound
	}
	return s.engs.Get(ctx, id)
}

// engagementFindings is an engagement report's finding list: everything its
// scans and manual reports found at the template's minimum severity, in any
// status but false positive (a deliverable reports what was fixed too), by
// priority.
func (s *Service) engagementFindings(ctx context.Context, projectID, engagementID string, t Template) ([]finding.Finding, error) {
	fs, err := s.findings.List(ctx, finding.Filter{
		ProjectID: projectID, EngagementID: engagementID, Severities: domain.SeveritiesAtLeast(t.MinSeverity),
		Sort: "priority", Limit: 2 * maxTemplateFindings,
	})
	if err != nil {
		return nil, err
	}
	fs = slices.DeleteFunc(fs, func(f finding.Finding) bool { return f.Status == domain.FindingFalsePositive })
	return fs[:min(t.MaxFindings, len(fs))], nil
}

// Portfolio builds the executive report over pids (nil = every project).
// Engagements are per project: opts.EngagementID is ignored.
func (s *Service) Portfolio(ctx context.Context, pids []string, opts Options) (Report, error) {
	ov, err := s.overview.Overview(ctx, pids)
	if err != nil {
		return Report{}, err
	}
	rep := s.base("Portfolio security report", ov, opts.Template)
	if rep.Projects, err = s.rows.ProjectRows(ctx, pids); err != nil {
		return Report{}, err
	}
	names := make(map[string]string, len(rep.Projects))
	for _, p := range rep.Projects {
		names[p.ID] = p.Name
	}
	for _, fa := range ov.Compliance {
		rep.Compliance = append(rep.Compliance, ComplianceRow{
			Name:   fa.Name,
			Score:  fa.AvgScore,
			Detail: fmt.Sprintf("average over %d projects", fa.ProjectsAssessed),
		})
	}
	top, err := s.top(ctx, finding.Filter{ProjectIDs: pids}, rep.Template)
	if err != nil {
		return Report{}, err
	}
	for _, f := range top {
		rep.Top = append(rep.Top, TopFinding{Finding: f, ProjectName: names[f.ProjectID]})
	}
	return rep, nil
}

// base fills what both reports share from the rollup. A zero template (no
// sections) means DefaultTemplate.
func (s *Service) base(title string, ov portfolio.Overview, t Template) Report {
	if len(t.Sections) == 0 {
		t = DefaultTemplate()
	}
	rep := Report{Title: title, GeneratedAt: s.now().UTC(), Overview: ov, Template: t}
	rep.Severities = severityCounts(ov.OpenBySeverity)
	for _, sev := range severityOrder {
		if d, ok := ov.SLA.MTTRDays[sev]; ok {
			rep.MTTR = append(rep.MTTR, SeverityDays{Severity: sev, Days: d})
		}
	}
	return rep
}

// severityCounts turns open counts into the severity table, critical first.
func severityCounts[K ~string](open map[K]int) []SeverityCount {
	most := 0
	for _, sev := range severityOrder {
		most = max(most, open[K(sev)])
	}
	out := make([]SeverityCount, 0, len(severityOrder))
	for _, sev := range severityOrder {
		n := open[K(sev)]
		sc := SeverityCount{Severity: sev, Count: n}
		if most > 0 {
			sc.BarPct = float64(n) / float64(most) * 100
		}
		out = append(out, sc)
	}
	return out
}

// severityOrder lists severities most severe first.
var severityOrder = []domain.Severity{
	domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow, domain.SeverityInfo,
}

// top returns the template's MaxFindings highest-priority live (open or
// confirmed) findings at its minimum severity matching base — default
// version, duplicates collapsed, as the inbox shows.
func (s *Service) top(ctx context.Context, base finding.Filter, t Template) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, st := range []domain.FindingStatus{domain.FindingOpen, domain.FindingConfirmed} {
		f := base
		f.Status, f.Sort, f.Limit = st, "priority", t.MaxFindings
		if t.MinSeverity != domain.SeverityInfo {
			f.Severities = domain.SeveritiesAtLeast(t.MinSeverity)
		}
		fs, err := s.findings.List(ctx, f)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	// Merge the two priority-ordered lists the way List orders one.
	slices.SortStableFunc(out, func(a, b finding.Finding) int {
		if c := cmp.Compare(b.Priority, a.Priority); c != 0 {
			return c
		}
		return b.LastSeenAt.Compare(a.LastSeenAt)
	})
	return out[:min(t.MaxFindings, len(out))], nil
}

func fullName(name, version string) string {
	if version == "" {
		return name
	}
	return name + " " + version
}

// controlsDetail summarises a framework's controls, saying how many are manual
// (process requirements no scan can assess) rather than counting them as
// passing.
func controlsDetail(res compliance.Result) string {
	d := fmt.Sprintf("%d of %d controls passing", res.PassingControls, res.TotalControls)
	if res.ManualControls > 0 {
		d += fmt.Sprintf(" · %d manual (attestation)", res.ManualControls)
	}
	return d
}
