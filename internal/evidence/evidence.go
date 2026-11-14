// Package evidence renders a project's evidence report for any compliance
// framework: the posture per control with the open findings behind each
// failing one, the manual controls with their attestations (who, when, how),
// the SBOM and vulnerability-handling facts an assessor asks for, and — for
// eu-cra — the CRA Article 14 reporting section. Like internal/report it is
// inert, printable HTML.
package evidence

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/cra"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
)

// SBOM is one current SBOM on the default version.
type SBOM struct {
	Artifact   string
	Version    string
	Format     string
	Components int
	CreatedAt  time.Time
}

// Inventory summarises the default version's current SBOMs.
type Inventory struct {
	SBOMs             []SBOM
	Components        int
	WithPurl          int
	WithHash          int
	LicenseResolved   int
	IntegrityMismatch int
}

// Analysis counts documented vulnerability analysis.
type Analysis struct {
	VEXStatements int
	Assessments   int
}

// Control is one control with the open findings that fail it.
type Control struct {
	compliance.ControlResult
	Findings []compliance.ControlFinding
	More     int // failing findings beyond those listed
}

// Article14 is the CRA reporting section (eu-cra only).
type Article14 struct {
	Product cra.Product
	Cases   []cra.Case
}

// CasesCompliant counts the cases whose every due stage was submitted on time.
func (a Article14) CasesCompliant() int {
	n := 0
	for _, c := range a.Cases {
		if c.Compliant() {
			n++
		}
	}
	return n
}

// Report is the evidence report's data.
type Report struct {
	GeneratedAt time.Time
	Project     project.Project
	Branch      string
	Posture     compliance.Result
	Measured    []Control
	Manual      []Control
	Overview    portfolio.Overview
	Inventory   Inventory
	Analysis    Analysis
	Severities  []domain.Severity
	CRA         *Article14
}

// findingsPerControl caps the findings listed under one control.
const findingsPerControl = 10

// Repository reads the report's SBOM and analysis facts.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

// Inventory summarises the project's current SBOMs on its default version
// (the newest per artifact).
func (r *Repository) Inventory(ctx context.Context, projectID string) (Inventory, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT ON (s.artifact) s.artifact, s.version, s.format, s.component_count, s.created_at
		FROM sboms s
		WHERE s.project_id = $1 AND s.version_id IN (SELECT id FROM project_versions WHERE is_default)
		ORDER BY s.artifact, s.created_at DESC`, projectID)
	if err != nil {
		return Inventory{}, fmt.Errorf("evidence sboms: %w", err)
	}
	var inv Inventory
	for rows.Next() {
		var s SBOM
		if err := rows.Scan(&s.Artifact, &s.Version, &s.Format, &s.Components, &s.CreatedAt); err != nil {
			rows.Close()
			return Inventory{}, err
		}
		inv.SBOMs = append(inv.SBOMs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Inventory{}, err
	}
	err = r.db.QueryRow(ctx, `
		WITH cur AS (
			SELECT DISTINCT ON (artifact) id FROM sboms
			WHERE project_id = $1 AND version_id IN (SELECT id FROM project_versions WHERE is_default)
			ORDER BY artifact, created_at DESC
		)
		SELECT count(*)::int,
		       count(*) FILTER (WHERE c.purl <> '')::int,
		       count(*) FILTER (WHERE c.hashes <> '{}'::jsonb)::int,
		       count(*) FILTER (WHERE c.license_resolved)::int,
		       count(*) FILTER (WHERE c.integrity = 'mismatch')::int
		FROM sbom_components c WHERE c.sbom_id IN (SELECT id FROM cur)`, projectID).
		Scan(&inv.Components, &inv.WithPurl, &inv.WithHash, &inv.LicenseResolved, &inv.IntegrityMismatch)
	if err != nil {
		return Inventory{}, fmt.Errorf("evidence components: %w", err)
	}
	return inv, nil
}

// Analysis counts the project's VEX statements and finding assessments.
func (r *Repository) Analysis(ctx context.Context, projectID string) (Analysis, error) {
	var a Analysis
	err := r.db.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM vex_statements WHERE project_id = $1)::int,
		(SELECT count(*) FROM finding_assessments WHERE project_id = $1)::int`, projectID).Scan(&a.VEXStatements, &a.Assessments)
	return a, err
}

// Sources the report reads.
type (
	projectSource interface {
		Get(ctx context.Context, id string) (project.Project, error)
		ListVersions(ctx context.Context, projectID string) ([]project.Version, error)
	}
	postureSource interface {
		Evaluate(ctx context.Context, projectID, frameworkKey string) (compliance.Result, error)
		ControlFindings(ctx context.Context, projectID, frameworkKey string, limit int) (map[string][]compliance.ControlFinding, error)
	}
	overviewSource interface {
		Overview(ctx context.Context, pids []string) (portfolio.Overview, error)
	}
	article14Source interface {
		Article14(ctx context.Context, projectID string, at time.Time) (cra.Product, []cra.Case, error)
	}
)

// Handler serves GET /projects/{id}/compliance/{framework}/report (viewer).
type Handler struct {
	repo     *Repository
	projects projectSource
	posture  postureSource
	overview overviewSource
	cra      article14Source
	now      func() time.Time
}

// NewHandler constructs the handler.
func NewHandler(repo *Repository, projects projectSource, posture postureSource, overview overviewSource, cra article14Source) *Handler {
	return &Handler{repo: repo, projects: projects, posture: posture, overview: overview, cra: cra, now: time.Now}
}

// Register mounts the route.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/compliance/:framework/report", h.report)
}

// Build assembles the report.
func (h *Handler) Build(ctx context.Context, projectID, framework string) (Report, error) {
	p, err := h.projects.Get(ctx, projectID)
	if err != nil {
		return Report{}, err
	}
	rep := Report{GeneratedAt: h.now().UTC(), Project: p, Severities: []domain.Severity{
		domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow,
	}}
	versions, err := h.projects.ListVersions(ctx, projectID)
	if err != nil {
		return Report{}, err
	}
	for _, v := range versions {
		if v.IsDefault {
			rep.Branch = v.Name
		}
	}
	if rep.Posture, err = h.posture.Evaluate(ctx, projectID, framework); err != nil {
		return Report{}, err
	}
	found, err := h.posture.ControlFindings(ctx, projectID, framework, findingsPerControl)
	if err != nil {
		return Report{}, err
	}
	for _, c := range rep.Posture.Controls {
		ctl := Control{ControlResult: c, Findings: found[c.Code]}
		if extra := c.OpenFindings - len(ctl.Findings); extra > 0 {
			ctl.More = extra
		}
		if c.Manual {
			rep.Manual = append(rep.Manual, ctl)
		} else {
			rep.Measured = append(rep.Measured, ctl)
		}
	}
	if rep.Overview, err = h.overview.Overview(ctx, []string{projectID}); err != nil {
		return Report{}, err
	}
	if rep.Inventory, err = h.repo.Inventory(ctx, projectID); err != nil {
		return Report{}, err
	}
	if rep.Analysis, err = h.repo.Analysis(ctx, projectID); err != nil {
		return Report{}, err
	}
	if framework == cra.FrameworkKey && h.cra != nil {
		prod, cases, err := h.cra.Article14(ctx, projectID, rep.GeneratedAt)
		if err != nil {
			return Report{}, err
		}
		rep.CRA = &Article14{Product: prod, Cases: cases}
	}
	return rep, nil
}

//go:embed evidence.html
var evidenceHTML string

var page = template.Must(template.New("evidence").Funcs(template.FuncMap{
	"date":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"day":   func(t time.Time) string { return t.UTC().Format(time.DateOnly) },
	"score": func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
	"pct": func(f *float64) string {
		if f == nil {
			return "—"
		}
		return strconv.FormatFloat(*f*100, 'f', 1, 64) + "%"
	},
	"days": func(m map[domain.Severity]float64, s domain.Severity) string {
		if d, ok := m[s]; ok {
			return strconv.FormatFloat(d, 'f', 1, 64) + " d"
		}
		return "—"
	},
	"open": func(m map[domain.Severity]int, s domain.Severity) int { return m[s] },
	"stamp": func(t *time.Time) string {
		if t == nil {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"human": func(s any) string { return strings.ReplaceAll(fmt.Sprint(s), "_", " ") },
	// safeURL keeps only http(s) links: an attestation's evidence URL is user
	// input and must never become a javascript: link in the report.
	"httpURL": func(s string) bool {
		l := strings.ToLower(strings.TrimSpace(s))
		return strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "http://")
	},
}).Parse(evidenceHTML))

// Render writes the report.
func Render(buf *bytes.Buffer, rep Report) error { return page.Execute(buf, rep) }

// ErrNoFramework: the framework doesn't exist.
var ErrNoFramework = compliance.ErrFrameworkNotFound

func (h *Handler) report(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	framework := c.Params("framework")
	rep, err := h.Build(c.UserContext(), pid, framework)
	switch {
	case errors.Is(err, project.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrNoFramework):
		return fiber.NewError(fiber.StatusNotFound, "framework not found")
	case err != nil:
		return err
	}
	var buf bytes.Buffer
	if err := Render(&buf, rep); err != nil {
		return err
	}
	// Inert: no scripts, no external fetches (see internal/report).
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; style-src 'unsafe-inline'")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderContentDisposition, fmt.Sprintf(`inline; filename="xila-%s-%s-%s.html"`,
		safeName(framework), safeName(rep.Project.Slug), rep.GeneratedAt.Format(time.DateOnly)))
	return c.Send(buf.Bytes())
}

func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, s)
}
