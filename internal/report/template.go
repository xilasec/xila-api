package report

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Report sections, in the default order. A template picks and orders a subset.
const (
	SectionSummary    = "summary"    // KPI tiles
	SectionSeverity   = "severity"   // open findings by severity + SLA posture
	SectionCompliance = "compliance" // framework scores
	SectionFindings   = "findings"   // the priority table
	SectionDetails    = "details"    // per-finding write-ups (pentest-report style)
	SectionProjects   = "projects"   // portfolio only: per-project table
)

// Sections lists every section in the default order.
var Sections = []string{SectionSummary, SectionSeverity, SectionCompliance, SectionFindings, SectionDetails, SectionProjects}

// Template errors.
var (
	ErrTemplateNotFound  = errors.New("report template not found")
	ErrTemplateDuplicate = errors.New("a report template with this name already exists")
)

// MaxLogoBytes bounds a template's logo (a data: URI).
const MaxLogoBytes = 300_000

// maxTemplateFindings bounds a template's finding list.
const maxTemplateFindings = 500

// Template is a report's branding and layout.
type Template struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Brand          string          `json:"brand"`          // replaces "Xila security report" above the title
	Classification string          `json:"classification"` // banner, e.g. "CONFIDENTIAL — client use only"
	Intro          string          `json:"intro"`          // free text under the header (scope, methodology)
	Footer         string          `json:"footer"`
	AccentColor    string          `json:"accent_color"` // #rrggbb
	Logo           string          `json:"logo"`         // data:image/png|jpeg|svg+xml;base64,…
	Sections       []string        `json:"sections"`
	MinSeverity    domain.Severity `json:"min_severity"` // findings / details sections
	MaxFindings    int             `json:"max_findings"`
	CreatedBy      *string         `json:"created_by"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// DefaultTemplate is the layout of a report rendered without a template.
func DefaultTemplate() Template {
	return Template{
		Sections:    []string{SectionSummary, SectionSeverity, SectionCompliance, SectionFindings, SectionProjects},
		MinSeverity: domain.SeverityInfo, MaxFindings: topN,
	}
}

var (
	hexColor   = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	logoPrefix = []string{"data:image/png;base64,", "data:image/jpeg;base64,", "data:image/svg+xml;base64,"}
)

// Validate normalizes and checks t.
func (t *Template) Validate() error {
	t.Name = strings.TrimSpace(t.Name)
	if t.Name == "" || len(t.Name) > 200 {
		return errors.New("name is required (≤ 200 characters)")
	}
	for _, s := range []*string{&t.Brand, &t.Classification, &t.Intro, &t.Footer} {
		*s = strings.TrimSpace(*s)
	}
	if len(t.Brand) > 200 || len(t.Classification) > 200 || len(t.Footer) > 2000 || len(t.Intro) > 20000 {
		return errors.New("brand and classification ≤ 200, footer ≤ 2000, intro ≤ 20000 characters")
	}
	if t.AccentColor != "" && !hexColor.MatchString(t.AccentColor) {
		return errors.New("accent_color must be #rrggbb")
	}
	if t.Logo != "" {
		if len(t.Logo) > MaxLogoBytes {
			return fmt.Errorf("logo must be at most %d bytes", MaxLogoBytes)
		}
		if !slices.ContainsFunc(logoPrefix, func(p string) bool { return strings.HasPrefix(t.Logo, p) }) {
			return errors.New("logo must be a base64 data: URI of a PNG, JPEG or SVG image")
		}
	}
	if len(t.Sections) == 0 {
		return errors.New("pick at least one section")
	}
	seen := map[string]bool{}
	for _, s := range t.Sections {
		if !slices.Contains(Sections, s) {
			return fmt.Errorf("unknown section %q (one of %s)", s, strings.Join(Sections, ", "))
		}
		if seen[s] {
			return fmt.Errorf("section %q listed twice", s)
		}
		seen[s] = true
	}
	if t.MinSeverity == "" {
		t.MinSeverity = domain.SeverityInfo
	}
	if !t.MinSeverity.Valid() {
		return errors.New("min_severity must be critical, high, medium, low or info")
	}
	if t.MaxFindings == 0 {
		t.MaxFindings = topN
	}
	if t.MaxFindings < 1 || t.MaxFindings > maxTemplateFindings {
		return fmt.Errorf("max_findings must be 1–%d", maxTemplateFindings)
	}
	return nil
}

// Has reports whether the template shows section s.
func (t Template) Has(s string) bool { return slices.Contains(t.Sections, s) }

// TemplateRepository stores report templates.
type TemplateRepository struct{ db *pgxpool.Pool }

// NewTemplateRepository constructs the repository.
func NewTemplateRepository(db *pgxpool.Pool) *TemplateRepository { return &TemplateRepository{db: db} }

const templateColumns = `id, name, brand, classification, intro, footer, accent_color, logo, sections,
	min_severity, max_findings, created_by, created_at, updated_at`

func scanTemplate(row pgx.Row) (Template, error) {
	var t Template
	err := row.Scan(&t.ID, &t.Name, &t.Brand, &t.Classification, &t.Intro, &t.Footer, &t.AccentColor, &t.Logo,
		&t.Sections, &t.MinSeverity, &t.MaxFindings, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrTemplateNotFound
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
		return Template{}, ErrTemplateDuplicate
	}
	return t, err
}

// List returns every template by name.
func (r *TemplateRepository) List(ctx context.Context) ([]Template, error) {
	rows, err := r.db.Query(ctx, `SELECT `+templateColumns+` FROM report_templates ORDER BY lower(name)`)
	if err != nil {
		return nil, fmt.Errorf("list report templates: %w", err)
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		t, err := scanTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns one template.
func (r *TemplateRepository) Get(ctx context.Context, id string) (Template, error) {
	return scanTemplate(r.db.QueryRow(ctx, `SELECT `+templateColumns+` FROM report_templates WHERE id = $1`, id))
}

// Create inserts a template.
func (r *TemplateRepository) Create(ctx context.Context, t Template, actor string) (Template, error) {
	return scanTemplate(r.db.QueryRow(ctx, `INSERT INTO report_templates
		(name, brand, classification, intro, footer, accent_color, logo, sections, min_severity, max_findings, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, '')::uuid) RETURNING `+templateColumns,
		t.Name, t.Brand, t.Classification, t.Intro, t.Footer, t.AccentColor, t.Logo, t.Sections, t.MinSeverity, t.MaxFindings, actor))
}

// Update rewrites a template.
func (r *TemplateRepository) Update(ctx context.Context, t Template) (Template, error) {
	return scanTemplate(r.db.QueryRow(ctx, `UPDATE report_templates SET name = $2, brand = $3, classification = $4,
		intro = $5, footer = $6, accent_color = $7, logo = $8, sections = $9, min_severity = $10, max_findings = $11,
		updated_at = now() WHERE id = $1 RETURNING `+templateColumns,
		t.ID, t.Name, t.Brand, t.Classification, t.Intro, t.Footer, t.AccentColor, t.Logo, t.Sections, t.MinSeverity, t.MaxFindings))
}

// Delete removes a template.
func (r *TemplateRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM report_templates WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrTemplateNotFound
	}
	return nil
}

// TemplateHandler serves /report-templates: readable by everyone signed in
// (anyone printing a report picks one), written by instance admins (authz).
type TemplateHandler struct{ repo *TemplateRepository }

// NewTemplateHandler constructs the handler.
func NewTemplateHandler(repo *TemplateRepository) *TemplateHandler {
	return &TemplateHandler{repo: repo}
}

// Register mounts the routes.
func (h *TemplateHandler) Register(r fiber.Router) {
	r.Get("/report-templates", h.list)
	r.Post("/report-templates", h.create)
	r.Get("/report-templates/:templateID", h.get)
	r.Put("/report-templates/:templateID", h.update)
	r.Delete("/report-templates/:templateID", h.delete)
}

func templateErr(err error) error {
	switch {
	case errors.Is(err, ErrTemplateNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrTemplateDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

func (h *TemplateHandler) list(c *fiber.Ctx) error {
	out, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"templates": out, "sections": Sections})
}

func (h *TemplateHandler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "templateID")
	if err != nil {
		return err
	}
	t, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return templateErr(err)
	}
	return c.JSON(t)
}

func (h *TemplateHandler) create(c *fiber.Ctx) error {
	var t Template
	if err := httpx.Parse(c, &t); err != nil {
		return err
	}
	if err := t.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Create(c.UserContext(), t, auth.UserID(c))
	if err != nil {
		return templateErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *TemplateHandler) update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "templateID")
	if err != nil {
		return err
	}
	var t Template
	if err := httpx.Parse(c, &t); err != nil {
		return err
	}
	t.ID = id
	if err := t.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Update(c.UserContext(), t)
	if err != nil {
		return templateErr(err)
	}
	return c.JSON(out)
}

func (h *TemplateHandler) delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "templateID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); err != nil {
		return templateErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
