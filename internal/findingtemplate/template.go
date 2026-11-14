// Package findingtemplate stores reusable write-ups for manual findings — a
// pentest team's standard issues ("Missing HSTS header", "IDOR on object
// ids") with their severity, CWE, description, mitigation and references —
// so reporting the same issue again is one click, worded the same way.
package findingtemplate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Errors.
var (
	ErrNotFound  = errors.New("finding template not found")
	ErrDuplicate = errors.New("a template with this title already exists")
)

// Template is a reusable finding write-up.
type Template struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	Severity    domain.Severity `json:"severity"`
	Category    domain.Category `json:"category"`
	CWE         *int            `json:"cwe"`
	CVE         []string        `json:"cve"`
	Description string          `json:"description"`
	Mitigation  string          `json:"mitigation"`
	Impact      string          `json:"impact"`
	References  []string        `json:"references"`
	Tags        []string        `json:"tags"`
	CreatedBy   *string         `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Validate normalizes and checks t.
func (t *Template) Validate() error {
	t.Title = strings.TrimSpace(t.Title)
	if t.Title == "" || len(t.Title) > 300 {
		return errors.New("title is required (≤ 300 characters)")
	}
	if !t.Severity.Valid() {
		return errors.New("severity must be critical, high, medium, low or info")
	}
	if t.Category == "" {
		t.Category = domain.CategoryDAST
	}
	if !t.Category.Valid() {
		return errors.New("invalid category")
	}
	tags, err := finding.NormalizeTags(t.Tags)
	if err != nil {
		return err
	}
	t.Tags = tags
	if t.CVE == nil {
		t.CVE = []string{}
	}
	if t.References == nil {
		t.References = []string{}
	}
	return nil
}

// Repository stores templates.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const columns = `id, title, severity, category, cwe, cve, description, mitigation, impact, refs, tags, created_by, created_at, updated_at`

func scan(row pgx.Row) (Template, error) {
	var t Template
	err := row.Scan(&t.ID, &t.Title, &t.Severity, &t.Category, &t.CWE, &t.CVE, &t.Description, &t.Mitigation,
		&t.Impact, &t.References, &t.Tags, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

func dupErr(err error) error {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
		return ErrDuplicate
	}
	return err
}

// List returns every template by title.
func (r *Repository) List(ctx context.Context) ([]Template, error) {
	rows, err := r.db.Query(ctx, `SELECT `+columns+` FROM finding_templates ORDER BY lower(title)`)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		t, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns one template.
func (r *Repository) Get(ctx context.Context, id string) (Template, error) {
	t, err := scan(r.db.QueryRow(ctx, `SELECT `+columns+` FROM finding_templates WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	return t, err
}

// Create inserts a template.
func (r *Repository) Create(ctx context.Context, t Template, actor string) (Template, error) {
	out, err := scan(r.db.QueryRow(ctx, `INSERT INTO finding_templates
		(title, severity, category, cwe, cve, description, mitigation, impact, refs, tags, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, '')::uuid) RETURNING `+columns,
		t.Title, t.Severity, t.Category, t.CWE, t.CVE, t.Description, t.Mitigation, t.Impact, t.References, t.Tags, actor))
	return out, dupErr(err)
}

// Update rewrites a template.
func (r *Repository) Update(ctx context.Context, t Template) (Template, error) {
	out, err := scan(r.db.QueryRow(ctx, `UPDATE finding_templates SET title = $2, severity = $3, category = $4,
		cwe = $5, cve = $6, description = $7, mitigation = $8, impact = $9, refs = $10, tags = $11, updated_at = now()
		WHERE id = $1 RETURNING `+columns,
		t.ID, t.Title, t.Severity, t.Category, t.CWE, t.CVE, t.Description, t.Mitigation, t.Impact, t.References, t.Tags))
	if errors.Is(err, pgx.ErrNoRows) {
		return Template{}, ErrNotFound
	}
	return out, dupErr(err)
}

// Delete removes a template (findings made from it keep their text).
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM finding_templates WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Handler serves /finding-templates: readable by everyone signed in (anyone
// filing a manual finding uses them), written by instance admins (authz).
type Handler struct{ repo *Repository }

// NewHandler constructs the handler.
func NewHandler(repo *Repository) *Handler { return &Handler{repo: repo} }

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/finding-templates", h.list)
	r.Post("/finding-templates", h.create)
	r.Get("/finding-templates/:templateID", h.get)
	r.Put("/finding-templates/:templateID", h.update)
	r.Delete("/finding-templates/:templateID", h.delete)
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

func (h *Handler) list(c *fiber.Ctx) error {
	out, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"templates": out})
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "templateID")
	if err != nil {
		return err
	}
	t, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(t)
}

func (h *Handler) create(c *fiber.Ctx) error {
	var t Template
	if err := httpx.Parse(c, &t); err != nil {
		return err
	}
	if err := t.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Create(c.UserContext(), t, auth.UserID(c))
	if err != nil {
		return mapErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) update(c *fiber.Ctx) error {
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
		return mapErr(err)
	}
	return c.JSON(out)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "templateID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); err != nil {
		return mapErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
