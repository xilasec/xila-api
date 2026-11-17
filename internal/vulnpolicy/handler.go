package vulnpolicy

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/httpx"
)

// customFieldLister lists custom-field definitions (customfield.Repository).
type customFieldLister interface {
	List(ctx context.Context, entity customfield.Entity) ([]customfield.Definition, error)
}

// Handler exposes vulnerability-policy management, preview and the GitOps
// bundle. Everything is instance-admin, enforced by the authz middleware
// (policies are instance-wide, like triage rules).
type Handler struct {
	repo   *Repository
	svc    *Service
	fields customFieldLister
}

// NewHandler constructs a vulnpolicy Handler.
func NewHandler(repo *Repository, svc *Service) *Handler {
	return &Handler{repo: repo, svc: svc}
}

// WithCustomFields lets conditions read project.custom.<key>.
func (h *Handler) WithCustomFields(fields customFieldLister) *Handler {
	h.fields = fields
	return h
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/vuln-policies", h.Create)
	r.Get("/vuln-policies", h.List)
	r.Post("/vuln-policies/preview", h.Preview)
	r.Post("/vuln-policies/evaluate", h.Evaluate)
	r.Get("/vuln-policies/bundle", h.ExportBundle)
	r.Put("/vuln-policies/bundle", h.ImportBundle)
	r.Get("/vuln-policies/:policyID", h.Get)
	r.Post("/vuln-policies/:policyID/preview", h.PreviewStored)
	r.Patch("/vuln-policies/:policyID", h.Update)
	r.Delete("/vuln-policies/:policyID", h.Delete)
}

// validate checks a policy against the project's currently defined custom
// fields: its condition dry-runs on a document carrying every defined one.
func (h *Handler) validate(ctx context.Context, p *Policy) error {
	var projectFields []customfield.Definition
	if h.fields != nil {
		var err error
		if projectFields, err = h.fields.List(ctx, customfield.EntityProject); err != nil {
			return err
		}
	}
	var verr *ValidationError
	err := p.Validate(SchemaFor(projectFields))
	if errors.As(err, &verr) {
		return fiber.NewError(fiber.StatusBadRequest, verr.Error())
	}
	return err
}

// Create adds a policy.
func (h *Handler) Create(c *fiber.Ctx) error {
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	if err := h.validate(c.UserContext(), &p); err != nil {
		return err
	}
	out, err := h.repo.Create(c.UserContext(), p, auth.UserID(c))
	if err != nil {
		return writeError(err)
	}
	h.reevaluate(out)
	return c.Status(fiber.StatusCreated).JSON(out)
}

// List returns all policies, highest priority first.
func (h *Handler) List(c *fiber.Ctx) error {
	policies, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"policies": policies})
}

// Get returns one policy.
func (h *Handler) Get(c *fiber.Ctx) error {
	p, err := h.lookup(c)
	if err != nil {
		return err
	}
	return c.JSON(p)
}

// Update replaces a policy.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "policyID")
	if err != nil {
		return err
	}
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	p.ID = id
	if err := h.validate(c.UserContext(), &p); err != nil {
		return err
	}
	out, err := h.repo.Update(c.UserContext(), p)
	if err != nil {
		return writeError(err)
	}
	h.reevaluate(out)
	return c.JSON(out)
}

// Delete removes a policy. Findings it was holding revert to what they were
// before on the evaluation that follows.
func (h *Handler) Delete(c *fiber.Ctx) error {
	p, err := h.lookup(c)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), p.ID); err != nil {
		return writeError(err)
	}
	h.reevaluate(p)
	return c.SendStatus(fiber.StatusNoContent)
}

// reevaluate re-evaluates, in the background, the policy's own scope — a
// create/update/delete may immediately claim or release findings, and the
// point of the admin action is that it takes effect now, not on the next
// scheduled sweep.
func (h *Handler) reevaluate(p Policy) {
	go func() {
		_, _ = h.svc.EvaluateAll(context.Background())
	}()
}

// Preview dry-runs an unsaved policy (same body as create): which findings
// it would act on. ?project_id= narrows the scope. Mutates nothing.
func (h *Handler) Preview(c *fiber.Ctx) error {
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	if p.Name == "" {
		p.Name = "preview"
	}
	if err := h.validate(c.UserContext(), &p); err != nil {
		return err
	}
	return h.preview(c, p)
}

// PreviewStored dry-runs a stored policy — whatever its enabled state.
func (h *Handler) PreviewStored(c *fiber.Ctx) error {
	p, err := h.lookup(c)
	if err != nil {
		return err
	}
	// Re-compile: the stored row doesn't carry the compiled program.
	if err := h.validate(c.UserContext(), &p); err != nil {
		return err
	}
	return h.preview(c, p)
}

func (h *Handler) preview(c *fiber.Ctx, p Policy) error {
	out, err := h.svc.Preview(c.UserContext(), p, c.Query("project_id"))
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Evaluate handles POST /vuln-policies/evaluate: re-evaluate ?project_id=, or
// every project, now.
func (h *Handler) Evaluate(c *fiber.Ctx) error {
	var (
		changed int
		err     error
	)
	if pid := c.Query("project_id"); pid != "" {
		changed, err = h.svc.ApplyToProject(c.UserContext(), pid)
	} else {
		changed, err = h.svc.EvaluateAll(c.UserContext())
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"applied": changed})
}

// ExportBundle handles GET /vuln-policies/bundle?format=yaml|json (default
// yaml): every policy as a downloadable GitOps bundle.
func (h *Handler) ExportBundle(c *fiber.Ctx) error {
	policies, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	format := c.Query("format", "yaml")
	raw, err := EncodeBundle(policies, format)
	if err != nil {
		return err
	}
	if format == "json" {
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	} else {
		c.Set(fiber.HeaderContentType, "application/yaml")
	}
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="vuln-policies.`+format+`"`)
	return c.Send(raw)
}

// ImportBundle handles PUT /vuln-policies/bundle?dry_run=true: replace the
// whole policy set from a YAML or JSON body, atomically. dry_run validates
// and reports the resulting set without writing it.
func (h *Handler) ImportBundle(c *fiber.Ctx) error {
	b, err := DecodeBundle(c.Body())
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	var projectFields []customfield.Definition
	if h.fields != nil {
		if projectFields, err = h.fields.List(c.UserContext(), customfield.EntityProject); err != nil {
			return err
		}
	}
	dryRun := c.QueryBool("dry_run", false)
	out, err := h.svc.ImportBundle(c.UserContext(), b.Policies, SchemaFor(projectFields), auth.UserID(c), dryRun)
	var verr *ValidationError
	if errors.As(err, &verr) {
		return fiber.NewError(fiber.StatusBadRequest, verr.Error())
	}
	if err != nil {
		return writeError(err)
	}
	return c.JSON(fiber.Map{"policies": out, "dry_run": dryRun})
}

func (h *Handler) lookup(c *fiber.Ctx) (Policy, error) {
	id, err := httpx.ID(c, "policyID")
	if err != nil {
		return Policy{}, err
	}
	p, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return Policy{}, fiber.NewError(fiber.StatusNotFound, "vulnerability policy not found")
	}
	return p, err
}

func writeError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "vulnerability policy not found")
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	var verr *ValidationError
	if errors.As(err, &verr) {
		return fiber.NewError(fiber.StatusBadRequest, verr.Error())
	}
	return err
}
