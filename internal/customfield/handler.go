package customfield

import (
	"context"
	"errors"
	"slices"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
)

// ComputedValidator compiles a computed field's expression against the facts
// its entity would see and rejects a result type that can't fit the field
// (internal/computed implements this; nil skips the check, e.g. in tests that
// don't exercise computed fields).
type ComputedValidator interface {
	Validate(ctx context.Context, d Definition) error
}

// Handler exposes definitions (read: anyone signed in; write: instance admin,
// enforced by authz) and the per-entity value edits (editor on the entity's
// project, enforced by authz through the path).
type Handler struct {
	repo *Repository
	svc  *Service
	// computed validates a computed definition's expression (WithComputedValidator).
	computed ComputedValidator
	// onComputedChanged backfills every entity of this type after a computed
	// definition is created or its expression changes (WithComputedChanged).
	onComputedChanged func(ctx context.Context, d Definition)
}

// WithComputedValidator sets the compile-time check for a computed field's
// expression.
func (h *Handler) WithComputedValidator(v ComputedValidator) *Handler {
	h.computed = v
	return h
}

// WithComputedChanged sets the hook run after a computed definition is
// created, or an existing one's expression (or computed flag) changes.
func (h *Handler) WithComputedChanged(fn func(ctx context.Context, d Definition)) *Handler {
	h.onComputedChanged = fn
	return h
}

// NewHandler constructs a Handler.
func NewHandler(repo *Repository, svc *Service) *Handler { return &Handler{repo: repo, svc: svc} }

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/custom-fields", h.List)
	r.Post("/custom-fields", h.Create)
	r.Get("/custom-fields/:fieldID", h.Get)
	r.Patch("/custom-fields/:fieldID", h.Update)
	r.Delete("/custom-fields/:fieldID", h.Delete)
	r.Patch("/projects/:projectID/custom", h.values(EntityProject, "projectID"))
	r.Patch("/assets/:assetID/custom", h.values(EntityAsset, "assetID"))
	r.Patch("/findings/:findingID/custom", h.values(EntityFinding, "findingID"))
}

func mapErr(err error) error {
	var v *ValidationError
	switch {
	case errors.As(err, &v):
		return fiber.NewError(fiber.StatusBadRequest, v.Error())
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrNoOrg):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return err
}

// List handles GET /custom-fields: ?entity= narrows to one entity;
// ?project_id= to the fields that apply to that project's organization (the
// caller must be able to see the project).
func (h *Handler) List(c *fiber.Ctx) error {
	entity := Entity(c.Query("entity"))
	if entity != "" && !entity.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "entity must be project, asset or finding")
	}
	defs, err := h.repo.List(c.UserContext(), entity)
	if err != nil {
		return err
	}
	if pid := c.Query("project_id"); pid != "" {
		if uuid.Validate(pid) != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
		}
		if s := authz.VisibleScope(c); !s.AllAccess && !slices.Contains(s.ProjectIDs, pid) {
			return fiber.NewError(fiber.StatusNotFound, "project not found")
		}
		org, err := h.repo.OrgOfProject(c.UserContext(), pid)
		if errors.Is(err, ErrEntityNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "project not found")
		}
		if err != nil {
			return err
		}
		defs = slices.DeleteFunc(defs, func(d Definition) bool { return !d.AppliesTo(org) })
	}
	return c.JSON(fiber.Map{"custom_fields": defs})
}

// Get handles GET /custom-fields/{id}.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "fieldID")
	if err != nil {
		return err
	}
	d, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(d)
}

// Create handles POST /custom-fields.
func (h *Handler) Create(c *fiber.Ctx) error {
	var d Definition
	if err := httpx.Parse(c, &d); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return mapErr(err)
	}
	if d.Computed && h.computed != nil {
		if err := h.computed.Validate(c.UserContext(), d); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
	}
	out, err := h.repo.Create(c.UserContext(), d)
	if err != nil {
		return mapErr(err)
	}
	if out.Computed && h.onComputedChanged != nil {
		h.onComputedChanged(c.UserContext(), out)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// updateRequest is PATCH /custom-fields/{id}: the editable parts. Entity, key
// and type are fixed (stored values and rule expressions depend on them).
type updateRequest struct {
	Label    *string   `json:"label"`
	Options  *[]string `json:"options"`
	Required *bool     `json:"required"`
	OrgID    *string   `json:"org_id"`
	// ClearOrg makes the field apply to every organization again.
	ClearOrg bool `json:"clear_org"`
	// Computed and Expression turn the field computed (or back into one a
	// person sets) and change what it is computed from.
	Computed   *bool   `json:"computed"`
	Expression *string `json:"expression"`
}

// Update handles PATCH /custom-fields/{id}.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "fieldID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	before, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	d := before
	if body.Label != nil {
		d.Label = *body.Label
	}
	if body.Options != nil {
		d.Options = *body.Options
	}
	if body.Required != nil {
		d.Required = *body.Required
	}
	switch {
	case body.ClearOrg:
		d.OrgID = nil
	case body.OrgID != nil:
		d.OrgID = body.OrgID
	}
	if body.Computed != nil {
		d.Computed = *body.Computed
	}
	if body.Expression != nil {
		d.Expression = *body.Expression
	}
	if err := d.Validate(); err != nil {
		return mapErr(err)
	}
	if d.Computed && h.computed != nil {
		if err := h.computed.Validate(c.UserContext(), d); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
	}
	out, err := h.repo.Update(c.UserContext(), d)
	if err != nil {
		return mapErr(err)
	}
	audit.SetChanges(c, before, out)
	if out.Computed && (out.Expression != before.Expression || !before.Computed) && h.onComputedChanged != nil {
		h.onComputedChanged(c.UserContext(), out)
	}
	return c.JSON(out)
}

// Delete handles DELETE /custom-fields/{id}: the definition and every value
// stored under it.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "fieldID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id, auth.UserID(c)); err != nil {
		return mapErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// values handles PATCH /{projects|assets|findings}/{id}/custom: a JSON object
// of key → value (null clears) merged into the entity's values.
func (h *Handler) values(entity Entity, param string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, err := httpx.ID(c, param)
		if err != nil {
			return err
		}
		var patch map[string]any
		if err := httpx.Parse(c, &patch); err != nil {
			return err
		}
		out, err := h.svc.Set(c.UserContext(), entity, id, patch, auth.UserID(c))
		if errors.Is(err, ErrEntityNotFound) {
			return fiber.NewError(fiber.StatusNotFound, string(entity)+" not found")
		}
		if err != nil {
			return mapErr(err)
		}
		return c.JSON(fiber.Map{"custom": out})
	}
}
