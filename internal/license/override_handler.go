package license

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/sbom"
)

// policyReevaluator re-runs component policies for a project after its
// overrides change, so policy violations reflect the new concluded licenses.
// policy.Service.Reevaluate implements it (coalesced, runs in the
// background; a burst of edits costs one pass per affected project).
type policyReevaluator interface {
	Reevaluate(projectIDs []string, all bool)
}

// licenseReapplier recomputes every current-snapshot component's license
// fields from a project's live overrides.
type licenseReapplier interface {
	ReapplyLicenseOverrides(ctx context.Context, projectID string) (int, error)
}

var _ licenseReapplier = Reapplier{}

// OverrideHandler serves a project's license overrides.
type OverrideHandler struct {
	repo    *OverrideRepository
	reapply licenseReapplier
	policy  policyReevaluator // optional: nil skips re-evaluation (tests, or the feature off)
}

func NewOverrideHandler(repo *OverrideRepository, reapply licenseReapplier) *OverrideHandler {
	return &OverrideHandler{repo: repo, reapply: reapply}
}

// WithPolicyReevaluation makes a write re-run the project's component
// policies once the reapply finishes, so violations reflect the new
// concluded licenses without waiting for the next upload or sweep.
func (h *OverrideHandler) WithPolicyReevaluation(p policyReevaluator) *OverrideHandler {
	h.policy = p
	return h
}

// Register mounts the license-override routes.
func (h *OverrideHandler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/license-overrides", h.list)
	r.Post("/projects/:projectID/license-overrides", h.create)
	r.Get("/projects/:projectID/license-overrides/:overrideID", h.get)
	r.Put("/projects/:projectID/license-overrides/:overrideID", h.update)
	r.Delete("/projects/:projectID/license-overrides/:overrideID", h.delete)
}

func (h *OverrideHandler) mapErr(err error) error {
	if errors.Is(err, ErrOverrideNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "license override not found")
	}
	return err
}

func (h *OverrideHandler) list(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	overrides, err := h.repo.List(c.UserContext(), projectID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"license_overrides": overrides})
}

func (h *OverrideHandler) get(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	id, err := httpx.ID(c, "overrideID")
	if err != nil {
		return err
	}
	o, err := h.repo.Get(c.UserContext(), projectID, id)
	if err != nil {
		return h.mapErr(err)
	}
	return c.JSON(o)
}

func (h *OverrideHandler) create(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in OverrideInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	if err := in.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	var createdBy string
	if u := auth.CurrentActor(c).UserID; u != "" {
		if _, perr := uuid.Parse(u); perr == nil {
			createdBy = u
		}
	}
	o, err := h.repo.Create(c.UserContext(), projectID, in, createdBy)
	if err != nil {
		return err
	}
	h.reapplyAndReevaluate(c.UserContext(), projectID)
	return c.Status(fiber.StatusCreated).JSON(o)
}

func (h *OverrideHandler) update(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	id, err := httpx.ID(c, "overrideID")
	if err != nil {
		return err
	}
	var in OverrideInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	if err := in.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	o, err := h.repo.Update(c.UserContext(), projectID, id, in)
	if err != nil {
		return h.mapErr(err)
	}
	h.reapplyAndReevaluate(c.UserContext(), projectID)
	return c.JSON(o)
}

func (h *OverrideHandler) delete(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	id, err := httpx.ID(c, "overrideID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), projectID, id); err != nil {
		return h.mapErr(err)
	}
	h.reapplyAndReevaluate(c.UserContext(), projectID)
	return c.SendStatus(fiber.StatusNoContent)
}

// reapplyAndReevaluate recomputes every current component's license fields
// and, if wired, re-runs component policies. Synchronous: a project's
// overrides and components are both small, and the caller (an admin editing
// overrides) wants to see the new verdict land, not poll for it.
func (h *OverrideHandler) reapplyAndReevaluate(ctx context.Context, projectID string) {
	if h.reapply == nil {
		return
	}
	if _, err := h.reapply.ReapplyLicenseOverrides(ctx, projectID); err != nil {
		return
	}
	if h.policy != nil {
		h.policy.Reevaluate([]string{projectID}, false)
	}
}

// Reapplier adapts sbom.Repository.ReapplyLicenseOverrides (which needs a
// freshly built matcher each call) to the simple (ctx, projectID) shape
// OverrideHandler wants, so cmd/api wiring doesn't need its own adapter
// type and smoke_test.go can share it. *Matcher satisfies
// sbom.LicenseOverrideMatcher structurally (plain string/[]string/bool
// types throughout), so this is the only file in the package that imports
// internal/sbom; internal/sbom itself never imports internal/license.
type Reapplier struct {
	sboms *sbom.Repository
	load  func(context.Context) (*Matcher, error)
}

// NewReapplier builds one; load builds a fresh matcher from every project's
// current overrides.
func NewReapplier(sboms *sbom.Repository, load func(context.Context) (*Matcher, error)) Reapplier {
	return Reapplier{sboms: sboms, load: load}
}

func (a Reapplier) ReapplyLicenseOverrides(ctx context.Context, projectID string) (int, error) {
	m, err := a.load(ctx)
	if err != nil {
		return 0, err
	}
	return a.sboms.ReapplyLicenseOverrides(ctx, projectID, sbom.LicenseResolver(Resolve), m)
}
