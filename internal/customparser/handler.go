package customparser

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/scanner"
)

// Handler exposes custom-parser management + a dry-run preview. Instance-
// admin gated by the authz middleware (definitions are instance-wide, like
// triage rules and component policies).
type Handler struct {
	svc *Service
}

// NewHandler constructs a customparser Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/custom-parsers", h.Create)
	r.Get("/custom-parsers", h.List)
	r.Post("/custom-parsers/dry-run", h.DryRun)
	r.Get("/custom-parsers/:parserID", h.Get)
	r.Put("/custom-parsers/:parserID", h.Update)
	r.Delete("/custom-parsers/:parserID", h.Delete)
}

// List returns every custom parser.
func (h *Handler) List(c *fiber.Ctx) error {
	defs, err := h.svc.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"custom_parsers": defs})
}

// Get returns one custom parser.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "parserID")
	if err != nil {
		return err
	}
	def, err := h.svc.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "custom parser not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(def)
}

// Create adds a custom parser.
func (h *Handler) Create(c *fiber.Ctx) error {
	var def scanner.CustomDefinition
	if err := httpx.Parse(c, &def); err != nil {
		return err
	}
	out, err := h.svc.Create(c.UserContext(), def, auth.UserID(c))
	if err != nil {
		return writeError(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// Update replaces a custom parser's mapping.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "parserID")
	if err != nil {
		return err
	}
	var def scanner.CustomDefinition
	if err := httpx.Parse(c, &def); err != nil {
		return err
	}
	out, err := h.svc.Update(c.UserContext(), id, def)
	if err != nil {
		return writeError(err)
	}
	return c.JSON(out)
}

// Delete removes a custom parser. Its findings keep their scanner name as
// history.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "parserID")
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.UserContext(), id); err != nil {
		return writeError(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// dryRunRequest is a definition plus a pasted sample report: the admin
// mapping editor's live preview, parsed without persisting anything.
type dryRunRequest struct {
	scanner.CustomDefinition
	Sample string `json:"sample"`
}

// DryRun handles POST /custom-parsers/dry-run: parses a pasted sample against
// an unsaved (or edited) definition and returns the findings it would
// create, with per-record errors. Writes nothing.
func (h *Handler) DryRun(c *fiber.Ctx) error {
	var req dryRunRequest
	if err := httpx.Parse(c, &req); err != nil {
		return err
	}
	findings, recErrs, err := h.svc.DryRun(req.CustomDefinition, []byte(req.Sample))
	if err != nil {
		return writeError(err)
	}
	return c.JSON(fiber.Map{"findings": findings, "record_errors": recErrs})
}

// writeError maps domain errors to HTTP status; a *ValidationError (a bad
// mapping) is always the caller's fault (400). Anything else is returned
// as-is for Fiber's default error handler (a storage failure is a 500, never
// shown as if it were the caller's mistake).
func writeError(err error) error {
	var v *ValidationError
	switch {
	case errors.As(err, &v):
		return fiber.NewError(fiber.StatusBadRequest, v.Error())
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "custom parser not found")
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}
