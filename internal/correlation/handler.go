package correlation

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes finding↔component correlation over HTTP.
type Handler struct {
	svc *Service
}

// NewHandler constructs a correlation Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts correlation routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/findings/:findingID/components", h.FindingComponents)
}

// FindingComponents handles GET /findings/{id}/components: the SBOM components
// that introduced the finding. Pass ?latest=true to match only current inventory.
func (h *Handler) FindingComponents(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}

	f, components, err := h.svc.ComponentsForFinding(c.UserContext(), id, c.QueryBool("latest"))
	if errors.Is(err, finding.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"finding":    f,
		"components": components,
	})
}
