package enrichment

import "github.com/gofiber/fiber/v2"

// Handler exposes a manual enrichment trigger.
type Handler struct {
	svc *Service
}

// NewHandler constructs an enrichment Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts the enrichment route.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/enrich", h.Run)
	r.Get("/enrich/kev-catalogs", h.KEVCatalogs)
}

// KEVCatalogs handles GET /enrich/kev-catalogs: each KEV catalog's sync state.
func (h *Handler) KEVCatalogs(c *fiber.Ctx) error {
	list, err := h.svc.KEVStatus(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"catalogs": list})
}

// Run handles POST /enrich: download the KEV catalogs, fetch EPSS and
// recompute priorities now. A failed catalog is reported in kev_failed (its
// last list still applies), not as a failure of the run.
func (h *Handler) Run(c *fiber.Ctx) error {
	res, err := h.svc.Enrich(c.UserContext())
	if err != nil {
		return fiber.NewError(fiber.StatusBadGateway, "enrichment failed: "+err.Error())
	}
	return c.JSON(res)
}
