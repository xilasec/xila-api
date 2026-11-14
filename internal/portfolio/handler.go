package portfolio

import (
	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/authz"
)

// Handler exposes the portfolio overview.
type Handler struct {
	repo *Repository
}

// NewHandler constructs a portfolio Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// Register mounts the portfolio route.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/portfolio", h.Overview)
}

// Overview handles GET /portfolio.
func (h *Handler) Overview(c *fiber.Ctx) error {
	var pids []string // nil = admin/all
	if s := authz.VisibleScope(c); !s.AllAccess {
		pids = s.ProjectIDs
	}
	out, err := h.repo.Overview(c.UserContext(), pids)
	if err != nil {
		return err
	}
	return c.JSON(out)
}
