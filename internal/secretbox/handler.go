package secretbox

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Handler serves the INTEGRATION_SECRET_KEY ring's rotation status.
type Handler struct {
	db   *pgxpool.Pool
	ring *Keyring
}

// NewHandler constructs a Handler.
func NewHandler(db *pgxpool.Pool, ring *Keyring) *Handler {
	return &Handler{db: db, ring: ring}
}

// Register mounts GET /admin/secrets/status (instance-admin; see
// internal/authz).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/admin/secrets/status", h.status)
}

// status reports every registered column's counts, so an operator can tell
// when INTEGRATION_SECRET_KEY_PREVIOUS can be dropped (previous reaches 0
// everywhere) and whether any row is unreadable with the configured keys.
func (h *Handler) status(c *fiber.Ctx) error {
	columns, err := Status(c.UserContext(), h.db, h.ring)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"columns": columns})
}
