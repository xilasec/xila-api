package inbox

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler serves /me/inbox for the signed-in person.
type Handler struct {
	repo *Repository
}

// NewHandler constructs a Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/me/inbox", h.list)
	r.Get("/me/inbox/count", h.count)
	r.Post("/me/inbox/read", h.markRead)
}

// actor returns the signed-in person's id; service accounts have no inbox.
func actor(c *fiber.Ctx) (string, error) {
	a := auth.CurrentActor(c)
	if a.IsServiceAccount {
		return "", fiber.NewError(fiber.StatusForbidden, "service accounts don't have an inbox")
	}
	return a.UserID, nil
}

// list handles GET /me/inbox?filter=unread|mentions|assigned.
func (h *Handler) list(c *fiber.Ctx) error {
	uid, err := actor(c)
	if err != nil {
		return err
	}
	switch mode := c.Query("filter"); mode {
	case "", "unread", "mentions", "assigned":
	default:
		return fiber.NewError(fiber.StatusBadRequest, "invalid filter")
	}
	page := httpx.ParsePage(c)
	items, err := h.repo.List(c.UserContext(), uid, Filter{Mode: c.Query("filter"), Limit: page.Limit + 1, Offset: page.Offset})
	if err != nil {
		return err
	}
	hasMore := len(items) > page.Limit
	if hasMore {
		items = items[:page.Limit]
	}
	return c.JSON(fiber.Map{"items": items, "pagination": httpx.Meta(page, len(items), hasMore)})
}

// count handles GET /me/inbox/count.
func (h *Handler) count(c *fiber.Ctx) error {
	uid, err := actor(c)
	if err != nil {
		return err
	}
	n, err := h.repo.UnreadCount(c.UserContext(), uid)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"unread": n})
}

type markReadRequest struct {
	IDs []string `json:"ids"`
	All bool     `json:"all"`
}

// markRead handles POST /me/inbox/read: {"ids": [...]} or {"all": true}.
func (h *Handler) markRead(c *fiber.Ctx) error {
	uid, err := actor(c)
	if err != nil {
		return err
	}
	var body markReadRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if !body.All {
		for _, id := range body.IDs {
			if uuid.Validate(id) != nil {
				return fiber.NewError(fiber.StatusBadRequest, "invalid id")
			}
		}
	}
	n, err := h.repo.MarkRead(c.UserContext(), uid, body.IDs, body.All)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"marked": n})
}
