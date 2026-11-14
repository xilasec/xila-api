package feature

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/user"
)

// Owners resolves whether a user is the instance owner (user.Repository).
type Owners interface {
	GetByID(ctx context.Context, id string) (user.User, error)
}

// Handler serves the switches and gates the routes of switched-off features.
type Handler struct {
	store  *Store
	owners Owners
}

// NewHandler constructs a Handler.
func NewHandler(store *Store, owners Owners) *Handler {
	return &Handler{store: store, owners: owners}
}

// Middleware answers 404 for the API routes of a switched-off feature. It
// belongs on the authenticated group after sign-in and the audit log, so an
// anonymous caller still gets 401 and every refused mutation is logged.
func (h *Handler) Middleware() fiber.Handler { return h.gate(false) }

// PublicMiddleware does the same for a feature's unauthenticated routes (CSAF
// directory, badge images, the MFA step of sign-in); it goes on the app,
// ahead of them.
func (h *Handler) PublicMiddleware() fiber.Handler { return h.gate(true) }

func (h *Handler) gate(public bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if key := h.store.featureFor(c.Path(), public); key != "" && !h.store.Enabled(c.UserContext(), key) {
			return fiber.NewError(fiber.StatusNotFound, "this feature is turned off on this instance ("+key+")")
		}
		return c.Next()
	}
}

// Register mounts GET /features (anyone signed in: the UI hides what is off)
// and PUT /features/:key (instance admins; authz).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/features", h.list)
	r.Put("/features/:key", h.set)
}

func (h *Handler) list(c *fiber.Ctx) error {
	states, err := h.store.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"features": states})
}

func (h *Handler) set(c *fiber.Ctx) error {
	key := c.Params("key")
	def, ok := lookup(key)
	if !ok {
		return fiber.NewError(fiber.StatusNotFound, "unknown feature")
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.BodyParser(&body); err != nil || body.Enabled == nil {
		return fiber.NewError(fiber.StatusBadRequest, `body must be {"enabled": true|false}`)
	}
	actor := auth.CurrentActor(c)
	if def.OwnerOnly {
		if actor.IsToken || actor.IsServiceAccount {
			return fiber.NewError(fiber.StatusForbidden, "sign in as the instance owner to switch this feature; API tokens can't")
		}
		u, err := h.owners.GetByID(c.UserContext(), actor.UserID)
		if err != nil && !errors.Is(err, user.ErrNotFound) {
			return err
		}
		if !u.IsOwner {
			return fiber.NewError(fiber.StatusForbidden, "only the instance owner can switch this feature")
		}
	}
	before, err := h.store.List(c.UserContext())
	if err != nil {
		return err
	}
	st, err := h.store.Set(c.UserContext(), key, *body.Enabled, actor.UserID)
	switch {
	case errors.Is(err, ErrUnavailable):
		return fiber.NewError(fiber.StatusConflict, "this feature isn't configured on this server, so it can't be turned on")
	case err != nil:
		return err
	}
	for _, b := range before {
		if b.Key == key {
			// "feature", not "key": the audit redaction treats a field named key
			// as a credential.
			audit.SetChanges(c, fiber.Map{"feature": key, "enabled": b.Enabled}, fiber.Map{"feature": key, "enabled": st.Enabled})
		}
	}
	return c.JSON(st)
}
