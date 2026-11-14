package auth

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// TokenPrefix identifies API-token credentials (vs JWT bearer tokens).
const TokenPrefix = "xila_"

const (
	userIDKey = "userID"
	actorKey  = "actor"
)

// Actor is the authenticated principal for a request.
type Actor struct {
	UserID    string
	ProjectID string // non-empty when a token is scoped to a single project
	IsToken   bool
	TokenID   string // the API token's id when IsToken (named in the audit log)
	IsAdmin   bool   // global instance admin (bypasses team authorization)
	// IsServiceAccount marks a service account (users.kind='service'); set by
	// its keys and federated sessions.
	IsServiceAccount bool
}

// TokenValidator resolves an API token string to an Actor. Implemented by the
// apitoken service; kept as an interface here to avoid an import cycle.
type TokenValidator interface {
	ValidateToken(ctx context.Context, raw string) (Actor, error)
}

// SessionValidator reports whether a JWT's session is still live: the user
// exists, isn't deactivated, and tokenVersion is current. Implemented by
// user.Repository.
type SessionValidator interface {
	SessionValid(ctx context.Context, userID string, tokenVersion int) (bool, error)
}

// Middleware authenticates a request via JWT (humans) or, when a validator is
// supplied, an API token (CI). It stores the actor on the request context.
// With sessions set, a JWT is also checked against the user's current token
// version, so a password change, "sign out everywhere" or deactivation takes
// effect immediately instead of when the token expires.
func Middleware(secret string, tokens TokenValidator, sessions SessionValidator) fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw, ok := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer ")
		if !ok || raw == "" {
			return fiber.NewError(fiber.StatusUnauthorized, "missing bearer token")
		}

		if tokens != nil && strings.HasPrefix(raw, TokenPrefix) {
			actor, err := tokens.ValidateToken(c.UserContext(), raw)
			if err != nil {
				return fiber.NewError(fiber.StatusUnauthorized, "invalid or expired token")
			}
			if err := checkProjectScope(c, actor); err != nil {
				return err
			}
			setActor(c, actor)
			return c.Next()
		}

		claims, err := ParseToken(secret, raw)
		if err != nil || claims.Purpose != "" {
			// A two-factor challenge is not a session.
			return fiber.NewError(fiber.StatusUnauthorized, "invalid or expired token")
		}
		if sessions != nil {
			ok, err := sessions.SessionValid(c.UserContext(), claims.Subject, claims.TokenVersion)
			if err != nil {
				return err
			}
			if !ok {
				return fiber.NewError(fiber.StatusUnauthorized, "session revoked — sign in again")
			}
		}
		actor := Actor{UserID: claims.Subject, IsAdmin: claims.IsAdmin,
			IsServiceAccount: claims.ServiceAccount, ProjectID: claims.ProjectID}
		if err := checkProjectScope(c, actor); err != nil {
			return err
		}
		setActor(c, actor)
		return c.Next()
	}
}

// checkProjectScope lets a project-scoped credential (API token or federated
// session) act only on its own project. Params are not yet bound in group
// middleware, so the id is read from the path.
func checkProjectScope(c *fiber.Ctx, actor Actor) error {
	if actor.ProjectID != "" {
		if pid := projectIDFromPath(c.Path()); pid != "" && pid != actor.ProjectID {
			return fiber.NewError(fiber.StatusForbidden, "token not authorized for this project")
		}
	}
	return nil
}

// projectIDFromPath returns the id in ".../projects/{id}/..." or "" if absent.
func projectIDFromPath(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if s == "projects" && i+1 < len(segs) {
			return segs[i+1]
		}
	}
	return ""
}

func setActor(c *fiber.Ctx, a Actor) {
	c.Locals(userIDKey, a.UserID)
	c.Locals(actorKey, a)
}

// UserID returns the authenticated user id, or "" if unset.
func UserID(c *fiber.Ctx) string {
	id, _ := c.Locals(userIDKey).(string)
	return id
}

// CurrentActor returns the authenticated actor set by Middleware.
func CurrentActor(c *fiber.Ctx) Actor {
	a, _ := c.Locals(actorKey).(Actor)
	return a
}
