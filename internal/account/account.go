// Package account exposes the current user (/me) and admin user management.
// It sits above auth + user to avoid an import cycle.
package account

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/user"
)

// Handler exposes account + user-admin endpoints.
type Handler struct {
	users *user.Repository
	auth  *auth.Service
	sso   *sso.Service
}

// NewHandler constructs an account Handler. ssoSvc ends a SAML Single Logout
// round trip on sign-out, when the caller's session came from a SAML
// provider whose IdP advertises one (POST /me/logout); nil disables that and
// Logout falls back to ending the session locally only.
func NewHandler(users *user.Repository, authSvc *auth.Service, ssoSvc *sso.Service) *Handler {
	return &Handler{users: users, auth: authSvc, sso: ssoSvc}
}

// Register mounts the routes. /users* is admin-gated by the authz middleware.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/me", h.Me)
	r.Post("/me/password", h.ChangePassword)
	r.Post("/me/logout", h.Logout)
	r.Post("/me/sessions/revoke", h.RevokeSessions)
	r.Get("/me/mfa", h.MFAStatus)
	r.Post("/me/mfa/setup", h.MFASetup)
	r.Post("/me/mfa/enable", h.MFAEnable)
	r.Post("/me/mfa/disable", h.MFADisable)
	r.Get("/users", h.ListUsers)
	r.Post("/users", h.CreateUser)
	r.Patch("/users/:userID", h.SetAdmin)
	r.Delete("/users/:userID", h.DeleteUser)
	r.Post("/users/:userID/deactivate", h.Deactivate)
	r.Post("/users/:userID/reactivate", h.Reactivate)
	r.Post("/users/:userID/password-reset-link", h.PasswordResetLink)
	r.Delete("/users/:userID/mfa", h.MFAReset)
	r.Post("/users/:userID/transfer-ownership", h.TransferOwnership)
}

// Me returns the authenticated user.
func (h *Handler) Me(c *fiber.Ctx) error {
	actor := auth.CurrentActor(c)
	u, err := h.users.GetByID(c.UserContext(), actor.UserID)
	if err != nil {
		return err
	}
	return c.JSON(u)
}

// ListUsers returns all users (admin only).
func (h *Handler) ListUsers(c *fiber.Ctx) error {
	users, err := h.users.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"users": users})
}

type createUserRequest struct {
	Email string `json:"email"`
}

// CreateUser pre-provisions a passwordless account (admin only), for SSO with
// SSO_AUTO_CREATE_USERS=false: the person's first SSO login links to it by
// (verified) email.
func (h *Handler) CreateUser(c *fiber.Ctx) error {
	var body createUserRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if !strings.Contains(email, "@") {
		return fiber.NewError(fiber.StatusBadRequest, "a valid email is required")
	}
	u, err := h.users.Create(c.UserContext(), email, "")
	if errors.Is(err, user.ErrDuplicate) {
		return fiber.NewError(fiber.StatusConflict, "email already registered")
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(u)
}

type setAdminRequest struct {
	IsAdmin bool `json:"is_admin"`
}

// SetAdmin promotes/demotes a user (admin only), refusing to remove the last admin.
func (h *Handler) SetAdmin(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	var body setAdminRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	cur, err := h.users.GetByID(c.UserContext(), id)
	if errors.Is(err, user.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "user not found")
	}
	if err != nil {
		return err
	}
	if !body.IsAdmin {
		n, err := h.users.CountAdmins(c.UserContext())
		if err != nil {
			return err
		}
		if cur.IsAdmin && n <= 1 {
			return fiber.NewError(fiber.StatusBadRequest, "cannot remove the last admin")
		}
	}
	u, err := h.users.SetAdmin(c.UserContext(), id, body.IsAdmin)
	switch {
	case errors.Is(err, user.ErrOwnerProtected):
		return fiber.NewError(fiber.StatusForbidden,
			"the instance owner cannot be demoted; transfer ownership first")
	case errors.Is(err, user.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "user not found")
	case err != nil:
		return err
	}
	audit.SetChanges(c, fiber.Map{"is_admin": cur.IsAdmin}, fiber.Map{"is_admin": u.IsAdmin})
	return c.JSON(u)
}

// TransferOwnership hands the instance owner role to another user.
//
// Only the current owner may call it — being an admin is not enough, which is the
// entire point of having an owner. Without this, any admin could demote any other
// admin, and whoever set the instance up had no more standing than the last person
// they promoted.
func (h *Handler) TransferOwnership(c *fiber.Ctx) error {
	toID, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	actor := auth.CurrentActor(c)

	u, err := h.users.TransferOwnership(c.UserContext(), actor.UserID, toID)
	switch {
	case errors.Is(err, user.ErrNotOwner):
		return fiber.NewError(fiber.StatusForbidden, "only the instance owner can transfer ownership")
	case errors.Is(err, user.ErrDisabled):
		return fiber.NewError(fiber.StatusBadRequest, "reactivate the account before making it the owner")
	case errors.Is(err, user.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "user not found")
	case err != nil:
		return err
	}
	return c.JSON(fiber.Map{
		"owner":   u,
		"message": "ownership transferred; you are still an admin, but no longer the owner",
	})
}

// sessionOnly refuses API tokens on account-security actions: a leaked CI token
// must not be able to change its owner's password or sign them out. Service
// accounts have no account security at all — no password, no MFA — and
// "revoke sessions" would trade a short federated session for a full-length one.
func sessionOnly(c *fiber.Ctx) (auth.Actor, error) {
	actor := auth.CurrentActor(c)
	if actor.IsToken {
		return actor, fiber.NewError(fiber.StatusForbidden, "sign in to manage your account; API tokens can't")
	}
	if actor.IsServiceAccount {
		return actor, fiber.NewError(fiber.StatusForbidden, "service accounts have no account settings; an admin manages them")
	}
	return actor, nil
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword sets the caller's password and signs out every other session.
// The response carries a fresh token for this one.
func (h *Handler) ChangePassword(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	var body changePasswordRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	token, u, err := h.auth.ChangePassword(c.UserContext(), actor.UserID, body.CurrentPassword, body.NewPassword)
	switch {
	case errors.Is(err, auth.ErrValidation):
		return fiber.NewError(fiber.StatusBadRequest, "new password must be at least 8 characters")
	case errors.Is(err, auth.ErrWrongPassword):
		return fiber.NewError(fiber.StatusBadRequest, "current password is incorrect")
	case err != nil:
		return err
	}
	return c.JSON(fiber.Map{"token": token, "user": u})
}

// RevokeSessions signs the caller out everywhere else.
func (h *Handler) RevokeSessions(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	token, u, err := h.auth.RevokeSessions(c.UserContext(), actor.UserID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"token": token, "user": u})
}

// Logout handles POST /me/logout, the "Sign out" button. Signing out stays
// local — the browser drops its token, other devices stay signed in ("sign
// out everywhere", /me/sessions/revoke, is the explicit way to end those).
// What this adds: if the caller's latest sign-in was through a SAML provider
// whose IdP advertises a Single Logout endpoint, it returns the signed
// LogoutRequest URL to send the browser to, so the IdP ends its session too.
// An empty redirect means plain local sign-out.
func (h *Handler) Logout(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	if h.sso == nil {
		return c.JSON(fiber.Map{"redirect": ""})
	}
	result, err := h.sso.Logout(c.UserContext(), actor.UserID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"redirect": result.Redirect})
}

// otherUser parses :userID and refuses the caller's own id: an admin who
// deactivates or deletes themselves has locked themselves out.
func otherUser(c *fiber.Ctx, verb string) (string, error) {
	id, err := httpx.ID(c, "userID")
	if err != nil {
		return "", err
	}
	if id == auth.CurrentActor(c).UserID {
		return "", fiber.NewError(fiber.StatusBadRequest, "you can't "+verb+" your own account")
	}
	return id, nil
}

func userErr(err error, what string) error {
	switch {
	case errors.Is(err, user.ErrOwnerProtected):
		return fiber.NewError(fiber.StatusForbidden, "the instance owner can't be "+what+"; transfer ownership first")
	case errors.Is(err, user.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "user not found")
	case errors.Is(err, user.ErrDisabled):
		return fiber.NewError(fiber.StatusBadRequest, "the account is deactivated; reactivate it first")
	}
	return err
}

// Deactivate blocks an account (password, SSO, API tokens) and ends its
// sessions, keeping its history. Reversible with Reactivate.
func (h *Handler) Deactivate(c *fiber.Ctx) error {
	id, err := otherUser(c, "deactivate")
	if err != nil {
		return err
	}
	u, err := h.users.SetDisabled(c.UserContext(), id, true)
	if err != nil {
		return userErr(err, "deactivated")
	}
	return c.JSON(u)
}

// Reactivate lifts a deactivation.
func (h *Handler) Reactivate(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	u, err := h.users.SetDisabled(c.UserContext(), id, false)
	if err != nil {
		return userErr(err, "modified")
	}
	return c.JSON(u)
}

// DeleteUser removes an account for good: memberships, identities and API
// tokens go with it; authored comments, rules and policies stay, unattributed.
func (h *Handler) DeleteUser(c *fiber.Ctx) error {
	id, err := otherUser(c, "delete")
	if err != nil {
		return err
	}
	if err := h.users.Delete(c.UserContext(), id); err != nil {
		return userErr(err, "deleted")
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// PasswordResetLink mints a single-use reset link (24h) for the admin to hand
// over — the way to set a password without SMTP, or to rescue a locked-out
// user. Earlier links for the user stop working.
func (h *Handler) PasswordResetLink(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	link, expires, err := h.auth.ResetLink(c.UserContext(), id)
	if err != nil {
		return userErr(err, "modified")
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"url": link, "expires_at": expires})
}

func mfaErr(err error) error {
	switch {
	case errors.Is(err, auth.ErrMFAUnavailable):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, auth.ErrInvalidCode):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, auth.ErrTooManyAttempts):
		return fiber.NewError(fiber.StatusTooManyRequests, err.Error())
	case errors.Is(err, user.ErrMFAEnabled):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

// MFAStatus handles GET /me/mfa.
func (h *Handler) MFAStatus(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	u, err := h.users.GetByID(c.UserContext(), actor.UserID)
	if err != nil {
		return err
	}
	left, err := h.auth.RecoveryCodesLeft(c.UserContext(), actor.UserID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"enabled": u.MFAEnabled, "recovery_codes_left": left, "available": h.auth.MFAAvailable()})
}

// MFASetup handles POST /me/mfa/setup: a new secret to scan (not active yet).
func (h *Handler) MFASetup(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	out, err := h.auth.SetupMFA(c.UserContext(), actor.UserID)
	if err != nil {
		return mfaErr(err)
	}
	return c.JSON(out)
}

type codeRequest struct {
	Code string `json:"code"`
}

// MFAEnable handles POST /me/mfa/enable: a code from the new secret turns
// two-factor on and returns the recovery codes (shown once).
func (h *Handler) MFAEnable(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	var body codeRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	codes, err := h.auth.ConfirmMFA(c.UserContext(), actor.UserID, body.Code)
	if err != nil {
		return mfaErr(err)
	}
	return c.JSON(fiber.Map{"recovery_codes": codes})
}

// MFADisable handles POST /me/mfa/disable with a current or recovery code.
func (h *Handler) MFADisable(c *fiber.Ctx) error {
	actor, err := sessionOnly(c)
	if err != nil {
		return err
	}
	var body codeRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if err := h.auth.DisableMFA(c.UserContext(), actor.UserID, body.Code); err != nil {
		return mfaErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// MFAReset handles DELETE /users/{id}/mfa (admin): a lost authenticator. The
// user is signed out everywhere and signs in with the password alone until
// they enroll again.
func (h *Handler) MFAReset(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	if err := h.auth.ResetMFA(c.UserContext(), id); err != nil {
		return userErr(err, "modified")
	}
	return c.SendStatus(fiber.StatusNoContent)
}
