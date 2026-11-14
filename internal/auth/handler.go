package auth

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/user"
)

// Handler exposes the auth use cases over HTTP.
type Handler struct {
	svc *Service
}

// PasswordLoginEnabled reports whether email + password sign-in is offered
// (for /auth/config).
func (h *Handler) PasswordLoginEnabled() bool { return h.svc.PasswordLoginEnabled() }

// NewHandler constructs an auth Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type authResponse struct {
	Token string    `json:"token,omitempty"`
	User  user.User `json:"user"`
}

// Register handles POST /auth/register.
func (h *Handler) Register(c *fiber.Ctx) error {
	var body credentials
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	u, err := h.svc.Register(c.UserContext(), body.Email, body.Password)
	switch {
	case errors.Is(err, ErrValidation):
		return fiber.NewError(fiber.StatusBadRequest,
			"email is required and password must be at least 8 characters")
	case errors.Is(err, ErrEmailTaken):
		return fiber.NewError(fiber.StatusConflict, "email already registered")
	case errors.Is(err, ErrRegistrationClosed):
		return fiber.NewError(fiber.StatusForbidden, "registration is disabled — sign in with single sign-on")
	case err != nil:
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(authResponse{User: u})
}

// Login handles POST /auth/login.
func (h *Handler) Login(c *fiber.Ctx) error {
	var body credentials
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}

	token, u, err := h.svc.Login(c.UserContext(), body.Email, body.Password)
	if mfa, ok := errors.AsType[*MFARequiredError](err); ok {
		return c.JSON(mfaRequired(mfa))
	}
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return fiber.NewError(fiber.StatusUnauthorized, "invalid credentials")
	case errors.Is(err, ErrPasswordLoginDisabled):
		return fiber.NewError(fiber.StatusForbidden, "password sign-in is disabled — sign in with single sign-on")
	case errors.Is(err, ErrAccountDisabled):
		return fiber.NewError(fiber.StatusForbidden, "this account is deactivated — ask an administrator")
	case errors.Is(err, ErrDirectoryRefused):
		return fiber.NewError(fiber.StatusForbidden, ErrDirectoryRefused.Error()+" — ask an administrator")
	case err != nil:
		return err
	}
	return c.JSON(authResponse{Token: token, User: u})
}

// DirectoryLogin reports whether the password form also signs in against
// LDAP (for /auth/config: the form must show even with passwords off).
func (h *Handler) DirectoryLogin() bool { return h.svc.DirectoryEnabled() }

// PasswordResetByEmail reports whether "forgot password" mail is offered (for
// /auth/config).
func (h *Handler) PasswordResetByEmail() bool {
	return h.svc.mailer != nil && h.svc.mailer.SMTPConfigured() && h.svc.publicURL != ""
}

type resetRequest struct {
	Email string `json:"email"`
}

// RequestPasswordReset handles POST /auth/password-reset/request. The answer
// is the same whether or not the address has an account.
func (h *Handler) RequestPasswordReset(c *fiber.Ctx) error {
	var body resetRequest
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	h.svc.RequestReset(c.UserContext(), body.Email)
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"message": "if that address has an account with a password, a reset link is on its way",
	})
}

type resetConfirm struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// ConfirmPasswordReset handles POST /auth/password-reset/confirm: sets the new
// password, signs out every other session and signs the caller in.
func (h *Handler) ConfirmPasswordReset(c *fiber.Ctx) error {
	var body resetConfirm
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	token, u, err := h.svc.ConfirmReset(c.UserContext(), body.Token, body.Password)
	if mfa, ok := errors.AsType[*MFARequiredError](err); ok {
		return c.JSON(mfaRequired(mfa)) // the password is set; the second factor still applies
	}
	switch {
	case errors.Is(err, ErrValidation):
		return fiber.NewError(fiber.StatusBadRequest, "password must be at least 8 characters")
	case errors.Is(err, user.ErrResetInvalid):
		return fiber.NewError(fiber.StatusBadRequest, user.ErrResetInvalid.Error())
	case err != nil:
		return err
	}
	return c.JSON(authResponse{Token: token, User: u})
}

// mfaRequired is the first step's answer when two-factor is on: no session,
// a short-lived challenge for POST /auth/mfa.
func mfaRequired(e *MFARequiredError) fiber.Map {
	return fiber.Map{"mfa_required": true, "mfa_token": e.Token, "expires_in": int(MFATTL.Seconds())}
}

type mfaRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

// VerifyMFA handles POST /auth/mfa: the challenge from sign-in plus a TOTP or
// recovery code.
func (h *Handler) VerifyMFA(c *fiber.Ctx) error {
	var body mfaRequest
	if err := c.BodyParser(&body); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	token, u, err := h.svc.VerifyMFA(c.UserContext(), body.MFAToken, body.Code)
	switch {
	case errors.Is(err, ErrInvalidCode):
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrChallengeExpired):
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrTooManyAttempts):
		return fiber.NewError(fiber.StatusTooManyRequests, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(authResponse{Token: token, User: u})
}
