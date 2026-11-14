package audit

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
)

// authAction names the public sign-in endpoint a request hits, or "" for one
// the log doesn't record (the login page config, SSO redirects out, metadata).
// segs are the path's segments after /api/v1/auth.
func authAction(method string, segs []string) (action, provider string) {
	p := strings.Join(segs, "/")
	if method == fiber.MethodPost {
		switch p {
		case "register":
			return "auth.register", ""
		case "login":
			return "auth.login", ""
		case "password-reset/request":
			return "auth.password_reset.request", ""
		case "password-reset/confirm":
			return "auth.password_reset.confirm", ""
		case "mfa":
			return "auth.mfa", ""
		}
	}
	// SSO completions: GET /oidc[/{slug}]/callback, POST /saml[/{slug}]/acs;
	// SAML Single Logout: GET|POST /saml[/{slug}]/slo.
	n := len(segs)
	if n < 2 || n > 3 {
		return "", ""
	}
	proto, last := segs[0], segs[n-1]
	if (proto == "oidc" && last == "callback" && method == fiber.MethodGet) ||
		(proto == "saml" && last == "acs" && method == fiber.MethodPost) {
		provider = proto // the environment-configured provider
		if n == 3 {
			provider = segs[1]
		}
		return "auth.sso_login", provider
	}
	// SAML Single Logout, either direction: an IdP's LogoutRequest ends
	// sessions here, so it is recorded like a sign-in.
	if proto == "saml" && last == "slo" && (method == fiber.MethodGet || method == fiber.MethodPost) {
		provider = proto
		if n == 3 {
			provider = segs[1]
		}
		return "auth.sso_logout", provider
	}
	return "", ""
}

// authResult is the part of a sign-in response the log reads: who signed in.
// Tokens are only parsed for their subject, never kept.
type authResult struct {
	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
}

// Auth records the public sign-in endpoints: registration, password login
// (success and failure, never the password), password reset, the two-factor
// step and SSO logins. Mount it on the /auth group before its routes.
func (r *Recorder) Auth() fiber.Handler {
	return func(c *fiber.Ctx) (err error) {
		segs := apiSegments(c.Path())
		if len(segs) == 0 || segs[0] != "auth" {
			return c.Next()
		}
		action, provider := authAction(c.Method(), segs[1:])
		if action == "" {
			return c.Next()
		}
		e := Entry{
			ActorKind: ActorAnonymous,
			Action:    action,
			Method:    c.Method(),
			Path:      strings.Clone(c.Path()),
			ClientIP:  strings.Clone(c.IP()),
			RequestID: requestID(c),
		}
		// The submitted identity, for a failure: who someone tried to be.
		var submitted struct {
			Email    string `json:"email"`
			MFAToken string `json:"mfa_token"`
		}
		_ = json.Unmarshal(c.Body(), &submitted)
		body := RedactBody(c.Body(), strings.Clone(c.Get(fiber.HeaderContentType)))

		defer func() {
			p := recover()
			e.Status = statusOf(c, err)
			if p != nil {
				e.Status = fiber.StatusInternalServerError
			}
			e.Outcome = outcomeOf(e.Status)
			changes := map[string]any{}
			if body != nil {
				changes["request"] = body
			}
			if provider != "" {
				r.ssoResult(c, &e, provider, changes)
			} else {
				r.passwordResult(c, &e, submitted.Email, submitted.MFAToken, changes)
			}
			e.Changes = mustJSON(changes)
			r.write(c, e)
			if p != nil {
				panic(p)
			}
		}()
		return c.Next()
	}
}

// passwordResult fills the actor of a JSON sign-in endpoint from its response
// (success) or the submitted identity (failure).
func (r *Recorder) passwordResult(c *fiber.Ctx, e *Entry, email, mfaToken string, changes map[string]any) {
	var res authResult
	if e.Outcome == OutcomeSuccess {
		_ = json.Unmarshal(c.Response().Body(), &res)
	}
	if res.User.ID != "" {
		e.ActorKind, e.ActorUserID, e.ActorEmail = ActorUser, new(res.User.ID), res.User.Email
		e.ResourceType, e.ResourceID = "users", res.User.ID
		return
	}
	e.ActorEmail = strings.ToLower(strings.TrimSpace(email))
	// A two-factor challenge names its user: the one issued (the password was
	// right, the second factor is pending) or the one presented with a code.
	if res.MFARequired {
		changes["mfa_required"] = true
		mfaToken = res.MFAToken
	}
	if mfaToken == "" {
		return
	}
	if claims, err := auth.ParseToken(r.secret, mfaToken); err == nil && isUUID(claims.Subject) {
		e.ActorUserID = new(claims.Subject)
		e.ResourceType, e.ResourceID = "users", claims.Subject
		if e.Outcome == OutcomeSuccess {
			e.ActorKind = ActorUser
		}
	}
}

// ssoResult reads an SSO completion's redirect: a session token in the
// fragment on success (whose subject names the user), an error code on the
// login page otherwise. Both answer 302, so the status alone can't tell.
func (r *Recorder) ssoResult(c *fiber.Ctx, e *Entry, provider string, changes map[string]any) {
	e.ResourceType, e.ResourceID = "sso_providers", provider
	loc := string(c.Response().Header.Peek(fiber.HeaderLocation))
	if token, ok := strings.CutPrefix(loc, "/#sso_token="); ok {
		if claims, err := auth.ParseToken(r.secret, token); err == nil && isUUID(claims.Subject) {
			e.ActorKind, e.ActorUserID = ActorUser, new(claims.Subject)
			return
		}
	}
	e.Outcome = OutcomeFailure
	if u, err := url.Parse(loc); err == nil && u.Query().Get("error") != "" {
		changes["error"] = u.Query().Get("error")
	}
}
