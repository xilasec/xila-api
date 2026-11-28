package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func status(t *testing.T, got int, want int, what string, body map[string]any) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d %v, want %d", what, got, body, want)
	}
}

// A password change (and "sign out everywhere") must kill the sessions an
// attacker might hold — immediately, not when the JWT expires — while keeping
// the person who made the change signed in.
func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	app := newTestApp(t)
	rbacUser(t, app, "owner@xila.io")
	stolen := rbacUser(t, app, "bob@xila.io")
	_, login := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"supersecret"}`)
	mine := login["token"].(string)

	resp, body := req(t, app, http.MethodPost, "/api/v1/me/password", mine, `{"current_password":"wrong-guess","new_password":"evenmoresecret"}`)
	status(t, resp.StatusCode, http.StatusBadRequest, "change with the wrong current password", body)

	resp, body = req(t, app, http.MethodPost, "/api/v1/me/password", mine, `{"current_password":"supersecret","new_password":"evenmoresecret"}`)
	status(t, resp.StatusCode, http.StatusOK, "change password", body)
	fresh, _ := body["token"].(string)

	for name, tok := range map[string]string{"the stolen session": stolen, "the session that changed it": mine} {
		if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", tok, ""); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s after a password change = %d, want 401", name, resp.StatusCode)
		}
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", fresh, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("the token returned by the change = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"supersecret"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password still logs in: %d", resp.StatusCode)
	}

	// Sign out everywhere: same effect without a password change.
	resp, body = req(t, app, http.MethodPost, "/api/v1/me/sessions/revoke", fresh, "")
	status(t, resp.StatusCode, http.StatusOK, "revoke sessions", body)
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", fresh, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("session after sign-out-everywhere = %d, want 401", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", body["token"].(string), ""); resp.StatusCode != http.StatusOK {
		t.Errorf("token returned by sign-out-everywhere = %d, want 200", resp.StatusCode)
	}

	// An API token can't do either: a leaked CI token must not take over the account.
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", body["token"].(string), `{"name":"ci"}`)
	secret, _ := tok["secret"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/me/password", secret, `{"current_password":"evenmoresecret","new_password":"attackerpass"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("password change with an API token = %d, want 403", resp.StatusCode)
	}
}

// Deactivation shuts every door — live sessions, password login, API tokens —
// and reactivation reopens them; the owner and the caller themselves are
// protected from lockout.
func TestDeactivateAndDeleteUser(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "owner@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", bob, `{"name":"ci"}`)
	ci, _ := tok["secret"].(string)
	bobID := userIDOf(t, app, admin, "bob@xila.io")
	ownerID := userIDOf(t, app, admin, "owner@xila.io")

	if resp, _ := req(t, app, http.MethodPost, "/api/v1/users/"+ownerID+"/deactivate", admin, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("deactivating yourself = %d, want 400", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/deactivate", bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin deactivating = %d, want 403", resp.StatusCode)
	}
	resp, body := req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/deactivate", admin, "")
	status(t, resp.StatusCode, http.StatusOK, "deactivate", body)
	if body["disabled_at"] == nil {
		t.Errorf("deactivated user has no disabled_at: %v", body)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", bob, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deactivated user's session = %d, want 401", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", ci, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deactivated user's API token = %d, want 401", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"supersecret"}`)
	status(t, resp.StatusCode, http.StatusForbidden, "deactivated user's login", body)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/transfer-ownership", admin, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("transferring ownership to a deactivated user = %d, want 400", resp.StatusCode)
	}

	req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/reactivate", admin, "")
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", ci, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("API token after reactivation = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", bob, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a session ended by deactivation came back on reactivation: %d", resp.StatusCode)
	}

	resp, _ = req(t, app, http.MethodDelete, "/api/v1/users/"+bobID, admin, "")
	status(t, resp.StatusCode, http.StatusNoContent, "delete user", nil)
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", ci, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deleted user's API token = %d, want 401", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/users/"+ownerID, admin, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("deleting yourself = %d, want 400", resp.StatusCode)
	}
}

// An admin-issued reset link works exactly once, sets the password and signs
// out every existing session. The public request endpoint answers the same for
// every address.
func TestAdminResetLink(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "owner@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	bobID := userIDOf(t, app, admin, "bob@xila.io")

	resp, link := req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/password-reset-link", admin, "")
	status(t, resp.StatusCode, http.StatusCreated, "mint reset link", link)
	_, token, ok := strings.Cut(link["url"].(string), "#token=")
	if !ok || token == "" {
		t.Fatalf("reset url %q carries no token fragment", link["url"])
	}

	confirm := `{"token":"` + token + `","password":"brandnewpass"}`
	resp, body := req(t, app, http.MethodPost, "/api/v1/auth/password-reset/confirm", "", confirm)
	status(t, resp.StatusCode, http.StatusOK, "confirm reset", body)
	if body["token"] == nil {
		t.Errorf("confirm didn't sign the user in: %v", body)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/password-reset/confirm", "", confirm); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reusing a reset link = %d, want 400", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", bob, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("session from before the reset = %d, want 401", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"brandnewpass"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("login with the reset password = %d, want 200", resp.StatusCode)
	}

	for _, email := range []string{"bob@xila.io", "nobody@xila.io"} {
		resp, body := req(t, app, http.MethodPost, "/api/v1/auth/password-reset/request", "", `{"email":"`+email+`"}`)
		status(t, resp.StatusCode, http.StatusAccepted, "reset request for "+email, body)
	}
}

// Creating an API token needs a recent sign-in (REAUTH_WINDOW): a stale
// session gets 403 with X-Reauth-Required, "sign out everywhere" doesn't
// freshen it, POST /me/reauth with the password does, and an API token can
// never mint another.
func TestAPITokenNeedsRecentAuth(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool, func(c *config.Config) { c.JWT.ReauthWindow = 10 * time.Minute })
	rbacUser(t, app, "owner@xila.io")
	fresh := rbacUser(t, app, "bob@xila.io")
	if resp, body := req(t, app, http.MethodPost, "/api/v1/tokens", fresh, `{"name":"ci"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("token from a fresh sign-in = %d %v", resp.StatusCode, body)
	}

	// A session that authenticated an hour ago.
	var id string
	var tv int
	if err := pool.QueryRow(context.Background(), `SELECT id, token_version FROM users WHERE email = 'bob@xila.io'`).Scan(&id, &tv); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	stale, err := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.Claims{TokenVersion: tv, AuthTime: now.Add(-time.Hour).Unix(),
		Subject: id, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour))}).
		SignedString([]byte("smoke-secret"))
	if err != nil {
		t.Fatal(err)
	}
	refused := func(token, what string) {
		t.Helper()
		resp, body := req(t, app, http.MethodPost, "/api/v1/tokens", token, `{"name":"ci"}`)
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("X-Reauth-Required") != "true" {
			t.Errorf("%s: token creation = %d %v (X-Reauth-Required %q), want 403 + header", what, resp.StatusCode, body, resp.Header.Get("X-Reauth-Required"))
		}
	}
	refused(stale, "stale session")

	// Reissuing the session proves nothing: its auth_time carries over.
	resp, revoked := req(t, app, http.MethodPost, "/api/v1/me/sessions/revoke", stale, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d %v", resp.StatusCode, revoked)
	}
	reissued := revoked["token"].(string)
	refused(reissued, "session reissued by sign-out-everywhere")

	if resp, _ := req(t, app, http.MethodPost, "/api/v1/me/reauth", reissued, `{"password":"wrong-password"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("reauth with a wrong password = %d, want 400", resp.StatusCode)
	}
	resp, re := req(t, app, http.MethodPost, "/api/v1/me/reauth", reissued, `{"password":"supersecret"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reauth = %d %v", resp.StatusCode, re)
	}
	resp, created := req(t, app, http.MethodPost, "/api/v1/tokens", re["token"].(string), `{"name":"ci"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("token after reauth = %d %v", resp.StatusCode, created)
	}

	// An API token can neither mint tokens nor re-authenticate.
	secret := created["secret"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/tokens", secret, `{"name":"child"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("API token creating a token = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/me/reauth", secret, `{"password":"supersecret"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("API token re-authenticating = %d, want 403", resp.StatusCode)
	}
}
