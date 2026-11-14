package server

import (
	"net/http"
	"testing"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func TestAuthConfigShape(t *testing.T) {
	app := newTestApp(t)
	resp, body := req(t, app, http.MethodGet, "/api/v1/auth/config", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/config = %d", resp.StatusCode)
	}
	if body["password_login_enabled"] != true {
		t.Errorf("password_login_enabled = %v, want true", body["password_login_enabled"])
	}
	if providers, ok := body["providers"].([]any); !ok || len(providers) != 0 {
		t.Errorf("providers = %#v, want an empty list (no SSO configured)", body["providers"])
	}
	if _, legacy := body["oidc_enabled"]; legacy {
		t.Error("the pre-SAML oidc_* fields must be gone")
	}
}

// With PASSWORD_LOGIN_ENABLED=false only the owner may sign in with a password
// (break-glass), registration is closed, and API tokens keep working.
func TestPasswordLoginDisabled(t *testing.T) {
	pool := pgtest.Pool(t)
	open := newTestAppOn(t, pool)
	owner := rbacUser(t, open, "owner@xila.io")
	rbacUser(t, open, "bob@xila.io")
	_, tok := req(t, open, http.MethodPost, "/api/v1/tokens", owner, `{"name":"ci"}`)
	apiToken, _ := tok["secret"].(string)
	if apiToken == "" {
		t.Fatalf("no api token: %v", tok)
	}

	closed := newTestAppOn(t, pool, func(c *config.Config) { c.PasswordLoginEnabled = false })

	if _, body := req(t, closed, http.MethodGet, "/api/v1/auth/config", "", ""); body["password_login_enabled"] != false {
		t.Errorf("auth config password_login_enabled = %v, want false", body["password_login_enabled"])
	}
	// The owner gets in.
	resp, body := req(t, closed, http.MethodPost, "/api/v1/auth/login", "", `{"email":"owner@xila.io","password":"supersecret"}`)
	if resp.StatusCode != http.StatusOK || body["token"] == nil {
		t.Errorf("owner break-glass login = %d, want 200 with a token", resp.StatusCode)
	}
	// Everyone else is refused — correct password or not, the owner's wrong
	// password included, with the same status.
	for _, creds := range []string{
		`{"email":"bob@xila.io","password":"supersecret"}`,
		`{"email":"owner@xila.io","password":"wrong-password"}`,
		`{"email":"nobody@xila.io","password":"supersecret"}`,
	} {
		if resp, _ := req(t, closed, http.MethodPost, "/api/v1/auth/login", "", creds); resp.StatusCode != http.StatusForbidden {
			t.Errorf("login %s = %d, want 403", creds, resp.StatusCode)
		}
	}
	if resp, _ := req(t, closed, http.MethodPost, "/api/v1/auth/register", "", `{"email":"carol@xila.io","password":"supersecret"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("register = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, closed, http.MethodGet, "/api/v1/me", apiToken, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("API token with password login disabled = %d, want 200", resp.StatusCode)
	}
}

// Group mappings are instance-admin only, validated, and deletable.
func TestSSOGroupMappingsAdmin(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", bob, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", bob, `{"slug":"platform","name":"Platform"}`)
	teamID, _ := teamBody["id"].(string)
	if teamID == "" {
		t.Fatal("setup: no team")
	}

	mapping := `{"provider":"any","group":"platform-devs","target_kind":"team","target_id":"` + teamID + `","role":"editor"}`
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/sso/group-mappings", ""},
		{http.MethodPost, "/api/v1/sso/group-mappings", mapping},
		{http.MethodGet, "/api/v1/sso/providers", ""},
	} {
		if resp, _ := req(t, app, r.method, r.path, bob, r.body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("non-admin %s %s = %d, want 403", r.method, r.path, resp.StatusCode)
		}
	}

	resp, created := req(t, app, http.MethodPost, "/api/v1/sso/group-mappings", admin, mapping)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create mapping = %d %v", resp.StatusCode, created)
	}
	if created["target_name"] != "Platform" || created["role"] != "editor" {
		t.Errorf("created = %v", created)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sso/group-mappings", admin, mapping); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate mapping = %d, want 409", resp.StatusCode)
	}
	for _, bad := range []string{
		`{"group":"x","target_kind":"team","target_id":"` + teamID + `","role":"admin"}`, // org role on a team
		`{"group":"x","target_kind":"instance_admin","role":"owner"}`,
		`{"group":"","target_kind":"instance_admin"}`,
		`{"group":"x","target_kind":"org","target_id":"00000000-0000-0000-0000-000000000000","role":"member"}`, // no such org
	} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/sso/group-mappings", admin, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid mapping %s = %d, want 400", bad, resp.StatusCode)
		}
	}

	_, list := req(t, app, http.MethodGet, "/api/v1/sso/group-mappings", admin, "")
	if items, _ := list["mappings"].([]any); len(items) != 1 {
		t.Fatalf("mappings = %v, want 1", list["mappings"])
	}
	id, _ := created["id"].(string)
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/sso/group-mappings/"+id, bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin delete = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/sso/group-mappings/"+id, admin, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("admin delete = %d, want 204", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/sso/group-mappings/"+id, admin, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("second delete = %d, want 404", resp.StatusCode)
	}

	_, providers := req(t, app, http.MethodGet, "/api/v1/sso/providers", admin, "")
	if p, ok := providers["providers"].([]any); !ok || len(p) != 0 || providers["auto_create_users"] != true {
		t.Errorf("providers = %v", providers)
	}

	// Pre-provisioning a passwordless account (for SSO_AUTO_CREATE_USERS=false).
	if resp, u := req(t, app, http.MethodPost, "/api/v1/users", admin, `{"email":"Dana@Xila.io"}`); resp.StatusCode != http.StatusCreated || u["email"] != "dana@xila.io" {
		t.Errorf("pre-provision = %d %v", resp.StatusCode, u)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"dana@xila.io","password":""}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("passwordless account password login = %d, want 401", resp.StatusCode)
	}
}
