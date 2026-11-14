package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/xilasec/xila-api/internal/pgtest"
)

const federationAudience = "https://xila.example"

// ciIssuer is an in-process OIDC issuer (discovery + JWKS) minting GitHub
// Actions–shaped identity tokens.
type ciIssuer struct {
	*httptest.Server
	key *rsa.PrivateKey
}

func newCIIssuer(t *testing.T) *ciIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	iss := &ciIssuer{key: key}
	mux := http.NewServeMux()
	iss.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss.URL, "jwks_uri": iss.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "gh-1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	t.Cleanup(iss.Close)
	return iss
}

// token signs a GitHub-shaped token; overrides replace (nil deletes) claims.
func (i *ciIssuer) token(t *testing.T, signer *rsa.PrivateKey, overrides map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": i.URL, "aud": federationAudience,
		"sub":        "repo:acme/web:ref:refs/heads/main",
		"repository": "acme/web", "repository_owner": "acme", "ref": "refs/heads/main",
		"environment": "production", "workflow": "ci",
		"iat": now.Unix(), "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "gh-1"
	s, err := tok.SignedString(signer)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// exchange posts an RFC 8693 form to /auth/token.
func exchange(t *testing.T, app *fiber.App, form url.Values) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &body)
	return resp.StatusCode, body
}

func exchangeForm(subject string) url.Values {
	return url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
	}
}

func TestServiceAccountsAndWorkloadFederation(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	idp := newCIIssuer(t)

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"web","name":"web"}`)
	pid, _ := p["id"].(string)
	_, p2 := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"api","name":"api"}`)
	otherPID, _ := p2["id"].(string)
	if pid == "" || otherPID == "" {
		t.Fatalf("projects not created: %v %v", p, p2)
	}

	// Non-admins manage none of it.
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/service-accounts", ""},
		{http.MethodPost, "/api/v1/service-accounts", `{"name":"sneaky"}`},
		{http.MethodGet, "/api/v1/federation/issuers", ""},
		{http.MethodPost, "/api/v1/federation/issuers", `{"name":"x","issuer_url":"` + idp.URL + `","audience":"a"}`},
		{http.MethodGet, "/api/v1/federation/bindings", ""},
		{http.MethodPost, "/api/v1/federation/bindings", `{}`},
	} {
		if resp, _ := req(t, app, r.method, r.path, bob, r.body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("non-admin %s %s = %d, want 403", r.method, r.path, resp.StatusCode)
		}
	}

	resp, sa := req(t, app, http.MethodPost, "/api/v1/service-accounts", admin, `{"name":"ci-web","description":"web pipeline"}`)
	saID, _ := sa["id"].(string)
	if resp.StatusCode != http.StatusCreated || sa["email"] != "ci-web@service-accounts.invalid" || sa["suspended_at"] != nil {
		t.Fatalf("create service account = %d %v", resp.StatusCode, sa)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/service-accounts", admin, `{"name":"ci-web"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", resp.StatusCode)
	}
	// Service accounts are not people: the users list doesn't show them.
	if _, users := req(t, app, http.MethodGet, "/api/v1/users", admin, ""); strings.Contains(asJSON(t, users), "ci-web@") {
		t.Errorf("users list shows the service account: %v", users)
	}
	// It takes a role like anyone: by email, through project membership.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", admin,
		`{"email":"ci-web@service-accounts.invalid","role":"editor"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("grant project role = %d", resp.StatusCode)
	}
	// …on both projects, so only the binding's project scope keeps it off the other.
	req(t, app, http.MethodPost, "/api/v1/projects/"+otherPID+"/members", admin, `{"email":"ci-web@service-accounts.invalid","role":"editor"}`)

	resp, issuer := req(t, app, http.MethodPost, "/api/v1/federation/issuers", admin,
		`{"name":"GitHub Actions","issuer_url":"`+idp.URL+`","audience":"`+federationAudience+`"}`)
	issuerID, _ := issuer["id"].(string)
	if resp.StatusCode != http.StatusCreated || issuer["enabled"] != true {
		t.Fatalf("create issuer = %d %v", resp.StatusCode, issuer)
	}
	if _, res := req(t, app, http.MethodPost, "/api/v1/federation/issuers/"+issuerID+"/test", admin, ""); res["ok"] != true {
		t.Errorf("issuer test = %v", res)
	}
	// A binding that doesn't pin the workload would admit any repository on
	// the platform.
	if resp, body := req(t, app, http.MethodPost, "/api/v1/federation/bindings", admin,
		`{"name":"main","issuer_id":"`+issuerID+`","service_account_id":"`+saID+`","conditions":{"ref":"refs/heads/main"}}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unpinned binding = %d %v, want 400", resp.StatusCode, body)
	}
	resp, binding := req(t, app, http.MethodPost, "/api/v1/federation/bindings", admin,
		`{"name":"web main","issuer_id":"`+issuerID+`","service_account_id":"`+saID+`","project_id":"`+pid+`",
		  "conditions":{"repository":"acme/web","ref":"refs/heads/main"}}`)
	if resp.StatusCode != http.StatusCreated || binding["service_account_name"] != "ci-web" {
		t.Fatalf("create binding = %d %v", resp.StatusCode, binding)
	}

	// The exchange.
	code, out := exchange(t, app, exchangeForm(idp.token(t, idp.key, nil)))
	session, _ := out["access_token"].(string)
	if code != http.StatusOK || session == "" || out["token_type"] != "Bearer" ||
		out["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" || out["expires_in"] != float64(900) {
		t.Fatalf("exchange = %d %v", code, out)
	}
	if _, me := req(t, app, http.MethodGet, "/api/v1/me", session, ""); me["kind"] != "service" || me["id"] != saID {
		t.Errorf("/me with the federated session = %v", me)
	}
	if resp, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", session, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload with the federated session = %d %v", resp.StatusCode, body)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+otherPID+"/scans?scanner=trivy", session, smokeTrivyReport); resp.StatusCode != http.StatusForbidden {
		t.Errorf("upload outside the binding's project = %d, want 403", resp.StatusCode)
	}
	// No account security, no self-issued keys.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/tokens", session, `{"name":"mine"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("service account minting its own token = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/me/sessions/revoke", session, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("service account renewing its session = %d, want 403", resp.StatusCode)
	}

	// The audit trail names the service account.
	_, list := req(t, app, http.MethodGet, "/api/v1/findings?project_id="+pid, session, "")
	items, _ := list["findings"].([]any)
	if len(items) == 0 {
		t.Fatalf("no findings visible to the service account: %v", list)
	}
	fid, _ := items[0].(map[string]any)["id"].(string)
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/findings/"+fid, session, `{"status":"confirmed","reason":"ci triage"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("triage by the service account = %d", resp.StatusCode)
	}
	if _, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+fid+"/history", admin, ""); !strings.Contains(asJSON(t, hist), `"actor_name":"ci-web@service-accounts.invalid"`) {
		t.Errorf("history doesn't name the service account: %v", hist)
	}

	// Refusals: every one a 401 invalid_grant.
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stranger := newCIIssuer(t)
	for name, tok := range map[string]string{
		"another ref":    idp.token(t, idp.key, map[string]any{"ref": "refs/heads/dev", "sub": "repo:acme/web:ref:refs/heads/dev"}),
		"another repo":   idp.token(t, idp.key, map[string]any{"repository": "evil/web"}),
		"wrong audience": idp.token(t, idp.key, map[string]any{"aud": "https://other.example"}),
		"expired":        idp.token(t, idp.key, map[string]any{"exp": time.Now().Add(-time.Hour).Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(), "nbf": nil}),
		"not yet valid":  idp.token(t, idp.key, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}),
		"bad signature":  idp.token(t, other, nil),
		"unknown issuer": stranger.token(t, stranger.key, nil),
		"not a jwt":      "not-a-jwt",
	} {
		if code, body := exchange(t, app, exchangeForm(tok)); code != http.StatusUnauthorized || body["error"] != "invalid_grant" {
			t.Errorf("%s: exchange = %d %v, want 401 invalid_grant", name, code, body)
		}
	}
	bad := exchangeForm(idp.token(t, idp.key, nil))
	bad.Set("grant_type", "client_credentials")
	if code, body := exchange(t, app, bad); code != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
		t.Errorf("wrong grant type = %d %v", code, body)
	}

	// Keys: expiring, capped, reusing API-token validation.
	keysPath := "/api/v1/service-accounts/" + saID + "/keys"
	if resp, _ := req(t, app, http.MethodPost, keysPath, admin, `{"name":"long","expires_in_days":91}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("key beyond the max = %d, want 400", resp.StatusCode)
	}
	resp, k := req(t, app, http.MethodPost, keysPath, admin, `{"name":"deploy"}`)
	key, _ := k["secret"].(string)
	meta, _ := k["key"].(map[string]any)
	exp, _ := time.Parse(time.RFC3339, meta["expires_at"].(string))
	if resp.StatusCode != http.StatusCreated || !strings.HasPrefix(key, "xila_") || exp.Sub(time.Now()) < 29*24*time.Hour || exp.Sub(time.Now()) > 30*24*time.Hour+time.Minute {
		t.Fatalf("create key = %d %v (default should expire in 30 days)", resp.StatusCode, k)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+pid, key, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("project read with the key = %d", resp.StatusCode)
	}
	resp, k2 := req(t, app, http.MethodPost, keysPath, admin, `{"name":"stale","expires_in_days":1}`)
	staleKey, _ := k2["secret"].(string)
	staleID, _ := k2["key"].(map[string]any)["id"].(string)
	if _, err := pool.Exec(context.Background(), `UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, staleID); err != nil {
		t.Fatal(err)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+pid, staleKey, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired key = %d, want 401", resp.StatusCode)
	}
	if _, keys := req(t, app, http.MethodGet, keysPath, admin, ""); len(keys["keys"].([]any)) != 2 {
		t.Errorf("keys = %v", keys)
	}

	// Suspension ends the session and the keys at once, and stops the exchange.
	if resp, s := req(t, app, http.MethodPost, "/api/v1/service-accounts/"+saID+"/suspend", admin, ""); resp.StatusCode != http.StatusOK || s["suspended_at"] == nil {
		t.Fatalf("suspend = %d %v", resp.StatusCode, s)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", session, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("federated session after suspension = %d, want 401", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+pid, key, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("key after suspension = %d, want 401", resp.StatusCode)
	}
	if code, _ := exchange(t, app, exchangeForm(idp.token(t, idp.key, nil))); code != http.StatusUnauthorized {
		t.Errorf("exchange while suspended = %d, want 401", code)
	}
	if resp, _ := req(t, app, http.MethodPost, keysPath, admin, `{"name":"again"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("new key while suspended = %d, want 409", resp.StatusCode)
	}
	req(t, app, http.MethodPost, "/api/v1/service-accounts/"+saID+"/resume", admin, "")
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+pid, key, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a key revoked by suspension came back on resume: %d", resp.StatusCode)
	}
	code, out = exchange(t, app, exchangeForm(idp.token(t, idp.key, nil)))
	if fresh, _ := out["access_token"].(string); code != http.StatusOK || fresh == "" {
		t.Fatalf("exchange after resume = %d %v", code, out)
	} else if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", fresh, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("fresh session after resume = %d", resp.StatusCode)
	}

	// A disabled issuer is an unknown one.
	req(t, app, http.MethodPut, "/api/v1/federation/issuers/"+issuerID, admin,
		`{"name":"GitHub Actions","issuer_url":"`+idp.URL+`","audience":"`+federationAudience+`","enabled":false}`)
	if code, _ := exchange(t, app, exchangeForm(idp.token(t, idp.key, nil))); code != http.StatusUnauthorized {
		t.Errorf("exchange with a disabled issuer = %d, want 401", code)
	}
}

func asJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
