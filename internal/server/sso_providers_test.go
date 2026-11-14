package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/xml"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	crewjam "github.com/crewjam/saml"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

const ssoPublicURL = "https://xila.test"

// oidcIdP is an in-process OpenID provider: discovery, JWKS and a token
// endpoint that signs an ID token for whoever the test says logs in next.
type oidcIdP struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu      sync.Mutex
	nonce   string
	subject string
	email   string
	groups  []string
}

var idpKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func newOIDCIdP(t *testing.T) *oidcIdP {
	t.Helper()
	m := &oidcIdP{key: idpKey()}
	mux := http.NewServeMux()
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer": m.URL, "authorization_endpoint": m.URL + "/auth", "token_endpoint": m.URL + "/token",
			"jwks_uri": m.URL + "/jwks", "scopes_supported": []string{"openid", "email", "profile"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &m.key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		clientID, _, ok := r.BasicAuth()
		if !ok {
			clientID = r.FormValue("client_id")
		}
		m.mu.Lock()
		claims := jwt.MapClaims{
			"iss": m.URL, "aud": clientID, "sub": m.subject, "email": m.email, "email_verified": true,
			"nonce": m.nonce, "groups": m.groups, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		}
		m.mu.Unlock()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k"
		signed, err := tok.SignedString(m.key)
		if err != nil {
			t.Errorf("sign: %v", err)
		}
		writeJSON(w, map[string]any{"access_token": "a", "token_type": "Bearer", "id_token": signed})
	})
	return m
}

// next sets who the IdP signs in at the next token request.
func (m *oidcIdP) next(nonce, subject, email string, groups ...string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonce, m.subject, m.email, m.groups = nonce, subject, email, groups
}

// ssoApps hands out app instances sharing one database. The public auth routes
// are rate-limited per instance (10/min), so each login flow gets a fresh one;
// that each has its own provider registry also makes them stand-in replicas.
type ssoApps struct {
	t    *testing.T
	pool *pgxpool.Pool
	opts []func(*config.Config)
}

func (a ssoApps) app() *fiber.App { return newTestAppOn(a.t, a.pool, a.opts...) }

func withSSOPublicURL(c *config.Config) { c.PublicURL = ssoPublicURL }

// startLogin runs GET loginPath and returns the IdP redirect and the cookies set.
func startLogin(t *testing.T, app *fiber.App, loginPath string) (*url.URL, []*http.Cookie) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, loginPath, nil), -1)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s = %v / %d", loginPath, err, resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return loc, resp.Cookies()
}

// callback calls an OIDC callback with the given state and cookies and returns
// where the browser is sent.
func callback(t *testing.T, app *fiber.App, path, state string, cookies []*http.Cookie) string {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path+"?code=c&state="+url.QueryEscape(state), nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	resp, err := app.Test(r, -1)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("GET %s = %v / %d", path, err, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// oidcLogin runs a whole login through a provider on a fresh instance and
// returns where it lands.
func (a ssoApps) oidcLogin(idp *oidcIdP, base, subject, email string, groups ...string) string {
	a.t.Helper()
	app := a.app()
	loc, cookies := startLogin(a.t, app, base+"/login")
	if !strings.HasPrefix(loc.String(), idp.URL+"/auth?") {
		a.t.Fatalf("login at %s redirected to %s, want %s", base, loc, idp.URL)
	}
	idp.next(loc.Query().Get("nonce"), subject, email, groups...)
	return callback(a.t, app, base+"/callback", loc.Query().Get("state"), cookies)
}

func providerBody(slug, name string, idp *oidcIdP, extra string) string {
	return `{"slug":"` + slug + `","kind":"oidc","name":"` + name + `","issuer":"` + idp.URL +
		`","client_id":"` + slug + `-client","client_secret":"` + slug + `-secret","groups_claim":"groups"` + extra + `}`
}

func listProviders(t *testing.T, app *fiber.App, token string) map[string]map[string]any {
	t.Helper()
	resp, body := req(t, app, http.MethodGet, "/api/v1/sso/providers", token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list providers = %d %v", resp.StatusCode, body)
	}
	out := map[string]map[string]any{}
	items, _ := body["providers"].([]any)
	for _, it := range items {
		p := it.(map[string]any)
		out[p["slug"].(string)] = p
	}
	return out
}

func loginURLs(t *testing.T, app *fiber.App) []string {
	t.Helper()
	_, body := req(t, app, http.MethodGet, "/api/v1/auth/config", "", "")
	var urls []string
	items, _ := body["providers"].([]any)
	for _, it := range items {
		urls = append(urls, it.(map[string]any)["login_url"].(string))
	}
	return urls
}

// Admin CRUD: providers are instance-admin only, validated, secrets are sealed
// at rest and never returned, environment providers are read-only.
func TestSSOProvidersAdmin(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	envIdP, idp := newOIDCIdP(t), newOIDCIdP(t)
	apps := ssoApps{t: t, pool: pool, opts: []func(*config.Config){withSSOPublicURL, func(c *config.Config) {
		c.OIDC = config.OIDC{
			Enabled: true, Issuer: envIdP.URL, ClientID: "env-client", ClientSecret: "env-secret",
			RedirectURL: ssoPublicURL + "/api/v1/auth/oidc/callback", ProviderName: "Env SSO", GroupsClaim: "groups",
			Scopes: []string{"openid", "email"},
		}
	}}}
	app := apps.app()
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")

	body := providerBody("corp", "Corp SSO", idp, `,"sort_order":1`)
	for _, r := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/sso/providers", ""},
		{http.MethodPost, "/api/v1/sso/providers", body},
		{http.MethodPost, "/api/v1/sso/providers/test", body},
		{http.MethodGet, "/api/v1/sso/providers/oidc", ""},
		{http.MethodPut, "/api/v1/sso/providers/00000000-0000-0000-0000-000000000000", body},
		{http.MethodDelete, "/api/v1/sso/providers/00000000-0000-0000-0000-000000000000", ""},
		{http.MethodPost, "/api/v1/sso/providers/oidc/test", ""},
	} {
		if resp, _ := req(t, app, r.method, r.path, bob, r.body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("non-admin %s %s = %d, want 403", r.method, r.path, resp.StatusCode)
		}
	}

	// The draft dry run reports what discovery found, or why it failed.
	if resp, res := req(t, app, http.MethodPost, "/api/v1/sso/providers/test", admin, body); resp.StatusCode != http.StatusOK || res["ok"] != true || res["details"] == nil {
		t.Errorf("test draft = %d %v", resp.StatusCode, res)
	}
	wrongIssuer := strings.Replace(body, idp.URL, idp.URL+"/realms/missing", 1)
	if _, res := req(t, app, http.MethodPost, "/api/v1/sso/providers/test", admin, wrongIssuer); res["ok"] != false || res["error"] == "" {
		t.Errorf("test draft with a bad issuer = %v, want ok=false with the error", res)
	}

	resp, created := req(t, app, http.MethodPost, "/api/v1/sso/providers", admin, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %v", resp.StatusCode, created)
	}
	id, _ := created["id"].(string)
	ep, _ := created["endpoints"].(map[string]any)
	if created["source"] != "database" || created["has_client_secret"] != true || created["status"] != "ok" ||
		ep["redirect_uri"] != ssoPublicURL+"/api/v1/auth/oidc/corp/callback" || ep["login_url"] != "/api/v1/auth/oidc/corp/login" {
		t.Errorf("created = %v", created)
	}
	if _, leaked := created["client_secret"]; leaked {
		t.Error("the client secret must never be returned")
	}
	var sealed []byte
	if err := pool.QueryRow(ctx, `SELECT client_secret_enc FROM sso_providers WHERE id = $1`, id).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || strings.Contains(string(sealed), "corp-secret") {
		t.Error("the client secret must be stored sealed")
	}

	for name, bad := range map[string]string{
		"bad slug":       providerBody("Corp_2", "x", idp, ""),
		"reserved slug":  providerBody("callback", "x", idp, ""),
		"no secret":      `{"slug":"nosecret","kind":"oidc","name":"x","issuer":"` + idp.URL + `","client_id":"c"}`,
		"relative issue": `{"slug":"rel","kind":"oidc","name":"x","issuer":"idp","client_id":"c","client_secret":"s"}`,
		"unknown kind":   `{"slug":"ldap","kind":"ldap","name":"x"}`,
	} {
		if resp, b := req(t, app, http.MethodPost, "/api/v1/sso/providers", admin, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %v, want 400", name, resp.StatusCode, b)
		}
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/sso/providers", admin, body); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate slug = %d, want 409", resp.StatusCode)
	}

	// Update without the secret keeps it; slug cannot change.
	update := `{"name":"Corp","issuer":"` + idp.URL + `","client_id":"corp-client","sort_order":1}`
	if resp, u := req(t, app, http.MethodPut, "/api/v1/sso/providers/"+id, admin, update); resp.StatusCode != http.StatusOK || u["name"] != "Corp" || u["has_client_secret"] != true {
		t.Errorf("update = %d %v", resp.StatusCode, u)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/sso/providers/"+id, admin, `{"slug":"renamed","name":"x","issuer":"`+idp.URL+`","client_id":"c"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("slug change = %d, want 400", resp.StatusCode)
	}
	if resp, res := req(t, app, http.MethodPost, "/api/v1/sso/providers/"+id+"/test", admin, ""); resp.StatusCode != http.StatusOK || res["ok"] != true {
		t.Errorf("test saved = %d %v", resp.StatusCode, res)
	}

	// The environment provider: listed, read-only, at its original URLs.
	all := listProviders(t, app, admin)
	env := all["oidc"]
	if env == nil || env["source"] != "environment" || env["status"] != "ok" || all["corp"] == nil {
		t.Fatalf("providers = %v", all)
	}
	if ep := env["endpoints"].(map[string]any); ep["login_url"] != "/api/v1/auth/oidc/login" || ep["redirect_uri"] != ssoPublicURL+"/api/v1/auth/oidc/callback" {
		t.Errorf("env endpoints = %v", ep)
	}
	for _, r := range []struct{ method, body string }{{http.MethodPut, update}, {http.MethodDelete, ""}} {
		if resp, b := req(t, app, r.method, "/api/v1/sso/providers/oidc", admin, r.body); resp.StatusCode != http.StatusConflict || !strings.Contains(b["error"].(string), "environment") {
			t.Errorf("%s env provider = %d %v, want 409 explaining it is read-only", r.method, resp.StatusCode, b)
		}
	}
	if resp, res := req(t, app, http.MethodPost, "/api/v1/sso/providers/oidc/test", admin, ""); resp.StatusCode != http.StatusOK || res["ok"] != true {
		t.Errorf("test env provider = %d %v", resp.StatusCode, res)
	}

	// The login page: both, by sort order (env 0, corp 1).
	if urls := loginURLs(t, apps.app()); len(urls) != 2 || urls[0] != "/api/v1/auth/oidc/login" || urls[1] != "/api/v1/auth/oidc/corp/login" {
		t.Errorf("login buttons = %v", urls)
	}

	// The environment provider keeps working at its original routes.
	if loc := apps.oidcLogin(envIdP, "/api/v1/auth/oidc", "env-sub", "erin@xila.io"); !strings.HasPrefix(loc, "/#sso_token=") {
		t.Errorf("env provider login → %q", loc)
	}
	if loc := apps.oidcLogin(idp, "/api/v1/auth/oidc/corp", "corp-sub", "carl@xila.io"); !strings.HasPrefix(loc, "/#sso_token=") {
		t.Errorf("corp login → %q", loc)
	}
	if n := listProviders(t, app, admin)["corp"]["linked_identities"]; n != float64(1) {
		t.Errorf("corp linked identities = %v, want 1", n)
	}

	// Delete: its routes 404, the user keeps the account and the identity.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/sso/providers/"+id, admin, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
	if resp, _ := apps.app().Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/corp/login", nil), -1); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleted provider login = %d, want 404", resp.StatusCode)
	}
	var identities int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM user_identities i JOIN users u ON u.id = i.user_id
		WHERE u.email = 'carl@xila.io' AND i.issuer = $1 AND i.provider_id IS NULL`, idp.URL).Scan(&identities); err != nil || identities != 1 {
		t.Errorf("carl's identity after the provider was deleted = %d (%v), want kept", identities, err)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/sso/providers/"+id, admin, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("get deleted = %d, want 404", resp.StatusCode)
	}
}

// Two OIDC providers at different IdPs both sign people in; a login started at
// one cannot be completed at the other; a mapping scoped to one provider only
// applies to logins through it; disabling and editing a provider apply on every
// replica without a restart.
func TestSSOMultipleOIDCProviders(t *testing.T) {
	pool := pgtest.Pool(t)
	alphaIdP, betaIdP, gammaIdP := newOIDCIdP(t), newOIDCIdP(t), newOIDCIdP(t)
	apps := ssoApps{t: t, pool: pool, opts: []func(*config.Config){withSSOPublicURL}}
	app := apps.app()
	admin := rbacUser(t, app, "admin@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", admin, `{"slug":"platform","name":"Platform"}`)
	teamID, _ := teamBody["id"].(string)

	ids := map[string]string{}
	for slug, idp := range map[string]*oidcIdP{"alpha": alphaIdP, "beta": betaIdP} {
		resp, p := req(t, app, http.MethodPost, "/api/v1/sso/providers", admin, providerBody(slug, strings.ToUpper(slug), idp, ""))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s = %d %v", slug, resp.StatusCode, p)
		}
		ids[slug] = p["id"].(string)
	}
	resp, m := req(t, app, http.MethodPost, "/api/v1/sso/group-mappings", admin,
		`{"provider_id":"`+ids["alpha"]+`","group":"devs","target_kind":"team","target_id":"`+teamID+`","role":"editor"}`)
	if resp.StatusCode != http.StatusCreated || m["provider"] != "oidc" || m["provider_id"] != ids["alpha"] || m["provider_name"] != "ALPHA" {
		t.Fatalf("scoped mapping = %d %v", resp.StatusCode, m)
	}

	// Both log in; the alpha-scoped mapping applies to the alpha login only.
	if loc := apps.oidcLogin(alphaIdP, "/api/v1/auth/oidc/alpha", "a-1", "dave@xila.io", "devs"); !strings.HasPrefix(loc, "/#sso_token=") {
		t.Fatalf("alpha login → %q", loc)
	}
	if loc := apps.oidcLogin(betaIdP, "/api/v1/auth/oidc/beta", "b-1", "carol@xila.io", "devs"); !strings.HasPrefix(loc, "/#sso_token=") {
		t.Fatalf("beta login → %q", loc)
	}
	roleOf := func(email string) string {
		var role string
		_ = pool.QueryRow(context.Background(), `SELECT tm.role FROM team_members tm JOIN users u ON u.id = tm.user_id
			WHERE u.email = $1 AND tm.team_id = $2`, email, teamID).Scan(&role)
		return role
	}
	if roleOf("dave@xila.io") != "editor" || roleOf("carol@xila.io") != "" {
		t.Errorf("roles: dave (alpha) = %q, carol (beta) = %q; want editor and none", roleOf("dave@xila.io"), roleOf("carol@xila.io"))
	}

	// A login started at alpha, completed at beta's callback (state and every
	// cookie of alpha's flow presented): refused — beta reads only its own.
	flow := apps.app()
	loc, cookies := startLogin(t, flow, "/api/v1/auth/oidc/alpha/login")
	betaIdP.next(loc.Query().Get("nonce"), "b-2", "mallory@xila.io")
	if got := callback(t, flow, "/api/v1/auth/oidc/beta/callback", loc.Query().Get("state"), cookies); got != "/login?error=sso_failed" {
		t.Errorf("alpha's flow at beta's callback → %q, want refused", got)
	}
	for _, c := range cookies {
		if !strings.HasPrefix(c.Name, "oidc_alpha_") || c.Path != "/api/v1/auth/oidc/alpha" {
			t.Errorf("alpha cookie %s (path %s) is not scoped to alpha", c.Name, c.Path)
		}
	}

	// A second replica that already built alpha's client.
	replica := apps.app()
	if loc, _ := startLogin(t, replica, "/api/v1/auth/oidc/alpha/login"); !strings.HasPrefix(loc.String(), alphaIdP.URL) {
		t.Fatalf("replica alpha → %s", loc)
	}
	// Repoint alpha at another IdP: the replica follows on its next request.
	if resp, b := req(t, app, http.MethodPut, "/api/v1/sso/providers/"+ids["alpha"], admin,
		`{"name":"ALPHA","issuer":"`+gammaIdP.URL+`","client_id":"alpha-client","groups_claim":"groups"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("update alpha = %d %v", resp.StatusCode, b)
	}
	if loc, _ := startLogin(t, replica, "/api/v1/auth/oidc/alpha/login"); !strings.HasPrefix(loc.String(), gammaIdP.URL) {
		t.Errorf("replica after update → %s, want the new issuer", loc)
	}
	// Disable beta: its routes 404 and its button goes, on the replica too.
	if resp, b := req(t, app, http.MethodPut, "/api/v1/sso/providers/"+ids["beta"], admin,
		`{"name":"BETA","issuer":"`+betaIdP.URL+`","client_id":"beta-client","enabled":false}`); resp.StatusCode != http.StatusOK || b["status"] != "disabled" {
		t.Fatalf("disable beta = %d %v", resp.StatusCode, b)
	}
	for _, path := range []string{"/api/v1/auth/oidc/beta/login", "/api/v1/auth/oidc/beta/callback"} {
		if resp, _ := replica.Test(httptest.NewRequest(http.MethodGet, path, nil), -1); resp.StatusCode != http.StatusNotFound {
			t.Errorf("disabled %s on the replica = %d, want 404", path, resp.StatusCode)
		}
	}
	if urls := loginURLs(t, replica); len(urls) != 1 || urls[0] != "/api/v1/auth/oidc/alpha/login" {
		t.Errorf("login buttons after disabling beta = %v", urls)
	}

	// Deleting alpha deletes the mapping scoped to it.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/sso/providers/"+ids["alpha"], admin, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete alpha = %d", resp.StatusCode)
	}
	if _, list := req(t, app, http.MethodGet, "/api/v1/sso/group-mappings", admin, ""); len(list["mappings"].([]any)) != 0 {
		t.Errorf("mappings after deleting their provider = %v", list["mappings"])
	}
}

// A SAML provider added at runtime is its own service provider, at its slug.
func TestSSOSAMLProviderAtRuntime(t *testing.T) {
	pool := pgtest.Pool(t)
	apps := ssoApps{t: t, pool: pool, opts: []func(*config.Config){withSSOPublicURL}}
	app := apps.app()
	admin := rbacUser(t, app, "admin@xila.io")

	md, err := json.Marshal(samlIdPMetadata(t))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"slug":"entra","kind":"saml","name":"Entra","idp_metadata":` + string(md) + `,"groups_attributes":["groups"]}`
	if _, res := req(t, app, http.MethodPost, "/api/v1/sso/providers/test", admin, body); res["ok"] != true || len(res["certificates"].([]any)) != 1 {
		t.Errorf("SAML draft test = %v, want ok with the IdP signing certificate", res)
	}
	resp, p := req(t, app, http.MethodPost, "/api/v1/sso/providers", admin, body)
	if resp.StatusCode != http.StatusCreated || p["status"] != "ok" {
		t.Fatalf("create SAML provider = %d %v", resp.StatusCode, p)
	}
	ep := p["endpoints"].(map[string]any)
	base := ssoPublicURL + "/api/v1/auth/saml/entra"
	if ep["acs_url"] != base+"/acs" || ep["sp_metadata_url"] != base+"/metadata" || ep["sp_entity_id"] != base+"/metadata" {
		t.Errorf("SAML endpoints = %v", ep)
	}

	r, err := apps.app().Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/entra/metadata", nil), -1)
	if err != nil || r.StatusCode != http.StatusOK {
		t.Fatalf("SP metadata = %v / %d", err, r.StatusCode)
	}
	raw, _ := io.ReadAll(r.Body)
	var sp crewjam.EntityDescriptor
	if err := xml.Unmarshal(raw, &sp); err != nil || sp.EntityID != base+"/metadata" ||
		sp.SPSSODescriptors[0].AssertionConsumerServices[0].Location != base+"/acs" {
		t.Errorf("SP metadata = %s (%v)", raw, err)
	}
	if r, _ := apps.app().Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/entra/login", nil), -1); r.StatusCode != http.StatusFound ||
		!strings.HasPrefix(r.Header.Get("Location"), "https://idp.test/sso?") {
		t.Errorf("SAML login = %d → %s", r.StatusCode, r.Header.Get("Location"))
	}
	// No SAML_* configured: the original routes 404.
	if r, _ := apps.app().Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/metadata", nil), -1); r.StatusCode != http.StatusNotFound {
		t.Errorf("env SAML metadata without SAML_ENABLED = %d, want 404", r.StatusCode)
	}
}

func samlIdPMetadata(t *testing.T) string {
	t.Helper()
	key := idpKey()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ssoURL, _ := url.Parse("https://idp.test/sso")
	metaURL, _ := url.Parse("https://idp.test/metadata")
	idp := crewjam.IdentityProvider{Certificate: cert, Key: key, SSOURL: *ssoURL, MetadataURL: *metaURL}
	out, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
