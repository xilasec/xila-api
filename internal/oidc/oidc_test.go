package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/xilasec/xila-api/internal/sso"
)

const testClientID = "test-client"

// mockIdP is a minimal OIDC provider: discovery + JWKS + token endpoints. The
// token endpoint enforces PKCE against the challenge the test hands it, and
// returns an ID token signed with priv carrying nonce + extra claims.
type mockIdP struct {
	*httptest.Server
	mu        sync.Mutex
	nonce     string
	challenge string         // expected S256 code_challenge ("" = don't check)
	claims    map[string]any // merged into the ID token
}

func newMockIdP(t *testing.T, priv *rsa.PrivateKey) *mockIdP {
	t.Helper()
	m := &mockIdP{}
	mux := http.NewServeMux()
	m.Server = httptest.NewServer(mux)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 m.URL,
			"authorization_endpoint": m.URL + "/auth",
			"token_endpoint":         m.URL + "/token",
			"jwks_uri":               m.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &priv.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.challenge != "" && oauth2.S256ChallengeFromVerifier(r.FormValue("code_verifier")) != m.challenge {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
		claims := jwt.MapClaims{
			"iss": m.URL, "aud": testClientID, "sub": "provider-subject-1",
			"email": "Sso.User@Example.io", "email_verified": true, "nonce": m.nonce,
			"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
		}
		for k, v := range m.claims {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "test-key"
		idToken, err := tok.SignedString(priv)
		if err != nil {
			t.Errorf("sign id token: %v", err)
		}
		writeJSON(w, map[string]any{"access_token": "access-xyz", "token_type": "Bearer", "id_token": idToken})
	})
	t.Cleanup(m.Close)
	return m
}

// set changes what the token endpoint does, safely against its handler goroutine.
func (m *mockIdP) set(nonce, challenge string, claims map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonce, m.challenge, m.claims = nonce, challenge, claims
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// fakeLogins records the assertion handed to the shared SSO layer.
type fakeLogins struct {
	got      *sso.Assertion
	provider sso.Provider
}

func (f *fakeLogins) Complete(_ context.Context, p sso.Provider, a sso.Assertion) string {
	f.got, f.provider = &a, p
	return "/#sso_token=MINTED"
}

// resolver serves fixed providers by slug, like sso.Registry would.
type resolver map[string]sso.Resolved

func (r resolver) Resolve(_ context.Context, kind, slug string) (sso.Resolved, error) {
	res, ok := r[slug]
	if !ok || res.Provider.Kind != kind || !res.Provider.Enabled {
		return sso.Resolved{}, sso.ErrProviderNotFound
	}
	return res, nil
}

// envProvider is the provider OIDC_* configures, served at the original routes.
func envProvider(p sso.Provider) sso.Provider {
	p.ID, p.Slug, p.Kind, p.Source, p.Enabled = sso.ProviderOIDC, sso.ProviderOIDC, sso.ProviderOIDC, sso.SourceEnvironment, true
	p.ClientID, p.ClientSecret = testClientID, "secret"
	p.Endpoints.LoginURL = "/api/v1/auth/oidc/login"
	p.Endpoints.RedirectURI = "http://app.local/api/v1/auth/oidc/callback"
	return p
}

func setup(t *testing.T, p sso.Provider) (*mockIdP, *fakeLogins, *fiber.App) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	idp := newMockIdP(t, priv)
	p = envProvider(p)
	p.Issuer = idp.URL
	client, err := Protocol{HTTPClient: idp.Client()}.Build(context.Background(), p)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	logins := &fakeLogins{}
	app := fiber.New()
	NewHandler(resolver{p.Slug: {Provider: p, Client: client}}, logins, false).Register(app.Group("/api/v1/auth"))
	return idp, logins, app
}

// loginRoundTrip runs GET /oidc/login, lets the mock IdP see the PKCE challenge
// and nonce the browser would carry, then calls back with the login's cookies.
func loginRoundTrip(t *testing.T, idp *mockIdP, app *fiber.App) (authURL *url.URL, callback *http.Response) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil), -1)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %v / %d", err, resp.StatusCode)
	}
	authURL, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("auth url: %v", err)
	}
	q := authURL.Query()
	idp.mu.Lock()
	idp.nonce, idp.challenge = q.Get("nonce"), q.Get("code_challenge")
	idp.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=abc&state="+url.QueryEscape(q.Get("state")), nil)
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	callback, err = app.Test(req, -1)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return authURL, callback
}

func TestOIDCLoginFlowWithPKCEAndGroups(t *testing.T) {
	idp, logins, app := setup(t, sso.Provider{
		Name: "Test SSO", GroupsClaim: "realm_access.roles",
		Scopes: []string{"openid", "email", "profile", "groups"},
	})
	idp.set("", "", map[string]any{"realm_access": map[string]any{"roles": []string{"xila-admins", "team-a"}}})

	authURL, resp := loginRoundTrip(t, idp, app)
	q := authURL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("authorization request lacks an S256 PKCE challenge: %s", authURL.RawQuery)
	}
	if q.Get("scope") != "openid email profile groups" {
		t.Errorf("scope = %q, want the configured scopes", q.Get("scope"))
	}
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/#sso_token=MINTED" {
		t.Fatalf("callback = %d → %q, want the completed login", resp.StatusCode, resp.Header.Get("Location"))
	}
	a := logins.got
	if a == nil {
		t.Fatal("no assertion reached the SSO layer")
	}
	if logins.provider.Slug != sso.ProviderOIDC || a.Issuer != idp.URL || a.Subject != "provider-subject-1" ||
		a.Email != "Sso.User@Example.io" || a.EmailTrust != sso.EmailVerified {
		t.Errorf("assertion = %+v", *a)
	}
	if !slices.Equal(a.Groups, []string{"xila-admins", "team-a"}) {
		t.Errorf("groups = %v, want the nested realm roles", a.Groups)
	}
}

func TestOIDCRejectsWrongPKCEVerifier(t *testing.T) {
	idp, logins, app := setup(t, sso.Provider{})
	idp.set("n", oauth2.S256ChallengeFromVerifier("some-other-verifier"), nil)
	names := cookieNames(envProvider(sso.Provider{}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=abc&state=s", nil)
	req.AddCookie(&http.Cookie{Name: names.state, Value: "s"})
	req.AddCookie(&http.Cookie{Name: names.nonce, Value: "n"})
	req.AddCookie(&http.Cookie{Name: names.pkce, Value: oauth2.GenerateVerifier()})
	resp, _ := app.Test(req, -1)
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?error=") || logins.got != nil {
		t.Errorf("redirect = %q (assertion %v), want a refused login", loc, logins.got)
	}
}

func TestOIDCCallbackRejectsBadState(t *testing.T) {
	_, logins, app := setup(t, sso.Provider{})
	// state query doesn't match the cookie -> back to the login page, no session.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/callback?code=abc&state=attacker", nil)
	req.AddCookie(&http.Cookie{Name: cookieNames(envProvider(sso.Provider{})).state, Value: "real"})
	resp, _ := app.Test(req, -1)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login?error=sso_failed" {
		t.Errorf("state mismatch → %d %q, want 302 to /login?error=sso_failed", resp.StatusCode, resp.Header.Get("Location"))
	}
	if logins.got != nil {
		t.Error("a state mismatch must not reach the SSO layer")
	}
}

// email_verified decides how far the email is trusted for linking.
func TestOIDCEmailTrust(t *testing.T) {
	cases := []struct {
		name  string
		claim any // nil = absent
		trust bool
		want  sso.EmailTrust
	}{
		{"verified", true, false, sso.EmailVerified},
		{"verified as string", "true", false, sso.EmailVerified},
		{"explicitly unverified", false, true, sso.EmailUnverified},
		{"absent, untrusted (default)", nil, false, sso.EmailUnknown},
		{"absent, OIDC_TRUST_UNVERIFIED_EMAIL", nil, true, sso.EmailVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp, logins, app := setup(t, sso.Provider{TrustUnverifiedEmail: tc.trust})
			idp.set("", "", map[string]any{"email_verified": tc.claim})
			if _, resp := loginRoundTrip(t, idp, app); resp.Header.Get("Location") != "/#sso_token=MINTED" {
				t.Fatalf("login refused: %q", resp.Header.Get("Location"))
			}
			if logins.got.EmailTrust != tc.want {
				t.Errorf("trust = %v, want %v", logins.got.EmailTrust, tc.want)
			}
		})
	}
}

func TestGroupsClaim(t *testing.T) {
	claims := map[string]any{
		"groups":                     []any{"a", "b", 7, ""},
		"role":                       "solo",
		"realm_access":               map[string]any{"roles": []any{"r1"}},
		"https://example.com/groups": []any{"namespaced"},
	}
	for path, want := range map[string][]string{
		"groups":                     {"a", "b"},
		"role":                       {"solo"},
		"realm_access.roles":         {"r1"},
		"https://example.com/groups": {"namespaced"},
		"missing":                    nil,
		"realm_access.missing":       nil,
		"":                           nil,
	} {
		if got := groupsClaim(claims, path); !slices.Equal(got, want) {
			t.Errorf("groupsClaim(%q) = %v, want %v", path, got, want)
		}
	}
}

// An admin-managed provider is served under its slug, with its cookies scoped
// to its own path and named after it; unknown, disabled and reserved slugs 404.
func TestOIDCSluggedProviderRoutes(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := newMockIdP(t, priv)
	p := sso.Provider{
		ID: "7d3c1d4e-0000-4000-8000-000000000001", Slug: "corp", Kind: sso.ProviderOIDC, Source: sso.SourceDatabase,
		Enabled: true, Issuer: idp.URL, ClientID: testClientID, ClientSecret: "secret",
		Endpoints: sso.Endpoints{RedirectURI: "http://app.local/api/v1/auth/oidc/corp/callback"},
	}
	client, err := Protocol{HTTPClient: idp.Client()}.Build(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	off := p
	off.Slug, off.Enabled = "off", false
	app := fiber.New()
	NewHandler(resolver{"corp": {Provider: p, Client: client}, "off": {Provider: off, Client: client}}, &fakeLogins{}, true).
		Register(app.Group("/api/v1/auth"))

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/corp/login", nil), -1)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login = %v / %d", err, resp.StatusCode)
	}
	if loc, _ := url.Parse(resp.Header.Get("Location")); loc.Query().Get("redirect_uri") != p.Endpoints.RedirectURI {
		t.Errorf("redirect_uri = %q, want the provider's own callback", loc.Query().Get("redirect_uri"))
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c
	}
	for _, name := range []string{"oidc_corp_state", "oidc_corp_nonce", "oidc_corp_pkce"} {
		if c := cookies[name]; c == nil || c.Path != "/api/v1/auth/oidc/corp" || !c.HttpOnly || !c.Secure {
			t.Errorf("cookie %s = %+v, want HttpOnly+Secure, path /api/v1/auth/oidc/corp", name, c)
		}
	}
	if len(cookies) != 3 {
		t.Errorf("cookies = %v, want only the provider's three", cookies)
	}
	for _, path := range []string{"/api/v1/auth/oidc/nope/login", "/api/v1/auth/oidc/off/login", "/api/v1/auth/oidc/off/callback", "/api/v1/auth/oidc/oidc/login"} {
		if resp, _ := app.Test(httptest.NewRequest(http.MethodGet, path, nil), -1); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
	// No environment provider configured: the original routes 404 too.
	if resp, _ := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/oidc/login", nil), -1); resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET /oidc/login without OIDC_ENABLED = %d, want 404", resp.StatusCode)
	}
}
