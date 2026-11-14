// Package oidc implements Single Sign-On via OpenID Connect. It only verifies
// the ID token (signature, issuer, audience, expiry, nonce — after an
// authorization-code exchange protected by PKCE) and turns it into an
// sso.Assertion; which providers exist, linking, group sync and the session
// are internal/sso's job.
package oidc

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/sso"
)

// Protocol builds OIDC clients for the provider registry (sso.Protocol).
type Protocol struct {
	// HTTPClient reaches the IdP (discovery, JWKS, token endpoint); nil = the
	// default client. Tests point it at an in-process IdP.
	HTTPClient *http.Client
}

// Build runs discovery against the provider's issuer (which must match the
// discovery document's) and returns its Client.
func (pr Protocol) Build(ctx context.Context, p sso.Provider) (sso.Client, error) {
	return newClient(ctx, p, pr.HTTPClient)
}

// Client is one configured OIDC provider: the OAuth2 client + an ID-token
// verifier.
type Client struct {
	oauth      oauth2.Config
	verifier   *oidc.IDTokenVerifier
	provider   sso.Provider
	discovery  discovery
	httpClient *http.Client // nil = default
}

// discovery is the part of the IdP's discovery document the admin page shows.
type discovery struct {
	Issuer          string   `json:"issuer"`
	AuthURL         string   `json:"authorization_endpoint"`
	TokenURL        string   `json:"token_endpoint"`
	JWKSURL         string   `json:"jwks_uri"`
	UserInfoURL     string   `json:"userinfo_endpoint"`
	ScopesSupported []string `json:"scopes_supported"`
	ClaimsSupported []string `json:"claims_supported"`
}

func newClient(ctx context.Context, p sso.Provider, httpClient *http.Client) (*Client, error) {
	if p.Issuer == "" || p.ClientID == "" || p.Endpoints.RedirectURI == "" {
		return nil, fmt.Errorf("oidc: issuer, client id and redirect url are required")
	}
	if httpClient == nil {
		// Discovery, JWKS and token calls go to an admin-entered issuer.
		httpClient = netguard.NewClient(30 * time.Second)
	}
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var disc discovery
	if err := provider.Claims(&disc); err != nil {
		return nil, fmt.Errorf("oidc discovery document: %w", err)
	}
	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &Client{
		oauth: oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			RedirectURL:  p.Endpoints.RedirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier:   provider.Verifier(&oidc.Config{ClientID: p.ClientID}),
		provider:   p,
		discovery:  disc,
		httpClient: httpClient,
	}, nil
}

// Report describes what discovery found, for the admin page's dry run.
func (c *Client) Report() sso.Report {
	d := c.discovery
	r := sso.Report{Details: []sso.Setting{
		{Label: "Issuer", Value: d.Issuer},
		{Label: "Authorization endpoint", Value: d.AuthURL},
		{Label: "Token endpoint", Value: d.TokenURL},
		{Label: "JWKS URI", Value: d.JWKSURL},
		{Label: "Userinfo endpoint", Value: d.UserInfoURL},
		{Label: "Scopes supported", Value: strings.Join(d.ScopesSupported, " ")},
		{Label: "Claims supported", Value: strings.Join(d.ClaimsSupported, " ")},
		{Label: "Scopes requested", Value: strings.Join(c.oauth.Scopes, " ")},
	}}
	if len(d.ScopesSupported) > 0 {
		for _, s := range c.oauth.Scopes {
			if !slices.Contains(d.ScopesSupported, s) {
				r.Warnings = append(r.Warnings, fmt.Sprintf("scope %q is not in the IdP's scopes_supported — it may be rejected", s))
			}
		}
	}
	if claim := c.provider.GroupsClaim; claim != "" && len(d.ClaimsSupported) > 0 {
		top, _, _ := strings.Cut(claim, ".")
		if !slices.Contains(d.ClaimsSupported, claim) && !slices.Contains(d.ClaimsSupported, top) {
			r.Warnings = append(r.Warnings, fmt.Sprintf("groups claim %q is not in the IdP's claims_supported — check the ID token actually carries it, or group mappings will grant nothing", claim))
		}
	}
	return r
}

// clientContext injects the configured HTTP client (if any) so exchange +
// verification use it; otherwise the default client is used.
func (c *Client) clientContext(ctx context.Context) context.Context {
	if c.httpClient != nil {
		ctx = oidc.ClientContext(ctx, c.httpClient)
		ctx = context.WithValue(ctx, oauth2.HTTPClient, c.httpClient)
	}
	return ctx
}

// authCodeURL builds the provider redirect for the given CSRF state, nonce and
// PKCE verifier (sent as its S256 challenge).
func (c *Client) authCodeURL(state, nonce, pkceVerifier string) string {
	return c.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkceVerifier))
}

// exchange trades an authorization code (plus its PKCE verifier) for a verified
// ID token, checks the nonce, and returns the assertion it makes.
func (c *Client) exchange(ctx context.Context, code, nonce, pkceVerifier string) (sso.Assertion, error) {
	ctx = c.clientContext(ctx)
	tok, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return sso.Assertion{}, fmt.Errorf("code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return sso.Assertion{}, fmt.Errorf("no id_token in token response")
	}
	idToken, err := c.verifier.Verify(ctx, rawID)
	if err != nil {
		return sso.Assertion{}, fmt.Errorf("verify id token: %w", err)
	}
	if nonce == "" || idToken.Nonce != nonce {
		return sso.Assertion{}, fmt.Errorf("nonce mismatch")
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return sso.Assertion{}, fmt.Errorf("parse claims: %w", err)
	}
	email, _ := claims["email"].(string)
	return sso.Assertion{
		Issuer:     idToken.Issuer,
		Subject:    idToken.Subject,
		Email:      email,
		EmailTrust: c.emailTrust(claims["email_verified"]),
		Groups:     groupsClaim(claims, c.provider.GroupsClaim),
	}, nil
}

// emailTrust reads email_verified: a boolean, or the string "true"/"false"
// some IdPs (Cognito) send. Absent → the provider's trust_unverified_email
// (OIDC_TRUST_UNVERIFIED_EMAIL) decides.
func (c *Client) emailTrust(v any) sso.EmailTrust {
	var verified bool
	switch x := v.(type) {
	case bool:
		verified = x
	case string:
		b, err := strconv.ParseBool(x)
		if err != nil {
			return sso.EmailUnverified
		}
		verified = b
	case nil:
		if c.provider.TrustUnverifiedEmail {
			return sso.EmailVerified
		}
		return sso.EmailUnknown
	default:
		return sso.EmailUnverified
	}
	if verified {
		return sso.EmailVerified
	}
	return sso.EmailUnverified
}

// groupsClaim reads the groups claim: a claim named exactly path (Auth0-style
// namespaced claims such as "https://example.com/groups" contain dots), else a
// dotted path into nested claims ("realm_access.roles"). The value is a string
// array or one string; anything else — or a missing claim — is no groups.
func groupsClaim(claims map[string]any, path string) []string {
	if path == "" {
		return nil
	}
	cur, ok := claims[path]
	if !ok {
		cur = claims
		for part := range strings.SplitSeq(path, ".") {
			m, isMap := cur.(map[string]any)
			if !isMap {
				return nil
			}
			if cur, ok = m[part]; !ok {
				return nil
			}
		}
	}
	switch v := cur.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		groups := make([]string, 0, len(v))
		for _, g := range v {
			if s, ok := g.(string); ok && s != "" {
				groups = append(groups, s)
			}
		}
		return groups
	}
	return nil
}
