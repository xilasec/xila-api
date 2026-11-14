package audit

import (
	"strings"
	"testing"
)

func TestAuthAction(t *testing.T) {
	cases := []struct {
		method, path, action, provider string
	}{
		{"POST", "login", "auth.login", ""},
		{"GET", "oidc/callback", "auth.sso_login", "oidc"},
		{"POST", "saml/corp/acs", "auth.sso_login", "corp"},
		// SAML Single Logout, both bindings, env and database providers.
		{"GET", "saml/slo", "auth.sso_logout", "saml"},
		{"POST", "saml/slo", "auth.sso_logout", "saml"},
		{"GET", "saml/corp/slo", "auth.sso_logout", "corp"},
		// Not recorded: redirects out and metadata.
		{"GET", "saml/login", "", ""},
		{"GET", "saml/corp/metadata", "", ""},
		{"GET", "config", "", ""},
	}
	for _, c := range cases {
		action, provider := authAction(c.method, strings.Split(c.path, "/"))
		if action != c.action || provider != c.provider {
			t.Errorf("%s %s = (%q, %q), want (%q, %q)", c.method, c.path, action, provider, c.action, c.provider)
		}
	}
}
