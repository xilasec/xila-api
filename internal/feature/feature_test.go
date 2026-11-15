package feature_test

import (
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/feature"
)

// The gate must match a path exactly when Fiber would route it to the
// feature: Fiber is case-insensitive and ignores a trailing slash, so a
// pattern that isn't would let "/API/V1/CRA/cases" through.
func TestFeatureFor(t *testing.T) {
	s := feature.NewStore(nil)
	for path, want := range map[string]string{
		"/api/v1/cra/cases":                                   feature.CRA,
		"/API/V1/CRA/Cases/":                                  feature.CRA,
		"/api/v1/projects/p1/cra":                             feature.CRA,
		"/api/v1/projects/p1/cra/cases":                       feature.CRA,
		"/api/v1/crash":                                       "",
		"/api/v1/projects/p1/crawl":                           "",
		"/api/v1/me/mfa/setup":                                feature.MFA,
		"/api/v1/auth/mfa":                                    feature.MFA,
		"/api/v1/users/u1/mfa":                                feature.MFA,
		"/api/v1/users/u1":                                    "",
		"/api/v1/me":                                          "",
		"/.well-known/csaf/provider-metadata.json":            feature.PSIRT,
		"/csaf/advisories/2026/x.json":                        feature.PSIRT,
		"/api/v1/psirt/advisories":                            feature.PSIRT,
		"/api/v1/mcp":                                         feature.MCP,
		"/api/v1/mcp/":                                        feature.MCP,
		"/api/v1/badges/tok/findings.svg":                     feature.Badges,
		"/api/v1/projects/p1/badge-token":                     feature.Badges,
		"/api/v1/custom-fields":                               feature.CustomFields,
		"/api/v1/findings/f1/custom":                          feature.CustomFields,
		"/api/v1/findings/f1":                                 "",
		"/api/v1/findings/f1/ai-proposals/prompt":             feature.AITriage,
		"/api/v1/me/notifications/deliveries":                 feature.PersonalNotifications,
		"/api/v1/projects/p1/watch":                           feature.PersonalNotifications,
		"/api/v1/notifications/channels":                      "",
		"/api/v1/remediation/sweep":                           feature.Remediation,
		"/api/v1/projects/p1/remediation":                     feature.Remediation,
		"/api/v1/root-causes":                                 feature.Remediation,
		"/api/v1/root-causes/package_upgrade/abc/remediation": feature.Remediation,
		"/api/v1/engagements/e1/restore":                      feature.Engagements,
		"/api/v1/projects/p1/engagements":                     feature.Engagements,
		"/api/v1/projects/p1/findings":                        "",
		"/cra":                                                "", // the UI page, not an API route
	} {
		if got := s.FeatureFor(path); got != want {
			t.Errorf("FeatureFor(%q) = %q, want %q", path, got, want)
		}
	}
}

// Features the server isn't configured for read as unavailable.
func TestUnavailable(t *testing.T) {
	if got := feature.Unavailable(config.Config{}); !slices.Equal(got, []string{feature.MCP, feature.AITriage, feature.MFA}) {
		t.Errorf("unconfigured = %v", got)
	}
	cfg := config.Config{MCPEnabled: true, IntegrationSecretKey: "k"}
	cfg.AI.Enabled = true
	if got := feature.Unavailable(cfg); len(got) != 0 {
		t.Errorf("configured = %v", got)
	}
}
