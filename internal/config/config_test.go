package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadPoolAndHTTPDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DB.MaxConns != 20 || cfg.DB.MinConns != 2 {
		t.Errorf("pool = %d/%d, want 20/2", cfg.DB.MaxConns, cfg.DB.MinConns)
	}
	if cfg.DB.ConnectTimeout != 10*time.Second {
		t.Errorf("connect timeout = %v, want 10s", cfg.DB.ConnectTimeout)
	}
	if cfg.HTTP.BodyLimit != 32*1024*1024 || cfg.HTTP.ReadTimeout != 15*time.Second {
		t.Errorf("http = %d bytes / %v read, want 32MiB / 15s", cfg.HTTP.BodyLimit, cfg.HTTP.ReadTimeout)
	}
	// connect_timeout is libpq-standard and belongs in the DSN; pool_* must not.
	dsn := cfg.DB.DSN()
	if !strings.Contains(dsn, "connect_timeout=10") {
		t.Errorf("DSN %q missing connect_timeout", dsn)
	}
	if strings.Contains(dsn, "pool_") {
		t.Errorf("DSN %q must not carry pool_* params (breaks the migration driver)", dsn)
	}
}

func TestLoadPoolAndHTTPOverrides(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("DB_MAX_CONNS", "50")
	t.Setenv("DB_CONNECT_TIMEOUT", "3s")
	t.Setenv("HTTP_BODY_LIMIT_MB", "64")
	t.Setenv("HTTP_READ_TIMEOUT", "5s")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DB.MaxConns != 50 {
		t.Errorf("MaxConns = %d, want 50", cfg.DB.MaxConns)
	}
	if cfg.HTTP.BodyLimit != 64*1024*1024 || cfg.HTTP.ReadTimeout != 5*time.Second {
		t.Errorf("http overrides not applied: %d / %v", cfg.HTTP.BodyLimit, cfg.HTTP.ReadTimeout)
	}
	if !strings.Contains(cfg.DB.DSN(), "connect_timeout=3") {
		t.Errorf("DSN missing overridden connect_timeout: %q", cfg.DB.DSN())
	}
}

func TestLoadDevelopmentDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	// no JWT_SECRET set

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IsDevelopment() {
		t.Errorf("env = %q, want development", cfg.Env)
	}
	if cfg.JWT.Secret != insecureDevSecret {
		t.Error("development should fall back to the throwaway dev secret")
	}
	if cfg.Security.CookieSecure {
		t.Error("cookie Secure should default off in development")
	}
	if !slices.Contains(cfg.Security.AllowedOrigins, "*") {
		t.Errorf("dev CORS = %v, want permissive '*'", cfg.Security.AllowedOrigins)
	}
	if cfg.RiskAcceptanceRequiresApproval {
		t.Error("risk acceptance four-eyes should default off in development")
	}
	if len(cfg.Warnings()) != 0 {
		t.Errorf("dev warnings = %v, want none", cfg.Warnings())
	}
}

func TestLoadProductionRequiresSecret(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	// no JWT_SECRET -> hard failure
	if _, err := Load(); err == nil {
		t.Fatal("production without JWT_SECRET should fail")
	}

	// The insecure dev secret is also rejected.
	t.Setenv("JWT_SECRET", insecureDevSecret)
	if _, err := Load(); err == nil {
		t.Fatal("production with the dev secret should fail")
	}
}

func TestLoadProductionHardensDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "prod") // alias -> production
	t.Setenv("JWT_SECRET", "a-strong-unique-production-secret")
	t.Setenv("DB_PASSWORD", "xila") // insecure default -> should warn

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IsProduction() {
		t.Fatalf("env = %q, want production (from alias)", cfg.Env)
	}
	if !cfg.Security.CookieSecure {
		t.Error("cookie Secure should default on in production")
	}
	if len(cfg.Security.AllowedOrigins) != 0 {
		t.Errorf("prod CORS = %v, want same-origin (empty) by default", cfg.Security.AllowedOrigins)
	}
	if !cfg.RiskAcceptanceRequiresApproval {
		t.Error("risk acceptance four-eyes should default on in production")
	}
	warns := cfg.Warnings()
	if len(warns) == 0 {
		t.Fatal("expected production warnings for the insecure DB defaults")
	}
	joined := ""
	for _, w := range warns {
		joined += w + "\n"
	}
	if !contains(joined, "DB_PASSWORD") || !contains(joined, "DB_SSLMODE") {
		t.Errorf("warnings missing DB advice:\n%s", joined)
	}
}

// Turning risk-acceptance four-eyes off in production boots, with a warning.
func TestLoadProductionWarnsWithoutRiskAcceptanceApproval(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("JWT_SECRET", "a-strong-unique-production-secret")
	t.Setenv("RISK_ACCEPTANCE_REQUIRES_APPROVAL", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RiskAcceptanceRequiresApproval {
		t.Fatal("RISK_ACCEPTANCE_REQUIRES_APPROVAL=false was ignored")
	}
	joined := ""
	for _, w := range cfg.Warnings() {
		joined += w + "\n"
	}
	if !contains(joined, "RISK_ACCEPTANCE_REQUIRES_APPROVAL") {
		t.Errorf("warnings missing four-eyes advice:\n%s", joined)
	}
}

func TestLoadRejectsUnknownEnv(t *testing.T) {
	t.Setenv("APP_ENV", "staging-typo")
	t.Setenv("JWT_SECRET", "x")
	if _, err := Load(); err == nil {
		t.Error("unknown APP_ENV should be rejected")
	}
}

func TestLoadVulnSources(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.VulnMatch.Sources) != 1 || cfg.VulnMatch.Sources[0] != "osv" || cfg.NVD.Enabled {
		t.Errorf("defaults = sources %v nvd %v, want [osv] / NVD off", cfg.VulnMatch.Sources, cfg.NVD.Enabled)
	}
	t.Setenv("VULNMATCH_SOURCES", "osv-local, private")
	if cfg, err := Load(); err != nil || len(cfg.VulnMatch.Sources) != 2 || cfg.VulnMatch.Sources[1] != "private" {
		t.Errorf("air-gapped sources = %v, %v", cfg.VulnMatch.Sources, err)
	}
	// A typo would silently drop a source (and its findings would auto-close).
	t.Setenv("VULNMATCH_SOURCES", "osv,gihtub")
	if _, err := Load(); err == nil || !contains(err.Error(), "gihtub") {
		t.Errorf("err = %v, want the unknown source rejected", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLoadSMTP(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("JWT_SECRET", "a-strong-unique-production-secret")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "xila@example.com")
	t.Setenv("SMTP_TLS", "NONE")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SMTP.Port != 587 || cfg.SMTP.TLS != "none" || !cfg.SMTP.Configured() {
		t.Errorf("smtp = %+v, want port 587, tls none, configured", cfg.SMTP)
	}
	joined := ""
	for _, w := range cfg.Warnings() {
		joined += w + "\n"
	}
	if !contains(joined, "SMTP_TLS=none") {
		t.Errorf("warnings missing SMTP_TLS advice:\n%s", joined)
	}

	t.Setenv("SMTP_TLS", "ssl")
	if _, err := Load(); err == nil {
		t.Error("invalid SMTP_TLS should be rejected")
	}
}

func TestSMTPDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SMTP.TLS != "starttls" || cfg.SMTP.Configured() {
		t.Errorf("default smtp = %+v, want starttls, unconfigured", cfg.SMTP)
	}
}

func TestTriageRulesRequireApproval(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.TriageRulesRequireApproval {
		t.Error("approval workflow must be off by default")
	}
	t.Setenv("TRIAGE_RULES_REQUIRE_APPROVAL", "true")
	if cfg, _ = Load(); !cfg.TriageRulesRequireApproval {
		t.Error("TRIAGE_RULES_REQUIRE_APPROVAL=true should enable it")
	}
}

func TestAssessmentRequiresApproval(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AssessmentRequiresApproval {
		t.Error("assessment approval must be off by default")
	}
	t.Setenv("ASSESSMENT_REQUIRES_APPROVAL", "true")
	if cfg, _ = Load(); !cfg.AssessmentRequiresApproval {
		t.Error("ASSESSMENT_REQUIRES_APPROVAL=true should enable it")
	}
}

func TestIntegrationSettings(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if key, err := cfg.IntegrationKey(); key != nil || err != nil {
		t.Errorf("unset key = %v, %v; want nil, nil", key, err)
	}
	if cfg.PublicURL != "" || cfg.IssueSyncInterval != 15*time.Minute {
		t.Errorf("defaults = %q / %v, want empty / 15m", cfg.PublicURL, cfg.IssueSyncInterval)
	}

	// 32 bytes, standard base64 (what `openssl rand -base64 32` prints).
	t.Setenv("INTEGRATION_SECRET_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") // gitleaks:allow -- test key: base64 of "0123456789abcdef" x2
	t.Setenv("PUBLIC_URL", "https://xila.example.com/")
	t.Setenv("ISSUE_SYNC_INTERVAL", "0")
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load with key: %v", err)
	}
	if key, err := cfg.IntegrationKey(); err != nil || string(key) != "0123456789abcdef0123456789abcdef" {
		t.Errorf("key = %q, %v", key, err)
	}
	if cfg.PublicURL != "https://xila.example.com" || cfg.IssueSyncInterval != 0 {
		t.Errorf("overrides = %q / %v", cfg.PublicURL, cfg.IssueSyncInterval)
	}

	for _, bad := range []string{"not base64!!", "c2hvcnQ="} { // invalid, and only 5 bytes
		t.Setenv("INTEGRATION_SECRET_KEY", bad)
		if _, err := Load(); err == nil || !contains(err.Error(), "INTEGRATION_SECRET_KEY") {
			t.Errorf("key %q: err = %v, want INTEGRATION_SECRET_KEY error", bad, err)
		}
	}
}

func TestIntegrationKeyWarningInProduction(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("JWT_SECRET", "a-strong-unique-production-secret")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	joined := ""
	for _, w := range cfg.Warnings() {
		joined += w + "\n"
	}
	if !contains(joined, "INTEGRATION_SECRET_KEY") {
		t.Errorf("warnings missing INTEGRATION_SECRET_KEY advice:\n%s", joined)
	}
	t.Setenv("INTEGRATION_SECRET_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=") // gitleaks:allow -- test key: base64 of "0123456789abcdef" x2
	cfg, _ = Load()
	for _, w := range cfg.Warnings() {
		if contains(w, "INTEGRATION_SECRET_KEY") {
			t.Errorf("unexpected warning with key set: %s", w)
		}
	}
}

// LICENSE_DENYLIST was replaced by component policies; an operator who still
// sets it must be told it no longer does anything — in every environment.
func TestLegacyLicenseDenylistWarns(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, w := range cfg.Warnings() {
		if contains(w, "LICENSE_DENYLIST") {
			t.Errorf("unexpected warning without LICENSE_DENYLIST set: %s", w)
		}
	}
	t.Setenv("LICENSE_DENYLIST", "GPL-3.0")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	joined := strings.Join(cfg.Warnings(), "\n")
	if !contains(joined, "LICENSE_DENYLIST") || !contains(joined, "ignored") || !contains(joined, "/policies") {
		t.Errorf("warnings = %q, want LICENSE_DENYLIST is ignored, pointing to /policies", joined)
	}
	if cfg.Policy.EvalInterval != 6*time.Hour {
		t.Errorf("POLICY_EVAL_INTERVAL default = %v, want 6h", cfg.Policy.EvalInterval)
	}
}

func TestSSODefaults(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.PasswordLoginEnabled || !cfg.SSO.AutoCreateUsers || cfg.OIDC.TrustUnverifiedEmail {
		t.Errorf("password/auto-create/trust = %v/%v/%v, want true/true/false",
			cfg.PasswordLoginEnabled, cfg.SSO.AutoCreateUsers, cfg.OIDC.TrustUnverifiedEmail)
	}
	if !slices.Equal(cfg.OIDC.Scopes, []string{"openid", "email", "profile"}) || cfg.OIDC.GroupsClaim != "groups" {
		t.Errorf("oidc scopes/claim = %v / %q", cfg.OIDC.Scopes, cfg.OIDC.GroupsClaim)
	}
	if !cfg.SAML.SignRequests || !cfg.SAML.LinkByEmail || cfg.SAML.AllowIDPInitiated ||
		!slices.Equal(cfg.SAML.GroupsAttributes, []string{"groups"}) {
		t.Errorf("saml defaults = %+v", cfg.SAML)
	}

	// openid is always requested; commas and spaces both separate.
	t.Setenv("OIDC_SCOPES", "email,profile groups")
	t.Setenv("PUBLIC_URL", "https://xila.example.com")
	if cfg, _ = Load(); !slices.Equal(cfg.OIDC.Scopes, []string{"openid", "email", "profile", "groups"}) {
		t.Errorf("scopes = %v", cfg.OIDC.Scopes)
	}
	if cfg.SAML.EntityID != "https://xila.example.com/api/v1/auth/saml/metadata" {
		t.Errorf("default SAML entity id = %q", cfg.SAML.EntityID)
	}
}

// SAML that cannot work, or would be unsafe, fails boot.
func TestSAMLValidation(t *testing.T) {
	const key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=" // gitleaks:allow -- test key: base64 of "0123456789abcdef" x2
	cases := []struct {
		name string
		env  map[string]string
		want string // "" = boots
	}{
		{"no public url", map[string]string{"SAML_IDP_METADATA_URL": "https://idp/md", "INTEGRATION_SECRET_KEY": key}, "PUBLIC_URL"},
		{"no metadata", map[string]string{"PUBLIC_URL": "https://x", "INTEGRATION_SECRET_KEY": key}, "SAML_IDP_METADATA"},
		{"generated key needs the integration key", map[string]string{"PUBLIC_URL": "https://x", "SAML_IDP_METADATA_URL": "https://idp/md"}, "INTEGRATION_SECRET_KEY"},
		{"half a key pair", map[string]string{"PUBLIC_URL": "https://x", "SAML_IDP_METADATA_URL": "https://idp/md", "SAML_SP_CERT": "pem"}, "SAML_SP_KEY"},
		{"http in production", map[string]string{"APP_ENV": "production", "JWT_SECRET": "a-strong-unique-production-secret",
			"PUBLIC_URL": "http://x", "SAML_IDP_METADATA_URL": "https://idp/md", "INTEGRATION_SECRET_KEY": key}, "https"},
		{"ok", map[string]string{"PUBLIC_URL": "https://x", "SAML_IDP_METADATA_URL": "https://idp/md", "INTEGRATION_SECRET_KEY": key}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_ENV", "development")
			t.Setenv("SAML_ENABLED", "true")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("Load: %v", err)
			case tc.want != "" && (err == nil || !contains(err.Error(), tc.want)):
				t.Errorf("err = %v, want one mentioning %s", err, tc.want)
			}
		})
	}
}

func TestPasswordLoginOffWithoutSSOWarns(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("PASSWORD_LOGIN_ENABLED", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if joined := strings.Join(cfg.Warnings(), "\n"); !contains(joined, "PASSWORD_LOGIN_ENABLED=false") {
		t.Errorf("warnings = %q, want the owner-only lockout warning", joined)
	}
}

// /metrics on the public listener without a token would expose the
// instance's internals in production: refuse to boot; a token or a separate
// (internal) METRICS_ADDR makes it acceptable.
func TestLoadProductionMetricsNeedsTokenOrSeparateListener(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("JWT_SECRET", "a-strong-unique-production-secret-value")
	t.Setenv("METRICS_ENABLED", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "METRICS_TOKEN") {
		t.Fatalf("open /metrics on the main port in production: err = %v", err)
	}
	t.Setenv("METRICS_ADDR", ":9090")
	if _, err := Load(); err != nil {
		t.Fatalf("separate listener: %v", err)
	}
	t.Setenv("METRICS_ADDR", "")
	t.Setenv("METRICS_TOKEN", "scrape-secret")
	if _, err := Load(); err != nil {
		t.Fatalf("token: %v", err)
	}
}

// SOURCE_URL defaults to the upstream repository and must stay a link: it is
// how an AGPL deployment offers its users the source (section 13).
func TestSourceURL(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SourceURL != DefaultSourceURL {
		t.Errorf("default SOURCE_URL = %q, want %q", cfg.SourceURL, DefaultSourceURL)
	}

	t.Setenv("SOURCE_URL", "https://git.example.com/acme/xila-fork")
	if cfg, err = Load(); err != nil || cfg.SourceURL != "https://git.example.com/acme/xila-fork" {
		t.Errorf("fork SOURCE_URL = %q, %v", cfg.SourceURL, err)
	}
	for _, bad := range []string{"git.example.com/acme", "javascript:alert(1)", "ftp://example.com/x", " "} {
		t.Setenv("SOURCE_URL", bad)
		if _, err := Load(); err == nil {
			t.Errorf("SOURCE_URL %q accepted", bad)
		}
	}
}
