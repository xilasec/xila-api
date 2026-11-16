package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
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

// unset clears key for this test and restores it afterwards.
func unset(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	os.Unsetenv(key)
}

// NAME_FILE reads a secret from a mounted file (Docker/Kubernetes secrets,
// Vault Agent, the Secrets Store CSI driver); one trailing newline is
// trimmed. Setting both forms, or naming a missing file, refuses to start.
func TestSecretFromFile(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "JWT_SECRET")
	path := filepath.Join(t.TempDir(), "jwt")
	if err := os.WriteFile(path, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("JWT_SECRET_FILE", path)
	cfg, err := Load()
	if err != nil || cfg.JWT.Secret != "from-a-file" {
		t.Fatalf("JWT_SECRET_FILE = %q, %v", cfg.JWT.Secret, err)
	}

	t.Setenv("JWT_SECRET", "also-set")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Errorf("both JWT_SECRET and JWT_SECRET_FILE: %v", err)
	}
	unset(t, "JWT_SECRET")
	t.Setenv("JWT_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := Load(); err == nil {
		t.Error("a missing JWT_SECRET_FILE was accepted")
	}
}

// A .env in the working directory (or ENV_FILE) fills settings the real
// environment doesn't set; the environment always wins, and an explicit
// ENV_FILE must exist.
func TestDotEnv(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	for _, k := range []string{"ENV_FILE", "DB_NAME", "SOURCE_URL", "JWT_SECRET", "JWT_SECRET_FILE"} {
		unset(t, k)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	keyFile := filepath.Join(dir, "jwt")
	if err := os.WriteFile(keyFile, []byte("jwt-from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	dotenv := "# comment\nDB_NAME=from_dotenv\nSOURCE_URL=\"https://git.example.com/fork\"\nexport JWT_SECRET_FILE=" + keyFile + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotenv), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_NAME", "from_env")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DB.Name != "from_env" {
		t.Errorf("DB_NAME = %q: the real environment must win over .env", cfg.DB.Name)
	}
	if cfg.SourceURL != "https://git.example.com/fork" {
		t.Errorf("SOURCE_URL = %q, want the .env value", cfg.SourceURL)
	}
	if cfg.JWT.Secret != "jwt-from-file" {
		t.Errorf("JWT_SECRET via a _FILE set in .env = %q", cfg.JWT.Secret)
	}

	t.Setenv("ENV_FILE", filepath.Join(dir, "nope.env"))
	if _, err := Load(); err == nil {
		t.Error("a missing ENV_FILE was accepted")
	}
}

// A generated password can hold any URL-special character; the DSN must
// round-trip it (and the rest) through the driver's own parser.
func TestDSNEscapesEveryPart(t *testing.T) {
	d := DB{User: "xila", Password: "a/b+c=@#?%d:e", Host: "db.internal", Port: "6543", Name: "xila prod", SSLMode: "require", ConnectTimeout: 5 * time.Second}
	cfg, err := pgconn.ParseConfig(d.DSN())
	if err != nil {
		t.Fatalf("parse %q: %v", d.DSN(), err)
	}
	if cfg.User != d.User || cfg.Password != d.Password || cfg.Host != d.Host || cfg.Port != 6543 || cfg.Database != d.Name {
		t.Errorf("round trip = %s/%s@%s:%d/%s", cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database)
	}
	if cfg.ConnectTimeout != 5*time.Second {
		t.Errorf("connect_timeout = %v", cfg.ConnectTimeout)
	}
}

// INGEST_WORKERS=0 is a web-only node (warned about, not refused); a negative
// count is a mistake.
func TestIngestWorkersZero(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("INGEST_ASYNC", "true")
	t.Setenv("INGEST_WORKERS", "0")
	cfg, err := Load()
	if err != nil || cfg.Ingest.Workers != 0 {
		t.Fatalf("INGEST_WORKERS=0: %d, %v", cfg.Ingest.Workers, err)
	}
	if !slices.ContainsFunc(cfg.Warnings(), func(w string) bool { return strings.Contains(w, "INGEST_WORKERS=0") }) {
		t.Errorf("no warning for an async node without workers: %v", cfg.Warnings())
	}
	t.Setenv("INGEST_WORKERS", "-1")
	if _, err := Load(); err == nil {
		t.Error("INGEST_WORKERS=-1 accepted")
	}
}

// INGEST_PAYLOAD_STORE defaults to postgres (today's behavior); an unknown
// value is rejected.
func TestIngestPayloadStoreDefault(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "INGEST_PAYLOAD_STORE")
	cfg, err := Load()
	if err != nil || cfg.Ingest.PayloadStore != "postgres" {
		t.Fatalf("default PayloadStore = %q, %v", cfg.Ingest.PayloadStore, err)
	}
	t.Setenv("INGEST_PAYLOAD_STORE", "dropbox")
	if _, err := Load(); err == nil {
		t.Error("INGEST_PAYLOAD_STORE=dropbox accepted")
	}
}

// INGEST_PAYLOAD_STORE=s3 fails fast (no network) without S3_BUCKET/REGION,
// the fields objectstore.New needs before it can even try to reach the
// bucket.
func TestIngestPayloadStoreS3RequiresBucketAndRegion(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("INGEST_PAYLOAD_STORE", "s3")
	unset(t, "S3_BUCKET")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "S3_BUCKET") {
		t.Errorf("s3 store without S3_BUCKET: %v", err)
	}
	t.Setenv("S3_BUCKET", "xila-payloads")
	t.Setenv("S3_REGION", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "S3_REGION") {
		t.Errorf("s3 store without S3_REGION: %v", err)
	}
	t.Setenv("S3_REGION", "eu-west-1")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("s3 store with bucket+region: %v", err)
	}
	if cfg.S3.Bucket != "xila-payloads" || cfg.S3.Region != "eu-west-1" {
		t.Errorf("S3 config = %+v", cfg.S3)
	}
	// S3_ENDPOINT goes through netguard.CheckURL, like every other configured
	// destination; a metadata-service address is refused.
	t.Setenv("S3_ENDPOINT", "http://169.254.169.254")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "S3_ENDPOINT") {
		t.Errorf("metadata-address S3_ENDPOINT accepted: %v", err)
	}
}

// S3_ACCESS_KEY_ID / S3_SECRET_ACCESS_KEY support the NAME_FILE secret
// convention, like every other credential in this package.
func TestS3CredentialsFromFile(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	unset(t, "S3_SECRET_ACCESS_KEY")
	path := filepath.Join(t.TempDir(), "s3-secret")
	if err := os.WriteFile(path, []byte("from-a-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("S3_SECRET_ACCESS_KEY_FILE", path)
	cfg, err := Load()
	if err != nil || cfg.S3.SecretAccessKey != "from-a-file" {
		t.Fatalf("S3_SECRET_ACCESS_KEY_FILE = %q, %v", cfg.S3.SecretAccessKey, err)
	}
}

// S3_FORCE_PATH_STYLE and S3_PREFIX reach the config untouched (the prefix
// trimmed of surrounding slashes).
func TestS3PathStyleAndPrefix(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("S3_PREFIX", "/xila/ingest/")
	t.Setenv("S3_FORCE_PATH_STYLE", "true")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.S3.Prefix != "xila/ingest" || !cfg.S3.ForcePathStyle {
		t.Errorf("S3 config = %+v", cfg.S3)
	}
}

// Reporting reads: no read settings = one pool; DB_READ_URL (also via
// _FILE, it holds a password) or DB_READ_STATEMENT_TIMEOUT = a separate one;
// a non-postgres URL is refused.
func TestReadPool(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	cfg, err := Load()
	if err != nil || cfg.DB.SeparateReadPool() || cfg.DB.ReadDSN() != cfg.DB.DSN() {
		t.Fatalf("default: separate=%v, %v", cfg.DB.SeparateReadPool(), err)
	}
	t.Setenv("DB_READ_STATEMENT_TIMEOUT", "5s")
	if cfg, err = Load(); err != nil || !cfg.DB.SeparateReadPool() || cfg.DB.ReadDSN() != cfg.DB.DSN() {
		t.Errorf("timeout only: separate=%v dsn=%q, %v; want a capped pool on the primary", cfg.DB.SeparateReadPool(), cfg.DB.ReadDSN(), err)
	}
	dir := t.TempDir()
	path := dir + "/read-url"
	if err := os.WriteFile(path, []byte("postgres://reader:s3cret@replica:5432/xila?sslmode=require\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DB_READ_URL_FILE", path)
	if cfg, err = Load(); err != nil || cfg.DB.ReadDSN() != "postgres://reader:s3cret@replica:5432/xila?sslmode=require" {
		t.Errorf("DB_READ_URL_FILE: %q, %v", cfg.DB.ReadDSN(), err)
	}
	t.Setenv("DB_READ_URL_FILE", "")
	t.Setenv("DB_READ_URL", "mysql://replica/xila")
	if _, err := Load(); err == nil {
		t.Error("a non-postgres DB_READ_URL was accepted")
	}
}
