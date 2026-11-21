// Package pgtest provides a real-Postgres harness for integration tests.
//
// Tests that call Pool are skipped unless TEST_DATABASE_URL points at a
// disposable database, e.g.:
//
//	TEST_DATABASE_URL=postgres://xila:xila@localhost:5432/xila?sslmode=disable go test ./...
//
// The compose stack's Postgres works for this. No third-party test framework is
// used — just the standard library and the app's own migrations.
package pgtest

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/database"
)

// allTables is the set truncated between tests, children first.
var allTables = []string{"feature_flags", "custom_parsers", "project_watches", "custom_field_definitions", "user_notification_prefs", "cra_case_events", "cra_cases", "exploit_refs", "exploit_sources", "kev_catalog_entries", "kev_catalogs", "project_badge_tokens", "report_templates", "finding_templates", "mfa_recovery_codes", "ingestion_anomalies", "password_reset_tokens", "auth_rate_limits", "audit_log", "saml_sessions", "user_identities", "sso_group_mappings", "sso_providers", "saml_sp_keys", "saml_seen_assertions", "vuln_policy_matches", "vuln_policy_projects", "vuln_policies", "policy_projects", "policies", "license_groups", "portfolio_parts", "metric_snapshots", "org_members", "team_members", "project_members", "vex_statements", "notification_outbox", "notification_deliveries", "notification_channels", "risk_acceptance_findings", "risk_acceptances", "finding_exceptions", "finding_events", "ai_proposals", "finding_comments", "finding_attachments", "finding_assessments", "finding_issues", "remediation_action_issues", "remediation_action_findings", "remediation_actions", "issue_trackers", "connectors", "scan_jobs", "gate_policies", "sla_policies", "triage_rule_actions", "triage_rules", "federation_bindings", "federation_issuers", "service_accounts", "api_tokens", "package_status", "package_meta", "osv_advisories", "jvn_advisories", "feed_rules", "psirt_revisions", "psirt_advisories", "private_advisories", "nvd_cves", "sbom_vulns", "sbom_dependencies", "sbom_services", "sbom_components", "sboms", "findings", "scans", "engagements", "project_versions", "asset_relations", "assets", "projects", "teams", "scim_tokens", "user_group_members", "user_groups", "custom_roles", "organizations", "users"}

// SeededPolicyID is the global "Strong copyleft licenses" policy migration
// 000040 seeds (the LICENSE_DENYLIST replacement). Truncate restores it, so
// every test starts from a fresh install's policies.
const SeededPolicyID = "c0b1ef7a-0000-4000-8000-000000000040"

// Pool returns a migrated connection pool, skipping the test when no test
// database is configured. The pool and a clean schema are torn down/reset
// automatically.
func Pool(t testing.TB) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run database integration tests")
	}

	if err := database.Migrate(dsn); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	pool, err := database.Connect(context.Background(), dsn, database.DefaultPoolConfig())
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)

	Truncate(t, pool)
	return pool
}

// Truncate wipes all domain tables so each test starts from a clean slate, and
// puts instance-wide singleton settings back to their defaults (they are
// rows that must exist, so they're reset rather than truncated).
func Truncate(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range allTables {
		if _, err := pool.Exec(context.Background(), "TRUNCATE "+table+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	if _, err := pool.Exec(context.Background(), `
		DELETE FROM sla_settings;
		INSERT INTO sla_settings DEFAULT VALUES`); err != nil {
		t.Fatalf("reset sla_settings: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		DELETE FROM ingest_settings;
		INSERT INTO ingest_settings DEFAULT VALUES`); err != nil {
		t.Fatalf("reset ingest_settings: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		DELETE FROM triage_settings;
		INSERT INTO triage_settings DEFAULT VALUES`); err != nil {
		t.Fatalf("reset triage_settings: %v", err)
	}
	// Keep in step with migration 000040's seed.
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO policies (id, name, description, operator, violation_state, scope, versions, conditions)
		VALUES ($1, 'Strong copyleft licenses',
		        'Components that can only be used under the AGPL-3.0, GPL-2.0 or GPL-3.0 family. Replaces the former LICENSE_DENYLIST default.',
		        'any', 'warn', 'global', 'all',
		        '[{"subject": "license", "operator": "is", "value": ["AGPL-3.0*", "GPL-2.0*", "GPL-3.0*"]}]')`,
		SeededPolicyID); err != nil {
		t.Fatalf("reset seeded policy: %v", err)
	}
}
