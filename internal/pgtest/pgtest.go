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
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/database"
)

// allTables is the set of domain tables emptied between tests (with every table
// that references one of them; see candidates). Add each new table here.
var allTables = []string{"user_sessions", "project_gate_state", "pkgmeta_registries", "component_patterns", "feature_flags", "custom_parsers", "project_assessment_approvers", "project_watches", "custom_field_definitions", "user_notification_prefs", "cra_case_events", "cra_cases", "exploit_refs", "exploit_sources", "kev_catalog_entries", "kev_catalogs", "project_badge_tokens", "report_templates", "finding_templates", "mfa_recovery_codes", "ingestion_anomalies", "password_reset_tokens", "auth_rate_limits", "audit_log", "saml_sessions", "user_identities", "sso_group_mappings", "sso_providers", "saml_sp_keys", "saml_seen_assertions", "vuln_policy_matches", "vuln_policy_projects", "vuln_policies", "policy_projects", "policies", "license_groups", "portfolio_parts", "metric_snapshots", "org_members", "team_members", "project_members", "vex_statements", "vex_document_revisions", "vex_documents", "triage_carries", "notification_outbox", "notification_deliveries", "notification_channels", "risk_acceptance_findings", "risk_acceptances", "finding_exceptions", "finding_events", "ai_proposals", "finding_comments", "finding_attachments", "finding_assessments", "finding_issue_comments", "finding_issues", "remediation_action_issues", "remediation_action_findings", "remediation_actions", "issue_trackers", "connectors", "scan_jobs", "gate_policies", "sla_policies", "triage_rule_actions", "triage_rules", "federation_bindings", "federation_issuers", "service_accounts", "api_tokens", "package_status", "package_meta", "osv_advisories", "jvn_advisories", "feed_rules", "psirt_revisions", "psirt_advisories", "private_advisories", "nvd_cves", "sbom_vulns", "sbom_dependencies", "sbom_services", "sbom_components", "sbom_processing", "sboms", "findings", "scans", "engagements", "project_versions", "asset_relations", "assets", "projects", "teams", "scim_tokens", "user_group_members", "user_groups", "custom_roles", "organizations", "users", "inbox_items", "report_schedule_runs", "report_schedules", "project_scan_expectations"}

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
	if err := reset(context.Background(), pool); err != nil {
		t.Fatalf("reset test database: %v", err)
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

// reset empties every domain table that holds rows.
//
// It used to TRUNCATE each of allTables with CASCADE: a commit, and a fresh set
// of relation files to sync, per table, ~7 s per test on a slow disk and most
// of the suite's run time. Tests touch a handful of tables, so this finds the
// non-empty ones in one round trip and DELETEs only those, in one transaction
// with foreign keys and triggers suspended (session_replication_role = replica,
// superuser only; the order then doesn't matter, and any table still holding
// rows is by definition one of them). audit_log is the exception: it is
// append-only by trigger and only ever emptied by TRUNCATE, as before.
//
// A role that can't set the replication role gets the old TRUNCATE, in one
// statement.
func reset(ctx context.Context, pool *pgxpool.Pool) error {
	cands, err := candidates(ctx, pool)
	if err != nil {
		return err
	}
	dirty, err := nonEmpty(ctx, pool, cands)
	if err != nil || len(dirty) == 0 {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42501" { // insufficient_privilege
			_, err = pool.Exec(ctx, "TRUNCATE "+identList(allTables)+" CASCADE")
		}
		return err
	}
	for _, table := range dirty {
		stmt := "DELETE FROM " + pgx.Identifier{table}.Sanitize()
		if table == "audit_log" {
			stmt = "TRUNCATE audit_log"
		}
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return tx.Commit(ctx)
}

// candidateCache holds the candidate tables, computed once per test binary.
var candidateCache struct {
	once   sync.Once
	tables []string
	err    error
}

// candidates is every table a reset must empty: allTables plus each table
// that references one of them, transitively. That is the reach TRUNCATE
// CASCADE had, so a table someone forgot to list still can't leak rows
// between tests. The schema doesn't change within a test binary, so it's
// computed once (candidateCache).
func candidates(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	candidateCache.once.Do(func() {
		rows, err := pool.Query(ctx, `
			WITH RECURSIVE reach(oid) AS (
			    SELECT c.oid FROM pg_class c
			    WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r' AND c.relname = ANY($1)
			    UNION
			    SELECT con.conrelid FROM pg_constraint con JOIN reach ON con.confrelid = reach.oid
			    WHERE con.contype = 'f'
			)
			SELECT c.relname FROM pg_class c JOIN reach USING (oid) ORDER BY c.relname`, allTables)
		if err != nil {
			candidateCache.err = err
			return
		}
		candidateCache.tables, candidateCache.err = pgx.CollectRows(rows, pgx.RowTo[string])
	})
	return candidateCache.tables, candidateCache.err
}

// nonEmpty returns the tables among cands that hold at least one row.
func nonEmpty(ctx context.Context, pool *pgxpool.Pool, cands []string) ([]string, error) {
	if len(cands) == 0 {
		return nil, nil
	}
	var b strings.Builder
	for i, table := range cands {
		if i > 0 {
			b.WriteString(" UNION ALL ")
		}
		fmt.Fprintf(&b, "SELECT %s::text WHERE EXISTS (SELECT 1 FROM %s)", quoteLiteral(table), pgx.Identifier{table}.Sanitize())
	}
	rows, err := pool.Query(ctx, b.String())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func identList(tables []string) string {
	ids := make([]string, len(tables))
	for i, table := range tables {
		ids[i] = pgx.Identifier{table}.Sanitize()
	}
	return strings.Join(ids, ", ")
}

// quoteLiteral quotes a table name as a SQL string literal. Names come from
// allTables and the catalog, never from input.
func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
