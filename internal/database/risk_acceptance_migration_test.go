package database

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Migration 000067 converts the old per-finding risk acceptances: seeded in a
// private schema migrated up to just before it, then migrated across it.
func TestRiskAcceptanceMigrationConvertsOldData(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run database integration tests")
	}
	const schema = "m8e_ra_migration"
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if _, err := admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE; CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`) })

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// The migrate driver holds db's only connection for its whole life: seed
	// and check through a second pool on the same schema, or every query
	// here waits forever for that connection.
	data, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer data.Close()
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{})
	if err != nil {
		t.Fatal(err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "pgx", driver)
	if err != nil {
		t.Fatal(err)
	}
	// Up to the last migration before 000067.
	for {
		v, _, err := m.Version()
		var next uint
		switch {
		case errors.Is(err, migrate.ErrNilVersion):
			next, err = src.First()
		case err == nil:
			next, err = src.Next(v)
		}
		if err != nil {
			t.Fatalf("next migration: %v", err)
		}
		if next >= 67 {
			break
		}
		if err := m.Steps(1); err != nil {
			t.Fatalf("migrate step: %v", err)
		}
	}

	ctx := context.Background()
	var user, project string
	if err := data.QueryRowContext(ctx, `INSERT INTO users (email, password_hash) VALUES ('alice@x.io', 'x') RETURNING id`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := data.QueryRowContext(ctx, `
		WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o', 'o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, 't', 't' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, 'p', 'p' FROM tm RETURNING id`).Scan(&project); err != nil {
		t.Fatal(err)
	}
	seed := func(fp, status, reason, by string, expires string) string {
		var id string
		if err := data.QueryRowContext(ctx, `
			INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status,
			                      exception_reason, exception_by, exception_expires_at, resolved_at)
			VALUES ($1, $2, 'trivy', 'sca', 't', 'high', $3, $4, $5, NULLIF($6, '')::timestamptz, now())
			RETURNING id`, project, fp, status, reason, by, expires).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
		return id
	}
	a := seed("a", "risk_accepted", "behind WAF", user, "2099-01-01T00:00:00Z")
	b := seed("b", "risk_accepted", "behind WAF", user, "2099-01-01T00:00:00Z")
	c := seed("c", "risk_accepted", "imported", "defectdojo", "")
	fp := seed("d", "false_positive", "test code", user, "")
	pend := seed("e", "open", "", "", "")
	if _, err := data.ExecContext(ctx, `INSERT INTO finding_assessments (finding_id, project_id, requested_by, requester, status, reason)
		VALUES ($1, $2, $3, 'alice@x.io', 'risk_accepted', 'please')`, pend, project, user); err != nil {
		t.Fatal(err)
	}
	if _, err := data.ExecContext(ctx, `INSERT INTO notification_channels (name, type, url, events)
		VALUES ('c', 'webhook', 'https://h', '{finding.risk_accepted,exception.expired}')`); err != nil {
		t.Fatal(err)
	}

	if err := m.Steps(1); err != nil {
		t.Fatalf("migration 000067: %v", err)
	}
	if v, _, _ := m.Version(); v != 67 {
		t.Fatalf("version = %d, want 67", v)
	}

	type acc struct {
		state, title, justification, approver string
		owner                                 sql.NullString
		expires                               sql.NullTime
		members                               int
	}
	got := map[string]acc{}
	rows, err := data.QueryContext(ctx, `
		SELECT m.finding_id, ra.state, ra.title, ra.justification, ra.approver, ra.owner_id::text, ra.expires_at,
		       (SELECT count(*) FROM risk_acceptance_findings x WHERE x.acceptance_id = ra.id AND x.removed_at IS NULL)
		FROM risk_acceptance_findings m JOIN risk_acceptances ra ON ra.id = m.acceptance_id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var fid string
		var x acc
		if err := rows.Scan(&fid, &x.state, &x.title, &x.justification, &x.approver, &x.owner, &x.expires, &x.members); err != nil {
			t.Fatal(err)
		}
		got[fid] = x
	}
	rows.Close()
	if len(got) != 4 {
		t.Fatalf("converted memberships = %d (%v), want a, b, c and the pending request", len(got), got)
	}
	if x := got[a]; x.state != "approved" || x.members != 2 || x.justification != "behind WAF" || x.approver != "alice@x.io" ||
		x.owner.String != user || !x.expires.Valid || x != got[b] {
		t.Errorf("a/b acceptance = %+v / %+v, want one approved group of 2 by alice", x, got[b])
	}
	if x := got[c]; x.state != "approved" || x.members != 1 || x.approver != "defectdojo" || x.owner.Valid || x.expires.Valid {
		t.Errorf("imported acceptance = %+v", x)
	}
	if x := got[pend]; x.state != "requested" || x.justification != "please" {
		t.Errorf("pending assessment → %+v, want a requested acceptance", x)
	}
	var reason string
	var cleared bool
	if err := data.QueryRowContext(ctx, `SELECT bool_and(exception_reason = '' AND exception_expires_at IS NULL)
		FROM findings WHERE status = 'risk_accepted'`).Scan(&cleared); err != nil || !cleared {
		t.Errorf("risk_accepted findings still carry exception fields (%v)", err)
	}
	if err := data.QueryRowContext(ctx, `SELECT exception_reason FROM findings WHERE id = $1`, fp).Scan(&reason); err != nil || reason != "test code" {
		t.Errorf("false positive reason = %q (%v), want kept", reason, err)
	}
	var aState string
	if err := data.QueryRowContext(ctx, `SELECT state FROM finding_assessments WHERE finding_id = $1`, pend).Scan(&aState); err != nil || aState != "rejected" {
		t.Errorf("converted assessment state = %q (%v), want closed", aState, err)
	}
	var events string
	if err := data.QueryRowContext(ctx, `SELECT array_to_string(events, ',') FROM notification_channels`).Scan(&events); err != nil ||
		events != "risk_acceptance.approved,exception.expired,risk_acceptance.expired" {
		t.Errorf("channel events = %q (%v)", events, err)
	}
}
