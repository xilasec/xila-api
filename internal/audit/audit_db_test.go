package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/retention"
)

// The log is append-only: the trigger refuses every UPDATE and DELETE, and the
// only way rows leave is the retention purge — which takes only rows older
// than its cutoff and leaves a system entry saying it ran.
func TestAuditLogAppendOnly(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := audit.NewRepository(pool)

	for _, action := range []string{"old.one", "new.one"} {
		if err := repo.Insert(ctx, audit.Entry{ActorKind: audit.ActorSystem, Action: action, Outcome: audit.OutcomeSuccess}); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	// Backdating is itself an UPDATE, so do it with the trigger disabled — the
	// test's stand-in for "this row is two years old".
	if _, err := pool.Exec(ctx, `
		ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only;
		UPDATE audit_log SET created_at = now() - interval '800 days' WHERE action = 'old.one';
		ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only;`); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	for _, stmt := range []string{
		`UPDATE audit_log SET action = 'tampered'`,
		`UPDATE audit_log SET changes = '{}' WHERE action = 'new.one'`,
		`DELETE FROM audit_log WHERE action = 'new.one'`,
		`DELETE FROM audit_log WHERE action = 'old.one'`, // old enough, but not through the purge
	} {
		if _, err := pool.Exec(ctx, stmt); err == nil {
			t.Errorf("%s succeeded; the audit log must be append-only", stmt)
		}
	}
	// The purge's permission is transaction-local: it doesn't leak to a later
	// statement on the same connection.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SELECT audit_log_purge(now() - interval '10 years')`); err != nil {
		t.Fatalf("purge nothing: %v", err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM audit_log WHERE action = 'old.one'`); err == nil {
		t.Error("a DELETE after a purge on the same connection succeeded")
	}
	conn.Release()

	res, err := retention.NewService(pool, nil, retention.Policy{AuditAge: 365 * 24 * time.Hour}).Run(ctx)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if res.AuditEntries != 1 {
		t.Errorf("purged %d entries, want the one older than a year", res.AuditEntries)
	}
	entries, err := repo.List(ctx, audit.Filter{}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	if len(entries) != 2 || entries[0].Action != "audit.purge" || entries[0].ActorKind != audit.ActorSystem || entries[1].Action != "new.one" {
		t.Errorf("after purge the log holds %v, want [audit.purge new.one]", actions)
	}
}

func TestAuditLogFilters(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := audit.NewRepository(pool)
	user := "7f4a1a2e-1c1e-4c1e-9c1e-000000000001"
	for _, e := range []audit.Entry{
		{ActorKind: audit.ActorUser, ActorUserID: &user, ActorEmail: "ann@x.io", Action: "users.create", ResourceType: "users", Outcome: audit.OutcomeSuccess},
		{ActorKind: audit.ActorUser, ActorUserID: &user, ActorEmail: "ann@x.io", Action: "users_x.create", ResourceType: "users_x", Outcome: audit.OutcomeSuccess},
		{ActorKind: audit.ActorAnonymous, ActorEmail: "mallory@x.io", Action: "auth.login", Outcome: audit.OutcomeFailure, Status: 401},
	} {
		if err := repo.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	count := func(f audit.Filter) int {
		t.Helper()
		got, err := repo.List(ctx, f, 50, 0)
		if err != nil {
			t.Fatalf("list %+v: %v", f, err)
		}
		return len(got)
	}
	if n := count(audit.Filter{Action: "users"}); n != 1 {
		t.Errorf("action prefix users matched %d, want 1 (users_x is a different resource)", n)
	}
	if n := count(audit.Filter{ActorID: user}); n != 2 {
		t.Errorf("actor_id matched %d, want 2", n)
	}
	if n := count(audit.Filter{Actor: "MALL", Outcome: audit.OutcomeFailure}); n != 1 {
		t.Errorf("failed sign-ins by mall* = %d, want 1", n)
	}
	if n := count(audit.Filter{From: time.Now().Add(time.Hour)}); n != 0 {
		t.Errorf("entries from the future = %d", n)
	}
}
