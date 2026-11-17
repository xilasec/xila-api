package database_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/database"
)

func pgQuoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func pgQuoteIdent(s string) string   { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// DB_PASSWORD rotation (M10 10.2): pgxpool's BeforeConnect reads
// PasswordGetter for every new physical connection, so rotating a role's
// password in Postgres takes effect without restarting the pool. Proven
// against a real, throwaway role created and dropped by this test.
func TestConnectPicksUpRotatedPassword(t *testing.T) {
	adminDSN := os.Getenv("TEST_DATABASE_URL")
	if adminDSN == "" {
		t.Skip("set TEST_DATABASE_URL to run database integration tests")
	}
	u, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	dbName := strings.TrimPrefix(u.Path, "/")

	ctx := context.Background()
	admin, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}

	const role = "xila_rotation_test_role"
	const initialPassword = "initial-rotation-pw-1"
	const rotatedPassword = "rotated-rotation-pw-2"

	// Leftover from a prior failed run.
	_, _ = admin.Exec(ctx, fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM %s", pgQuoteIdent(dbName), role))
	_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+role)
	if _, err := admin.Exec(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD %s", role, pgQuoteLiteral(initialPassword))); err != nil {
		t.Fatalf("create role: %v", err)
	}
	t.Cleanup(func() {
		cctx := context.Background()
		_, _ = admin.Exec(cctx, fmt.Sprintf("REVOKE ALL ON DATABASE %s FROM %s", pgQuoteIdent(dbName), role))
		_, _ = admin.Exec(cctx, "DROP ROLE IF EXISTS "+role)
		_ = admin.Close(cctx)
	})
	if _, err := admin.Exec(ctx, fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s", pgQuoteIdent(dbName), role)); err != nil {
		t.Fatalf("grant connect: %v", err)
	}

	var current atomic.Value
	current.Store(initialPassword)

	roleURL := *u
	roleURL.User = url.User(role)

	pool, err := database.Connect(ctx, roleURL.String(), database.PoolConfig{
		MaxConns: 1, MinConns: 0,
		PasswordGetter: func() string { return current.Load().(string) },
	})
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("select with initial password: %v", err)
	}

	// Rotate the role's password in Postgres and the getter's live value.
	if _, err := admin.Exec(ctx, fmt.Sprintf("ALTER ROLE %s PASSWORD %s", role, pgQuoteLiteral(rotatedPassword))); err != nil {
		t.Fatalf("alter role password: %v", err)
	}
	current.Store(rotatedPassword)

	// The existing connection keeps working (it authenticated already and
	// Postgres doesn't retroactively check it). Force the pool to open a
	// fresh one, which must use the rotated password.
	pool.Reset()

	if _, err := pool.Exec(ctx, "SELECT 1"); err != nil {
		t.Fatalf("select after rotation: new connections should use the rotated password: %v", err)
	}
}
