// Package database manages the PostgreSQL connection pool and schema migrations.
package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/exaring/otelpgx"
	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver for migrations
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// PoolConfig tunes the connection pool. Zero-value fields fall back to the
// defaults in DefaultPoolConfig — except StatementTimeout, where zero means
// "no timeout".
type PoolConfig struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration

	// StatementTimeout caps any single query. Zero disables it. It is set on each
	// pooled connection rather than in the DSN, because the same DSN drives the
	// migration driver — where a slow CREATE INDEX must not be cancelled.
	StatementTimeout time.Duration

	// StartupWait keeps retrying the first connection for this long before
	// giving up, so a database that's still starting (a fresh Kubernetes install,
	// both restarted together) delays boot instead of crash-looping the process.
	// Zero fails on the first attempt.
	StartupWait time.Duration

	// PasswordGetter, if set, returns the current password for every new
	// connection the pool opens (pgxpool's BeforeConnect, M10 10.2:
	// DB_PASSWORD rotation). Connections already open keep working with the
	// password they authenticated with; only later connections (pool growth,
	// recycling, a dropped connection) pick up a rotated password. nil keeps
	// the password baked into dsn, as before.
	PasswordGetter func() string
}

// DefaultPoolConfig is the tuning for a typical API workload (also used by tests).
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:          20,
		MinConns:          2,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
		StatementTimeout:  30 * time.Second,
	}
}

// Connect opens a traced pgx connection pool and verifies connectivity. Pool
// tuning is applied programmatically (not via the DSN) so the same DSN works for
// the database/sql migration driver.
func Connect(ctx context.Context, dsn string, pc PoolConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database config: %w", err)
	}

	// Emit an OpenTelemetry span for every query.
	poolCfg.ConnConfig.Tracer = otelpgx.NewTracer()

	def := DefaultPoolConfig()
	poolCfg.MaxConns = orInt32(pc.MaxConns, def.MaxConns)
	poolCfg.MinConns = orInt32(pc.MinConns, def.MinConns)
	poolCfg.MaxConnLifetime = orDur(pc.MaxConnLifetime, def.MaxConnLifetime)
	poolCfg.MaxConnIdleTime = orDur(pc.MaxConnIdleTime, def.MaxConnIdleTime)
	poolCfg.HealthCheckPeriod = orDur(pc.HealthCheckPeriod, def.HealthCheckPeriod)

	// Bound every statement, and every transaction left idle holding locks. A
	// runaway query would otherwise hold its connection until the pool starves.
	if ms := pc.StatementTimeout.Milliseconds(); ms > 0 {
		poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, fmt.Sprintf(
				"SET statement_timeout = %d; SET idle_in_transaction_session_timeout = %d", ms, 2*ms))
			return err
		}
	}

	if pc.PasswordGetter != nil {
		getPassword := pc.PasswordGetter
		poolCfg.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
			cc.Password = getPassword()
			return nil
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := waitForDatabase(ctx, pool, pc.StartupWait); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// waitForDatabase pings until it succeeds, ctx ends, or wait has elapsed,
// backing off from 500ms to 5s between attempts.
func waitForDatabase(ctx context.Context, pool *pgxpool.Pool, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	backoff := 500 * time.Millisecond
	for {
		err := pool.Ping(ctx)
		if err == nil || time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		slog.WarnContext(ctx, "database not reachable yet, retrying", "in", backoff, "error", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(min(backoff, time.Until(deadline))):
		}
		backoff = min(2*backoff, 5*time.Second)
	}
}

func orInt32(v, fallback int32) int32 {
	if v > 0 {
		return v
	}
	return fallback
}

func orDur(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

// Migrate applies all pending schema migrations embedded in the binary.
func Migrate(dsn string) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("open migration source: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open migration db: %w", err)
	}
	defer db.Close()

	driver, err := migratepgx.WithInstance(db, &migratepgx.Config{})
	if err != nil {
		return fmt.Errorf("build migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "pgx", driver)
	if err != nil {
		return fmt.Errorf("init migrator: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
