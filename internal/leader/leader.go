// Package leader elects one instance to run the scheduled background jobs when
// several replicas share a database (Kubernetes, compose --scale, …).
//
// The leader holds a session-level Postgres advisory lock on a dedicated
// connection. Postgres releases it the moment that session ends — the pod is
// killed, the node dies, the network drops — so another replica takes over on
// its next attempt, with no lease bookkeeping and nothing to clean up. The
// leader checks its connection on an interval and steps down (cancelling the
// jobs) as soon as it can't prove it still holds the session.
//
// Like every session advisory lock in Xila, this needs a direct connection or
// session-mode pooling: transaction-mode PgBouncer would hand the lock to
// whichever client next uses that server connection.
package leader

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JobsLockKey is the advisory lock for "runs the scheduled background jobs".
// Single-bigint keys are a separate key space from the (int, int) namespaces
// used for dedup / vulnmatch / connectors; it differs from the issue-sync key.
const JobsLockKey int64 = 0x7869_6c61_6a6f_6273 // "xilajobs"

// Options tune the election; zero values use the defaults.
type Options struct {
	// Retry is how often a follower tries to take the lock (default 15s) —
	// the worst-case gap before a new leader starts after the old one dies.
	Retry time.Duration
	// Check is how often the leader verifies its session (default 10s). A new
	// leader waits 2×Check before starting the jobs, so a previous leader whose
	// session died has noticed and stopped first — the two never overlap.
	Check time.Duration
}

func (o Options) withDefaults() Options {
	if o.Retry <= 0 {
		o.Retry = 15 * time.Second
	}
	if o.Check <= 0 {
		o.Check = 10 * time.Second
	}
	return o
}

// Run campaigns for key until ctx ends. Whenever this instance is the leader it
// calls lead with a context that is cancelled when leadership is lost (or ctx
// ends); lead must return once that context is done. lead may be called again
// after a later re-election.
func Run(ctx context.Context, pool *pgxpool.Pool, key int64, opts Options, lead func(ctx context.Context)) {
	opts = opts.withDefaults()
	for {
		conn, ok := acquire(ctx, pool, key)
		if ok {
			hold(ctx, conn, key, opts.Check, lead)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(opts.Retry):
		}
	}
}

// acquire takes the lock on a connection removed from the pool (so the pool can
// never reset or hand out the session that owns the lock). Followers don't keep
// a connection.
func acquire(ctx context.Context, pool *pgxpool.Pool, key int64) (*pgx.Conn, bool) {
	pc, err := pool.Acquire(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "leader: no database connection", "error", err)
		}
		return nil, false
	}
	conn := pc.Hijack()
	// If this node dies without closing TCP, the server would keep the dead
	// session — and the lock — until the OS keepalive gives up (~2h by
	// default). Probe it from the server side so a crashed leader is detected
	// within about a minute. Best-effort: some poolers/proxies reject SET.
	_, _ = conn.Exec(ctx, `SET tcp_keepalives_idle = 30; SET tcp_keepalives_interval = 10; SET tcp_keepalives_count = 3`)
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil || !got {
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "leader: lock attempt failed", "error", err)
		}
		closeConn(conn)
		return nil, false
	}
	return conn, true
}

// hold keeps the lock while its session stays healthy, starting lead after the
// fencing delay and stopping it when the session fails or ctx ends.
func hold(ctx context.Context, conn *pgx.Conn, key int64, check time.Duration, lead func(context.Context)) {
	leadCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		done   chan struct{} // closed when lead returns; nil until it starts
		exited chan struct{} // done, until lead has returned (then nil)
		start  = time.After(2 * check)
	)
	stop := func() {
		cancel()
		if done != nil {
			<-done
		}
	}
	ticker := time.NewTicker(check)
	defer ticker.Stop()
	for {
		select {
		case <-start:
			start = nil
			done = make(chan struct{})
			exited = done
			slog.InfoContext(ctx, "leader: running background jobs on this instance")
			go func() {
				defer close(done)
				lead(leadCtx)
			}()
		case <-ctx.Done():
			stop()
			// Unlock explicitly so a peer can take over without waiting for the
			// session to end; closing the connection would release it too.
			unlockCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
			_, _ = conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, key)
			c()
			closeConn(conn)
			return
		case <-ticker.C:
			pingCtx, c := context.WithTimeout(ctx, check/2)
			err := conn.Ping(pingCtx)
			c()
			if err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "leader: lost the lock session, stopping background jobs", "error", err)
				stop()
				closeConn(conn)
				return
			}
		case <-exited:
			// lead returned on its own; keep the lock so no peer starts a second
			// copy, until shutdown or the session fails.
			exited = nil
		}
	}
}

func closeConn(conn *pgx.Conn) {
	ctx, c := context.WithTimeout(context.Background(), 2*time.Second)
	defer c()
	_ = conn.Close(ctx)
}
