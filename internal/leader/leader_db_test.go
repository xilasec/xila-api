package leader_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/leader"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// A key of its own, so the test never contends with a real instance.
const testKey int64 = 0x7465_7374_6c65_6164 // "testlead"

// candidate records when it leads; leading counts concurrent leaders.
type candidate struct {
	terms   atomic.Int32 // how many times it became leader
	current atomic.Bool
}

func (c *candidate) lead(leading *atomic.Int32) func(context.Context) {
	return func(ctx context.Context) {
		c.terms.Add(1)
		c.current.Store(true)
		if n := leading.Add(1); n > 1 {
			panic("two leaders at once")
		}
		<-ctx.Done()
		leading.Add(-1)
		c.current.Store(false)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Exactly one replica runs the jobs; when its database session dies (pod
// killed, node lost) the other takes over and the old one's jobs are stopped;
// a clean shutdown hands over without waiting for a session timeout.
func TestOneLeaderAndFailover(t *testing.T) {
	pool := pgtest.Pool(t)
	opts := leader.Options{Retry: 50 * time.Millisecond, Check: 50 * time.Millisecond}

	var leading atomic.Int32
	a, b := &candidate{}, &candidate{}
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, c := range []struct {
		ctx context.Context
		c   *candidate
	}{{ctxA, a}, {ctxB, b}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			leader.Run(c.ctx, pool, testKey, opts, c.c.lead(&leading))
		}()
	}
	t.Cleanup(func() { stopA(); stopB(); wg.Wait() })

	eventually(t, "a leader", func() bool { return leading.Load() == 1 })
	// It stays one: give the follower several retry rounds to (wrongly) win too.
	time.Sleep(300 * time.Millisecond)
	if leading.Load() != 1 {
		t.Fatalf("%d leaders, want 1", leading.Load())
	}
	first, second := a, b
	if b.current.Load() {
		first, second = b, a
	}

	// Kill the leader's session from the server side, as a lost pod would.
	var killed int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(pg_terminate_backend(pid)) FROM pg_locks
		WHERE locktype = 'advisory' AND objsubid = 1 AND granted
		  AND ((classid::bigint << 32) | objid::bigint) = $1`, testKey).Scan(&killed); err != nil || killed != 1 {
		t.Fatalf("terminate leader session: killed %d (%v)", killed, err)
	}
	eventually(t, "failover to the other replica", func() bool { return second.current.Load() })
	if first.current.Load() {
		t.Fatal("the old leader kept running its jobs after losing its session")
	}

	// Shut the new leader down cleanly: the old one is re-elected promptly.
	before := first.terms.Load()
	if second == a {
		stopA()
	} else {
		stopB()
	}
	eventually(t, "re-election after a clean shutdown", func() bool {
		return first.terms.Load() > before && first.current.Load()
	})
}
