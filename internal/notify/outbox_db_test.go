package notify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// An event outlives the process that raised it: queued by one Service, failed
// by a dispatcher that then "restarts", and delivered by a fresh Service —
// with exactly one delivery-log entry for the outcome.
func TestOutboxSurvivesRestartAndRetries(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := notify.NewRepository(pool)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway) // the receiver is down the first time
		}
	}))
	defer srv.Close()
	if _, err := repo.Create(ctx, notify.Channel{Name: "hook", Type: "webhook", URL: srv.URL, Events: []string{"*"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	fast := notify.DeliveryPolicy{MaxAttempts: 5, RetryBase: 50 * time.Millisecond, RetryMax: time.Second, Retention: time.Hour}

	first := notify.NewService(repo, notify.SMTPConfig{})
	first.SetDeliveryPolicy(fast)
	first.Notify(ctx, notify.Event{Type: notify.EventCriticalFinding, Title: "boom"})
	if n, err := first.DispatchDue(ctx); err != nil || n != 1 {
		t.Fatalf("first dispatch = %d, %v", n, err)
	}
	pending, err := repo.ListPending(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Attempts != 1 || pending[0].LastError == "" || *pending[0].LastStatus != 502 {
		t.Fatalf("after a failed send: pending = %+v, %v", pending, err)
	}
	// Not due yet: the backoff holds it back.
	if n, _ := first.DispatchDue(ctx); n != 0 {
		t.Errorf("a row was resent %d time(s) before its backoff elapsed", n)
	}

	time.Sleep(80 * time.Millisecond)
	second := notify.NewService(repo, notify.SMTPConfig{}) // the "restarted" process
	second.SetDeliveryPolicy(fast)
	if n, err := second.DispatchDue(ctx); err != nil || n != 1 {
		t.Fatalf("dispatch after restart = %d, %v", n, err)
	}
	if hits.Load() != 2 {
		t.Errorf("receiver hits = %d, want 2", hits.Load())
	}
	if pending, _ := repo.ListPending(ctx, 10); len(pending) != 0 {
		t.Errorf("still pending after delivery: %+v", pending)
	}
	log, _ := repo.ListDeliveries(ctx, 10)
	if len(log) != 1 || !log[0].Delivered || log[0].Attempts != 2 {
		t.Errorf("delivery log = %+v, want one delivered entry after 2 attempts", log)
	}
}

// Two dispatchers never get the same row, and a row whose dispatcher died is
// handed out again once its lease runs out.
func TestOutboxClaimsAreExclusiveAndLeased(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := notify.NewRepository(pool)
	ch, err := repo.Create(ctx, notify.Channel{Name: "hook", Type: "webhook", URL: "https://example.invalid", Events: []string{"*"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := repo.Enqueue(ctx, []string{ch.ID}, notify.Event{Type: notify.EventTest}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := repo.Claim(ctx, 2, 300*time.Millisecond)
	if err != nil || len(a) != 2 {
		t.Fatalf("claim A = %d, %v", len(a), err)
	}
	b, _ := repo.Claim(ctx, 10, time.Minute)
	if len(b) != 1 || b[0].ID == a[0].ID || b[0].ID == a[1].ID {
		t.Fatalf("claim B got %+v; must be only the row A didn't take", b)
	}
	if b[0].Channel.ID != ch.ID || b[0].Event.Type != notify.EventTest {
		t.Errorf("claimed row lost its channel/event: %+v", b[0])
	}
	if again, _ := repo.Claim(ctx, 10, time.Minute); len(again) != 0 {
		t.Fatalf("leased rows handed out again: %d", len(again))
	}

	// A "dies": its lease expires and the rows come back, attempts counted.
	time.Sleep(400 * time.Millisecond)
	back, _ := repo.Claim(ctx, 10, time.Minute)
	if len(back) != 2 || back[0].Attempts != 2 {
		t.Fatalf("after lease expiry: %+v, want A's 2 rows on attempt 2", back)
	}

	// Finished rows are purged after retention; deleting a channel drops its queue.
	for _, it := range back {
		if err := repo.Finish(ctx, it.ID, 200, "", true, nil, false); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE notification_outbox SET created_at = now() - interval '8 days' WHERE delivered_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	if n, err := repo.PurgeOutbox(ctx, 7*24*time.Hour); err != nil || n != 2 {
		t.Errorf("purge = %d, %v; want the 2 old delivered rows", n, err)
	}
	if err := repo.Delete(ctx, ch.ID); err != nil {
		t.Fatal(err)
	}
	var left int
	pool.QueryRow(ctx, `SELECT count(*) FROM notification_outbox`).Scan(&left)
	if left != 0 {
		t.Errorf("%d outbox rows outlived their channel", left)
	}
}

// The backlog the outbox gauges publish: pending (not yet delivered, not given
// up on) vs failed, and how long the oldest pending one has waited.
func TestOutboxBacklog(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := notify.NewRepository(pool)
	ch, err := repo.Create(ctx, notify.Channel{Name: "hook", Type: "webhook", URL: "https://hooks.example.test/x", Events: []string{"*"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := repo.OutboxBacklog(ctx); err != nil || b != (notify.Backlog{}) {
		t.Fatalf("empty outbox = %+v, %v", b, err)
	}
	for range 3 {
		if err := repo.Enqueue(ctx, []string{ch.ID}, notify.Event{Type: notify.EventCriticalFinding}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE notification_outbox SET created_at = now() - interval '10 minutes'
		WHERE id = (SELECT min(id) FROM notification_outbox)`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE notification_outbox SET failed_at = now()
		WHERE id = (SELECT max(id) FROM notification_outbox)`); err != nil {
		t.Fatal(err)
	}
	b, err := repo.OutboxBacklog(ctx)
	if err != nil || b.Pending != 2 || b.Failed != 1 || b.OldestWait < 599 || b.OldestWait > 660 {
		t.Fatalf("backlog = %+v, %v; want 2 pending, 1 failed, oldest ≈ 600 s", b, err)
	}
}
