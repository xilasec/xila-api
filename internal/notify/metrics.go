package notify

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

// Backlog is the outbox's state: what is waiting, what was given up on.
type Backlog struct {
	Pending    int64   // queued, not yet delivered nor given up on
	Failed     int64   // gave up after NOTIFY_MAX_ATTEMPTS (kept until NOTIFY_RETENTION)
	OldestWait float64 // seconds the oldest pending delivery has waited
}

// backlogSampler is implemented by the Postgres outbox (not the test fakes).
type backlogSampler interface {
	OutboxBacklog(ctx context.Context) (Backlog, error)
}

// OutboxBacklog counts the outbox in one pass over its (small, purged) table.
func (r *Repository) OutboxBacklog(ctx context.Context) (Backlog, error) {
	var b Backlog
	err := r.db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE delivered_at IS NULL AND failed_at IS NULL),
		       count(*) FILTER (WHERE failed_at IS NOT NULL),
		       COALESCE(EXTRACT(EPOCH FROM now() - min(created_at) FILTER (WHERE delivered_at IS NULL AND failed_at IS NULL)), 0)
		FROM notification_outbox`).Scan(&b.Pending, &b.Failed, &b.OldestWait)
	return b, err
}

// backlogSampleEvery bounds the backlog query to one per interval, however
// often the dispatcher ticks; scrapes read the last sample, never the DB.
const backlogSampleEvery = 15 * time.Second

// outboxGauges publishes the last backlog sample. Only the dispatching
// (leader) instance samples, so the series comes from one replica.
type outboxGauges struct {
	sampled          atomic.Bool
	pending, failed  atomic.Int64
	oldestWaitMillis atomic.Int64
	last             time.Time
	registered       bool
}

func (g *outboxGauges) sample(ctx context.Context, src outboxStore) {
	b, ok := src.(backlogSampler)
	if !ok || time.Since(g.last) < backlogSampleEvery {
		return
	}
	g.last = time.Now()
	if !g.registered {
		g.registered = true
		if err := g.register(); err != nil {
			slog.WarnContext(ctx, "notify: outbox metrics unavailable", "error", err)
		}
	}
	bl, err := b.OutboxBacklog(ctx)
	if err != nil {
		// Keep the last good sample: a DB hiccup isn't an empty backlog.
		slog.WarnContext(ctx, "notify: sample outbox backlog failed", "error", err)
		return
	}
	g.pending.Store(bl.Pending)
	g.failed.Store(bl.Failed)
	g.oldestWaitMillis.Store(int64(bl.OldestWait * 1000))
	g.sampled.Store(true)
}

func (g *outboxGauges) register() error {
	m := otel.Meter("github.com/xilasec/xila-api/internal/notify")
	pending, err := m.Int64ObservableGauge("xila.notify.outbox.pending", metric.WithUnit("{delivery}"),
		metric.WithDescription("Notification deliveries waiting in the outbox"))
	if err != nil {
		return err
	}
	failed, err := m.Int64ObservableGauge("xila.notify.outbox.failed", metric.WithUnit("{delivery}"),
		metric.WithDescription("Notification deliveries given up on (NOTIFY_MAX_ATTEMPTS), still retained"))
	if err != nil {
		return err
	}
	wait, err := m.Float64ObservableGauge("xila.notify.outbox.oldest_wait", metric.WithUnit("s"),
		metric.WithDescription("Age of the oldest pending delivery — alert on this, not on depth"))
	if err != nil {
		return err
	}
	_, err = m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		if !g.sampled.Load() {
			return nil
		}
		o.ObserveInt64(pending, g.pending.Load())
		o.ObserveInt64(failed, g.failed.Load())
		o.ObserveFloat64(wait, float64(g.oldestWaitMillis.Load())/1000)
		return nil
	}, pending, failed, wait)
	return err
}
