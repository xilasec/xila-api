package scan

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// statusKey labels the queue-depth gauge by job status.
var statusKey = attribute.Key("status")

// queueSampler is the subset of the repository the monitor polls.
type queueSampler interface {
	QueueStats(ctx context.Context) (QueueStats, error)
}

// QueueMonitor keeps a recent snapshot of the ingest queue in memory. Two things
// need to know how deep the queue is — the metrics exporter and the upload
// handler, which sheds load when the backlog is too deep — and neither can
// afford to hit the database per request. So one goroutine samples on an interval
// and both read the result for free.
//
// The snapshot is therefore up to one interval stale. That is fine for both uses:
// a queue that crosses the limit mid-interval is a queue that will still be over
// it a second later.
type QueueMonitor struct {
	jobs     queueSampler
	interval time.Duration
	maxDepth int // 0 = no backpressure

	pending    atomic.Int64
	processing atomic.Int64
	failed     atomic.Int64
	oldestSecs atomic.Int64
}

// NewQueueMonitor builds a monitor. maxDepth is the pending-job count at which
// Saturated starts reporting true; 0 disables shedding.
func NewQueueMonitor(jobs queueSampler, interval time.Duration, maxDepth int) *QueueMonitor {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &QueueMonitor{jobs: jobs, interval: interval, maxDepth: maxDepth}
}

// Run samples the queue until ctx is cancelled. Call it in a goroutine.
func (m *QueueMonitor) Run(ctx context.Context) {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		m.sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *QueueMonitor) sample(ctx context.Context) {
	s, err := m.jobs.QueueStats(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "queue stats failed", "error", err)
		}
		return
	}
	m.pending.Store(int64(s.Pending))
	m.processing.Store(int64(s.Processing))
	m.failed.Store(int64(s.Failed))
	m.oldestSecs.Store(int64(s.OldestWait.Seconds()))
}

// Snapshot returns the last sample.
func (m *QueueMonitor) Snapshot() QueueStats {
	oldest := time.Duration(m.oldestSecs.Load()) * time.Second
	return QueueStats{
		Pending:           int(m.pending.Load()),
		Processing:        int(m.processing.Load()),
		Failed:            int(m.failed.Load()),
		OldestWait:        oldest,
		OldestWaitSeconds: oldest.Seconds(),
	}
}

// Saturated reports whether the backlog is too deep to accept more work. Uploads
// are rejected with 429 while it is true: an upload we accept but cannot process
// for an hour is worse than one the client is told to retry, because the client
// still believes it was ingested and its gate result is stale.
func (m *QueueMonitor) Saturated() bool {
	return m.maxDepth > 0 && int(m.pending.Load()) >= m.maxDepth
}

// RegisterMetrics publishes the queue as OpenTelemetry gauges. Depth alone can't
// tell you if you are keeping up — a steady 500 with workers draining it is
// healthy — so the oldest pending job's age is exported alongside it; that is the
// one to alert on.
func (m *QueueMonitor) RegisterMetrics() error {
	meter := otel.Meter("github.com/xilasec/xila-api/internal/scan")

	depth, err := meter.Int64ObservableGauge("xila.ingest.queue.depth",
		metric.WithDescription("Ingest jobs in the queue, by status"),
		metric.WithUnit("{job}"))
	if err != nil {
		return err
	}
	wait, err := meter.Float64ObservableGauge("xila.ingest.queue.oldest_wait",
		metric.WithDescription("Age of the oldest pending ingest job — how far behind the workers are"),
		metric.WithUnit("s"))
	if err != nil {
		return err
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		s := m.Snapshot()
		o.ObserveInt64(depth, int64(s.Pending), metric.WithAttributes(statusKey.String("pending")))
		o.ObserveInt64(depth, int64(s.Processing), metric.WithAttributes(statusKey.String("processing")))
		o.ObserveInt64(depth, int64(s.Failed), metric.WithAttributes(statusKey.String("failed")))
		o.ObserveFloat64(wait, s.OldestWaitSeconds)
		return nil
	}, depth, wait)
	return err
}

// Worker-side instruments. The global meter delegates until the SDK provider is
// installed, so creating them at init is safe and keeps ProcessJob allocation-free.
var (
	ingestMeter    = otel.Meter("github.com/xilasec/xila-api/internal/scan")
	jobsProcessed  metric.Int64Counter
	jobDuration    metric.Float64Histogram
	outcomeKey     = attribute.Key("outcome")
	instrumentInit error
)

func init() {
	jobsProcessed, instrumentInit = ingestMeter.Int64Counter("xila.ingest.jobs",
		metric.WithDescription("Ingest jobs run by a worker"),
		metric.WithUnit("{job}"))
	if instrumentInit != nil {
		return
	}
	jobDuration, instrumentInit = ingestMeter.Float64Histogram("xila.ingest.job.duration",
		metric.WithDescription("Time a worker spent running one ingest job end to end"),
		metric.WithUnit("s"))
}

// observeJob records the outcome and cost of one job. Together with the queue
// gauges this is enough to answer the only question that matters under load:
// are we draining faster than we're filling?
func observeJob(ctx context.Context, start time.Time, err error) {
	if instrumentInit != nil {
		return
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	attrs := metric.WithAttributes(outcomeKey.String(outcome))
	jobsProcessed.Add(ctx, 1, attrs)
	jobDuration.Record(ctx, time.Since(start).Seconds(), attrs)
}
