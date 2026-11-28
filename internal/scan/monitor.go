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

// settingsSampler is the subset of the repository the monitor reads live
// tuning overrides from (M11 11.7). Optional: nil means no live tuning, just
// the configured defaults.
type settingsSampler interface {
	GetIngestSettings(ctx context.Context) (IngestSettings, error)
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
//
// M11 11.7 live tuning: WithLiveSettings wires an operator override source and
// a worker pool, so the same sample also applies the current override to the
// backpressure threshold and resizes this node's pool — both take effect
// within one sample interval, no restart.
type QueueMonitor struct {
	jobs            queueSampler
	settings        settingsSampler // optional
	pool            *WorkerPool     // optional
	interval        time.Duration
	defaultMaxDepth int // 0 = no backpressure
	defaultWorkers  int

	pending    atomic.Int64
	processing atomic.Int64
	failed     atomic.Int64
	oldestSecs atomic.Int64
	maxDepth   atomic.Int64 // effective value in force right now: override ?? defaultMaxDepth
}

// NewQueueMonitor builds a monitor. maxDepth is the pending-job count at which
// Saturated starts reporting true; 0 disables shedding.
func NewQueueMonitor(jobs queueSampler, interval time.Duration, maxDepth int) *QueueMonitor {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	m := &QueueMonitor{jobs: jobs, interval: interval, defaultMaxDepth: maxDepth}
	m.maxDepth.Store(int64(maxDepth))
	return m
}

// WithLiveSettings wires the operator-override source and the worker pool to
// resize, enabling M11 11.7. defaultWorkers is the configured INGEST_WORKERS,
// used whenever no override is stored (or the override is explicitly null).
func (m *QueueMonitor) WithLiveSettings(settings settingsSampler, pool *WorkerPool, defaultWorkers int) *QueueMonitor {
	m.settings = settings
	m.pool = pool
	m.defaultWorkers = defaultWorkers
	return m
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
	if s, err := m.jobs.QueueStats(ctx); err != nil {
		if ctx.Err() == nil {
			slog.WarnContext(ctx, "queue stats failed", "error", err)
		}
		// Keep the last good snapshot — reporting an empty queue when the
		// database is unreachable would disable backpressure exactly when
		// it's needed. Still fall through to apply live settings: a stats
		// hiccup shouldn't also stall a worker-count change.
	} else {
		m.pending.Store(int64(s.Pending))
		m.processing.Store(int64(s.Processing))
		m.failed.Store(int64(s.Failed))
		m.oldestSecs.Store(int64(s.OldestWait.Seconds()))
	}

	maxDepth := m.defaultMaxDepth
	workers := m.defaultWorkers
	if m.settings != nil {
		set, err := m.settings.GetIngestSettings(ctx)
		if err != nil {
			// Keep what is in force: falling back to the env defaults on a
			// database hiccup would resize every node and move the 429
			// threshold for no reason.
			if ctx.Err() == nil {
				slog.WarnContext(ctx, "ingest settings unavailable, keeping the current ones", "error", err)
			}
			return
		}
		if set.MaxQueueDepth != nil {
			maxDepth = *set.MaxQueueDepth
		}
		// The worker override is for worker nodes only: a web-only node
		// (INGEST_WORKERS=0, the web/worker split) never starts workers.
		if set.Workers != nil && m.defaultWorkers > 0 {
			workers = *set.Workers
		}
	}
	m.maxDepth.Store(int64(maxDepth))
	if m.pool != nil {
		m.pool.Resize(ctx, workers)
	}
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
	peak := m.maxDepth.Load()
	return peak > 0 && m.pending.Load() >= peak
}

// EffectiveMaxDepth returns the queue-depth backpressure threshold currently
// in force: the stored override if one is set, else the configured default.
func (m *QueueMonitor) EffectiveMaxDepth() int {
	return int(m.maxDepth.Load())
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
	ingestMeter       = otel.Meter("github.com/xilasec/xila-api/internal/scan")
	jobsProcessed     metric.Int64Counter
	jobDuration       metric.Float64Histogram
	outcomeKey        = attribute.Key("outcome")
	errInstrumentInit error
)

func init() {
	jobsProcessed, errInstrumentInit = ingestMeter.Int64Counter("xila.ingest.jobs",
		metric.WithDescription("Ingest jobs run by a worker"),
		metric.WithUnit("{job}"))
	if errInstrumentInit != nil {
		return
	}
	jobDuration, errInstrumentInit = ingestMeter.Float64Histogram("xila.ingest.job.duration",
		metric.WithDescription("Time a worker spent running one ingest job end to end"),
		metric.WithUnit("s"))
}

// observeJob records the outcome and cost of one job. Together with the queue
// gauges this is enough to answer the only question that matters under load:
// are we draining faster than we're filling?
func observeJob(ctx context.Context, start time.Time, err error) {
	if errInstrumentInit != nil {
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
