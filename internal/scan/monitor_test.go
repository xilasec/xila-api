package scan

import (
	"context"
	"errors"
	"testing"
	"time"
)

type stubSampler struct {
	stats QueueStats
	err   error
	calls int
}

func (s *stubSampler) QueueStats(context.Context) (QueueStats, error) {
	s.calls++
	return s.stats, s.err
}

func TestSaturatedAtMaxDepth(t *testing.T) {
	src := &stubSampler{stats: QueueStats{Pending: 99}}
	m := NewQueueMonitor(src, time.Minute, 100)
	m.sample(context.Background())

	if m.Saturated() {
		t.Error("99 pending with a limit of 100 must still accept uploads")
	}
	src.stats.Pending = 100
	m.sample(context.Background())
	if !m.Saturated() {
		t.Error("at the limit the queue must shed load")
	}

	// Zero means "accept unboundedly" — backpressure is opt-out.
	unbounded := NewQueueMonitor(&stubSampler{stats: QueueStats{Pending: 1 << 20}}, time.Minute, 0)
	unbounded.sample(context.Background())
	if unbounded.Saturated() {
		t.Error("maxDepth 0 must never saturate")
	}
}

func TestSnapshotSurvivesSamplingFailure(t *testing.T) {
	src := &stubSampler{stats: QueueStats{Pending: 7, Processing: 2, Failed: 1, OldestWait: 90 * time.Second}}
	m := NewQueueMonitor(src, time.Minute, 10)
	m.sample(context.Background())

	// A failed sample must not zero the snapshot: reporting an empty queue when
	// the database is unreachable would silently disable backpressure exactly when
	// the system is least healthy.
	src.err = errors.New("db down")
	m.sample(context.Background())

	got := m.Snapshot()
	if got.Pending != 7 || got.Processing != 2 || got.Failed != 1 || got.OldestWaitSeconds != 90 {
		t.Errorf("snapshot = %+v, want the last good sample (7/2/1, 90s)", got)
	}
}
