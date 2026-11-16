package scan

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeSettingsSampler struct {
	settings IngestSettings
	err      error
}

func (f *fakeSettingsSampler) GetIngestSettings(context.Context) (IngestSettings, error) {
	return f.settings, f.err
}

// TestQueueMonitorAppliesLiveSettings is M11 11.7's core contract: an operator
// override changes both the queue-depth backpressure threshold and this
// node's worker pool size within one sample, no restart — and clearing the
// override reverts to the configured defaults.
func TestQueueMonitorAppliesLiveSettings(t *testing.T) {
	src := &stubSampler{stats: QueueStats{Pending: 50}}
	settings := &fakeSettingsSampler{}
	pool := NewWorkerPool(fakeIdleClaimer{}, fakeRunner{}, 20*time.Millisecond, 3)
	defer pool.Stop()

	m := NewQueueMonitor(src, time.Minute, 100).WithLiveSettings(settings, pool, 2)

	// No override yet: the configured defaults apply.
	m.sample(context.Background())
	if m.EffectiveMaxDepth() != 100 {
		t.Errorf("effective max depth = %d, want 100 (default)", m.EffectiveMaxDepth())
	}
	waitForActive(t, pool, 2)

	// The operator lowers the queue-depth threshold and raises the worker
	// count — both apply on the very next sample.
	depth, workers := 10, 5
	settings.settings = IngestSettings{MaxQueueDepth: &depth, Workers: &workers}
	m.sample(context.Background())

	if m.EffectiveMaxDepth() != 10 {
		t.Errorf("effective max depth = %d, want 10 (override)", m.EffectiveMaxDepth())
	}
	if !m.Saturated() {
		t.Error("pending=50 past the lowered limit of 10 must saturate")
	}
	waitForActive(t, pool, 5)

	// Clearing the override (both fields null) reverts to the env defaults.
	settings.settings = IngestSettings{}
	m.sample(context.Background())
	if m.EffectiveMaxDepth() != 100 {
		t.Errorf("effective max depth after clearing override = %d, want 100", m.EffectiveMaxDepth())
	}
	waitForActive(t, pool, 2)
}

// A web-only node (INGEST_WORKERS=0) ignores the worker override, so live
// tuning can't undo the web/worker split; the depth override still applies.
func TestQueueMonitorWebOnlyNodeIgnoresWorkerOverride(t *testing.T) {
	depth, workers := 10, 5
	settings := &fakeSettingsSampler{settings: IngestSettings{MaxQueueDepth: &depth, Workers: &workers}}
	pool := NewWorkerPool(fakeIdleClaimer{}, fakeRunner{}, 20*time.Millisecond, 3)
	defer pool.Stop()
	m := NewQueueMonitor(&stubSampler{}, time.Minute, 100).WithLiveSettings(settings, pool, 0)
	m.sample(context.Background())
	if pool.Count() != 0 {
		t.Errorf("web-only node runs %d workers, want 0", pool.Count())
	}
	if m.EffectiveMaxDepth() != 10 {
		t.Errorf("effective max depth = %d, want the override 10", m.EffectiveMaxDepth())
	}
}

// When the settings can't be read, what is in force stays: no resize back
// to the env defaults on a database hiccup.
func TestQueueMonitorKeepsSettingsOnReadError(t *testing.T) {
	depth, workers := 10, 4
	settings := &fakeSettingsSampler{settings: IngestSettings{MaxQueueDepth: &depth, Workers: &workers}}
	pool := NewWorkerPool(fakeIdleClaimer{}, fakeRunner{}, 20*time.Millisecond, 3)
	defer pool.Stop()
	m := NewQueueMonitor(&stubSampler{}, time.Minute, 100).WithLiveSettings(settings, pool, 2)
	m.sample(context.Background())
	settings.err = errors.New("connection refused")
	m.sample(context.Background())
	if pool.Count() != 4 || m.EffectiveMaxDepth() != 10 {
		t.Errorf("after a failed read: %d workers, depth %d; want 4 and 10", pool.Count(), m.EffectiveMaxDepth())
	}
}
