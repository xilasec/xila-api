package scan

import (
	"context"
	"fmt"
	"time"
)

// IngestSettings are the instance-wide operator overrides for ingest tuning
// (M11 11.7): the queue-depth backpressure threshold and the worker count per
// node, changeable at runtime without a restart. A nil field means "use the
// env default" (INGEST_MAX_QUEUE_DEPTH / INGEST_WORKERS) — this is a singleton
// row, like sla_settings.
type IngestSettings struct {
	MaxQueueDepth *int      `json:"max_queue_depth"`
	Workers       *int      `json:"workers"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// GetIngestSettings returns the current overrides.
func (r *Repository) GetIngestSettings(ctx context.Context) (IngestSettings, error) {
	var s IngestSettings
	if err := r.db.QueryRow(ctx, `SELECT max_queue_depth, workers, updated_at FROM ingest_settings`).
		Scan(&s.MaxQueueDepth, &s.Workers, &s.UpdatedAt); err != nil {
		return IngestSettings{}, fmt.Errorf("get ingest settings: %w", err)
	}
	return s, nil
}

// PutIngestSettings stores the overrides. Every node picks up the change on
// its next queue sample (QueueMonitor.sample): the backpressure threshold and
// that node's worker count change within one sample interval, no restart.
func (r *Repository) PutIngestSettings(ctx context.Context, s IngestSettings) (IngestSettings, error) {
	var out IngestSettings
	err := r.db.QueryRow(ctx, `
		INSERT INTO ingest_settings (id, max_queue_depth, workers, updated_at)
		VALUES (true, $1, $2, now())
		ON CONFLICT (id) DO UPDATE SET
			max_queue_depth = EXCLUDED.max_queue_depth,
			workers = EXCLUDED.workers,
			updated_at = now()
		RETURNING max_queue_depth, workers, updated_at`,
		s.MaxQueueDepth, s.Workers).
		Scan(&out.MaxQueueDepth, &out.Workers, &out.UpdatedAt)
	if err != nil {
		return IngestSettings{}, fmt.Errorf("put ingest settings: %w", err)
	}
	return out, nil
}
