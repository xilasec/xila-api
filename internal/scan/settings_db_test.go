package scan_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/scan"
)

// TestIngestSettingsRoundTrip covers M11 11.7's storage: a fresh install has
// no override (both fields null), saving one persists it, and saving nulls
// again reverts to "use the env default".
func TestIngestSettingsRoundTrip(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)

	got, err := repo.GetIngestSettings(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MaxQueueDepth != nil || got.Workers != nil {
		t.Fatalf("fresh install settings = %+v, want both nil", got)
	}

	depth, workers := 500, 8
	out, err := repo.PutIngestSettings(ctx, scan.IngestSettings{MaxQueueDepth: &depth, Workers: &workers})
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if out.MaxQueueDepth == nil || *out.MaxQueueDepth != 500 || out.Workers == nil || *out.Workers != 8 {
		t.Errorf("saved settings = %+v, want depth 500 workers 8", out)
	}

	// Reading it back agrees (a second node picking it up on its next sample).
	got, err = repo.GetIngestSettings(ctx)
	if err != nil || got.MaxQueueDepth == nil || *got.MaxQueueDepth != 500 {
		t.Fatalf("get after put = %+v, err %v", got, err)
	}

	// Clearing reverts to "use the env default".
	out, err = repo.PutIngestSettings(ctx, scan.IngestSettings{})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if out.MaxQueueDepth != nil || out.Workers != nil {
		t.Errorf("cleared settings = %+v, want both nil", out)
	}
}

// TestIngestSettingsRejectsNegative mirrors the sla_settings pattern: the
// database CHECK constraint is the one source of truth for valid ranges.
func TestIngestSettingsRejectsNegative(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)

	bad := -1
	_, err := repo.PutIngestSettings(ctx, scan.IngestSettings{Workers: &bad})
	if err == nil {
		t.Fatal("negative workers must be rejected")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Errorf("error = %v, want a 23514 check_violation", err)
	}
}
