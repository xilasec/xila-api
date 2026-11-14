package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// fakeJobs accepts enqueues without a database.
type fakeJobs struct{ enqueued int }

func (f *fakeJobs) EnqueueJob(context.Context, string, []byte, string, bool) error {
	f.enqueued++
	return nil
}

func upload(t *testing.T, app *fiber.App) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/projects/00000000-0000-0000-0000-000000000001/scans?scanner=trivy",
		strings.NewReader(trivyDoc))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

// TestUploadShedsLoadWhenQueueSaturated: a queued-but-unprocessable scan is worse
// than a rejected one — the client believes it was ingested and gates on a
// backlog we never updated. So once the queue is past its limit, uploads are
// refused with 429 + Retry-After instead of being accepted.
func TestUploadShedsLoadWhenQueueSaturated(t *testing.T) {
	jobs := &fakeJobs{}
	svc := NewService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: true},
		newTestRegistry(), nil, nil, jobs)

	mon := NewQueueMonitor(&stubSampler{stats: QueueStats{Pending: 500}}, time.Minute, 100)
	mon.sample(t.Context())

	app := fiber.New()
	NewHandler(nil, svc, true, mon).Register(app)

	resp := upload(t, app)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429 when the queue is saturated", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a shed upload must tell the client when to come back (Retry-After)")
	}
	if jobs.enqueued != 0 {
		t.Errorf("enqueued %d jobs; a shed upload must not reach the queue", jobs.enqueued)
	}
}

// Below the limit the upload is queued as normal (202).
func TestUploadAcceptedBelowLimit(t *testing.T) {
	jobs := &fakeJobs{}
	svc := NewService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: true},
		newTestRegistry(), nil, nil, jobs)

	mon := NewQueueMonitor(&stubSampler{stats: QueueStats{Pending: 99}}, time.Minute, 100)
	mon.sample(t.Context())

	app := fiber.New()
	NewHandler(nil, svc, true, mon).Register(app)

	resp := upload(t, app)
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", resp.StatusCode)
	}
	if jobs.enqueued != 1 {
		t.Errorf("enqueued = %d, want 1", jobs.enqueued)
	}
}
