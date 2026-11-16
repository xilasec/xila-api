package scan

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// fakePayloadStore is an in-memory PayloadStore (no S3): object round-trip
// tests live in internal/objectstore against gofakes3; these tests only cover
// how Service.Enqueue/ProcessJob use the interface.
type fakePayloadStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	deletes []string
}

func newFakePayloadStore() *fakePayloadStore { return &fakePayloadStore{objects: map[string][]byte{}} }

func (f *fakePayloadStore) Put(_ context.Context, key string, payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = append([]byte(nil), payload...)
	return nil
}

func (f *fakePayloadStore) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.objects[key]
	if !ok {
		return nil, errNotFound
	}
	return v, nil
}

func (f *fakePayloadStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objects, key)
	f.deletes = append(f.deletes, key)
	return nil
}

func (f *fakePayloadStore) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[key]
	return ok
}

var errNotFound = errors.New("object not found")

// capturingJobs records what Enqueue asked it to persist (fakeJobs in
// handler_test.go only counts calls).
type capturingJobs struct {
	payload    []byte
	payloadRef string
}

func (c *capturingJobs) EnqueueJob(_ context.Context, _ string, payload []byte, payloadRef, _ string, _, _ bool) error {
	c.payload, c.payloadRef = payload, payloadRef
	return nil
}

// Enqueue, configured with a PayloadStore, uploads the payload there instead
// of handing it to scan_jobs.payload, and persists only the object key.
func TestEnqueueWithPayloadStoreUploadsAndStoresRef(t *testing.T) {
	store := newFakePayloadStore()
	jobs := &capturingJobs{}
	svc := NewService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: true}, newTestRegistry(), nil, nil, jobs).
		WithPayloadStore(store)

	sc, err := svc.Enqueue(context.Background(), IngestRequest{ProjectID: "proj-1", Scanner: "trivy"}, []byte(trivyDoc))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	wantRef := "scan-jobs/" + sc.ID
	if jobs.payload != nil {
		t.Errorf("EnqueueJob got a non-nil payload, want nil (it went to the payload store)")
	}
	if jobs.payloadRef != wantRef {
		t.Errorf("EnqueueJob payloadRef = %q, want %q", jobs.payloadRef, wantRef)
	}
	if !store.has(wantRef) {
		t.Errorf("payload store has no object at %q", wantRef)
	}
	if got, _ := store.Get(context.Background(), wantRef); string(got) != trivyDoc {
		t.Errorf("stored payload = %q, want the uploaded report", got)
	}
}

// Without WithPayloadStore, Enqueue behaves exactly as before: the raw bytes
// go to EnqueueJob and no ref is set.
func TestEnqueueWithoutPayloadStoreUsesPostgres(t *testing.T) {
	jobs := &capturingJobs{}
	svc := NewService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: true}, newTestRegistry(), nil, nil, jobs)

	if _, err := svc.Enqueue(context.Background(), IngestRequest{ProjectID: "proj-1", Scanner: "trivy"}, []byte(trivyDoc)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if string(jobs.payload) != trivyDoc || jobs.payloadRef != "" {
		t.Errorf("payload=%q ref=%q, want the raw bytes and no ref", jobs.payload, jobs.payloadRef)
	}
}

// ProcessJob fetches a PayloadRef from the configured store and deletes the
// object once the pipeline completes successfully.
func TestProcessJobFetchesAndDeletesOnSuccess(t *testing.T) {
	store := newFakePayloadStore()
	ref := "scan-jobs/scan-1"
	if err := store.Put(context.Background(), ref, []byte(trivyDoc)); err != nil {
		t.Fatal(err)
	}
	findings := &fakeFindings{}
	svc := NewService(&fakeScans{created: Scan{Scanner: "trivy"}}, findings, fakeProjects{exists: true}, newTestRegistry(), nil, nil, nil).
		WithPayloadStore(store)

	job := Job{ID: "job-1", ScanID: "scan-1", PayloadRef: ref, CloseMissing: true}
	if err := svc.ProcessJob(context.Background(), job); err != nil {
		t.Fatalf("process job: %v", err)
	}
	if len(findings.upserts) != 2 {
		t.Errorf("upserted %d findings, want 2 (fetched payload was parsed)", len(findings.upserts))
	}
	if store.has(ref) {
		t.Errorf("payload object at %q should be deleted after success", ref)
	}
}

// A PayloadRef that resolves to nothing fails the job with a clear error
// rather than processing an empty/garbage payload.
func TestProcessJobMissingPayloadFails(t *testing.T) {
	store := newFakePayloadStore()
	svc := NewService(&fakeScans{created: Scan{Scanner: "trivy"}}, &fakeFindings{}, fakeProjects{exists: true}, newTestRegistry(), nil, nil, nil).
		WithPayloadStore(store)

	job := Job{ID: "job-1", ScanID: "scan-1", PayloadRef: "scan-jobs/scan-1", CloseMissing: true}
	err := svc.ProcessJob(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "fetch queued payload") {
		t.Errorf("process job with a missing payload = %v, want a clear fetch error", err)
	}
}

// A PayloadRef with no configured store is a clear configuration error, not a
// nil-pointer panic — e.g. a worker node started before INGEST_PAYLOAD_STORE
// rolled out everywhere.
func TestProcessJobPayloadRefWithoutStoreFails(t *testing.T) {
	svc := NewService(&fakeScans{created: Scan{Scanner: "trivy"}}, &fakeFindings{}, fakeProjects{exists: true}, newTestRegistry(), nil, nil, nil)

	job := Job{ID: "job-1", ScanID: "scan-1", PayloadRef: "scan-jobs/scan-1", CloseMissing: true}
	err := svc.ProcessJob(context.Background(), job)
	if err == nil || !strings.Contains(err.Error(), "no payload store is configured") {
		t.Errorf("process job without a configured store = %v", err)
	}
}

// A pipeline failure (bad payload) leaves the object in place: the job will
// retry (or, once retries are exhausted, the failed-job retention sweep
// removes it alongside the row) — ProcessJob itself must never delete on
// failure.
func TestProcessJobKeepsPayloadOnFailure(t *testing.T) {
	store := newFakePayloadStore()
	ref := "scan-jobs/scan-1"
	if err := store.Put(context.Background(), ref, []byte("not valid json")); err != nil {
		t.Fatal(err)
	}
	svc := NewService(&fakeScans{created: Scan{Scanner: "trivy"}}, &fakeFindings{}, fakeProjects{exists: true}, newTestRegistry(), nil, nil, nil).
		WithPayloadStore(store)

	job := Job{ID: "job-1", ScanID: "scan-1", PayloadRef: ref, CloseMissing: true}
	if err := svc.ProcessJob(context.Background(), job); err == nil {
		t.Fatal("expected a parse failure for invalid JSON")
	}
	if !store.has(ref) {
		t.Error("payload object should survive a failed attempt (kept for retry)")
	}
}
