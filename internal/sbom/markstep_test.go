package sbom

import (
	"context"
	"testing"
)

// recordingStore records the state of the context each MarkStep arrives with.
type recordingStore struct {
	sbomStore
	ctxErr error
	status string
}

func (r *recordingStore) MarkStep(ctx context.Context, _, _, status, _ string) (ProcessingStatus, error) {
	r.ctxErr, r.status = ctx.Err(), status
	return ProcessingStatus{}, ctx.Err()
}

// A step that failed because its own deadline expired must still be recorded:
// otherwise the upload reads "running" forever and CI waiting on it hangs.
func TestMarkStepOutlivesTheStepDeadline(t *testing.T) {
	store := &recordingStore{}
	s := &Service{store: store}
	expired, cancel := context.WithCancel(context.Background())
	cancel()

	s.markStep(expired, "sbom-1", StepVulnMatch, StepFailed, "advisory match failed")

	if store.status != StepFailed {
		t.Fatalf("MarkStep recorded %q, want %q", store.status, StepFailed)
	}
	if store.ctxErr != nil {
		t.Errorf("MarkStep ran on a done context (%v): the failure would never be recorded", store.ctxErr)
	}
}
