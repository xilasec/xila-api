package gate

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/xilasec/xila-api/internal/notify"
)

// notifier is the slice of notify.Service the evaluator needs.
type notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Evaluator re-evaluates a project's gate under its effective policy and
// stores the result (project_gate_state), emitting gate.changed when it
// flips pass<->fail. It is a thin wrapper around the existing Evaluate +
// Repository — the gate logic itself is not forked.
type Evaluator struct {
	policies *Repository
	stats    statsProvider
	versions versionFinder
	notifier notifier // optional
}

// NewEvaluator constructs an Evaluator. notifier may be nil (state is still
// stored; gate.changed is just never raised).
func NewEvaluator(policies *Repository, stats statsProvider, versions versionFinder, notifier notifier) *Evaluator {
	return &Evaluator{policies: policies, stats: stats, versions: versions, notifier: notifier}
}

// EvaluateVersion re-evaluates and stores one project version's gate result
// under the project's effective policy (its own, else the global default),
// using the policy's own NewOnly/BaselineBranch settings — same as an
// unparameterized POST /projects/{id}/gate. versionID "" evaluates (and
// stores under) the project's current default version. An unresolved
// baseline branch (deleted since the policy was set) degrades to "no
// baseline" rather than failing: unlike the on-demand endpoint, a background
// re-evaluation must not error out on stale config.
func (e *Evaluator) EvaluateVersion(ctx context.Context, projectID, versionID string) (Result, error) {
	policy, scope, err := e.policies.Effective(ctx, projectID)
	if err != nil {
		return Result{}, err
	}

	var baselineVersionID string
	if policy.BaselineBranch != nil {
		if id, ok, err := e.versions.FindVersion(ctx, projectID, *policy.BaselineBranch); err != nil {
			return Result{}, err
		} else if ok {
			baselineVersionID = id
		}
	}

	stats, err := e.stats.ComputeGateStats(ctx, projectID, versionID, policy.NewOnly, baselineVersionID)
	if err != nil {
		return Result{}, err
	}
	result := Evaluate(policy, stats)
	result.Scope = scope
	result.VersionID = versionID
	result.NewOnly = policy.NewOnly

	// The state table always keys on a concrete version id.
	storedVersionID := versionID
	if storedVersionID == "" {
		id, ok, err := e.versions.FindVersion(ctx, projectID, "")
		if err != nil {
			return result, err
		}
		if !ok {
			return result, nil // no version yet (a brand-new project): nothing to store
		}
		storedVersionID = id
	}

	prev, had, err := e.policies.GetState(ctx, projectID, storedVersionID)
	if err != nil {
		return result, err
	}
	if err := e.policies.UpsertState(ctx, State{
		ProjectID: projectID, VersionID: storedVersionID, Passed: result.Passed,
		Scope: scope, NewOnly: policy.NewOnly, Violations: result.Violations,
	}); err != nil {
		return result, err
	}
	if had && prev.Passed != result.Passed && e.notifier != nil {
		title := "Gate now failing"
		if result.Passed {
			title = "Gate now passing"
		}
		e.notifier.Notify(ctx, notify.Event{
			Type: notify.EventGateChanged, Title: title, ProjectID: projectID,
			Fields: map[string]string{"passed": fmt.Sprintf("%t", result.Passed), "version_id": storedVersionID},
		})
	}
	slog.DebugContext(ctx, "gate state re-evaluated", "project_id", projectID, "version_id", storedVersionID, "passed", result.Passed)
	return result, nil
}

// Reevaluate is EvaluateVersion without the Result, for callers (scan ingest,
// exploit intel) that only need to trigger the recompute and log a failure.
func (e *Evaluator) Reevaluate(ctx context.Context, projectID, versionID string) error {
	_, err := e.EvaluateVersion(ctx, projectID, versionID)
	return err
}

// EvaluateAllDefaults re-evaluates every project's default-version gate —
// the leader-interval sweep that catches enrichment/vulnmatch/pkgmeta/exploit
// changes an ingest-triggered Reevaluate didn't directly see.
func (e *Evaluator) EvaluateAllDefaults(ctx context.Context, projectIDs []string) (evaluated, failed int) {
	for _, id := range projectIDs {
		if _, err := e.EvaluateVersion(ctx, id, ""); err != nil {
			slog.WarnContext(ctx, "gate sweep: project failed", "project_id", id, "error", err)
			failed++
			continue
		}
		evaluated++
	}
	return evaluated, failed
}
