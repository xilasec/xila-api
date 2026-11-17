package computed

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/customfield"
)

func TestComputedOnly(t *testing.T) {
	defs := []customfield.Definition{{Key: "a", Computed: true}, {Key: "b"}, {Key: "c", Computed: true}}
	got := computedOnly(defs)
	if len(got) != 2 || got[0].Key != "a" || got[1].Key != "c" {
		t.Errorf("computedOnly = %+v", got)
	}
}

// evalChanges writes a changed value, unsets a value that no longer fits (or
// errored, or evaluated to null) — never a guess — and leaves an unchanged
// value alone (idempotent).
func TestEvalChanges(t *testing.T) {
	urgency := customfield.Definition{Key: "urgency", Type: customfield.TypeEnum, Options: []string{"urgent", "normal"}, Expression: `finding.kev ? "urgent" : "normal"`}
	stale := customfield.Definition{Key: "stale", Type: customfield.TypeText, Expression: `finding.missing`} // always null: no such fact
	defs := []customfield.Definition{urgency, stale}
	programs, err := loadPrograms([]string{"finding"}, defs)
	if err != nil {
		t.Fatalf("loadPrograms: %v", err)
	}

	doc := map[string]any{"finding": map[string]any{"kev": true}}

	// New urgency, and a stale value whose expression no longer fits (null —
	// no such fact) leaves the field unset rather than keeping the old value.
	set, unset := evalChanges(context.Background(), defs, programs, doc, map[string]any{"stale": "old"})
	if set["urgency"] != "urgent" || len(unset) != 1 || unset[0] != "stale" {
		t.Errorf("first run: set=%+v unset=%v", set, unset)
	}

	// Idempotent: already at the target value, stale already unset.
	set, unset = evalChanges(context.Background(), defs, programs, doc, map[string]any{"urgency": "urgent"})
	if len(set) != 0 || len(unset) != 0 {
		t.Errorf("idempotent run changed something: set=%+v unset=%v", set, unset)
	}

	// Changed: kev went false, so urgency now fits "normal".
	doc2 := map[string]any{"finding": map[string]any{"kev": false}}
	set, unset = evalChanges(context.Background(), defs, programs, doc2, map[string]any{"urgency": "urgent"})
	if set["urgency"] != "normal" || len(unset) != 0 {
		t.Errorf("changed run: set=%+v unset=%v", set, unset)
	}
}

type fakeFields struct {
	org string
	err error
}

func (f fakeFields) List(context.Context, customfield.Entity) ([]customfield.Definition, error) {
	return nil, nil
}
func (f fakeFields) OrgOfProject(context.Context, string) (string, error) { return f.org, f.err }
func (f fakeFields) SetValues(context.Context, customfield.Entity, string, map[string]any, []string) (map[string]any, error) {
	return nil, nil
}

func TestApplicableDefs(t *testing.T) {
	orgA, orgB := "org-a", "org-b"
	global := customfield.Definition{Key: "g"}
	scopedA := customfield.Definition{Key: "a", OrgID: &orgA}

	// No organization-scoped definitions: no lookup needed, everything applies.
	got, err := applicableDefs(context.Background(), fakeFields{err: context.Canceled}, []customfield.Definition{global}, "p1")
	if err != nil || len(got) != 1 {
		t.Errorf("unscoped: got %+v, %v", got, err)
	}

	// Scoped definition: applies only to its organization's projects.
	got, err = applicableDefs(context.Background(), fakeFields{org: orgA}, []customfield.Definition{global, scopedA}, "p1")
	if err != nil || len(got) != 2 {
		t.Errorf("matching org: got %+v, %v", got, err)
	}
	got, err = applicableDefs(context.Background(), fakeFields{org: orgB}, []customfield.Definition{global, scopedA}, "p1")
	if err != nil || len(got) != 1 || got[0].Key != "g" {
		t.Errorf("other org: got %+v, %v", got, err)
	}
}
