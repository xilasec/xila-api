package policy_test

import (
	"os"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/policy"
	"github.com/xilasec/xila-api/internal/sbom"
)

// uploadFixture ingests an SBOM from internal/sbom/testdata.
func (e *env) uploadFixture(projectID, name string) {
	e.t.Helper()
	f, err := os.Open("../sbom/testdata/" + name)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	if _, err := e.sboms.Ingest(e.ctx, sbom.IngestRequest{ProjectID: projectID}, f); err != nil {
		e.t.Fatalf("upload %s: %v", name, err)
	}
}

// An approved-models list: the CycloneDX spec's Llama 2 ML-BOM (a hub model
// outside the list) raises a policy finding on upload; an SBOM without the
// model closes it. A policy on model facts never flags the dataset.
func TestUnapprovedModelViolation(t *testing.T) {
	e := setup(t)
	p := e.project()
	e.create(draft("Approved models only", cond(policy.SubjectModelName, policy.OpNoMatch, `["mistralai/*", "google/flan-t5-*"]`)))

	e.uploadFixture(p, "machine-learning-env-1.6.cdx.json")
	vs := open(e.violations(p))
	if len(vs) != 1 {
		t.Fatalf("violations = %d (%v), want 1 (Llama-2-7b)", len(vs), vs)
	}
	v := vs[0]
	if v.PackageName != "Llama-2-7b" || v.Category != domain.CategorySCA ||
		v.Title != `Policy "Approved models only" violated by meta-llama/Llama-2-7b` {
		t.Errorf("violation = %s / %s / %s", v.PackageName, v.Category, v.Title)
	}

	// The next SBOM of the artifact ships only a data component: the model
	// is gone, so its violation closes; the dataset isn't a model.
	e.uploadFixture(p, "component-data-1.6.cdx.json")
	got, err := e.findings.Get(e.ctx, v.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingRemediated {
		t.Errorf("status after the model left = %s, want remediated", got.Status)
	}
	if again := open(e.violations(p)); len(again) != 0 {
		t.Errorf("open violations = %v, want none", again)
	}
}
