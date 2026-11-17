package computed

import (
	"reflect"
	"testing"

	"github.com/xilasec/xila-api/internal/asset"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/triage"
)

// findingDoc must be exactly triage.FindingDoc (the document triage rules
// evaluate) when no field is computed — one shared builder, not a copy.
func TestFindingDocMatchesTriageWhenNothingComputed(t *testing.T) {
	f := finding.Finding{Scanner: "trivy", Severity: domain.SeverityCritical, Status: domain.FindingOpen,
		KEV: true, Custom: map[string]any{"owner": "alice"}}
	facts := triage.ProjectFacts{Criticality: domain.CriticalityHigh, Custom: map[string]any{"tier": "gold"}}
	got := findingDoc(f, facts, nil, nil)
	want := triage.FindingDoc(f, facts)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findingDoc diverged from triage.FindingDoc:\n got  %#v\n want %#v", got, want)
	}
}

// A computed field never sees computed fields: its own document drops every
// computed key from finding.custom and project.custom, while an ordinary
// (person-set) key stays visible.
func TestFindingDocStripsComputedKeys(t *testing.T) {
	f := finding.Finding{Custom: map[string]any{"owner": "alice", "urgency": "urgent"}}
	facts := triage.ProjectFacts{Custom: map[string]any{"tier": "gold", "risk_score": "90"}}
	findingFields := []customfield.Definition{{Key: "urgency", Computed: true}, {Key: "owner"}}
	projectFields := []customfield.Definition{{Key: "risk_score", Computed: true}, {Key: "tier"}}

	doc := findingDoc(f, facts, findingFields, projectFields)
	fc := doc["finding"].(map[string]any)["custom"].(map[string]any)
	if _, had := fc["urgency"]; had {
		t.Error("computed finding key urgency not stripped")
	}
	if fc["owner"] != "alice" {
		t.Errorf("non-computed finding key dropped: %+v", fc)
	}
	pc := doc["project"].(map[string]any)["custom"].(map[string]any)
	if _, had := pc["risk_score"]; had {
		t.Error("computed project key risk_score not stripped")
	}
	if pc["tier"] != "gold" {
		t.Errorf("non-computed project key dropped: %+v", pc)
	}
}

// The save-time schema sample mirrors the stripped document exactly, so the
// dry run can't accept a field runtime evaluation would never see.
func TestFindingSchemaForStripsComputedKeys(t *testing.T) {
	findingFields := []customfield.Definition{{Key: "urgency", Computed: true}}
	s := findingSchemaFor(findingFields, nil)
	fc := s.Sample["finding"].(map[string]any)["custom"].(map[string]any)
	if _, had := fc["urgency"]; had {
		t.Error("computed key present in schema sample")
	}
}

func TestProjectDoc(t *testing.T) {
	p := project.Project{Name: "web", Slug: "web", Tags: []string{"pci"},
		BusinessCriticality: domain.CriticalityHigh, Custom: map[string]any{"owner": "bob", "score": "99"}}
	defs := []customfield.Definition{{Key: "score", Computed: true}}
	open := map[string]any{"critical": int64(3)}
	doc := projectDoc(p, open, defs)
	proj := doc["project"].(map[string]any)
	if proj["name"] != "web" || proj["slug"] != "web" || proj["criticality"] != "high" {
		t.Errorf("project facts = %+v", proj)
	}
	custom := proj["custom"].(map[string]any)
	if custom["owner"] != "bob" {
		t.Errorf("custom = %+v", custom)
	}
	if _, had := custom["score"]; had {
		t.Error("computed project key score not stripped from its own doc")
	}
	if proj["open_findings"].(map[string]any)["critical"] != int64(3) {
		t.Errorf("open_findings = %+v", proj["open_findings"])
	}
}

func TestAssetDoc(t *testing.T) {
	exposure := domain.ExposureInternet
	a := asset.Asset{Name: "api", Type: domain.AssetHost, Identifier: "10.0.0.1",
		Exposure: &exposure, Custom: map[string]any{"owner": "carol"}}
	projSection := map[string]any{"project": map[string]any{"name": "web"}}
	doc := assetDoc(a, projSection, nil)
	assetSec := doc["asset"].(map[string]any)
	if assetSec["name"] != "api" || assetSec["type"] != "host" || assetSec["exposure"] != "internet" {
		t.Errorf("asset facts = %+v", assetSec)
	}
	if doc["project"].(map[string]any)["name"] != "web" {
		t.Errorf("project section not carried over: %+v", doc["project"])
	}
}

// Unknown exposure is null, never a guess.
func TestAssetDocUnknownExposure(t *testing.T) {
	a := asset.Asset{Name: "api"}
	doc := assetDoc(a, map[string]any{}, nil)
	if doc["asset"].(map[string]any)["exposure"] != nil {
		t.Errorf("exposure = %v, want nil", doc["asset"].(map[string]any)["exposure"])
	}
}
