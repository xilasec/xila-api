// Package computed evaluates "computed" custom fields: a field definition
// that carries a CEL expression instead of being set by a person. The value
// is recomputed from the entity's facts and stored in the same `custom`
// column every other field uses (customfield.Repository.SetValues /
// finding.Repository.SetCustom), so filters, exports, history and other CEL
// expressions see it exactly like a hand-set value; only a direct write to it
// is refused (customfield.Service.Prepare).
//
// Values are kept fresh three ways: ApplyToScan (a scan.Applier run after the
// triage rules, scoped to the scan's findings) on every ingest; RecomputeDefinition,
// a full backfill of one entity type, when a computed definition is created or
// its expression changes; and RunSweep on COMPUTED_FIELDS_INTERVAL, which
// recomputes every project, asset and finding in batches (grouped per project)
// so facts nothing re-ingests — EPSS/KEV, status changes, exposure, package
// metadata — still reach a computed field within one interval. Every pass
// writes only the rows whose target value actually changed.
package computed

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/xilasec/xila-api/internal/asset"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/triage"
)

// computedActor attributes a recompute in a finding's history, like a triage
// rule's "triage-rule:<name>" (internal/finding.Repository.SetCustom).
const computedActor = "computed-fields"

// sweepBatchLimit caps how many findings one project's periodic recompute
// reads at once (internal/finding.Repository.List; generous since a project's
// findings are the natural batch — see RecomputeFindings).
const sweepBatchLimit = 50_000

// fieldStore is the subset of customfield.Repository this package needs.
type fieldStore interface {
	List(ctx context.Context, entity customfield.Entity) ([]customfield.Definition, error)
	OrgOfProject(ctx context.Context, projectID string) (string, error)
	SetValues(ctx context.Context, entity customfield.Entity, id string, set map[string]any, unset []string) (map[string]any, error)
}

// findingFacts resolves a project's triage facts (criticality, custom) —
// triage.Repository satisfies it.
type findingFacts interface {
	ProjectFacts(ctx context.Context, projectID string) (triage.ProjectFacts, error)
}

// findingStore is the subset of finding.Repository this package needs.
type findingStore interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	SetCustom(ctx context.Context, id string, set map[string]any, unset []string, actor, note string) (map[string]any, error)
	ProjectIDsWithFindings(ctx context.Context) ([]string, error)
	CountByProjects(ctx context.Context, projectIDs []string) ([]finding.StatusSeverityCount, error)
}

// projectStore is the subset of project.Repository this package needs.
type projectStore interface {
	List(ctx context.Context, teamID string, scopeProjectIDs []string, custom []customfield.Cond, archived bool) ([]project.Project, error)
	Get(ctx context.Context, id string) (project.Project, error)
}

// assetStore is the subset of asset.Repository this package needs.
type assetStore interface {
	List(ctx context.Context, f asset.Filter) ([]asset.Asset, error)
}

// Service recomputes computed custom-field values.
type Service struct {
	fields   fieldStore
	findings findingStore
	facts    findingFacts
	projects projectStore
	assets   assetStore
}

// NewService constructs a Service.
func NewService(fields fieldStore, findings findingStore, facts findingFacts, projects projectStore, assets assetStore) *Service {
	return &Service{fields: fields, findings: findings, facts: facts, projects: projects, assets: assets}
}

// Name identifies this pass in the ingest pipeline (scan.Applier).
func (s *Service) Name() string { return "computed-fields" }

// Validate compiles a computed definition's expression against the facts its
// entity would see and rejects a result type CEL can already prove will
// never fit the field (customfield.Handler.WithComputedValidator).
func (s *Service) Validate(ctx context.Context, d customfield.Definition) error {
	schema, err := s.schemaFor(ctx, d.Entity)
	if err != nil {
		return err
	}
	prog, err := expr.CompileValue(schema, d.Expression)
	if err != nil {
		return err
	}
	if !d.Type.FitsOutputType(prog.OutputType) {
		return fmt.Errorf("expression always evaluates to %s, which never fits a %s field", prog.OutputType, d.Type)
	}
	return nil
}

func (s *Service) schemaFor(ctx context.Context, entity customfield.Entity) (expr.Schema, error) {
	switch entity {
	case customfield.EntityFinding:
		findingFields, err := s.fields.List(ctx, customfield.EntityFinding)
		if err != nil {
			return expr.Schema{}, err
		}
		projectFields, err := s.fields.List(ctx, customfield.EntityProject)
		if err != nil {
			return expr.Schema{}, err
		}
		return findingSchemaFor(findingFields, projectFields), nil
	case customfield.EntityProject:
		projectFields, err := s.fields.List(ctx, customfield.EntityProject)
		if err != nil {
			return expr.Schema{}, err
		}
		return projectSchemaFor(projectFields), nil
	case customfield.EntityAsset:
		assetFields, err := s.fields.List(ctx, customfield.EntityAsset)
		if err != nil {
			return expr.Schema{}, err
		}
		projectFields, err := s.fields.List(ctx, customfield.EntityProject)
		if err != nil {
			return expr.Schema{}, err
		}
		return assetSchemaFor(assetFields, projectFields), nil
	}
	return expr.Schema{}, fmt.Errorf("computed fields: unknown entity %q", entity)
}

// ApplyToScan recomputes the computed finding fields of the scan's findings
// (scan.Applier, run right after the triage rules). Idempotent: a finding
// already at its target value is left untouched.
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	findingFields, err := s.fields.List(ctx, customfield.EntityFinding)
	if err != nil {
		return 0, err
	}
	computedFields := computedOnly(findingFields)
	if len(computedFields) == 0 {
		return 0, nil
	}
	projectFields, err := s.fields.List(ctx, customfield.EntityProject)
	if err != nil {
		return 0, err
	}
	applicable, err := applicableDefs(ctx, s.fields, computedFields, projectID)
	if err != nil {
		return 0, err
	}
	if len(applicable) == 0 {
		return 0, nil
	}
	programs, err := loadPrograms(findingSchemaVars, applicable)
	if err != nil {
		return 0, err
	}
	facts, err := s.facts.ProjectFacts(ctx, projectID)
	if err != nil {
		return 0, err
	}
	findings, err := s.findings.List(ctx, finding.Filter{ProjectID: projectID, ScanID: scanID})
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, f := range findings {
		doc := findingDoc(f, facts, findingFields, projectFields)
		set, unset := evalChanges(ctx, applicable, programs, doc, f.Custom)
		if len(set) == 0 && len(unset) == 0 {
			continue
		}
		if _, err := s.findings.SetCustom(ctx, f.ID, set, unset, computedActor, "recomputed custom fields"); err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// RecomputeProjects recomputes every project's computed custom fields. One
// failing project doesn't stop the sweep.
func (s *Service) RecomputeProjects(ctx context.Context) (int, error) {
	defs, err := s.fields.List(ctx, customfield.EntityProject)
	if err != nil {
		return 0, err
	}
	computedFields := computedOnly(defs)
	if len(computedFields) == 0 {
		return 0, nil
	}
	programs, err := loadPrograms(projectSchemaVars, computedFields)
	if err != nil {
		return 0, err
	}
	projects, err := s.projects.List(ctx, "", nil, nil, false)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, p := range projects {
		applicable, err := applicableDefs(ctx, s.fields, computedFields, p.ID)
		if err != nil {
			slog.WarnContext(ctx, "computed fields: project scope lookup failed", "project_id", p.ID, "error", err)
			continue
		}
		if len(applicable) == 0 {
			continue
		}
		counts, err := s.findings.CountByProjects(ctx, []string{p.ID})
		if err != nil {
			slog.WarnContext(ctx, "computed fields: project finding counts failed", "project_id", p.ID, "error", err)
			continue
		}
		doc := projectDoc(p, openFindingCounts(counts), defs)
		set, unset := evalChanges(ctx, applicable, programs, doc, p.Custom)
		if len(set) == 0 && len(unset) == 0 {
			continue
		}
		if _, err := s.fields.SetValues(ctx, customfield.EntityProject, p.ID, set, unset); err != nil {
			slog.WarnContext(ctx, "computed fields: writing project values failed", "project_id", p.ID, "error", err)
			continue
		}
		changed++
	}
	return changed, nil
}

// RecomputeAssets recomputes every asset's computed custom fields, grouped by
// project so its project.* facts (and the open-finding counts) are built once
// per project. One failing project doesn't stop the sweep.
func (s *Service) RecomputeAssets(ctx context.Context) (int, error) {
	assetDefs, err := s.fields.List(ctx, customfield.EntityAsset)
	if err != nil {
		return 0, err
	}
	computedAssetFields := computedOnly(assetDefs)
	if len(computedAssetFields) == 0 {
		return 0, nil
	}
	projectDefs, err := s.fields.List(ctx, customfield.EntityProject)
	if err != nil {
		return 0, err
	}
	programs, err := loadPrograms(assetSchemaVars, computedAssetFields)
	if err != nil {
		return 0, err
	}
	assets, err := s.assets.List(ctx, asset.Filter{})
	if err != nil {
		return 0, err
	}
	byProject := map[string][]asset.Asset{}
	for _, a := range assets {
		byProject[a.ProjectID] = append(byProject[a.ProjectID], a)
	}
	changed := 0
	for projectID, as := range byProject {
		applicable, err := applicableDefs(ctx, s.fields, computedAssetFields, projectID)
		if err != nil {
			slog.WarnContext(ctx, "computed fields: asset project scope lookup failed", "project_id", projectID, "error", err)
			continue
		}
		if len(applicable) == 0 {
			continue
		}
		p, err := s.projects.Get(ctx, projectID)
		if err != nil {
			slog.WarnContext(ctx, "computed fields: loading asset project failed", "project_id", projectID, "error", err)
			continue
		}
		counts, err := s.findings.CountByProjects(ctx, []string{projectID})
		if err != nil {
			slog.WarnContext(ctx, "computed fields: asset project finding counts failed", "project_id", projectID, "error", err)
			continue
		}
		projSection := projectDoc(p, openFindingCounts(counts), projectDefs)
		for _, a := range as {
			doc := assetDoc(a, projSection, assetDefs)
			set, unset := evalChanges(ctx, applicable, programs, doc, a.Custom)
			if len(set) == 0 && len(unset) == 0 {
				continue
			}
			if _, err := s.fields.SetValues(ctx, customfield.EntityAsset, a.ID, set, unset); err != nil {
				slog.WarnContext(ctx, "computed fields: writing asset values failed", "asset_id", a.ID, "error", err)
				continue
			}
			changed++
		}
	}
	return changed, nil
}

// RecomputeFindings recomputes every project's computed finding fields, in
// per-project batches (see sweepBatchLimit). One failing project doesn't stop
// the sweep.
func (s *Service) RecomputeFindings(ctx context.Context) (int, error) {
	findingFields, err := s.fields.List(ctx, customfield.EntityFinding)
	if err != nil {
		return 0, err
	}
	computedFindingFields := computedOnly(findingFields)
	if len(computedFindingFields) == 0 {
		return 0, nil
	}
	projectFields, err := s.fields.List(ctx, customfield.EntityProject)
	if err != nil {
		return 0, err
	}
	programs, err := loadPrograms(findingSchemaVars, computedFindingFields)
	if err != nil {
		return 0, err
	}
	projectIDs, err := s.findings.ProjectIDsWithFindings(ctx)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, projectID := range projectIDs {
		applicable, err := applicableDefs(ctx, s.fields, computedFindingFields, projectID)
		if err != nil {
			slog.WarnContext(ctx, "computed fields: finding project scope lookup failed", "project_id", projectID, "error", err)
			continue
		}
		if len(applicable) == 0 {
			continue
		}
		facts, err := s.facts.ProjectFacts(ctx, projectID)
		if err != nil {
			slog.WarnContext(ctx, "computed fields: project facts failed", "project_id", projectID, "error", err)
			continue
		}
		findings, err := s.findings.List(ctx, finding.Filter{ProjectID: projectID, AllVersions: true, Limit: sweepBatchLimit})
		if err != nil {
			slog.WarnContext(ctx, "computed fields: listing findings failed", "project_id", projectID, "error", err)
			continue
		}
		for _, f := range findings {
			doc := findingDoc(f, facts, findingFields, projectFields)
			set, unset := evalChanges(ctx, applicable, programs, doc, f.Custom)
			if len(set) == 0 && len(unset) == 0 {
				continue
			}
			if _, err := s.findings.SetCustom(ctx, f.ID, set, unset, computedActor, "recomputed custom fields"); err != nil {
				slog.WarnContext(ctx, "computed fields: writing finding values failed", "finding_id", f.ID, "error", err)
				continue
			}
			changed++
		}
	}
	return changed, nil
}

// RunSweep recomputes projects, assets and findings — the leader job on
// COMPUTED_FIELDS_INTERVAL. One kind failing doesn't stop the others.
func (s *Service) RunSweep(ctx context.Context) (int, error) {
	total := 0
	if n, err := s.RecomputeProjects(ctx); err != nil {
		slog.WarnContext(ctx, "computed fields: project sweep failed", "error", err)
	} else {
		total += n
	}
	if n, err := s.RecomputeAssets(ctx); err != nil {
		slog.WarnContext(ctx, "computed fields: asset sweep failed", "error", err)
	} else {
		total += n
	}
	if n, err := s.RecomputeFindings(ctx); err != nil {
		slog.WarnContext(ctx, "computed fields: finding sweep failed", "error", err)
	} else {
		total += n
	}
	return total, nil
}

// RecomputeDefinition backfills every entity of d's type — the full sweep for
// that one entity kind, reused because a definition change and the periodic
// sweep need exactly the same work (a scoped backfill would duplicate it).
func (s *Service) RecomputeDefinition(ctx context.Context, d customfield.Definition) (int, error) {
	switch d.Entity {
	case customfield.EntityProject:
		return s.RecomputeProjects(ctx)
	case customfield.EntityAsset:
		return s.RecomputeAssets(ctx)
	case customfield.EntityFinding:
		return s.RecomputeFindings(ctx)
	}
	return 0, fmt.Errorf("computed fields: unknown entity %q", d.Entity)
}

// OnDefinitionChanged backfills every entity of d's entity type synchronously
// (customfield.Handler.WithComputedChanged runs this inside the request that
// created or edited the definition, so the response already reflects the new
// values). A failure here is logged, not propagated — the definition was
// already saved validly, and the next periodic sweep catches a transient error.
func (s *Service) OnDefinitionChanged(ctx context.Context, d customfield.Definition) {
	if _, err := s.RecomputeDefinition(ctx, d); err != nil {
		slog.WarnContext(ctx, "computed fields: backfill after definition change failed", "entity", d.Entity, "error", err)
	}
}

// computedOnly keeps only the computed definitions.
func computedOnly(defs []customfield.Definition) []customfield.Definition {
	out := make([]customfield.Definition, 0, len(defs))
	for _, d := range defs {
		if d.Computed {
			out = append(out, d)
		}
	}
	return out
}

// anyOrgScoped reports whether any definition is scoped to one organization —
// applicableDefs skips the per-project organization lookup otherwise.
func anyOrgScoped(defs []customfield.Definition) bool {
	for _, d := range defs {
		if d.OrgID != nil {
			return true
		}
	}
	return false
}

// applicableDefs narrows computed to the ones that apply to projectID's
// organization (customfield.Definition.AppliesTo); when none are
// organization-scoped it returns computed unchanged without the lookup.
func applicableDefs(ctx context.Context, fields fieldStore, computed []customfield.Definition, projectID string) ([]customfield.Definition, error) {
	if !anyOrgScoped(computed) {
		return computed, nil
	}
	org, err := fields.OrgOfProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]customfield.Definition, 0, len(computed))
	for _, d := range computed {
		if d.AppliesTo(org) {
			out = append(out, d)
		}
	}
	return out, nil
}

// loadPrograms compiles every definition's expression (already validated when
// saved) against vars.
func loadPrograms(vars []string, defs []customfield.Definition) (map[string]*expr.Program, error) {
	out := make(map[string]*expr.Program, len(defs))
	for _, d := range defs {
		p, err := expr.LoadValue(vars, d.Expression)
		if err != nil {
			return nil, fmt.Errorf("computed field %s: %w", d.Key, err)
		}
		out[d.Key] = p
	}
	return out, nil
}

// evalChanges evaluates every def's program on doc and fits the result to the
// field's type (Definition.Fit), diffing against current to report only what
// changed: set for a new or changed value, unset for a value that no longer
// fits (never a guess — the field goes back to unset, not stale).
func evalChanges(ctx context.Context, defs []customfield.Definition, programs map[string]*expr.Program, doc, current map[string]any) (map[string]any, []string) {
	set := map[string]any{}
	var unset []string
	for _, d := range defs {
		prog := programs[d.Key]
		var target any
		if v, err := prog.Eval(ctx, doc); err == nil {
			target, _ = d.Fit(v)
		}
		cur, had := current[d.Key]
		switch {
		case target == nil && had:
			unset = append(unset, d.Key)
		case target != nil && (!had || !reflect.DeepEqual(cur, target)):
			set[d.Key] = target
		}
	}
	return set, unset
}
