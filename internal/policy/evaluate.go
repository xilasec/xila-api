package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
)

// compiledPolicy is a validated policy with its conditions' matchers.
type compiledPolicy struct {
	Policy
	conds []compiled
}

// validate checks p's shape and compiles its conditions, normalizing them in
// place (each condition's value is stored in its canonical form).
func validate(p *Policy, groups groupResolver, schema expr.Schema) (compiledPolicy, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return compiledPolicy{}, invalid("name is required")
	}
	if p.Operator != CombineAny && p.Operator != CombineAll {
		return compiledPolicy{}, invalid(`operator must be "any" or "all"`)
	}
	if p.ViolationState != StateFail && p.ViolationState != StateWarn && p.ViolationState != StateInfo {
		return compiledPolicy{}, invalid(`violation_state must be "fail", "warn" or "info"`)
	}
	if p.Versions != VersionsAll && p.Versions != VersionsDefault {
		return compiledPolicy{}, invalid(`versions must be "all" or "default"`)
	}
	switch p.Scope {
	case ScopeGlobal:
		p.ProjectIDs = []string{}
	case ScopeProjects:
		if len(p.ProjectIDs) == 0 {
			return compiledPolicy{}, invalid(`scope "projects" needs at least one project_ids entry`)
		}
		slices.Sort(p.ProjectIDs)
		p.ProjectIDs = slices.Compact(p.ProjectIDs)
		for _, id := range p.ProjectIDs {
			if _, err := uuid.Parse(id); err != nil {
				return compiledPolicy{}, invalid("project_ids: %q is not a project id", id)
			}
		}
	default:
		return compiledPolicy{}, invalid(`scope must be "global" or "projects"`)
	}
	p.IncludeTags, p.ExcludeTags = normalizeTags(p.IncludeTags), normalizeTags(p.ExcludeTags)
	for _, t := range p.IncludeTags {
		if slices.Contains(p.ExcludeTags, t) {
			return compiledPolicy{}, invalid("tag %q is both included and excluded", t)
		}
	}
	if len(p.Conditions) == 0 {
		return compiledPolicy{}, invalid("a policy needs at least one condition")
	}
	cp := compiledPolicy{conds: make([]compiled, len(p.Conditions))}
	for i, c := range p.Conditions {
		cc, err := compile(c, groups, schema)
		if err != nil {
			return compiledPolicy{}, err
		}
		cp.conds[i] = cc
		p.Conditions[i] = cc.Condition
	}
	cp.Policy = *p
	return cp, nil
}

// evaluate returns the conditions c matched and whether that is a violation:
// any one of them (operator any) or every one (all).
func (cp compiledPolicy) evaluate(c *Component, now time.Time) ([]Match, bool) {
	var matches []Match
	for _, cond := range cp.conds {
		ok, fact := cond.match(c, now)
		if !ok {
			if cp.Operator == CombineAll {
				return nil, false
			}
			continue
		}
		matches = append(matches, Match{Subject: cond.Subject, Operator: cond.Operator, Value: cond.Value, Fact: fact})
	}
	return matches, len(matches) > 0
}

// needsMeta reports whether any condition reads package metadata.
func (cp compiledPolicy) needsMeta() bool {
	return slices.ContainsFunc(cp.conds, func(c compiled) bool {
		return c.Subject == SubjectOutdated || c.Subject == SubjectVersionsBehind || c.Subject == SubjectAge
	})
}

// needsGraph reports whether an expression calls a dependency-graph function,
// so evaluation loads the snapshots' graphs only when one does.
func (cp compiledPolicy) needsGraph() bool {
	return slices.ContainsFunc(cp.conds, func(c compiled) bool {
		src := string(c.Value) // the expression's JSON string; the names appear verbatim
		return c.Subject == SubjectExpression &&
			(strings.Contains(src, "depends_on(") || strings.Contains(src, "dependency_of("))
	})
}

// usesLicense reports whether any condition reads the license.
func (cp compiledPolicy) usesLicense() bool {
	return slices.ContainsFunc(cp.conds, func(c compiled) bool { return c.Subject.IsLicense() })
}

// violationCategory is license when every matched condition is about the
// license, else sca.
func violationCategory(matches []Match) domain.Category {
	for _, m := range matches {
		if !m.Subject.IsLicense() {
			return domain.CategorySCA
		}
	}
	return domain.CategoryLicense
}

// violations is what policies find in one version's components: per policy, a
// package is reported once (componentKey, which its finding's fingerprint is
// built from) when any of its occurrences violates. A package can appear in
// several artifacts of a version with different facts, an artifact's hashes
// and so its integrity among them; judging only one copy would miss a tampered
// one depending on row order.
func violations(policies []compiledPolicy, comps []*Component, isDefault bool, now time.Time) []finding.Finding {
	var found []finding.Finding
	for _, cp := range policies {
		if cp.Versions == VersionsDefault && !isDefault {
			continue
		}
		reported := map[string]bool{}
		for _, c := range comps {
			key := componentKey(c)
			if reported[key] {
				continue
			}
			if matches, ok := cp.evaluate(c, now); ok {
				found = append(found, toFinding(cp.Policy, c, matches))
				reported[key] = true
			}
		}
	}
	return found
}

// componentKey identifies a component version: its purl, else name@version.
// Migration 000040 computes the same key for carried-over license findings.
func componentKey(c *Component) string {
	if c.Purl != "" {
		return c.Purl
	}
	return c.Name + "@" + c.Version
}

// fingerprint is stable per (policy, component version), so re-evaluation
// upserts the same finding and keeps its triage.
func fingerprint(policyID, key string) string {
	sum := sha256.Sum256([]byte(Scanner + "|" + policyID + "|" + key))
	return hex.EncodeToString(sum[:])
}

// toFinding turns a violation into a finding. ProjectID, VersionID, Scanner and
// the scan are stamped by ApplyFindings.
func toFinding(p Policy, c *Component, matches []Match) finding.Finding {
	pkg := coordinates(c)
	var b strings.Builder
	fmt.Fprintf(&b, "Component %s violates policy %q (%s):\n", pkg, p.Name, p.ViolationState)
	for _, m := range matches {
		fmt.Fprintf(&b, "- %s %s %s", m.Subject, m.Operator, m.Value)
		if m.Fact != "" {
			fmt.Fprintf(&b, " — %s", m.Fact)
		}
		b.WriteString("\n")
	}
	if p.Description != "" {
		b.WriteString("\n" + p.Description)
	}
	return finding.Finding{
		Fingerprint:    fingerprint(p.ID, componentKey(c)),
		Category:       violationCategory(matches),
		RuleID:         p.ID,
		Title:          fmt.Sprintf("Policy %q violated by %s", p.Name, pkg),
		Description:    strings.TrimSpace(b.String()),
		Severity:       p.ViolationState.Severity(),
		PackageName:    c.Name,
		PackageVersion: c.Version,
		Purl:           c.Purl,
		Metadata: map[string]any{
			"policy_id":          p.ID,
			"policy_name":        p.Name,
			"violation_state":    p.ViolationState,
			"matched_conditions": matches,
			"facts":              facts(c),
		},
	}
}

// facts is the component's evidence recorded on its violations.
func facts(c *Component) map[string]any {
	out := map[string]any{"license": c.InventoryComponent.License, "license_expression": c.LicenseExpression}
	if c.LicenseResolved != nil {
		out["license_resolved"] = *c.LicenseResolved
	}
	if c.MaxSeverity != nil {
		out["max_severity"] = *c.MaxSeverity
	}
	if len(c.VulnIDs) > 0 {
		out["vulnerabilities"] = c.VulnIDs[:min(len(c.VulnIDs), 20)]
		out["kev"] = c.KEV
		if len(c.KEVSources) > 0 {
			out["kev_sources"] = c.KEVSources
		}
	}
	if c.EPSS != nil {
		out["epss"] = *c.EPSS
	}
	if c.Meta != nil {
		out["latest_version"] = c.Meta.Latest
		out["outdated"] = c.Meta.Outdated
		if c.Meta.VersionsBehind != nil {
			out["versions_behind"] = *c.Meta.VersionsBehind
		}
		if c.Meta.Published != nil {
			out["published"] = c.Meta.Published.UTC().Format(time.RFC3339)
		}
	}
	return out
}

// normalizeTags trims, drops empty and duplicate tags, and sorts; never nil.
func normalizeTags(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}
