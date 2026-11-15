package fixplan

import (
	"cmp"
	"slices"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/pkgmeta"
)

// RootCauseLive identifies one project's live remediation action tracking a
// change, the same identity Change groups within a project: project, kind
// and key.
type RootCauseLive struct {
	ProjectID string
	Kind      Kind
	Key       string
}

// RootCause is one change shared by the projects you can see: the same
// package upgrade, base-image rebuild, or rule fix needed in more than one
// project collapses to one row, so fixing (or reviewing) it once covers every
// project it touches instead of a separate line per project.
type RootCause struct {
	Kind  Kind   `json:"kind"`
	Key   string `json:"key"`
	Title string `json:"title"`
	// Target is what to move to (package_upgrade): the highest of the
	// affected projects' minimal fixes, the same rule Change applies within
	// one project.
	Target string `json:"target"`
	// What the change is on, per kind — same meaning as Change's fields.
	Package   string `json:"package,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Installed string `json:"installed,omitempty"`
	Image     string `json:"image,omitempty"`
	OS        string `json:"os,omitempty"`
	FilePath  string `json:"file_path,omitempty"`
	Resource  string `json:"resource,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	// Projects is how many visible projects carry this change; ProjectIDs
	// lists them, in the order first seen.
	Projects   int      `json:"projects"`
	ProjectIDs []string `json:"project_ids"`
	// What it closes, summed over every affected project.
	Findings        int                     `json:"findings"`
	BySeverity      map[domain.Severity]int `json:"by_severity"`
	MaxSeverity     domain.Severity         `json:"max_severity"`
	PriorityRemoved float64                 `json:"priority_removed"`
	KEV             int                     `json:"kev"`
	MaxEPSS         *float64                `json:"max_epss"`
	// AllActioned is true once every affected project already has a live
	// remediation action tracking exactly this change.
	AllActioned bool `json:"all_actioned"`
}

// RootCauses merges per-project changes (fixplan.Changes, run over every
// visible project's live candidates) into one row per (kind, key): the same
// change needed in several projects is one root cause instead of one line per
// project, no second grouping decision. live reports which (project, kind,
// key) triples already have a live remediation action tracking that change; a
// nil or incomplete map treats the missing ones as not yet actioned. Sorted by
// priority removed, then projects affected. Pure: no I/O.
func RootCauses(changes []Change, live map[RootCauseLive]bool) []RootCause {
	type key struct {
		kind Kind
		key  string
	}
	groups := map[key]*RootCause{}
	var order []key
	for _, c := range changes {
		k := key{c.Kind, c.Key}
		rc, ok := groups[k]
		if !ok {
			rc = &RootCause{
				Kind: c.Kind, Key: c.Key, Title: c.Title, Target: c.Target,
				Package: c.Package, Purl: c.Purl, Ecosystem: c.Ecosystem, Installed: c.Installed,
				Image: c.Image, OS: c.OS, FilePath: c.FilePath, Resource: c.Resource, RuleID: c.RuleID,
				BySeverity: map[domain.Severity]int{}, AllActioned: true,
			}
			groups[k] = rc
			order = append(order, k)
		}
		if c.Kind == KindPackageUpgrade && pkgmeta.CompareVersions(rc.Ecosystem, c.Target, rc.Target) > 0 {
			rc.Target = c.Target
		}
		rc.Projects++
		rc.ProjectIDs = append(rc.ProjectIDs, c.ProjectID)
		rc.Findings += c.Closes
		for sev, n := range c.BySeverity {
			rc.BySeverity[sev] += n
		}
		if rc.MaxSeverity == "" || c.MaxSeverity.Weight() > rc.MaxSeverity.Weight() {
			rc.MaxSeverity = c.MaxSeverity
		}
		rc.PriorityRemoved += c.PriorityRemoved
		rc.KEV += c.KEV
		if c.MaxEPSS != nil && (rc.MaxEPSS == nil || *c.MaxEPSS > *rc.MaxEPSS) {
			rc.MaxEPSS = new(*c.MaxEPSS)
		}
		if !live[RootCauseLive{c.ProjectID, c.Kind, c.Key}] {
			rc.AllActioned = false
		}
	}
	out := make([]RootCause, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	slices.SortStableFunc(out, func(a, b RootCause) int {
		if d := cmp.Compare(b.PriorityRemoved, a.PriorityRemoved); d != 0 {
			return d
		}
		if d := cmp.Compare(b.Projects, a.Projects); d != 0 {
			return d
		}
		return cmp.Compare(a.Title, b.Title)
	})
	return out
}
