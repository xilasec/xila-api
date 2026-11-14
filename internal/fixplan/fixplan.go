// Package fixplan answers "what should we fix first?": it groups a backlog's
// live findings by the change that resolves them and ranks the changes by the
// risk they remove — "upgrade log4j-core 2.14.1 → 2.17.1 closes 4 findings
// (1 KEV)" instead of 4 separate tickets. The fix plan endpoints list the
// package upgrades; internal/remediation tracks every kind (Changes) as work
// items.
package fixplan

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/pkgmeta"
)

// Kind is the sort of change that resolves a group of findings.
type Kind string

// Change kinds.
const (
	KindPackageUpgrade Kind = "package_upgrade" // bump one package version
	KindBaseImage      Kind = "base_image"      // rebuild an image on a patched base
	KindIaCRule        Kind = "iac_rule"        // fix one IaC / cloud rule on one file or resource
	KindCodeLocation   Kind = "code_location"   // fix one source file
	KindConfig         Kind = "config"          // one configuration change (DAST / infra rule)
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindPackageUpgrade, KindBaseImage, KindIaCRule, KindCodeLocation, KindConfig:
		return true
	}
	return false
}

// Change is one change that resolves a group of live findings in a project:
// the fix plan's package upgrades, and every kind of remediation action. Key
// identifies the change within (project, kind), stably across scans, so new
// findings the same change fixes land in the same group.
type Change struct {
	Kind        Kind   `json:"kind"`
	Key         string `json:"key"`
	ProjectID   string `json:"project_id"`
	ProjectName string `json:"project_name"`
	Title       string `json:"title"`
	// Target is what to move to: the version to upgrade to (package_upgrade).
	Target string `json:"target"`
	// What the change is on, per kind.
	Package   string `json:"package,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Installed string `json:"installed,omitempty"`
	Direct    *bool  `json:"direct,omitempty"`
	Image     string `json:"image,omitempty"`
	OS        string `json:"os,omitempty"`
	FilePath  string `json:"file_path,omitempty"`
	Resource  string `json:"resource,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	// What it closes.
	Closes          int                     `json:"closes"`
	BySeverity      map[domain.Severity]int `json:"by_severity"`
	MaxSeverity     domain.Severity         `json:"max_severity"`
	PriorityRemoved float64                 `json:"priority_removed"`
	KEV             int                     `json:"kev"`
	MaxEPSS         *float64                `json:"max_epss"`
	FindingIDs      []string                `json:"finding_ids"`
}

// Options tune the grouping.
type Options struct {
	// BaseImages groups the distro packages of a scanned container image as
	// one "rebuild on a patched base image" change, instead of one upgrade per
	// package (which is what the fix plan lists).
	BaseImages bool
}

// osPurlTypes are distro package ecosystems: packages that come with the base
// image, not from the application's own manifests.
var osPurlTypes = map[string]bool{"deb": true, "rpm": true, "apk": true, "alpm": true}

// Changes groups live findings by the change that resolves them. Pure: no I/O.
//
//   - package findings → the smallest upgrade fixing every finding on that
//     package version (none published: counted in NoFix);
//   - with Options.BaseImages, distro packages of a scanned image → one
//     rebuild per image and OS;
//   - IaC / cloud / Kubernetes findings → per rule and file (and resource,
//     when the scanner names one);
//   - SAST and secret findings → per file (one fix per file);
//   - anything else with a rule (DAST, infrastructure) → per rule.
//
// Findings that fit none (no rule, no file, licence findings) are left out.
func Changes(cands []finding.FixCandidate, opts Options) ([]Change, NoFix) {
	type gkey struct {
		project string
		kind    Kind
		key     string
	}
	groups := map[gkey]*Change{}
	var order []gkey
	noFix := NoFix{BySeverity: map[domain.Severity]int{}}
	noFixPkgs := map[[4]string]bool{}
	for _, c := range cands {
		var ch Change
		if c.PackageName != "" {
			eco := ecosystem(c.Purl)
			// A distro package the scanner says has a fix: the image's base
			// carries it. (Distro version strings — epochs, "+deb12u3" — don't
			// order reliably here, so "has a fixed version" is the test.)
			osPkg := opts.BaseImages && c.Image != "" && (c.PkgClass == "os-pkgs" || osPurlTypes[eco])
			target := ""
			if !osPkg {
				target = Target(eco, c.PackageVersion, c.FixedVersion)
			}
			if (osPkg && strings.TrimSpace(c.FixedVersion) == "") || (!osPkg && target == "") {
				noFix.Findings++
				noFix.BySeverity[c.Severity]++
				noFixPkgs[[4]string{c.ProjectID, c.PackageName, c.PackageVersion, purlBase(c.Purl)}] = true
				continue
			}
			if osPkg {
				title := "Rebuild " + c.Image + " on a patched base image"
				if c.OS != "" {
					title += " (" + c.OS + ")"
				}
				ch = Change{Kind: KindBaseImage, Key: c.Image + "|" + c.OS, Title: title, Image: c.Image, OS: c.OS}
			} else {
				ch = Change{Kind: KindPackageUpgrade, Key: purlBase(c.Purl) + "|" + c.PackageName + "@" + c.PackageVersion,
					Title: "Upgrade " + c.PackageName + " " + c.PackageVersion, Target: target,
					Package: c.PackageName, Purl: c.Purl, Ecosystem: eco, Installed: c.PackageVersion, Direct: c.DepDirect}
			}
		} else {
			switch c.Category {
			case domain.CategoryLicense:
				continue
			case domain.CategorySAST, domain.CategorySecret:
				if c.FilePath == "" {
					continue
				}
				ch = Change{Kind: KindCodeLocation, Key: c.FilePath, Title: "Fix " + c.FilePath, FilePath: c.FilePath}
			case domain.CategoryIaC, domain.CategoryCloud, domain.CategoryKubernetes, domain.CategoryContainer:
				if c.RuleID == "" {
					continue
				}
				title := cmp.Or(c.Title, c.RuleID)
				if where := cmp.Or(c.Resource, c.FilePath); where != "" {
					title += " in " + where
				}
				ch = Change{Kind: KindIaCRule, Key: c.RuleID + "|" + c.FilePath + "|" + c.Resource, Title: title,
					RuleID: c.RuleID, FilePath: c.FilePath, Resource: c.Resource}
			default:
				if c.RuleID == "" {
					continue
				}
				ch = Change{Kind: KindConfig, Key: c.RuleID, Title: cmp.Or(c.Title, c.RuleID), RuleID: c.RuleID}
			}
		}
		k := gkey{c.ProjectID, ch.Kind, ch.Key}
		g, ok := groups[k]
		if !ok {
			ch.ProjectID, ch.ProjectName, ch.BySeverity = c.ProjectID, c.ProjectName, map[domain.Severity]int{}
			g = &ch
			groups[k] = g
			order = append(order, k)
		}
		// One upgrade has to fix every finding on this version: the highest of
		// their individual minimal fixes.
		if ch.Kind == KindPackageUpgrade && pkgmeta.CompareVersions(g.Ecosystem, ch.Target, g.Target) > 0 {
			g.Target = ch.Target
		}
		g.Closes++
		g.BySeverity[c.Severity]++
		if g.MaxSeverity == "" || c.Severity.Weight() > g.MaxSeverity.Weight() {
			g.MaxSeverity = c.Severity
		}
		g.PriorityRemoved += c.Priority
		if c.KEV {
			g.KEV++
		}
		if c.EPSS != nil && (g.MaxEPSS == nil || *c.EPSS > *g.MaxEPSS) {
			g.MaxEPSS = new(*c.EPSS)
		}
		g.FindingIDs = append(g.FindingIDs, c.ID)
	}
	noFix.Packages = len(noFixPkgs)
	out := make([]Change, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	slices.SortStableFunc(out, func(a, b Change) int {
		if c := cmp.Compare(b.PriorityRemoved, a.PriorityRemoved); c != 0 {
			return c
		}
		if c := cmp.Compare(b.KEV, a.KEV); c != 0 {
			return c
		}
		return cmp.Compare(a.Title, b.Title)
	})
	return out, noFix
}

// Fix is one upgrade: a package version in a project, its target, and what it
// closes.
type Fix struct {
	ProjectID       string                  `json:"project_id"`
	ProjectName     string                  `json:"project_name"`
	Package         string                  `json:"package"`
	Purl            string                  `json:"purl"`
	Ecosystem       string                  `json:"ecosystem"`
	Installed       string                  `json:"installed"`
	UpgradeTo       string                  `json:"upgrade_to"`
	Closes          int                     `json:"closes"`
	BySeverity      map[domain.Severity]int `json:"by_severity"`
	PriorityRemoved float64                 `json:"priority_removed"`
	KEV             int                     `json:"kev"`
	MaxEPSS         *float64                `json:"max_epss"`
	Direct          *bool                   `json:"direct"` // nil: no SBOM graph
	FindingIDs      []string                `json:"finding_ids"`
}

// NoFix counts the live package findings no published version fixes (no fixed
// version, or none newer than what's installed).
type NoFix struct {
	Findings   int                     `json:"findings"`
	Packages   int                     `json:"packages"`
	BySeverity map[domain.Severity]int `json:"by_severity"`
}

// Plan ranks the package upgrades for a set of findings: the package_upgrade
// changes of Changes. Pure: no I/O.
func Plan(cands []finding.FixCandidate) ([]Fix, NoFix) {
	changes, noFix := Changes(cands, Options{})
	fixes := make([]Fix, 0, len(changes))
	for _, c := range changes {
		if c.Kind != KindPackageUpgrade {
			continue
		}
		fixes = append(fixes, Fix{ProjectID: c.ProjectID, ProjectName: c.ProjectName, Package: c.Package, Purl: c.Purl,
			Ecosystem: c.Ecosystem, Installed: c.Installed, UpgradeTo: c.Target, Closes: c.Closes,
			BySeverity: c.BySeverity, PriorityRemoved: c.PriorityRemoved, KEV: c.KEV, MaxEPSS: c.MaxEPSS,
			Direct: c.Direct, FindingIDs: c.FindingIDs})
	}
	return fixes, noFix
}

// Target is the smallest version listed in fixed that is newer than
// installed ("" when none is). Scanners list one fixed version per release
// line ("2.12.2, 2.16.0" — Trivy) or a constraint (">=1.2.3"): every
// version-looking token counts.
func Target(eco, installed, fixed string) string {
	best := ""
	for _, tok := range strings.FieldsFunc(fixed, func(r rune) bool {
		return r == ',' || r == ' ' || r == '|' || r == ';'
	}) {
		v := strings.TrimLeft(tok, "<>=^~v")
		if v == "" || !strings.ContainsAny(v[:1], "0123456789") {
			continue
		}
		if installed != "" && pkgmeta.CompareVersions(eco, v, installed) <= 0 {
			continue // not an upgrade (another release line's backport)
		}
		if best == "" || pkgmeta.CompareVersions(eco, v, best) < 0 {
			best = v
		}
	}
	return best
}

func ecosystem(purl string) string {
	if p, err := pkgmeta.ParsePURL(purl); err == nil {
		return p.Type
	}
	return ""
}

// purlBase keys a group by package identity without the version, so two
// ecosystems' same-named packages stay apart.
func purlBase(purl string) string {
	if p, err := pkgmeta.ParsePURL(purl); err == nil {
		return p.Base()
	}
	return ""
}

// candidateSource is finding.Repository.
type candidateSource interface {
	FixCandidates(ctx context.Context, ff finding.FixFilter) ([]finding.FixCandidate, error)
}

// Handler serves the fix plan.
type Handler struct{ src candidateSource }

// NewHandler constructs the handler.
func NewHandler(src candidateSource) *Handler { return &Handler{src: src} }

// Register mounts GET /projects/{id}/fix-plan (project viewer) and the
// portfolio-wide GET /fix-plan (scoped to the caller's visible projects).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/fix-plan", h.project)
	r.Get("/fix-plan", h.portfolio)
}

func (h *Handler) project(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.respond(c, []string{pid})
}

func (h *Handler) portfolio(c *fiber.Ctx) error {
	var pids []string // nil = instance admin: every project
	if s := authz.VisibleScope(c); !s.AllAccess {
		pids = s.ProjectIDs
		if pids == nil {
			pids = []string{}
		}
	}
	return h.respond(c, pids)
}

func (h *Handler) respond(c *fiber.Ctx, pids []string) error {
	page := httpx.ParsePage(c)
	cands, err := h.src.FixCandidates(c.UserContext(),
		finding.FixFilter{ProjectIDs: pids, DirectOnly: c.QueryBool("direct"), PackagesOnly: true})
	if err != nil {
		return err
	}
	fixes, noFix := Plan(cands)
	from := min(page.Offset, len(fixes))
	to := min(from+page.Limit, len(fixes))
	return c.JSON(fiber.Map{
		"fixes":      fixes[from:to],
		"no_fix":     noFix,
		"pagination": httpx.Meta(page, to-from, to < len(fixes)),
	})
}
