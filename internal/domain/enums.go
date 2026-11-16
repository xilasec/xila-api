// Package domain holds enums and value types shared across the security model.
package domain

import (
	"slices"
	"time"
)

// Severity is the normalized severity scale all scanners are mapped onto.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severities = []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// Valid reports whether s is a known severity.
func (s Severity) Valid() bool { return slices.Contains(severities, s) }

// SeveritiesAtLeast lists the severities from floor up to critical (all of
// them for an unknown floor).
func SeveritiesAtLeast(floor Severity) []Severity {
	i := max(slices.Index(severities, floor), 0)
	return slices.Clone(severities[i:])
}

// Weight is the base risk contribution of a single finding at this severity.
func (s Severity) Weight() float64 {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 7
	case SeverityCritical:
		return 15
	default: // info
		return 0
	}
}

// Category is the class of security testing that produced a finding.
type Category string

const (
	CategorySAST       Category = "sast"
	CategoryDAST       Category = "dast"
	CategorySCA        Category = "sca"
	CategorySecret     Category = "secret"
	CategoryContainer  Category = "container"
	CategoryIaC        Category = "iac"
	CategoryLicense    Category = "license"
	CategoryCloud      Category = "cloud"      // CSPM: cloud posture (Prowler, ...)
	CategoryKubernetes Category = "kubernetes" // KSPM: k8s posture (Kubescape, kubeaudit, ...)
)

var categories = []Category{
	CategorySAST, CategoryDAST, CategorySCA, CategorySecret,
	CategoryContainer, CategoryIaC, CategoryLicense,
	CategoryCloud, CategoryKubernetes,
}

// Valid reports whether c is a known category.
func (c Category) Valid() bool { return slices.Contains(categories, c) }

// FindingStatus is the lifecycle state of a persistent finding.
type FindingStatus string

const (
	FindingOpen          FindingStatus = "open"
	FindingConfirmed     FindingStatus = "confirmed"
	FindingFalsePositive FindingStatus = "false_positive"
	FindingRiskAccepted  FindingStatus = "risk_accepted"
	FindingRemediated    FindingStatus = "remediated"
	FindingWontFix       FindingStatus = "wont_fix"
)

var findingStatuses = []FindingStatus{
	FindingOpen, FindingConfirmed, FindingFalsePositive,
	FindingRiskAccepted, FindingRemediated, FindingWontFix,
}

// Valid reports whether s is a known finding status.
func (s FindingStatus) Valid() bool { return slices.Contains(findingStatuses, s) }

// CountsRisk reports whether findings in this state contribute to the risk score
// (i.e. they represent live, unresolved exposure).
func (s FindingStatus) CountsRisk() bool {
	return s == FindingOpen || s == FindingConfirmed
}

// PausesSLA reports whether a finding in this state has its SLA clock stopped:
// an accepted exception is a decision not to fix (yet), so it is not overdue.
// Remediated does not pause — a finding that comes back was never really fixed.
// The findings_sla_maintain trigger (migration 000027) mirrors this list.
func (s FindingStatus) PausesSLA() bool {
	return s == FindingRiskAccepted || s == FindingFalsePositive || s == FindingWontFix
}

// SLAStatus is where a finding stands against its remediation deadline.
type SLAStatus string

const (
	SLANone     SLAStatus = "none"     // no SLA applies to this severity
	SLAOnTrack  SLAStatus = "on_track" // live, comfortably inside its window
	SLADueSoon  SLAStatus = "due_soon" // live, in the last SLADueSoonFraction of its window
	SLABreached SLAStatus = "breached" // live, past its deadline
	SLAPaused   SLAStatus = "paused"   // in an exception state; the clock is stopped
	SLAMet      SLAStatus = "met"      // remediated on or before the deadline
	SLAMissed   SLAStatus = "missed"   // remediated after the deadline
)

var slaStatuses = []SLAStatus{SLANone, SLAOnTrack, SLADueSoon, SLABreached, SLAPaused, SLAMet, SLAMissed}

// Valid reports whether s is a known SLA status.
func (s SLAStatus) Valid() bool { return slices.Contains(slaStatuses, s) }

// SLADueSoonFraction is the tail of the SLA window that counts as "due soon".
// Proportional rather than a fixed number of days, so a 7-day critical isn't
// "due soon" from the moment it's found while a 120-day low still gets a month
// of warning: critical 7d → last 1.75d, high 30d → 7.5d, low 120d → 30d.
const SLADueSoonFraction = 0.25

// SLAStatusAt classifies a finding against its SLA at time now. days and due
// are nil when no SLA applies; resolvedAt is when it was remediated.
func SLAStatusAt(status FindingStatus, days *int, due, resolvedAt *time.Time, now time.Time) SLAStatus {
	if days == nil || due == nil {
		return SLANone
	}
	switch {
	case status == FindingRemediated:
		if resolvedAt != nil && !resolvedAt.After(*due) {
			return SLAMet
		}
		return SLAMissed
	case status.PausesSLA():
		return SLAPaused
	case now.After(*due):
		return SLABreached
	case due.Sub(now) <= time.Duration(float64(*days)*SLADueSoonFraction*float64(24*time.Hour)):
		return SLADueSoon
	default:
		return SLAOnTrack
	}
}

// ScanStatus is the processing state of an ingested scan.
type ScanStatus string

const (
	ScanPending    ScanStatus = "pending"
	ScanProcessing ScanStatus = "processing"
	ScanCompleted  ScanStatus = "completed"
	ScanFailed     ScanStatus = "failed"
)

// Criticality is the business importance of a project, used to weight risk.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

var criticalities = []Criticality{
	CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical,
}

// Valid reports whether c is a known criticality.
func (c Criticality) Valid() bool { return slices.Contains(criticalities, c) }

// Multiplier scales a project's risk score by its business importance.
func (c Criticality) Multiplier() float64 {
	switch c {
	case CriticalityMedium:
		return 1.5
	case CriticalityHigh:
		return 2
	case CriticalityCritical:
		return 3
	default: // low
		return 1
	}
}

// AssetType is the kind of thing an asset represents.
type AssetType string

const (
	AssetRepository     AssetType = "repository"
	AssetContainerImage AssetType = "container_image"
	AssetCloudResource  AssetType = "cloud_resource"
	AssetHost           AssetType = "host"
	AssetKubernetes     AssetType = "kubernetes"
	AssetServerless     AssetType = "serverless"
)

var assetTypes = []AssetType{
	AssetRepository, AssetContainerImage, AssetCloudResource,
	AssetHost, AssetKubernetes, AssetServerless,
}

// Valid reports whether t is a known asset type.
func (t AssetType) Valid() bool { return slices.Contains(assetTypes, t) }

// TeamRole is a user's role within a team (RBAC). Ranked: viewer < uploader <
// editor < owner. uploader is "viewer plus uploads": it reads everything a
// viewer can, and on top of that may upload scans, SBOMs and VEX and run the
// gate — the minimum a CI build needs to report its result (see authz.go's
// allowUploader carve-out for those specific routes) — but nothing
// editor-level: no triage, no comments, no settings, no membership.
type TeamRole string

const (
	TeamViewer TeamRole = "viewer" // read-only within the team
	// TeamUploader is viewer plus uploads: it may also upload scans, SBOMs
	// and VEX, and run the gate. See the allowUploader carve-out in
	// internal/authz.
	TeamUploader TeamRole = "uploader"
	TeamEditor   TeamRole = "editor" // read + write (triage, upload, config)
	TeamOwner    TeamRole = "owner"  // editor + manage the team & its members
)

var teamRoles = []TeamRole{TeamViewer, TeamUploader, TeamEditor, TeamOwner}

// Valid reports whether r is a known team role.
func (r TeamRole) Valid() bool { return slices.Contains(teamRoles, r) }

func (r TeamRole) rank() int {
	switch r {
	case TeamOwner:
		return 4
	case TeamEditor:
		return 3
	case TeamUploader:
		return 2
	case TeamViewer:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r meets or exceeds the required role.
func (r TeamRole) AtLeast(min TeamRole) bool { return r.rank() >= min.rank() }

// OrgRole is a user's role within an organization. admin manages the org and all
// its teams; member's access comes from team membership.
type OrgRole string

const (
	OrgMember OrgRole = "member"
	OrgAdmin  OrgRole = "admin"
)

var orgRoles = []OrgRole{OrgMember, OrgAdmin}

// Valid reports whether r is a known org role.
func (r OrgRole) Valid() bool { return slices.Contains(orgRoles, r) }

// DepScope is where a dependency is actually used. It comes from the SBOM
// itself (CycloneDX component scope, SPDX DEV/TEST/OPTIONAL_DEPENDENCY_OF), not
// from any analysis we do.
type DepScope string

const (
	// DepScopeUnknown means the SBOM said nothing. Treated as runtime: absence of
	// evidence is not evidence of safety, so we never discount a finding for it.
	DepScopeUnknown  DepScope = ""
	DepScopeRuntime  DepScope = "runtime"
	DepScopeDev      DepScope = "dev"      // build/test-only; never ships
	DepScopeOptional DepScope = "optional" // shipped only if a feature is enabled
)

var depScopes = []DepScope{DepScopeUnknown, DepScopeRuntime, DepScopeDev, DepScopeOptional}

// Valid reports whether s is a known dependency scope.
func (s DepScope) Valid() bool { return slices.Contains(depScopes, s) }

// Reachability is the cheap, SBOM-derived answer to "can this actually hurt us?"
// — the two facts that make most of a dependency backlog irrelevant: the package
// is only used at build time, or it is buried deep in the transitive tree and we
// never call it. It is a *heuristic*: it discounts, it never suppresses. A
// critical KEV bug stays near the top of the list wherever it sits.
type Reachability struct {
	// Direct is nil when the SBOM carried no dependency graph.
	Direct *bool
	Scope  DepScope
}

// Multiplier scales a finding's priority by how reachable its dependency is.
// Both signals only ever discount, and unknown never discounts:
//
//	direct + runtime      1.0 × 1.0  = 1.0   (the real backlog)
//	transitive + runtime  0.8 × 1.0  = 0.8
//	direct + optional     1.0 × 0.5  = 0.5
//	transitive + dev      0.8 × 0.25 = 0.2   (the noise)
func (r Reachability) Multiplier() float64 {
	m := 1.0
	if r.Direct != nil && !*r.Direct {
		m = 0.8 // transitive: we depend on it, but not on purpose
	}
	switch r.Scope {
	case DepScopeDev:
		m *= 0.25 // never ships to production
	case DepScopeOptional:
		m *= 0.5
	}
	return m
}

// ExploitMaturity is the best public exploit known for a finding's CVEs
// (internal/exploitintel): a proof of concept (ExploitDB, a Nuclei template)
// or a weaponized module (Metasploit). Empty means none is known — which is
// not evidence of safety, so it never lowers a priority.
type ExploitMaturity string

// Exploit maturities, weakest first.
const (
	ExploitNone       ExploitMaturity = ""
	ExploitPoC        ExploitMaturity = "poc"
	ExploitWeaponized ExploitMaturity = "weaponized"
)

// Valid reports whether m is a known maturity (or none).
func (m ExploitMaturity) Valid() bool {
	return m == ExploitNone || m == ExploitPoC || m == ExploitWeaponized
}

// KEV catalogs: the known-exploited-vulnerabilities lists a finding's KEV flag
// can come from (findings.kev_sources).
const (
	KEVCISA      = "cisa"      // CISA Known Exploited Vulnerabilities
	KEVENISA     = "enisa"     // ENISA EU Vulnerability Database, exploited
	KEVVulnCheck = "vulncheck" // VulnCheck KEV
)

// KEVCatalogs lists every KEV catalog.
var KEVCatalogs = []string{KEVCISA, KEVENISA, KEVVulnCheck}

// ValidKEVCatalog reports whether s names a KEV catalog.
func ValidKEVCatalog(s string) bool { return slices.Contains(KEVCatalogs, s) }

// Exploitability is the evidence that a finding is (or will be) exploited.
type Exploitability struct {
	EPSS     float64 // FIRST EPSS probability, 0–1
	KEV      bool    // on any KEV catalog (CISA, ENISA, VulnCheck)
	Maturity ExploitMaturity
}

// Multiplier scales a severity weight by exploitability, 1× to 3×. A KEV
// listing (exploited in the wild) is the ceiling. Otherwise the strongest of
// the other signals wins — they're evidence of the same thing, so they don't
// stack: EPSS scales 1 + 2×p; a weaponized exploit counts like EPSS 0.75
// (2.5×: point-and-shoot, on par with a high EPSS) and a public PoC like EPSS
// 0.25 (1.5×). No evidence leaves the weight as it is.
func (x Exploitability) Multiplier() float64 {
	if x.KEV {
		return 3.0
	}
	m := 1.0 + 2.0*x.EPSS
	switch x.Maturity {
	case ExploitWeaponized:
		m = max(m, 2.5)
	case ExploitPoC:
		m = max(m, 1.5)
	}
	return m
}

// Exposure is where an asset can be reached from (internal/asset): the network
// position of the thing a finding sits on. Empty means nobody knows — which is
// not evidence of safety, so it never discounts.
type Exposure string

// Asset exposures. Unknown is NULL in the database.
const (
	ExposureUnknown  Exposure = ""
	ExposureInternet Exposure = "internet" // reachable from the public internet
	ExposureInternal Exposure = "internal" // reachable inside the organisation's network
	ExposureIsolated Exposure = "isolated" // no inbound network path (air-gapped, batch-only)
)

// Valid reports whether e is a known exposure (or unknown).
func (e Exposure) Valid() bool {
	return e == ExposureUnknown || e == ExposureInternet || e == ExposureInternal || e == ExposureIsolated
}

// Rank orders exposures by how reachable they are (unknown lowest): inference
// only ever raises an asset's exposure, because evidence of a path is positive
// evidence while its absence in one scan proves nothing.
func (e Exposure) Rank() int {
	switch e {
	case ExposureInternet:
		return 3
	case ExposureInternal:
		return 2
	case ExposureIsolated:
		return 1
	}
	return 0
}

// Multiplier scales a finding's priority by its asset's exposure. Internet
// exposure raises moderately (anyone can try), internal leaves it, isolated
// discounts — and unknown never discounts:
//
//	internet  1.25
//	internal  1.0
//	unknown   1.0
//	isolated  0.75
//
// The isolated discount is bounded so the worst case still keeps a real
// emergency on top: an exploited critical in a build-only transitive dependency
// on an isolated host (15 × 3 × 0.2 × 0.75 = 6.75) outranks a quiet shipped
// medium even on an internet-facing asset (3 × 1 × 1 × 1.25 = 3.75). Both
// factors are exact binary fractions, so priorities stay exact numbers.
func (e Exposure) Multiplier() float64 {
	switch e {
	case ExposureInternet:
		return 1.25
	case ExposureIsolated:
		return 0.75
	}
	return 1.0
}

// Priority ranks a finding for the working backlog. Severity is the base weight;
// exploitability scales it up (KEV triples it; EPSS or a public exploit scale it
// up to 2.5–3×); reachability scales it back down when the vulnerable dependency
// can't plausibly be reached (transitive, or dev-only); the asset's exposure
// raises it on internet-facing assets and discounts it on isolated ones.
//
//	critical + KEV, direct runtime, internet  15 × 3   × 1.0 × 1.25 = 56.25
//	critical + KEV, direct runtime            15 × 3   × 1.0 × 1.0  = 45
//	critical + Metasploit module              15 × 2.5 × 1.0 × 1.0  = 37.5
//	critical, quiet, direct runtime           15 × 1   × 1.0 × 1.0  = 15
//	critical + KEV, transitive dev            15 × 3   × 0.2 × 1.0  =  9
//	critical + KEV, transitive dev, isolated  15 × 3   × 0.2 × 0.75 =  6.75
//	medium + KEV, direct runtime               3 × 3   × 1.0 × 1.0  =  9
//
// Note what the sixth line means: an exploited critical buried in a build-only
// dependency on an isolated asset still outranks a quiet medium. Reachability
// and exposure discount noise; they never bury a real emergency.
func Priority(sev Severity, x Exploitability, reach Reachability, exp Exposure) float64 {
	return sev.Weight() * x.Multiplier() * reach.Multiplier() * exp.Multiplier()
}

// MaxTeamRole returns the highest of the given roles — a user's effective role
// when they hold access through several paths (a direct project role, their team
// role, an org admin fallback). Access is the union of what you've been granted:
// a grant in one place is never cancelled by the absence of one somewhere else.
// Returns false when the user holds no role at all.
func MaxTeamRole(roles ...TeamRole) (TeamRole, bool) {
	best, found := TeamRole(""), false
	for _, r := range roles {
		if !r.Valid() {
			continue
		}
		if !found || r.rank() > best.rank() {
			best, found = r, true
		}
	}
	return best, found
}

// Capability is a fine-grained action a custom role can deny on top of its
// base TeamRole (viewer/uploader/editor/owner). A custom role is always a
// base role minus a subset of these; the ladder rank used everywhere else
// (RoleOnProject, RoleOnTeam, authz's minRole) stays the base role — a
// capability only narrows specific route classes within it, it never changes
// what role a grant ranks as.
type Capability string

// Capabilities a custom role may deny.
const (
	CapTriage                Capability = "triage"                  // finding status / assignee / severity changes
	CapComment               Capability = "comment"                 // finding comments
	CapManageMembers         Capability = "manage_members"          // team/org/project member + group management
	CapProjectSettings       Capability = "project_settings"        // gate policy, SLA, issue tracker, connectors
	CapUpload                Capability = "upload"                  // pushing scans/SBOMs/VEX, running the gate
	CapExport                Capability = "export"                  // CSV/XLSX exports of findings/components/VEX
	CapRiskAcceptanceApprove Capability = "risk_acceptance_approve" // approve/reject/revoke a risk acceptance
)

// Capabilities lists every capability a custom role may deny, in the order
// they are presented to admins.
var Capabilities = []Capability{
	CapTriage, CapComment, CapManageMembers, CapProjectSettings, CapUpload, CapExport, CapRiskAcceptanceApprove,
}

// Valid reports whether c is a known capability.
func (c Capability) Valid() bool { return slices.Contains(Capabilities, c) }

// ValidCapabilities reports whether every capability in cs is known.
func ValidCapabilities(cs []Capability) bool {
	for _, c := range cs {
		if !c.Valid() {
			return false
		}
	}
	return true
}
