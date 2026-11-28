package vex

import (
	"cmp"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Export formats.
const (
	FormatOpenVEX   = "openvex"
	FormatCycloneDX = "cyclonedx"
	FormatCSAF      = "csaf"
)

// ExportFormats lists every format Export can render.
var ExportFormats = []string{FormatOpenVEX, FormatCycloneDX, FormatCSAF}

// ExportScope is the product a VEX export speaks about: one project version,
// plus who is asking and where this instance lives (for document identity).
//
// The Doc* / Publisher* fields are overrides a stored VEX document (M13
// 13.14) sets to make the builders below render its frozen identity (a
// stable id, its own tracking version, its real revision history, its
// configured publisher) instead of the ad hoc export's derived defaults — the
// same mapping logic, never forked.
type ExportScope struct {
	ProjectID   string
	ProjectSlug string
	ProjectName string
	// VersionID is empty when the project has no version yet (nothing scanned).
	VersionID   string
	VersionName string
	// Author is the requesting user's email ("" = unknown); PublicURL the
	// instance origin ("" = not configured).
	Author    string
	PublicURL string
	// DocID overrides the derived documentID/tracking id. "" = derive.
	DocID string
	// Title overrides CSAF's default "VEX for <project> (<version>)". "" = derive.
	Title string
	// TrackVersion overrides the OpenVEX/CycloneDX "version" int and CSAF
	// tracking.version. 0 = 1 (an ad hoc export is always "version 1").
	TrackVersion int
	// Revisions overrides the single synthetic CSAF revision_history entry
	// with the document's real history. Empty = the synthetic one.
	Revisions []DocRevision
	// PublisherName/Namespace/Contact override "Xila" / PublicURL / Author as
	// the CSAF publisher and CycloneDX metadata author name. Empty = derive.
	PublisherName      string
	PublisherNamespace string
	PublisherContact   string
}

// DocRevision is one entry of a stored VEX document's revision history, for
// CSAF's tracking.revision_history.
type DocRevision struct {
	Number  int
	Date    time.Time
	Summary string
}

// ProjectProduct is the product identifier used for findings that carry no
// package purl: the project version itself, as pkg:generic/<slug>@<version>.
func (s ExportScope) ProjectProduct() string {
	return "pkg:generic/" + purlEscape(s.ProjectSlug) + "@" + purlEscape(s.VersionName)
}

func purlEscape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}

// productOf names the product a finding is about: its package purl; for a
// package the scanner gave no purl, pkg:generic/<name>@<version> (which the VEX
// importer matches back by name and version); else the project version.
func productOf(f finding.Finding, projectProduct string) string {
	switch {
	case f.Purl != "":
		return f.Purl
	case f.PackageName != "":
		p := "pkg:generic/" + purlEscape(f.PackageName)
		if f.PackageVersion != "" {
			p += "@" + purlEscape(f.PackageVersion)
		}
		return p
	}
	return projectProduct
}

// ExportFinding is a finding as the exporter sees it, with the time its triage
// last changed (latest status event, else when it was last seen).
type ExportFinding struct {
	finding.Finding
	TriagedAt time.Time
}

// Verdict is the VEX reading of a triage decision.
type Verdict struct {
	Status Status
	// Justification is the not_affected justification code as recorded
	// (CycloneDX or OpenVEX/CSAF vocabulary; knownJustification), or "" when
	// none is known. Never invented: it only comes from a VEX statement or a
	// stored vex_justification (M13 13.2). Each format translates it on
	// output, so a CycloneDX export restates a CycloneDX code exactly.
	Justification string
	// Impact explains a not_affected verdict (OpenVEX impact_statement).
	Impact string
	// Action says what is being done about an affected verdict.
	Action string
	// Response is the CycloneDX analysis response codes (nil = none).
	Response []string
	// Remediation is the CSAF remediation category for affected verdicts.
	Remediation string
	Timestamp   time.Time
}

// Triaged is the subset of a finding's triage state a verdict is derived from.
type Triaged struct {
	Status       domain.FindingStatus
	Reason       string
	By           string
	ExpiresAt    *time.Time
	FixedVersion string
	// VexJustification / VexResponse: the finding's own stored structured
	// analysis (M13 13.2), set directly by an analyst, a triage rule or a
	// vulnerability policy — not only through a VEX statement. "" / nil means
	// none was recorded.
	VexJustification domain.VexJustification
	VexResponse      []domain.VexResponse
	At               time.Time
}

// vexResponseStrings converts to the plain []string CycloneAnalysis emits.
func vexResponseStrings(rs []domain.VexResponse) []string {
	if len(rs) == 0 {
		return nil
	}
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}

// VerdictFor maps a finding's triage onto a VEX verdict. stmt is the stored
// statement that matches the finding (nil = none); it is only trusted as the
// source of the verdict when the finding was triaged by the VEX engine. A
// stored vex_justification / vex_response (set directly on the finding) is
// always honored when present, VEX-triaged or not — it was never invented,
// an analyst (or rule, or policy) put it there.
//
//	false_positive                       → not_affected (fixed, if VEX said fixed)
//	remediated                           → fixed
//	confirmed / risk_accepted / wont_fix → affected
//	open                                 → under_investigation
func VerdictFor(t Triaged, stmt *Statement) Verdict {
	v := Verdict{Timestamp: t.At}
	byVEX := stmt != nil && t.By == vexActor
	switch t.Status {
	case domain.FindingFalsePositive:
		v.Status = StatusNotAffected
		if byVEX {
			if stmt.Status == StatusFixed {
				v.Status = StatusFixed
				return v
			}
			v.Justification = knownJustification(stmt.Justification)
			if v.Justification == "" && stmt.Justification != "" {
				// A free-text justification is kept as prose, not coerced into a code.
				v.Impact = joinNonEmpty(": ", stmt.Justification, stmt.Detail)
			} else {
				v.Impact = stmt.Detail
			}
			return v
		}
		v.Impact = t.Reason
		if v.Impact == "" {
			v.Impact = "Triaged as a false positive"
			if t.By != "" {
				v.Impact += " by " + t.By
			}
		}
		v.Justification = knownJustification(string(t.VexJustification))
		v.Response = vexResponseStrings(t.VexResponse)
	case domain.FindingRemediated:
		v.Status = StatusFixed
	case domain.FindingConfirmed:
		v.Status = StatusAffected
		if byVEX && stmt.Detail != "" {
			v.Action = stmt.Detail
		}
		if t.FixedVersion != "" {
			v.Action = joinNonEmpty(" ", v.Action, "Upgrade to "+t.FixedVersion+".")
			v.Response, v.Remediation = []string{"update"}, "vendor_fix"
		} else {
			v.Action = cmp.Or(v.Action, "Confirmed affected; no fix is available yet.")
			v.Remediation = "none_available"
		}
	case domain.FindingRiskAccepted:
		v.Status = StatusAffected
		v.Action = "Risk accepted" + until(t.ExpiresAt) + reasonSuffix(t.Reason)
		v.Response, v.Remediation = []string{"will_not_fix"}, "no_fix_planned"
	case domain.FindingWontFix:
		v.Status = StatusAffected
		v.Action = "Will not fix" + reasonSuffix(t.Reason)
		v.Response, v.Remediation = []string{"will_not_fix"}, "no_fix_planned"
		// A justification explains a not_affected verdict only; on an affected
		// one every format would misstate it, so it stays in the history.
		if len(t.VexResponse) > 0 {
			v.Response = vexResponseStrings(t.VexResponse)
		}
	default:
		v.Status = StatusUnderInvestigation
	}
	return v
}

func until(t *time.Time) string {
	if t == nil {
		return ""
	}
	return " until " + t.UTC().Format("2006-01-02")
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return "."
	}
	return ": " + reason
}

func joinNonEmpty(sep string, parts ...string) string {
	return strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), sep)
}

// statementVerdict is the verdict a stored statement makes on its own, for
// statements no exported finding covers.
func statementVerdict(st Statement) Verdict {
	v := Verdict{Status: st.Status, Timestamp: st.UpdatedAt}
	switch st.Status {
	case StatusNotAffected:
		v.Justification = knownJustification(st.Justification)
		if v.Justification == "" {
			v.Impact = joinNonEmpty(": ", st.Justification, st.Detail)
		} else {
			v.Impact = st.Detail
		}
		if v.Justification == "" && v.Impact == "" {
			v.Impact = "Not affected (imported " + cmp.Or(st.Source, "VEX") + " statement)"
		}
	case StatusAffected:
		v.Action = cmp.Or(st.Detail, "No action recorded (imported "+cmp.Or(st.Source, "VEX")+" statement).")
		v.Remediation = "none_available"
	}
	return v
}

// verdictRank orders verdicts by caution when several findings speak about the
// same (vulnerability, product): one affected instance makes the product
// affected; an untriaged one keeps it under investigation; not_affected is only
// claimed when every instance says so.
func verdictRank(s Status) int {
	switch s {
	case StatusAffected:
		return 3
	case StatusUnderInvestigation:
		return 2
	case StatusFixed:
		return 1
	}
	return 0
}

// Combine merges two verdicts about the same (vulnerability, product).
func Combine(a, b Verdict) Verdict {
	ts := a.Timestamp
	if b.Timestamp.After(ts) {
		ts = b.Timestamp
	}
	out := a
	if ra, rb := verdictRank(a.Status), verdictRank(b.Status); rb > ra || (rb == ra && b.Timestamp.After(a.Timestamp)) {
		out = b
	}
	out.Timestamp = ts
	return out
}

// knownJustification is j normalized when it is a justification code of
// either vocabulary (CycloneDX or OpenVEX/CSAF), else "".
func knownJustification(j string) string {
	j = strings.ToLower(strings.TrimSpace(j))
	if openVEXJustification(j) == "" {
		return ""
	}
	return j
}

// openVEXJustification normalizes a stored justification (OpenVEX or CycloneDX
// vocabulary) to the OpenVEX / CSAF code; "" when it is neither.
func openVEXJustification(j string) string {
	switch j = strings.ToLower(strings.TrimSpace(j)); j {
	case "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist":
		return j
	case "code_not_present":
		return "vulnerable_code_not_present"
	case "code_not_reachable":
		return "vulnerable_code_not_in_execute_path"
	case "requires_dependency":
		return "component_not_present"
	case "requires_configuration", "requires_environment":
		return "vulnerable_code_cannot_be_controlled_by_adversary"
	case "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter", "protected_by_mitigating_control":
		return "inline_mitigations_already_exist"
	}
	return ""
}

// CycloneJustification maps an OpenVEX justification code (or a CycloneDX one,
// unchanged) onto the CycloneDX analysis vocabulary; "" when there is none.
func CycloneJustification(j string) string {
	switch j = strings.ToLower(strings.TrimSpace(j)); j {
	case "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
		"requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter",
		"protected_by_mitigating_control":
		return j
	}
	switch openVEXJustification(j) {
	case "component_not_present":
		return "requires_dependency"
	case "vulnerable_code_not_present":
		return "code_not_present"
	case "vulnerable_code_not_in_execute_path":
		return "code_not_reachable"
	case "vulnerable_code_cannot_be_controlled_by_adversary":
		return "requires_environment"
	case "inline_mitigations_already_exist":
		return "protected_by_mitigating_control"
	}
	return ""
}

// CycloneAnalysis renders a verdict as a CycloneDX vulnerability analysis.
func CycloneAnalysis(v Verdict) CDXAnalysis {
	a := CDXAnalysis{Justification: CycloneJustification(v.Justification)}
	switch v.Status {
	case StatusNotAffected:
		a.State, a.Detail = "not_affected", v.Impact
	case StatusFixed:
		a.State = "resolved"
	case StatusAffected:
		a.State, a.Detail = "exploitable", v.Action
	default:
		a.State = "in_triage"
	}
	if len(v.Response) > 0 {
		a.Response = v.Response
	}
	if !v.Timestamp.IsZero() {
		a.LastUpdated = v.Timestamp.UTC().Format(time.RFC3339)
	}
	return a
}

// CDXAnalysis is CycloneDX's vulnerabilities[].analysis.
type CDXAnalysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	LastUpdated   string   `json:"lastUpdated,omitempty"`
}

// ExportStatement is one (vulnerability, product) verdict of an export.
type ExportStatement struct {
	VulnID   string
	Aliases  []string
	Product  string
	Title    string
	Severity domain.Severity
	Verdict
}

// advisoryIDs are the vulnerability ids a finding is exported under: its CVEs,
// else its rule id when that is a CVE / GHSA (OSV findings carry the GHSA there).
func advisoryIDs(f finding.Finding) []string {
	var ids []string
	for _, c := range f.CVE {
		if c = strings.TrimSpace(c); c != "" && !slices.ContainsFunc(ids, func(x string) bool { return strings.EqualFold(x, c) }) {
			ids = append(ids, c)
		}
	}
	if len(ids) == 0 && isAdvisoryID(f.RuleID) {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func isAdvisoryID(id string) bool {
	u := strings.ToUpper(id)
	return strings.HasPrefix(u, "CVE-") || strings.HasPrefix(u, "GHSA-")
}

// matchFor finds the stored statement about vulnID that applies to f,
// preferring a product-specific one over a project-wide one (as match does).
func matchFor(stmts []Statement, vulnID string, f finding.Finding) (int, bool) {
	wildcard := -1
	for i, st := range stmts {
		if !strings.EqualFold(st.VulnID, vulnID) {
			continue
		}
		if st.Product == "" {
			wildcard = i
			continue
		}
		if namesProduct(st.Product, f) {
			return i, true
		}
	}
	return wildcard, wildcard >= 0
}

// BuildStatements derives the export's statements: one per (vulnerability,
// product) from the version's findings, merged with the project's stored VEX
// statements. A stored statement no exported finding covers is exported as
// stored (an upstream analysis of something not currently detected still is
// the project's analysis).
func BuildStatements(scope ExportScope, findings []ExportFinding, stmts []Statement) []ExportStatement {
	type key struct{ vuln, product string }
	byKey := map[key]*ExportStatement{}
	covered := make([]bool, len(stmts))
	projectProduct := scope.ProjectProduct()

	for _, ef := range findings {
		f := ef.Finding
		ids := advisoryIDs(f)
		product := productOf(f, projectProduct)
		for _, id := range ids {
			var stmt *Statement
			if i, ok := matchFor(stmts, id, f); ok {
				covered[i] = true
				stmt = &stmts[i]
			}
			v := VerdictFor(Triaged{Status: f.Status, Reason: f.ExceptionReason, By: f.ExceptionBy,
				ExpiresAt: f.ExceptionExpiresAt, FixedVersion: f.FixedVersion, At: ef.TriagedAt,
				VexJustification: f.VexJustification, VexResponse: f.VexResponse}, stmt)
			k := key{strings.ToUpper(id), product}
			if cur := byKey[k]; cur != nil {
				cur.Verdict = Combine(cur.Verdict, v)
				if f.Severity.Weight() > cur.Severity.Weight() {
					cur.Severity = f.Severity
				}
				continue
			}
			var aliases []string
			for _, other := range slices.Concat(ids, []string{f.RuleID}) {
				if !strings.EqualFold(other, id) && isAdvisoryID(other) && !slices.Contains(aliases, other) {
					aliases = append(aliases, other)
				}
			}
			byKey[k] = &ExportStatement{VulnID: id, Aliases: aliases, Product: product,
				Title: f.Title, Severity: f.Severity, Verdict: v}
		}
	}
	for i, st := range stmts {
		if covered[i] {
			continue
		}
		product := cmp.Or(st.Product, projectProduct)
		k := key{strings.ToUpper(st.VulnID), product}
		if byKey[k] != nil {
			continue
		}
		byKey[k] = &ExportStatement{VulnID: st.VulnID, Product: product, Verdict: statementVerdict(st)}
	}

	out := make([]ExportStatement, 0, len(byKey))
	for _, s := range byKey {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b ExportStatement) int {
		return cmp.Or(cmp.Compare(strings.ToUpper(a.VulnID), strings.ToUpper(b.VulnID)), cmp.Compare(a.Product, b.Product))
	})
	return out
}

// MergeStatements combines several already-deduped ExportStatement lists (one
// per version or project a stored VEX document's scope spans) into one, using
// the same (vulnerability, product) key and Combine rule BuildStatements uses
// within a single scope — so a document naming several versions or projects
// still asserts the most cautious verdict when more than one speaks about the
// same product.
func MergeStatements(groups ...[]ExportStatement) []ExportStatement {
	type key struct{ vuln, product string }
	byKey := map[key]*ExportStatement{}
	for _, g := range groups {
		for _, s := range g {
			k := key{strings.ToUpper(s.VulnID), s.Product}
			cur, ok := byKey[k]
			if !ok {
				cp := s
				byKey[k] = &cp
				continue
			}
			cur.Verdict = Combine(cur.Verdict, s.Verdict)
			if s.Severity.Weight() > cur.Severity.Weight() {
				cur.Severity = s.Severity
			}
			for _, a := range s.Aliases {
				if !strings.EqualFold(a, cur.VulnID) && !slices.Contains(cur.Aliases, a) {
					cur.Aliases = append(cur.Aliases, a)
				}
			}
		}
	}
	out := make([]ExportStatement, 0, len(byKey))
	for _, s := range byKey {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b ExportStatement) int {
		return cmp.Or(cmp.Compare(strings.ToUpper(a.VulnID), strings.ToUpper(b.VulnID)), cmp.Compare(a.Product, b.Product))
	})
	return out
}

// FilterByVuln keeps only the statements about vulnID (by its own id or one of
// its aliases) — how a vulnerability-scope document narrows a project's full
// statement list down to the one it documents.
func FilterByVuln(stmts []ExportStatement, vulnID string) []ExportStatement {
	out := make([]ExportStatement, 0, len(stmts))
	for _, s := range stmts {
		if strings.EqualFold(s.VulnID, vulnID) || slices.ContainsFunc(s.Aliases, func(a string) bool { return strings.EqualFold(a, vulnID) }) {
			out = append(out, s)
		}
	}
	return out
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// documentID is the stable identity of a project version's VEX document, or
// scope.DocID when a stored document overrides it.
func documentID(scope ExportScope) string {
	if scope.DocID != "" {
		return scope.DocID
	}
	version := cmp.Or(scope.VersionID, "default")
	if scope.PublicURL != "" {
		return scope.PublicURL + "/api/v1/projects/" + scope.ProjectID + "/vex/export?version_id=" + version
	}
	return "urn:xila:vex:" + scope.ProjectID + ":" + version
}

func author(scope ExportScope) string {
	if scope.Author != "" {
		return scope.Author
	}
	if scope.PublisherName != "" {
		return scope.PublisherName
	}
	if scope.PublicURL != "" {
		return "Xila (" + scope.PublicURL + ")"
	}
	return "Xila"
}

// --- OpenVEX v0.2.0 ---

type openVEXOut struct {
	Context    string            `json:"@context"`
	ID         string            `json:"@id"`
	Author     string            `json:"author"`
	Role       string            `json:"role,omitempty"`
	Timestamp  string            `json:"timestamp"`
	Version    int               `json:"version"`
	Tooling    string            `json:"tooling,omitempty"`
	Statements []openVEXStmtsOut `json:"statements"`
}

type openVEXStmtsOut struct {
	Vulnerability struct {
		Name    string   `json:"name"`
		Aliases []string `json:"aliases,omitempty"`
	} `json:"vulnerability"`
	Products        []openVEXProduct `json:"products"`
	Status          string           `json:"status"`
	Justification   string           `json:"justification,omitempty"`
	ImpactStatement string           `json:"impact_statement,omitempty"`
	ActionStatement string           `json:"action_statement,omitempty"`
	ActionTimestamp string           `json:"action_statement_timestamp,omitempty"`
	Timestamp       string           `json:"timestamp,omitempty"`
}

type openVEXProduct struct {
	ID          string            `json:"@id"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
}

// OpenVEX renders statements as an OpenVEX v0.2.0 document.
func OpenVEX(scope ExportScope, stmts []ExportStatement, now time.Time) any {
	doc := openVEXOut{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         documentID(scope),
		Author:     author(scope),
		Role:       "Document Creator",
		Timestamp:  rfc3339(now),
		Version:    cmp.Or(scope.TrackVersion, 1),
		Tooling:    "Xila",
		Statements: []openVEXStmtsOut{},
	}
	for _, s := range stmts {
		var o openVEXStmtsOut
		o.Vulnerability.Name = s.VulnID
		o.Vulnerability.Aliases = s.Aliases
		p := openVEXProduct{ID: s.Product}
		if strings.HasPrefix(s.Product, "pkg:") {
			p.Identifiers = map[string]string{"purl": s.Product}
		}
		o.Products = []openVEXProduct{p}
		o.Status = string(s.Status)
		if !s.Timestamp.IsZero() {
			o.Timestamp = rfc3339(s.Timestamp)
		}
		switch s.Status {
		case StatusNotAffected:
			o.Justification, o.ImpactStatement = openVEXJustification(s.Justification), s.Impact
		case StatusAffected:
			o.ActionStatement, o.ActionTimestamp = s.Action, o.Timestamp
		}
		doc.Statements = append(doc.Statements, o)
	}
	return doc
}

// --- CycloneDX 1.6 VEX ---

// CDXComponent is a CycloneDX component (the subset exports emit).
type CDXComponent struct {
	BomRef     string           `json:"bom-ref,omitempty"`
	Type       string           `json:"type"`
	Group      string           `json:"group,omitempty"`
	Name       string           `json:"name"`
	Version    string           `json:"version,omitempty"`
	Scope      string           `json:"scope,omitempty"`
	Hashes     []CDXHash        `json:"hashes,omitempty"`
	Licenses   []CDXLicense     `json:"licenses,omitempty"`
	Purl       string           `json:"purl,omitempty"`
	Cpe        string           `json:"cpe,omitempty"`
	Evidence   *CDXEvidence     `json:"evidence,omitempty"`
	Properties []map[string]any `json:"properties,omitempty"`
}

// CDXHash is a CycloneDX hash.
type CDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// CDXLicense is one CycloneDX license choice: a named license or an expression.
type CDXLicense struct {
	License    *CDXLicenseName `json:"license,omitempty"`
	Expression string          `json:"expression,omitempty"`
}

// CDXLicenseName is a license by SPDX id or by name.
type CDXLicenseName struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CDXEvidence carries where a component was found.
type CDXEvidence struct {
	Occurrences []CDXOccurrence `json:"occurrences"`
}

// CDXOccurrence is one location a component was found at.
type CDXOccurrence struct {
	Location string `json:"location"`
}

// CDXVulnerability is a CycloneDX vulnerabilities[] entry.
type CDXVulnerability struct {
	BomRef         string          `json:"bom-ref,omitempty"`
	ID             string          `json:"id"`
	Source         *CDXSource      `json:"source,omitempty"`
	References     []CDXReference  `json:"references,omitempty"`
	Ratings        []CDXRating     `json:"ratings,omitempty"`
	Description    string          `json:"description,omitempty"`
	Recommendation string          `json:"recommendation,omitempty"`
	Analysis       *CDXAnalysis    `json:"analysis,omitempty"`
	Affects        []CDXAffectsRef `json:"affects"`
}

// CDXSource names the database a vulnerability id comes from.
type CDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CDXReference is an alias of a vulnerability in another database.
type CDXReference struct {
	ID     string    `json:"id"`
	Source CDXSource `json:"source"`
}

// CDXRating is a severity rating.
type CDXRating struct {
	Severity string `json:"severity"`
}

// CDXAffectsRef points a vulnerability at a component by bom-ref.
type CDXAffectsRef struct {
	Ref string `json:"ref"`
}

// VulnSource is where an advisory id is published (nil for unknown schemes).
func VulnSource(id string) *CDXSource {
	u := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(u, "CVE-"):
		return &CDXSource{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + id}
	case strings.HasPrefix(u, "GHSA-"):
		return &CDXSource{Name: "GitHub", URL: "https://github.com/advisories/" + id}
	}
	return &CDXSource{Name: "OSV", URL: "https://osv.dev/vulnerability/" + id}
}

// CDXSeverity maps a Xila severity onto CycloneDX's vocabulary.
func CDXSeverity(s domain.Severity) string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}

type cdxVEXOut struct {
	BomFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []CDXComponent     `json:"components"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     cdxTools     `json:"tools"`
	Authors   []cdxAuthor  `json:"authors,omitempty"`
	Component CDXComponent `json:"component"`
}

type cdxTools struct {
	Components []CDXComponent `json:"components"`
}

type cdxAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// purlNameVersion extracts the package name and version from a purl (or
// returns a bare product identifier as the name).
func purlNameVersion(product string) (string, string) {
	if !strings.HasPrefix(product, "pkg:") {
		return product, ""
	}
	rest, _, _ := strings.Cut(strings.TrimPrefix(product, "pkg:"), "?")
	rest, _, _ = strings.Cut(rest, "#")
	name, version, _ := strings.Cut(rest, "@")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if n, err := url.PathUnescape(name); err == nil {
		name = n
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return name, version
}

// CDXSpecVersions are the CycloneDX versions the exports write: 1.6 (the
// default) and 1.7. 1.7 only adds optional fields, so the same document is
// valid under either; the version just says which schema to check it with.
var CDXSpecVersions = []string{"1.6", "1.7"}

// ParseCDXSpec reads ?spec=; "" is the default (1.6).
func ParseCDXSpec(q string) (string, error) {
	if q == "" {
		return CDXSpecVersions[0], nil
	}
	if !slices.Contains(CDXSpecVersions, q) {
		return "", fmt.Errorf("spec must be one of: %s", strings.Join(CDXSpecVersions, ", "))
	}
	return q, nil
}

// CycloneDXVEX renders statements as a CycloneDX VEX BOM of the given spec
// version: the project is the metadata component, every package product a
// component, and each statement a vulnerability whose affects[].ref points at
// its product's bom-ref.
func CycloneDXVEX(scope ExportScope, stmts []ExportStatement, serial, spec string, now time.Time) any {
	projectRef := scope.ProjectProduct()
	doc := cdxVEXOut{
		BomFormat:    "CycloneDX",
		SpecVersion:  spec,
		SerialNumber: "urn:uuid:" + serial,
		Version:      cmp.Or(scope.TrackVersion, 1),
		Metadata: cdxMetadata{
			Timestamp: rfc3339(now),
			Tools:     cdxTools{Components: []CDXComponent{{Type: "application", Name: "Xila"}}},
			Component: CDXComponent{BomRef: projectRef, Type: "application",
				Name: cmp.Or(scope.ProjectName, scope.ProjectSlug), Version: scope.VersionName, Purl: projectRef},
		},
		Components:      []CDXComponent{},
		Vulnerabilities: []CDXVulnerability{},
	}
	if scope.PublisherName != "" || scope.Author != "" {
		doc.Metadata.Authors = []cdxAuthor{{Name: scope.PublisherName, Email: scope.Author}}
	}
	seen := map[string]bool{projectRef: true}
	for _, s := range stmts {
		if !seen[s.Product] {
			seen[s.Product] = true
			name, version := purlNameVersion(s.Product)
			c := CDXComponent{BomRef: s.Product, Type: "library", Name: name, Version: version}
			if strings.HasPrefix(s.Product, "pkg:") {
				c.Purl = s.Product
			}
			doc.Components = append(doc.Components, c)
		}
		a := CycloneAnalysis(s.Verdict)
		v := CDXVulnerability{ID: s.VulnID, Source: VulnSource(s.VulnID), Description: s.Title,
			Analysis: &a, Affects: []CDXAffectsRef{{Ref: s.Product}}}
		for _, alias := range s.Aliases {
			v.References = append(v.References, CDXReference{ID: alias, Source: *VulnSource(alias)})
		}
		if s.Severity != "" {
			v.Ratings = []CDXRating{{Severity: CDXSeverity(s.Severity)}}
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
	}
	return doc
}

// --- CSAF 2.0, VEX profile ---

type csafOut struct {
	Document        csafDocument `json:"document"`
	ProductTree     csafTree     `json:"product_tree"`
	Vulnerabilities []csafVuln   `json:"vulnerabilities"`
}

type csafDocument struct {
	Category    string        `json:"category"`
	CSAFVersion string        `json:"csaf_version"`
	Lang        string        `json:"lang"`
	Publisher   csafPublisher `json:"publisher"`
	Title       string        `json:"title"`
	Tracking    csafTracking  `json:"tracking"`
}

type csafPublisher struct {
	Category       string `json:"category"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	ContactDetails string `json:"contact_details,omitempty"`
}

type csafTracking struct {
	ID                 string         `json:"id"`
	Status             string         `json:"status"`
	Version            string         `json:"version"`
	InitialReleaseDate string         `json:"initial_release_date"`
	CurrentReleaseDate string         `json:"current_release_date"`
	RevisionHistory    []csafRevision `json:"revision_history"`
	Generator          csafGenerator  `json:"generator"`
}

type csafRevision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type csafGenerator struct {
	Date   string `json:"date"`
	Engine struct {
		Name string `json:"name"`
	} `json:"engine"`
}

type csafTree struct {
	FullProductNames []csafProduct `json:"full_product_names"`
}

type csafProduct struct {
	Name      string             `json:"name"`
	ProductID string             `json:"product_id"`
	Helper    *csafProductHelper `json:"product_identification_helper,omitempty"`
}

type csafProductHelper struct {
	Purl string `json:"purl"`
}

type csafVuln struct {
	CVE           string            `json:"cve,omitempty"`
	IDs           []csafID          `json:"ids,omitempty"`
	Notes         []csafNote        `json:"notes"`
	ProductStatus csafProductStatus `json:"product_status"`
	Flags         []csafFlag        `json:"flags,omitempty"`
	Threats       []csafThreat      `json:"threats,omitempty"`
	Remediations  []csafRemediation `json:"remediations,omitempty"`
}

type csafID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type csafNote struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

type csafProductStatus struct {
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type csafFlag struct {
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids"`
}

type csafThreat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type csafRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

// csafIDSystem names the tracking system of a non-CVE advisory id.
func csafIDSystem(id string) string {
	if strings.HasPrefix(strings.ToUpper(id), "GHSA-") {
		return "GitHub Security Advisory"
	}
	return "OSV"
}

// CSAFVEX renders statements as a CSAF 2.0 document of the VEX profile
// (document.category csaf_vex): the mandatory product_tree, and per
// vulnerability its cve/ids, notes and product_status — with a flag or impact
// threat for every known_not_affected product and a remediation for every
// known_affected one, as the profile requires.
func CSAFVEX(scope ExportScope, stmts []ExportStatement, now time.Time) any {
	date := rfc3339(now)
	publisherURL := cmp.Or(scope.PublisherNamespace, scope.PublicURL, "urn:xila")
	title := cmp.Or(scope.Title, fmt.Sprintf("VEX for %s (%s)", cmp.Or(scope.ProjectName, scope.ProjectSlug), scope.VersionName))
	trackingID := cmp.Or(scope.DocID, "xila-vex-"+scope.ProjectID+"-"+cmp.Or(scope.VersionID, "default"))

	version := cmp.Or(scope.TrackVersion, 1)
	hist := []csafRevision{{Date: date, Number: "1", Summary: "Generated by Xila from the project's triage."}}
	initialDate, currentDate := date, date
	if len(scope.Revisions) > 0 {
		version = scope.Revisions[len(scope.Revisions)-1].Number
		initialDate = rfc3339(scope.Revisions[0].Date)
		currentDate = rfc3339(scope.Revisions[len(scope.Revisions)-1].Date)
		hist = hist[:0]
		for _, r := range scope.Revisions {
			hist = append(hist, csafRevision{Date: rfc3339(r.Date), Number: strconv.Itoa(r.Number),
				Summary: cmp.Or(r.Summary, "Generated by Xila from the project's data.")})
		}
	}

	doc := csafOut{
		Document: csafDocument{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Lang:        "en",
			Publisher: csafPublisher{Category: "vendor", Name: cmp.Or(scope.PublisherName, "Xila"), Namespace: publisherURL,
				ContactDetails: cmp.Or(scope.PublisherContact, scope.Author)},
			Title: title,
			Tracking: csafTracking{
				ID:                 trackingID,
				Status:             "final",
				Version:            strconv.Itoa(version),
				InitialReleaseDate: initialDate,
				CurrentReleaseDate: currentDate,
				RevisionHistory:    hist,
			},
		},
		ProductTree:     csafTree{FullProductNames: []csafProduct{}},
		Vulnerabilities: []csafVuln{},
	}
	doc.Document.Tracking.Generator.Date = date
	doc.Document.Tracking.Generator.Engine.Name = "Xila"

	productIDs := map[string]string{}
	productID := func(product string) string {
		if id, ok := productIDs[product]; ok {
			return id
		}
		id := fmt.Sprintf("CSAFPID-%04d", len(productIDs)+1)
		productIDs[product] = id
		p := csafProduct{Name: product, ProductID: id}
		if strings.HasPrefix(product, "pkg:") {
			p.Helper = &csafProductHelper{Purl: product}
		}
		doc.ProductTree.FullProductNames = append(doc.ProductTree.FullProductNames, p)
		return id
	}

	// Statements are sorted by vulnerability: group consecutive runs.
	for start := 0; start < len(stmts); {
		end := start
		for end < len(stmts) && strings.EqualFold(stmts[end].VulnID, stmts[start].VulnID) {
			end++
		}
		group := stmts[start:end]
		start = end

		id := group[0].VulnID
		v := csafVuln{Notes: []csafNote{{Category: "description", Title: "Vulnerability",
			Text: cmp.Or(group[0].Title, id)}}}
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			v.CVE = id
		} else {
			v.IDs = []csafID{{SystemName: csafIDSystem(id), Text: id}}
		}
		flags := map[string][]string{}
		threats := map[string][]string{}
		type remKey struct{ category, details string }
		rems := map[remKey][]string{}
		for _, s := range group {
			pid := productID(s.Product)
			switch s.Status {
			case StatusNotAffected:
				v.ProductStatus.KnownNotAffected = append(v.ProductStatus.KnownNotAffected, pid)
				j := openVEXJustification(s.Justification)
				if j != "" {
					flags[j] = append(flags[j], pid)
				}
				if s.Impact != "" || j == "" {
					details := cmp.Or(s.Impact, "Not affected.")
					threats[details] = append(threats[details], pid)
				}
			case StatusFixed:
				v.ProductStatus.Fixed = append(v.ProductStatus.Fixed, pid)
			case StatusAffected:
				v.ProductStatus.KnownAffected = append(v.ProductStatus.KnownAffected, pid)
				k := remKey{cmp.Or(s.Remediation, "none_available"), cmp.Or(s.Action, "No remediation recorded.")}
				rems[k] = append(rems[k], pid)
			default:
				v.ProductStatus.UnderInvestigation = append(v.ProductStatus.UnderInvestigation, pid)
			}
		}
		for _, label := range slices.Sorted(maps.Keys(flags)) {
			v.Flags = append(v.Flags, csafFlag{Label: label, ProductIDs: flags[label]})
		}
		for _, details := range slices.Sorted(maps.Keys(threats)) {
			v.Threats = append(v.Threats, csafThreat{Category: "impact", Details: details, ProductIDs: threats[details]})
		}
		remKeys := slices.Collect(maps.Keys(rems))
		slices.SortFunc(remKeys, func(a, b remKey) int {
			return cmp.Or(cmp.Compare(a.category, b.category), cmp.Compare(a.details, b.details))
		})
		for _, k := range remKeys {
			v.Remediations = append(v.Remediations, csafRemediation{Category: k.category, Details: k.details, ProductIDs: rems[k]})
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
	}
	return doc
}
