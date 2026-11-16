// Package finding stores normalized, deduplicated vulnerabilities.
package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/notify"
)

// ErrNotFound is returned when a finding does not exist.
var ErrNotFound = errors.New("finding not found")

// Finding is a persistent vulnerability, unique per (project version,
// fingerprint). It survives across scans: repeated sightings refresh LastSeenAt
// rather than creating duplicates.
type Finding struct {
	ID        string  `json:"id"`
	ProjectID string  `json:"project_id"`
	AssetID   *string `json:"asset_id"`
	// VersionID is the project version (branch / release) this finding lives on.
	// On upsert it may be left empty: it is then taken from LastScanID's scan, or
	// the project's default version when there is no scan.
	VersionID      string               `json:"version_id"`
	Fingerprint    string               `json:"fingerprint"`
	Scanner        string               `json:"scanner"`
	Category       domain.Category      `json:"category"`
	RuleID         string               `json:"rule_id"`
	Title          string               `json:"title"`
	Description    string               `json:"description"`
	Severity       domain.Severity      `json:"severity"`
	CWE            *int                 `json:"cwe"`
	CVE            []string             `json:"cve"`
	FilePath       string               `json:"file_path"`
	Line           *int                 `json:"line"`
	PackageName    string               `json:"package_name"`
	PackageVersion string               `json:"package_version"`
	FixedVersion   string               `json:"fixed_version"`
	Purl           string               `json:"purl"`
	URL            string               `json:"url"`
	Metadata       map[string]any       `json:"metadata"`
	Status         domain.FindingStatus `json:"status"`
	FirstSeenAt    time.Time            `json:"first_seen_at"`
	LastSeenAt     time.Time            `json:"last_seen_at"`
	FirstScanID    *string              `json:"first_scan_id"`
	LastScanID     *string              `json:"last_scan_id"`
	ResolvedAt     *time.Time           `json:"resolved_at"`
	CreatedAt      time.Time            `json:"created_at"`
	UpdatedAt      time.Time            `json:"updated_at"`
	// Enrichment / prioritization.
	CVSS     *float64 `json:"cvss"`
	EPSS     *float64 `json:"epss"`
	KEV      bool     `json:"kev"`
	Priority float64  `json:"priority"`
	// KEVSources names the catalogs asserting the finding is known-exploited
	// (cisa, enisa, vulncheck; sorted). KEV is true when any does.
	KEVSources []string `json:"kev_sources"`
	// KEVRansomware is true when a KEV catalog asserting the finding says the
	// flaw is known to be used in ransomware campaigns.
	KEVRansomware bool `json:"kev_ransomware"`
	// ExploitMaturity is the strongest public exploit known for the finding's
	// CVEs (internal/exploitintel): "", "poc" or "weaponized".
	ExploitMaturity domain.ExploitMaturity `json:"exploit_maturity"`
	// AssetExposure is the exposure of the finding's asset, read through
	// asset_id: nil when unknown or there is no asset. A priority input.
	AssetExposure *domain.Exposure `json:"asset_exposure"`
	// NVD CVSS (enrichment, NVD_ENABLED): the CVE's CVSS vector + version as NVD
	// publishes it. CVSSSource is "nvd" when CVSS itself was filled from NVD
	// because the scanner reported none; nil when CVSS (if any) is the scanner's.
	CVSSVector  *string `json:"cvss_vector"`
	CVSSVersion *string `json:"cvss_version"`
	CVSSSource  *string `json:"cvss_source"`
	// Exception (active false_positive / wont_fix): reason, who decided and an
	// optional expiry. Cleared on reopen/expiry. A risk_accepted finding carries
	// none: its reason and expiry are its RiskAcceptance's.
	ExceptionReason    string     `json:"exception_reason"`
	ExceptionBy        string     `json:"exception_by"`
	ExceptionExpiresAt *time.Time `json:"exception_expires_at"`
	// RiskAcceptance is the live (requested or approved) risk acceptance that
	// covers the finding, if any. Read-only.
	RiskAcceptance *AcceptanceRef `json:"risk_acceptance"`
	// TitleManual / SeverityManual: a person edited the scanner's value; the
	// next scan keeps it (and triage rules don't reset the severity) until it
	// is reset. PlannedRemediationAt is the team's own target date.
	TitleManual          bool       `json:"title_manual"`
	SeverityManual       bool       `json:"severity_manual"`
	PlannedRemediationAt *time.Time `json:"planned_remediation_at"`
	// SourceURL links file:line into the repository at the scanned commit
	// (GET /findings/{id} only; nil when the project has no recognized repo).
	SourceURL *string `json:"source_url,omitempty"`
	// Cross-tool dedup. CorrelationKey groups the same CVE+package across scanners;
	// DuplicateOf points a non-primary report at its elected primary (both set by
	// Deduplicate, not Upsert). DuplicateCount is computed for API responses only.
	CorrelationKey *string `json:"correlation_key"`
	DuplicateOf    *string `json:"duplicate_of"`
	DuplicateCount int     `json:"duplicate_count,omitempty"`
	// Tags are user-managed labels (lowercase; see NormalizeTags). Scanners
	// never set them; re-ingest leaves them alone.
	Tags []string `json:"tags"`
	// Custom holds the admin-defined custom fields' values (key → value; see
	// internal/customfield). Scanners never set them; re-ingest leaves them alone.
	Custom map[string]any `json:"custom"`
	// Reachability, matched from the project's current SBOM inventory (nil/"" when
	// we have no SBOM for the package). Direct = the project asked for this
	// dependency; DepDepth = hops from the root; DepScope = whether it ships.
	DepDirect *bool           `json:"dep_direct"`
	DepDepth  *int            `json:"dep_depth"`
	DepScope  domain.DepScope `json:"dep_scope"`
	// SLA, maintained by the findings_sla trigger: SLADays is the window this
	// finding's severity gets under its project's policy (nil = no SLA), SLADueAt
	// the deadline (extended by any time spent in an exception state). SLAStatus
	// is derived at read time.
	SLADays   *int             `json:"sla_days"`
	SLADueAt  *time.Time       `json:"sla_due_at"`
	SLAStatus domain.SLAStatus `json:"sla_status"`
	// AssigneeID is who owns fixing it (nil = unassigned); AssigneeEmail is
	// read alongside for display.
	AssigneeID    *string `json:"assignee_id"`
	AssigneeEmail *string `json:"assignee_email"`
	// ArchivedAt / ArchivedBy: set while the finding itself is archived
	// (internal/archive); a finding of an archived project is archived through
	// the project and carries neither. Re-reported by a scan, it is live again.
	ArchivedAt *time.Time `json:"archived_at"`
	ArchivedBy *string    `json:"archived_by"`
}

// Reachability is how much this finding's dependency can actually hurt us — the
// input to the priority multiplier.
func (f Finding) Reachability() domain.Reachability {
	return domain.Reachability{Direct: f.DepDirect, Scope: f.DepScope}
}

// Repository provides access to the findings table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// onDefaultVersion restricts a findings query (table alias-free) to each
// project's default version — what metrics, summaries, alerts and the default
// listings report. Feature branches and old releases are excluded so the same
// issue present on five branches counts once.
const onDefaultVersion = ` version_id IN (SELECT id FROM project_versions WHERE is_default)`

const findingColumns = `id, project_id, version_id, fingerprint, scanner, category, rule_id,
	title, description, severity, cwe, cve, file_path, line, package_name,
	package_version, fixed_version, purl, url, metadata, status, first_seen_at,
	last_seen_at, first_scan_id, last_scan_id, resolved_at, created_at, updated_at,
	cvss, epss, kev, kev_sources, kev_ransomware, priority, asset_id, cvss_vector, cvss_version, cvss_source,
	exception_reason, exception_by, exception_expires_at,
	correlation_key, duplicate_of, dep_direct, dep_depth, dep_scope,
	sla_days, sla_due_at, tags, custom, COALESCE(exploit_maturity, ''),
	assignee_id, (SELECT email FROM users WHERE users.id = assignee_id),
	(SELECT exposure FROM assets WHERE assets.id = asset_id),
	` + acceptanceRefSQL + `,
	title_manual, severity_manual, planned_remediation_at, archived_at, archived_by`

// assetExposureSQL reads a finding's asset exposure (table alias-free; ” when
// unknown or there is no asset) — the fourth domain.Priority input.
const assetExposureSQL = `COALESCE((SELECT exposure FROM assets WHERE assets.id = asset_id), '')`

// scanFinding reads findingColumns, then any extra columns selected after them.
func scanFinding(row pgx.Row, extra ...any) (Finding, error) {
	var f Finding
	err := row.Scan(append([]any{&f.ID, &f.ProjectID, &f.VersionID, &f.Fingerprint, &f.Scanner, &f.Category, &f.RuleID,
		&f.Title, &f.Description, &f.Severity, &f.CWE, &f.CVE, &f.FilePath, &f.Line, &f.PackageName,
		&f.PackageVersion, &f.FixedVersion, &f.Purl, &f.URL, &f.Metadata, &f.Status, &f.FirstSeenAt,
		&f.LastSeenAt, &f.FirstScanID, &f.LastScanID, &f.ResolvedAt, &f.CreatedAt, &f.UpdatedAt,
		&f.CVSS, &f.EPSS, &f.KEV, &f.KEVSources, &f.KEVRansomware, &f.Priority, &f.AssetID, &f.CVSSVector, &f.CVSSVersion, &f.CVSSSource,
		&f.ExceptionReason, &f.ExceptionBy, &f.ExceptionExpiresAt,
		&f.CorrelationKey, &f.DuplicateOf, &f.DepDirect, &f.DepDepth, &f.DepScope,
		&f.SLADays, &f.SLADueAt, &f.Tags, &f.Custom, &f.ExploitMaturity,
		&f.AssigneeID, &f.AssigneeEmail, &f.AssetExposure, &f.RiskAcceptance,
		&f.TitleManual, &f.SeverityManual, &f.PlannedRemediationAt, &f.ArchivedAt, &f.ArchivedBy}, extra...)...)
	if err == nil {
		f.SLAStatus = domain.SLAStatusAt(f.Status, f.SLADays, f.SLADueAt, f.ResolvedAt, time.Now())
	}
	return f, err
}

// Upsert inserts a new finding or, when one already exists for the same
// (version, fingerprint), refreshes its mutable fields and last-seen metadata.
// A finding previously marked remediated is reopened when it reappears.
func (r *Repository) Upsert(ctx context.Context, f Finding) (Finding, error) {
	out, err := scanFinding(r.db.QueryRow(ctx, upsertSQL+` RETURNING `+findingColumns, upsertArgs(f)...))
	if err != nil {
		return Finding{}, fmt.Errorf("upsert finding: %w", err)
	}
	return out, nil
}

// UpsertBatch upserts many findings using pipelined round-trips. A scan can carry
// thousands of findings; sending them one statement at a time makes ingestion
// latency a multiple of the network RTT. Chunked so a huge report doesn't build
// one enormous batch. Results are discarded — callers that need the stored rows
// back should use Upsert. actor attributes the history events the upserts
// write (a person filing a manual finding); "" records them as system.
func (r *Repository) UpsertBatch(ctx context.Context, fs []Finding, actor string) error {
	const chunk = 500
	for start := 0; start < len(fs); start += chunk {
		end := min(start+chunk, len(fs))

		// A batch is one implicit transaction, so the transaction-local actor
		// set first applies to every upsert in it.
		b := &pgx.Batch{}
		if actor != "" {
			b.Queue(`SELECT set_config('xila.actor', $1, true)`, actor)
		}
		for _, f := range fs[start:end] {
			b.Queue(upsertSQL, upsertArgs(f)...)
		}

		br := r.db.SendBatch(ctx, b)
		var firstErr error
		for range b.Len() {
			if _, err := br.Exec(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if err := br.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		if firstErr != nil {
			return fmt.Errorf("upsert findings: %w", firstErr)
		}
	}
	return nil
}

// upsertSQL inserts a sighting or refreshes the existing one. Note it sets
// first_scan_id = last_scan_id on insert only — that's how "new this scan" is
// detected. correlation_key/duplicate_of are deliberately absent: Deduplicate
// recomputes them.
const upsertSQL = `
		INSERT INTO findings (
			project_id, fingerprint, scanner, category, rule_id, title, description,
			severity, cwe, cve, file_path, line, package_name, package_version,
			fixed_version, purl, url, metadata, cvss, first_scan_id, last_scan_id, last_seen_at, priority, asset_id,
			version_id
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $20, $19, $19, now(),
			CASE $8 WHEN 'critical' THEN 15 WHEN 'high' THEN 7 WHEN 'medium' THEN 3 WHEN 'low' THEN 1 ELSE 0 END,
			$21,
			COALESCE($22::uuid, (SELECT version_id FROM scans WHERE id = $19), project_version($1, NULL, NULL))
		)
		ON CONFLICT (version_id, fingerprint) DO UPDATE SET
			-- A person's title / severity edit sticks until they reset it.
			title         = CASE WHEN findings.title_manual THEN findings.title ELSE EXCLUDED.title END,
			description   = EXCLUDED.description,
			severity      = CASE WHEN findings.severity_manual THEN findings.severity ELSE EXCLUDED.severity END,
			cwe           = EXCLUDED.cwe,
			cve           = EXCLUDED.cve,
			fixed_version = EXCLUDED.fixed_version,
			purl          = EXCLUDED.purl,
			url           = EXCLUDED.url,
			metadata      = EXCLUDED.metadata,
			-- A scanner-reported score wins; without one, an NVD-filled score stays
			-- (cvss_source = 'nvd') rather than flapping to NULL until enrichment.
			cvss          = CASE WHEN EXCLUDED.cvss IS NULL AND findings.cvss_source = 'nvd'
			                     THEN findings.cvss ELSE EXCLUDED.cvss END,
			cvss_source   = CASE WHEN EXCLUDED.cvss IS NULL THEN findings.cvss_source END,
			asset_id      = COALESCE(EXCLUDED.asset_id, findings.asset_id),
			last_scan_id  = EXCLUDED.last_scan_id,
			last_seen_at  = now(),
			status        = CASE WHEN findings.status = 'remediated' THEN 'open' ELSE findings.status END,
			resolved_at   = CASE WHEN findings.status = 'remediated' THEN NULL ELSE findings.resolved_at END,
			-- Reported again: an archived finding exists again, so it is live.
			archived_at   = NULL,
			archived_by   = NULL,
			updated_at    = now()`

// upsertArgs orders a finding's fields to match upsertSQL's placeholders.
func upsertArgs(f Finding) []any {
	// The cve/metadata columns are NOT NULL: a passed value overrides the column
	// default, so coalesce nils to empty rather than sending SQL NULL.
	cve := f.CVE
	if cve == nil {
		cve = []string{}
	}
	metadata := f.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	var version *string
	if f.VersionID != "" {
		version = &f.VersionID
	}
	return []any{
		f.ProjectID, f.Fingerprint, f.Scanner, f.Category, f.RuleID, f.Title, f.Description,
		f.Severity, f.CWE, cve, f.FilePath, f.Line, f.PackageName, f.PackageVersion,
		f.FixedVersion, f.Purl, f.URL, metadata, f.LastScanID, f.CVSS, f.AssetID, version,
	}
}

// Filter narrows a finding listing. Limit defaults to 100 when unset.
type Filter struct {
	ProjectID  string
	ProjectIDs []string // RBAC scope: non-nil restricts to these projects
	AssetID    string
	Status     domain.FindingStatus
	// OpenOnly narrows to findings still awaiting a fix (open / confirmed).
	OpenOnly bool
	Severity domain.Severity
	Category domain.Category
	Scanner  string
	// RuleID narrows to one rule — e.g. a policy's violations (scanner policy).
	RuleID  string
	KEVOnly bool
	// RansomwareOnly narrows to findings a KEV catalog marks as used in
	// ransomware campaigns.
	RansomwareOnly bool
	// Reachable narrows to findings that plausibly matter: the dependency ships
	// (not dev-only) and the project asked for it (not transitive). Findings with
	// no reachability data are kept — unknown is never treated as safe.
	ReachableOnly bool
	// DirectOnly / Scope filter on the SBOM-derived facts individually.
	DirectOnly bool
	Scope      domain.DepScope
	// ScanID narrows to the findings one scan reported (its last_scan_id).
	ScanID string
	// EngagementID narrows to the findings an engagement's scans reported
	// (first or last seen in one of them), on any version.
	EngagementID string
	// Severities keeps findings at any of these severities (report minimums).
	Severities []domain.Severity
	// Exploit narrows by public exploit: "poc", "weaponized", or "any" (either).
	Exploit string
	// VersionID narrows to one project version. With neither VersionID, ScanID
	// nor AllVersions set, listings show each project's default version only —
	// otherwise every issue would appear once per branch that carries it.
	VersionID   string
	AllVersions bool
	// VersionName narrows to a version of ProjectID by name (branch / release).
	VersionName string
	// AssigneeID narrows to one assignee; Unassigned to findings nobody owns.
	AssigneeID string
	Unassigned bool
	// NewOnly narrows to findings first seen in the scan that reported them —
	// "what this change introduced", which is what a PR comment and a new-only gate
	// are actually about.
	NewOnly bool
	// SLA narrows to findings in one SLA state (see domain.SLAStatus).
	SLA domain.SLAStatus
	// Query is a full-text search (websearch syntax: words, "quoted phrases",
	// -excluded, or) over title, rule, CVEs, package, purl, path, tags and
	// description. Without an explicit Sort, results rank by relevance.
	Query string
	// Tags keeps findings carrying every one of these tags.
	Tags []string
	// Custom keeps findings whose custom fields match (?cf.<key>=…).
	Custom []customfield.Cond
	// IncludeDuplicates includes cross-tool duplicate reports; default hides them.
	IncludeDuplicates bool
	// Archived lists archived findings (their own, their scan's or their
	// project's archive) instead of live ones.
	Archived bool
	// Sort is "priority" (highest first), "sla_due" (soonest deadline first), or
	// "" for most-recently-seen.
	Sort   string
	Limit  int
	Offset int
}

// List returns findings matching the filter, newest first. Scope by ProjectID
// and/or AssetID.
func (r *Repository) List(ctx context.Context, f Filter) ([]Finding, error) {
	q, args := listQuery(f, findingColumns)
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	args = append(args, limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))
	if f.Offset > 0 {
		args = append(args, f.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	findings := []Finding{}
	for rows.Next() {
		fnd, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, fnd)
	}
	return findings, rows.Err()
}

// listQuery builds the SELECT of cols over the findings f matches, in f.Sort
// order, without a LIMIT — shared by List and Each so an export is exactly the
// listing it was taken from.
func listQuery(f Filter, cols string) (string, []any) {
	q := `SELECT ` + cols + ` FROM findings WHERE 1 = 1`
	var args []any

	if f.ProjectID != "" {
		args = append(args, f.ProjectID)
		q += fmt.Sprintf(" AND project_id = $%d", len(args))
	}
	if f.AssetID != "" {
		args = append(args, f.AssetID)
		q += fmt.Sprintf(" AND asset_id = $%d", len(args))
	}
	switch {
	case f.VersionID != "":
		args = append(args, f.VersionID)
		q += fmt.Sprintf(" AND version_id = $%d", len(args))
	case f.VersionName != "" && f.ProjectID != "":
		args = append(args, f.ProjectID, f.VersionName)
		q += fmt.Sprintf(" AND version_id = (SELECT id FROM project_versions WHERE project_id = $%d AND name = $%d)",
			len(args)-1, len(args))
	case f.VersionName != "" && f.ProjectIDs != nil:
		// A rollup: the version of that name in each project that has one.
		args = append(args, f.ProjectIDs, f.VersionName)
		q += fmt.Sprintf(" AND version_id IN (SELECT id FROM project_versions WHERE project_id = ANY($%d) AND name = $%d)",
			len(args)-1, len(args))
	case f.ScanID == "" && f.EngagementID == "" && !f.AllVersions:
		q += " AND" + onDefaultVersion
	}
	if f.ProjectIDs != nil {
		args = append(args, f.ProjectIDs)
		q += fmt.Sprintf(" AND project_id = ANY($%d)", len(args))
	}
	switch {
	case f.AssigneeID != "":
		args = append(args, f.AssigneeID)
		q += fmt.Sprintf(" AND assignee_id = $%d", len(args))
	case f.Unassigned:
		q += " AND assignee_id IS NULL"
	}
	if f.Status != "" {
		args = append(args, f.Status)
		q += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if f.OpenOnly {
		q += ` AND status IN ('open', 'confirmed')`
	}
	if f.Severity != "" {
		args = append(args, f.Severity)
		q += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if f.Category != "" {
		args = append(args, f.Category)
		q += fmt.Sprintf(" AND category = $%d", len(args))
	}
	if f.Scanner != "" {
		args = append(args, f.Scanner)
		q += fmt.Sprintf(" AND scanner = $%d", len(args))
	}
	if f.RuleID != "" {
		args = append(args, f.RuleID)
		q += fmt.Sprintf(" AND rule_id = $%d", len(args))
	}
	if f.KEVOnly {
		q += ` AND kev`
	}
	if f.RansomwareOnly {
		q += ` AND kev_ransomware`
	}
	switch f.Exploit {
	case "any":
		q += ` AND exploit_maturity IS NOT NULL`
	case "poc", "weaponized":
		args = append(args, f.Exploit)
		q += fmt.Sprintf(" AND exploit_maturity = $%d", len(args))
	}
	if f.ScanID != "" {
		args = append(args, f.ScanID)
		q += fmt.Sprintf(" AND last_scan_id = $%d", len(args))
	}
	if f.EngagementID != "" {
		args = append(args, f.EngagementID)
		q += fmt.Sprintf(` AND EXISTS (SELECT 1 FROM scans es WHERE es.engagement_id = $%d
			AND es.id IN (first_scan_id, last_scan_id))`, len(args))
	}
	if len(f.Severities) > 0 {
		args = append(args, f.Severities)
		q += fmt.Sprintf(" AND severity = ANY($%d)", len(args))
	}
	if f.NewOnly {
		q += ` AND first_scan_id = last_scan_id`
	}
	if f.ReachableOnly {
		q += ` AND dep_scope <> 'dev' AND dep_direct IS NOT FALSE`
	}
	if f.DirectOnly {
		q += ` AND dep_direct`
	}
	if f.Scope != "" {
		args = append(args, f.Scope)
		q += fmt.Sprintf(" AND dep_scope = $%d", len(args))
	}
	if f.SLA != "" {
		var cond string
		cond, args = slaCondition(f.SLA, args)
		q += " AND " + cond
	}
	if !f.IncludeDuplicates {
		q += ` AND duplicate_of IS NULL` // collapse cross-tool duplicates
	}
	q += " AND" + archive.Only(archive.Finding(""), f.Archived)
	if len(f.Tags) > 0 {
		args = append(args, f.Tags)
		q += fmt.Sprintf(" AND tags @> $%d", len(args))
	}
	if len(f.Custom) > 0 {
		var cond string
		cond, args = customfield.AppendSQL(f.Custom, "custom", args)
		q += cond
	}
	rank := ""
	if f.Query != "" {
		args = append(args, f.Query)
		q += fmt.Sprintf(" AND search @@ websearch_to_tsquery('simple', $%d)", len(args))
		rank = fmt.Sprintf("ts_rank(search, websearch_to_tsquery('simple', $%d))", len(args))
	}
	switch {
	case f.Sort == "priority":
		q += ` ORDER BY priority DESC, last_seen_at DESC`
	case f.Sort == "sla_due":
		q += ` ORDER BY sla_due_at ASC NULLS LAST, priority DESC`
	case rank != "": // a search without an explicit sort: most relevant first
		q += ` ORDER BY ` + rank + ` DESC, priority DESC, last_seen_at DESC`
	default:
		q += ` ORDER BY last_seen_at DESC`
	}
	return q, args
}

// Labeled is a finding with the project and version names an export prints in
// place of their ids.
type Labeled struct {
	Finding
	ProjectName string
	VersionName string
}

// Each streams the findings f matches — exactly List's rows and order, ignoring
// Limit/Offset — to fn from a single cursor, stopping after limit rows. Exports
// use it so a download never holds the whole result set in memory.
func (r *Repository) Each(ctx context.Context, f Filter, limit int, fn func(Labeled) error) error {
	q, args := listQuery(f, findingColumns+`,
		(SELECT p.name FROM projects p WHERE p.id = findings.project_id),
		(SELECT v.name FROM project_versions v WHERE v.id = findings.version_id)`)
	args = append(args, limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("export findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var l Labeled
		if l.Finding, err = scanFinding(rows, &l.ProjectName, &l.VersionName); err != nil {
			return fmt.Errorf("scan finding: %w", err)
		}
		if err := fn(l); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Status sets the SLA SQL is written against; they mirror FindingStatus.CountsRisk
// and FindingStatus.PausesSLA.
const (
	slaLiveStatuses   = `status IN ('open', 'confirmed')`
	slaPausedStatuses = `status IN ('risk_accepted', 'false_positive', 'wont_fix')`
)

// slaCondition is the SQL form of domain.SLAStatusAt for one status, appending
// any parameter it needs. The due-soon fraction is passed in so it has one source.
func slaCondition(s domain.SLAStatus, args []any) (string, []any) {
	frac := func() string {
		args = append(args, domain.SLADueSoonFraction)
		return fmt.Sprintf("make_interval(days => sla_days) * $%d", len(args))
	}
	switch s {
	case domain.SLANone:
		return `sla_due_at IS NULL`, args
	case domain.SLABreached:
		return slaLiveStatuses + ` AND sla_due_at < now()`, args
	case domain.SLADueSoon:
		cond := slaLiveStatuses + ` AND sla_due_at >= now() AND sla_due_at - now() <= ` + frac()
		return cond, args
	case domain.SLAOnTrack:
		cond := slaLiveStatuses + ` AND sla_due_at - now() > ` + frac()
		return cond, args
	case domain.SLAPaused:
		return slaPausedStatuses + ` AND sla_due_at IS NOT NULL`, args
	case domain.SLAMet:
		return `status = 'remediated' AND resolved_at <= sla_due_at`, args
	case domain.SLAMissed:
		return `status = 'remediated' AND sla_due_at IS NOT NULL AND (resolved_at IS NULL OR resolved_at > sla_due_at)`, args
	}
	return `false`, args
}

// SLAResolvedWindowDays is the look-back for the "how are we doing" SLA metrics
// (compliance, MTTR): recent performance, not the project's whole history.
const SLAResolvedWindowDays = 90

// SLAStats is SLA posture over a set of projects' non-duplicate findings.
type SLAStats struct {
	// Live backlog against its deadlines.
	Breached           int                     `json:"breached"`
	DueSoon            int                     `json:"due_soon"`
	OnTrack            int                     `json:"on_track"`
	Paused             int                     `json:"paused"`
	BreachedBySeverity map[domain.Severity]int `json:"breached_by_severity"`
	// Remediated in the last SLAResolvedWindowDays: fixed on time vs late, the
	// share fixed on time (nil when nothing with an SLA was fixed), and the mean
	// days from first seen to fixed per severity.
	Met        int                         `json:"met"`
	Missed     int                         `json:"missed"`
	Compliance *float64                    `json:"compliance"`
	MTTRDays   map[domain.Severity]float64 `json:"mttr_days"`
	WindowDays int                         `json:"window_days"`
}

// SLAParts is one project's share of SLAStats, in summable form (counts, and
// remediation days as a sum and a count), so a portfolio can be combined from
// per-project parts, live or from snapshots, with the same result.
type SLAParts struct {
	Breached  map[domain.Severity]int     `json:"breached"`
	DueSoon   int                         `json:"due_soon"`
	OnTrack   int                         `json:"on_track"`
	Paused    int                         `json:"paused"`
	Met       int                         `json:"met"`
	Missed    int                         `json:"missed"`
	DaysSum   map[domain.Severity]float64 `json:"days_sum"`
	DaysCount map[domain.Severity]int     `json:"days_count"`
}

func newSLAParts() *SLAParts {
	return &SLAParts{Breached: map[domain.Severity]int{}, DaysSum: map[domain.Severity]float64{}, DaysCount: map[domain.Severity]int{}}
}

// SLAStats is the SLA posture of projectIDs (nil = every project): the
// combination of their SLAParts.
func (r *Repository) SLAStats(ctx context.Context, projectIDs []string) (SLAStats, error) {
	parts, err := r.SLAPartsByProject(ctx, projectIDs)
	if err != nil {
		return SLAStats{}, err
	}
	list := make([]SLAParts, 0, len(parts))
	for _, p := range parts {
		list = append(list, p)
	}
	return CombineSLA(list), nil
}

// CombineSLA adds up per-project SLAParts into SLAStats.
func CombineSLA(parts []SLAParts) SLAStats {
	out := SLAStats{
		BreachedBySeverity: map[domain.Severity]int{},
		MTTRDays:           map[domain.Severity]float64{},
		WindowDays:         SLAResolvedWindowDays,
	}
	sum := map[domain.Severity]float64{}
	cnt := map[domain.Severity]int{}
	for _, p := range parts {
		for sev, n := range p.Breached {
			out.Breached += n
			if n > 0 {
				out.BreachedBySeverity[sev] += n
			}
		}
		out.DueSoon += p.DueSoon
		out.OnTrack += p.OnTrack
		out.Paused += p.Paused
		out.Met += p.Met
		out.Missed += p.Missed
		for sev, v := range p.DaysSum {
			sum[sev] += v
		}
		for sev, n := range p.DaysCount {
			cnt[sev] += n
		}
	}
	for sev, n := range cnt {
		if n > 0 {
			out.MTTRDays[sev] = sum[sev] / float64(n)
		}
	}
	if total := out.Met + out.Missed; total > 0 {
		c := float64(out.Met) / float64(total)
		out.Compliance = &c
	}
	return out
}

// SLAPartsByProject computes each project's SLAParts (projects with no
// finding under an SLA are absent).
func (r *Repository) SLAPartsByProject(ctx context.Context, projectIDs []string) (map[string]SLAParts, error) {
	out := map[string]*SLAParts{}
	get := func(pid string) *SLAParts {
		p := out[pid]
		if p == nil {
			p = newSLAParts()
			out[pid] = p
		}
		return p
	}
	live := `
		SELECT project_id, severity,
			count(*) FILTER (WHERE ` + slaLiveStatuses + ` AND sla_due_at < now()),
			count(*) FILTER (WHERE ` + slaLiveStatuses + ` AND sla_due_at >= now()
			                   AND sla_due_at - now() <= make_interval(days => sla_days) * $2),
			count(*) FILTER (WHERE ` + slaLiveStatuses + ` AND sla_due_at - now() > make_interval(days => sla_days) * $2),
			count(*) FILTER (WHERE ` + slaPausedStatuses + `)
		FROM findings
		WHERE duplicate_of IS NULL AND sla_due_at IS NOT NULL AND` + onDefaultVersion + ` AND` + archive.Finding("") + `
		  AND ($1::uuid[] IS NULL OR project_id = ANY($1))
		GROUP BY project_id, severity`
	rows, err := r.db.Query(ctx, live, projectIDs, domain.SLADueSoonFraction)
	if err != nil {
		return nil, fmt.Errorf("sla live stats: %w", err)
	}
	for rows.Next() {
		var pid string
		var sev domain.Severity
		var breached, dueSoon, onTrack, paused int
		if err := rows.Scan(&pid, &sev, &breached, &dueSoon, &onTrack, &paused); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan sla live stats: %w", err)
		}
		p := get(pid)
		if breached > 0 {
			p.Breached[sev] += breached
		}
		p.DueSoon += dueSoon
		p.OnTrack += onTrack
		p.Paused += paused
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sla live stats: %w", err)
	}

	resolved := `
		SELECT project_id, severity,
			count(*) FILTER (WHERE resolved_at <= sla_due_at),
			count(*) FILTER (WHERE resolved_at > sla_due_at),
			COALESCE(sum(extract(epoch FROM resolved_at - first_seen_at)) / 86400, 0)::float8,
			count(*)
		FROM findings
		WHERE status = 'remediated' AND duplicate_of IS NULL AND` + onDefaultVersion + ` AND` + archive.Finding("") + `
		  AND resolved_at > now() - make_interval(days => $2)
		  AND ($1::uuid[] IS NULL OR project_id = ANY($1))
		GROUP BY project_id, severity`
	rows, err = r.db.Query(ctx, resolved, projectIDs, SLAResolvedWindowDays)
	if err != nil {
		return nil, fmt.Errorf("sla resolved stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pid string
		var sev domain.Severity
		var met, missed, n int
		var days float64
		if err := rows.Scan(&pid, &sev, &met, &missed, &days, &n); err != nil {
			return nil, fmt.Errorf("scan sla resolved stats: %w", err)
		}
		p := get(pid)
		p.Met += met
		p.Missed += missed
		p.DaysSum[sev] += days
		p.DaysCount[sev] += n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sla resolved stats: %w", err)
	}
	res := make(map[string]SLAParts, len(out))
	for k, v := range out {
		res[k] = *v
	}
	return res, nil
}

// Get returns a finding by id.
func (r *Repository) Get(ctx context.Context, id string) (Finding, error) {
	const q = `SELECT ` + findingColumns + ` FROM findings WHERE id = $1`
	f, err := scanFinding(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	if err != nil {
		return Finding{}, fmt.Errorf("get finding: %w", err)
	}
	return f, nil
}

// Triage is a status change, optionally carrying an exception (reason + expiry
// + who decided it). It can't set risk_accepted: only an approved risk
// acceptance does that (ErrRiskAcceptanceRequired).
type Triage struct {
	Status    domain.FindingStatus
	Reason    string
	Actor     string
	ExpiresAt *time.Time
}

// isExceptionStatus reports whether a status is a triage exception that carries
// its own reason and optional expiry on the finding (false_positive,
// wont_fix). risk_accepted is an exception too, but its reason and expiry live
// on the covering risk acceptance.
func isExceptionStatus(s domain.FindingStatus) bool {
	return s == domain.FindingFalsePositive || s == domain.FindingWontFix
}

// SetStatus transitions a finding's triage status. Moving to an exception state
// records the reason/actor/expiry on the finding and appends an audit row;
// moving out of one clears the active exception. Any status set by hand also
// takes the finding out of its live risk acceptance (the ledger keeps it).
func (r *Repository) SetStatus(ctx context.Context, id string, t Triage) (Finding, error) {
	if t.Status == domain.FindingRiskAccepted {
		return Finding{}, ErrRiskAcceptanceRequired
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Finding{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	// Attribute the change in the finding's history (findings_events trigger).
	if err := withActor(ctx, tx, t.Actor, t.Reason); err != nil {
		return Finding{}, err
	}
	f, err := setStatusTx(ctx, tx, id, t)
	if err != nil {
		return Finding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, fmt.Errorf("commit: %w", err)
	}
	return f, nil
}

// setStatusTx is SetStatus inside tx (whose actor is already set). Shared with
// an approved assessment, so both land exactly the same way.
func setStatusTx(ctx context.Context, tx pgx.Tx, id string, t Triage) (Finding, error) {
	if t.Status == domain.FindingRiskAccepted {
		return Finding{}, ErrRiskAcceptanceRequired
	}
	if err := leaveAcceptances(ctx, tx, []string{id}, t.Actor, "status set to "+string(t.Status)); err != nil {
		return Finding{}, err
	}
	reason, actor := "", ""
	var expires *time.Time
	if isExceptionStatus(t.Status) {
		reason, actor, expires = t.Reason, t.Actor, t.ExpiresAt
	}
	const q = `
		UPDATE findings
		SET status               = $2,
		    resolved_at          = CASE
		        WHEN $2 IN ('false_positive', 'remediated', 'wont_fix')
		        THEN now() ELSE NULL END,
		    exception_reason     = $3,
		    exception_by         = $4,
		    exception_expires_at = $5,
		    updated_at           = now()
		WHERE id = $1
		RETURNING ` + findingColumns
	f, err := scanFinding(tx.QueryRow(ctx, q, id, t.Status, reason, actor, expires))
	if errors.Is(err, pgx.ErrNoRows) {
		return Finding{}, ErrNotFound
	}
	if err != nil {
		return Finding{}, fmt.Errorf("set finding status: %w", err)
	}

	if isExceptionStatus(t.Status) {
		if _, err := tx.Exec(ctx,
			`INSERT INTO finding_exceptions (finding_id, project_id, status, reason, actor, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			f.ID, f.ProjectID, t.Status, reason, actor, expires); err != nil {
			return Finding{}, fmt.Errorf("record exception: %w", err)
		}
	}
	return f, nil
}

// ExpireExceptions reopens false_positive / wont_fix findings whose exception
// has passed its expiry, recording an "expired" audit event. Returns the
// number reopened. (Risk acceptances expire as a whole: ExpireAcceptances.)
func (r *Repository) ExpireExceptions(ctx context.Context) (int64, error) {
	const q = `
		WITH expired AS (
			UPDATE findings
			SET status = 'open', resolved_at = NULL,
			    exception_reason = '', exception_by = '', exception_expires_at = NULL,
			    updated_at = now()
			WHERE status IN ('false_positive', 'wont_fix')
			  AND exception_expires_at IS NOT NULL
			  AND exception_expires_at <= now()
			RETURNING id, project_id
		),
		logged AS (
			INSERT INTO finding_exceptions (finding_id, project_id, status, reason, actor)
			SELECT id, project_id, 'open', 'exception expired', 'system' FROM expired
		)
		SELECT count(*) FROM expired`
	var n int64
	if err := r.db.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("expire exceptions: %w", err)
	}
	return n, nil
}

// ExceptionExpirySQL is when a finding's exception lapses (alias-free, over
// findings): the approved covering risk acceptance's expiry for risk_accepted,
// the finding's own exception expiry for false_positive / wont_fix, NULL
// otherwise or when it never lapses.
const ExceptionExpirySQL = `(CASE
	WHEN findings.status = 'risk_accepted' THEN (
		SELECT ra.expires_at FROM risk_acceptance_findings ram
		JOIN risk_acceptances ra ON ra.id = ram.acceptance_id
		WHERE ram.finding_id = findings.id AND ram.removed_at IS NULL AND ra.state = 'approved')
	WHEN findings.status IN ('false_positive', 'wont_fix') THEN findings.exception_expires_at
	END)`

// ListExpiring returns exception findings whose exception (or covering risk
// acceptance) expires within the next `days` days (across all projects),
// soonest first — the review queue.
func (r *Repository) ListExpiring(ctx context.Context, days int, projectIDs []string) ([]Finding, error) {
	if days <= 0 {
		days = 30
	}
	q := `SELECT ` + findingColumns + ` FROM findings
		WHERE ` + ExceptionExpirySQL + ` > now()
		  AND ` + ExceptionExpirySQL + ` <= now() + make_interval(days => $1)
		  AND` + onDefaultVersion + ` AND` + archive.Finding("")
	args := []any{days}
	if projectIDs != nil {
		args = append(args, projectIDs)
		q += fmt.Sprintf(" AND project_id = ANY($%d)", len(args))
	}
	q += ` ORDER BY ` + ExceptionExpirySQL + ` ASC`
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list expiring: %w", err)
	}
	defer rows.Close()
	findings := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// ListNewHighSeverity returns critical/high findings first created by the given
// scan (first_scan_id) and still live — i.e. the "scary new stuff" to alert on.
func (r *Repository) ListNewHighSeverity(ctx context.Context, scanID string) ([]Finding, error) {
	q := `SELECT ` + findingColumns + ` FROM findings
		WHERE first_scan_id = $1
		  AND severity IN ('critical', 'high')
		  AND status IN ('open', 'confirmed')
		  AND duplicate_of IS NULL
		  -- Alerts follow the default branch: a first scan of a new feature branch
		  -- makes everything "new" on that branch, and would page for all of it.
		  AND` + onDefaultVersion + ` AND` + archive.Finding("") + `
		ORDER BY priority DESC`
	rows, err := r.db.Query(ctx, q, scanID)
	if err != nil {
		return nil, fmt.Errorf("list new high severity: %w", err)
	}
	defer rows.Close()
	findings := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// SummaryData computes a scheduled summary's figures for one project (or the
// whole portfolio when projectID is ""): what appeared and was fixed since
// `since`, and the open backlog now. Same counting rules as every other view:
// default versions only, cross-tool duplicates collapsed.
func (r *Repository) SummaryData(ctx context.Context, projectID string, since time.Time) (notify.SummaryData, error) {
	d := notify.SummaryData{New: map[string]int{}, Open: map[string]int{}, TopTitles: []string{}}
	var pid *string
	if projectID != "" {
		pid = &projectID
	}
	scope := ` duplicate_of IS NULL AND` + onDefaultVersion + ` AND` + archive.Finding("") + ` AND ($1::uuid IS NULL OR project_id = $1)`

	rows, err := r.db.Query(ctx, `
		SELECT severity,
		       count(*) FILTER (WHERE first_seen_at >= $2)::int,
		       count(*) FILTER (WHERE status IN ('open', 'confirmed'))::int
		FROM findings WHERE`+scope+` GROUP BY severity`, pid, since)
	if err != nil {
		return d, fmt.Errorf("summary by severity: %w", err)
	}
	for rows.Next() {
		var sev string
		var n, open int
		if err := rows.Scan(&sev, &n, &open); err != nil {
			rows.Close()
			return d, fmt.Errorf("scan summary: %w", err)
		}
		if n > 0 {
			d.New[sev] = n
		}
		if open > 0 {
			d.Open[sev] = open
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return d, fmt.Errorf("summary by severity: %w", err)
	}

	breached, args := slaCondition(domain.SLABreached, []any{pid, since})
	if err := r.db.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status = 'remediated' AND resolved_at >= $2)::int,
		       count(*) FILTER (WHERE `+breached+`)::int,
		       count(*) FILTER (WHERE kev AND status IN ('open', 'confirmed'))::int,
		       count(*) FILTER (WHERE `+ExceptionExpirySQL+` > now()
		                          AND `+ExceptionExpirySQL+` <= now() + interval '30 days')::int
		FROM findings WHERE`+scope, args...).Scan(&d.Fixed, &d.Breached, &d.KEV, &d.Expiring); err != nil {
		return d, fmt.Errorf("summary counts: %w", err)
	}

	top, err := r.db.Query(ctx, `
		SELECT title FROM findings
		WHERE`+scope+` AND status IN ('open', 'confirmed')
		ORDER BY priority DESC, first_seen_at LIMIT 5`, pid)
	if err != nil {
		return d, fmt.Errorf("summary top: %w", err)
	}
	defer top.Close()
	for top.Next() {
		var t string
		if err := top.Scan(&t); err != nil {
			return d, fmt.Errorf("scan top: %w", err)
		}
		d.TopTitles = append(d.TopTitles, t)
	}
	return d, top.Err()
}

// Exception is an audit record of a triage/exception action on a finding.
type Exception struct {
	ID        string               `json:"id"`
	FindingID string               `json:"finding_id"`
	Status    domain.FindingStatus `json:"status"`
	Reason    string               `json:"reason"`
	Actor     string               `json:"actor"`
	ExpiresAt *time.Time           `json:"expires_at"`
	CreatedAt time.Time            `json:"created_at"`
}

// ListExceptions returns a finding's exception history, newest first.
func (r *Repository) ListExceptions(ctx context.Context, findingID string) ([]Exception, error) {
	const q = `SELECT id, finding_id, status, reason, actor, expires_at, created_at
		FROM finding_exceptions WHERE finding_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q, findingID)
	if err != nil {
		return nil, fmt.Errorf("list exceptions: %w", err)
	}
	defer rows.Close()
	out := []Exception{}
	for rows.Next() {
		var e Exception
		if err := rows.Scan(&e.ID, &e.FindingID, &e.Status, &e.Reason, &e.Actor, &e.ExpiresAt, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan exception: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CloseMissing auto-remediates live findings from a scanner that were NOT seen
// in the given scan — i.e. they no longer appear, so the scanner (treated as the
// authoritative current view of the target it scanned) considers them fixed.
//
// A scan only vouches for its own target: its project version (branch /
// release) and its asset. A finding is closed only if it lives on the scan's
// version and the scan that last reported it had the same asset_id — so
// scanning a feature branch never closes main's findings, and scanning image B
// never closes image A's. A finding with no recorded last scan belongs to the
// version's asset-less target.
//
// Triaged states (false_positive, risk_accepted, wont_fix) are left untouched;
// only open/confirmed findings are auto-closed.
// It returns the ids it closed: closing a finding removes it from its
// correlation group, so the caller must feed those ids to DeduplicateScan for
// the group to re-elect a primary.
func (r *Repository) CloseMissing(ctx context.Context, projectID, scanner, scanID string) ([]string, error) {
	q := `
		UPDATE findings f
		SET status = 'remediated', resolved_at = now(), updated_at = now()
		FROM scans cur
		WHERE cur.id = $3
		  AND f.project_id = $1
		  AND f.version_id = cur.version_id
		  AND f.scanner = $2
		  AND f.status IN ('open', 'confirmed')
		  AND f.last_scan_id IS DISTINCT FROM $3
		  AND` + archive.Finding("f") + `
		  AND (
		        EXISTS (SELECT 1 FROM scans prev
		                WHERE prev.id = f.last_scan_id
		                  AND prev.asset_id IS NOT DISTINCT FROM cur.asset_id)
		     OR (f.last_scan_id IS NULL AND cur.asset_id IS NULL)
		  )
		RETURNING f.id`
	rows, err := r.db.Query(ctx, q, projectID, scanner, scanID)
	if err != nil {
		return nil, fmt.Errorf("close missing findings: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("close missing findings: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// CarryForward moves every finding still pointing at an earlier scan onto a new
// one that repeated it exactly (scan.Service's skip-unchanged short-circuit):
// refreshes last_seen_at as if the new scan had reported them, without
// touching first_scan_id (so they never start counting as "new") or anything a
// full re-ingest would otherwise redo — status, priority, correlation are
// already settled from the scan being repeated.
//
// want is how many distinct findings the new report holds. The move happens in
// one transaction and only if exactly that many findings still point at the
// earlier scan; otherwise (one was deleted or moved meanwhile) nothing changes
// and ok is false, so the caller runs the full pipeline instead.
func (r *Repository) CarryForward(ctx context.Context, prevScanID, newScanID string, want int) (ok bool, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("carry forward findings: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `UPDATE findings SET last_scan_id = $2, last_seen_at = now() WHERE last_scan_id = $1`, prevScanID, newScanID)
	if err != nil {
		return false, fmt.Errorf("carry forward findings: %w", err)
	}
	if tag.RowsAffected() != int64(want) {
		return false, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("carry forward findings: %w", err)
	}
	return true, nil
}

// ChangedSince reports whether anything a re-ingest would act on changed after
// since for the findings an earlier scan reported (their state_changed_at,
// stamped by the findings_state trigger: status, severity, title,
// description, the manual-override flags, archiving) or for the scan's asset
// (its exposure). A repeat of that scan may only skip the pipeline when this is
// false: a reset field, a manually closed finding or a cleared exposure all need
// the full pipeline to put the scanner's view back.
func (r *Repository) ChangedSince(ctx context.Context, prevScanID string, since time.Time, assetID *string) (bool, error) {
	const q = `SELECT EXISTS (SELECT 1 FROM findings WHERE last_scan_id = $1 AND state_changed_at > $2)
		OR ($3::uuid IS NOT NULL AND EXISTS (SELECT 1 FROM assets WHERE id = $3 AND exposure_updated_at > $2))`
	var changed bool
	if err := r.db.QueryRow(ctx, q, prevScanID, since, assetID).Scan(&changed); err != nil {
		return false, fmt.Errorf("findings changed since scan: %w", err)
	}
	return changed, nil
}

// Enrichable is the minimal finding data needed to compute enrichment.
type Enrichable struct {
	ID       string
	Severity domain.Severity
	CVE      []string
	KEV      bool     // current KEV state (to detect a transition)
	EPSS     *float64 // current EPSS (to detect a transition)
	// IDs are every vulnerability id the finding is known by, uppercased: its
	// CVEs, its rule id, the aliases its scanner reported (metadata.aliases)
	// and those of the advisory its rule id names (local OSV mirror, private
	// advisories) — what KEV catalogs are matched against.
	IDs       []string
	Title     string
	ProjectID string
	// Reachability is carried so recomputing priority here doesn't silently undo
	// the reachability discount applied at ingest.
	DepDirect *bool
	DepScope  domain.DepScope
	// ExploitMaturity is kept so the recomputed priority keeps its exploit uplift.
	ExploitMaturity domain.ExploitMaturity
	// AssetExposure is kept so the recomputed priority keeps its exposure factor.
	AssetExposure domain.Exposure
}

// Reachability is the finding's dependency reachability, for domain.Priority.
func (e Enrichable) Reachability() domain.Reachability {
	return domain.Reachability{Direct: e.DepDirect, Scope: e.DepScope}
}

// ListEnrichable returns findings that carry a CVE or an advisory rule id
// (GHSA/EUVD/CVE), or are flagged KEV (so a flag no catalog backs any more
// clears).
func (r *Repository) ListEnrichable(ctx context.Context) ([]Enrichable, error) {
	const q = `SELECT f.id, f.severity, f.cve, f.kev, f.epss, f.title, f.project_id, f.dep_direct, f.dep_scope,
			COALESCE(f.exploit_maturity, ''),
			ARRAY(SELECT DISTINCT upper(x) FROM unnest(
				f.cve || f.rule_id
				|| COALESCE((SELECT array_agg(a) FROM jsonb_array_elements_text(
					CASE WHEN jsonb_typeof(f.metadata->'aliases') = 'array' THEN f.metadata->'aliases' END) a), '{}')
				|| COALESCE((SELECT aliases FROM osv_advisories WHERE id = f.rule_id), '{}')
				|| COALESCE((SELECT aliases FROM private_advisories WHERE id = f.rule_id), '{}')
			) x WHERE x <> ''),
			COALESCE((SELECT exposure FROM assets WHERE assets.id = f.asset_id), '')
		FROM findings f
		WHERE cardinality(f.cve) > 0 OR f.kev OR f.rule_id ~* '^(CVE|GHSA|EUVD)-'`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list enrichable: %w", err)
	}
	defer rows.Close()

	var out []Enrichable
	for rows.Next() {
		var e Enrichable
		if err := rows.Scan(&e.ID, &e.Severity, &e.CVE, &e.KEV, &e.EPSS, &e.Title, &e.ProjectID,
			&e.DepDirect, &e.DepScope, &e.ExploitMaturity, &e.IDs, &e.AssetExposure); err != nil {
			return nil, fmt.Errorf("scan enrichable: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListForTriage returns a project's active (open/confirmed) findings — the set
// auto-triage rules evaluate.
func (r *Repository) ListForTriage(ctx context.Context, projectID string) ([]Finding, error) {
	return r.listForTriage(ctx, projectID, nil)
}

// ListForTriageScan is ListForTriage narrowed to the findings a given scan
// reported — what the ingest path re-evaluates.
func (r *Repository) ListForTriageScan(ctx context.Context, projectID, scanID string) ([]Finding, error) {
	return r.listForTriage(ctx, projectID, &scanID)
}

func (r *Repository) listForTriage(ctx context.Context, projectID string, scanID *string) ([]Finding, error) {
	q := `SELECT ` + findingColumns + ` FROM findings
		WHERE project_id = $1 AND status IN ('open', 'confirmed') AND duplicate_of IS NULL AND` + archive.Finding("") + `
		  AND ($2::uuid IS NULL OR last_scan_id = $2)`
	rows, err := r.db.Query(ctx, q, projectID, scanID)
	if err != nil {
		return nil, fmt.Errorf("list for triage: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// SetSeverity sets a finding's severity for a triage rule and recomputes its
// priority from every input. A severity a person set (severity_manual) is
// left alone: a generic rule never overrides an analyst's judgment.
func (r *Repository) SetSeverity(ctx context.Context, id string, sev domain.Severity) (Finding, error) {
	tag, err := r.db.Exec(ctx, `UPDATE findings SET severity = $2, updated_at = now()
		WHERE id = $1 AND NOT severity_manual AND severity IS DISTINCT FROM $2`, id, sev)
	if err != nil {
		return Finding{}, fmt.Errorf("set severity: %w", err)
	}
	if tag.RowsAffected() > 0 {
		if _, _, err := r.Reprioritize(ctx, PriorityScope{FindingIDs: []string{id}}); err != nil {
			return Finding{}, err
		}
	}
	return r.Get(ctx, id)
}

// FixCandidate is a live finding as the fix plan and remediation grouping
// (internal/fixplan) need it.
type FixCandidate struct {
	ID             string
	ProjectID      string
	ProjectName    string
	Scanner        string
	Category       domain.Category
	RuleID         string
	Title          string
	Severity       domain.Severity
	Priority       float64
	KEV            bool
	EPSS           *float64
	PackageName    string
	PackageVersion string
	FixedVersion   string
	Purl           string
	DepDirect      *bool
	FilePath       string
	// From the scanner's metadata: the container image the finding was found
	// in, the package class ("os-pkgs" for distro packages — Trivy) and the
	// image's OS ("debian 12.5"), when the scanner reports them.
	Image    string
	PkgClass string
	OS       string
	// Resource is the IaC / cloud resource the finding is on, when the scanner
	// names it separately from the file (metadata "resource").
	Resource string
}

// FixFilter selects fix candidates.
type FixFilter struct {
	ProjectIDs   []string // nil = every project
	DirectOnly   bool     // only direct dependencies
	PackagesOnly bool     // only package findings (the fix plan)
	ScanID       string   // only findings the scan reported ("" = all)
	// Unactioned skips findings already in a live (open / in progress)
	// remediation action.
	Unactioned bool
}

// FixCandidates returns every live (open or confirmed) finding matching the
// filter on its project's default version — duplicates collapsed, policy
// findings excluded (a licence violation has no upgrade) — for the fix plan
// and remediation actions to group by the change that resolves them.
func (r *Repository) FixCandidates(ctx context.Context, ff FixFilter) ([]FixCandidate, error) {
	q := `SELECT f.id, f.project_id, p.name, f.scanner, f.category, f.rule_id, f.title, f.severity, f.priority,
			f.kev, f.epss, f.package_name, f.package_version, f.fixed_version, f.purl, f.dep_direct, f.file_path,
			COALESCE(f.metadata->>'image', ''), COALESCE(f.metadata->>'pkg_class', ''),
			COALESCE(f.metadata->>'os', ''), COALESCE(f.metadata->>'resource', '')
		FROM findings f JOIN projects p ON p.id = f.project_id
		WHERE f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL AND f.scanner <> 'policy'
			AND f.` + strings.TrimSpace(onDefaultVersion) + ` AND` + archive.Finding("f")
	args := []any{}
	if ff.ProjectIDs != nil {
		args = append(args, ff.ProjectIDs)
		q += fmt.Sprintf(" AND f.project_id = ANY($%d)", len(args))
	}
	if ff.ScanID != "" {
		args = append(args, ff.ScanID)
		q += fmt.Sprintf(" AND f.last_scan_id = $%d", len(args))
	}
	if ff.PackagesOnly {
		q += " AND f.package_name <> ''"
	}
	if ff.DirectOnly {
		q += " AND f.dep_direct"
	}
	if ff.Unactioned {
		q += ` AND NOT EXISTS (SELECT 1 FROM remediation_action_findings raf
			JOIN remediation_actions ra ON ra.id = raf.action_id
			WHERE raf.finding_id = f.id AND ra.status IN ('open', 'in_progress'))`
	}
	q += " ORDER BY f.project_id, f.id"
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("fix candidates: %w", err)
	}
	defer rows.Close()
	var out []FixCandidate
	for rows.Next() {
		var c FixCandidate
		if err := rows.Scan(&c.ID, &c.ProjectID, &c.ProjectName, &c.Scanner, &c.Category, &c.RuleID, &c.Title,
			&c.Severity, &c.Priority, &c.KEV, &c.EPSS, &c.PackageName, &c.PackageVersion, &c.FixedVersion,
			&c.Purl, &c.DepDirect, &c.FilePath, &c.Image, &c.PkgClass, &c.OS, &c.Resource); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GateStats are the live aggregates a security gate evaluates, over a project's
// active (open/confirmed), non-duplicate findings.
type GateStats struct {
	OpenCritical int `json:"open_critical"`
	OpenHigh     int `json:"open_high"`
	OpenMedium   int `json:"open_medium"`
	OpenLow      int `json:"open_low"`
	OpenInfo     int `json:"open_info"`
	OpenKEV      int `json:"open_kev"`
	// OpenKEVSources counts the open KEV findings by the exact set of catalogs
	// asserting them (comma-joined, sorted: "cisa,enisa"), so a gate limited to
	// some catalogs can count the findings any of them asserts.
	OpenKEVSources map[string]int `json:"open_kev_sources"`
	OpenLicense    int            `json:"open_license"`
	MaxEPSS        float64        `json:"max_epss"`
	SLABreached    int            `json:"sla_breached"`
	// RiskScore is the same business-weighted score project.Summary shows
	// (severity weight × count × business-criticality multiplier), computed over
	// this one gated version instead of rolled up across projects.
	RiskScore float64 `json:"risk_score"`
}

// gateStatsQuery computes the gate aggregates for one project version. The
// newness filter is a single SQL expression rather than Go-built branches so the
// parameter list never changes shape:
//   - $4 = false: no filtering at all (the whole live backlog).
//   - $4 = true, $3 NULL: "new" = seen in exactly one scan so far
//     (first_scan_id = last_scan_id) — the original heuristic.
//   - $4 = true, $3 set: "new" = no open/confirmed finding with the same
//     fingerprint is already live on the baseline version ($3). fingerprint
//     (scanner, category, rule_id, file_path, package[, line]; see
//     internal/scan/ingest.go) is the identity Upsert/CloseMissing already use to
//     recognize "the same finding reappearing" across scans, and — unlike
//     correlation_key, which is NULL for every non-CVE finding (SAST, secrets,
//     DAST-without-a-CVE) and would make all of those look "new" on every
//     branch — it never encodes version_id, so the same code on two branches
//     hashes identically. A baseline finding only excuses the reappearance while
//     it is still live (open/confirmed) there: once triaged away (false
//     positive, won't-fix, risk-accepted, remediated) it no longer vouches for
//     the fingerprint resurfacing on a feature branch.
var gateStatsQuery = `WITH f AS (
	SELECT severity, kev, kev_sources, category, epss, sla_due_at
	FROM findings fo
	WHERE fo.project_id = $1 AND fo.status IN ('open', 'confirmed') AND fo.duplicate_of IS NULL AND` + archive.Finding("fo") + `
	  AND fo.version_id = COALESCE($2::uuid, (SELECT id FROM project_versions WHERE project_id = $1 AND is_default))
	  AND ($4 = false OR (
	        ($3::uuid IS NOT NULL AND NOT EXISTS (
	                SELECT 1 FROM findings b
	                WHERE b.project_id = $1 AND b.version_id = $3::uuid AND b.fingerprint = fo.fingerprint
	                  AND b.status IN ('open', 'confirmed') AND b.duplicate_of IS NULL AND` + archive.Finding("b") + `
	        ))
	     OR ($3::uuid IS NULL AND fo.first_scan_id = fo.last_scan_id)
	  ))
)
SELECT
	count(*) FILTER (WHERE severity = 'critical'),
	count(*) FILTER (WHERE severity = 'high'),
	count(*) FILTER (WHERE severity = 'medium'),
	count(*) FILTER (WHERE severity = 'low'),
	count(*) FILTER (WHERE severity = 'info'),
	count(*) FILTER (WHERE kev),
	(SELECT COALESCE(jsonb_object_agg(k, n), '{}') FROM
		(SELECT array_to_string(kev_sources, ',') AS k, count(*) AS n FROM f WHERE kev GROUP BY 1) g),
	count(*) FILTER (WHERE category = 'license'),
	COALESCE(max(epss), 0),
	count(*) FILTER (WHERE sla_due_at < now()),
	(SELECT business_criticality FROM projects WHERE id = $1)
FROM f`

// ComputeGateStats returns the gate aggregates for one project version (""
// means the project's default version). When newOnly is set, it counts only
// newly-introduced findings: against baselineVersionID when one is given (""
// means none), else those seen in a single scan so far (first_scan_id =
// last_scan_id) — so PR gates ignore pre-existing debt.
func (r *Repository) ComputeGateStats(ctx context.Context, projectID, versionID string, newOnly bool, baselineVersionID string) (GateStats, error) {
	var version *string
	if versionID != "" {
		version = &versionID
	}
	var baseline *string
	if baselineVersionID != "" {
		baseline = &baselineVersionID
	}
	var s GateStats
	var crit domain.Criticality
	if err := r.db.QueryRow(ctx, gateStatsQuery, projectID, version, baseline, newOnly).
		Scan(&s.OpenCritical, &s.OpenHigh, &s.OpenMedium, &s.OpenLow, &s.OpenInfo, &s.OpenKEV, &s.OpenKEVSources, &s.OpenLicense, &s.MaxEPSS, &s.SLABreached, &crit); err != nil {
		return GateStats{}, fmt.Errorf("gate stats: %w", err)
	}
	s.RiskScore = domain.SeverityCritical.Weight()*float64(s.OpenCritical) +
		domain.SeverityHigh.Weight()*float64(s.OpenHigh) +
		domain.SeverityMedium.Weight()*float64(s.OpenMedium) +
		domain.SeverityLow.Weight()*float64(s.OpenLow)
	s.RiskScore *= crit.Multiplier()
	return s, nil
}

// dedupLockNamespace keys the advisory lock Deduplicate takes, so it can't
// collide with any other advisory lock the app might take on the same project.
const dedupLockNamespace = 1

// Deduplicate recomputes cross-tool grouping for an entire project: it derives a
// correlation key (min CVE + package) for each finding, then within each group of
// active findings elects a primary (highest priority, oldest, stable) and points
// the rest at it via duplicate_of. Idempotent. Use it after a change that can
// reshuffle any group in the project (a triage-rule backfill, an enrichment pass);
// the ingest path uses DeduplicateScan instead.
func (r *Repository) Deduplicate(ctx context.Context, projectID string) (int, error) {
	return r.deduplicate(ctx, projectID, "", nil)
}

// DeduplicateScan is Deduplicate scoped to the correlation groups one scan could
// have disturbed. Dedup runs after every ingest, and a project accumulates
// findings from every scanner and every past scan — recomputing all of it on each
// upload makes ingestion cost grow with the project's history rather than with
// the size of the scan. The affected groups are:
//
//   - the groups this scan's findings belong to now;
//   - the groups they belonged to *before* (a finding whose CVE set changed moves
//     between groups, and the group it left must re-elect);
//   - the groups of findings closedIDs just auto-closed (a closed primary must
//     hand off to a still-open sibling).
//
// Anything outside those groups is untouched by definition, so skipping it is not
// an approximation.
func (r *Repository) DeduplicateScan(ctx context.Context, projectID, scanID string, closedIDs []string) (int, error) {
	return r.deduplicate(ctx, projectID, scanID, closedIDs)
}

// deduplicate does the work for both. An empty scanID means "the whole project".
// Returns how many findings had their grouping changed.
func (r *Repository) deduplicate(ctx context.Context, projectID, scanID string, closedIDs []string) (int, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin dedup: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	// Serialize dedup per project. Both statements below decide what to write from
	// a snapshot; a concurrent dedup of the same project (two workers draining
	// scans of one project) could commit between that snapshot and the write, and
	// we'd then overwrite its result with a stale one — pointing a duplicate at a
	// finding the other run just demoted, i.e. a dup -> dup chain that hides
	// findings from every list. The lock is held to commit and only blocks other
	// dedups of this same project.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, dedupLockNamespace, projectID); err != nil {
		return 0, fmt.Errorf("dedup lock: %w", err)
	}

	// The findings whose key we recompute: this scan's (plus the ones just closed,
	// whose key can't have changed but whose group must re-elect), or all of them.
	// $4 is NULL for a full run, which makes the scan predicate a no-op.
	var scan *string
	if scanID != "" {
		scan = &scanID
	}

	// 1. Correlation key. Two shapes:
	//   - CVE findings: min CVE (for determinism) plus what the CVE is *in*: the
	//     package, or, for a package-less finding (network, DAST: OpenVAS,
	//     Nessus, nuclei), its location. The same CVE on two hosts is two
	//     vulnerabilities, never one another's duplicate. Keep in sync with
	//     migration 000056's backfill.
	//   - Non-CVE findings (SAST, secrets, IaC, ...): category + file_path +
	//     line, plus CWE when the finding has one. A finding's key simply omits
	//     the CWE segment when it has none, so a CWE-bearing and a CWE-less
	//     report at the same line never share a key (no forced match on an
	//     absent CWE); two CWE-less reports at the same spot still fall back to
	//     grouping by location alone. This branch only fires when cve is empty,
	//     so it never touches a CVE-keyed finding; findings with no
	//     file_path/line (most DAST without a CVE) still get no key, same as
	//     before (no fuzzy title matching). Keep in sync with migration
	//     000089's backfill. A location-keyed group only ever collapses when
	//     every one of its members is from a *different* scanner (step 2's
	//     scanner_counts): two rules from the same tool sharing a line/CWE must
	//     never hide one another, even when a third tool's report is also in
	//     the group, so the whole group stays ungrouped rather than guess which
	//     pair to collapse. CVE-keyed groups never consult scanner identity, same
	//     as before this feature.
	// Only rows whose key actually changes are written: dedup runs after every
	// ingest, and rewriting a whole project's findings each time would churn the
	// table (dead tuples, WAL, bloat) to store values identical to the old ones.
	// RETURNING the *pre-update* key (read from the subquery's snapshot) tells us
	// which groups a moved finding just left. A group is (version, key): the same
	// CVE on two branches is two independent issues, never one another's duplicate.
	rows, err := tx.Query(ctx, `
		UPDATE findings SET correlation_key = k.key
		FROM (
			SELECT id, version_id, correlation_key AS old_key, CASE
				WHEN cardinality(cve) > 0 AND package_name <> ''
					THEN lower((SELECT min(c) FROM unnest(cve) c)) || '|' || lower(package_name)
				WHEN cardinality(cve) > 0 AND file_path <> ''
					THEN lower((SELECT min(c) FROM unnest(cve) c)) || '@' || lower(file_path)
				WHEN cardinality(cve) > 0
					THEN lower((SELECT min(c) FROM unnest(cve) c))
				WHEN cardinality(cve) = 0 AND file_path <> '' AND line IS NOT NULL AND cwe IS NOT NULL
					THEN 'loc|' || category || '|' || lower(file_path) || '|' || line::text || '|' || cwe::text
				WHEN cardinality(cve) = 0 AND file_path <> '' AND line IS NOT NULL
					THEN 'loc|' || category || '|' || lower(file_path) || '|' || line::text
				ELSE NULL END AS key
			FROM findings
			WHERE project_id = $1
			  AND ($2::uuid IS NULL OR last_scan_id = $2 OR id = ANY($3))
		) k
		WHERE findings.id = k.id AND findings.correlation_key IS DISTINCT FROM k.key
		RETURNING k.version_id::text || '|' || k.old_key`,
		projectID, scan, closedIDs)
	if err != nil {
		return 0, fmt.Errorf("dedup keys: %w", err)
	}
	var vacated []string // "version|key" groups a finding moved out of
	for rows.Next() {
		var old *string
		if err := rows.Scan(&old); err != nil {
			rows.Close()
			return 0, fmt.Errorf("dedup keys: %w", err)
		}
		if old != nil {
			vacated = append(vacated, *old)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("dedup keys: %w", err)
	}

	// 2. Elect a primary per affected group and point the rest at it. Computing
	// every finding's target duplicate_of (NULL for primaries, for ungrouped and
	// for triaged/closed findings) in one statement means there is never a moment
	// where the old grouping has been cleared but the new one isn't written yet —
	// a reader mid-dedup would otherwise see duplicates surface.
	tag, err := tx.Exec(ctx, `
		WITH affected AS (
			SELECT DISTINCT version_id::text || '|' || correlation_key AS grp FROM findings
			WHERE project_id = $1 AND correlation_key IS NOT NULL
			  AND ($2::uuid IS NULL OR last_scan_id = $2 OR id = ANY($3))
			UNION
			SELECT unnest($4::text[])
		),
		scoped AS (
			-- The affected groups, plus the touched findings themselves: one whose
			-- CVE was dropped has no key at all now, and still has to lose its
			-- duplicate_of.
			SELECT * FROM findings f
			WHERE f.project_id = $1
			  AND ($2::uuid IS NULL
			       OR f.version_id::text || '|' || f.correlation_key IN (SELECT grp FROM affected)
			       OR f.last_scan_id = $2 OR f.id = ANY($3))
		),
		scanner_counts AS (
			-- Per correlation group among electable (open/confirmed, non-archived)
			-- findings: how many rows, and how many distinct scanners reported
			-- them. A CVE-keyed group collapses whenever it has more than one
			-- member, same scanner or not (unchanged from before this feature). A
			-- location-keyed group (no CVE: category+file+line[+CWE]) collapses
			-- only when grp = distinct_scanners, i.e. every member is a different
			-- tool; otherwise none of its members is marked a duplicate, so one
			-- tool's second rule on the same line never disappears behind another
			-- tool's report of a third.
			SELECT version_id, correlation_key,
				count(*) AS grp,
				count(DISTINCT scanner) AS distinct_scanners
			FROM scoped
			WHERE correlation_key IS NOT NULL AND status IN ('open', 'confirmed') AND`+archive.Finding("")+`
			GROUP BY version_id, correlation_key
		),
		ranked AS (
			SELECT id,
				first_value(id) OVER (
					PARTITION BY version_id, correlation_key ORDER BY priority DESC, created_at ASC, id ASC
				) AS primary_id
			FROM scoped
			-- An archived finding is never elected, nor anyone's duplicate.
			WHERE correlation_key IS NOT NULL AND status IN ('open', 'confirmed') AND`+archive.Finding("")+`
		),
		target AS (
			SELECT s.id, CASE
				WHEN sc.grp > 1 AND s.id <> r.primary_id
				     AND (s.correlation_key NOT LIKE 'loc|%' OR sc.grp = sc.distinct_scanners)
					THEN r.primary_id
				ELSE NULL END AS dup
			FROM scoped s
			LEFT JOIN ranked r ON r.id = s.id
			LEFT JOIN scanner_counts sc ON sc.version_id = s.version_id AND sc.correlation_key = s.correlation_key
		)
		UPDATE findings f SET duplicate_of = t.dup
		FROM target t
		WHERE f.id = t.id AND f.duplicate_of IS DISTINCT FROM t.dup`,
		projectID, scan, closedIDs, vacated)
	if err != nil {
		return 0, fmt.Errorf("dedup elect: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit dedup: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListDuplicatesOf returns the duplicate reports that point at a primary finding.
func (r *Repository) ListDuplicatesOf(ctx context.Context, id string) ([]Finding, error) {
	const q = `SELECT ` + findingColumns + ` FROM findings WHERE duplicate_of = $1 ORDER BY scanner`
	rows, err := r.db.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("list duplicates: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// TagCount is one tag in use and how many open findings carry it.
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// TagCounts lists every tag on findings in scope (default versions, no
// duplicates — what listings show), most-used first. Count is open findings
// only; a tag left only on closed findings is still listed (count 0), so it
// stays filterable. projectID narrows; scope non-nil restricts to those projects.
func (r *Repository) TagCounts(ctx context.Context, projectID string, scope []string) ([]TagCount, error) {
	q := `SELECT t, count(*) FILTER (WHERE status IN ('open', 'confirmed'))::int
		FROM findings, unnest(tags) t
		WHERE duplicate_of IS NULL AND` + onDefaultVersion + ` AND` + archive.Finding("") + `
		  AND ($1::uuid IS NULL OR project_id = $1)
		  AND ($2::uuid[] IS NULL OR project_id = ANY($2))
		GROUP BY t ORDER BY 2 DESC, t`
	var pid *string
	if projectID != "" {
		pid = &projectID
	}
	rows, err := r.db.Query(ctx, q, pid, scope)
	if err != nil {
		return nil, fmt.Errorf("tag counts: %w", err)
	}
	defer rows.Close()
	out := []TagCount{}
	for rows.Next() {
		var t TagCount
		if err := rows.Scan(&t.Tag, &t.Count); err != nil {
			return nil, fmt.Errorf("scan tag: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DuplicateCounts returns, for each given finding id, how many duplicate reports
// point at it — used to badge list rows ("+N tools").
func (r *Repository) DuplicateCounts(ctx context.Context, ids []string) (map[string]int, error) {
	counts := map[string]int{}
	if len(ids) == 0 {
		return counts, nil
	}
	const q = `SELECT duplicate_of, count(*) FROM findings
		WHERE duplicate_of = ANY($1) GROUP BY duplicate_of`
	rows, err := r.db.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("duplicate counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		counts[id] = n
	}
	return counts, rows.Err()
}

// ProjectIDsWithFindings returns the distinct projects that have findings.
func (r *Repository) ProjectIDsWithFindings(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `SELECT DISTINCT project_id FROM findings`)
	if err != nil {
		return nil, fmt.Errorf("project ids with findings: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// SetEnrichment stores a finding's EPSS, the KEV catalogs asserting it (kev =
// any), whether a catalog marks it as used in ransomware campaigns and the
// recomputed priority.
func (r *Repository) SetEnrichment(ctx context.Context, id string, epss *float64, kevSources []string, ransomware bool, priority float64) error {
	const q = `UPDATE findings SET epss = $2, kev = cardinality($3::text[]) > 0, kev_sources = $3,
		kev_ransomware = cardinality($3::text[]) > 0 AND $5, priority = $4, updated_at = now() WHERE id = $1`
	if kevSources == nil {
		kevSources = []string{}
	}
	_, err := r.db.Exec(ctx, q, id, epss, kevSources, priority, ransomware)
	if err != nil {
		return fmt.Errorf("set enrichment: %w", err)
	}
	return nil
}

// StatusSeverityCount is one bucket of the per-project finding breakdown,
// with the business criticality of the project the findings are in.
type StatusSeverityCount struct {
	Status      domain.FindingStatus
	Severity    domain.Severity
	Criticality domain.Criticality
	Count       int
}

// CountByProjects returns per (status, severity, project criticality) counts
// over a set of projects — one project, or a project and its descendants.
func (r *Repository) CountByProjects(ctx context.Context, projectIDs []string) ([]StatusSeverityCount, error) {
	q := `
		SELECT f.status, f.severity, p.business_criticality, count(*)
		FROM findings f JOIN projects p ON p.id = f.project_id
		WHERE f.project_id = ANY($1) AND f.duplicate_of IS NULL AND` + onDefaultVersion + ` AND` + archive.Finding("f") + `
		GROUP BY f.status, f.severity, p.business_criticality`
	rows, err := r.db.Query(ctx, q, projectIDs)
	if err != nil {
		return nil, fmt.Errorf("count findings: %w", err)
	}
	defer rows.Close()

	var counts []StatusSeverityCount
	for rows.Next() {
		var c StatusSeverityCount
		if err := rows.Scan(&c.Status, &c.Severity, &c.Criticality, &c.Count); err != nil {
			return nil, fmt.Errorf("scan count: %w", err)
		}
		counts = append(counts, c)
	}
	return counts, rows.Err()
}

// ReachTarget is a finding paired with the reachability of the SBOM component it
// came from, plus what's needed to recompute its priority.
type ReachTarget struct {
	ID        string
	Severity  domain.Severity
	EPSS      *float64
	KEV       bool
	DepDirect *bool
	DepDepth  *int
	DepScope  domain.DepScope
	// ExploitMaturity is kept so the recomputed priority keeps its exploit uplift.
	ExploitMaturity domain.ExploitMaturity
	// AssetExposure is kept so the recomputed priority keeps its exposure factor.
	AssetExposure domain.Exposure
}

// Reachability assembles the multiplier input.
func (t ReachTarget) Reachability() domain.Reachability {
	return domain.Reachability{Direct: t.DepDirect, Scope: t.DepScope}
}

// MatchInventory pairs a project's package findings with the component they came
// from in the *current* SBOM inventory (newest snapshot per artifact), so their
// reachability can be applied. An empty scanID matches the whole project;
// otherwise only the findings that scan reported.
//
// When a package appears more than once — several artifacts, several depths — we
// take the **least discounted** match: an exact PURL hit over a name match, then
// runtime over optional over dev, then the shallowest depth. Reachability is a
// heuristic that lowers priority, so where the evidence is ambiguous it must err
// toward keeping the finding visible.
//
// The inventory is the finding's own version's current SBOMs; a version with no
// SBOM of its own (a feature branch scanned in CI, an SBOM only uploaded for
// main) borrows the default version's, which is the best evidence there is.
func (r *Repository) MatchInventory(ctx context.Context, projectID, scanID string) ([]ReachTarget, error) {
	const q = `
		SELECT f.id, f.severity, f.epss, f.kev, c.direct, c.depth, c.scope, COALESCE(f.exploit_maturity, ''),
			COALESCE((SELECT a.exposure FROM assets a WHERE a.id = f.asset_id), '')
		FROM findings f
		JOIN LATERAL (
			SELECT c.direct, c.depth, c.scope
			FROM sbom_components c
			WHERE c.project_id = f.project_id
			  AND c.sbom_id IN (
			      SELECT DISTINCT ON (artifact) id FROM sboms
			      WHERE project_id = f.project_id
			        AND version_id = CASE
			            WHEN EXISTS (SELECT 1 FROM sboms o WHERE o.version_id = f.version_id) THEN f.version_id
			            ELSE (SELECT id FROM project_versions WHERE project_id = f.project_id AND is_default) END
			      ORDER BY artifact, created_at DESC)
			  AND (
			      (f.purl <> '' AND c.purl = f.purl)
			   OR (f.package_name <> '' AND lower(c.name) = lower(f.package_name)
			       AND (f.package_version = '' OR c.version = f.package_version))
			  )
			ORDER BY (c.purl = f.purl) DESC,
			         (c.scope = 'dev') ASC, (c.scope = 'optional') ASC,
			         c.depth ASC NULLS FIRST
			LIMIT 1
		) c ON true
		WHERE f.project_id = $1
		  AND (f.package_name <> '' OR f.purl <> '')
		  AND ($2::uuid IS NULL OR f.last_scan_id = $2)`

	var scan *string
	if scanID != "" {
		scan = &scanID
	}
	rows, err := r.db.Query(ctx, q, projectID, scan)
	if err != nil {
		return nil, fmt.Errorf("match inventory: %w", err)
	}
	defer rows.Close()

	var out []ReachTarget
	for rows.Next() {
		var t ReachTarget
		if err := rows.Scan(&t.ID, &t.Severity, &t.EPSS, &t.KEV, &t.DepDirect, &t.DepDepth, &t.DepScope, &t.ExploitMaturity,
			&t.AssetExposure); err != nil {
			return nil, fmt.Errorf("scan reach target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetReachability stores a finding's dependency reachability and the priority it
// implies. Only rows that actually change are written, so re-running is free.
func (r *Repository) SetReachability(ctx context.Context, targets []ReachTarget, priorities []float64) (int, error) {
	if len(targets) == 0 {
		return 0, nil
	}
	ids := make([]string, len(targets))
	directs := make([]*bool, len(targets))
	depths := make([]*int, len(targets))
	scopes := make([]string, len(targets))
	for i, t := range targets {
		ids[i], directs[i], depths[i], scopes[i] = t.ID, t.DepDirect, t.DepDepth, string(t.DepScope)
	}

	const q = `
		UPDATE findings f
		SET dep_direct = u.direct, dep_depth = u.depth, dep_scope = u.scope,
		    priority = u.priority, updated_at = now()
		FROM (
			SELECT unnest($1::uuid[]) AS id, unnest($2::boolean[]) AS direct,
			       unnest($3::int[]) AS depth, unnest($4::text[]) AS scope,
			       unnest($5::float8[]) AS priority
		) u
		WHERE f.id = u.id
		  AND (f.dep_direct IS DISTINCT FROM u.direct
		    OR f.dep_depth  IS DISTINCT FROM u.depth
		    OR f.dep_scope  IS DISTINCT FROM u.scope
		    OR f.priority   IS DISTINCT FROM u.priority)`
	tag, err := r.db.Exec(ctx, q, ids, directs, depths, scopes, priorities)
	if err != nil {
		return 0, fmt.Errorf("set reachability: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
