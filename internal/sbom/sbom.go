// Package sbom stores software bills of materials as historical snapshots and
// makes their components searchable across the whole portfolio.
package sbom

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// ErrNotFound is returned when an SBOM does not exist.
var ErrNotFound = errors.New("sbom not found")

// ErrCollection is returned for an SBOM uploaded to a collection project,
// which holds no SBOMs of its own (its children do).
var ErrCollection = errors.New("project is a collection: upload to one of its child projects")

// Sbom is one uploaded bill of materials: an immutable point-in-time snapshot.
type Sbom struct {
	ID             string    `json:"id"`
	ProjectID      string    `json:"project_id"`
	Artifact       string    `json:"artifact"`
	Version        string    `json:"version"`
	Format         string    `json:"format"`
	SpecVersion    string    `json:"spec_version"`
	SerialNumber   string    `json:"serial_number"`
	ComponentCount int       `json:"component_count"`
	Source         string    `json:"source"`
	CreatedAt      time.Time `json:"created_at"`
	// RootRef is the graph node the SBOM describes (see Document.RootRef).
	RootRef string `json:"root_ref"`
	// VersionID is the project version (branch / release) the snapshot belongs to.
	VersionID string `json:"version_id"`
	// VersionName + VersionKind resolve VersionID on Ingest (empty name = the
	// project's default version); not read back.
	VersionName string `json:"-"`
	VersionKind string `json:"-"`
	// Processing is this upload's background-processing status (vulnmatch
	// match, pkgmeta fetch, policy evaluation, reachability), set by
	// Service.Ingest on its return value only — not a stored column, and nil
	// on every other read (use GET /sboms/{id}/status instead).
	Processing *ProcessingStatus `json:"processing,omitempty"`
}

// Component is a single entry in a bill of materials.
type Component struct {
	ID string `json:"id"`
	// BomRef is this component's node id in the SBOM's dependency graph
	// (CycloneDX bom-ref / SPDX SPDXID); empty when the document gave none.
	BomRef    string `json:"bom_ref"`
	SbomID    string `json:"sbom_id"`
	ProjectID string `json:"project_id"`
	Type      string `json:"type"`
	// Kind is software, model, dataset or ai-service (the AI inventory); ML
	// holds an AI component's model-card essentials (nil for software).
	Kind      string            `json:"kind"`
	ML        *MLFacts          `json:"ml"`
	Group     string            `json:"group"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Purl      string            `json:"purl"`
	Cpe       string            `json:"cpe"`
	License   string            `json:"license"`
	FilePath  string            `json:"file_path"`
	Hashes    map[string]string `json:"hashes"`
	CreatedAt time.Time         `json:"created_at"`
	// Internal marks a first-party component (internal/component patterns):
	// never sent to public registries or public advisory sources.
	Internal bool `json:"internal"`

	// Reachability, read from the SBOM's own dependency graph (nil/"" when the
	// document carried none). Direct = the project depends on it on purpose;
	// Depth = hops from the root component; Scope = whether it ships at all.
	Direct *bool           `json:"direct"`
	Depth  *int            `json:"depth"`
	Scope  domain.DepScope `json:"scope"`

	// License resolution (see LicenseResolver): the normalized SPDX expression
	// ("" when absent or unparseable), the license ids it mentions, their
	// ScanCode categories, and whether it all resolved to known licenses
	// (nil = not computed yet — rows awaiting the startup backfill).
	LicenseExpression string   `json:"license_expression"`
	LicenseIDs        []string `json:"license_ids"`
	LicenseCategories []string `json:"license_categories"`
	LicenseResolved   *bool    `json:"license_resolved"`
	// LicenseTerms are the license statements the parser read, each one an
	// SPDX expression, id or name, all of which apply — the resolver's input.
	// Not stored: License keeps the raw, flattened form.
	LicenseTerms []string `json:"-"`

	// Declared* keep the SBOM's own resolved license once a project
	// license_overrides row replaces License{Expression,IDs,Categories,Resolved}
	// with the curated, concluded value (M13 13.12). Empty/nil when no override
	// applies: the two pairs are then identical.
	LicenseDeclaredExpression string   `json:"license_declared_expression"`
	LicenseDeclaredIDs        []string `json:"license_declared_ids"`
	LicenseDeclaredCategories []string `json:"license_declared_categories"`
	LicenseDeclaredResolved   *bool    `json:"license_declared_resolved"`
	LicenseOverrideID         *string  `json:"license_override_id"`
}

// ComponentHit is a component plus the snapshot/project context it was found in.
// It powers snapshot inventories, per-project inventories and global search.
type ComponentHit struct {
	Component
	ProjectSlug   string    `json:"project_slug"`
	ProjectName   string    `json:"project_name"`
	Artifact      string    `json:"artifact"`
	SbomVersion   string    `json:"sbom_version"`
	SbomCreatedAt time.Time `json:"sbom_created_at"`
	VulnState
	PackageFreshness
	// Integrity is the registry check of the component's hashes
	// (internal/pkgmeta): "verified", "mismatch", or "" when unknown.
	Integrity string `json:"integrity"`
}

// PackageFreshness is whether a component's package version is behind the
// newest release in its registry (internal/pkgmeta keeps package_status, keyed
// by purl). All fields are null when unknown — no purl, an unsupported
// ecosystem, a package the registry doesn't have, or not fetched yet — which
// is never the same as up to date.
type PackageFreshness struct {
	LatestVersion      *string    `json:"latest_version"`
	Outdated           *bool      `json:"outdated"`
	VersionsBehind     *int       `json:"versions_behind"`
	VersionPublishedAt *time.Time `json:"version_published_at"`
}

// packageFreshnessJoin attaches package_status row `ps` to component row `c`.
const packageFreshnessJoin = `
	LEFT JOIN package_status ps ON c.purl <> '' AND ps.purl = c.purl`

// VulnState is whether a component (this exact version, in this snapshot) is
// known to be vulnerable, and how badly. A vulnerability counts when either
//
//   - an advisory matched this snapshot's purl (sbom_vulns, kept by vulnmatch
//     for every snapshot — so history stays answerable after an upgrade), or
//   - a scanner reported it against this package version in the project, in any
//     status except false_positive (a remediated finding means the project
//     moved off the version, not that the version got safer).
//
// Vulns are deduplicated by CVE when there is one, else by advisory/rule id, so
// Trivy's and OSV's report of the same CVE count once.
type VulnState struct {
	VulnCount   int              `json:"vuln_count"`
	MaxSeverity *domain.Severity `json:"max_severity"`
	KEV         bool             `json:"kev"`
	Vulns       []string         `json:"vulns"`
}

// severityByRank inverts the rank componentVulnsJoin sorts severities by.
var severityByRank = map[int]domain.Severity{
	5: domain.SeverityCritical, 4: domain.SeverityHigh, 3: domain.SeverityMedium,
	2: domain.SeverityLow, 1: domain.SeverityInfo,
}

func (v *VulnState) setRank(rank *int) {
	if rank == nil {
		return
	}
	if sev, ok := severityByRank[*rank]; ok {
		v.MaxSeverity = &sev
	}
}

// componentVulnsJoin computes VulnState for component row `c` as columns
// vs.vuln_count, vs.max_rank, vs.kev, vs.vulns. See VulnState for the rule.
var componentVulnsJoin = `
	LEFT JOIN LATERAL (
		SELECT count(DISTINCT k.key)::int AS vuln_count,
		       max(k.rank) AS max_rank,
		       COALESCE(bool_or(k.kev), false) AS kev,
		       COALESCE(array_agg(DISTINCT k.key ORDER BY k.key), '{}') AS vulns
		FROM (
			SELECT COALESCE((SELECT min(x) FROM unnest(v.cves) x), v.vuln_id) AS key,
			       ` + rankAdvisorySQL + ` AS rank, false AS kev
			FROM sbom_vulns v
			WHERE ` + componentKeySQL + ` <> '' AND v.sbom_id = c.sbom_id AND v.purl = ` + componentKeySQL + `
			UNION ALL
			SELECT COALESCE((SELECT min(x) FROM unnest(f.cve) x), NULLIF(f.rule_id, ''), f.fingerprint),
			       ` + rankFindingSQL + `, f.kev
			FROM findings f
			WHERE ` + findingOnComponentSQL + `
		) k
	) vs ON true`

// Severity ranks (critical=5 … info=1) for advisory rows `v` and finding rows
// `f`; severityByRank inverts them.
const (
	rankAdvisorySQL = `CASE v.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`
	rankFindingSQL  = `CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`
)

// findingOnComponentSQL is when finding row `f` reports a vulnerability of
// component row `c` (see VulnState): same project, same package version, not
// dismissed as a false positive. License findings and policy violations
// (scanner `policy`) are findings *about* the component, not vulnerabilities
// in it — counting them would let a policy on vulnerability facts sustain itself.
//
// A *remediated* advisory finding (scanner `osv`) doesn't count either: those
// findings are derived from sbom_vulns, which already records every snapshot's
// matches. An advisory that still matches an old release is in that release's
// sbom_vulns; one that was withdrawn or no longer covers the version (a private
// advisory's range was fixed) closes its finding — counting the closed finding
// would keep the component "vulnerable" forever. Remediated *scanner* findings
// (Trivy…) still count: they are the only record that an old release shipped them.
// An archived finding doesn't count: it is out of every view.
var findingOnComponentSQL = `f.project_id = c.project_id AND` + archive.Finding("f") + `
	  AND f.status <> 'false_positive' AND f.category <> 'license' AND f.scanner <> 'policy'
	  AND NOT (f.scanner = 'osv' AND f.status = 'remediated')
	  AND ((c.purl <> '' AND f.purl = c.purl)
	    OR (f.package_name <> '' AND lower(f.package_name) = lower(c.name) AND f.package_version = c.version))`

// Repository provides access to the sboms and sbom_components tables.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const sbomColumns = `id, project_id, artifact, version, format, spec_version,
	serial_number, component_count, source, created_at, root_ref, version_id`

func scanSbom(row pgx.Row) (Sbom, error) {
	var s Sbom
	err := row.Scan(&s.ID, &s.ProjectID, &s.Artifact, &s.Version, &s.Format, &s.SpecVersion,
		&s.SerialNumber, &s.ComponentCount, &s.Source, &s.CreatedAt, &s.RootRef, &s.VersionID)
	return s, err
}

// Ingest persists a snapshot, its components, services and dependency edges in
// a single transaction, bulk-loaded with COPY for speed on large bills of
// materials.
func (r *Repository) Ingest(ctx context.Context, s Sbom, components []Component, services []BomService, edges []Edge) (Sbom, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Sbom{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	const insert = `
		INSERT INTO sboms (project_id, artifact, version, format, spec_version, serial_number, component_count, source, root_ref, version_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, project_version($1, $10, $11))
		RETURNING ` + sbomColumns
	out, err := scanSbom(tx.QueryRow(ctx, insert,
		s.ProjectID, s.Artifact, s.Version, s.Format, s.SpecVersion, s.SerialNumber, len(components), s.Source, s.RootRef,
		s.VersionName, s.VersionKind))
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.ConstraintName == "project_is_collection" {
		return Sbom{}, ErrCollection
	}
	if err != nil {
		return Sbom{}, fmt.Errorf("insert sbom: %w", err)
	}

	if len(components) > 0 {
		rows := make([][]any, len(components))
		for i, c := range components {
			hashes := c.Hashes
			if hashes == nil {
				hashes = map[string]string{}
			}
			rows[i] = []any{out.ID, out.ProjectID, c.BomRef, c.Type, cmp.Or(c.Kind, KindSoftware), c.ML, c.Group, c.Name, c.Version, c.Purl, c.Cpe, c.License, c.FilePath, hashes,
				c.Direct, c.Depth, string(c.Scope), c.Internal,
				c.LicenseExpression, nonNil(c.LicenseIDs), nonNil(c.LicenseCategories), c.LicenseResolved,
				c.LicenseDeclaredExpression, nonNil(c.LicenseDeclaredIDs), nonNil(c.LicenseDeclaredCategories), c.LicenseDeclaredResolved, c.LicenseOverrideID}
		}
		_, err = tx.CopyFrom(ctx,
			pgx.Identifier{"sbom_components"},
			[]string{"sbom_id", "project_id", "bom_ref", "type", "kind", "ml", "group", "name", "version", "purl", "cpe", "license", "file_path", "hashes",
				"direct", "depth", "scope", "internal",
				"license_expression", "license_ids", "license_categories", "license_resolved",
				"license_declared_expression", "license_declared_ids", "license_declared_categories", "license_declared_resolved", "license_override_id"},
			pgx.CopyFromRows(rows))
		if err != nil {
			return Sbom{}, fmt.Errorf("copy components: %w", err)
		}
	}
	if err := insertServices(ctx, tx, out.ID, out.ProjectID, services); err != nil {
		return Sbom{}, err
	}

	// Documents repeat edges (and the table's key forbids that), so dedupe first.
	seen := make(map[Edge]bool, len(edges))
	edgeRows := make([][]any, 0, len(edges))
	for _, e := range edges {
		if e.Parent == "" || e.Child == "" || seen[e] {
			continue
		}
		seen[e] = true
		edgeRows = append(edgeRows, []any{out.ID, e.Parent, e.Child})
	}
	if len(edgeRows) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"sbom_dependencies"},
			[]string{"sbom_id", "parent_ref", "child_ref"}, pgx.CopyFromRows(edgeRows)); err != nil {
			return Sbom{}, fmt.Errorf("copy dependencies: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Sbom{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// ListByProject returns SBOM snapshots for a project (its history), newest
// first, optionally filtered to a single artifact.
func (r *Repository) ListByProject(ctx context.Context, projectID, artifact string) ([]Sbom, error) {
	q := `SELECT ` + sbomColumns + ` FROM sboms WHERE project_id = $1`
	args := []any{projectID}
	if artifact != "" {
		args = append(args, artifact)
		q += fmt.Sprintf(" AND artifact = $%d", len(args))
	}
	q += ` ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list sboms: %w", err)
	}
	defer rows.Close()

	sboms := []Sbom{}
	for rows.Next() {
		s, err := scanSbom(rows)
		if err != nil {
			return nil, fmt.Errorf("scan sbom: %w", err)
		}
		sboms = append(sboms, s)
	}
	return sboms, rows.Err()
}

// Get returns an SBOM snapshot by id.
func (r *Repository) Get(ctx context.Context, id string) (Sbom, error) {
	const q = `SELECT ` + sbomColumns + ` FROM sboms WHERE id = $1`
	s, err := scanSbom(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Sbom{}, ErrNotFound
	}
	if err != nil {
		return Sbom{}, fmt.Errorf("get sbom: %w", err)
	}
	return s, nil
}

// ComponentFilter narrows a component search. Any zero field is ignored.
//
//   - SbomID scopes to one snapshot's inventory.
//   - ProjectID scopes to one project.
//   - LatestOnly restricts to the newest snapshot per (project, artifact),
//     i.e. current inventory rather than all history.
//   - Name/Purl/Version are exact matches; Search is a case-insensitive
//     substring match on the component name (the "filter by package" box).
//   - Vulnerable, when set, keeps only components that are (true) or are not
//     (false) known vulnerable — see VulnState.
//   - License / LicenseCategory match the resolved license ids / categories.
//   - Outdated, when set, keeps only components known to be behind (true) or
//     known to be on the newest release (false) — see PackageFreshness;
//     unknown freshness matches neither.
type ComponentFilter struct {
	SbomID     string
	ProjectID  string
	ProjectIDs []string // RBAC scope: non-nil restricts to these projects
	Name       string
	Purl       string
	Version    string
	Type       string
	// Kind keeps one component kind (see Kinds), or with "ai" every AI kind
	// (the AI inventory).
	Kind       string
	Search     string
	LatestOnly bool
	Vulnerable *bool
	// License keeps components whose resolved license ids include this id;
	// LicenseCategory those with a license in this ScanCode category. Both
	// case-insensitive.
	License         string
	LicenseCategory string
	Outdated        *bool
	// Integrity keeps components by registry hash check: "verified",
	// "mismatch", or "unknown" (no comparable hash).
	Integrity string
	// Internal keeps components by internal/component patterns' computed flag
	// (nil = both).
	Internal *bool
	Limit    int
	Offset   int
}

// SnapshotComponent is one purl-bearing package of one snapshot — the unit the
// advisory matcher evaluates. Current marks the newest snapshot per (version,
// artifact): only those produce findings (on that version); every snapshot
// records its matches.
type SnapshotComponent struct {
	SbomID    string
	ProjectID string
	VersionID string
	Name      string
	Version   string
	Purl      string
	Cpe       string
	Current   bool
	// Internal marks a first-party component (internal/component patterns):
	// matched against private advisories only, never the public ones.
	Internal bool
}

// MatchKey is how a component is matched against advisories: its purl, else
// its CPE (NVD's identifier, for components no package ecosystem names — C
// libraries, firmware, appliances). It is the key sbom_vulns rows carry in
// their purl column; componentKeySQL is its SQL twin.
func (c SnapshotComponent) MatchKey() string {
	if c.Purl != "" {
		return c.Purl
	}
	return c.Cpe
}

// componentKeySQL is SnapshotComponent.MatchKey for a component row `c`: what
// an advisory match (sbom_vulns.purl) refers to. Empty for a component with
// neither purl nor CPE: check it is non-empty before joining on it.
const componentKeySQL = `COALESCE(NULLIF(c.purl, ''), c.cpe)`

// ListSnapshotInventory returns every distinct matchable component (purl or
// CPE) of every snapshot, optionally for one project. Components with neither
// can't be matched against an advisory feed, so they're skipped.
func (r *Repository) ListSnapshotInventory(ctx context.Context, projectID string) ([]SnapshotComponent, error) {
	q := `
		WITH latest AS (
			SELECT DISTINCT ON (version_id, artifact) id FROM sboms
			WHERE $1::uuid IS NULL OR project_id = $1
			ORDER BY version_id, artifact, created_at DESC
		)
		SELECT DISTINCT c.sbom_id, c.project_id, s.version_id, c.name, c.version, c.purl, c.cpe, c.sbom_id IN (SELECT id FROM latest), c.internal
		FROM sbom_components c
		JOIN sboms s ON s.id = c.sbom_id
		WHERE (c.purl <> '' OR c.cpe <> '') AND ($1::uuid IS NULL OR c.project_id = $1)
		  -- An archived project is matched again once restored.
		  AND c.project_id IN (SELECT id FROM projects WHERE` + archive.Project("") + `)
		ORDER BY c.project_id, c.sbom_id, c.purl, c.cpe`
	var scope *string
	if projectID != "" {
		scope = &projectID
	}
	rows, err := r.db.Query(ctx, q, scope)
	if err != nil {
		return nil, fmt.Errorf("list snapshot inventory: %w", err)
	}
	defer rows.Close()
	out := []SnapshotComponent{}
	for rows.Next() {
		var c SnapshotComponent
		if err := rows.Scan(&c.SbomID, &c.ProjectID, &c.VersionID, &c.Name, &c.Version, &c.Purl, &c.Cpe, &c.Current, &c.Internal); err != nil {
			return nil, fmt.Errorf("scan snapshot component: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// componentColumns selects a ComponentHit (with its VulnState and
// PackageFreshness); pair it with componentFrom and scanComponentHit.
const componentColumns = `
		SELECT c.id, c.bom_ref, c.sbom_id, c.project_id, c.type, c.kind, c.ml, c."group", c.name, c.version,
		       c.purl, c.cpe, c.license, c.file_path, c.hashes, c.created_at, c.internal,
		       c.direct, c.depth, c.scope,
		       c.license_expression, c.license_ids, c.license_categories, c.license_resolved,
		       c.license_declared_expression, c.license_declared_ids, c.license_declared_categories, c.license_declared_resolved, c.license_override_id,
		       p.slug, p.name, s.artifact, s.version, s.created_at,
		       vs.vuln_count, vs.max_rank, vs.kev, vs.vulns,
		       ps.latest_version, ps.outdated, ps.versions_behind, ps.published_at,
		       COALESCE(c.integrity, '')`

var componentFrom = `
		FROM sbom_components c
		JOIN sboms s ON s.id = c.sbom_id
		JOIN projects p ON p.id = c.project_id` + componentVulnsJoin + packageFreshnessJoin

func scanComponentHit(row pgx.Row) (ComponentHit, error) {
	var h ComponentHit
	var rank *int
	err := row.Scan(&h.ID, &h.BomRef, &h.SbomID, &h.ProjectID, &h.Type, &h.Kind, &h.ML, &h.Group, &h.Name, &h.Version,
		&h.Purl, &h.Cpe, &h.License, &h.FilePath, &h.Hashes, &h.Component.CreatedAt, &h.Internal,
		&h.Direct, &h.Depth, &h.Scope,
		&h.LicenseExpression, &h.LicenseIDs, &h.LicenseCategories, &h.LicenseResolved,
		&h.LicenseDeclaredExpression, &h.LicenseDeclaredIDs, &h.LicenseDeclaredCategories, &h.LicenseDeclaredResolved, &h.LicenseOverrideID,
		&h.ProjectSlug, &h.ProjectName, &h.Artifact, &h.SbomVersion, &h.SbomCreatedAt,
		&h.VulnCount, &rank, &h.KEV, &h.Vulns,
		&h.LatestVersion, &h.Outdated, &h.VersionsBehind, &h.VersionPublishedAt,
		&h.Integrity)
	h.setRank(rank)
	return h, err
}

// ListComponents runs a filtered component search joined with its snapshot and
// project context and its vulnerability state.
func (r *Repository) ListComponents(ctx context.Context, f ComponentFilter) ([]ComponentHit, error) {
	q, args := componentQuery(f)
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	args = append(args, limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))
	if f.Offset > 0 {
		args = append(args, f.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list components: %w", err)
	}
	defer rows.Close()

	hits := []ComponentHit{}
	for rows.Next() {
		h, err := scanComponentHit(rows)
		if err != nil {
			return nil, fmt.Errorf("scan component: %w", err)
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}

// componentQuery builds the ordered, unlimited component SELECT for f — shared
// by ListComponents and EachComponent so an export is exactly the listing.
func componentQuery(f ComponentFilter) (string, []any) {
	q := componentColumns + componentFrom + ` WHERE 1 = 1`
	if f.SbomID == "" {
		q += " AND" + archive.Project("p") // an archived project's inventory is out of the listings
	}
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		q += fmt.Sprintf(" AND "+cond, len(args))
	}

	if f.SbomID != "" {
		add("c.sbom_id = $%d", f.SbomID)
	}
	if f.ProjectID != "" {
		add("c.project_id = $%d", f.ProjectID)
	}
	if f.ProjectIDs != nil {
		add("c.project_id = ANY($%d)", f.ProjectIDs)
	}
	if f.Name != "" {
		add("c.name = $%d", f.Name)
	}
	if f.Purl != "" {
		add("c.purl = $%d", f.Purl)
	}
	if f.Version != "" {
		add("c.version = $%d", f.Version)
	}
	if f.Type != "" {
		add("c.type = $%d", f.Type)
	}
	switch f.Kind {
	case "":
	case KindAI:
		q += ` AND c.kind <> '` + KindSoftware + `'`
	default:
		add("c.kind = $%d", f.Kind)
	}
	if f.Search != "" {
		add("c.name ILIKE '%%' || $%d || '%%'", f.Search)
	}
	if f.LatestOnly {
		// The current inventory: the newest snapshot per artifact of each
		// project's default version — what actually ships.
		latest := `c.sbom_id IN (
			SELECT DISTINCT ON (s.version_id, s.artifact) s.id FROM sboms s
			JOIN project_versions v ON v.id = s.version_id AND v.is_default`
		switch {
		case f.ProjectID != "":
			args = append(args, f.ProjectID)
			latest += fmt.Sprintf(" WHERE s.project_id = $%d", len(args))
		case f.ProjectIDs != nil:
			args = append(args, f.ProjectIDs)
			latest += fmt.Sprintf(" WHERE s.project_id = ANY($%d)", len(args))
		}
		latest += ` ORDER BY s.version_id, s.artifact, s.created_at DESC)`
		q += " AND " + latest
	}
	if f.Vulnerable != nil {
		if *f.Vulnerable {
			q += ` AND vs.vuln_count > 0`
		} else {
			q += ` AND vs.vuln_count = 0`
		}
	}
	if f.License != "" {
		add("EXISTS (SELECT 1 FROM unnest(c.license_ids) x WHERE lower(x) = lower($%d))", f.License)
	}
	if f.LicenseCategory != "" {
		add("EXISTS (SELECT 1 FROM unnest(c.license_categories) x WHERE lower(x) = lower($%d))", f.LicenseCategory)
	}
	if f.Outdated != nil {
		if *f.Outdated {
			q += ` AND ps.outdated`
		} else {
			q += ` AND NOT ps.outdated` // NULL (unknown) matches neither
		}
	}
	switch f.Integrity {
	case "unknown":
		q += ` AND c.integrity IS NULL`
	case "verified", "mismatch":
		add("c.integrity = $%d", f.Integrity)
	}
	if f.Internal != nil {
		add("c.internal = $%d", *f.Internal)
	}
	return q + ` ORDER BY c.name, s.created_at DESC`, args
}

// EachComponent streams the components f matches — exactly ListComponents'
// rows and order, ignoring Limit/Offset — to fn from a single cursor, stopping
// after limit rows. Exports use it so a download never holds the whole
// inventory in memory.
func (r *Repository) EachComponent(ctx context.Context, f ComponentFilter, limit int, fn func(ComponentHit) error) error {
	q, args := componentQuery(f)
	args = append(args, limit)
	q += fmt.Sprintf(" LIMIT $%d", len(args))
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("export components: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		h, err := scanComponentHit(rows)
		if err != nil {
			return fmt.Errorf("scan component: %w", err)
		}
		if err := fn(h); err != nil {
			return err
		}
	}
	return rows.Err()
}
