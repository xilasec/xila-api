package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// Relation errors.
var (
	ErrRelationNotFound  = errors.New("relation not found")
	ErrRelationDuplicate = errors.New("relation already exists")
	ErrSelfRelation      = errors.New("an asset cannot relate to itself")
)

// RelationKind types an edge, read as a sentence: from <kind> to.
type RelationKind string

// Relation kinds.
const (
	// BuiltFrom: from was built from to (an app image built from a base image).
	BuiltFrom RelationKind = "built_from"
	// DeployedAs: from runs as to (an image deployed as a Kubernetes workload).
	DeployedAs RelationKind = "deployed_as"
	// DependsOn: from needs to at runtime (a service and its database). It is
	// informational: a vulnerability in to doesn't ship inside from, so it is not
	// part of a blast radius.
	DependsOn RelationKind = "depends_on"
)

// Valid reports whether k is a known relation kind.
func (k RelationKind) Valid() bool { return k == BuiltFrom || k == DeployedAs || k == DependsOn }

// Ref is the identity of an asset at the other end of an edge.
type Ref struct {
	ID        string           `json:"id"`
	ProjectID string           `json:"project_id"`
	Type      domain.AssetType `json:"type"`
	Name      string           `json:"name"`
	Exposure  *domain.Exposure `json:"exposure"`
}

// Relation is a typed edge between two assets.
type Relation struct {
	ID          string       `json:"id"`
	FromAssetID string       `json:"from_asset_id"`
	ToAssetID   string       `json:"to_asset_id"`
	Kind        RelationKind `json:"kind"`
	CreatedBy   *string      `json:"created_by"`
	CreatedAt   time.Time    `json:"created_at"`
	// From/To describe both ends (filled by ListRelations).
	From *Ref `json:"from,omitempty"`
	To   *Ref `json:"to,omitempty"`
}

const relationColumns = `id, from_asset_id, to_asset_id, kind, created_by, created_at`

func scanRelation(row pgx.Row, extra ...any) (Relation, error) {
	var r Relation
	err := row.Scan(append([]any{&r.ID, &r.FromAssetID, &r.ToAssetID, &r.Kind, &r.CreatedBy, &r.CreatedAt}, extra...)...)
	return r, err
}

// CreateRelation stores an edge. createdBy may be empty (API token without a user).
func (r *Repository) CreateRelation(ctx context.Context, rel Relation) (Relation, error) {
	if rel.FromAssetID == rel.ToAssetID {
		return Relation{}, ErrSelfRelation
	}
	var by *string
	if rel.CreatedBy != nil && *rel.CreatedBy != "" {
		by = rel.CreatedBy
	}
	out, err := scanRelation(r.db.QueryRow(ctx, `
		INSERT INTO asset_relations (from_asset_id, to_asset_id, kind, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING `+relationColumns, rel.FromAssetID, rel.ToAssetID, rel.Kind, by))
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case "23505":
			return Relation{}, ErrRelationDuplicate
		case "23503":
			return Relation{}, ErrNotFound
		}
	}
	if err != nil {
		return Relation{}, fmt.Errorf("insert relation: %w", err)
	}
	return out, nil
}

// ListRelations returns every edge touching an asset, both ends described.
func (r *Repository) ListRelations(ctx context.Context, assetID string) ([]Relation, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.id, r.from_asset_id, r.to_asset_id, r.kind, r.created_by, r.created_at,
		       fa.project_id, fa.type, fa.name, fa.exposure,
		       ta.project_id, ta.type, ta.name, ta.exposure
		FROM asset_relations r
		JOIN assets fa ON fa.id = r.from_asset_id
		JOIN assets ta ON ta.id = r.to_asset_id
		WHERE r.from_asset_id = $1 OR r.to_asset_id = $1
		ORDER BY r.kind, r.created_at`, assetID)
	if err != nil {
		return nil, fmt.Errorf("list relations: %w", err)
	}
	defer rows.Close()
	out := []Relation{}
	for rows.Next() {
		var from, to Ref
		rel, err := scanRelation(rows, &from.ProjectID, &from.Type, &from.Name, &from.Exposure,
			&to.ProjectID, &to.Type, &to.Name, &to.Exposure)
		if err != nil {
			return nil, fmt.Errorf("scan relation: %w", err)
		}
		from.ID, to.ID = rel.FromAssetID, rel.ToAssetID
		rel.From, rel.To = &from, &to
		out = append(out, rel)
	}
	return out, rows.Err()
}

// DeleteRelation removes an edge, which must touch assetID.
func (r *Repository) DeleteRelation(ctx context.Context, assetID, relationID string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM asset_relations
		WHERE id = $1 AND (from_asset_id = $2 OR to_asset_id = $2)`, relationID, assetID)
	if err != nil {
		return fmt.Errorf("delete relation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRelationNotFound
	}
	return nil
}

// Downstream is an asset in another's blast radius.
type Downstream struct {
	Asset Asset `json:"asset"`
	// Depth is the number of edges from the root (1 = built directly from it /
	// deployed directly as it); the shortest path wins.
	Depth int `json:"depth"`
	// Via is the kind of the last edge on that path.
	Via RelationKind `json:"via"`
}

// maxBlastDepth bounds the traversal; real image lineages are a handful deep.
const maxBlastDepth = 16

// Downstream walks everything that inherits an asset's content, transitively:
// assets built_from it, and what it (or they) are deployed_as. Cycles are cut;
// each asset appears once, at its shallowest depth.
func (r *Repository) Downstream(ctx context.Context, assetID string) ([]Downstream, error) {
	rows, err := r.db.Query(ctx, `
		WITH RECURSIVE edges AS (
			SELECT to_asset_id AS src, from_asset_id AS dst, kind FROM asset_relations WHERE kind = 'built_from'
			UNION ALL
			SELECT from_asset_id, to_asset_id, kind FROM asset_relations WHERE kind = 'deployed_as'
		), down(asset_id, depth, via, path) AS (
			SELECT $1::uuid, 0, ''::text, ARRAY[$1::uuid]
			UNION ALL
			SELECT e.dst, d.depth + 1, e.kind, d.path || e.dst
			FROM down d JOIN edges e ON e.src = d.asset_id
			WHERE NOT e.dst = ANY(d.path) AND d.depth < $2
		), best AS (
			SELECT DISTINCT ON (asset_id) asset_id, depth, via FROM down WHERE depth > 0
			ORDER BY asset_id, depth, via
		)
		SELECT a.id, a.project_id, a.type, a.name, a.identifier, a.metadata, a.exposure, a.exposure_source,
		       a.exposure_reason, a.exposure_updated_at, a.created_at, a.updated_at, b.depth, b.via
		FROM best b JOIN assets a ON a.id = b.asset_id
		ORDER BY b.depth, a.name, a.id`, assetID, maxBlastDepth)
	if err != nil {
		return nil, fmt.Errorf("downstream assets: %w", err)
	}
	defer rows.Close()
	out := []Downstream{}
	for rows.Next() {
		var d Downstream
		a := &d.Asset
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Type, &a.Name, &a.Identifier, &a.Metadata,
			&a.Exposure, &a.ExposureSource, &a.ExposureReason, &a.ExposureUpdatedAt, &a.CreatedAt, &a.UpdatedAt,
			&d.Depth, &d.Via); err != nil {
			return nil, fmt.Errorf("scan downstream: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SharedFinding is an open finding on a downstream asset that shares a CVE or
// a package (same purl, or same name and version) with the root asset's open
// findings — the inherited part of its backlog.
type SharedFinding struct {
	ID             string               `json:"id"`
	AssetID        string               `json:"asset_id"`
	ProjectID      string               `json:"project_id"`
	Title          string               `json:"title"`
	Severity       domain.Severity      `json:"severity"`
	Status         domain.FindingStatus `json:"status"`
	Priority       float64              `json:"priority"`
	CVE            []string             `json:"cve"`
	PackageName    string               `json:"package_name"`
	PackageVersion string               `json:"package_version"`
}

// liveDefault restricts a findings query (alias f) to the working backlog: open
// or confirmed, the primary of its dedup group, on the project's default
// version, not archived.
var liveDefault = `f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
	AND f.version_id IN (SELECT id FROM project_versions WHERE is_default) AND` + archive.Finding("f")

// SharedFindings returns the open findings on the given assets that share a CVE
// or package with rootID's open findings, highest priority first.
func (r *Repository) SharedFindings(ctx context.Context, rootID string, assetIDs []string) ([]SharedFinding, error) {
	out := []SharedFinding{}
	if len(assetIDs) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `
		WITH root AS (
			SELECT f.cve, f.purl, lower(f.package_name) AS pn, f.package_version AS pv
			FROM findings f WHERE f.asset_id = $1 AND `+liveDefault+`
		)
		SELECT f.id, f.asset_id, f.project_id, f.title, f.severity, f.status, f.priority, f.cve,
		       f.package_name, f.package_version
		FROM findings f
		WHERE f.asset_id = ANY($2) AND `+liveDefault+`
		  AND (f.cve && ARRAY(SELECT DISTINCT unnest(cve) FROM root)
		    OR (f.purl <> '' AND f.purl IN (SELECT purl FROM root WHERE purl <> ''))
		    OR (f.package_name <> '' AND (lower(f.package_name), f.package_version) IN
		        (SELECT pn, pv FROM root WHERE pn <> '')))
		ORDER BY f.priority DESC, f.id`, rootID, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("shared findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s SharedFinding
		if err := rows.Scan(&s.ID, &s.AssetID, &s.ProjectID, &s.Title, &s.Severity, &s.Status, &s.Priority,
			&s.CVE, &s.PackageName, &s.PackageVersion); err != nil {
			return nil, fmt.Errorf("scan shared finding: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ScanEvidence returns the live findings a scan reported, as exposure inference
// reads them. False positives and remediated findings are no evidence.
func (r *Repository) ScanEvidence(ctx context.Context, scanID string) ([]Evidence, error) {
	rows, err := r.db.Query(ctx, `
		SELECT asset_id, scanner, category, rule_id, file_path,
		       COALESCE(metadata->>'resource_arn', ''),
		       ARRAY(SELECT jsonb_array_elements_text(CASE WHEN jsonb_typeof(metadata->'categories') = 'array'
		                                                  THEN metadata->'categories' ELSE '[]' END))
		FROM findings
		WHERE last_scan_id = $1 AND status NOT IN ('false_positive', 'remediated')`, scanID)
	if err != nil {
		return nil, fmt.Errorf("scan evidence: %w", err)
	}
	defer rows.Close()
	out := []Evidence{}
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.AssetID, &e.Scanner, &e.Category, &e.RuleID, &e.Resource, &e.ResourceARN, &e.Categories); err != nil {
			return nil, fmt.Errorf("scan evidence row: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// IdentifierIndex maps a project's asset identifiers to asset ids, so a cloud
// finding naming a resource (id or ARN) can be tied to the asset registered for it.
func (r *Repository) IdentifierIndex(ctx context.Context, projectID string) (map[string]string, error) {
	rows, err := r.db.Query(ctx, `SELECT identifier, id FROM assets WHERE project_id = $1 AND identifier <> ''`, projectID)
	if err != nil {
		return nil, fmt.Errorf("asset identifiers: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var ident, id string
		if err := rows.Scan(&ident, &id); err != nil {
			return nil, err
		}
		out[ident] = id
	}
	return out, rows.Err()
}

// Overlap is how many OS packages another container image shares with one image.
type Overlap struct {
	AssetID string
	Total   int // the other image's OS packages
	Shared  int // of those, also in this image
}

// OSPackageOverlap compares a container image's OS package set with every other
// container image in scope (all projects, or projectIDs). An image's packages are
// its project's newest default-version SBOM whose artifact names the image (equal
// to the asset's identifier or name); OS packages are deb/apk/rpm/alpm purls,
// version included. mine is 0 when the image has no such SBOM.
func (r *Repository) OSPackageOverlap(ctx context.Context, assetID string, all bool, projectIDs []string) (int, []Overlap, error) {
	rows, err := r.db.Query(ctx, `
		WITH img AS (
			SELECT a.id AS asset_id, s.id AS sbom_id
			FROM assets a
			JOIN LATERAL (
				SELECT s.id FROM sboms s JOIN project_versions v ON v.id = s.version_id AND v.is_default
				WHERE s.project_id = a.project_id AND s.artifact <> '' AND s.artifact IN (a.identifier, a.name)
				ORDER BY s.created_at DESC LIMIT 1
			) s ON true
			WHERE a.type = 'container_image' AND (a.id = $1 OR $2 OR a.project_id = ANY($3))
		), os AS (
			SELECT DISTINCT i.asset_id, c.purl
			FROM img i JOIN sbom_components c ON c.sbom_id = i.sbom_id
			WHERE c.purl ~ '^pkg:(deb|apk|rpm|alpm)/'
		)
		SELECT o.asset_id, count(*), count(*) FILTER (WHERE o.purl IN (SELECT purl FROM os WHERE asset_id = $1))
		FROM os o
		GROUP BY o.asset_id`, assetID, all, projectIDs)
	if err != nil {
		return 0, nil, fmt.Errorf("os package overlap: %w", err)
	}
	defer rows.Close()
	mine := 0
	var out []Overlap
	for rows.Next() {
		var o Overlap
		if err := rows.Scan(&o.AssetID, &o.Total, &o.Shared); err != nil {
			return 0, nil, err
		}
		if o.AssetID == assetID {
			mine = o.Total
			continue
		}
		if o.Shared > 0 {
			out = append(out, o)
		}
	}
	return mine, out, rows.Err()
}

// MinBaseOSPackages is the smallest OS package set taken as evidence of a base
// image: below it (scratch, distroless) a subset relation is coincidence.
const MinBaseOSPackages = 5

// Proposal is an inferred built_from edge between this image and another.
type Proposal struct {
	// Base is true when the other image is this one's base (this built_from
	// other); false when the other is built from this one.
	Base   bool
	Other  Overlap
	Reason string
}

// ProposeBuiltFrom turns OS package overlaps into built_from proposals. Another
// image is this one's base when its whole OS package set (≥ MinBaseOSPackages,
// same versions) is a proper subset of this image's; of several such bases only
// the largest — the closest parent — is proposed. Conversely every image whose
// set properly contains this one's is proposed as built from it. Identical sets
// are the same image, or a rebuild, and propose nothing.
func ProposeBuiltFrom(mine int, others []Overlap) []Proposal {
	var out []Proposal
	best := 0
	for _, o := range others {
		if o.Shared == o.Total && o.Total < mine && o.Total >= MinBaseOSPackages {
			best = max(best, o.Total)
		}
	}
	for _, o := range others {
		switch {
		case best > 0 && o.Total == best && o.Shared == o.Total && o.Total < mine:
			out = append(out, Proposal{Base: true, Other: o, Reason: fmt.Sprintf(
				"all %d of its OS packages are in this image (which has %d)", o.Total, mine)})
		case mine >= MinBaseOSPackages && o.Shared == mine && mine < o.Total:
			out = append(out, Proposal{Other: o, Reason: fmt.Sprintf(
				"all %d of this image's OS packages are in it (which has %d)", mine, o.Total)})
		}
	}
	return out
}
