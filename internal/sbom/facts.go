package sbom

import (
	"context"
	"fmt"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// InventoryComponent is one component of a project version's current inventory
// (the newest snapshot per artifact) with the facts policies judge it on: its
// coordinates, hashes, resolved license and vulnerability state.
type InventoryComponent struct {
	SbomID      string
	ProjectID   string
	ProjectName string
	// ProjectCustom is the project's custom-field values.
	ProjectCustom map[string]any
	VersionID     string
	VersionName   string
	// IsDefault marks the project's default version.
	IsDefault bool

	Type string
	// Kind is the component kind (see Kinds); ML its model-card facts (nil
	// for software, and fields unknown when unset).
	Kind    string
	ML      *MLFacts
	Group   string
	Name    string
	Version string
	Purl    string
	Hashes  map[string]string
	// Integrity is the registry check of Hashes (internal/pkgmeta):
	// "verified", "mismatch", or "" when unknown.
	Integrity string

	// License is the raw string from the SBOM; LicenseExpression its normalized
	// SPDX expression ('' when empty or unparseable). LicenseResolved is nil
	// until the license resolver has run on the row.
	License           string
	LicenseExpression string
	LicenseResolved   *bool

	// Vulnerability facts, by the VulnState rule: every advisory/rule id and CVE
	// (VulnIDs), the worst severity, whether any is on a KEV catalog (and
	// which: KEVSources, sorted), the highest EPSS and the CWEs scanners
	// reported.
	VulnIDs     []string
	MaxSeverity *domain.Severity
	KEV         bool
	KEVSources  []string
	EPSS        *float64
	CWEs        []int
}

// CurrentInventory returns the components of every project version's current
// snapshots — optionally only for projectIDs (nil = every project) and one
// version — ordered by project, version, name. It is what the policy engine
// evaluates.
func (r *Repository) CurrentInventory(ctx context.Context, projectIDs []string, versionID string) ([]InventoryComponent, error) {
	q := `
		WITH current AS (
			SELECT DISTINCT ON (version_id, artifact) id FROM sboms
			WHERE ($1::uuid[] IS NULL OR project_id = ANY($1))
			  AND ($2::uuid IS NULL OR version_id = $2)
			  AND project_id IN (SELECT id FROM projects WHERE` + archive.Project("") + `)
			ORDER BY version_id, artifact, created_at DESC, id DESC
		)
		SELECT c.sbom_id, c.project_id, p.name, p.custom, s.version_id, pv.name, pv.is_default,
		       c.type, c.kind, c.ml, c."group", c.name, c.version, c.purl, c.hashes, COALESCE(c.integrity, ''),
		       c.license, COALESCE(c.license_expression, ''), c.license_resolved,
		       vf.ids, vf.max_rank, COALESCE(vf.kev, false), vf.kev_sources, vf.epss, vf.cwes
		FROM current cur
		JOIN sboms s ON s.id = cur.id
		JOIN sbom_components c ON c.sbom_id = s.id
		JOIN projects p ON p.id = c.project_id
		JOIN project_versions pv ON pv.id = s.version_id
		LEFT JOIN LATERAL (
			SELECT COALESCE(array_agg(DISTINCT k.id) FILTER (WHERE k.id <> ''), '{}') AS ids,
			       max(k.rank) AS max_rank,
			       bool_or(k.kev) AS kev,
			       COALESCE(array_agg(DISTINCT ks.s ORDER BY ks.s) FILTER (WHERE ks.s IS NOT NULL), '{}') AS kev_sources,
			       max(k.epss) AS epss,
			       COALESCE(array_agg(DISTINCT k.cwe) FILTER (WHERE k.cwe IS NOT NULL), '{}') AS cwes
			FROM (
				SELECT unnest(array_prepend(v.vuln_id, v.cves)) AS id,
				       ` + rankAdvisorySQL + ` AS rank, false AS kev, '{}'::text[] AS kev_sources,
				       NULL::float8 AS epss, NULL::int AS cwe
				FROM sbom_vulns v
				WHERE ` + componentKeySQL + ` <> '' AND v.sbom_id = c.sbom_id AND v.purl = ` + componentKeySQL + `
				UNION ALL
				SELECT unnest(array_prepend(f.rule_id, f.cve)), ` + rankFindingSQL + `, f.kev, f.kev_sources,
				       f.epss::float8, f.cwe
				FROM findings f
				WHERE ` + findingOnComponentSQL + `
			) k
			LEFT JOIN LATERAL unnest(k.kev_sources) ks(s) ON true
		) vf ON true
		ORDER BY c.project_id, s.version_id, c.name, c.version, c.purl`
	var version *string
	if versionID != "" {
		version = &versionID
	}
	rows, err := r.db.Query(ctx, q, projectIDs, version)
	if err != nil {
		return nil, fmt.Errorf("current inventory: %w", err)
	}
	defer rows.Close()
	out := []InventoryComponent{}
	for rows.Next() {
		var (
			c    InventoryComponent
			rank *int
		)
		if err := rows.Scan(&c.SbomID, &c.ProjectID, &c.ProjectName, &c.ProjectCustom, &c.VersionID, &c.VersionName, &c.IsDefault,
			&c.Type, &c.Kind, &c.ML, &c.Group, &c.Name, &c.Version, &c.Purl, &c.Hashes, &c.Integrity,
			&c.License, &c.LicenseExpression, &c.LicenseResolved,
			&c.VulnIDs, &rank, &c.KEV, &c.KEVSources, &c.EPSS, &c.CWEs); err != nil {
			return nil, fmt.Errorf("scan inventory component: %w", err)
		}
		if rank != nil {
			if sev, ok := severityByRank[*rank]; ok {
				c.MaxSeverity = &sev
			}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
