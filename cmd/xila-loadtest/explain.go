package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// explainQuery mirrors one of the app's real query shapes (copied from
// internal/finding and internal/sbom; kept here rather than exported from
// those packages so this diagnostic tool can't accidentally change
// production SQL). args are filled in by name below.
type explainQuery struct {
	sql string
	// needsProject/needsProjects/needsSearch select which flag values fill $1…
	needsProject  bool
	needsProjects bool
	needsSearch   bool
}

// Mirrors finding.listQuery's default listing: one project, default version,
// duplicates collapsed, newest first (internal/finding/finding.go).
const listDefaultSQL = `
	SELECT id FROM findings WHERE 1 = 1
	  AND project_id = $1
	  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND duplicate_of IS NULL
	  AND archived_at IS NULL AND project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
	ORDER BY last_seen_at DESC LIMIT 101`

// Mirrors the active-backlog, priority-sorted listing (gates, the UI's
// default "priority" sort) — the shape idx_findings_active targets.
const listPriorityActiveSQL = `
	SELECT id FROM findings WHERE 1 = 1
	  AND project_id = $1
	  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND status IN ('open', 'confirmed')
	  AND duplicate_of IS NULL
	  AND archived_at IS NULL AND project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
	ORDER BY priority DESC, last_seen_at DESC LIMIT 101`

// Mirrors a full-text search listing (findings_search GIN index).
const listSearchSQL = `
	SELECT id FROM findings WHERE 1 = 1
	  AND project_id = $1
	  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND duplicate_of IS NULL
	  AND archived_at IS NULL AND project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
	  AND search @@ websearch_to_tsquery('simple', $2)
	ORDER BY ts_rank(search, websearch_to_tsquery('simple', $2)) DESC, priority DESC, last_seen_at DESC LIMIT 101`

// Mirrors GET /findings (admin, no project scope): the cross-project default
// listing every portfolio-wide view pays for.
const listPortfolioSQL = `
	SELECT id FROM findings WHERE 1 = 1
	  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND duplicate_of IS NULL
	  AND archived_at IS NULL AND project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
	ORDER BY last_seen_at DESC LIMIT 101`

// Mirrors finding.Repository.CountByProjects — the per-project summary and
// the portfolio rollup's shared aggregate.
const countByProjectsSQL = `
	SELECT f.status, f.severity, p.business_criticality, count(*)
	FROM findings f JOIN projects p ON p.id = f.project_id
	WHERE f.project_id = ANY($1) AND f.duplicate_of IS NULL
	  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND f.archived_at IS NULL AND f.project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
	GROUP BY f.status, f.severity, p.business_criticality`

// Mirrors sbom.componentQuery's global /components?q= search.
const componentsSearchSQL = `
	SELECT c.id
	FROM sbom_components c
	JOIN sboms s ON s.id = c.sbom_id
	JOIN projects p ON p.id = c.project_id
	LEFT JOIN LATERAL (
		SELECT count(DISTINCT k.key)::int AS vuln_count
		FROM (
			SELECT COALESCE((SELECT min(x) FROM unnest(v.cves) x), v.vuln_id) AS key
			FROM sbom_vulns v
			WHERE COALESCE(NULLIF(c.purl, ''), c.cpe) <> '' AND v.sbom_id = c.sbom_id
			  AND v.purl = COALESCE(NULLIF(c.purl, ''), c.cpe)
			UNION ALL
			SELECT COALESCE((SELECT min(x) FROM unnest(f.cve) x), NULLIF(f.rule_id, ''), f.fingerprint)
			FROM findings f
			WHERE f.project_id = c.project_id AND f.archived_at IS NULL
			  AND f.status <> 'false_positive' AND f.category <> 'license' AND f.scanner <> 'policy'
			  AND NOT (f.scanner = 'osv' AND f.status = 'remediated')
			  AND ((c.purl <> '' AND f.purl = c.purl)
			    OR (f.package_name <> '' AND lower(f.package_name) = lower(c.name) AND f.package_version = c.version))
		) k
	) vs ON true
	LEFT JOIN package_status ps ON c.purl <> '' AND ps.purl = c.purl
	WHERE 1 = 1 AND p.archived_at IS NULL AND c.name ILIKE '%' || $1 || '%'
	ORDER BY c.name, s.created_at DESC LIMIT 101`

var explainQueries = map[string]explainQuery{
	"list-default":         {sql: listDefaultSQL, needsProject: true},
	"list-priority-active": {sql: listPriorityActiveSQL, needsProject: true},
	"list-search":          {sql: listSearchSQL, needsProject: true, needsSearch: true},
	"list-portfolio":       {sql: listPortfolioSQL},
	"count-by-projects":    {sql: countByProjectsSQL, needsProjects: true},
	"components-search":    {sql: componentsSearchSQL, needsSearch: true},
}

func runExplain(args []string) error {
	fs := flag.NewFlagSet("explain", flag.ExitOnError)
	dsn := fs.String("dsn", "", "Postgres DSN (required)")
	query := fs.String("query", "", "query key: list-default, list-priority-active, list-search, list-portfolio, count-by-projects, components-search")
	project := fs.String("project", "", "project id (for project-scoped keys)")
	search := fs.String("search", "pkg-0001234", "search term (for *-search keys)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" || *query == "" {
		return errors.New("--dsn and --query are required")
	}
	eq, ok := explainQueries[*query]
	if !ok {
		return fmt.Errorf("unknown query key %q", *query)
	}
	if eq.needsProject && *project == "" {
		return fmt.Errorf("--project is required for %q", *query)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	var qargs []any
	switch {
	case eq.needsProject && eq.needsSearch:
		qargs = []any{*project, *search}
	case eq.needsProject:
		qargs = []any{*project}
	case eq.needsProjects:
		ids, err := allProjectIDs(ctx, pool)
		if err != nil {
			return err
		}
		qargs = []any{ids}
	case eq.needsSearch:
		qargs = []any{*search}
	}

	rows, err := pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+eq.sql, qargs...)
	if err != nil {
		return fmt.Errorf("explain: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return err
		}
		fmt.Println(line)
	}
	return rows.Err()
}

func allProjectIDs(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `SELECT id FROM projects`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
