package sbom

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// SnapshotVuln is one advisory matched against one purl of one snapshot.
type SnapshotVuln struct {
	SbomID       string
	Purl         string
	VulnID       string
	CVEs         []string
	Severity     domain.Severity
	Summary      string
	FixedVersion string
}

// matchChunk bounds how many matches go into one upsert statement.
const matchChunk = 5000

// RecordMatches replaces the advisory matches of the given snapshots with
// matches: new ones are inserted, still-matching ones refreshed (first_seen_at
// kept — it's when we learned of it), and ones today's feed no longer reports
// (withdrawn advisory, corrected range) removed. One transaction, so a reader
// never sees a half-replaced snapshot.
func (r *Repository) RecordMatches(ctx context.Context, sbomIDs []string, matches []SnapshotVuln) error {
	if len(sbomIDs) == 0 {
		return nil
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	// now() is fixed for the whole transaction: every row this run touches gets
	// exactly it, so "last_seen_at < now()" is precisely the set it didn't.
	const upsert = `
		INSERT INTO sbom_vulns (sbom_id, purl, vuln_id, cves, severity, summary, fixed_version, last_seen_at)
		SELECT m.sbom_id, m.purl, m.vuln_id, COALESCE(string_to_array(NULLIF(m.cves, ''), ','), '{}'), m.severity, m.summary, m.fixed, now()
		FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
		     AS m(sbom_id, purl, vuln_id, cves, severity, summary, fixed)
		ON CONFLICT (sbom_id, purl, vuln_id) DO UPDATE SET
			cves = EXCLUDED.cves, severity = EXCLUDED.severity, summary = EXCLUDED.summary,
			fixed_version = EXCLUDED.fixed_version, last_seen_at = now()`
	for start := 0; start < len(matches); start += matchChunk {
		batch := matches[start:min(start+matchChunk, len(matches))]
		cols := make([][]string, 7)
		for _, m := range batch {
			cols[0] = append(cols[0], m.SbomID)
			cols[1] = append(cols[1], m.Purl)
			cols[2] = append(cols[2], m.VulnID)
			cols[3] = append(cols[3], strings.Join(m.CVEs, ","))
			cols[4] = append(cols[4], string(m.Severity))
			cols[5] = append(cols[5], m.Summary)
			cols[6] = append(cols[6], m.FixedVersion)
		}
		if _, err := tx.Exec(ctx, upsert, cols[0], cols[1], cols[2], cols[3], cols[4], cols[5], cols[6]); err != nil {
			return fmt.Errorf("record matches: %w", err)
		}
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM sbom_vulns WHERE sbom_id = ANY($1) AND last_seen_at < now()`, sbomIDs); err != nil {
		return fmt.Errorf("prune matches: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// matchLockNamespace keys the per-project advisory lock the vulnerability
// matcher holds while it applies findings (finding dedup uses namespace 1).
const matchLockNamespace = 2

// LockProject serializes advisory-match application for one project across
// goroutines and instances. Hold it only around short work — never across the
// advisory feed's network call. The returned func releases it.
func (r *Repository) LockProject(ctx context.Context, projectID string) (func(), error) {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1, hashtext($2))`, matchLockNamespace, projectID); err != nil {
		conn.Release()
		return nil, fmt.Errorf("match lock: %w", err)
	}
	return func() {
		// Session locks outlive the request context, so release with a fresh one.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1, hashtext($2))`, matchLockNamespace, projectID)
		conn.Release()
	}, nil
}

// CurrentSnapshots returns the ids of a project version's newest snapshot per
// artifact, sorted — what "current inventory" means right now.
func (r *Repository) CurrentSnapshots(ctx context.Context, projectID, versionID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id FROM (SELECT DISTINCT ON (artifact) id FROM sboms WHERE project_id = $1 AND version_id = $2
		                ORDER BY artifact, created_at DESC, id DESC) latest
		ORDER BY id`, projectID, versionID)
	if err != nil {
		return nil, fmt.Errorf("current snapshots: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("current snapshots: %w", err)
	}
	return ids, nil
}

// Vulnerability is one vulnerability present in a snapshot, with every
// component it affects. Key is the CVE when there is one, else the advisory or
// rule id — the same identity VulnState counts by.
type Vulnerability struct {
	Key          string              `json:"key"`
	IDs          []string            `json:"ids"`
	Severity     domain.Severity     `json:"severity"`
	Summary      string              `json:"summary"`
	FixedVersion string              `json:"fixed_version"`
	Sources      []string            `json:"sources"`  // "advisory" and/or scanner names
	Statuses     []string            `json:"statuses"` // finding statuses, when a scanner reported it
	Components   []AffectedComponent `json:"components"`
	rank         int
}

// AffectedComponent is a component a vulnerability hits.
type AffectedComponent struct {
	ID      string `json:"id"`
	BomRef  string `json:"bom_ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

// SnapshotVulnerabilities lists every vulnerability in one snapshot — advisory
// matches and scanner findings, by the VulnState rule — worst first.
func (r *Repository) SnapshotVulnerabilities(ctx context.Context, sbomID string) ([]Vulnerability, error) {
	q := `
		SELECT COALESCE((SELECT min(x) FROM unnest(v.cves) x), v.vuln_id), v.vuln_id, v.cves,
		       v.severity, ` + rankAdvisorySQL + `, v.summary, v.fixed_version, 'advisory', '',
		       c.id, c.bom_ref, c.name, c.version, c.purl
		FROM sbom_vulns v
		JOIN sbom_components c ON c.sbom_id = v.sbom_id AND ` + componentKeySQL + ` = v.purl
		WHERE v.sbom_id = $1
		UNION ALL
		SELECT COALESCE((SELECT min(x) FROM unnest(f.cve) x), NULLIF(f.rule_id, ''), f.fingerprint), f.rule_id, f.cve,
		       f.severity, ` + rankFindingSQL + `, f.title, f.fixed_version, f.scanner, f.status,
		       c.id, c.bom_ref, c.name, c.version, c.purl
		FROM sbom_components c
		JOIN findings f ON ` + findingOnComponentSQL + `
		WHERE c.sbom_id = $1`
	rows, err := r.db.Query(ctx, q, sbomID)
	if err != nil {
		return nil, fmt.Errorf("snapshot vulnerabilities: %w", err)
	}
	defer rows.Close()

	byKey := map[string]*Vulnerability{}
	for rows.Next() {
		var (
			key, id, summary, fixed, source, status string
			cves                                    []string
			sev                                     domain.Severity
			rank                                    int
			c                                       AffectedComponent
		)
		if err := rows.Scan(&key, &id, &cves, &sev, &rank, &summary, &fixed, &source, &status,
			&c.ID, &c.BomRef, &c.Name, &c.Version, &c.Purl); err != nil {
			return nil, fmt.Errorf("scan snapshot vulnerability: %w", err)
		}
		v := byKey[key]
		if v == nil {
			// Lists are always present in the JSON ([] not null) — clients iterate them.
			v = &Vulnerability{Key: key, Severity: sev, rank: rank,
				IDs: []string{}, Sources: []string{}, Statuses: []string{}, Components: []AffectedComponent{}}
			byKey[key] = v
		}
		if rank > v.rank {
			v.Severity, v.rank = sev, rank
		}
		v.Summary = cmp.Or(v.Summary, summary)
		v.FixedVersion = cmp.Or(v.FixedVersion, fixed)
		for _, x := range append([]string{id}, cves...) {
			if x != "" && !slices.Contains(v.IDs, x) {
				v.IDs = append(v.IDs, x)
			}
		}
		if !slices.Contains(v.Sources, source) {
			v.Sources = append(v.Sources, source)
		}
		if status != "" && !slices.Contains(v.Statuses, status) {
			v.Statuses = append(v.Statuses, status)
		}
		if !slices.ContainsFunc(v.Components, func(a AffectedComponent) bool { return a.ID == c.ID }) {
			v.Components = append(v.Components, c)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("snapshot vulnerabilities: %w", err)
	}

	out := make([]Vulnerability, 0, len(byKey))
	for _, v := range byKey {
		slices.Sort(v.IDs)
		slices.Sort(v.Sources)
		slices.Sort(v.Statuses)
		out = append(out, *v)
	}
	slices.SortFunc(out, func(a, b Vulnerability) int {
		return cmp.Or(cmp.Compare(b.rank, a.rank), cmp.Compare(a.Key, b.Key))
	})
	return out, nil
}

// TimelineSnapshot is one snapshot of an artifact, and whether it shipped the
// vulnerability (and in which package versions).
type TimelineSnapshot struct {
	SbomID    string    `json:"sbom_id"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Affected  bool      `json:"affected"`
	Packages  []string  `json:"packages"` // "name@version" that carried it
}

// ArtifactTimeline is one artifact's history against a vulnerability on one
// project version (a branch's or a release line's snapshots — never interleaved
// with another branch's): every snapshot in order, the snapshot that introduced
// it, the one that fixed it, and whether the newest still ships it.
type ArtifactTimeline struct {
	ProjectID         string             `json:"project_id"`
	ProjectName       string             `json:"project_name"`
	VersionID         string             `json:"version_id"`
	VersionName       string             `json:"version_name"`
	IsDefault         bool               `json:"is_default"`
	Artifact          string             `json:"artifact"`
	Snapshots         []TimelineSnapshot `json:"snapshots"`
	IntroducedIn      *TimelineSnapshot  `json:"introduced_in"`
	FixedIn           *TimelineSnapshot  `json:"fixed_in"`
	CurrentlyAffected bool               `json:"currently_affected"`
}

// VulnerabilityTimeline answers "which releases ever shipped this, and which
// introduced / fixed it?" for a CVE or advisory id, across every artifact that
// ever shipped it. projectIDs nil means every project.
func (r *Repository) VulnerabilityTimeline(ctx context.Context, vulnID string, projectIDs []string) ([]ArtifactTimeline, error) {
	q := `
		WITH hit AS (
			SELECT v.sbom_id, c.name || '@' || c.version AS pkg
			FROM sbom_vulns v
			JOIN sbom_components c ON c.sbom_id = v.sbom_id AND ` + componentKeySQL + ` = v.purl
			WHERE v.vuln_id = $1 OR $1 = ANY(v.cves)
			UNION
			SELECT c.sbom_id, c.name || '@' || c.version
			FROM findings f
			JOIN sbom_components c ON c.project_id = f.project_id
			 AND ((c.purl <> '' AND f.purl = c.purl)
			   OR (f.package_name <> '' AND lower(f.package_name) = lower(c.name) AND f.package_version = c.version))
			WHERE (f.rule_id = $1 OR $1 = ANY(f.cve))
			  AND f.status <> 'false_positive' AND f.category <> 'license' AND f.scanner <> 'policy'
			  AND` + archive.Finding("f") + `
		),
		pairs AS (
			SELECT DISTINCT s.project_id, s.version_id, s.artifact FROM hit JOIN sboms s ON s.id = hit.sbom_id
		)
		SELECT s.project_id, p.name, s.version_id, pv.name, pv.is_default, s.artifact, s.id, s.version, s.created_at,
		       COALESCE((SELECT array_agg(DISTINCT h.pkg ORDER BY h.pkg) FROM hit h WHERE h.sbom_id = s.id), '{}')
		FROM sboms s
		JOIN pairs USING (project_id, version_id, artifact)
		JOIN projects p ON p.id = s.project_id
		JOIN project_versions pv ON pv.id = s.version_id
		WHERE $2::uuid[] IS NULL OR s.project_id = ANY($2)
		ORDER BY p.name, s.project_id, pv.is_default DESC, pv.name, s.version_id, s.artifact, s.created_at, s.id`
	rows, err := r.db.Query(ctx, q, vulnID, projectIDs)
	if err != nil {
		return nil, fmt.Errorf("vulnerability timeline: %w", err)
	}
	defer rows.Close()

	var out []ArtifactTimeline
	for rows.Next() {
		var (
			t TimelineSnapshot
			a ArtifactTimeline
		)
		if err := rows.Scan(&a.ProjectID, &a.ProjectName, &a.VersionID, &a.VersionName, &a.IsDefault, &a.Artifact,
			&t.SbomID, &t.Version, &t.CreatedAt, &t.Packages); err != nil {
			return nil, fmt.Errorf("scan timeline: %w", err)
		}
		t.Affected = len(t.Packages) > 0
		if n := len(out); n == 0 || out[n-1].VersionID != a.VersionID || out[n-1].Artifact != a.Artifact {
			out = append(out, a)
		}
		out[len(out)-1].Snapshots = append(out[len(out)-1].Snapshots, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulnerability timeline: %w", err)
	}
	for i := range out {
		out[i].settle()
	}
	if out == nil {
		out = []ArtifactTimeline{}
	}
	return out, nil
}

// settle derives introduced/fixed/current from the ordered snapshots: the most
// recent transition into "affected" introduced it; the first unaffected
// snapshot after that fixed it (nil while the newest still ships it). Pure.
func (t *ArtifactTimeline) settle() {
	t.IntroducedIn, t.FixedIn = nil, nil
	for i := range t.Snapshots {
		s := &t.Snapshots[i]
		prevAffected := i > 0 && t.Snapshots[i-1].Affected
		switch {
		case s.Affected && !prevAffected:
			t.IntroducedIn, t.FixedIn = s, nil
		case !s.Affected && prevAffected:
			t.FixedIn = s
		}
	}
	if n := len(t.Snapshots); n > 0 {
		t.CurrentlyAffected = t.Snapshots[n-1].Affected
	}
}

// Previous returns the snapshot of the same project version and artifact
// uploaded just before s, if any — the default base for a diff.
func (r *Repository) Previous(ctx context.Context, s Sbom) (Sbom, bool, error) {
	prev, err := scanSbom(r.db.QueryRow(ctx, `SELECT `+sbomColumns+` FROM sboms
		WHERE version_id = $1 AND artifact = $2 AND (created_at, id) < ($3, $4)
		ORDER BY created_at DESC, id DESC LIMIT 1`, s.VersionID, s.Artifact, s.CreatedAt, s.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Sbom{}, false, nil
	}
	if err != nil {
		return Sbom{}, false, fmt.Errorf("previous sbom: %w", err)
	}
	return prev, true, nil
}

// SnapshotComponents returns every component of one snapshot with its
// vulnerability state — the full inventory a diff or graph needs, unpaginated.
func (r *Repository) SnapshotComponents(ctx context.Context, sbomID string) ([]ComponentHit, error) {
	rows, err := r.db.Query(ctx, componentColumns+componentFrom+` WHERE c.sbom_id = $1 ORDER BY c.name, c.version`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("snapshot components: %w", err)
	}
	defer rows.Close()
	out := []ComponentHit{}
	for rows.Next() {
		h, err := scanComponentHit(rows)
		if err != nil {
			return nil, fmt.Errorf("scan component: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Edges returns one snapshot's dependency edges.
func (r *Repository) Edges(ctx context.Context, sbomID string) ([]Edge, error) {
	rows, err := r.db.Query(ctx,
		`SELECT parent_ref, child_ref FROM sbom_dependencies WHERE sbom_id = $1 ORDER BY parent_ref, child_ref`, sbomID)
	if err != nil {
		return nil, fmt.Errorf("sbom edges: %w", err)
	}
	defer rows.Close()
	out := []Edge{}
	for rows.Next() {
		var e Edge
		if err := rows.Scan(&e.Parent, &e.Child); err != nil {
			return nil, fmt.Errorf("scan edge: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
