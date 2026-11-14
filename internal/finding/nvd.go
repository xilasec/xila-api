package finding

import (
	"context"
	"fmt"
	"time"
)

// CVSSRecord is one CVE's CVSS metric as NVD publishes it (cached in nvd_cves).
type CVSSRecord struct {
	CVE          string
	Score        *float64 // nil: NVD knows the CVE but has no v3.x/v4.0 metric yet
	Vector       string
	Version      string // "3.1", "3.0", "4.0"
	LastModified *time.Time
}

// StaleNVDCVEs lists the CVE ids carried by findings whose NVD data is not
// cached yet, or older than refresh (refreshPending for CVEs NVD hadn't scored
// yet — they get metrics once analyzed). Uncached ids come first.
func (r *Repository) StaleNVDCVEs(ctx context.Context, refresh, refreshPending time.Duration, limit int) ([]string, error) {
	const q = `
		SELECT c.cve_id
		FROM (SELECT DISTINCT unnest(cve) AS cve_id FROM findings WHERE cardinality(cve) > 0) c
		LEFT JOIN nvd_cves n ON n.cve_id = c.cve_id
		WHERE c.cve_id LIKE 'CVE-%'
		  AND (n.cve_id IS NULL
		       OR n.fetched_at < now() - $1::interval
		       OR (n.cvss_score IS NULL AND n.fetched_at < now() - $2::interval))
		ORDER BY n.fetched_at NULLS FIRST, c.cve_id
		LIMIT $3`
	rows, err := r.db.Query(ctx, q, refresh, refreshPending, limit)
	if err != nil {
		return nil, fmt.Errorf("stale nvd cves: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// SaveNVD caches NVD's answers. Ids in asked that NVD didn't return are cached
// without a score, so they're retried on the pending window, not every run.
func (r *Repository) SaveNVD(ctx context.Context, asked []string, found []CVSSRecord) error {
	ids := make([]string, 0, len(found))
	scores := make([]*float64, 0, len(found))
	vectors := make([]string, 0, len(found))
	versions := make([]string, 0, len(found))
	modified := make([]*time.Time, 0, len(found))
	for _, f := range found {
		ids = append(ids, f.CVE)
		scores = append(scores, f.Score)
		vectors = append(vectors, f.Vector)
		versions = append(versions, f.Version)
		modified = append(modified, f.LastModified)
	}
	const upsert = `
		INSERT INTO nvd_cves (cve_id, cvss_score, cvss_vector, cvss_version, last_modified, fetched_at)
		SELECT id, score, NULLIF(vector, ''), NULLIF(version, ''), modified, now()
		FROM unnest($1::text[], $2::real[], $3::text[], $4::text[], $5::timestamptz[])
		     AS t(id, score, vector, version, modified)
		ON CONFLICT (cve_id) DO UPDATE SET cvss_score = EXCLUDED.cvss_score,
			cvss_vector = EXCLUDED.cvss_vector, cvss_version = EXCLUDED.cvss_version,
			last_modified = EXCLUDED.last_modified, fetched_at = now()`
	if _, err := r.db.Exec(ctx, upsert, ids, scores, vectors, versions, modified); err != nil {
		return fmt.Errorf("save nvd cves: %w", err)
	}
	// Asked but unknown to NVD (reserved / not yet received): remember we asked.
	const unknown = `
		INSERT INTO nvd_cves (cve_id, fetched_at)
		SELECT id, now() FROM unnest($1::text[]) AS id WHERE NOT (id = ANY($2::text[]))
		ON CONFLICT (cve_id) DO UPDATE SET fetched_at = now()
		WHERE nvd_cves.cvss_score IS NULL`
	if len(asked) > 0 {
		if _, err := r.db.Exec(ctx, unknown, asked, ids); err != nil {
			return fmt.Errorf("save unknown nvd cves: %w", err)
		}
	}
	return nil
}

// ApplyNVD stamps cached NVD CVSS onto findings (one scan's when scanID is
// set). A finding with several CVEs takes the highest-scoring one. The vector
// and version are NVD's; `cvss` takes NVD's score only when the scanner gave
// none — a scanner-provided score is never overwritten (cvss_source stays NULL
// for it, "nvd" marks a filled one). Rows that would not change are skipped.
func (r *Repository) ApplyNVD(ctx context.Context, scanID *string) (int, error) {
	const q = `
		WITH best AS (
			SELECT f.id, n.cvss_score, n.cvss_vector, n.cvss_version
			FROM findings f
			CROSS JOIN LATERAL (
				SELECT n.cvss_score, n.cvss_vector, n.cvss_version FROM nvd_cves n
				WHERE n.cve_id = ANY(f.cve) AND n.cvss_score IS NOT NULL
				ORDER BY n.cvss_score DESC, n.cve_id LIMIT 1
			) n
			WHERE cardinality(f.cve) > 0 AND ($1::uuid IS NULL OR f.last_scan_id = $1)
		), next AS (
			SELECT f.id, b.cvss_vector, b.cvss_version,
				CASE WHEN f.cvss IS NULL OR f.cvss_source = 'nvd' THEN b.cvss_score ELSE f.cvss END AS cvss,
				CASE WHEN f.cvss IS NULL OR f.cvss_source = 'nvd' THEN 'nvd' END AS cvss_source
			FROM findings f JOIN best b ON b.id = f.id
		)
		UPDATE findings f SET cvss_vector = n.cvss_vector, cvss_version = n.cvss_version,
			cvss = n.cvss, cvss_source = n.cvss_source, updated_at = now()
		FROM next n
		WHERE f.id = n.id AND (f.cvss_vector IS DISTINCT FROM n.cvss_vector
			OR f.cvss_version IS DISTINCT FROM n.cvss_version
			OR f.cvss IS DISTINCT FROM n.cvss OR f.cvss_source IS DISTINCT FROM n.cvss_source)`
	tag, err := r.db.Exec(ctx, q, scanID)
	if err != nil {
		return 0, fmt.Errorf("apply nvd cvss: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
