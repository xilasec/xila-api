-- Cross-tool dedup without a CVE: a SAST/secrets/IaC finding (no CVE) now
-- groups across scanners by category + file_path + line, plus CWE when the
-- finding has one (a CWE-bearing and a CWE-less report at the same spot never
-- share a key; two CWE-less reports there still fall back to location alone).
-- finding.Repository.deduplicate computes the same key; keep them in sync.
-- Backfill the keys, then re-elect every group's primary exactly as the dedup
-- pass does: a CVE-keyed group still collapses whenever it has more than one
-- member (same scanner or not, unchanged); a location-keyed group collapses
-- only when every one of its members is from a different scanner, so two
-- rules from one tool on one line never hide each other, nor hide behind a
-- third tool's report of the same spot.
UPDATE findings SET correlation_key = CASE
        WHEN cwe IS NOT NULL
            THEN 'loc|' || category || '|' || lower(file_path) || '|' || line::text || '|' || cwe::text
        ELSE 'loc|' || category || '|' || lower(file_path) || '|' || line::text
        END
WHERE cardinality(cve) = 0 AND file_path <> '' AND line IS NOT NULL;

WITH scanner_counts AS (
    SELECT project_id, version_id, correlation_key,
        count(*) AS grp,
        count(DISTINCT scanner) AS distinct_scanners
    FROM findings
    WHERE correlation_key IS NOT NULL AND status IN ('open', 'confirmed')
      -- Archived findings (or findings of archived projects) are never elected
      -- nor anyone's duplicate, as in finding.Repository.deduplicate.
      AND archived_at IS NULL
      AND project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
    GROUP BY project_id, version_id, correlation_key
),
ranked AS (
    SELECT id,
        first_value(id) OVER (
            PARTITION BY project_id, version_id, correlation_key ORDER BY priority DESC, created_at ASC, id ASC
        ) AS primary_id
    FROM findings
    WHERE correlation_key IS NOT NULL AND status IN ('open', 'confirmed')
      -- Archived findings (or findings of archived projects) are never elected
      -- nor anyone's duplicate, as in finding.Repository.deduplicate.
      AND archived_at IS NULL
      AND project_id NOT IN (SELECT id FROM projects WHERE archived_at IS NOT NULL)
),
target AS (
    SELECT f.id, CASE
        WHEN sc.grp > 1 AND f.id <> r.primary_id
             AND (f.correlation_key NOT LIKE 'loc|%' OR sc.grp = sc.distinct_scanners)
            THEN r.primary_id
        END AS dup
    FROM findings f
    LEFT JOIN ranked r ON r.id = f.id
    LEFT JOIN scanner_counts sc ON sc.project_id = f.project_id AND sc.version_id = f.version_id AND sc.correlation_key = f.correlation_key
)
UPDATE findings f SET duplicate_of = t.dup
FROM target t
WHERE f.id = t.id AND f.duplicate_of IS DISTINCT FROM t.dup;
