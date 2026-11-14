-- Cross-tool dedup grouped a CVE finding without a package by the CVE alone,
-- so the same CVE on two hosts (OpenVAS, Nessus, nuclei, nmap) collapsed into
-- one visible finding. The key now carries the finding's location
-- (file_path, which network / DAST parsers fill with host:port or the URL);
-- finding.Repository.deduplicate computes it the same way. Backfill the keys,
-- then re-elect every group's primary exactly as the dedup pass does.
UPDATE findings SET correlation_key = lower((SELECT min(c) FROM unnest(cve) c)) || '@' || lower(file_path)
WHERE cardinality(cve) > 0 AND package_name = '' AND file_path <> '';

WITH ranked AS (
    SELECT id,
        first_value(id) OVER (
            PARTITION BY project_id, version_id, correlation_key ORDER BY priority DESC, created_at ASC, id ASC
        ) AS primary_id,
        count(*) OVER (PARTITION BY project_id, version_id, correlation_key) AS grp
    FROM findings
    WHERE correlation_key IS NOT NULL AND status IN ('open', 'confirmed')
),
target AS (
    SELECT f.id, CASE WHEN r.grp > 1 AND f.id <> r.primary_id THEN r.primary_id END AS dup
    FROM findings f LEFT JOIN ranked r ON r.id = f.id
)
UPDATE findings f SET duplicate_of = t.dup
FROM target t
WHERE f.id = t.id AND f.duplicate_of IS DISTINCT FROM t.dup;
