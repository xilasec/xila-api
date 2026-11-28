-- Malicious packages (OSV MAL- advisories): a finding flag set by every
-- upsert (finding.isMalicious), which also raises the severity to critical.
-- It is a priority input (the exploitability ceiling, never discounted for
-- reachability) and fails the gate unless the policy sets allow_malicious.
ALTER TABLE findings ADD COLUMN malicious BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gate_policies ADD COLUMN allow_malicious BOOLEAN NOT NULL DEFAULT false;

-- Findings stored before this: the same rule as isMalicious. Their priority is
-- recomputed by the next pass that reprioritizes them (the next scan or
-- advisory match of the project).
UPDATE findings f SET
    malicious = true,
    severity  = CASE WHEN f.severity_manual THEN f.severity ELSE 'critical' END
WHERE f.rule_id ILIKE 'MAL-%'
   OR EXISTS (SELECT 1 FROM unnest(f.cve) c WHERE c ILIKE 'MAL-%')
   OR (jsonb_typeof(f.metadata->'aliases') = 'array'
       AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(f.metadata->'aliases') a WHERE a ILIKE 'MAL-%'));

CREATE INDEX idx_findings_malicious ON findings (project_id) WHERE malicious;
