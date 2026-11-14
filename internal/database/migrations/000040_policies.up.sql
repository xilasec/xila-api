-- Component policies (Dependency-Track parity): admin-defined rules over SBOM
-- components — security (severity / vulnerability id / KEV / EPSS / CWE),
-- license (SPDX ids, license groups, unresolved) and operational facts
-- (outdated, versions behind, age, missing hash, coordinates, purl, type).
--
-- A policy is evaluated per component of every project version's current
-- snapshots (newest SBOM per artifact). Each violation is a finding by scanner
-- `policy` with rule_id = the policy id, applied through the normal ingest
-- pipeline, so triage, gates, SLA and alerts work unchanged and a violation that
-- stops applying auto-closes.
--
--   operator         any = one matching condition is a violation; all = every one.
--   violation_state  fail | warn | info → finding severity high | medium | low.
--   scope            global = every project; projects = only policy_projects.
--   versions         all = every version with a current snapshot; default = only
--                    the project's default version.
--   conditions       [{subject, operator, value}], validated by the API.
--
-- Written idempotently (IF NOT EXISTS / ON CONFLICT / guarded UPDATEs): the
-- policy tests re-run this file to exercise the legacy-finding migration.
CREATE TABLE IF NOT EXISTS policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    operator        TEXT NOT NULL DEFAULT 'any' CHECK (operator IN ('any', 'all')),
    violation_state TEXT NOT NULL DEFAULT 'fail' CHECK (violation_state IN ('fail', 'warn', 'info')),
    scope           TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'projects')),
    versions        TEXT NOT NULL DEFAULT 'all' CHECK (versions IN ('all', 'default')),
    conditions      JSONB NOT NULL DEFAULT '[]',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_projects (
    policy_id  UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, project_id)
);
CREATE INDEX IF NOT EXISTS idx_policy_projects_project ON policy_projects (project_id);

-- A policy's violations are looked up by (scanner, rule_id).
CREATE INDEX IF NOT EXISTS idx_findings_policy_rule ON findings (rule_id) WHERE scanner = 'policy';

-- Replace LICENSE_DENYLIST (default AGPL-3.0,GPL-2.0,GPL-3.0, matched as
-- case-insensitive substrings of the raw license string) with an equivalent
-- global policy. Semantic changes, deliberately:
--   * ids are matched against the parsed SPDX expression, by glob: LGPL-* is no
--     longer flagged as "GPL-3.0", and `MIT OR GPL-3.0-only` is compliant (the
--     MIT branch avoids the denied license); `MIT AND GPL-3.0-only` is not;
--   * a violation is per component version (purl), not per component name;
--   * violations auto-close when the component or its license leaves the
--     current SBOM; open ones are re-evaluated on every upload and schedule.
-- `warn` keeps the old findings' medium severity.
INSERT INTO policies (id, name, description, operator, violation_state, scope, versions, conditions)
VALUES (
    'c0b1ef7a-0000-4000-8000-000000000040',
    'Strong copyleft licenses',
    'Components that can only be used under the AGPL-3.0, GPL-2.0 or GPL-3.0 family. Replaces the former LICENSE_DENYLIST default.',
    'any', 'warn', 'global', 'all',
    '[{"subject": "license", "operator": "is", "value": ["AGPL-3.0*", "GPL-2.0*", "GPL-3.0*"]}]'
)
ON CONFLICT (id) DO NOTHING;

-- Carry the existing license-policy findings over to the seeded policy so their
-- triage (status, exception, history, comments) survives: same row, new scanner
-- and the fingerprint the policy engine computes —
--   sha256('policy|' || policy_id || '|' || (purl, else name@version)).
-- One row per (version, new fingerprint) can move; when the old per-name scheme
-- left several (rare: the license changed between denylist entries), the most
-- triaged / most recent wins and the rest stay as frozen `license-policy` history.
WITH legacy AS (
    SELECT f.id, f.version_id,
           encode(sha256(convert_to('policy|c0b1ef7a-0000-4000-8000-000000000040|' ||
               CASE WHEN f.purl <> '' THEN f.purl ELSE f.package_name || '@' || f.package_version END,
               'UTF8')), 'hex') AS fp,
           f.status, f.last_seen_at
    FROM findings f
    WHERE f.scanner = 'license-policy'
), ranked AS (
    SELECT l.*, row_number() OVER (
               PARTITION BY l.version_id, l.fp
               ORDER BY (l.status NOT IN ('open', 'remediated')) DESC, l.last_seen_at DESC, l.id) AS rn
    FROM legacy l
)
UPDATE findings f
SET scanner     = 'policy',
    fingerprint = r.fp,
    rule_id     = 'c0b1ef7a-0000-4000-8000-000000000040',
    metadata    = f.metadata || jsonb_build_object(
        'policy_id', 'c0b1ef7a-0000-4000-8000-000000000040',
        'policy_name', 'Strong copyleft licenses',
        'legacy_rule', f.rule_id),
    updated_at  = now()
FROM ranked r
WHERE f.id = r.id AND r.rn = 1
  AND NOT EXISTS (SELECT 1 FROM findings x WHERE x.version_id = f.version_id AND x.fingerprint = r.fp);

-- Leftover legacy rows nothing produces any more: close the untriaged ones
-- (triaged ones keep their state as history).
UPDATE findings
SET status = 'remediated', resolved_at = now(), updated_at = now()
WHERE scanner = 'license-policy' AND status IN ('open', 'confirmed');
