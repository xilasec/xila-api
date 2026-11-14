-- Compliance frameworks (CIS, SOC2, OWASP...) and their controls, plus a mapping
-- from scanner signals to controls. A control "fails" when an open finding maps
-- to it; compliance score = passing / total controls.
CREATE TABLE IF NOT EXISTS frameworks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key         TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS controls (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES frameworks(id) ON DELETE CASCADE,
    code         TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    UNIQUE (framework_id, code)
);

-- A control is satisfied/violated based on matching findings. A mapping matches
-- either by CWE (tool-agnostic) or by a specific scanner rule (e.g. Prowler CIS).
CREATE TABLE IF NOT EXISTS control_mappings (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    match_type TEXT NOT NULL CHECK (match_type IN ('cwe', 'rule')),
    scanner    TEXT,
    rule_id    TEXT,
    cwe        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_control_mappings_cwe ON control_mappings (cwe) WHERE match_type = 'cwe';
CREATE INDEX IF NOT EXISTS idx_control_mappings_rule ON control_mappings (scanner, rule_id) WHERE match_type = 'rule';

-- Seed OWASP Top 10 (2021), mapped by CWE so it works with any scanner that
-- emits CWEs (Semgrep, Trivy, ...).
INSERT INTO frameworks (key, name, version, description)
VALUES ('owasp-top-10-2021', 'OWASP Top 10', '2021', 'OWASP Top 10 web application security risks, mapped by CWE.');

INSERT INTO controls (framework_id, code, title)
SELECT fw.id, v.code, v.title
FROM frameworks fw
CROSS JOIN (VALUES
    ('A01', 'Broken Access Control'),
    ('A02', 'Cryptographic Failures'),
    ('A03', 'Injection'),
    ('A04', 'Insecure Design'),
    ('A05', 'Security Misconfiguration'),
    ('A06', 'Vulnerable and Outdated Components'),
    ('A07', 'Identification and Authentication Failures'),
    ('A08', 'Software and Data Integrity Failures'),
    ('A09', 'Security Logging and Monitoring Failures'),
    ('A10', 'Server-Side Request Forgery')
) AS v(code, title)
WHERE fw.key = 'owasp-top-10-2021';

INSERT INTO control_mappings (control_id, match_type, cwe)
SELECT c.id, 'cwe', v.cwe
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'owasp-top-10-2021'
JOIN (VALUES
    ('A01', 22), ('A01', 284), ('A01', 639), ('A01', 862), ('A01', 863),
    ('A02', 259), ('A02', 327), ('A02', 331),
    ('A03', 79), ('A03', 89), ('A03', 78), ('A03', 94), ('A03', 77),
    ('A04', 209), ('A04', 501), ('A04', 256),
    ('A05', 16), ('A05', 611), ('A05', 1032),
    ('A06', 1104), ('A06', 937),
    ('A07', 287), ('A07', 384), ('A07', 297),
    ('A08', 502), ('A08', 829), ('A08', 494),
    ('A09', 778), ('A09', 117), ('A09', 223),
    ('A10', 918)
) AS v(code, cwe) ON v.code = c.code;
