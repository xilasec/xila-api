-- No-code parsers (M12 12.4, DefectDojo Pro "Universal Parser" parity): an
-- instance admin maps the fields of any CSV, JSON or XML report onto findings
-- from the UI. `name` is the scanner identifier used in uploads
-- (?scanner=<name>); the application enforces it doesn't collide with a
-- built-in parser's name (the registry is static Go code, not visible to
-- Postgres). `fields` is a JSON object of ParsedFinding field -> mapping
-- (record path/column, static value, template, or a severity value map); see
-- internal/scanner.CustomDefinition / CustomFieldMap.
CREATE TABLE IF NOT EXISTS custom_parsers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    category        TEXT NOT NULL,
    format          TEXT NOT NULL CHECK (format IN ('csv', 'json', 'xml')),
    record_selector TEXT NOT NULL DEFAULT '',
    fields          JSONB NOT NULL DEFAULT '{}',
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
