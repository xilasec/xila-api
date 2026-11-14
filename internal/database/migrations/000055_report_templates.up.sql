-- Report templates: branding and the section layout of the printable HTML
-- reports (internal/report). A pentest deliverable, an executive summary and a
-- compliance pack are different templates over the same data.
CREATE TABLE report_templates (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL CHECK (name <> ''),
    brand          text NOT NULL DEFAULT '',
    classification text NOT NULL DEFAULT '',
    intro          text NOT NULL DEFAULT '',
    footer         text NOT NULL DEFAULT '',
    accent_color   text NOT NULL DEFAULT '' CHECK (accent_color = '' OR accent_color ~ '^#[0-9a-fA-F]{6}$'),
    logo           text NOT NULL DEFAULT '' CHECK (length(logo) <= 300000),
    sections       text[] NOT NULL,
    min_severity   text NOT NULL DEFAULT 'info' CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    max_findings   int NOT NULL DEFAULT 20 CHECK (max_findings BETWEEN 1 AND 500),
    created_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT report_templates_name UNIQUE (name)
);
