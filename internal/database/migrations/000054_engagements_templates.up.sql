-- DefectDojo-style engagements: a time-boxed piece of security work on a
-- project (a pentest, an audit, a CI/CD pipeline) that scans and manual
-- findings are filed under. A scan in an engagement is DefectDojo's "test".
CREATE TABLE engagements (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name        text NOT NULL CHECK (name <> ''),
    kind        text NOT NULL DEFAULT 'interactive' CHECK (kind IN ('interactive', 'ci_cd')),
    status      text NOT NULL DEFAULT 'in_progress' CHECK (status IN ('not_started', 'in_progress', 'on_hold', 'completed', 'cancelled')),
    description text NOT NULL DEFAULT '',
    lead_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    starts_on   date,
    ends_on     date,
    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT engagements_dates CHECK (ends_on IS NULL OR starts_on IS NULL OR ends_on >= starts_on),
    -- Target of the scans FK: a scan can only join an engagement of its own project.
    CONSTRAINT engagements_id_project UNIQUE (id, project_id)
);
CREATE INDEX engagements_project ON engagements (project_id, created_at DESC);

ALTER TABLE scans ADD COLUMN engagement_id uuid;
ALTER TABLE scans ADD CONSTRAINT scans_engagement_fk FOREIGN KEY (engagement_id, project_id)
    REFERENCES engagements (id, project_id) ON DELETE SET NULL (engagement_id);
CREATE INDEX scans_engagement ON scans (engagement_id) WHERE engagement_id IS NOT NULL;

-- Reusable write-ups for manual findings (a pentest team's standard issues).
CREATE TABLE finding_templates (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title       text NOT NULL CHECK (title <> ''),
    severity    text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category    text NOT NULL DEFAULT 'dast',
    cwe         int,
    cve         text[] NOT NULL DEFAULT '{}',
    description text NOT NULL DEFAULT '',
    mitigation  text NOT NULL DEFAULT '',
    impact      text NOT NULL DEFAULT '',
    refs        text[] NOT NULL DEFAULT '{}',
    tags        text[] NOT NULL DEFAULT '{}',
    created_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT finding_templates_title UNIQUE (title)
);
