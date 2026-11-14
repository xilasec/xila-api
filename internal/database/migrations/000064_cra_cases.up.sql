-- EU Cyber Resilience Act, Article 14 (internal/cra): a project marked as a
-- product with digital elements made available on the EU market must report
-- every actively exploited vulnerability it becomes aware of — an early
-- warning within 24 h, a vulnerability notification within 72 h and a final
-- report within 14 days of a corrective or mitigating measure being available.
ALTER TABLE projects
    ADD COLUMN cra_in_scope        boolean NOT NULL DEFAULT false,
    ADD COLUMN cra_product_name    text    NOT NULL DEFAULT '',
    ADD COLUMN cra_product_version text    NOT NULL DEFAULT '',
    -- ISO 3166-1 alpha-2 codes of the Member States the product is made
    -- available in (Art. 14(2)(a)).
    ADD COLUMN cra_member_states   text[]  NOT NULL DEFAULT '{}';

-- One reporting case per (project, vulnerability). Deadlines are absolute
-- (hours, never calendar days) and fixed from the awareness time.
CREATE TABLE cra_cases (
    id                       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id               uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    finding_id               uuid REFERENCES findings (id) ON DELETE SET NULL,
    vuln_id                  text NOT NULL,
    title                    text NOT NULL DEFAULT '',
    severity                 text NOT NULL DEFAULT '',
    trigger                  text NOT NULL CHECK (trigger IN ('kev', 'weaponized', 'manual')),
    state                    text NOT NULL DEFAULT 'open' CHECK (state IN
        ('open', 'early_warning_sent', 'notification_sent', 'final_report_sent', 'closed', 'dismissed')),
    aware_at                 timestamptz NOT NULL,
    early_warning_due_at     timestamptz NOT NULL,
    notification_due_at      timestamptz NOT NULL,
    corrective_available_at  timestamptz,
    final_report_due_at      timestamptz,
    early_warning_sent_at    timestamptz,
    notification_sent_at     timestamptz,
    final_report_sent_at     timestamptz,
    closed_at                timestamptz,
    dismissed_reason         text NOT NULL DEFAULT '',
    -- Report content the manufacturer fills in (Art. 14(2)(b)/(c)).
    exploitation             text NOT NULL DEFAULT '',
    corrective_measures      text NOT NULL DEFAULT '',
    user_mitigations         text NOT NULL DEFAULT '',
    impact                   text NOT NULL DEFAULT '',
    malicious_actor          text NOT NULL DEFAULT '',
    sensitivity              text NOT NULL DEFAULT '' CHECK (sensitivity IN
        ('', 'TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')),
    -- Stages already alerted as due soon / missed (each alerted once).
    alerted_due_soon         text[] NOT NULL DEFAULT '{}',
    alerted_missed           text[] NOT NULL DEFAULT '{}',
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, vuln_id)
);
CREATE INDEX cra_cases_active ON cra_cases (state) WHERE state NOT IN ('closed', 'dismissed');
CREATE INDEX cra_cases_finding ON cra_cases (finding_id);

-- The case history: opening, each submission (with the payload as sent),
-- dismissal and closure, with who did it.
CREATE TABLE cra_case_events (
    id          bigserial PRIMARY KEY,
    case_id     uuid NOT NULL REFERENCES cra_cases (id) ON DELETE CASCADE,
    from_state  text NOT NULL DEFAULT '',
    to_state    text NOT NULL,
    stage       text NOT NULL DEFAULT '' CHECK (stage IN ('', 'early_warning', 'notification', 'final')),
    payload     jsonb,
    reference   text NOT NULL DEFAULT '',
    note        text NOT NULL DEFAULT '',
    actor_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    actor_email text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cra_case_events_case ON cra_case_events (case_id, id);
