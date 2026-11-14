-- Open ingestion-health anomalies, so the leader's sweep alerts once when one
-- appears (and again only after it cleared and came back), not every hour.
CREATE TABLE ingestion_anomalies (
    key         text PRIMARY KEY,           -- kind + stream identity
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind        text NOT NULL,
    detail      text NOT NULL DEFAULT '',
    detected_at timestamptz NOT NULL DEFAULT now()
);
