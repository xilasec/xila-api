-- Opt-in AI-assisted triage (8.21): a bring-your-own model (AI_TRIAGE_*)
-- proposes a false-positive verdict, an exploitability assessment or a fix
-- for one finding. Every request is recorded here, valid or not; a proposal
-- changes nothing until a person accepts it, and accepting applies it through
-- the normal finding mutation path (history, assessments, risk acceptances).

-- A project can keep its findings away from the model altogether.
ALTER TABLE projects ADD COLUMN ai_triage_opt_out BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE ai_proposals (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id        UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    project_id        UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK (kind IN ('false_positive', 'exploitability', 'fix')),
    provider          TEXT NOT NULL,
    model             TEXT NOT NULL,
    -- SHA-256 (hex) of exactly the prompt that was sent.
    prompt_hash       TEXT NOT NULL,
    -- The model's raw answer (untrusted; capped by the service).
    response          TEXT NOT NULL DEFAULT '',
    -- Parsed from a valid answer; empty / NULL for an invalid one.
    verdict           TEXT NOT NULL DEFAULT '',
    rationale         TEXT NOT NULL DEFAULT '',
    fix               TEXT NOT NULL DEFAULT '',
    proposed_status   TEXT CHECK (proposed_status IN ('open', 'confirmed', 'false_positive', 'risk_accepted', 'wont_fix')),
    proposed_severity TEXT CHECK (proposed_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence        DOUBLE PRECISION CHECK (confidence >= 0 AND confidence <= 1),
    state             TEXT NOT NULL DEFAULT 'proposed'
                      CHECK (state IN ('proposed', 'accepted', 'rejected', 'superseded', 'invalid')),
    invalid_reason    TEXT NOT NULL DEFAULT '',
    created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    decided_at        TIMESTAMPTZ,
    decision_note     TEXT NOT NULL DEFAULT '',
    -- What accepting did: applied | assessment_requested |
    -- risk_acceptance_requested | comment_added, and the id of the request /
    -- comment it created.
    outcome           TEXT NOT NULL DEFAULT '',
    outcome_ref       UUID,
    CHECK ((state = 'invalid') = (invalid_reason <> ''))
);
CREATE INDEX idx_ai_proposals_finding ON ai_proposals (finding_id, created_at DESC);
CREATE INDEX idx_ai_proposals_project ON ai_proposals (project_id, created_at DESC);
