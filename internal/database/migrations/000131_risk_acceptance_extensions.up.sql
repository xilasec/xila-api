-- Extending an approved risk acceptance: the expiry of an approved acceptance
-- changes only through an extension, with a reason. A project owner's
-- extension applies at once (unless four-eyes needs a second person); anyone
-- else's waits for an owner while the acceptance stays active on its current
-- expiry. At most one pending extension per acceptance.
CREATE TABLE risk_acceptance_extensions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    acceptance_id   UUID NOT NULL REFERENCES risk_acceptances(id) ON DELETE CASCADE,
    reason          TEXT NOT NULL,
    from_expires_at TIMESTAMPTZ NOT NULL,
    to_expires_at   TIMESTAMPTZ NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected', 'withdrawn')),
    requested_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    requester       TEXT NOT NULL DEFAULT '',
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    decider         TEXT NOT NULL DEFAULT '',
    decided_at      TIMESTAMPTZ,
    decision_note   TEXT NOT NULL DEFAULT '',
    CHECK (to_expires_at > from_expires_at)
);
CREATE INDEX idx_risk_acceptance_extensions_acceptance ON risk_acceptance_extensions (acceptance_id, requested_at);
CREATE UNIQUE INDEX idx_risk_acceptance_extensions_pending ON risk_acceptance_extensions (acceptance_id) WHERE state = 'pending';
