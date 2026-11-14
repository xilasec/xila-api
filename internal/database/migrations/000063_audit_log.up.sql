-- Instance audit log: one row per mutating API request and per sign-in event.
-- Append-only: rows are never updated, and deleted only by the retention purge
-- (audit_log_purge), which is the only path the trigger lets through.
--
-- No foreign keys on purpose: the log outlives the users, tokens and projects it
-- names (a deleted project's history is exactly what an auditor asks about), and
-- actor_email keeps the name readable after the user is gone.
CREATE TABLE audit_log (
    id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_kind     TEXT NOT NULL CHECK (actor_kind IN ('user', 'service_account', 'api_token', 'system', 'anonymous')),
    actor_user_id  UUID,
    actor_token_id UUID,
    actor_email    TEXT NOT NULL DEFAULT '',
    action         TEXT NOT NULL,
    resource_type  TEXT NOT NULL DEFAULT '',
    resource_id    TEXT NOT NULL DEFAULT '',
    project_id     UUID,
    team_id        UUID,
    org_id         UUID,
    method         TEXT NOT NULL DEFAULT '',
    path           TEXT NOT NULL DEFAULT '',
    client_ip      TEXT NOT NULL DEFAULT '',
    status         INT NOT NULL DEFAULT 0,
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    request_id     TEXT NOT NULL DEFAULT '',
    changes        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_log_created_idx ON audit_log (created_at DESC, id DESC);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_user_id, created_at DESC);
CREATE INDEX audit_log_project_idx ON audit_log (project_id, created_at DESC);
CREATE INDEX audit_log_resource_idx ON audit_log (resource_type, resource_id);

-- The retention purge announces its cutoff in a transaction-local setting; a
-- DELETE is allowed only for rows older than it. Nothing may UPDATE a row.
CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    cutoff TEXT := current_setting('xila.audit_purge_before', true);
BEGIN
    IF TG_OP = 'DELETE' AND cutoff IS NOT NULL AND cutoff <> '' AND OLD.created_at < cutoff::timestamptz THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only (% refused)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- audit_log_purge deletes entries older than cutoff and records that it did, as
-- a system entry. The retention job's only way to delete audit rows.
CREATE FUNCTION audit_log_purge(cutoff TIMESTAMPTZ) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE
    n BIGINT;
BEGIN
    PERFORM set_config('xila.audit_purge_before', cutoff::text, true);
    DELETE FROM audit_log WHERE created_at < cutoff;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('xila.audit_purge_before', '', true);
    IF n > 0 THEN
        INSERT INTO audit_log (actor_kind, action, resource_type, outcome, changes)
        VALUES ('system', 'audit.purge', 'audit_log', 'success',
                jsonb_build_object('deleted', n, 'before', cutoff));
    END IF;
    RETURN n;
END $$;
