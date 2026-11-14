-- Personal notifications (8.15): people subscribe themselves — no admin — to
-- events on findings assigned to them and on projects they watch, by email
-- (their account address, resolved at send time) or a personal Slack / Teams
-- webhook (sealed with secretbox: url_enc, AAD = the channel id; write-only).
-- A personal channel is an ordinary channel row owned by its user, so it goes
-- through the same outbox, retries and delivery log; admin channel lists and
-- the normal routing ignore it.
ALTER TABLE notification_channels
    ADD COLUMN owner_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    ADD COLUMN url_enc BYTEA;
CREATE UNIQUE INDEX uq_notification_channels_personal
    ON notification_channels (owner_user_id, type) WHERE owner_user_id IS NOT NULL;

CREATE TABLE user_notification_prefs (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    on_assigned BOOLEAN NOT NULL DEFAULT true,  -- findings assigned to me
    on_watched  BOOLEAN NOT NULL DEFAULT true,  -- events on projects I watch
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_watches (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, project_id)
);
CREATE INDEX idx_project_watches_project ON project_watches (project_id);
