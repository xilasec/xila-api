-- A channel's optional CEL filter over the event (internal/expr): the channel
-- receives an event only when it holds, beside the event-type, project and
-- minimum-severity filters. '' = no filter.
ALTER TABLE notification_channels ADD COLUMN filter TEXT NOT NULL DEFAULT '';
