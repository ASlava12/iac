-- Phase 7v: persistent cursor for the webhook dispatcher.
--
-- Single-row table tracking the highest audit_events.id we've already
-- considered for fan-out. On restart the dispatcher reads this row
-- and resumes from there, so events written between the last tick
-- and a server crash still get delivered (instead of being skipped
-- by the in-memory cursor's MAX(id) initializer).
--
-- The `key` column is a stable opaque tag (always 'audit') — we keep
-- it as a column rather than baking the constraint in so future
-- bucket types can share the same table.

CREATE TABLE webhook_cursor (
    key            TEXT PRIMARY KEY,
    last_seen_id   INTEGER NOT NULL,
    updated_at     TEXT NOT NULL
);
