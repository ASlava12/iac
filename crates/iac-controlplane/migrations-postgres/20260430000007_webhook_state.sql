-- Phase 7al: Postgres flavor of the Phase 7v webhook-cursor migration.
-- Differences:
--   * last_seen_id is BIGINT in Postgres (matches audit_events.id BIGSERIAL).
--     SQLite is dynamically typed, so its INTEGER works for both.

CREATE TABLE webhook_cursor (
    key            TEXT PRIMARY KEY,
    last_seen_id   BIGINT NOT NULL,
    updated_at     TEXT NOT NULL
);
