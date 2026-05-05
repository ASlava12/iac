-- Phase 7al: Postgres flavor of the Phase 2b assignments migration.
-- Differences from the SQLite version:
--   * desired_states.id  INTEGER PRIMARY KEY AUTOINCREMENT  ->  BIGSERIAL
--   * Multiple ALTER TABLE … ADD COLUMN statements work in Postgres but
--     each takes its own AccessExclusive lock; that's fine for a fresh
--     install, the existing assignments table is empty.

CREATE TABLE operations (
    id              TEXT PRIMARY KEY,
    kind            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    requested_by    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    source_commit   TEXT,
    summary         TEXT,
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    finished_at     TEXT
);
CREATE INDEX idx_operations_env_created
    ON operations(environment, created_at DESC);

CREATE TABLE desired_states (
    id              BIGSERIAL PRIMARY KEY,
    operation_id    TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    spec_json       TEXT NOT NULL,
    metadata_json   TEXT NOT NULL,
    UNIQUE (operation_id, resource_id)
);
CREATE INDEX idx_desired_resource
    ON desired_states(resource_id);

ALTER TABLE assignments ADD COLUMN kind TEXT NOT NULL DEFAULT 'apply';
ALTER TABLE assignments ADD COLUMN result_json TEXT;
ALTER TABLE assignments ADD COLUMN expires_at TEXT;
