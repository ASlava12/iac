-- Phase 2b: pull-mode assignments.
--
-- An `operations` row represents one request from a CLI/operator: "make this
-- environment look like these resources". The server fans the request out
-- into per-agent `assignments`. Agents poll, apply, and post results back.
--
-- Apply planning stays on the agent side (it's idempotent and has the freshest
-- observation). The server is a router + audit log.

CREATE TABLE operations (
    id              TEXT PRIMARY KEY,                      -- ULID
    kind            TEXT NOT NULL,                         -- e.g. 'apply'
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
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id    TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL,                         -- 'kind/env/name'
    kind            TEXT NOT NULL,
    environment     TEXT NOT NULL,
    spec_json       TEXT NOT NULL,
    metadata_json   TEXT NOT NULL,
    UNIQUE (operation_id, resource_id)
);
CREATE INDEX idx_desired_resource
    ON desired_states(resource_id);

-- Phase 2a created `assignments` with the columns we need, but missing
-- `kind` / `result_json`. Add them.
ALTER TABLE assignments ADD COLUMN kind TEXT NOT NULL DEFAULT 'apply';
ALTER TABLE assignments ADD COLUMN result_json TEXT;
ALTER TABLE assignments ADD COLUMN expires_at TEXT;
