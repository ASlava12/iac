-- Phase 7al: Postgres flavor of the Phase 2a baseline schema.
-- Mirrors migrations/20260429000001_init.sql one-for-one. Differences:
--   * INTEGER PRIMARY KEY AUTOINCREMENT  ->  BIGSERIAL PRIMARY KEY
--   * Boolean-ish INTEGER columns stay as INTEGER so the runtime bind layer
--     (i64::from(bool)) keeps working unchanged across both dialects. We can
--     tighten to BOOLEAN in a later phase once all bind sites are audited.

CREATE TABLE agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    environment     TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    registered_at   TEXT NOT NULL,
    last_heartbeat_at      TEXT,
    last_observation_at    TEXT,
    last_status     TEXT NOT NULL DEFAULT 'healthy',
    last_managed    BIGINT NOT NULL DEFAULT 0,
    last_open_drifts BIGINT NOT NULL DEFAULT 0,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE observations (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    present         BIGINT NOT NULL,
    spec_json       TEXT NOT NULL,
    facts_json      TEXT NOT NULL,
    received_at     TEXT NOT NULL
);
CREATE INDEX idx_observations_agent_resource
    ON observations(agent_id, resource_id, observed_at DESC);

CREATE TABLE drift_events (
    id              BIGSERIAL PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    diff_json       TEXT NOT NULL,
    detected_at     TEXT NOT NULL,
    received_at     TEXT NOT NULL,
    resolved_at     TEXT,
    resolution      TEXT,
    UNIQUE (agent_id, resource_id, detected_at)
);
CREATE INDEX idx_drift_open
    ON drift_events(agent_id, resource_id) WHERE resolved_at IS NULL;

CREATE TABLE assignments (
    id              TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    operation_id    TEXT,
    payload_json    TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    fetched_at      TEXT,
    completed_at    TEXT,
    status          TEXT NOT NULL DEFAULT 'pending'
);
CREATE INDEX idx_assignments_pending
    ON assignments(agent_id, created_at) WHERE status = 'pending';
