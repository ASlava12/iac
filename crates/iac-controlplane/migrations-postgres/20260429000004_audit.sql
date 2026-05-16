-- Phase 7al: Postgres flavor of the Phase 6c audit-log migration.
-- Differences:
--   * audit_events.id  INTEGER PRIMARY KEY AUTOINCREMENT  ->  BIGSERIAL
--   * audit_events.drift_id  is BIGINT to match drift_events.id (BIGSERIAL).
--     The original Phase 7al note flagged INTEGER as a 2^31 overflow risk
--     for a "real-fleet trial within striking distance of 2^31 drift rows";
--     by Phase 9-F1 the wire-side i64 serialization had already locked
--     BIGINT in as the right shape on both engines, so we just promoted
--     it ahead of schedule (no schema migration needed — this is the
--     initial-creation migration; existing deployments still use SQLite
--     which has unified INTEGER regardless).

CREATE TABLE audit_events (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TEXT NOT NULL,
    actor           TEXT NOT NULL,
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    operation_id    TEXT,
    agent_id        TEXT,
    resource_id     TEXT,
    drift_id        BIGINT,
    payload_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_kind ON audit_events(kind, timestamp DESC);
CREATE INDEX idx_audit_op
    ON audit_events(operation_id) WHERE operation_id IS NOT NULL;
CREATE INDEX idx_audit_agent
    ON audit_events(agent_id) WHERE agent_id IS NOT NULL;
