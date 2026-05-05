-- Phase 7al: Postgres flavor of the Phase 6c audit-log migration.
-- Differences:
--   * audit_events.id  INTEGER PRIMARY KEY AUTOINCREMENT  ->  BIGSERIAL
--   * audit_events.drift_id stays as INTEGER. drift_events.id is BIGSERIAL
--     (BIGINT) — narrowing the FK-ish reference to INTEGER risks overflow
--     after ~2^31 drift rows, but matching the existing on-the-wire shape
--     (we serialize as i64) is more important. Promote to BIGINT once a
--     real-fleet trial gets within striking distance of 2^31 drift rows;
--     the audit-bind machinery can absorb the dialect divergence at the
--     wire layer when that happens.

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
