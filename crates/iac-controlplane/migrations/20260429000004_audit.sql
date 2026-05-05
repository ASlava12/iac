-- Phase 6c: audit log.
--
-- Append-only record of every operationally-significant event the server
-- handles. Operators query this to answer "who changed X / when / why".
-- Phase 6d will make actor a real named identity once RBAC lands. For now
-- actor is a coarse string ("admin", "agent:<id>", "system").

CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    actor           TEXT NOT NULL,
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    operation_id    TEXT,
    agent_id        TEXT,
    resource_id     TEXT,
    drift_id        INTEGER,
    payload_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_kind ON audit_events(kind, timestamp DESC);
CREATE INDEX idx_audit_op
    ON audit_events(operation_id) WHERE operation_id IS NOT NULL;
CREATE INDEX idx_audit_agent
    ON audit_events(agent_id) WHERE agent_id IS NOT NULL;
