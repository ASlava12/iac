-- Phase 7da.5: Merkle-chain integrity for the audit log. See the
-- sqlite migration for the design discussion.

ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN row_hash TEXT;

CREATE TABLE audit_chain_tip (
    id          INTEGER PRIMARY KEY,
    last_id     BIGINT NOT NULL DEFAULT 0,
    last_hash   TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);
INSERT INTO audit_chain_tip (id, last_id, last_hash, updated_at)
VALUES (1, 0, '', '1970-01-01T00:00:00Z');
