-- Phase 7da.5: Merkle-chain integrity for the audit log.
--
-- Pre-7da the `audit_events` table was append-only by code, but
-- nothing prevented a compromised admin or DB-writer from running
-- `UPDATE` / `DELETE` against historical rows. With the tracking we
-- have now (RBAC, signed assignments, replay protection) the audit
-- log is the single source of truth for "who did what" — and a
-- silent post-hoc edit of those rows is the highest-leverage attack
-- a server-compromise opens up.
--
-- The chain: each new row carries `prev_hash` = sha256 of the prior
-- row's `(id, timestamp, actor, kind, severity, op, agent, resource,
-- drift, payload, prev_hash)` (canonical concatenation). Tampering
-- with any column in any row breaks the chain at that point. A
-- separate `audit_chain_tip` table holds the latest hash for fast
-- lookups (operators log it to syslog / S3 as an out-of-band trust
-- anchor; on suspicion of tampering, re-hash the chain and compare).
--
-- `prev_hash` is NULLable on the very first row only.

ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_events ADD COLUMN row_hash TEXT;

-- Materialised tip pointer. Always exactly one row (id=1) — UPSERTed
-- on every audit insert. Operators read this via
-- `GET /v1/audit/chain-tip`. Storing it as a row (vs deriving on
-- read) lets operators wire the value to a tamper-evident log
-- without re-walking N rows on every probe.
CREATE TABLE audit_chain_tip (
    id          INTEGER PRIMARY KEY,
    last_id     INTEGER NOT NULL DEFAULT 0,
    last_hash   TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL
);
INSERT INTO audit_chain_tip (id, last_id, last_hash, updated_at)
VALUES (1, 0, '', '1970-01-01T00:00:00Z');
