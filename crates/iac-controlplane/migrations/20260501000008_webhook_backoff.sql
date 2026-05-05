-- Phase 7as: persist receiver-requested backoff deadlines so a server
-- restart during an active 429 cool-down doesn't immediately re-fire
-- the same misbehaving receiver.
--
-- One row per webhook name. `deadline_unix` is the absolute Unix
-- timestamp (seconds) past which the dispatcher resumes that receiver.
-- Expired rows are harmless and get overwritten on the next 429 — no
-- separate prune loop needed.

CREATE TABLE webhook_backoff (
    webhook_name   TEXT PRIMARY KEY,
    deadline_unix  INTEGER NOT NULL,
    updated_at     TEXT NOT NULL
);
