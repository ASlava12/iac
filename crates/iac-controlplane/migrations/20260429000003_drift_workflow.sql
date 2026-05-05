-- Phase 4: drift workflows.
--
-- `ignored_until` lets operators silence a drift event for a TTL — it's still
-- in the table, just hidden from `GET /v1/drift` until the timestamp passes.
-- Acceptance still uses the existing `resolved_at` + `resolution` columns
-- with a prefix convention ("accepted: <reason>"), no schema change there.

ALTER TABLE drift_events ADD COLUMN ignored_until TEXT;

CREATE INDEX idx_drift_ignored
    ON drift_events(ignored_until) WHERE ignored_until IS NOT NULL;
