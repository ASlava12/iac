-- Phase 7al: Postgres flavor of the Phase 4 drift-workflow migration.
-- Identical to the SQLite version — partial indexes work in both dialects.

ALTER TABLE drift_events ADD COLUMN ignored_until TEXT;

CREATE INDEX idx_drift_ignored
    ON drift_events(ignored_until) WHERE ignored_until IS NOT NULL;
