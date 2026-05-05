-- Phase 7al: Postgres flavor of the Phase 6d approval-gate migration.
-- Identical SQL — INTEGER for the bool-ish requires_approval keeps the
-- bind layer (i64::from(bool)) working unchanged across dialects.

ALTER TABLE operations ADD COLUMN requires_approval BIGINT NOT NULL DEFAULT 0;
ALTER TABLE operations ADD COLUMN approved_by TEXT;
ALTER TABLE operations ADD COLUMN approved_at TEXT;
ALTER TABLE operations ADD COLUMN rejected_by TEXT;
ALTER TABLE operations ADD COLUMN rejected_at TEXT;
ALTER TABLE operations ADD COLUMN rejection_reason TEXT;
ALTER TABLE operations ADD COLUMN approval_reason TEXT;
ALTER TABLE operations ADD COLUMN matched_policies_json TEXT NOT NULL DEFAULT '[]';

CREATE INDEX idx_operations_pending_approval
    ON operations(status) WHERE status = 'pending_approval';
