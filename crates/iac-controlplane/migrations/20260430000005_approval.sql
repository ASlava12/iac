-- Phase 6d: approval gate.
--
-- An operation that matches a configured policy with `requires_approval=true`
-- enters status `pending_approval`. Assignments are NOT created until an
-- approver calls POST /v1/operations/{id}/approve. Rejecting transitions the
-- operation to `rejected` (terminal).

ALTER TABLE operations ADD COLUMN requires_approval INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operations ADD COLUMN approved_by TEXT;
ALTER TABLE operations ADD COLUMN approved_at TEXT;
ALTER TABLE operations ADD COLUMN rejected_by TEXT;
ALTER TABLE operations ADD COLUMN rejected_at TEXT;
ALTER TABLE operations ADD COLUMN rejection_reason TEXT;
ALTER TABLE operations ADD COLUMN approval_reason TEXT;
ALTER TABLE operations ADD COLUMN matched_policies_json TEXT NOT NULL DEFAULT '[]';

CREATE INDEX idx_operations_pending_approval
    ON operations(status) WHERE status = 'pending_approval';
