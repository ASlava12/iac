-- Phase 7by: phased apply — cross-agent dependency gating.
-- See SQLite version for full description.

ALTER TABLE assignments ADD COLUMN IF NOT EXISTS layer INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS assignments_op_layer_idx
    ON assignments (operation_id, layer, status);
