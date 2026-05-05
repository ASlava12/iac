-- Phase 7cg: canary rollouts. See SQLite migration for description.

ALTER TABLE assignments ADD COLUMN IF NOT EXISTS batch INTEGER;

CREATE INDEX IF NOT EXISTS assignments_op_layer_batch_idx
    ON assignments (operation_id, layer, batch, status);
