-- Phase 7cg: canary rollouts.
--
-- Within a single layer (Phase 7by), assignments can now be split
-- into two batches: 0 = canary, 1 = baseline. Canary dispatches
-- immediately; baseline holds in `status = 'pending_canary'` until
-- the canary batch completes successfully across every agent it was
-- sent to. Any failure in canary cancels both the rest of canary AND
-- the baseline batch — the rollout stops at the smallest possible
-- blast radius. Composes with phased apply: layer-N+1 still waits
-- for layer-N to fully complete (canary AND baseline), so canary
-- gating runs per-layer.
--
-- `batch` is NULL on operations that didn't request canary (the
-- vast majority of pre-7cg behavior — preserved for backwards
-- compat; old operations have NULL and still flow straight from
-- pending → succeeded with no canary gating).

ALTER TABLE assignments ADD COLUMN batch INTEGER;

-- Index used by the canary-promotion path: "for this op + layer,
-- count how many batch-0 assignments are still running and how many
-- have failed." Covers the same pattern as the layer index.
CREATE INDEX IF NOT EXISTS assignments_op_layer_batch_idx
    ON assignments (operation_id, layer, batch, status);
