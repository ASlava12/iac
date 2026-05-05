-- Phase 7by: phased apply — cross-agent dependency gating.
--
-- Resources can declare `metadata.dependsOn` (Phase 7g). Until now the
-- topo sort only ordered intra-agent dispatch; cross-agent dependents
-- shipped to all agents in parallel and could begin applying before
-- their dependencies finished elsewhere. Phase 7by introduces a
-- `layer` column: BFS depth from no-deps roots. Layer-0 assignments
-- ship immediately; layer-N (N>0) assignments hold in
-- `status='pending_layer'` until ALL layer-(N-1) assignments succeed
-- across every agent. A failure in any layer cancels all subsequent
-- pending_layer assignments — the rollout stops on the first failure
-- instead of cascading damage to dependents.
--
-- Backwards compat: existing operations have layer=0 by default, so
-- they keep flat-dispatch semantics. Operations submitted on/after the
-- migration get phased dispatch automatically when dependsOn graphs
-- exceed one layer.

ALTER TABLE assignments ADD COLUMN layer INTEGER NOT NULL DEFAULT 0;

-- Index by (operation_id, layer) so the phased-apply progression
-- query (find min pending_layer per op + check completion of
-- layer below) hits an index. Covers the common pattern:
-- "given this op, what's the next layer to promote?".
CREATE INDEX IF NOT EXISTS assignments_op_layer_idx
    ON assignments (operation_id, layer, status);
