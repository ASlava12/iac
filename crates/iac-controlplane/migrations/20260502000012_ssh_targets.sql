-- Phase 7ck: SSH push deployment.
--
-- Some hosts can't run a long-running agent — embedded network gear,
-- vendor appliances, contractor environments where security policy
-- bans daemons. The control plane reaches these via SSH push: pop
-- assignment, ssh + pipe payload, capture result.
--
-- Design choice: rather than introduce a new table, mark the existing
-- agents row with `kind = 'ssh'`. SSH targets behave like agents for
-- the dispatch model (host_selector routing, layered apply, canary,
-- audit log) — only difference is who initiates: pull-agents poll,
-- SSH targets are pushed by a server-side worker.
--
-- `kind = 'pull'` is the default (existing behavior). Bootstrap rows
-- get the default; the upgrade is fully backwards compatible.

ALTER TABLE agents ADD COLUMN kind TEXT NOT NULL DEFAULT 'pull';

-- Index lookup-by-kind for the SSH worker pool's queue scan: it asks
-- "which assignments are pending for kind=ssh agents in this env?"
-- on every poll cycle. Without the index, we'd table-scan agents.
CREATE INDEX IF NOT EXISTS agents_kind_env_idx
    ON agents (kind, environment);
