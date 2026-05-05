-- Phase 7ck: SSH push deployment. See SQLite migration for description.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'pull';

CREATE INDEX IF NOT EXISTS agents_kind_env_idx
    ON agents (kind, environment);
