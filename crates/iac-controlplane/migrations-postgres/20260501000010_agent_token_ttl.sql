-- Phase 7cc: agent token TTL + explicit rotation. See SQLite migration
-- for description.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS token_expires_at TEXT;
