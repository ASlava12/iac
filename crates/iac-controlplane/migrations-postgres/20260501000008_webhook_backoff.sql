-- Phase 7as: Postgres flavor. `deadline_unix` is BIGINT to match the
-- `i64` we bind from Rust (matches the existing pattern for integer
-- columns across this schema).

CREATE TABLE webhook_backoff (
    webhook_name   TEXT PRIMARY KEY,
    deadline_unix  BIGINT NOT NULL,
    updated_at     TEXT NOT NULL
);
