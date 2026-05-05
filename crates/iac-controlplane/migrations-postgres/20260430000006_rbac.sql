-- Phase 7al: Postgres flavor of the Phase 6e RBAC migration.
-- Identical SQL — no autoincrement IDs in this set (users.id is a TEXT ULID,
-- user_tokens uses token_hash as PK), so no dialect-specific changes.

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    roles_json      TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    disabled_at     TEXT
);

CREATE INDEX idx_users_disabled
    ON users(disabled_at) WHERE disabled_at IS NOT NULL;

CREATE TABLE user_tokens (
    token_hash      TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

CREATE INDEX idx_user_tokens_user
    ON user_tokens(user_id);
