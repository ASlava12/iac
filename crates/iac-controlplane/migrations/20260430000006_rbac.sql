-- Phase 6e: role-based access control.
--
-- `users` are human operators. Each carries a list of roles serialized as
-- JSON. `user_tokens` is the issued-token table -- analogous to the agent
-- token mechanism, but tied to a user_id and with an explicit expiry.

CREATE TABLE users (
    id              TEXT PRIMARY KEY,                    -- ULID
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,                       -- Argon2id PHC string
    roles_json      TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL,
    disabled_at     TEXT
);

CREATE INDEX idx_users_disabled
    ON users(disabled_at) WHERE disabled_at IS NOT NULL;

CREATE TABLE user_tokens (
    token_hash      TEXT PRIMARY KEY,                    -- hex(sha256(token))
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at       TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);

CREATE INDEX idx_user_tokens_user
    ON user_tokens(user_id);
