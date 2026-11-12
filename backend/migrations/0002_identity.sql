-- Phase 2 / 0002: users, roles, permissions, refresh sessions.

CREATE TABLE roles (
    id          SMALLINT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE CHECK (name IN ('ADMIN', 'ANALYST', 'VIEWER')),
    description TEXT NOT NULL
);

CREATE TABLE permissions (
    id          SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE CHECK (code ~ '^[a-z_]+:[a-z_]+$'),
    description TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role_id       SMALLINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id SMALLINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username              TEXT NOT NULL CHECK (char_length(username) BETWEEN 3 AND 64),
    email                 TEXT CHECK (email IS NULL OR char_length(email) <= 254),
    password_hash         TEXT NOT NULL,                 -- Argon2id PHC string only
    role_id               SMALLINT NOT NULL REFERENCES roles(id),
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password  BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_count    INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    password_changed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_password_is_argon2id CHECK (password_hash LIKE '$argon2id$%')
);
CREATE UNIQUE INDEX users_username_lower_uq ON users (lower(username));
CREATE UNIQUE INDEX users_email_lower_uq    ON users (lower(email)) WHERE email IS NOT NULL;
CREATE INDEX users_role_idx ON users (role_id);
CREATE TRIGGER users_set_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Refresh sessions. Only the SHA-256 digest of the opaque token is stored.
-- A rotation chain shares one family_id; presenting a revoked token whose
-- family is still live signals reuse and the whole family is revoked.
CREATE TABLE refresh_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id           UUID NOT NULL,
    token_hash          BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    replaced_by         UUID REFERENCES refresh_sessions(id) ON DELETE SET NULL,
    user_agent          TEXT,
    ip_address          INET,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoked_reason      TEXT CHECK (revoked_reason IN ('rotated', 'logout', 'logout_all', 'reuse_detected', 'password_change', 'admin_reset', 'expired')),
    CONSTRAINT refresh_sessions_expiry_after_creation CHECK (expires_at > created_at)
);
CREATE INDEX refresh_sessions_user_idx    ON refresh_sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX refresh_sessions_family_idx  ON refresh_sessions (family_id);
CREATE INDEX refresh_sessions_expires_idx ON refresh_sessions (expires_at);
