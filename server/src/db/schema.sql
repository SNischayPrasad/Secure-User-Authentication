-- =============================================================================
-- Secure User Authentication — database schema (DOCUMENTATION COPY)
-- =============================================================================
--
-- IMPORTANT: this file is NOT read at runtime.
--
-- `tsc` compiles src/**/*.ts into dist/ and does not copy .sql assets, so a
-- runtime `fs.readFileSync` of this path would work under `tsx` in development
-- and then fail in a production `node dist/index.js` boot. To keep development
-- and production identical, the authoritative DDL lives as the exported
-- `SCHEMA_SQL` template literal in `src/db/migrate.ts`.
--
-- This file exists purely as human-readable documentation and MUST be kept
-- byte-for-byte identical to `SCHEMA_SQL` in migrate.ts. If you change one,
-- change the other in the same commit.
--
-- Every statement is idempotent (`IF NOT EXISTS`) so `migrate()` can run on
-- every boot without guards or a migration-version table.
--
-- All timestamps are INTEGER epoch milliseconds (Date.now()).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- users
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id                  TEXT    PRIMARY KEY,                     -- "usr_" + 21 char random id
  email               TEXT    NOT NULL UNIQUE,                 -- normalised: trimmed + lowercased
  email_canonical     TEXT    NOT NULL UNIQUE,                 -- same value as email; explicit lookup key
  name                TEXT    NOT NULL,
  password_hash       TEXT    NOT NULL,                        -- argon2id encoded string; NEVER selected into a response
  password_algo       TEXT    NOT NULL DEFAULT 'argon2id',     -- lets us rehash on algorithm upgrade
  role                TEXT    NOT NULL DEFAULT 'user'
                              CHECK (role IN ('user', 'admin')),
  failed_attempts     INTEGER NOT NULL DEFAULT 0,              -- consecutive bad passwords; reset on success
  locked_until        INTEGER,                                 -- epoch ms; NULL when not locked
  password_changed_at INTEGER NOT NULL,                        -- access tokens minted before this are rejected
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);

-- -----------------------------------------------------------------------------
-- sessions — one row per refresh-token family member
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id             TEXT    PRIMARY KEY,                          -- "ses_" + id; this is the JWT `sid` claim
  user_id        TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id      TEXT    NOT NULL,                             -- rotation family; reuse detection revokes the family
  token_hash     TEXT    NOT NULL UNIQUE,                      -- sha256 hex of the opaque refresh token; raw token never stored
  user_agent     TEXT,
  ip_address     TEXT,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER,                                      -- NULL while active
  revoked_reason TEXT,                                         -- 'logout' | 'logout_all' | 'rotated' | 'reuse_detected' | 'revoked_by_user' | 'password_changed'
  replaced_by    TEXT                                          -- session id that superseded this one on rotation
);

-- -----------------------------------------------------------------------------
-- auth_events — append-only audit log
--
-- Deliberately has NO foreign key on user_id: the audit trail must outlive the
-- user row (and must accept failed logins for e-mail addresses that never
-- existed), so it is never cascaded away.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_events (
  id              TEXT    PRIMARY KEY,
  user_id         TEXT,                                        -- nullable: failed login for an unknown email
  email_attempted TEXT,
  type            TEXT    NOT NULL,                            -- register | login | logout | logout_all | token_refresh |
                                                               -- token_reuse_detected | password_change | profile_update |
                                                               -- session_revoked | account_locked | rate_limited
  outcome         TEXT    NOT NULL
                          CHECK (outcome IN ('success', 'failure')),
  detail          TEXT,
  ip_address      TEXT,
  user_agent      TEXT,
  created_at      INTEGER NOT NULL
);

-- -----------------------------------------------------------------------------
-- vault_items — the protected resource showcased in the UI
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_items (
  id         TEXT    PRIMARY KEY,                              -- "itm_" + 21 char random id
  user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL,
  body       TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- -----------------------------------------------------------------------------
-- Indexes
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_sessions_user_id
  ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_family_id
  ON sessions (family_id);

-- Redundant alongside the UNIQUE constraint on token_hash, but named explicitly
-- because refresh lookup by token hash is the hottest path in the auth flow.
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash
  ON sessions (token_hash);

CREATE INDEX IF NOT EXISTS idx_auth_events_user_id_created_at
  ON auth_events (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vault_items_user_id_updated_at
  ON vault_items (user_id, updated_at DESC);
