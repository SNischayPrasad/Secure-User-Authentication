-- =============================================================================
-- Secure User Authentication — database schema (DOCUMENTATION COPY)
-- =============================================================================
--
-- GENERATED FILE. Do not edit by hand.
--
-- The authoritative DDL is the exported `SCHEMA_SQL` string in src/db/migrate.ts.
-- tsc does not copy .sql assets into dist/, so a runtime read of this path would
-- work under tsx and then fail on a production boot. Regenerate with:
--
--     npm run schema:dump --workspace server
--
-- Dialect: PostgreSQL — Neon in production, PGlite (in-process) in development
-- and tests, so the SQL that ships is the SQL the tests ran.
--
-- All timestamps are BIGINT epoch milliseconds. BIGINT, not INTEGER: Date.now()
-- is ~1.79e12 and a Postgres INTEGER tops out at 2.15e9.
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
  id                  TEXT    PRIMARY KEY,
  email               TEXT    NOT NULL UNIQUE,
  email_canonical     TEXT    NOT NULL UNIQUE,
  name                TEXT    NOT NULL,
  password_hash       TEXT    NOT NULL,
  password_algo       TEXT    NOT NULL DEFAULT 'argon2id',
  role                TEXT    NOT NULL DEFAULT 'user'
                              CHECK (role IN ('user', 'admin')),
  failed_attempts     INTEGER NOT NULL DEFAULT 0,
  locked_until        BIGINT,
  password_changed_at BIGINT  NOT NULL,
  created_at          BIGINT  NOT NULL,
  updated_at          BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id             TEXT   PRIMARY KEY,
  user_id        TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id      TEXT   NOT NULL,
  token_hash     TEXT   NOT NULL UNIQUE,
  user_agent     TEXT,
  ip_address     TEXT,
  created_at     BIGINT NOT NULL,
  last_used_at   BIGINT NOT NULL,
  expires_at     BIGINT NOT NULL,
  revoked_at     BIGINT,
  revoked_reason TEXT,
  replaced_by    TEXT
);

CREATE TABLE IF NOT EXISTS auth_events (
  id              TEXT   PRIMARY KEY,
  user_id         TEXT,
  email_attempted TEXT,
  type            TEXT   NOT NULL,
  outcome         TEXT   NOT NULL CHECK (outcome IN ('success', 'failure')),
  detail          TEXT,
  ip_address      TEXT,
  user_agent      TEXT,
  created_at      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_items (
  id         TEXT   PRIMARY KEY,
  user_id    TEXT   NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT   NOT NULL,
  body       TEXT   NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
  ON sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_sessions_family_id
  ON sessions (family_id);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash
  ON sessions (token_hash);

CREATE INDEX IF NOT EXISTS idx_auth_events_user_id_created_at
  ON auth_events (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_vault_items_user_id_updated_at
  ON vault_items (user_id, updated_at DESC);
