import { db } from "./index.js";

/**
 * The authoritative schema DDL, embedded as a string on purpose.
 *
 * `tsc` compiles the TypeScript sources into `dist/` and does NOT copy `.sql` files, so
 * reading `db/schema.sql` from disk at runtime would work under `tsx` in
 * development and then crash a production `node dist/index.js` boot. Keeping the
 * DDL in the module means the compiled output is self-contained.
 *
 * `db/schema.sql` holds an identical copy purely as human-readable documentation —
 * change both in the same commit.
 *
 * Every statement is `IF NOT EXISTS`, so applying it repeatedly is a no-op.
 */
export const SCHEMA_SQL = `
-- users --------------------------------------------------------------------
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
  locked_until        INTEGER,
  password_changed_at INTEGER NOT NULL,
  created_at          INTEGER NOT NULL,
  updated_at          INTEGER NOT NULL
);

-- sessions (one row per refresh-token family member) ------------------------
CREATE TABLE IF NOT EXISTS sessions (
  id             TEXT    PRIMARY KEY,
  user_id        TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id      TEXT    NOT NULL,
  token_hash     TEXT    NOT NULL UNIQUE,
  user_agent     TEXT,
  ip_address     TEXT,
  created_at     INTEGER NOT NULL,
  last_used_at   INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  revoked_at     INTEGER,
  revoked_reason TEXT,
  replaced_by    TEXT
);

-- auth_events (append-only audit log; no FK so it outlives the user row) ----
CREATE TABLE IF NOT EXISTS auth_events (
  id              TEXT    PRIMARY KEY,
  user_id         TEXT,
  email_attempted TEXT,
  type            TEXT    NOT NULL,
  outcome         TEXT    NOT NULL
                          CHECK (outcome IN ('success', 'failure')),
  detail          TEXT,
  ip_address      TEXT,
  user_agent      TEXT,
  created_at      INTEGER NOT NULL
);

-- vault_items (the protected resource) -------------------------------------
CREATE TABLE IF NOT EXISTS vault_items (
  id         TEXT    PRIMARY KEY,
  user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title      TEXT    NOT NULL,
  body       TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- indexes -------------------------------------------------------------------
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
`;

/**
 * Applies the schema. Idempotent, and wrapped in a transaction so a half-created
 * schema can never be left behind if one statement fails. Call once at boot,
 * before the server accepts any request.
 */
export function migrate(): void {
  const apply = db.transaction((): void => {
    db.exec(SCHEMA_SQL);
  });
  apply();
}
