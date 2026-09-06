import { getDb } from "./index.js";

/**
 * The authoritative DDL.
 *
 * It lives here as a string rather than being read from schema.sql at runtime, because `tsc`
 * compiles src/**\/*.ts into dist/ without copying .sql assets — a `readFileSync` would work
 * under tsx in development and then fail on a production boot. `server/src/db/schema.sql` is
 * kept byte-for-byte identical purely as readable documentation.
 *
 * Every statement is idempotent, so migrate() can run on every boot without a version table.
 * That matters more on Vercel than it did locally: any cold-started instance may be the first
 * one to touch a fresh database.
 *
 * All timestamps are BIGINT epoch milliseconds. BIGINT rather than INTEGER is not cosmetic —
 * Date.now() is about 1.79e12, which overflows Postgres INTEGER at 2.15e9.
 */
export const SCHEMA_SQL = `
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
`;

let applied: Promise<void> | null = null;

/**
 * Applies the schema exactly once per process.
 *
 * The cached promise matters on serverless: several requests can hit a cold instance at once,
 * and without it each would run the DDL concurrently. `CREATE TABLE IF NOT EXISTS` is not
 * immune to that — two concurrent creations of the same table race in Postgres and one raises
 * a duplicate-object error.
 */
export function migrate(): Promise<void> {
  if (!applied) {
    applied = (async () => {
      const db = await getDb();
      await db.exec(SCHEMA_SQL);
    })().catch((error: unknown) => {
      // Let the next caller retry rather than caching a permanent failure.
      applied = null;
      throw error;
    });
  }
  return applied;
}
