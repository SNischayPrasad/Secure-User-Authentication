import { getDb, isUniqueViolation } from "../db/index.js";
import { newId } from "../lib/crypto.js";
import { AppError } from "../lib/errors.js";

/**
 * User data access. Every read returns the raw row (which carries `password_hash`); only
 * `toPublicUser` is allowed to cross the wire, so a password hash can never leak into a response.
 *
 * Writes use `RETURNING *` rather than an update followed by a select. On a serverless
 * deployment every extra statement is another network round trip to the database, and the
 * two-statement form is also racy: another request could change the row in between.
 */

/** A `users` row exactly as stored. Contains `password_hash` — never serialise this directly. */
export interface UserRecord {
  id: string;
  email: string;
  email_canonical: string;
  name: string;
  password_hash: string;
  password_algo: string;
  role: "user" | "admin";
  failed_attempts: number;
  locked_until: number | null;
  password_changed_at: number;
  created_at: number;
  updated_at: number;
}

/** The only user shape ever serialised to a client: no password material, no lockout internals. */
export interface PublicUser {
  id: string;
  email: string;
  name: string;
  role: "user" | "admin";
  createdAt: number;
  passwordChangedAt: number;
}

/** Failed logins tolerated before the account locks. */
export const MAX_FAILED_ATTEMPTS = 5;

/** How long an account stays locked once the failure threshold is hit (15 minutes). */
export const LOCK_WINDOW_MS = 15 * 60_000;

const SELECT_COLUMNS = `id, email, email_canonical, name, password_hash, password_algo, role,
  failed_attempts, locked_until, password_changed_at, created_at, updated_at`;

/** Trims and lowercases an address so one human identity maps to exactly one stored account. */
export function normaliseEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

/**
 * Strips every password and lockout field from a row. The whitelist is explicit — never a
 * spread — so adding a column to the table cannot silently start leaking it.
 */
export function toPublicUser(row: UserRecord): PublicUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role === "admin" ? "admin" : "user",
    createdAt: row.created_at,
    passwordChangedAt: row.password_changed_at,
  };
}

/**
 * Looks a user up by canonical email. Callers must still return a generic error either way, so
 * this cannot be used to enumerate accounts.
 */
export async function findByEmail(email: string): Promise<UserRecord | undefined> {
  const db = await getDb();
  const { rows } = await db.query<UserRecord>(
    `SELECT ${SELECT_COLUMNS} FROM users WHERE email_canonical = $1`,
    [normaliseEmail(email)],
  );
  return rows[0];
}

/** Loads a user by id, or `undefined` if the account has since been deleted. */
export async function findById(id: string): Promise<UserRecord | undefined> {
  const db = await getDb();
  const { rows } = await db.query<UserRecord>(
    `SELECT ${SELECT_COLUMNS} FROM users WHERE id = $1`,
    [id],
  );
  return rows[0];
}

/**
 * Inserts a new user and returns the stored row.
 *
 * Uniqueness is enforced by the database and the constraint error is translated here, rather
 * than doing a check-then-insert, so two simultaneous registrations of the same address cannot
 * both win the race.
 */
export async function createUser(input: {
  name: string;
  email: string;
  passwordHash: string;
}): Promise<UserRecord> {
  const db = await getDb();
  const now = Date.now();
  const id = newId("usr");
  const canonical = normaliseEmail(input.email);

  try {
    const { rows } = await db.query<UserRecord>(
      `INSERT INTO users (
         id, email, email_canonical, name, password_hash, password_algo, role,
         failed_attempts, locked_until, password_changed_at, created_at, updated_at
       ) VALUES ($1, $2, $3, $4, $5, 'argon2id', 'user', 0, NULL, $6, $7, $8)
       RETURNING ${SELECT_COLUMNS}`,
      [id, canonical, canonical, input.name.trim(), input.passwordHash, now, now, now],
    );
    const row = rows[0];
    if (!row) throw new AppError(500, "INTERNAL_ERROR", "The account could not be created.");
    return row;
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new AppError(409, "EMAIL_TAKEN", "That email address is already registered.");
    }
    throw err;
  }
}

/** Updates the display name and returns the fresh row. */
export async function updateName(id: string, name: string): Promise<UserRecord> {
  const db = await getDb();
  const { rows } = await db.query<UserRecord>(
    `UPDATE users SET name = $1, updated_at = $2 WHERE id = $3 RETURNING ${SELECT_COLUMNS}`,
    [name.trim(), Date.now(), id],
  );
  const row = rows[0];
  if (!row) throw new AppError(404, "NOT_FOUND", "That account no longer exists.");
  return row;
}

/**
 * Stores a new password hash and stamps `password_changed_at`, which is what invalidates access
 * tokens minted before the change (authenticate compares `iat` against it).
 */
export async function updatePassword(id: string, passwordHash: string): Promise<UserRecord> {
  const db = await getDb();
  const now = Date.now();
  const { rows } = await db.query<UserRecord>(
    `UPDATE users
        SET password_hash = $1, password_algo = 'argon2id', password_changed_at = $2, updated_at = $3
      WHERE id = $4
      RETURNING ${SELECT_COLUMNS}`,
    [passwordHash, now, now, id],
  );
  const row = rows[0];
  if (!row) throw new AppError(404, "NOT_FOUND", "That account no longer exists.");
  return row;
}

/**
 * Counts one failed sign-in and locks the account for 15 minutes once the threshold is reached,
 * which caps online password guessing to a handful of tries per window.
 *
 * The increment happens in a single statement rather than read-then-write, so concurrent failed
 * attempts cannot both read the same counter and lose one of the increments.
 */
export async function registerFailedLogin(
  id: string,
): Promise<{ attempts: number; lockedUntil: number | null }> {
  const db = await getDb();
  const now = Date.now();
  const lockUntil = now + LOCK_WINDOW_MS;

  const { rows } = await db.query<{ failed_attempts: number; locked_until: number | null }>(
    `UPDATE users
        SET failed_attempts = failed_attempts + 1,
            locked_until = CASE
              WHEN failed_attempts + 1 >= $1 THEN $2
              WHEN locked_until IS NOT NULL AND locked_until > $3 THEN locked_until
              ELSE NULL
            END,
            updated_at = $3
      WHERE id = $4
      RETURNING failed_attempts, locked_until`,
    [MAX_FAILED_ATTEMPTS, lockUntil, now, id],
  );

  const row = rows[0];
  if (!row) return { attempts: 0, lockedUntil: null };
  return { attempts: row.failed_attempts, lockedUntil: row.locked_until };
}

/** Resets the failure counter and any lock after a successful sign-in. */
export async function clearLoginFailures(id: string): Promise<void> {
  const db = await getDb();
  await db.query(
    `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = $1 WHERE id = $2`,
    [Date.now(), id],
  );
}

/**
 * Reports whether the account is currently locked, with the seconds left so the route can answer
 * 423 with `retryAfterSeconds`. Pure computation over a row already in hand — no query.
 */
export function isLocked(row: UserRecord): { locked: boolean; retryAfterSeconds: number } {
  const now = Date.now();
  if (row.locked_until !== null && row.locked_until > now) {
    return {
      locked: true,
      retryAfterSeconds: Math.max(1, Math.ceil((row.locked_until - now) / 1000)),
    };
  }
  return { locked: false, retryAfterSeconds: 0 };
}
