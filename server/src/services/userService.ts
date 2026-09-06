import type Database from "better-sqlite3";
import { db } from "../db/index.js";
import { newId } from "../lib/crypto.js";
import { AppError } from "../lib/errors.js";

/**
 * User data access. Every read returns the raw row (which carries `password_hash`); only
 * `toPublicUser` is allowed to cross the wire, so a password hash can never leak into a response.
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

const statements = new Map<string, Database.Statement<unknown[], unknown>>();

/**
 * Lazily prepares and caches a statement. Lazy because module import happens before
 * `migrate()` runs, so preparing at import time would fail with "no such table".
 */
function stmt<R = unknown>(sql: string): Database.Statement<unknown[], R> {
  const cached = statements.get(sql);
  if (cached) return cached as Database.Statement<unknown[], R>;
  const prepared = db.prepare<unknown[], R>(sql);
  statements.set(sql, prepared as Database.Statement<unknown[], unknown>);
  return prepared;
}

const SELECT_COLUMNS = `id, email, email_canonical, name, password_hash, password_algo, role,
  failed_attempts, locked_until, password_changed_at, created_at, updated_at`;

/** True when better-sqlite3 rejected a write because of a UNIQUE index (here: the email columns). */
function isUniqueViolation(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const code = (err as { code?: unknown }).code;
  return code === "SQLITE_CONSTRAINT_UNIQUE" || code === "SQLITE_CONSTRAINT";
}

/** Trims and lowercases an address so one human identity maps to exactly one stored account. */
export function normaliseEmail(raw: string): string {
  return raw.trim().toLowerCase();
}

/** Strips every password and lockout field from a row; the whitelist is explicit (never a spread) so a new column can't silently leak. */
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

/** Looks a user up by canonical email; callers must still return a generic error so this cannot be used to enumerate accounts. */
export function findByEmail(email: string): UserRecord | undefined {
  return stmt<UserRecord>(
    `SELECT ${SELECT_COLUMNS} FROM users WHERE email_canonical = ?`,
  ).get(normaliseEmail(email));
}

/** Loads a user by id, or `undefined` if the account has since been deleted. */
export function findById(id: string): UserRecord | undefined {
  return stmt<UserRecord>(`SELECT ${SELECT_COLUMNS} FROM users WHERE id = ?`).get(id);
}

/**
 * Inserts a new user and returns the stored row.
 * Uniqueness is enforced by the database and the constraint error is translated here, rather than
 * doing a check-then-insert, so two simultaneous registrations cannot both win the race.
 */
export function createUser(input: { name: string; email: string; passwordHash: string }): UserRecord {
  const now = Date.now();
  const id = newId("usr");
  const canonical = normaliseEmail(input.email);

  try {
    stmt(
      `INSERT INTO users (
         id, email, email_canonical, name, password_hash, password_algo, role,
         failed_attempts, locked_until, password_changed_at, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, 'argon2id', 'user', 0, NULL, ?, ?, ?)`,
    ).run(id, canonical, canonical, input.name.trim(), input.passwordHash, now, now, now);
  } catch (err) {
    if (isUniqueViolation(err)) {
      throw new AppError(409, "EMAIL_TAKEN", "That email address is already registered.");
    }
    throw err;
  }

  const row = findById(id);
  if (!row) throw new AppError(500, "INTERNAL_ERROR", "The account could not be created.");
  return row;
}

/** Updates the display name and returns the fresh row. */
export function updateName(id: string, name: string): UserRecord {
  const now = Date.now();
  stmt(`UPDATE users SET name = ?, updated_at = ? WHERE id = ?`).run(name.trim(), now, id);
  const row = findById(id);
  if (!row) throw new AppError(404, "NOT_FOUND", "That account no longer exists.");
  return row;
}

/**
 * Stores a new password hash and stamps `password_changed_at`, which is what invalidates access
 * tokens minted before the change (authenticate compares `iat` against it).
 */
export function updatePassword(id: string, passwordHash: string): UserRecord {
  const now = Date.now();
  stmt(
    `UPDATE users
        SET password_hash = ?, password_algo = 'argon2id', password_changed_at = ?, updated_at = ?
      WHERE id = ?`,
  ).run(passwordHash, now, now, id);
  const row = findById(id);
  if (!row) throw new AppError(404, "NOT_FOUND", "That account no longer exists.");
  return row;
}

/**
 * Counts one failed sign-in and locks the account for 15 minutes once the threshold is reached,
 * which caps online password guessing to a handful of tries per window.
 */
export function registerFailedLogin(id: string): { attempts: number; lockedUntil: number | null } {
  const now = Date.now();
  const run = db.transaction((userId: string): { attempts: number; lockedUntil: number | null } => {
    const row = findById(userId);
    if (!row) return { attempts: 0, lockedUntil: null };

    const attempts = row.failed_attempts + 1;
    const existingLock = row.locked_until !== null && row.locked_until > now ? row.locked_until : null;
    const lockedUntil = attempts >= MAX_FAILED_ATTEMPTS ? now + LOCK_WINDOW_MS : existingLock;

    stmt(
      `UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?`,
    ).run(attempts, lockedUntil, now, userId);

    return { attempts, lockedUntil };
  });
  return run(id);
}

/** Resets the failure counter and any lock after a successful sign-in. */
export function clearLoginFailures(id: string): void {
  stmt(
    `UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`,
  ).run(Date.now(), id);
}

/** Reports whether the account is currently locked, with the seconds left so the route can answer 423 with `retryAfterSeconds`. */
export function isLocked(row: UserRecord): { locked: boolean; retryAfterSeconds: number } {
  const now = Date.now();
  if (row.locked_until !== null && row.locked_until > now) {
    return { locked: true, retryAfterSeconds: Math.max(1, Math.ceil((row.locked_until - now) / 1000)) };
  }
  return { locked: false, retryAfterSeconds: 0 };
}
