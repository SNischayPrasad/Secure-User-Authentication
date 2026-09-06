import type Database from "better-sqlite3";
import type { Request } from "express";
import { env } from "../config/env.js";
import { db } from "../db/index.js";
import { AppError } from "../lib/errors.js";
import { newId, randomToken, sha256 } from "../lib/crypto.js";

/**
 * Refresh-token session store (CONTRACT section 6).
 *
 * A session row is one member of a rotation *family*. The raw refresh token is returned to the
 * caller exactly once and only its sha256 is persisted, so a database leak cannot be replayed as
 * a login. Every refresh mints a successor and revokes its predecessor; presenting a revoked
 * member again is token reuse and burns the whole family.
 */

/**
 * The `sessions` row shape is defined once, in types.ts, and re-exported here so callers can
 * import it from the service they are already using. Two independent definitions had drifted
 * on `revoked_reason`, which is exactly the kind of divergence a single source of truth avoids.
 */
export type { SessionRecord } from "../types.js";

/** The session shape returned by `GET /api/v1/me/sessions` — no token material of any kind. */
export interface PublicSession {
  id: string;
  current: boolean;
  userAgent: string | null;
  ipAddress: string | null;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
}

/** The audit reasons a session may carry once revoked. */
export type { SessionRevokedReason as SessionRevokeReason } from "../types.js";

import type { SessionRecord } from "../types.js";

const MAX_USER_AGENT_CHARS = 255;

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

const SELECT_COLUMNS = `id, user_id, family_id, token_hash, user_agent, ip_address,
  created_at, last_used_at, expires_at, revoked_at, revoked_reason, replaced_by`;

const INSERT_SESSION = `INSERT INTO sessions (
    id, user_id, family_id, token_hash, user_agent, ip_address,
    created_at, last_used_at, expires_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`;

/** Client user agent, length-capped so a hostile header cannot bloat the row. */
function userAgentOf(req?: Request): string | null {
  const raw = req?.get("user-agent");
  if (!raw) return null;
  return raw.slice(0, MAX_USER_AGENT_CHARS);
}

/** Client IP as Express resolved it (honouring `trust proxy`). */
function ipOf(req?: Request): string | null {
  const raw = req?.ip;
  return raw ? raw.slice(0, 64) : null;
}

function requireById(id: string): SessionRecord {
  const row = findById(id);
  if (!row) throw new AppError(500, "INTERNAL_ERROR", "The session could not be created.");
  return row;
}

/** Loads a session by id — used by `authenticate` to confirm the `sid` in an access token is still live. */
export function findById(id: string): SessionRecord | undefined {
  return stmt<SessionRecord>(`SELECT ${SELECT_COLUMNS} FROM sessions WHERE id = ?`).get(id);
}

/**
 * Issues a new session and its opaque refresh token. The raw token is returned here and nowhere
 * else; only its sha256 is written, so the stored row cannot be turned back into a credential.
 * Omit `familyId` to start a new rotation family (a fresh login).
 */
export function createSession(input: {
  userId: string;
  familyId?: string;
  req?: Request;
}): { session: SessionRecord; refreshToken: string } {
  const now = Date.now();
  const id = newId("ses");
  const familyId = input.familyId ?? newId("fam");
  const refreshToken = randomToken(32);
  const expiresAt = now + env.refreshTokenTtlSeconds * 1000;

  stmt(INSERT_SESSION).run(
    id,
    input.userId,
    familyId,
    sha256(refreshToken),
    userAgentOf(input.req),
    ipOf(input.req),
    now,
    now,
    expiresAt,
  );

  return { session: requireById(id), refreshToken };
}

/**
 * Finds the session a raw refresh token belongs to by digest, never by comparing raw values.
 * Revoked and expired rows are returned deliberately: the refresh route must be able to tell
 * "unknown token" from "already-rotated token" to detect reuse.
 */
export function findByToken(rawToken: string): SessionRecord | undefined {
  if (!rawToken) return undefined;
  return stmt<SessionRecord>(
    `SELECT ${SELECT_COLUMNS} FROM sessions WHERE token_hash = ?`,
  ).get(sha256(rawToken));
}

/**
 * Rotates a session: creates its successor in the same family and revokes the presented row with
 * reason `rotated`, both in one transaction so a crash can never leave two live tokens in a family.
 * Throws 401 `SESSION_INVALID` if the row was concurrently revoked, which rolls the successor back.
 */
export function rotate(
  current: SessionRecord,
  req?: Request,
): { session: SessionRecord; refreshToken: string } {
  const now = Date.now();
  const nextId = newId("ses");
  const refreshToken = randomToken(32);
  const expiresAt = now + env.refreshTokenTtlSeconds * 1000;

  const run = db.transaction((): void => {
    const revoked = stmt(
      `UPDATE sessions
          SET revoked_at = ?, revoked_reason = 'rotated', replaced_by = ?, last_used_at = ?
        WHERE id = ? AND revoked_at IS NULL`,
    ).run(now, nextId, now, current.id);

    if (revoked.changes === 0) {
      throw new AppError(401, "SESSION_INVALID", "Your session has ended. Sign in again.");
    }

    stmt(INSERT_SESSION).run(
      nextId,
      current.user_id,
      current.family_id,
      sha256(refreshToken),
      userAgentOf(req),
      ipOf(req),
      now,
      now,
      expiresAt,
    );
  });
  run();

  return { session: requireById(nextId), refreshToken };
}

/**
 * Revokes every still-active member of a rotation family and returns how many were closed.
 * This is the reuse-detection hammer: one replayed token invalidates the whole chain.
 * Already-revoked rows keep their original reason so the audit trail stays truthful.
 */
export function revokeFamily(familyId: string, reason: string): number {
  const info = stmt(
    `UPDATE sessions
        SET revoked_at = ?, revoked_reason = ?
      WHERE family_id = ? AND revoked_at IS NULL`,
  ).run(Date.now(), reason, familyId);
  return info.changes;
}

/** Revokes a single session; already-revoked rows are left untouched so the first reason survives. */
export function revokeSession(id: string, reason: string): void {
  stmt(
    `UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE id = ? AND revoked_at IS NULL`,
  ).run(Date.now(), reason, id);
}

/**
 * Revokes all of a user's live sessions and returns the count. `exceptSessionId` keeps one alive,
 * which is how a password change signs out every other device without signing out the one in use.
 */
export function revokeAllForUser(userId: string, reason: string, exceptSessionId?: string): number {
  const keep = exceptSessionId ?? null;
  const info = stmt(
    `UPDATE sessions
        SET revoked_at = ?, revoked_reason = ?
      WHERE user_id = ? AND revoked_at IS NULL AND (? IS NULL OR id <> ?)`,
  ).run(Date.now(), reason, userId, keep, keep);
  return info.changes;
}

/** Lists the user's live sessions, newest activity first, for the "where you are signed in" view. */
export function listActiveForUser(userId: string): SessionRecord[] {
  return stmt<SessionRecord>(
    `SELECT ${SELECT_COLUMNS}
       FROM sessions
      WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
      ORDER BY last_used_at DESC`,
  ).all(userId, Date.now());
}

/** True only while a session is neither revoked nor expired — the single definition of "still signed in". */
export function isActive(s: SessionRecord, now: number = Date.now()): boolean {
  return s.revoked_at === null && s.expires_at > now;
}

/** Maps a row to the client shape, flagging the caller's own session and exposing no token digest. */
export function toPublicSession(s: SessionRecord, currentSessionId: string): PublicSession {
  return {
    id: s.id,
    current: s.id === currentSessionId,
    userAgent: s.user_agent,
    ipAddress: s.ip_address,
    createdAt: s.created_at,
    lastUsedAt: s.last_used_at,
    expiresAt: s.expires_at,
  };
}

/** Records activity on a session so the sessions list shows real last-seen times. */
export function touch(id: string): void {
  stmt(`UPDATE sessions SET last_used_at = ? WHERE id = ?`).run(Date.now(), id);
}
