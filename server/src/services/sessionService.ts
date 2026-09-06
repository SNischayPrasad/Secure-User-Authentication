import type { Request } from "express";
import { env } from "../config/env.js";
import { getDb } from "../db/index.js";
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

const SELECT_COLUMNS = `id, user_id, family_id, token_hash, user_agent, ip_address,
  created_at, last_used_at, expires_at, revoked_at, revoked_reason, replaced_by`;

/**
 * The insert hands the stored row straight back with `RETURNING`, so creating a session costs one
 * round trip instead of an insert followed by a select — and the row returned is unambiguously
 * the one just written, even if another request touches the table immediately afterwards.
 */
const INSERT_SESSION = `INSERT INTO sessions (
    id, user_id, family_id, token_hash, user_agent, ip_address,
    created_at, last_used_at, expires_at
  ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
  RETURNING ${SELECT_COLUMNS}`;

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

/** Guards the row an insert returns: no row back means the session was never stored. */
function requireStored(row: SessionRecord | undefined): SessionRecord {
  if (!row) throw new AppError(500, "INTERNAL_ERROR", "The session could not be created.");
  return row;
}

/** Loads a session by id — used by `authenticate` to confirm the `sid` in an access token is still live. */
export async function findById(id: string): Promise<SessionRecord | undefined> {
  const db = await getDb();
  const { rows } = await db.query<SessionRecord>(
    `SELECT ${SELECT_COLUMNS} FROM sessions WHERE id = $1`,
    [id],
  );
  return rows[0];
}

/**
 * Issues a new session and its opaque refresh token. The raw token is returned here and nowhere
 * else; only its sha256 is written, so the stored row cannot be turned back into a credential.
 * Omit `familyId` to start a new rotation family (a fresh login).
 */
export async function createSession(input: {
  userId: string;
  familyId?: string;
  req?: Request;
}): Promise<{ session: SessionRecord; refreshToken: string }> {
  const db = await getDb();
  const now = Date.now();
  const id = newId("ses");
  const familyId = input.familyId ?? newId("fam");
  const refreshToken = randomToken(32);
  const expiresAt = now + env.refreshTokenTtlSeconds * 1000;

  const { rows } = await db.query<SessionRecord>(INSERT_SESSION, [
    id,
    input.userId,
    familyId,
    sha256(refreshToken),
    userAgentOf(input.req),
    ipOf(input.req),
    now,
    now,
    expiresAt,
  ]);

  return { session: requireStored(rows[0]), refreshToken };
}

/**
 * Finds the session a raw refresh token belongs to by digest, never by comparing raw values.
 * Revoked and expired rows are returned deliberately: the refresh route must be able to tell
 * "unknown token" from "already-rotated token" to detect reuse.
 */
export async function findByToken(rawToken: string): Promise<SessionRecord | undefined> {
  if (!rawToken) return undefined;
  const db = await getDb();
  const { rows } = await db.query<SessionRecord>(
    `SELECT ${SELECT_COLUMNS} FROM sessions WHERE token_hash = $1`,
    [sha256(rawToken)],
  );
  return rows[0];
}

/**
 * Rotates a session: creates its successor in the same family and revokes the presented row with
 * reason `rotated`, both in one transaction so a crash can never leave two live tokens in a family.
 * Throws 401 `SESSION_INVALID` if the row was concurrently revoked, which rolls the successor back.
 */
export async function rotate(
  current: SessionRecord,
  req?: Request,
): Promise<{ session: SessionRecord; refreshToken: string }> {
  const db = await getDb();
  const now = Date.now();
  const nextId = newId("ses");
  const refreshToken = randomToken(32);
  const expiresAt = now + env.refreshTokenTtlSeconds * 1000;

  const session = await db.transaction(async (tx) => {
    const revoked = await tx.query(
      `UPDATE sessions
          SET revoked_at = $1, revoked_reason = 'rotated', replaced_by = $2, last_used_at = $3
        WHERE id = $4 AND revoked_at IS NULL`,
      [now, nextId, now, current.id],
    );

    // Retiring the predecessor is what decides the race: `revoked_at IS NULL` lets exactly one of
    // two concurrent refreshes match the row, so the loser updates nothing, is rejected here, and
    // never walks away with a second live token in the family.
    if (revoked.rowCount === 0) {
      throw new AppError(401, "SESSION_INVALID", "Your session has ended. Sign in again.");
    }

    const { rows } = await tx.query<SessionRecord>(INSERT_SESSION, [
      nextId,
      current.user_id,
      current.family_id,
      sha256(refreshToken),
      userAgentOf(req),
      ipOf(req),
      now,
      now,
      expiresAt,
    ]);

    return requireStored(rows[0]);
  });

  return { session, refreshToken };
}

/**
 * Revokes every still-active member of a rotation family and returns how many were closed.
 * This is the reuse-detection hammer: one replayed token invalidates the whole chain.
 * Already-revoked rows keep their original reason so the audit trail stays truthful.
 */
export async function revokeFamily(familyId: string, reason: string): Promise<number> {
  const db = await getDb();
  const info = await db.query(
    `UPDATE sessions
        SET revoked_at = $1, revoked_reason = $2
      WHERE family_id = $3 AND revoked_at IS NULL`,
    [Date.now(), reason, familyId],
  );
  return info.rowCount;
}

/** Revokes a single session; already-revoked rows are left untouched so the first reason survives. */
export async function revokeSession(id: string, reason: string): Promise<void> {
  const db = await getDb();
  await db.query(
    `UPDATE sessions SET revoked_at = $1, revoked_reason = $2 WHERE id = $3 AND revoked_at IS NULL`,
    [Date.now(), reason, id],
  );
}

/**
 * Revokes all of a user's live sessions and returns the count. `exceptSessionId` keeps one alive,
 * which is how a password change signs out every other device without signing out the one in use.
 */
export async function revokeAllForUser(
  userId: string,
  reason: string,
  exceptSessionId?: string,
): Promise<number> {
  const db = await getDb();
  const keep = exceptSessionId ?? null;
  // `$4` carries the "keep this one" id and is cast explicitly: a placeholder that appears only
  // inside `IS NULL` gives Postgres nothing to infer a type from. One placeholder serves both
  // halves of the guard, exactly as the two `?` bound the same value before.
  const info = await db.query(
    `UPDATE sessions
        SET revoked_at = $1, revoked_reason = $2
      WHERE user_id = $3 AND revoked_at IS NULL AND ($4::text IS NULL OR id <> $4)`,
    [Date.now(), reason, userId, keep],
  );
  return info.rowCount;
}

/** Lists the user's live sessions, newest activity first, for the "where you are signed in" view. */
export async function listActiveForUser(userId: string): Promise<SessionRecord[]> {
  const db = await getDb();
  const { rows } = await db.query<SessionRecord>(
    `SELECT ${SELECT_COLUMNS}
       FROM sessions
      WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2
      ORDER BY last_used_at DESC`,
    [userId, Date.now()],
  );
  return rows;
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
export async function touch(id: string): Promise<void> {
  const db = await getDb();
  await db.query(`UPDATE sessions SET last_used_at = $1 WHERE id = $2`, [Date.now(), id]);
}
