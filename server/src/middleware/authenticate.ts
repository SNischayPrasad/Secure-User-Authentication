import type Database from "better-sqlite3";
import type { RequestHandler } from "express";

import { db } from "../db/index.js";
import { unauthorized } from "../lib/errors.js";
import type { AccessClaims } from "../lib/tokens.js";
import { verifyAccessToken } from "../lib/tokens.js";
import { toPublicUser } from "../services/userService.js";
import type { UserRecord } from "../types.js";

/** The columns of `sessions` that access-token validation needs. */
type SessionAuthRow = {
  id: string;
  user_id: string;
  revoked_at: number | null;
  expires_at: number;
};

let userByIdStmt: Database.Statement<[string], UserRecord> | undefined;
let sessionByIdStmt: Database.Statement<[string], SessionAuthRow> | undefined;

/**
 * Lazily compiles the user lookup. Compiled on first use, not at import time, because `migrate()`
 * must have created the tables before SQLite will accept the statement.
 */
function selectUserById(): Database.Statement<[string], UserRecord> {
  userByIdStmt ??= db.prepare<[string], UserRecord>(
    "SELECT * FROM users WHERE id = ?",
  );
  return userByIdStmt;
}

/** Lazily compiles the session lookup (see {@link selectUserById} for why it is lazy). */
function selectSessionById(): Database.Statement<[string], SessionAuthRow> {
  sessionByIdStmt ??= db.prepare<[string], SessionAuthRow>(
    "SELECT id, user_id, revoked_at, expires_at FROM sessions WHERE id = ?",
  );
  return sessionByIdStmt;
}

/**
 * Extracts the credential from an `Authorization: Bearer <jwt>` header.
 *
 * The scheme is matched case-insensitively per RFC 7235; anything else yields `null` so the caller
 * answers 401 `AUTH_REQUIRED` rather than trying to verify a non-JWT string.
 */
function readBearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const separator = header.indexOf(" ");
  if (separator < 0) return null;
  const scheme = header.slice(0, separator);
  if (scheme.toLowerCase() !== "bearer") return null;
  const token = header.slice(separator + 1).trim();
  return token.length > 0 ? token : null;
}

/**
 * Guards every Bearer-protected route. A request only proceeds when all four checks pass:
 *
 * 1. the `Authorization: Bearer` JWT verifies (signature, `iss`, `aud`, HS256, `typ`, `exp`);
 * 2. the user named by `sub` still exists — a deleted account must not keep a live token working;
 * 3. the session named by `sid` is still active (not revoked, not expired) — this is what makes
 *    "log out everywhere" and per-session revocation cut off already-issued access tokens
 *    immediately instead of waiting out their 15-minute TTL;
 * 4. `iat >= floor(password_changed_at / 1000)` — tokens minted before a password change die with
 *    the old password, so a stolen token cannot outlive the credential it was issued against.
 *
 * On success it attaches `req.auth = { user, sessionId, claims }`, where `user` is the sanitised
 * `PublicUser` projection so no password material can reach a response.
 */
export const authenticate: RequestHandler = (req, _res, next) => {
  const token = readBearerToken(req.get("authorization"));
  if (!token) {
    next(unauthorized("AUTH_REQUIRED", "Sign in to access this resource."));
    return;
  }

  // Throws AppError 401 TOKEN_EXPIRED / TOKEN_INVALID, which Express forwards to the error handler.
  const claims: AccessClaims = verifyAccessToken(token);

  const user = selectUserById().get(claims.sub);
  if (!user) {
    // Deliberately TOKEN_INVALID, not NOT_FOUND: the token is what is unusable, and we do not
    // confirm to an unauthenticated caller whether a given account id exists.
    next(unauthorized("TOKEN_INVALID", "This access token is no longer valid."));
    return;
  }

  const session = selectSessionById().get(claims.sid);
  const now = Date.now();
  if (
    !session ||
    session.user_id !== user.id ||
    session.revoked_at !== null ||
    session.expires_at <= now
  ) {
    next(unauthorized("SESSION_INVALID", "This session has ended. Sign in again."));
    return;
  }

  if (claims.iat < Math.floor(user.password_changed_at / 1000)) {
    next(
      unauthorized("TOKEN_INVALID", "The password changed after this token was issued. Sign in again."),
    );
    return;
  }

  req.auth = {
    user: toPublicUser(user),
    sessionId: session.id,
    claims,
  };

  next();
};
