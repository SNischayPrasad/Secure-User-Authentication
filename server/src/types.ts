/**
 * Shared server-wide types.
 *
 * Naming rule used throughout the server (important for integration):
 *   - `*Record` / `*Row` types mirror a SQLite row EXACTLY, in snake_case, and may contain
 *     secrets (e.g. `password_hash`). They must never be handed to `res.json()`.
 *   - every other type here is a serialisation shape: camelCase, safe to send to a client.
 */

/** Roles a user can hold; mirrors the `users.role` column ('user' | 'admin'). */
export type UserRole = "user" | "admin";

/** Reasons a session row can be revoked; mirrors `sessions.revoked_reason`. */
export type SessionRevokedReason =
  | "logout"
  | "logout_all"
  | "rotated"
  | "reuse_detected"
  | "revoked_by_user"
  | "password_changed";

/** The audit event vocabulary written to `auth_events.type`. */
export type AuthEventType =
  | "register"
  | "login"
  | "logout"
  | "logout_all"
  | "token_refresh"
  | "token_reuse_detected"
  | "password_change"
  | "profile_update"
  | "session_revoked"
  | "account_locked";

/** Outcome recorded on every audit event; mirrors `auth_events.outcome`. */
export type AuthEventOutcome = "success" | "failure";

/**
 * The `users` table row, exactly as SQLite returns it.
 * Contains `password_hash`, so this type must never escape the data layer — convert with a
 * `toPublicUser()`-style mapper before responding, which is what keeps hashes out of responses.
 */
export type UserRecord = {
  id: string;
  email: string;
  email_canonical: string;
  name: string;
  password_hash: string;
  password_algo: string;
  role: UserRole;
  failed_attempts: number;
  locked_until: number | null;
  password_changed_at: number;
  created_at: number;
  updated_at: number;
};

/**
 * The ONLY user shape ever serialised to a client — it structurally cannot carry a password
 * hash, lockout counters or internal columns, so leaking them requires an explicit new type.
 */
export type PublicUser = {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  createdAt: number;
  passwordChangedAt: number;
};

/**
 * The `sessions` table row, exactly as SQLite returns it — one row per refresh-token family
 * member. `token_hash` is a sha256 hex digest; the raw refresh token is never persisted.
 */
export type SessionRecord = {
  id: string;
  user_id: string;
  family_id: string;
  token_hash: string;
  user_agent: string | null;
  ip_address: string | null;
  created_at: number;
  last_used_at: number;
  expires_at: number;
  revoked_at: number | null;
  revoked_reason: SessionRevokedReason | null;
  replaced_by: string | null;
};

/**
 * A session as shown to its owner (GET /api/v1/me/sessions). Deliberately omits `token_hash`
 * and `family_id` so the listing cannot be used to reconstruct or correlate refresh tokens.
 */
export type SessionSummary = {
  id: string;
  current: boolean;
  userAgent: string | null;
  ipAddress: string | null;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
};

/** The `auth_events` table row, exactly as SQLite returns it (append-only audit log). */
export type AuthEventRow = {
  id: string;
  user_id: string | null;
  email_attempted: string | null;
  type: string;
  outcome: AuthEventOutcome;
  detail: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: number;
};

/**
 * A serialised audit event (GET /api/v1/me/activity). Read it out of SQLite with aliased
 * columns, e.g. `SELECT id, user_id AS userId, email_attempted AS emailAttempted, ...`.
 */
export type AuthEvent = {
  id: string;
  userId: string | null;
  emailAttempted: string | null;
  type: string;
  outcome: AuthEventOutcome;
  detail: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: number;
};

/** The `vault_items` table row, exactly as SQLite returns it. */
export type VaultItemRow = {
  id: string;
  user_id: string;
  title: string;
  body: string;
  created_at: number;
  updated_at: number;
};

/**
 * A serialised vault item — the protected resource showcased in the UI. Read it out of SQLite
 * with aliased columns, e.g. `SELECT id, user_id AS userId, created_at AS createdAt, ...`.
 */
export type VaultItem = {
  id: string;
  userId: string;
  title: string;
  body: string;
  createdAt: number;
  updatedAt: number;
};

/**
 * Verified claims carried by an HS256 access token. `typ` is checked on every request so a
 * token minted for another purpose can never be replayed as an access token.
 */
export type AccessClaims = {
  sub: string;
  sid: string;
  email: string;
  role: UserRole;
  typ: "access";
  iss: string;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
};

/**
 * What `authenticate` attaches to a request once a bearer token, its user and its session have
 * all been re-checked against the database — never trusted straight from the token payload.
 */
export type AuthContext = {
  user: PublicUser;
  sessionId: string;
  claims: AccessClaims;
};

/** One field-level validation problem, as returned in `error.details` for 400 responses. */
export type ErrorDetail = {
  field: string;
  message: string;
};

/**
 * The single error envelope used for EVERY error response, including 404 and 500, so clients
 * never have to guess a shape and internals never leak through an ad-hoc error body.
 */
export type ErrorBody = {
  error: { code: string; message: string; details?: unknown };
  requestId?: string;
};

declare global {
  namespace Express {
    interface Request {
      /** Correlation id assigned by `middleware/requestId.ts`; echoed in `X-Request-Id`. */
      requestId?: string;
      /** Present only after `authenticate` has verified the bearer token, user and session. */
      auth?: AuthContext;
    }
  }
}
