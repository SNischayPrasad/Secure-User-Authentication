import type { Request } from "express";
import { getDb } from "../db/index.js";
import { newId } from "./crypto.js";

/** The event names written to `auth_events.type`. Kept as a union so callers cannot invent a name silently. */
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
  | "account_locked"
  | "rate_limited";

/** Every event name the schema defines, in the order they appear in the contract. */
export const AUTH_EVENT_TYPES: readonly AuthEventType[] = [
  "register",
  "login",
  "logout",
  "logout_all",
  "token_refresh",
  "token_reuse_detected",
  "password_change",
  "profile_update",
  "session_revoked",
  "account_locked",
  "rate_limited",
];

/** Whether the attempted action succeeded. Written to `auth_events.outcome`. */
export type AuthOutcome = "success" | "failure";

/** One row of the append-only audit log, in the camelCase shape the API serialises. */
export type AuthEvent = {
  id: string;
  userId: string | null;
  emailAttempted: string | null;
  type: string;
  outcome: AuthOutcome;
  detail: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  createdAt: number;
};

/** What {@link recordEvent} accepts. `userId` is optional because a failed login may have no known account. */
export type AuthEventInput = {
  userId?: string | null;
  emailAttempted?: string | null;
  type: string;
  outcome: AuthOutcome;
  detail?: string;
  req?: Request;
};

/** Raw column shape of `auth_events`, before mapping to {@link AuthEvent}. */
type AuthEventRow = {
  id: string;
  user_id: string | null;
  email_attempted: string | null;
  type: string;
  outcome: string;
  detail: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: number;
};

const INSERT_EVENT_SQL = `
  INSERT INTO auth_events
    (id, user_id, email_attempted, type, outcome, detail, ip_address, user_agent, created_at)
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
`;

const LIST_EVENTS_SQL = `
  SELECT id, user_id, email_attempted, type, outcome, detail, ip_address, user_agent, created_at
  FROM auth_events
  WHERE user_id = $1
  ORDER BY created_at DESC, id DESC
  LIMIT $2
`;

/** Upper bound on how many events one call can return, so a hostile `limit` cannot drain the table. */
const MAX_LIST_LIMIT = 200;

/** Longest user-agent we keep; the header is attacker-controlled, so it is truncated before storage. */
const MAX_USER_AGENT_LENGTH = 256;

/** Longest address string we keep, enough for IPv6 with an IPv4 suffix and a zone id. */
const MAX_IP_LENGTH = 64;

/**
 * Appends one row to the audit log, deriving IP and user-agent from the request when given.
 *
 * The returned promise never rejects: an audit write must not be able to fail a login or a
 * logout, so any error — including a failure to reach the database at all — is logged
 * server-side and swallowed rather than surfaced to the caller. Callers may await it or leave
 * it floating; both are safe.
 */
export async function recordEvent(e: AuthEventInput): Promise<void> {
  try {
    const db = await getDb();
    await db.query(INSERT_EVENT_SQL, [
      newId("evt"),
      e.userId ?? null,
      e.emailAttempted ?? null,
      e.type,
      e.outcome,
      e.detail ?? null,
      clientIp(e.req),
      clientUserAgent(e.req),
      Date.now(),
    ]);
  } catch (err) {
    console.error(`[audit] failed to record "${e.type}" (${e.outcome})`, err);
  }
}

/**
 * Returns a user's most recent audit events, newest first.
 * Scoped to a single `userId` so one account can never read another account's security history.
 */
export async function listEvents(userId: string, limit = 50): Promise<AuthEvent[]> {
  const db = await getDb();
  const safeLimit = clampLimit(limit);
  const { rows } = await db.query<AuthEventRow>(LIST_EVENTS_SQL, [userId, safeLimit]);
  return rows.map(toAuthEvent);
}

/** Maps a database row to the camelCase event shape returned by the API. */
function toAuthEvent(row: AuthEventRow): AuthEvent {
  return {
    id: row.id,
    userId: row.user_id,
    emailAttempted: row.email_attempted,
    type: row.type,
    outcome: row.outcome === "success" ? "success" : "failure",
    detail: row.detail,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    createdAt: row.created_at,
  };
}

/** Forces `limit` into 1..MAX_LIST_LIMIT, treating anything non-numeric as the default 50. */
function clampLimit(limit: number): number {
  if (!Number.isFinite(limit)) return 50;
  return Math.min(MAX_LIST_LIMIT, Math.max(1, Math.floor(limit)));
}

/** Reads the caller's IP from the request, truncated; returns null when there is no request. */
function clientIp(req: Request | undefined): string | null {
  const ip = req?.ip;
  return typeof ip === "string" && ip.length > 0 ? ip.slice(0, MAX_IP_LENGTH) : null;
}

/** Reads the caller's user-agent header, truncated because the value is attacker-controlled. */
function clientUserAgent(req: Request | undefined): string | null {
  const ua = req?.get("user-agent");
  return typeof ua === "string" && ua.length > 0 ? ua.slice(0, MAX_USER_AGENT_LENGTH) : null;
}
