// ---------------------------------------------------------------------------------------
// Environment first. `config/env.ts` validates and freezes configuration the moment it is
// imported, so these assignments must land before any module under src/ is evaluated.
// ESM hoists `import` declarations above ordinary statements, which is why this file
// imports NOTHING from src/ statically — every server module is pulled in lazily below.
// (vitest.config.ts sets the same three variables; this is the belt to that pair of braces.)
// ---------------------------------------------------------------------------------------
process.env.NODE_ENV = "test";
process.env.DATABASE_FILE = ":memory:";
process.env.JWT_SECRET = "test-secret-that-is-definitely-long-enough-32";
process.env.BOOTSTRAP_DEMO_USER = "false";

import { randomUUID } from "node:crypto";
import request from "supertest";
import type { Agent, Response } from "supertest";

/** A supertest client. `request(app)` and `request.agent(app)` both produce this shape. */
export type TestClient = Agent;

/** Anything the tests need to drive supertest against; the app factory's return value. */
export type TestApp = Parameters<typeof request>[0];

/**
 * A password that satisfies the contract's policy (>= 12 chars, all four character classes,
 * not a common password, and not derived from the test name or email local-part).
 */
export const VALID_PASSWORD = "Vp7#quorumLattice42";

/** A second policy-satisfying password, used wherever a password must actually change. */
export const NEW_PASSWORD = "Zx9$meridianCobalt31";

/** Passes the zod schema (1..200 chars) but must fail `assessPassword` — drives WEAK_PASSWORD. */
export const WEAK_PASSWORD = "password123";

/** Default display name for generated test accounts; short enough to satisfy nameSchema. */
export const TEST_NAME = "Ada Lovelace";

/** Row shape of the `users` table, for tests that inspect storage directly. */
export type UserRow = {
  id: string;
  email: string;
  email_canonical: string;
  name: string;
  password_hash: string;
  password_algo: string;
  role: string;
  failed_attempts: number;
  locked_until: number | null;
  password_changed_at: number;
  created_at: number;
  updated_at: number;
};

/** Row shape of the `sessions` table, for refresh-rotation and revocation assertions. */
export type SessionRow = {
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
  revoked_reason: string | null;
  replaced_by: string | null;
};

/** Decoded access-token claims, as minted by `lib/tokens.ts`. */
export type AccessTokenClaims = {
  sub: string;
  sid: string;
  email: string;
  role: string;
  typ: string;
  iss: string;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
};

/**
 * Builds the Express app through the factory, importing it lazily so the environment above
 * is already in place. `migrate()` is idempotent, so calling it here is safe even though
 * the app bootstraps its own schema.
 */
export async function makeApp(): Promise<TestApp> {
  const { migrate } = await import("../src/db/migrate.js");
  await migrate();
  const { createApp } = await import("../src/app.js");
  return (await createApp()) as TestApp;
}

/**
 * Returns the live database handle the app is writing through, so tests can assert on what is
 * actually persisted (e.g. that a plaintext password never reaches a column) rather than on
 * what a response happens to omit.
 */
export async function getDb() {
  const mod = await import("../src/db/index.js");
  return mod.getDb();
}

/** A fresh lowercase email per call, so each test gets its own account and rate-limit key. */
export function uniqueEmail(prefix = "acct"): string {
  return `${prefix}-${randomUUID().slice(0, 8)}@example.test`;
}

/**
 * Parses every `Set-Cookie` on a response into name -> decoded value. Values are decoded
 * because that is the form `cookie-parser` hands the server, which is what CSRF compares.
 */
export function parseSetCookie(res: Response): Record<string, string> {
  const raw = (res.headers as Record<string, unknown>)["set-cookie"];
  const lines: string[] = Array.isArray(raw) ? (raw as string[]) : typeof raw === "string" ? [raw] : [];
  const jar: Record<string, string> = {};
  for (const line of lines) {
    const pair = line.split(";")[0];
    if (pair === undefined) continue;
    const eq = pair.indexOf("=");
    if (eq < 0) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name.length === 0) continue;
    try {
      jar[name] = decodeURIComponent(value);
    } catch {
      jar[name] = value;
    }
  }
  return jar;
}

/** Pulls one cookie value (e.g. `refresh_token`, `csrf_token`) out of a response, if set. */
export function getCookie(res: Response, name: string): string | undefined {
  return parseSetCookie(res)[name];
}

/** True when the response explicitly clears `name` (empty value = browser drops the cookie). */
export function clearsCookie(res: Response, name: string): boolean {
  const jar = parseSetCookie(res);
  return name in jar && (jar[name] ?? "") === "";
}

/** Serialises cookies into a `Cookie:` header, for the tests that must replay an exact token. */
export function cookieHeader(cookies: Record<string, string | undefined>): string {
  return Object.entries(cookies)
    .filter((entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].length > 0)
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

/** Authorization header for a bearer access token. */
export function bearer(accessToken: string): Record<string, string> {
  return { Authorization: `Bearer ${accessToken}` };
}

/** Convenience accessor for the contract's error envelope code, or undefined if absent. */
export function errorCode(res: Response): string | undefined {
  const body = res.body as { error?: { code?: unknown } } | undefined;
  const code = body?.error?.code;
  return typeof code === "string" ? code : undefined;
}

/**
 * Fetches a CSRF token and (for agents) the matching `csrf_token` cookie. The double-submit
 * check compares the header against the cookie, so the cookie value is preferred as the
 * source of truth.
 */
export async function csrfToken(client: TestClient): Promise<string> {
  const res = await client.get("/api/v1/auth/csrf");
  const fromCookie = getCookie(res, "csrf_token");
  const body = res.body as { csrfToken?: unknown } | undefined;
  const fromBody = typeof body?.csrfToken === "string" ? body.csrfToken : undefined;
  const token = fromCookie ?? fromBody;
  if (!token) {
    throw new Error(`GET /api/v1/auth/csrf did not yield a csrf token (status ${res.status})`);
  }
  return token;
}

/** Everything a test needs about an account it just created. */
export type RegisteredAccount = {
  res: Response;
  email: string;
  password: string;
  name: string;
  userId: string;
  accessToken: string;
  refreshToken: string | undefined;
};

/** Registers a fresh account (unique email unless overridden) and returns its credentials. */
export async function register(
  client: TestClient,
  overrides: { name?: string; email?: string; password?: string } = {},
): Promise<RegisteredAccount> {
  const email = overrides.email ?? uniqueEmail();
  const password = overrides.password ?? VALID_PASSWORD;
  const name = overrides.name ?? TEST_NAME;
  const res = await client.post("/api/v1/auth/register").send({ name, email, password });
  const body = res.body as { user?: { id?: string }; accessToken?: string } | undefined;
  return {
    res,
    email,
    password,
    name,
    userId: body?.user?.id ?? "",
    accessToken: body?.accessToken ?? "",
    refreshToken: getCookie(res, "refresh_token"),
  };
}

/** Logs in and hands back the raw response plus the freshly issued access/refresh material. */
export async function login(
  client: TestClient,
  email: string,
  password: string,
): Promise<{ res: Response; accessToken: string; refreshToken: string | undefined }> {
  const res = await client.post("/api/v1/auth/login").send({ email, password });
  const body = res.body as { accessToken?: string } | undefined;
  return {
    res,
    accessToken: body?.accessToken ?? "",
    refreshToken: getCookie(res, "refresh_token"),
  };
}

/**
 * Decodes (does NOT verify) an access token's payload. Tests use it to learn the `sid` claim
 * so they can assert on the exact session row the server bound the token to.
 */
export function decodeJwtPayload(token: string): AccessTokenClaims {
  const segment = token.split(".")[1];
  if (segment === undefined) throw new Error("not a JWT: missing payload segment");
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as AccessTokenClaims;
}
