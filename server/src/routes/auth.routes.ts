import { Router, type Request, type Response } from "express";

import { env, isProd } from "../config/env.js";
import { recordEvent } from "../lib/audit.js";
import { AppError } from "../lib/errors.js";
import { assessPassword, getDummyHash, hashPassword, verifyPassword } from "../lib/password.js";
import { signAccessToken } from "../lib/tokens.js";
import { authenticate } from "../middleware/authenticate.js";
import { issueCsrfToken, requireCsrf } from "../middleware/csrf.js";
import { validate } from "../middleware/validate.js";
import { loginSchema, registerSchema } from "../schemas/auth.js";
import {
  createSession as createSessionRecord,
  findByToken as findSessionByRefreshToken,
  revokeAllForUser,
  revokeFamily,
  revokeSession,
  rotate as rotateSessionRecord,
} from "../services/sessionService.js";
import {
  clearLoginFailures,
  createUser,
  findByEmail as findUserByEmail,
  findById as findUserById,
  registerFailedLogin,
  toPublicUser,
} from "../services/userService.js";
import type { SessionRecord } from "../types.js";

/**
 * The session service speaks in records; these routes only ever need the new session's id and
 * the raw refresh token to put in the cookie. These two adapters keep that difference in one
 * place instead of spreading destructuring through every handler.
 */
async function createSession(
  userId: string,
  req?: Request,
): Promise<{ id: string; refreshToken: string }> {
  const { session, refreshToken } = await createSessionRecord({ userId, req });
  return { id: session.id, refreshToken };
}

async function rotateSession(
  current: SessionRecord,
  req?: Request,
): Promise<{ id: string; refreshToken: string }> {
  const { session, refreshToken } = await rotateSessionRecord(current, req);
  return { id: session.id, refreshToken };
}

/**
 * Name of the httpOnly cookie carrying the opaque refresh token; the raw value never
 * reaches JavaScript, so an XSS payload cannot lift a long-lived credential.
 */
export const REFRESH_COOKIE_NAME = "refresh_token";

/**
 * Sets the refresh cookie with the exact hardening the contract requires: httpOnly and
 * SameSite=Strict block XSS reads and cross-site sends, and the narrow `/api/v1/auth`
 * path means the token is only ever transmitted to the endpoints that rotate it.
 */
export function setRefreshCookie(res: Response, token: string): void {
  res.cookie(REFRESH_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "strict",
    secure: isProd,
    path: "/api/v1/auth",
    maxAge: env.refreshTokenTtlSeconds * 1000,
  });
}

/**
 * Removes the refresh cookie using the same attributes it was set with, so the browser
 * actually drops it; called on logout and on every failed or revoked refresh attempt.
 */
export function clearRefreshCookie(res: Response): void {
  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    sameSite: "strict",
    secure: isProd,
    path: "/api/v1/auth",
  });
}

/** The auth context the `authenticate` middleware attaches to the request. */
type AuthContext = NonNullable<Request["auth"]>;

/** Widens a route-specific request to the base Express `Request` the audit log accepts. */
function asRequest(req: unknown): Request {
  return req as Request;
}

/** Returns the authenticated context, or 401 if the route was mounted without `authenticate`. */
function requireAuthContext(req: { auth?: AuthContext }): AuthContext {
  if (!req.auth) {
    throw new AppError(401, "AUTH_REQUIRED", "Sign in to continue.");
  }
  return req.auth;
}

/** Reads the opaque refresh token from the cookie jar, treating an empty value as absent. */
function readRefreshCookie(req: { cookies?: unknown }): string | undefined {
  const jar = req.cookies as Record<string, unknown> | undefined | null;
  if (!jar) {
    return undefined;
  }
  const raw = jar[REFRESH_COOKIE_NAME];
  return typeof raw === "string" && raw.length > 0 ? raw : undefined;
}

/** Maps password-policy issues onto the validation `details` shape used by the error envelope. */
function passwordDetails(field: string, issues: string[]): Array<{ field: string; message: string }> {
  return issues.map((message) => ({ field, message }));
}

/**
 * Inserts the user, translating a UNIQUE collision on email into 409 so a race between two
 * concurrent registrations cannot surface as a 500.
 */
async function createUserOrConflict(input: { name: string; email: string; passwordHash: string }) {
  try {
    return await createUser(input);
  } catch (err) {
    if (err instanceof Error && /unique|constraint/i.test(err.message)) {
      throw new AppError(409, "EMAIL_TAKEN", "That email address is already registered.");
    }
    throw err;
  }
}

/** Ends the refresh flow with a generic 401 that does not distinguish unknown, expired or revoked. */
function sessionInvalid(res: Response): AppError {
  clearRefreshCookie(res);
  return new AppError(401, "SESSION_INVALID", "Your session has ended. Sign in again.");
}

/**
 * Authentication routes: CSRF issuance, registration, login, refresh-token rotation and logout.
 * Mounted at `/api/v1/auth`, which is also the path the refresh cookie is scoped to.
 */
const router = Router();

/**
 * Endpoint 2 — GET /auth/csrf. Mints the double-submit token, sets the readable `csrf_token`
 * cookie and returns the value the client must echo in `X-CSRF-Token`.
 */
router.get("/csrf", (_req, res) => {
  res.status(200).json({ csrfToken: issueCsrfToken(res) });
});

/**
 * Endpoint 3 — POST /auth/register. Enforces the password policy before any hashing work,
 * then issues a session so the caller is signed in immediately.
 */
router.post("/register", validate({ body: registerSchema }), async (req, res) => {
  const body = req.body as { name: string; email: string; password: string };

  const assessment = assessPassword(body.password, { email: body.email, name: body.name });
  if (!assessment.ok) {
    throw new AppError(
      400,
      "WEAK_PASSWORD",
      "That password does not meet the policy.",
      passwordDetails("password", assessment.issues),
    );
  }

  if (await findUserByEmail(body.email)) {
    throw new AppError(409, "EMAIL_TAKEN", "That email address is already registered.");
  }

  const passwordHash = await hashPassword(body.password);
  const user = await createUserOrConflict({ name: body.name, email: body.email, passwordHash });

  const session = await createSession(user.id, asRequest(req));
  setRefreshCookie(res, session.refreshToken);

  const access = signAccessToken(
    { id: user.id, email: user.email, role: user.role as "user" | "admin" },
    session.id,
  );

  await recordEvent({
    userId: user.id,
    emailAttempted: user.email,
    type: "register",
    outcome: "success",
    req: asRequest(req),
  });

  res.status(201).json({
    user: toPublicUser(user),
    accessToken: access.token,
    expiresIn: access.expiresIn,
  });
});

/**
 * Endpoint 4 — POST /auth/login. An unknown email still pays the full argon2 cost against a
 * dummy hash and returns the same generic 401 as a wrong password, so login cannot be used to
 * enumerate accounts by response body or by timing.
 */
router.post("/login", validate({ body: loginSchema }), async (req, res) => {
  const body = req.body as { email: string; password: string };
  const user = await findUserByEmail(body.email);

  if (!user) {
    await verifyPassword(await getDummyHash(), body.password);
    await recordEvent({
      userId: null,
      emailAttempted: body.email,
      type: "login",
      outcome: "failure",
      detail: "unknown_email",
      req: asRequest(req),
    });
    throw new AppError(401, "INVALID_CREDENTIALS", "Email or password is incorrect.");
  }

  const now = Date.now();
  const lockedUntil = user.locked_until;
  if (typeof lockedUntil === "number" && lockedUntil > now) {
    throw new AppError(
      423,
      "ACCOUNT_LOCKED",
      "This account is temporarily locked after repeated failed sign-in attempts.",
      { retryAfterSeconds: Math.ceil((lockedUntil - now) / 1000) },
    );
  }

  const passwordOk = await verifyPassword(user.password_hash, body.password);
  if (!passwordOk) {
    await registerFailedLogin(user.id);
    await recordEvent({
      userId: user.id,
      emailAttempted: body.email,
      type: "login",
      outcome: "failure",
      detail: "bad_password",
      req: asRequest(req),
    });
    throw new AppError(401, "INVALID_CREDENTIALS", "Email or password is incorrect.");
  }

  await clearLoginFailures(user.id);

  const session = await createSession(user.id, asRequest(req));
  setRefreshCookie(res, session.refreshToken);

  const access = signAccessToken(
    { id: user.id, email: user.email, role: user.role as "user" | "admin" },
    session.id,
  );

  await recordEvent({
    userId: user.id,
    emailAttempted: user.email,
    type: "login",
    outcome: "success",
    req: asRequest(req),
  });

  res.status(200).json({
    user: toPublicUser(user),
    accessToken: access.token,
    expiresIn: access.expiresIn,
  });
});

/**
 * Endpoint 5 — POST /auth/refresh. Full rotation with reuse detection: presenting a token that
 * was already rotated means the cookie leaked, so the entire family is revoked rather than
 * silently issuing the attacker a fresh pair.
 */
router.post("/refresh", requireCsrf, async (req, res) => {
  const presented = readRefreshCookie(req);
  if (!presented) {
    throw sessionInvalid(res);
  }

  const session = await findSessionByRefreshToken(presented);
  if (!session) {
    throw sessionInvalid(res);
  }

  if (typeof session.revoked_at === "number") {
    await revokeFamily(session.family_id, "reuse_detected");
    await recordEvent({
      userId: session.user_id,
      type: "token_reuse_detected",
      outcome: "failure",
      detail: `family=${session.family_id}`,
      req: asRequest(req),
    });
    clearRefreshCookie(res);
    throw new AppError(
      401,
      "SESSION_REVOKED",
      "This session was ended for your security. Sign in again.",
    );
  }

  if (session.expires_at <= Date.now()) {
    throw sessionInvalid(res);
  }

  const user = await findUserById(session.user_id);
  if (!user) {
    throw sessionInvalid(res);
  }

  const rotated = await rotateSession(session, asRequest(req));
  setRefreshCookie(res, rotated.refreshToken);

  const access = signAccessToken(
    { id: user.id, email: user.email, role: user.role as "user" | "admin" },
    rotated.id,
  );

  await recordEvent({
    userId: user.id,
    type: "token_refresh",
    outcome: "success",
    detail: `${session.id}->${rotated.id}`,
    req: asRequest(req),
  });

  res.status(200).json({ accessToken: access.token, expiresIn: access.expiresIn });
});

/**
 * Endpoint 6 — POST /auth/logout. Revokes only the presented session and is idempotent: a
 * caller with no cookie still gets 204, so a client can always reach a signed-out state.
 */
router.post("/logout", requireCsrf, async (req, res) => {
  const presented = readRefreshCookie(req);

  if (presented) {
    const session = await findSessionByRefreshToken(presented);
    if (session && typeof session.revoked_at !== "number") {
      await revokeSession(session.id, "logout");
      await recordEvent({
        userId: session.user_id,
        type: "logout",
        outcome: "success",
        detail: session.id,
        req: asRequest(req),
      });
    }
  }

  clearRefreshCookie(res);
  res.status(204).end();
});

/**
 * Endpoint 7 — POST /auth/logout-all. Revokes every session for the user, which also cuts off
 * access tokens already minted because `authenticate` re-checks the session behind each `sid`.
 */
router.post("/logout-all", authenticate, requireCsrf, async (req, res) => {
  const auth = requireAuthContext(req);

  await revokeAllForUser(auth.user.id, "logout_all");
  clearRefreshCookie(res);

  await recordEvent({
    userId: auth.user.id,
    type: "logout_all",
    outcome: "success",
    req: asRequest(req),
  });

  res.status(204).end();
});

/** Router for `/api/v1/auth` (endpoints 2-7). */
export default router;
