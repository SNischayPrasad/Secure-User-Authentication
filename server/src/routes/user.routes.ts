import { Router, type Request } from "express";

import { listEvents, recordEvent } from "../lib/audit.js";
import { AppError } from "../lib/errors.js";
import { assessPassword, hashPassword, verifyPassword } from "../lib/password.js";
import { authenticate } from "../middleware/authenticate.js";
import { requireCsrf } from "../middleware/csrf.js";
import { validate } from "../middleware/validate.js";
import { changePasswordSchema, idParamSchema, updateProfileSchema } from "../schemas/auth.js";
import {
  findById as findSessionById,
  listActiveForUser as listSessions,
  revokeAllForUser,
  revokeSession,
} from "../services/sessionService.js";
import {
  findById as findUserById,
  toPublicUser,
  updateName as updateProfile,
  updatePassword,
} from "../services/userService.js";
import { clearRefreshCookie } from "./auth.routes.js";

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

/** Reads a validated path parameter; `noUncheckedIndexedAccess` makes the lookup optional. */
function pathParam(req: { params?: unknown }, key: string): string {
  const params = req.params as Record<string, unknown> | undefined | null;
  const value = params ? params[key] : undefined;
  return typeof value === "string" ? value : "";
}

/** Maps password-policy issues onto the validation `details` shape used by the error envelope. */
function passwordDetails(field: string, issues: string[]): Array<{ field: string; message: string }> {
  return issues.map((message) => ({ field, message }));
}

/**
 * Account routes for the signed-in user: profile, password, sessions and audit trail.
 * Mounted at `/api/v1/me`; every route below sits behind `authenticate`.
 */
const router = Router();

router.use(authenticate);

/**
 * Endpoint 8 — GET /me. The primary protected endpoint; returns the public user shape only,
 * which never carries password material.
 */
router.get("/", (req, res) => {
  const auth = requireAuthContext(req);
  res.status(200).json({ user: auth.user });
});

/** Endpoint 9 — PATCH /me. Updates the display name and records a profile_update audit event. */
router.patch("/", requireCsrf, validate({ body: updateProfileSchema }), async (req, res) => {
  const auth = requireAuthContext(req);
  const body = req.body as { name: string };

  const updated = await updateProfile(auth.user.id, body.name);

  await recordEvent({
    userId: auth.user.id,
    type: "profile_update",
    outcome: "success",
    detail: "name",
    req: asRequest(req),
  });

  res.status(200).json({ user: toPublicUser(updated) });
});

/**
 * Endpoint 10 — POST /me/password. Re-verifies the current password before accepting a change,
 * then revokes every other session so a stolen refresh token cannot outlive the rotation.
 */
router.post("/password", requireCsrf, validate({ body: changePasswordSchema }), async (req, res) => {
  const auth = requireAuthContext(req);
  const body = req.body as { currentPassword: string; newPassword: string };

  const user = await findUserById(auth.user.id);
  if (!user) {
    throw new AppError(401, "TOKEN_INVALID", "Your session is no longer valid. Sign in again.");
  }

  const currentOk = await verifyPassword(user.password_hash, body.currentPassword);
  if (!currentOk) {
    await recordEvent({
      userId: user.id,
      type: "password_change",
      outcome: "failure",
      detail: "bad_current_password",
      req: asRequest(req),
    });
    throw new AppError(401, "INVALID_CREDENTIALS", "Your current password is incorrect.");
  }

  if (body.newPassword === body.currentPassword) {
    throw new AppError(400, "SAME_PASSWORD", "Choose a new password that differs from the current one.");
  }

  const assessment = assessPassword(body.newPassword, { email: user.email, name: user.name });
  if (!assessment.ok) {
    throw new AppError(
      400,
      "WEAK_PASSWORD",
      "That password does not meet the policy.",
      passwordDetails("newPassword", assessment.issues),
    );
  }

  const passwordHash = await hashPassword(body.newPassword);
  await updatePassword(user.id, passwordHash);
  await revokeAllForUser(user.id, "password_changed", auth.sessionId);

  await recordEvent({
    userId: user.id,
    type: "password_change",
    outcome: "success",
    req: asRequest(req),
  });

  res.status(204).end();
});

/**
 * Endpoint 11 — GET /me/sessions. Lists active sessions with a `current` flag so a person can
 * tell which device they are looking from before revoking the others.
 */
router.get("/sessions", async (req, res) => {
  const auth = requireAuthContext(req);

  const sessions = (await listSessions(auth.user.id)).map((session) => ({
    id: session.id,
    current: session.id === auth.sessionId,
    userAgent: session.user_agent ?? null,
    ipAddress: session.ip_address ?? null,
    createdAt: session.created_at,
    lastUsedAt: session.last_used_at,
    expiresAt: session.expires_at,
  }));

  res.status(200).json({ sessions });
});

/**
 * Endpoint 12 — DELETE /me/sessions/:id. Answers 404 for a session owned by anyone else, so the
 * endpoint cannot be used to probe which session ids exist.
 */
router.delete(
  "/sessions/:id",
  requireCsrf,
  validate({ params: idParamSchema }),
  async (req, res) => {
    const auth = requireAuthContext(req);
    const id = pathParam(req, "id");

  const session = await findSessionById(id);
  if (!session || session.user_id !== auth.user.id) {
    throw new AppError(404, "NOT_FOUND", "That session does not exist.");
  }

  await revokeSession(session.id, "revoked_by_user");

  if (session.id === auth.sessionId) {
    clearRefreshCookie(res);
  }

  await recordEvent({
    userId: auth.user.id,
    type: "session_revoked",
    outcome: "success",
    detail: session.id,
    req: asRequest(req),
  });

  res.status(204).end();
});

/** Endpoint 13 — GET /me/activity. Returns the caller's last 50 audit events, newest first. */
router.get("/activity", async (req, res) => {
  const auth = requireAuthContext(req);
  res.status(200).json({ events: await listEvents(auth.user.id, 50) });
});

/** Router for `/api/v1/me` (endpoints 8-13). */
export default router;
