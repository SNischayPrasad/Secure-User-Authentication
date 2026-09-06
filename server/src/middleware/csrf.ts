import type { Request, RequestHandler, Response } from "express";

import { env, isProd } from "../config/env.js";
import { randomToken, timingSafeEqualStr } from "../lib/crypto.js";
import { forbidden } from "../lib/errors.js";

/** Name of the readable double-submit cookie. */
export const CSRF_COOKIE_NAME = "csrf_token";

/** Name of the header the client must echo the cookie value in. */
export const CSRF_HEADER_NAME = "X-CSRF-Token";

/** Methods that cannot change state, so they carry no CSRF requirement. */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Reads the double-submit cookie off the request.
 *
 * `req.cookies` is populated by `cookie-parser` and typed loosely, so it is narrowed here rather
 * than trusted.
 */
function readCsrfCookie(req: Request): string | undefined {
  const cookies = req.cookies as Record<string, unknown> | undefined;
  const value = cookies?.[CSRF_COOKIE_NAME];
  return typeof value === "string" ? value : undefined;
}

/**
 * Mints a CSRF token, sets it as the readable `csrf_token` cookie, and returns it.
 *
 * The cookie is intentionally NOT httpOnly — the browser client must read it to echo it back in
 * the `X-CSRF-Token` header, which is exactly what a cross-site attacker cannot do. `sameSite:
 * "strict"` and the `secure` flag in production keep the value off cross-site and plaintext hops.
 */
export function issueCsrfToken(res: Response): string {
  const token = randomToken(32);
  res.cookie(CSRF_COOKIE_NAME, token, {
    httpOnly: false,
    sameSite: "strict",
    secure: isProd,
    path: "/",
    maxAge: env.refreshTokenTtlSeconds * 1000,
  });
  return token;
}

/**
 * Enforces the double-submit cookie pattern on state-changing requests.
 *
 * Safe methods pass straight through. Otherwise the `X-CSRF-Token` header must equal the
 * `csrf_token` cookie, compared with a constant-time check so the comparison cannot be used as an
 * oracle to recover the token byte by byte. A missing header or cookie is a failure, never a skip,
 * so an attacker cannot bypass the check simply by omitting one side.
 */
export const requireCsrf: RequestHandler = (req, _res, next) => {
  if (SAFE_METHODS.has(req.method.toUpperCase())) {
    next();
    return;
  }

  const headerValue = req.get(CSRF_HEADER_NAME);
  const cookieValue = readCsrfCookie(req);

  if (!headerValue || !cookieValue || !timingSafeEqualStr(headerValue, cookieValue)) {
    next(forbidden("CSRF_FAILED", "The CSRF token is missing or does not match. Reload and try again."));
    return;
  }

  next();
};
