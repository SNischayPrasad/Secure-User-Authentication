import type { NextFunction, Request, Response } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import type { Options, RateLimitInfo } from "express-rate-limit";

import { tooManyRequests } from "../lib/errors.js";

/** Shared window for every limiter: 15 minutes, in milliseconds. */
const WINDOW_MS = 15 * 60 * 1000;

/**
 * Builds the shared over-limit handler.
 *
 * It sets `Retry-After` (seconds until the window resets) and then hands a `RATE_LIMITED`
 * `AppError` to `next`, so a throttled request renders the exact same error envelope as every
 * other failure instead of express-rate-limit's default plaintext body.
 */
function limitHandler(message: string) {
  return (req: Request, res: Response, next: NextFunction, options: Options): void => {
    const info = (req as Request & { rateLimit?: RateLimitInfo }).rateLimit;
    const resetTime = info?.resetTime;
    const remainingMs = resetTime ? resetTime.getTime() - Date.now() : options.windowMs;
    const retryAfterSeconds = Math.max(1, Math.ceil(remainingMs / 1000));

    res.setHeader("Retry-After", String(retryAfterSeconds));
    next(tooManyRequests("RATE_LIMITED", message));
  };
}

/**
 * Reads the submitted email for the login/register bucket key.
 *
 * `req.body` can legitimately be `undefined` (no body, or a body-parser failure that this limiter
 * still runs after), so the value is narrowed rather than indexed blindly.
 */
function submittedEmail(req: Request): string {
  const body = req.body as { email?: unknown } | undefined;
  const email = body?.email;
  return typeof email === "string" ? email.trim().toLowerCase().slice(0, 254) : "";
}

/**
 * Throttles `login` and `register`: 10 attempts per 15 minutes per IP + email pair.
 *
 * Keying on both means one attacker cannot lock every account from a single IP, and a botnet
 * cannot spray one account from many IPs without also tripping the account half of the key. The
 * IP half goes through `ipKeyGenerator` because a raw `req.ip` would give every address in an IPv6
 * /64 its own bucket (and express-rate-limit v8 rejects the raw form outright).
 */
export const authLimiter = rateLimit({
  windowMs: WINDOW_MS,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: (req: Request): string => `${ipKeyGenerator(req.ip ?? "")}|${submittedEmail(req)}`,
  handler: limitHandler("Too many sign-in attempts. Wait a few minutes and try again."),
});

/**
 * Throttles refresh-token rotation: 60 requests per 15 minutes per IP.
 *
 * Generous enough for normal 15-minute access-token renewal across several tabs, tight enough to
 * blunt automated probing of stolen refresh cookies.
 */
export const refreshLimiter = rateLimit({
  windowMs: WINDOW_MS,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: limitHandler("Too many refresh requests. Wait a few minutes and try again."),
});

/**
 * Backstop for the whole `/api` surface: 300 requests per 15 minutes per IP, so no endpoint is
 * left completely unmetered even if a route forgets its own limiter.
 */
export const globalLimiter = rateLimit({
  windowMs: WINDOW_MS,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  handler: limitHandler("Too many requests. Wait a few minutes and try again."),
});
