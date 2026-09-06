import jwt from "jsonwebtoken";
import { env } from "../config/env.js";
import { AppError } from "./errors.js";
import { newId, randomToken, sha256 } from "./crypto.js";

/** Roles a credential can carry. Mirrors `users.role` in the schema. */
export type TokenRole = "user" | "admin";

/** The minimal user projection {@link signAccessToken} needs; deliberately excludes the password hash. */
export type AccessTokenUser = {
  id: string;
  email: string;
  role: TokenRole;
};

/** Verified claim set carried by an access token. */
export type AccessClaims = {
  sub: string;
  sid: string;
  email: string;
  role: TokenRole;
  typ: "access";
  iss: string;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
};

/** A freshly minted access token together with its lifetime, ready to put in a response body. */
export type SignedAccessToken = {
  token: string;
  /** Seconds until expiry, matching the `expiresIn` field of the API success envelope. */
  expiresIn: number;
  /** Absolute expiry as epoch milliseconds, matching the epoch-ms convention used across the schema. */
  expiresAt: number;
};

/** A new opaque refresh token plus the only form of it that is ever persisted. */
export type NewRefreshToken = {
  /** Sent to the client in the `refresh_token` cookie and never written to the database. */
  token: string;
  /** sha256 hex digest stored in `sessions.token_hash`, so a database leak cannot be replayed. */
  tokenHash: string;
};

/** The single algorithm we will accept, pinned so a forged `alg: none` or `alg: RS256` header cannot bypass verification. */
const ALLOWED_ALGORITHMS: ["HS256"] = ["HS256"];

/** Marks the token kind, so a refresh or any future token type can never be replayed as an access token. */
const ACCESS_TOKEN_TYPE = "access";

/**
 * Signs a short-lived HS256 access token bound to one user and one session.
 * `sid` is embedded so revoking a session immediately invalidates its access tokens,
 * and `iat` is explicit so a password change can reject every token minted before it.
 */
export function signAccessToken(u: AccessTokenUser, sessionId: string): SignedAccessToken {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAtSeconds = issuedAt + env.accessTokenTtlSeconds;

  const token = jwt.sign(
    {
      sid: sessionId,
      email: u.email,
      role: u.role,
      typ: ACCESS_TOKEN_TYPE,
      iat: issuedAt,
      exp: expiresAtSeconds,
    },
    env.jwtSecret,
    {
      algorithm: "HS256",
      subject: u.id,
      issuer: env.jwtIssuer,
      audience: env.jwtAudience,
      jwtid: newId("jti"),
    },
  );

  return {
    token,
    expiresIn: env.accessTokenTtlSeconds,
    expiresAt: expiresAtSeconds * 1000,
  };
}

/**
 * Verifies an access token and returns its claims.
 * Checks signature, the HS256 allowlist, issuer, audience, expiry and `typ === "access"`;
 * anything that fails becomes a 401 rather than a 500 so the client can refresh instead of erroring.
 */
export function verifyAccessToken(token: string): AccessClaims {
  let decoded: unknown;
  try {
    decoded = jwt.verify(token, env.jwtSecret, {
      algorithms: ALLOWED_ALGORITHMS,
      issuer: env.jwtIssuer,
      audience: env.jwtAudience,
    });
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      throw new AppError(
        401,
        "TOKEN_EXPIRED",
        "Your access token has expired. Refresh it and send the request again.",
      );
    }
    throw invalidToken();
  }

  if (typeof decoded !== "object" || decoded === null) throw invalidToken();
  const raw = decoded as Record<string, unknown>;

  const sub = asString(raw["sub"]);
  const sid = asString(raw["sid"]);
  const email = asString(raw["email"]);
  const jti = asString(raw["jti"]);
  const iss = asString(raw["iss"]);
  const aud = asAudience(raw["aud"]);
  const role = raw["role"];
  const iat = raw["iat"];
  const exp = raw["exp"];

  if (raw["typ"] !== ACCESS_TOKEN_TYPE) throw invalidToken();
  if (sub === null || sid === null || email === null || jti === null) throw invalidToken();
  if (iss === null || aud === null) throw invalidToken();
  if (role !== "user" && role !== "admin") throw invalidToken();
  if (typeof iat !== "number" || typeof exp !== "number") throw invalidToken();

  return { sub, sid, email, role, typ: ACCESS_TOKEN_TYPE, iss, aud, jti, iat, exp };
}

/**
 * Mints a refresh token: a 32-byte opaque random string for the cookie plus its sha256 digest.
 * The token is opaque rather than a JWT so it can be revoked server-side, and only the
 * digest is stored so stolen database rows cannot be turned back into usable tokens.
 */
export function newRefreshToken(): NewRefreshToken {
  const token = randomToken(32);
  return { token, tokenHash: sha256(token) };
}

/** Hashes a presented refresh token the same way it was stored, for lookup against `sessions.token_hash`. */
export function hashRefreshToken(token: string): string {
  return sha256(token);
}

/** Builds the single generic 401 used for every claim failure, so the response never explains what was wrong. */
function invalidToken(): AppError {
  return new AppError(401, "TOKEN_INVALID", "That access token is not valid. Sign in again.");
}

/** Narrows an unknown claim to a non-empty string, or null when it is anything else. */
function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

/** Normalises the `aud` claim, which jsonwebtoken may hand back as a string or an array. */
function asAudience(value: unknown): string | null {
  if (typeof value === "string" && value.length > 0) return value;
  if (Array.isArray(value)) {
    const first = value[0];
    if (typeof first === "string" && first.length > 0) return first;
  }
  return null;
}
