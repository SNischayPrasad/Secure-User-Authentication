import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

/** Resolved, validated configuration for the whole server. */
export type AppEnv = {
  nodeEnv: "development" | "production" | "test";
  port: number;
  webOrigin: string;
  databaseFile: string;
  /**
   * A Postgres connection string. When present the app connects to that server; when absent it
   * runs PGlite (in-process Postgres) against `databaseFile`. Vercel injects this automatically
   * once a Neon store is attached to the project.
   */
  databaseUrl: string | null;
  jwtSecret: string;
  jwtIssuer: string;
  jwtAudience: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  bootstrapDemoUser: boolean;
};

/** Server package root: `src/config/env.ts` and `dist/config/env.js` both sit two levels down. */
const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/**
 * On Vercel the client and the API are served from the same deployment, so the allowed origin is
 * the deployment's own URL. Vercel exposes it without the scheme; the production alias is
 * preferred over the per-deployment host so preview builds do not pin CORS to a URL that changes
 * on every push. Returns null anywhere else, leaving the localhost default in place.
 */
function vercelOrigin(): string | null {
  const host = process.env["VERCEL_PROJECT_PRODUCTION_URL"] ?? process.env["VERCEL_URL"];
  return host ? `https://${host}` : null;
}

/** Defaults from the build contract, expressed as raw strings so they validate like real input. */
const DEFAULTS: Record<string, string> = {
  NODE_ENV: "development",
  PORT: "4000",
  WEB_ORIGIN: vercelOrigin() ?? "http://localhost:5173",
  DATABASE_FILE: "./data/auth-pg",
  JWT_ISSUER: "secure-user-auth",
  JWT_AUDIENCE: "secure-user-auth.web",
  ACCESS_TOKEN_TTL: "900",
  REFRESH_TOKEN_TTL: "604800",
};

const TRUTHY = new Set(["1", "true", "yes", "on"]);
const FALSY = new Set(["0", "false", "no", "off"]);

/**
 * Minimal `.env` reader (no dotenv dependency). Real environment variables always win, so a
 * checked-out `.env` can never silently override a secret injected by the deployment platform.
 */
function loadDotEnvFile(): void {
  const candidates = [path.join(serverRoot, ".env"), path.resolve(process.cwd(), ".env")];
  const seen = new Set<string>();

  for (const candidate of candidates) {
    if (seen.has(candidate)) continue;
    seen.add(candidate);

    let raw: string;
    try {
      raw = readFileSync(candidate, "utf8");
    } catch {
      continue; // absent or unreadable: a .env file is entirely optional
    }

    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed === "" || trimmed.startsWith("#")) continue;

      const separator = trimmed.indexOf("=");
      if (separator <= 0) continue;

      const key = trimmed.slice(0, separator).trim().replace(/^export\s+/, "");
      if (key === "") continue;

      let value = trimmed.slice(separator + 1).trim();
      const quote = value.charAt(0);
      if (value.length >= 2 && (quote === '"' || quote === "'") && value.endsWith(quote)) {
        value = value.slice(1, -1);
      }

      if (process.env[key] === undefined) process.env[key] = value;
    }

    return; // the first file found wins
  }
}

/** Builds a zod schema that accepts a whole-number string within an inclusive range. */
function integerEnv(label: string, min: number, max: number) {
  return z
    .string()
    .refine((value) => /^\d+$/.test(value.trim()), `${label} must be a whole number.`)
    .transform((value) => Number.parseInt(value.trim(), 10))
    .refine(
      (value) => Number.isSafeInteger(value) && value >= min && value <= max,
      `${label} must be between ${min} and ${max}.`,
    );
}

/** Accepts the usual truthy/falsy spellings people put in env files. */
const booleanEnv = z
  .string()
  .transform((value) => value.trim().toLowerCase())
  .refine(
    (value) => TRUTHY.has(value) || FALSY.has(value),
    "Expected one of: true, false, 1, 0, yes, no, on, off.",
  )
  .transform((value) => TRUTHY.has(value));

/** An absolute http(s) origin; trailing slashes are trimmed so CORS matching is exact. */
const originEnv = z
  .string()
  .refine((value) => {
    try {
      const url = new URL(value.trim());
      return url.protocol === "http:" || url.protocol === "https:";
    } catch {
      return false;
    }
  }, "WEB_ORIGIN must be a valid http(s) URL, e.g. http://localhost:5173.")
  .transform((value) => value.trim().replace(/\/+$/, ""));

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "production", "test"]),
  PORT: integerEnv("PORT", 1, 65535),
  WEB_ORIGIN: originEnv,
  DATABASE_FILE: z.string().min(1, "DATABASE_FILE must not be empty."),
  // Vercel's Neon integration sets several aliases; any one of them is accepted.
  DATABASE_URL: z.string().min(1).optional(),
  POSTGRES_URL: z.string().min(1).optional(),
  DATABASE_POSTGRES_URL: z.string().min(1).optional(),
  JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters.").optional(),
  JWT_ISSUER: z.string().min(1, "JWT_ISSUER must not be empty."),
  JWT_AUDIENCE: z.string().min(1, "JWT_AUDIENCE must not be empty."),
  ACCESS_TOKEN_TTL: integerEnv("ACCESS_TOKEN_TTL", 60, 86400),
  REFRESH_TOKEN_TTL: integerEnv("REFRESH_TOKEN_TTL", 300, 31536000),
  BOOTSTRAP_DEMO_USER: booleanEnv.optional(),
});

/**
 * Resolves the HMAC signing key.
 *
 * In production an absent or short `JWT_SECRET` is fatal: booting with a guessable key would let
 * anyone mint valid access tokens. Outside production we mint a per-process ephemeral key and
 * say so loudly, so nobody mistakes surviving-a-restart sessions for a configured deployment.
 */
function resolveJwtSecret(configured: string | undefined, production: boolean): string {
  if (production) {
    if (configured === undefined || configured.length < 32) {
      throw new Error(
        "Invalid environment configuration:\n" +
          "  - JWT_SECRET: must be set to at least 32 characters when NODE_ENV=production.\n" +
          "    Refusing to start. Generate one with:\n" +
          '      node -e "console.log(require(\'node:crypto\').randomBytes(48).toString(\'base64url\'))"',
      );
    }
    return configured;
  }

  if (configured !== undefined) return configured;

  const ephemeral = randomBytes(48).toString("base64url");
  console.warn(
    "[env] JWT_SECRET is not set. Generated an ephemeral signing key for this process only — " +
      "every access token and session becomes invalid when the server restarts. " +
      "Set JWT_SECRET in server/.env to keep sessions across restarts.",
  );
  return ephemeral;
}

function loadEnv(): AppEnv {
  loadDotEnvFile();

  // Start from the contract defaults, then let non-blank real env vars override them. Treating a
  // blank value as "unset" stops `JWT_SECRET=` in a .env file from failing the length check.
  const source: Record<string, string> = { ...DEFAULTS };
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === "string" && value.trim() !== "") source[key] = value;
  }

  const parsed = envSchema.safeParse(source);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((issue) => {
      const field = issue.path.length > 0 ? issue.path.join(".") : "(root)";
      return `  - ${field}: ${issue.message}`;
    });
    throw new Error(`Invalid environment configuration:\n${lines.join("\n")}`);
  }

  const data = parsed.data;
  const production = data.NODE_ENV === "production";

  const databaseUrl = data.DATABASE_URL ?? data.POSTGRES_URL ?? data.DATABASE_POSTGRES_URL ?? null;

  // Without a connection string the server falls back to PGlite, which keeps its data in a
  // directory on the local filesystem. That is exactly right in development and impossible in a
  // serverless deployment, where the filesystem is read-only and each instance is discarded —
  // it would "work" until the first cold start and then silently lose every account. Refusing to
  // boot turns that into an obvious deployment error instead of a data-loss bug.
  if (production && !databaseUrl) {
    throw new Error(
      "DATABASE_URL is required when NODE_ENV=production. The in-process PGlite fallback " +
        "stores data on the local filesystem, which is read-only and ephemeral on a serverless " +
        "host, so any account created there would be lost on the next cold start. Attach a " +
        "Postgres database (on Vercel: Storage > Create Database > Neon) and the connection " +
        "string will be injected automatically.",
    );
  }

  return Object.freeze({
    nodeEnv: data.NODE_ENV,
    port: data.PORT,
    webOrigin: data.WEB_ORIGIN,
    databaseFile: data.DATABASE_FILE,
    databaseUrl,
    jwtSecret: resolveJwtSecret(data.JWT_SECRET, production),
    jwtIssuer: data.JWT_ISSUER,
    jwtAudience: data.JWT_AUDIENCE,
    accessTokenTtlSeconds: data.ACCESS_TOKEN_TTL,
    refreshTokenTtlSeconds: data.REFRESH_TOKEN_TTL,
    // Seeding a known-password demo account is a development affordance only.
    bootstrapDemoUser: data.BOOTSTRAP_DEMO_USER ?? !production,
  });
}

/**
 * The validated environment. Frozen, and resolved exactly once at import time so the process
 * fails fast at startup rather than half-way through serving traffic with a bad config.
 */
export const env: AppEnv = loadEnv();

/** True when running in production — gates `secure` cookies and error-message redaction. */
export const isProd = env.nodeEnv === "production";
