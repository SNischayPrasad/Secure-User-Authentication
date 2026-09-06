#!/usr/bin/env node
/**
 * End-to-end verification of the running API.
 *
 * This exercises the behaviour the README claims, against a live server, and prints a
 * pass/fail line for each check. It is deliberately dependency-free so it can be run
 * straight from a clone:
 *
 *     npm run dev:api          # in one terminal
 *     node scripts/smoke.mjs   # in another
 *
 * Exits non-zero if anything fails, so it is usable as a CI gate.
 */

import { createHmac } from "node:crypto";

const BASE = process.env.SMOKE_BASE ?? "http://localhost:4000";
const API = `${BASE}/api/v1`;

let passed = 0;
let failed = 0;
const failures = [];

function check(label, expected, actual) {
  const ok = String(expected) === String(actual);
  if (ok) passed += 1;
  else {
    failed += 1;
    failures.push(`${label} — expected ${expected}, got ${actual}`);
  }
  const mark = ok ? "[32mPASS[0m" : "[31mFAIL[0m";
  console.log(`  ${mark}  ${label.padEnd(52)} ${String(expected).padEnd(18)} ${actual}`);
}

function section(title) {
  console.log(`\n[1m${title}[0m`);
}

/** A minimal cookie jar, so rotation and httpOnly behaviour are exercised realistically. */
class Jar {
  constructor() {
    this.cookies = new Map();
  }

  absorb(response) {
    const raw = response.headers.getSetCookie?.() ?? [];
    for (const line of raw) {
      const [pair] = line.split(";");
      const index = pair.indexOf("=");
      if (index > 0) this.cookies.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
    }
  }

  header() {
    return [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  get(name) {
    return this.cookies.get(name) ?? null;
  }
}

async function call(jar, method, path, { body, token, csrf, cookieHeader } = {}) {
  const headers = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const cookies = cookieHeader ?? jar?.header();
  if (cookies) headers["Cookie"] = cookies;
  const csrfValue = csrf === undefined ? jar?.get("csrf_token") : csrf;
  if (csrfValue && method !== "GET") headers["X-CSRF-Token"] = csrfValue;

  const response = await fetch(`${API}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  jar?.absorb(response);

  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: response.status, json, text, code: json?.error?.code ?? null };
}

const STRONG = "Tr0ubador&Horse!92";
const stamp = Date.now().toString(36);
const EMAIL = `smoke-${stamp}@example.com`;

async function main() {
  console.log(`\nSmoke test against ${API}\n${"─".repeat(92)}`);

  section("Service");
  const health = await fetch(`${BASE}/api/health`);
  check("GET  /api/health", 200, health.status);

  const jar = new Jar();

  section("CSRF");
  const csrf = await call(jar, "GET", "/auth/csrf");
  check("GET  /auth/csrf", 200, csrf.status);
  check("     csrf_token cookie set", true, Boolean(jar.get("csrf_token")));

  section("Input validation and error codes");
  const empty = await call(jar, "POST", "/auth/register", { body: {} });
  check("POST /auth/register  missing fields", 400, empty.status);
  check("     error code", "VALIDATION_FAILED", empty.code);
  check("     names the offending field", true, Array.isArray(empty.json?.error?.details));

  const weak = await call(jar, "POST", "/auth/register", {
    body: { name: "Smoke Test", email: EMAIL, password: "password123" },
  });
  check("POST /auth/register  weak password", 400, weak.status);
  check("     error code", "WEAK_PASSWORD", weak.code);

  const badEmail = await call(jar, "POST", "/auth/register", {
    body: { name: "Smoke Test", email: "not-an-email", password: STRONG },
  });
  check("POST /auth/register  invalid email", 400, badEmail.status);

  const malformed = await call(jar, "POST", "/auth/register", { body: "{oops" });
  check("POST /auth/register  malformed JSON", 400, malformed.status);
  check("     error code", "MALFORMED_JSON", malformed.code);

  const unknown = await call(jar, "GET", "/does-not-exist");
  check("GET  /does-not-exist", 404, unknown.status);
  check("     error code", "ROUTE_NOT_FOUND", unknown.code);

  section("Registration");
  const created = await call(jar, "POST", "/auth/register", {
    body: { name: "Smoke Test", email: EMAIL, password: STRONG },
  });
  check("POST /auth/register  valid", 201, created.status);
  check("     returns an access token", true, typeof created.json?.accessToken === "string");
  check("     leaks no password material", false, /password_hash|passwordHash|"password"/i.test(created.text));
  check("     never echoes the plaintext", false, created.text.includes(STRONG));
  check("     refresh cookie set", true, Boolean(jar.get("refresh_token")));
  const accessToken = created.json?.accessToken;

  const duplicate = await call(jar, "POST", "/auth/register", {
    body: { name: "Smoke Test", email: EMAIL, password: STRONG },
  });
  check("POST /auth/register  duplicate email", 409, duplicate.status);
  check("     error code", "EMAIL_TAKEN", duplicate.code);

  section("Protected routes");
  check("GET  /me             no token", 401, (await call(null, "GET", "/me")).status);
  const garbage = await call(null, "GET", "/me", { token: "garbage.token.here" });
  check("GET  /me             invalid token", 401, garbage.status);
  check("     error code", "TOKEN_INVALID", garbage.code);

  const me = await call(null, "GET", "/me", { token: accessToken });
  check("GET  /me             valid token", 200, me.status);
  check("     returns the caller", EMAIL, me.json?.user?.email);
  check("     omits password material", false, /password_hash|passwordHash/i.test(me.text));

  check("GET  /vault          no token", 401, (await call(null, "GET", "/vault")).status);
  check("GET  /vault          valid token", 200, (await call(null, "GET", "/vault", { token: accessToken })).status);
  check("GET  /me/sessions", 200, (await call(null, "GET", "/me/sessions", { token: accessToken })).status);
  check("GET  /me/activity", 200, (await call(null, "GET", "/me/activity", { token: accessToken })).status);

  const item = await call(jar, "POST", "/vault", {
    token: accessToken,
    body: { title: "Smoke note", body: "Written by scripts/smoke.mjs" },
  });
  check("POST /vault          create", 201, item.status);
  check("     returns the public item shape", true,
    typeof item.json?.item?.createdAt === "number" && !("user_id" in (item.json?.item ?? {})));

  section("Forged tokens");
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const nowSec = Math.floor(Date.now() / 1000);
  const forgedClaims = {
    sub: "usr_forged", sid: "ses_forged", email: "attacker@example.com", role: "admin",
    typ: "access", iss: "secure-user-auth", aud: "secure-user-auth.web",
    jti: "forged", iat: nowSec, exp: nowSec + 9999,
  };
  // An unsigned token with a valid-looking payload. Rejected by the algorithm allowlist.
  const algNone = `${b64({ alg: "none", typ: "JWT" })}.${b64(forgedClaims)}.`;
  const noneRes = await call(null, "GET", "/me", { token: algNone });
  check("GET  /me             alg:none forgery", 401, noneRes.status);
  check("     error code", "TOKEN_INVALID", noneRes.code);

  // Correct algorithm, wrong signing key.
  const head = b64({ alg: "HS256", typ: "JWT" });
  const body64 = b64(forgedClaims);
  const badSig = createHmac("sha256", "guessed-secret").update(`${head}.${body64}`).digest("base64url");
  const wrongKey = await call(null, "GET", "/me", { token: `${head}.${body64}.${badSig}` });
  check("GET  /me             HS256 wrong key", 401, wrongKey.status);
  check("     error code", "TOKEN_INVALID", wrongKey.code);

  section("CSRF enforcement");
  const noCsrf = await call(null, "POST", "/vault", {
    token: accessToken,
    cookieHeader: jar.header(),
    csrf: null,
    body: { title: "no csrf", body: "should be rejected" },
  });
  check("POST /vault          without CSRF header", 403, noCsrf.status);
  check("     error code", "CSRF_FAILED", noCsrf.code);

  section("Refresh rotation and reuse detection");
  const originalRefresh = jar.get("refresh_token");
  const rotated = await call(jar, "POST", "/auth/refresh");
  check("POST /auth/refresh   rotate", 200, rotated.status);
  check("     token actually changed", true, jar.get("refresh_token") !== originalRefresh);

  const replay = await call(null, "POST", "/auth/refresh", {
    cookieHeader: `refresh_token=${originalRefresh}; csrf_token=${jar.get("csrf_token")}`,
    csrf: jar.get("csrf_token"),
  });
  check("POST /auth/refresh   replay the old token", 401, replay.status);
  check("     error code", "SESSION_REVOKED", replay.code);

  const burned = await call(jar, "POST", "/auth/refresh");
  check("POST /auth/refresh   whole family revoked", 401, burned.status);

  section("Login, and no account enumeration");
  const jar2 = new Jar();
  await call(jar2, "GET", "/auth/csrf");
  const login = await call(jar2, "POST", "/auth/login", { body: { email: EMAIL, password: STRONG } });
  check("POST /auth/login     valid", 200, login.status);
  const liveToken = login.json?.accessToken;

  const strip = (t) => t.replace(/"requestId":"[^"]*"/, "");
  const wrongPassword = await call(null, "POST", "/auth/login", {
    body: { email: EMAIL, password: "WrongPassword!123" },
  });
  const unknownEmail = await call(null, "POST", "/auth/login", {
    body: { email: `nobody-${stamp}@example.com`, password: "WrongPassword!123" },
  });
  check("POST /auth/login     wrong password", 401, wrongPassword.status);
  check("POST /auth/login     unknown email", 401, unknownEmail.status);
  check("     identical response body", true, strip(wrongPassword.text) === strip(unknownEmail.text));

  section("Revocation cuts off live access tokens");
  check("GET  /me             before logout-all", 200, (await call(null, "GET", "/me", { token: liveToken })).status);
  const logoutAll = await call(jar2, "POST", "/auth/logout-all", { token: liveToken });
  check("POST /auth/logout-all", 204, logoutAll.status);
  const after = await call(null, "GET", "/me", { token: liveToken });
  check("GET  /me             after logout-all", 401, after.status);
  check("     error code", "SESSION_INVALID", after.code);

  section("Account lockout");
  const lockEmail = `lock-${stamp}@example.com`;
  const jar3 = new Jar();
  await call(jar3, "GET", "/auth/csrf");
  await call(jar3, "POST", "/auth/register", {
    body: { name: "Lock Test", email: lockEmail, password: STRONG },
  });
  for (let i = 0; i < 5; i += 1) {
    await call(null, "POST", "/auth/login", { body: { email: lockEmail, password: "Nope!12345678" } });
  }
  const locked = await call(null, "POST", "/auth/login", { body: { email: lockEmail, password: STRONG } });
  check("POST /auth/login     after 5 failures", 423, locked.status);
  check("     error code", "ACCOUNT_LOCKED", locked.code);
  check("     tells the caller when to retry", true, Boolean(locked.json?.error?.details?.retryAfterSeconds));

  console.log(`\n${"─".repeat(92)}`);
  if (failed === 0) {
    console.log(`[32mAll ${passed} checks passed.[0m\n`);
  } else {
    console.log(`[31m${failed} of ${passed + failed} checks failed:[0m`);
    for (const f of failures) console.log(`  - ${f}`);
    console.log("");
  }
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error("\nSmoke test could not run:", error.message);
  console.error("Is the API running?  npm run dev:api\n");
  process.exit(2);
});
