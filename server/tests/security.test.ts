// ---------------------------------------------------------------------------------------
// Security-property tests.
//
// Where auth.test.ts checks the shape of the API, this file checks the properties that make
// the API safe: what actually lands in the database, that a rotated refresh token can never
// be replayed, that revocation reaches access tokens which were already minted, and that a
// failed sign-in tells an attacker nothing about whether the account exists.
//
// Every assertion pins BOTH the HTTP status and the contract error `code`, because a 401
// with the wrong code is a different security story than the one being claimed.
// ---------------------------------------------------------------------------------------
import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";

// `./helpers.js` is imported before anything under src/ on purpose: its top-level statements
// pin NODE_ENV / DATABASE_FILE / JWT_SECRET, and `config/env.ts` validates and freezes the
// configuration the moment it is first evaluated — which the two src imports below trigger.
import {
  bearer,
  clearsCookie,
  cookieHeader,
  csrfToken,
  decodeJwtPayload,
  errorCode,
  getCookie,
  login,
  makeApp,
  register,
  uniqueEmail,
  NEW_PASSWORD,
  TEST_NAME,
  VALID_PASSWORD,
  type SessionRow,
  type TestApp,
  type UserRow,
} from "./helpers.js";
import { getDb } from "../src/db/index.js";
import { ARGON2_OPTIONS, verifyPassword } from "../src/lib/password.js";

let app: TestApp;

beforeAll(async () => {
  app = await makeApp();
});

// --- direct storage access -------------------------------------------------------------
// These read the same database the app writes through, so the assertions below are about what
// is genuinely persisted rather than about what a response happens to omit.

async function userRow(userId: string): Promise<UserRow> {
  const db = await getDb();
  const { rows } = await db.query<UserRow>("SELECT * FROM users WHERE id = $1", [userId]);
  const row = rows[0];
  if (!row) throw new Error(`no users row for ${userId}`);
  return row;
}

async function sessionRow(sessionId: string): Promise<SessionRow> {
  const db = await getDb();
  const { rows } = await db.query<SessionRow>("SELECT * FROM sessions WHERE id = $1", [sessionId]);
  const row = rows[0];
  if (!row) throw new Error(`no sessions row for ${sessionId}`);
  return row;
}

async function familyRows(familyId: string): Promise<SessionRow[]> {
  const db = await getDb();
  // Ordered by created_at then id. The previous tiebreaker was SQLite's implicit `rowid`, which
  // Postgres does not have; `id` is unique, so it gives the same deterministic ordering.
  const { rows } = await db.query<SessionRow>(
    "SELECT * FROM sessions WHERE family_id = $1 ORDER BY created_at ASC, id ASC",
    [familyId],
  );
  return rows;
}

describe("password storage", () => {
  it("persists an argon2id hash at the documented cost and never the plaintext", async () => {
    const account = await register(request.agent(app));
    expect(account.res.status).toBe(201);

    const row = await userRow(account.userId);

    // The encoded PHC string carries algorithm, version and cost parameters inline.
    expect(row.password_hash.startsWith("$argon2id$")).toBe(true);
    expect(row.password_algo).toBe("argon2id");

    const segments = row.password_hash.split("$");
    expect(segments[1]).toBe("argon2id");
    expect(segments[2]).toBe("v=19");
    // Pinned to the exported options, so quietly lowering the work factor breaks this test.
    expect(segments[3]).toBe(
      `m=${ARGON2_OPTIONS.memoryCost},t=${ARGON2_OPTIONS.timeCost},p=${ARGON2_OPTIONS.parallelism}`,
    );

    // The plaintext must not survive anywhere in the row: not in the hash, not in a stray
    // column, not in any form the serialised row could be grepped for.
    const serialised = JSON.stringify(row);
    expect(serialised).not.toContain(VALID_PASSWORD);
    expect(serialised.toLowerCase()).not.toContain(VALID_PASSWORD.toLowerCase());
    for (const value of Object.values(row)) {
      if (typeof value === "string") expect(value).not.toContain(VALID_PASSWORD);
    }

    // ...and the stored value really is a hash OF that password, so the checks above are not
    // passing merely because the column holds something unrelated.
    await expect(verifyPassword(row.password_hash, VALID_PASSWORD)).resolves.toBe(true);
    await expect(verifyPassword(row.password_hash, `${VALID_PASSWORD}x`)).resolves.toBe(false);
  });

  it("salts per account, so two users sharing a password do not share a hash", async () => {
    const first = await register(request.agent(app), { password: VALID_PASSWORD });
    const second = await register(request.agent(app), { password: VALID_PASSWORD });

    expect(first.res.status).toBe(201);
    expect(second.res.status).toBe(201);

    const a = await userRow(first.userId);
    const b = await userRow(second.userId);

    expect(a.password_hash).not.toBe(b.password_hash);
    // Same cost parameters, different salt segment — that difference is the salt doing its job.
    expect(a.password_hash.split("$")[3]).toBe(b.password_hash.split("$")[3]);
    expect(a.password_hash.split("$")[4]).not.toBe(b.password_hash.split("$")[4]);
    await expect(verifyPassword(b.password_hash, VALID_PASSWORD)).resolves.toBe(true);
  });
});

describe("refresh-token rotation and reuse detection", () => {
  it("rotates on every refresh, and a replayed token burns the whole family", async () => {
    const agent = request.agent(app);
    const account = await register(agent);
    expect(account.res.status).toBe(201);
    expect(account.refreshToken).toBeTruthy();

    const csrf = await csrfToken(agent);
    const originalSessionId = decodeJwtPayload(account.accessToken).sid;
    const familyId = (await sessionRow(originalSessionId)).family_id;

    // --- 1. a legitimate refresh rotates the cookie -------------------------------------
    const rotated = await agent.post("/api/v1/auth/refresh").set("X-CSRF-Token", csrf);
    expect(rotated.status).toBe(200);

    const rotatedCookie = getCookie(rotated, "refresh_token");
    expect(rotatedCookie).toBeTruthy();
    expect(rotatedCookie).not.toBe(account.refreshToken);

    const rotatedAccessToken = rotated.body.accessToken as string;
    const rotatedSessionId = decodeJwtPayload(rotatedAccessToken).sid;
    expect(rotatedSessionId).not.toBe(originalSessionId);

    // The predecessor is closed and points at its successor; both live in the same family.
    const predecessor = await sessionRow(originalSessionId);
    expect(predecessor.revoked_at).not.toBeNull();
    expect(predecessor.revoked_reason).toBe("rotated");
    expect(predecessor.replaced_by).toBe(rotatedSessionId);
    expect((await sessionRow(rotatedSessionId)).family_id).toBe(familyId);

    const liveBefore = await request(app).get("/api/v1/me").set(bearer(rotatedAccessToken));
    expect(liveBefore.status).toBe(200);

    // --- 2. replaying the ORIGINAL cookie is reuse --------------------------------------
    const replay = await request(app)
      .post("/api/v1/auth/refresh")
      .set("Cookie", cookieHeader({ refresh_token: account.refreshToken, csrf_token: csrf }))
      .set("X-CSRF-Token", csrf);

    expect(replay.status).toBe(401);
    expect(errorCode(replay)).toBe("SESSION_REVOKED");
    expect(clearsCookie(replay, "refresh_token")).toBe(true);
    // The attacker is not handed a fresh pair on the way out.
    expect(replay.body.accessToken).toBeUndefined();

    // --- 3. the family is burned, including the successor that was still valid ----------
    const burned = await agent.post("/api/v1/auth/refresh").set("X-CSRF-Token", csrf);
    expect(burned.status).toBe(401);
    expect(errorCode(burned)).toBe("SESSION_REVOKED");
    expect(burned.body.accessToken).toBeUndefined();

    // The access token minted by the good refresh dies with its session, not on its own TTL.
    const liveAfter = await request(app).get("/api/v1/me").set(bearer(rotatedAccessToken));
    expect(liveAfter.status).toBe(401);
    expect(errorCode(liveAfter)).toBe("SESSION_INVALID");

    const family = await familyRows(familyId);
    expect(family).toHaveLength(2);
    expect(family.every((session) => session.revoked_at !== null)).toBe(true);
    expect(family.map((session) => session.revoked_reason)).toEqual(["rotated", "reuse_detected"]);
  });
});

describe("POST /api/v1/auth/logout-all", () => {
  it("revokes every session, so an access token issued earlier returns 401 SESSION_INVALID", async () => {
    const agent = request.agent(app);
    const account = await register(agent);
    const csrf = await csrfToken(agent);

    const before = await request(app).get("/api/v1/me").set(bearer(account.accessToken));
    expect(before.status).toBe(200);

    const res = await agent
      .post("/api/v1/auth/logout-all")
      .set(bearer(account.accessToken))
      .set("X-CSRF-Token", csrf);
    expect(res.status).toBe(204);
    expect(clearsCookie(res, "refresh_token")).toBe(true);

    // The JWT is still cryptographically valid; it is the session behind it that is gone.
    const after = await request(app).get("/api/v1/me").set(bearer(account.accessToken));
    expect(after.status).toBe(401);
    expect(errorCode(after)).toBe("SESSION_INVALID");

    const sessionId = decodeJwtPayload(account.accessToken).sid;
    expect((await sessionRow(sessionId)).revoked_at).not.toBeNull();
    expect((await sessionRow(sessionId)).revoked_reason).toBe("logout_all");

    // The refresh cookie captured before the logout is dead too.
    const replay = await request(app)
      .post("/api/v1/auth/refresh")
      .set("Cookie", cookieHeader({ refresh_token: account.refreshToken, csrf_token: csrf }))
      .set("X-CSRF-Token", csrf);
    expect(replay.status).toBe(401);
    expect(errorCode(replay)).toBe("SESSION_REVOKED");
  });

  it("is refused without the CSRF header, and the session survives the refusal", async () => {
    const agent = request.agent(app);
    const account = await register(agent);
    await csrfToken(agent);

    const forged = await agent.post("/api/v1/auth/logout-all").set(bearer(account.accessToken));
    expect(forged.status).toBe(403);
    expect(errorCode(forged)).toBe("CSRF_FAILED");

    // A cross-site POST must not be able to sign anyone out.
    const still = await request(app).get("/api/v1/me").set(bearer(account.accessToken));
    expect(still.status).toBe(200);
    expect((await sessionRow(decodeJwtPayload(account.accessToken).sid)).revoked_at).toBeNull();
  });
});

describe("POST /api/v1/me/password", () => {
  it("revokes the other devices and leaves the caller's own session signed in", async () => {
    const here = request.agent(app);
    const account = await register(here);
    const currentSessionId = decodeJwtPayload(account.accessToken).sid;

    // A second device signed in to the same account.
    const elsewhere = request.agent(app);
    const other = await login(elsewhere, account.email, VALID_PASSWORD);
    expect(other.res.status).toBe(200);
    const otherSessionId = decodeJwtPayload(other.accessToken).sid;
    expect(otherSessionId).not.toBe(currentSessionId);

    const otherBefore = await request(app).get("/api/v1/me").set(bearer(other.accessToken));
    expect(otherBefore.status).toBe(200);

    const csrf = await csrfToken(here);
    const changed = await here
      .post("/api/v1/me/password")
      .set(bearer(account.accessToken))
      .set("X-CSRF-Token", csrf)
      .send({ currentPassword: VALID_PASSWORD, newPassword: NEW_PASSWORD });
    expect(changed.status).toBe(204);

    // The other device is cut off immediately, with the reason recorded.
    const otherAfter = await request(app).get("/api/v1/me").set(bearer(other.accessToken));
    expect(otherAfter.status).toBe(401);
    expect(errorCode(otherAfter)).toBe("SESSION_INVALID");
    expect((await sessionRow(otherSessionId)).revoked_at).not.toBeNull();
    expect((await sessionRow(otherSessionId)).revoked_reason).toBe("password_changed");

    // The caller's own session row is deliberately spared.
    expect((await sessionRow(currentSessionId)).revoked_at).toBeNull();

    // And it still works end to end: it can rotate, and the token that rotation mints is
    // accepted. (The pre-change access token is deliberately not asserted on — `iat` is
    // second-granular, so whether it outlives the change is a coin flip on the clock.)
    const refreshed = await here.post("/api/v1/auth/refresh").set("X-CSRF-Token", csrf);
    expect(refreshed.status).toBe(200);
    const freshToken = refreshed.body.accessToken as string;

    const me = await request(app).get("/api/v1/me").set(bearer(freshToken));
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(account.email);

    // Exactly one live session remains for this account, and it is the caller's own.
    const sessions = await request(app).get("/api/v1/me/sessions").set(bearer(freshToken));
    expect(sessions.status).toBe(200);
    const listed = sessions.body.sessions as Array<{ id: string; current: boolean }>;
    expect(listed).toHaveLength(1);
    expect(listed[0]?.current).toBe(true);

    // The credential really did change.
    const oldPassword = await login(request.agent(app), account.email, VALID_PASSWORD);
    expect(oldPassword.res.status).toBe(401);
    expect(errorCode(oldPassword.res)).toBe("INVALID_CREDENTIALS");

    const newPassword = await login(request.agent(app), account.email, NEW_PASSWORD);
    expect(newPassword.res.status).toBe(200);
  });

  it("refuses the change when the current password is wrong, and revokes nothing", async () => {
    const here = request.agent(app);
    const account = await register(here);

    const elsewhere = request.agent(app);
    const other = await login(elsewhere, account.email, VALID_PASSWORD);
    expect(other.res.status).toBe(200);
    const otherSessionId = decodeJwtPayload(other.accessToken).sid;

    const csrf = await csrfToken(here);
    const res = await here
      .post("/api/v1/me/password")
      .set(bearer(account.accessToken))
      .set("X-CSRF-Token", csrf)
      .send({ currentPassword: "Definitely-Not-It-8!", newPassword: NEW_PASSWORD });

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("INVALID_CREDENTIALS");

    // A stolen access token alone must not be enough to take over the account.
    const stored = await userRow(account.userId);
    await expect(verifyPassword(stored.password_hash, VALID_PASSWORD)).resolves.toBe(true);
    await expect(verifyPassword(stored.password_hash, NEW_PASSWORD)).resolves.toBe(false);
    expect((await sessionRow(otherSessionId)).revoked_at).toBeNull();

    const otherStillWorks = await request(app).get("/api/v1/me").set(bearer(other.accessToken));
    expect(otherStillWorks.status).toBe(200);
  });
});

describe("account lockout", () => {
  it("locks after five failed sign-ins and answers 423 even to the correct password", async () => {
    const email = uniqueEmail("lock");
    const created = await register(request.agent(app), { email });
    expect(created.res.status).toBe(201);

    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const failure = await login(request.agent(app), email, "Nope-Not-Even-Close-7!");
      // Every attempt below the threshold looks identical to the caller: no hint that a
      // counter is filling up, and no hint that the account exists.
      expect(failure.res.status).toBe(401);
      expect(errorCode(failure.res)).toBe("INVALID_CREDENTIALS");
      expect(failure.res.body.error.details).toBeUndefined();
    }

    const locked = await login(request.agent(app), email, VALID_PASSWORD);
    expect(locked.res.status).toBe(423);
    expect(errorCode(locked.res)).toBe("ACCOUNT_LOCKED");

    const retryAfterSeconds = locked.res.body.error.details.retryAfterSeconds as number;
    expect(typeof retryAfterSeconds).toBe("number");
    expect(retryAfterSeconds).toBeGreaterThan(0);
    expect(retryAfterSeconds).toBeLessThanOrEqual(15 * 60);

    // The correct password is rejected without minting anything.
    expect(locked.res.body.accessToken).toBeUndefined();
    expect(getCookie(locked.res, "refresh_token")).toBeUndefined();

    const row = await userRow(created.userId);
    expect(row.failed_attempts).toBe(5);
    expect(row.locked_until).not.toBeNull();
    expect(row.locked_until as number).toBeGreaterThan(Date.now());
  });
});

describe("account enumeration", () => {
  it("answers an unknown email exactly as it answers a wrong password", async () => {
    const account = await register(request.agent(app), { name: TEST_NAME });
    const attempted = "Definitely-Not-It-8!";

    const wrongPassword = await login(request.agent(app), account.email, attempted);
    const unknownEmail = await login(request.agent(app), uniqueEmail("ghost"), attempted);

    expect(wrongPassword.res.status).toBe(401);
    expect(errorCode(wrongPassword.res)).toBe("INVALID_CREDENTIALS");
    expect(unknownEmail.res.status).toBe(401);
    expect(errorCode(unknownEmail.res)).toBe("INVALID_CREDENTIALS");

    // Byte-identical bodies once the per-request id — the only field allowed to differ — is
    // normalised away. Anything else (a different message, a `details` array, even a length
    // difference) would be an oracle for "this address is registered".
    const strip = (text: string): string => text.replace(/"requestId":"[^"]*"/, '"requestId":""');
    expect(strip(unknownEmail.res.text)).toBe(strip(wrongPassword.res.text));
    expect(unknownEmail.res.body.error).toEqual(wrongPassword.res.body.error);

    // Neither answer leaks a session, and neither echoes the credentials it was handed.
    for (const res of [wrongPassword.res, unknownEmail.res]) {
      expect(getCookie(res, "refresh_token")).toBeUndefined();
      expect(res.text).not.toContain(attempted);
      expect(res.text).not.toContain(account.email);
    }
  });
});
