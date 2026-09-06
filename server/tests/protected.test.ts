import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import {
  bearer,
  csrfToken,
  decodeJwtPayload,
  errorCode,
  makeApp,
  register,
  TEST_NAME,
  VALID_PASSWORD,
  type TestApp,
} from "./helpers.js";

let app: TestApp;

beforeAll(async () => {
  app = await makeApp();
});

/**
 * Every key name that appears anywhere in a JSON value, however deeply nested. Used to prove a
 * response body carries no password material at *any* depth, not merely at the top level.
 */
function deepKeys(value: unknown, seen: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const entry of value) deepKeys(entry, seen);
    return seen;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      seen.push(key);
      deepKeys(nested, seen);
    }
  }
  return seen;
}

/** Registers an account on its own agent and returns the agent alongside the credentials. */
async function accountWithAgent() {
  const agent = request.agent(app);
  const account = await register(agent);
  expect(account.res.status).toBe(201);
  expect(account.accessToken).toBeTruthy();
  return { agent, account };
}

/** Creates one vault item for the agent's account, asserting the write actually succeeded. */
async function createItem(agent: ReturnType<typeof request.agent>, accessToken: string, title: string) {
  const csrf = await csrfToken(agent);
  const res = await agent
    .post("/api/v1/vault")
    .set(bearer(accessToken))
    .set("X-CSRF-Token", csrf)
    .send({ title, body: `body for ${title}` });

  expect(res.status).toBe(201);
  expect(typeof res.body.item.id).toBe("string");
  return { csrf, id: res.body.item.id as string, res };
}

describe("GET /api/v1/me", () => {
  it("rejects a request with no Authorization header with 401 AUTH_REQUIRED", async () => {
    const res = await request(app).get("/api/v1/me");

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("AUTH_REQUIRED");
    expect(res.body.error.message).toEqual(expect.any(String));
    expect(typeof res.body.requestId).toBe("string");
    // A rejected request must not hand back any part of a user record.
    expect(res.body.user).toBeUndefined();
  });

  it("rejects a syntactically broken bearer token with 401 TOKEN_INVALID", async () => {
    const res = await request(app).get("/api/v1/me").set("Authorization", "Bearer garbage.token.here");

    expect(res.status).toBe(401);
    // Distinct from AUTH_REQUIRED: a credential was presented, it just does not verify.
    expect(errorCode(res)).toBe("TOKEN_INVALID");
    expect(res.body.user).toBeUndefined();
  });

  it("returns 200 and the caller's own public user for a valid token", async () => {
    const { account } = await accountWithAgent();

    const res = await request(app).get("/api/v1/me").set(bearer(account.accessToken));

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(account.email);
    expect(res.body.user.id).toBe(account.userId);
    expect(res.body.user.name).toBe(TEST_NAME);
    expect(res.body.user.role).toBe("user");

    // The user the token names, not merely *a* user.
    const claims = decodeJwtPayload(account.accessToken);
    expect(res.body.user.id).toBe(claims.sub);
    expect(res.body.user.email).toBe(claims.email);
  });

  it("never serialises password material at any depth of the response", async () => {
    const { account } = await accountWithAgent();

    const res = await request(app).get("/api/v1/me").set(bearer(account.accessToken));

    expect(res.status).toBe(200);

    // Raw-text check first: catches the hash appearing under any key name at all.
    expect(res.text).not.toMatch(/password_hash|passwordHash/i);
    expect(res.text).not.toContain("argon2");
    expect(res.text).not.toContain(VALID_PASSWORD);

    // Then the key names, recursively. `passwordChangedAt` is the only permitted mention.
    const keys = deepKeys(res.body);
    expect(keys.filter((key) => /password/i.test(key))).toEqual(["passwordChangedAt"]);
    expect(keys.filter((key) => /hash|salt|secret|argon/i.test(key))).toEqual([]);
  });
});

describe("GET /api/v1/vault", () => {
  it("rejects an unauthenticated request with 401 AUTH_REQUIRED", async () => {
    const res = await request(app).get("/api/v1/vault");

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("AUTH_REQUIRED");
    expect(res.body.items).toBeUndefined();
  });

  it("returns 200 with the caller's items for a valid token", async () => {
    const { agent, account } = await accountWithAgent();

    const empty = await request(app).get("/api/v1/vault").set(bearer(account.accessToken));
    expect(empty.status).toBe(200);
    expect(empty.body.items).toEqual([]);

    const created = await createItem(agent, account.accessToken, "First note");

    const listed = await request(app).get("/api/v1/vault").set(bearer(account.accessToken));
    expect(listed.status).toBe(200);
    expect(Array.isArray(listed.body.items)).toBe(true);
    expect(listed.body.items).toHaveLength(1);
    expect(listed.body.items[0]).toMatchObject({ id: created.id, title: "First note" });
    // The response is the public shape: camelCase timestamps, and no internal columns.
    expect(typeof listed.body.items[0].createdAt).toBe("number");
    expect(typeof listed.body.items[0].updatedAt).toBe("number");
    // `user_id` is never serialised. The listing is already ownership-scoped, so echoing the
    // owner back would only hand a caller an internal identifier it has no use for.
    expect(listed.body.items[0]).not.toHaveProperty("user_id");
    expect(listed.body.items[0]).not.toHaveProperty("userId");
    expect(Object.keys(listed.body.items[0]).sort()).toEqual([
      "body",
      "createdAt",
      "id",
      "title",
      "updatedAt",
    ]);
  });
});

describe("Vault tenant isolation", () => {
  it("never lists one account's item in another account's vault", async () => {
    const alice = await accountWithAgent();
    const aliceItem = await createItem(alice.agent, alice.account.accessToken, "Alice private note");

    const bob = await accountWithAgent();

    const bobVault = await request(app).get("/api/v1/vault").set(bearer(bob.account.accessToken));
    expect(bobVault.status).toBe(200);
    expect(bobVault.body.items).toEqual([]);
    expect(bobVault.text).not.toContain(aliceItem.id);
    expect(bobVault.text).not.toContain("Alice private note");

    // The item is genuinely there — Bob's empty vault is isolation, not a lost write.
    const aliceVault = await request(app).get("/api/v1/vault").set(bearer(alice.account.accessToken));
    expect(aliceVault.status).toBe(200);
    expect(aliceVault.body.items.map((item: { id: string }) => item.id)).toEqual([aliceItem.id]);
  });

  it("answers 404 NOT_FOUND — never 403 — when deleting another account's item", async () => {
    const alice = await accountWithAgent();
    const aliceItem = await createItem(alice.agent, alice.account.accessToken, "Alice deletable note");

    const bob = await accountWithAgent();
    const bobCsrf = await csrfToken(bob.agent);

    const stolen = await bob.agent
      .delete(`/api/v1/vault/${aliceItem.id}`)
      .set(bearer(bob.account.accessToken))
      .set("X-CSRF-Token", bobCsrf);

    // 403 would confirm the id exists; 404 is the only answer that leaks nothing.
    expect(stolen.status).toBe(404);
    expect(stolen.status).not.toBe(403);
    expect(errorCode(stolen)).toBe("NOT_FOUND");

    // An id that never existed must be indistinguishable from one Bob simply does not own.
    const bogus = await bob.agent
      .delete("/api/v1/vault/itm_thisidhasneverexisted")
      .set(bearer(bob.account.accessToken))
      .set("X-CSRF-Token", bobCsrf);

    expect(bogus.status).toBe(404);
    expect(errorCode(bogus)).toBe("NOT_FOUND");
    // Byte-identical error objects; only the top-level requestId may differ.
    expect(stolen.body.error).toEqual(bogus.body.error);

    // Alice's item survived Bob's attempt, and is deletable by its real owner — which proves
    // the 404 above was an ownership decision rather than a missing row.
    const stillThere = await request(app).get("/api/v1/vault").set(bearer(alice.account.accessToken));
    expect(stillThere.status).toBe(200);
    expect(stillThere.body.items.map((item: { id: string }) => item.id)).toContain(aliceItem.id);

    const ownDelete = await alice.agent
      .delete(`/api/v1/vault/${aliceItem.id}`)
      .set(bearer(alice.account.accessToken))
      .set("X-CSRF-Token", aliceItem.csrf);
    expect(ownDelete.status).toBe(204);
  });
});

describe("GET /api/v1/me/sessions", () => {
  it("rejects an unauthenticated request with 401 AUTH_REQUIRED", async () => {
    const res = await request(app).get("/api/v1/me/sessions");

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("AUTH_REQUIRED");
    expect(res.body.sessions).toBeUndefined();
  });

  it("returns 200 and flags exactly one session as the current one", async () => {
    const { account } = await accountWithAgent();

    const res = await request(app).get("/api/v1/me/sessions").set(bearer(account.accessToken));

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.sessions)).toBe(true);
    expect(res.body.sessions.length).toBeGreaterThanOrEqual(1);

    const current = res.body.sessions.filter((session: { current: boolean }) => session.current);
    expect(current).toHaveLength(1);

    // The flagged session is the one the presented access token is actually bound to.
    const claims = decodeJwtPayload(account.accessToken);
    expect(current[0].id).toBe(claims.sid);
    expect(typeof current[0].createdAt).toBe("number");
    expect(current[0].expiresAt).toBeGreaterThan(Date.now());

    // Session listings must not carry the opaque refresh token or its digest.
    expect(res.text).not.toMatch(/token_hash|tokenHash/i);
    if (account.refreshToken) expect(res.text).not.toContain(account.refreshToken);
  });
});

describe("GET /api/v1/me/activity", () => {
  it("rejects an unauthenticated request with 401 AUTH_REQUIRED", async () => {
    const res = await request(app).get("/api/v1/me/activity");

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("AUTH_REQUIRED");
    expect(res.body.events).toBeUndefined();
  });

  it("returns 200 with only the caller's own audit events", async () => {
    const { account } = await accountWithAgent();

    const res = await request(app).get("/api/v1/me/activity").set(bearer(account.accessToken));

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.events)).toBe(true);

    const events = res.body.events as Array<{ userId: string; type: string; outcome: string }>;
    // Registering is itself an auditable event, so the trail is never empty here.
    expect(events.some((event) => event.type === "register" && event.outcome === "success")).toBe(true);
    // Tenant isolation on the audit trail: no other account's rows may appear.
    expect(events.every((event) => event.userId === account.userId)).toBe(true);
    expect(events.length).toBeLessThanOrEqual(50);
  });
});
