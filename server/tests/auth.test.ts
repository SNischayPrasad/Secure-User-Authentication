import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import {
  bearer,
  clearsCookie,
  csrfToken,
  decodeJwtPayload,
  errorCode,
  getCookie,
  login,
  makeApp,
  register,
  TEST_NAME,
  uniqueEmail,
  VALID_PASSWORD,
  type TestApp,
} from "./helpers.js";

let app: TestApp;

beforeAll(async () => {
  app = await makeApp();
});

describe("POST /api/v1/auth/register", () => {
  it("creates the account, returns 201 with the public user and an access token", async () => {
    const agent = request.agent(app);
    const account = await register(agent);

    expect(account.res.status).toBe(201);

    const body = account.res.body;
    expect(typeof body.accessToken).toBe("string");
    expect(body.accessToken.split(".")).toHaveLength(3);
    expect(typeof body.expiresIn).toBe("number");
    expect(body.expiresIn).toBeGreaterThan(0);

    expect(body.user).toMatchObject({
      email: account.email,
      name: TEST_NAME,
      role: "user",
    });
    expect(typeof body.user.id).toBe("string");
    expect(body.user.id.startsWith("usr_")).toBe(true);
    expect(typeof body.user.createdAt).toBe("number");
    expect(typeof body.user.passwordChangedAt).toBe("number");

    const claims = decodeJwtPayload(account.accessToken);
    expect(claims.typ).toBe("access");
    expect(claims.sub).toBe(body.user.id);
    expect(claims.email).toBe(account.email);
    expect(claims.sid.startsWith("ses_")).toBe(true);

    // A refresh cookie must be issued alongside the access token.
    expect(account.refreshToken).toBeTruthy();
  });

  it("never serialises any password material", async () => {
    const agent = request.agent(app);
    const account = await register(agent);

    expect(account.res.status).toBe(201);

    const userKeys = Object.keys(account.res.body.user);
    // `passwordChangedAt` is the only key in PublicUser that may mention a password.
    expect(userKeys.filter((key) => /password/i.test(key))).toEqual(["passwordChangedAt"]);
    expect(userKeys.some((key) => /hash|salt|secret/i.test(key))).toBe(false);

    expect(account.res.text).not.toContain(VALID_PASSWORD);
    expect(account.res.text).not.toContain("argon2");
    expect(account.res.text).not.toContain("password_hash");
  });

  it("rejects a duplicate email with 409 EMAIL_TAKEN", async () => {
    const email = uniqueEmail("dupe");

    const first = await register(request.agent(app), { email });
    expect(first.res.status).toBe(201);

    const second = await register(request.agent(app), { email });
    expect(second.res.status).toBe(409);
    expect(errorCode(second.res)).toBe("EMAIL_TAKEN");
    expect(second.res.body.error.message).toEqual(expect.any(String));
    expect(getCookie(second.res, "refresh_token")).toBeUndefined();
  });
});

describe("POST /api/v1/auth/login", () => {
  it("returns 200 with a user, an access token and a refresh cookie", async () => {
    const account = await register(request.agent(app));

    const client = request.agent(app);
    const { res, accessToken, refreshToken } = await login(client, account.email, VALID_PASSWORD);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(account.email);
    expect(res.body.user.id).toBe(account.userId);
    expect(typeof accessToken).toBe("string");
    expect(accessToken.split(".")).toHaveLength(3);
    expect(typeof res.body.expiresIn).toBe("number");
    expect(refreshToken).toBeTruthy();
    expect(res.text).not.toContain(VALID_PASSWORD);

    // The token minted by login is immediately usable on the protected endpoint.
    const me = await request(app).get("/api/v1/me").set(bearer(accessToken));
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(account.email);
  });

  it("rejects a wrong password with 401 INVALID_CREDENTIALS and issues no session", async () => {
    const account = await register(request.agent(app));

    const client = request.agent(app);
    const { res } = await login(client, account.email, "Definitely-Not-It-8!");

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("INVALID_CREDENTIALS");
    expect(getCookie(res, "refresh_token")).toBeUndefined();
  });

  it("answers an unknown email exactly as it answers a wrong password (no user enumeration)", async () => {
    const account = await register(request.agent(app));
    const attemptedPassword = "Definitely-Not-It-8!";

    const wrongPassword = await login(request.agent(app), account.email, attemptedPassword);
    const unknownEmail = await login(request.agent(app), uniqueEmail("ghost"), attemptedPassword);

    expect(wrongPassword.res.status).toBe(401);
    expect(errorCode(wrongPassword.res)).toBe("INVALID_CREDENTIALS");

    expect(unknownEmail.res.status).toBe(401);
    expect(errorCode(unknownEmail.res)).toBe("INVALID_CREDENTIALS");

    // Identical error object — only the per-request id may differ between the two responses.
    expect(unknownEmail.res.body.error).toEqual(wrongPassword.res.body.error);
    expect(unknownEmail.res.status).toBe(wrongPassword.res.status);
  });
});

describe("POST /api/v1/auth/logout", () => {
  it("returns 204 and clears the refresh cookie", async () => {
    const agent = request.agent(app);
    await register(agent);
    const csrf = await csrfToken(agent);

    const res = await agent.post("/api/v1/auth/logout").set("X-CSRF-Token", csrf);

    expect(res.status).toBe(204);
    expect(res.body).toEqual({});
    expect(clearsCookie(res, "refresh_token")).toBe(true);
  });
});

describe("POST /api/v1/auth/refresh", () => {
  it("rotates the refresh cookie and returns a new access token bound to the new session", async () => {
    const agent = request.agent(app);
    const account = await register(agent);
    const csrf = await csrfToken(agent);

    const res = await agent.post("/api/v1/auth/refresh").set("X-CSRF-Token", csrf);

    expect(res.status).toBe(200);
    expect(typeof res.body.accessToken).toBe("string");
    expect(typeof res.body.expiresIn).toBe("number");
    expect(res.body.accessToken).not.toBe(account.accessToken);

    const rotated = getCookie(res, "refresh_token");
    expect(rotated).toBeTruthy();
    expect(rotated).not.toBe(account.refreshToken);

    const before = decodeJwtPayload(account.accessToken);
    const after = decodeJwtPayload(res.body.accessToken);
    expect(after.sid).not.toBe(before.sid);
    expect(after.sub).toBe(before.sub);

    const me = await request(app).get("/api/v1/me").set(bearer(res.body.accessToken));
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(account.email);
  });

  it("rejects a refresh with no cookie at all with 401 SESSION_INVALID", async () => {
    const agent = request.agent(app);
    const csrf = await csrfToken(agent);

    const res = await agent.post("/api/v1/auth/refresh").set("X-CSRF-Token", csrf);

    expect(res.status).toBe(401);
    expect(errorCode(res)).toBe("SESSION_INVALID");
  });
});
