import { beforeAll, describe, expect, it } from "vitest";
import request from "supertest";
import type { Response } from "supertest";
import {
  bearer,
  csrfToken,
  errorCode,
  getCookie,
  makeApp,
  register,
  TEST_NAME,
  uniqueEmail,
  VALID_PASSWORD,
  WEAK_PASSWORD,
  type TestApp,
} from "./helpers.js";

/**
 * Input validation, error codes and the shape of the error envelope.
 *
 * Everything below asserts on BOTH halves of the contract: the HTTP status AND the stable
 * `error.code` string, because a client switches on the code and a status alone would let a
 * 400 `VALIDATION_FAILED` silently become a 400 `WEAK_PASSWORD` without a test noticing.
 */

let app: TestApp;

beforeAll(async () => {
  app = await makeApp();
});

/** One entry of the `error.details` array the validator and the password policy both emit. */
type Detail = { field: string; message: string };

/** Reads `error.details` as the `[{ field, message }]` array, or `[]` when the envelope omits it. */
function details(res: Response): Detail[] {
  const body = res.body as { error?: { details?: unknown } } | undefined;
  const raw = body?.error?.details;
  return Array.isArray(raw) ? (raw as Detail[]) : [];
}

/** The distinct field names named by `error.details`. */
function detailFields(res: Response): string[] {
  return [...new Set(details(res).map((detail) => detail.field))];
}

/** Every `error.details` message joined, for asserting that a specific reason was reported. */
function detailMessages(res: Response): string {
  return details(res)
    .map((detail) => detail.message)
    .join(" | ");
}

/** Server-minted correlation id: the `req_` prefix plus 21 characters of `newId`'s base32 alphabet. */
const REQUEST_ID_PATTERN = /^req_[0-9A-Z]{21}$/;

describe("POST /api/v1/auth/register — body shape", () => {
  it("rejects an empty body with 400 VALIDATION_FAILED naming every missing field", async () => {
    const res = await request(app).post("/api/v1/auth/register").send({});

    expect(res.status).toBe(400);
    expect(errorCode(res)).toBe("VALIDATION_FAILED");
    expect(res.body.error.message).toEqual(expect.any(String));

    // The contract promises the caller is told *which* fields are wrong, not merely that
    // something is: all three required fields must be named in one response.
    expect(Array.isArray(res.body.error.details)).toBe(true);
    expect(detailFields(res)).toEqual(expect.arrayContaining(["name", "email", "password"]));
    for (const detail of details(res)) {
      expect(typeof detail.field).toBe("string");
      expect(detail.message.length).toBeGreaterThan(0);
    }

    // A rejected registration must not start a session.
    expect(getCookie(res, "refresh_token")).toBeUndefined();
    expect(res.body.accessToken).toBeUndefined();
  });

  it("rejects an invalid email address with 400 VALIDATION_FAILED naming email", async () => {
    const invalidEmails = ["not-an-email", "missing-at.example.test", "@example.test", "user@"];

    for (const email of invalidEmails) {
      const res = await request(app)
        .post("/api/v1/auth/register")
        .send({ name: TEST_NAME, email, password: VALID_PASSWORD });

      expect(res.status, `email ${JSON.stringify(email)}`).toBe(400);
      expect(errorCode(res), `email ${JSON.stringify(email)}`).toBe("VALIDATION_FAILED");
      expect(detailFields(res)).toContain("email");
      expect(getCookie(res, "refresh_token")).toBeUndefined();
      // The shape check runs before the policy check, so this must never be reported as weak.
      expect(errorCode(res)).not.toBe("WEAK_PASSWORD");
    }
  });

  it("reports only the field that is actually missing", async () => {
    const res = await request(app)
      .post("/api/v1/auth/register")
      .send({ name: TEST_NAME, email: uniqueEmail("partial") });

    expect(res.status).toBe(400);
    expect(errorCode(res)).toBe("VALIDATION_FAILED");
    expect(detailFields(res)).toEqual(["password"]);
  });
});

describe("POST /api/v1/auth/register — password policy", () => {
  it('rejects "password123" with 400 WEAK_PASSWORD and lists the user-facing issues', async () => {
    const res = await request(app)
      .post("/api/v1/auth/register")
      .send({ name: TEST_NAME, email: uniqueEmail("weak"), password: WEAK_PASSWORD });

    expect(res.status).toBe(400);
    expect(errorCode(res)).toBe("WEAK_PASSWORD");

    // A weak password is a *policy* failure, not a shape failure — the codes must not blur.
    expect(errorCode(res)).not.toBe("VALIDATION_FAILED");

    // Every issue is attributed to `password` so a form can render them under that input.
    expect(details(res).length).toBeGreaterThan(0);
    expect(detailFields(res)).toEqual(["password"]);

    // "password123" is short, uses two character classes and is a breach-list entry; the
    // caller is told all of that at once rather than one reason per round trip.
    const messages = detailMessages(res);
    expect(messages).toMatch(/at least 12 characters/i);
    expect(messages).toMatch(/lowercase|uppercase|numbers|symbols/i);
    expect(messages).toMatch(/breach/i);

    expect(getCookie(res, "refresh_token")).toBeUndefined();
    // The rejected secret is never echoed back to the caller.
    expect(res.text).not.toContain(WEAK_PASSWORD);
  });

  it("rejects a password built from the email local-part with 400 WEAK_PASSWORD", async () => {
    // Satisfies length and all four character classes, so the ONLY thing wrong with it is that
    // it contains the local-part of the address being registered.
    const password = "Peregrine#Vault8x";

    const res = await request(app)
      .post("/api/v1/auth/register")
      .send({ name: TEST_NAME, email: "peregrine@example.test", password });

    expect(res.status).toBe(400);
    expect(errorCode(res)).toBe("WEAK_PASSWORD");
    expect(detailFields(res)).toEqual(["password"]);
    expect(detailMessages(res)).toMatch(/email/i);
    expect(getCookie(res, "refresh_token")).toBeUndefined();

    // Control: the identical password is accepted against an unrelated address, which proves
    // the rejection above came from the email rule and not from generic weakness.
    const control = await register(request.agent(app), {
      email: uniqueEmail("unrelated"),
      password,
    });
    expect(control.res.status).toBe(201);
    expect(control.accessToken.split(".")).toHaveLength(3);
  });
});

describe("Malformed request bodies", () => {
  it("rejects a body that is not valid JSON with 400 MALFORMED_JSON", async () => {
    const malformedBodies = ["{oops", '{"email": ', "[1, 2,"];

    for (const body of malformedBodies) {
      const res = await request(app)
        .post("/api/v1/auth/register")
        .set("Content-Type", "application/json")
        .send(body);

      expect(res.status, `body ${JSON.stringify(body)}`).toBe(400);
      expect(errorCode(res), `body ${JSON.stringify(body)}`).toBe("MALFORMED_JSON");
      expect(res.body.error.message).toEqual(expect.any(String));
      // Body-parser failures go through the same envelope as everything else — never HTML,
      // never a stack trace.
      expect(res.body.error.stack).toBeUndefined();
      expect(typeof res.body.requestId).toBe("string");
    }
  });
});

describe("Unknown routes", () => {
  it("answers an unknown /api/v1 path with 404 ROUTE_NOT_FOUND in the JSON envelope", async () => {
    const res = await request(app).get("/api/v1/does-not-exist");

    expect(res.status).toBe(404);
    expect(errorCode(res)).toBe("ROUTE_NOT_FOUND");
    expect(res.body.error.message).toEqual(expect.any(String));
    // Express's default 404 is an HTML page that leaks the framework; ours must be JSON.
    expect(res.type).toBe("application/json");
    expect(res.text).not.toMatch(/<html|<pre/i);
  });

  it("answers an unsupported method on a known path with 404 ROUTE_NOT_FOUND", async () => {
    // /auth/csrf exists for GET only, so a POST falls through to the terminal /api handler.
    const res = await request(app).post("/api/v1/auth/csrf").send({});

    expect(res.status).toBe(404);
    expect(errorCode(res)).toBe("ROUTE_NOT_FOUND");
  });
});

describe("CSRF enforcement", () => {
  it("rejects a mutating request that carries no X-CSRF-Token header with 403 CSRF_FAILED", async () => {
    const res = await request(app).post("/api/v1/auth/logout").send({});

    expect(res.status).toBe(403);
    expect(errorCode(res)).toBe("CSRF_FAILED");
  });

  it("rejects a mutating request whose header does not match the cookie with 403 CSRF_FAILED", async () => {
    const agent = request.agent(app);
    const token = await csrfToken(agent);
    expect(token.length).toBeGreaterThan(0);

    // The agent is holding the real csrf_token cookie; only the echoed header is wrong.
    const res = await agent
      .post("/api/v1/auth/logout")
      .set("X-CSRF-Token", `${token}-tampered`)
      .send({});

    expect(res.status).toBe(403);
    expect(errorCode(res)).toBe("CSRF_FAILED");
  });

  it("blocks an authenticated write without the header and allows it once the header matches", async () => {
    const agent = request.agent(app);
    const account = await register(agent);
    expect(account.res.status).toBe(201);
    const token = await csrfToken(agent);

    const payload = { title: "CSRF check", body: "Written by validation.test.ts" };

    // A valid bearer token is not sufficient: the double-submit header is still required.
    const blocked = await agent.post("/api/v1/vault").set(bearer(account.accessToken)).send(payload);

    expect(blocked.status).toBe(403);
    expect(errorCode(blocked)).toBe("CSRF_FAILED");

    // Control: the identical request succeeds with the header echoing the cookie, so the 403
    // above is the CSRF check firing and not a broken request.
    const allowed = await agent
      .post("/api/v1/vault")
      .set(bearer(account.accessToken))
      .set("X-CSRF-Token", token)
      .send(payload);

    expect(allowed.status).toBe(201);
    expect(allowed.body.item).toMatchObject({ title: payload.title, body: payload.body });
  });
});

describe("Error envelope", () => {
  it("returns X-Request-Id and a matching requestId on every error response", async () => {
    const account = await register(request.agent(app));
    expect(account.res.status).toBe(201);

    const failures: Array<{ label: string; status: number; code: string; res: Response }> = [];

    const cases: Array<{ label: string; status: number; code: string; send: () => Promise<Response> }> = [
      {
        label: "400 VALIDATION_FAILED",
        status: 400,
        code: "VALIDATION_FAILED",
        send: () => request(app).post("/api/v1/auth/register").send({}),
      },
      {
        label: "400 WEAK_PASSWORD",
        status: 400,
        code: "WEAK_PASSWORD",
        send: () =>
          request(app)
            .post("/api/v1/auth/register")
            .send({ name: TEST_NAME, email: uniqueEmail("envelope"), password: WEAK_PASSWORD }),
      },
      {
        label: "400 MALFORMED_JSON",
        status: 400,
        code: "MALFORMED_JSON",
        send: () =>
          request(app)
            .post("/api/v1/auth/register")
            .set("Content-Type", "application/json")
            .send("{not json"),
      },
      {
        label: "401 AUTH_REQUIRED",
        status: 401,
        code: "AUTH_REQUIRED",
        send: () => request(app).get("/api/v1/me"),
      },
      {
        label: "401 TOKEN_INVALID",
        status: 401,
        code: "TOKEN_INVALID",
        send: () => request(app).get("/api/v1/me").set(bearer("garbage.token.here")),
      },
      {
        label: "403 CSRF_FAILED",
        status: 403,
        code: "CSRF_FAILED",
        send: () => request(app).post("/api/v1/auth/logout").send({}),
      },
      {
        label: "404 ROUTE_NOT_FOUND",
        status: 404,
        code: "ROUTE_NOT_FOUND",
        send: () => request(app).get("/api/v1/nope"),
      },
      {
        label: "409 EMAIL_TAKEN",
        status: 409,
        code: "EMAIL_TAKEN",
        send: () =>
          request(app)
            .post("/api/v1/auth/register")
            .send({ name: TEST_NAME, email: account.email, password: VALID_PASSWORD }),
      },
    ];

    for (const testCase of cases) {
      const res = await testCase.send();
      failures.push({ ...testCase, res });
    }

    const seen = new Set<string>();

    for (const { label, status, code, res } of failures) {
      expect(res.status, label).toBe(status);
      expect(errorCode(res), label).toBe(code);

      const header = res.headers["x-request-id"];
      expect(header, label).toMatch(REQUEST_ID_PATTERN);

      // The body's requestId is the same id the header carries, so a user quoting either one
      // from a bug report points at exactly one line in the server log.
      expect(res.body.requestId, label).toBe(header);
      expect(res.body.error.message, label).toEqual(expect.any(String));
      expect((res.body.error.message as string).length, label).toBeGreaterThan(0);

      // Ids are per-request, never reused across responses.
      expect(seen.has(header as string), `${label} reused a request id`).toBe(false);
      seen.add(header as string);
    }

    expect(seen.size).toBe(cases.length);
  });

  it("mints the request id server-side instead of echoing one supplied by the caller", async () => {
    const forged = "req_FORGEDBYTHECLIENT000";

    const res = await request(app)
      .get("/api/v1/does-not-exist")
      .set("X-Request-Id", forged);

    expect(res.status).toBe(404);
    expect(errorCode(res)).toBe("ROUTE_NOT_FOUND");
    // A caller-controlled id would let an attacker collide with (or poison) another request's
    // audit trail, so the value on the way out must be freshly generated.
    expect(res.headers["x-request-id"]).not.toBe(forged);
    expect(res.headers["x-request-id"]).toMatch(REQUEST_ID_PATTERN);
    expect(res.body.requestId).toBe(res.headers["x-request-id"]);
  });
});
