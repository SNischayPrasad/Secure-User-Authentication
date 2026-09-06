# API reference

Base URL `http://localhost:4000`. Everything below `/api/v1` unless stated otherwise.
All bodies are JSON. Every response carries an `X-Request-Id` header.

Every example here was captured from a running server.

---

## Conventions

### Authentication

| Marker | Meaning |
|---|---|
| — | Public |
| **bearer** | `Authorization: Bearer <access token>` |
| **cookie** | The httpOnly `refresh_token` cookie, sent automatically by the browser |
| **csrf** | `X-CSRF-Token` header echoing the readable `csrf_token` cookie |

Every mutating request needs **csrf** except `POST /auth/register` and `POST /auth/login`,
which have no cookie to protect yet.

### The user object

The only user shape ever serialised. No password field of any kind appears in any response.

```json
{
  "id": "usr_CEP6T22Z7RBHH27CZKCSX",
  "email": "ada@example.com",
  "name": "Ada Lovelace",
  "role": "user",
  "createdAt": 1788687915853,
  "passwordChangedAt": 1788687915853
}
```

Timestamps are epoch milliseconds. Ids are prefixed: `usr_` users, `ses_` sessions,
`itm_` vault items, `evt_` audit events, `req_` requests.

### The error envelope

Every failure, including `404` and `500`:

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Check the fields listed in details and try again.",
    "details": [
      { "field": "name", "message": "Name is required." },
      { "field": "email", "message": "Email is required." }
    ]
  },
  "requestId": "req_NYWRDEABV3SSPRVZQCKGB"
}
```

`details` is present for `VALIDATION_FAILED` and `WEAK_PASSWORD`, and carries
`retryAfterSeconds` for `ACCOUNT_LOCKED`.

### Cookies

| Cookie | Flags | Scope |
|---|---|---|
| `refresh_token` | `HttpOnly; SameSite=Strict; Secure` (production) | `/api/v1/auth` |
| `csrf_token` | `SameSite=Strict; Secure` (production), readable by script **by design** | `/` |

---

## Service

### `GET /api/health`

Outside the versioned prefix, so uptime checks do not break on a version bump.

**200**

```json
{ "status": "ok", "uptime": 3.992, "version": "1.0.0", "time": "2026-09-06T09:27:30.224Z" }
```

---

## Authentication

### `GET /api/v1/auth/csrf`

Mints a CSRF token and sets the readable `csrf_token` cookie. Call once per session, before any
mutating request.

**200**

```json
{ "csrfToken": "yq0Xn2Kp5Yq7Mx1Bz4Cv6Rt8Wn2Kp5Yq7Mx1Bz4Cv6" }
```

---

### `POST /api/v1/auth/register`

**Auth:** — · **Body:**

```json
{ "name": "Ada Lovelace", "email": "ada@example.com", "password": "correct-horse-battery-staple-9" }
```

`email` is trimmed and lowercased. The password must pass the policy: at least 12 characters,
at least three of {lowercase, uppercase, digits, symbols}, not containing the name or the email
local-part, not a known-breached password, and no keyboard or counting runs.

**201** — also sets `refresh_token`.

```json
{
  "user": { "id": "usr_CEP6T22Z7RBHH27CZKCSX", "email": "ada@example.com", "name": "Ada Lovelace",
            "role": "user", "createdAt": 1788687915853, "passwordChangedAt": 1788687915853 },
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…",
  "expiresIn": 900
}
```

| Failure | Code |
|---|---|
| `400` | `VALIDATION_FAILED` — missing or malformed fields |
| `400` | `WEAK_PASSWORD` — `details` lists every rule the password breaks |
| `409` | `EMAIL_TAKEN` |
| `429` | `RATE_LIMITED` |

A `WEAK_PASSWORD` response:

```json
{
  "error": {
    "code": "WEAK_PASSWORD",
    "message": "That password does not meet the policy.",
    "details": [
      { "field": "password", "message": "Use at least 12 characters." },
      { "field": "password", "message": "Mix at least three of these: lowercase letters, uppercase letters, numbers and symbols." },
      { "field": "password", "message": "This password appears in public breach lists. Pick one unrelated to it." }
    ]
  },
  "requestId": "req_C92ZXD10Y1S5QF93TZ4E2"
}
```

---

### `POST /api/v1/auth/login`

**Auth:** — · **Body:** `{ "email": "…", "password": "…" }`

**200** — same body as register, and sets a fresh `refresh_token`.

| Failure | Code | Note |
|---|---|---|
| `400` | `VALIDATION_FAILED` | |
| `401` | `INVALID_CREDENTIALS` | Identical body for a wrong password and an unknown email. An unknown email still runs a full Argon2id verification against a dummy hash, so timing does not distinguish them either. |
| `423` | `ACCOUNT_LOCKED` | After 5 failures. `details.retryAfterSeconds` says when to retry. |
| `429` | `RATE_LIMITED` | |

---

### `POST /api/v1/auth/refresh`

**Auth:** cookie + csrf

Rotates the refresh token and issues a new access token bound to the new session.

**200** — sets a **new** `refresh_token`; the presented one is now retired.

```json
{ "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…", "expiresIn": 900 }
```

| Failure | Code | Note |
|---|---|---|
| `401` | `SESSION_INVALID` | No cookie, unknown token, or expired session |
| `401` | `SESSION_REVOKED` | **A retired token was replayed.** The entire token family is revoked and the cookie cleared. |
| `403` | `CSRF_FAILED` | |

---

### `POST /api/v1/auth/logout`

**Auth:** cookie + csrf · **204**

Revokes the presented session and clears the cookie. Idempotent — still `204` when no cookie
is present, so signing out twice is not an error.

---

### `POST /api/v1/auth/logout-all`

**Auth:** bearer + csrf · **204**

Revokes every session for the account. Access tokens already issued stop working on their next
request, because `authenticate` checks the session behind the token.

---

## Account

All routes below require **bearer**.

### `GET /api/v1/me`

The primary protected endpoint. **200** → `{ "user": { … } }`

| Failure | Code |
|---|---|
| `401` | `AUTH_REQUIRED` — no header |
| `401` | `TOKEN_INVALID` — bad signature, issuer, audience, or algorithm; or the password changed after the token was minted |
| `401` | `TOKEN_EXPIRED` — past `exp`; refresh and retry |
| `401` | `SESSION_INVALID` — the session was revoked |

---

### `PATCH /api/v1/me`

**Auth:** bearer + csrf · **Body:** `{ "name": "Ada Byron" }` · **200** → `{ "user": { … } }`

---

### `POST /api/v1/me/password`

**Auth:** bearer + csrf · **Body:** `{ "currentPassword": "…", "newPassword": "…" }` · **204**

Revokes every session **except** the one making the request, so the person changing the password
stays signed in and every other device is signed out.

| Failure | Code |
|---|---|
| `400` | `WEAK_PASSWORD`, `SAME_PASSWORD`, `VALIDATION_FAILED` |
| `401` | `INVALID_CREDENTIALS` — `currentPassword` wrong |

---

### `GET /api/v1/me/sessions`

**200**

```json
{
  "sessions": [
    {
      "id": "ses_XYXVW6C8MYKFZC9QSDJCX",
      "current": true,
      "userAgent": "Mozilla/5.0 …",
      "ipAddress": "::1",
      "createdAt": 1788687915854,
      "lastUsedAt": 1788687915854,
      "expiresAt": 1789292715854
    }
  ]
}
```

No token material of any kind is included — not even the digest.

---

### `DELETE /api/v1/me/sessions/:id`

**Auth:** bearer + csrf · **204**

`404 NOT_FOUND` if the session is not the caller's — never `403`, which would confirm it exists.

---

### `GET /api/v1/me/activity`

Last 50 audit events, newest first. **200**

```json
{
  "events": [
    {
      "id": "evt_XT2P08546R7CAN7WEBN9K",
      "userId": "usr_CEP6T22Z7RBHH27CZKCSX",
      "emailAttempted": "ada@example.com",
      "type": "register",
      "outcome": "success",
      "detail": null,
      "ipAddress": "::1",
      "userAgent": "Mozilla/5.0 …",
      "createdAt": 1788687915855
    }
  ]
}
```

`type` is one of `register`, `login`, `logout`, `logout_all`, `token_refresh`,
`token_reuse_detected`, `password_change`, `profile_update`, `session_revoked`,
`account_locked`, `rate_limited`.

---

## Vault — the protected resource

Private notes, scoped to the owning account. All routes require **bearer**.
This is the endpoint that demonstrates "returns data only when authenticated".

### `GET /api/v1/vault`

**200**

```json
{
  "items": [
    {
      "id": "itm_AJN3FGF0H7YY6KX5NH627",
      "title": "Recovery codes",
      "body": "Single-use backup codes.",
      "createdAt": 1788687970764,
      "updatedAt": 1788687970764
    }
  ]
}
```

`401 AUTH_REQUIRED` without a token, with no items in the body.

---

### `POST /api/v1/vault`

**Auth:** bearer + csrf · **Body:** `{ "title": "…", "body": "…" }`
(title 1–120 characters, body 1–4000) · **201** → `{ "item": { … } }`

---

### `PATCH /api/v1/vault/:id`

**Auth:** bearer + csrf · **Body:** `{ "title"?: "…", "body"?: "…" }` · **200** → `{ "item": { … } }`

---

### `DELETE /api/v1/vault/:id`

**Auth:** bearer + csrf · **204**

Another account's item id returns `404 NOT_FOUND`, identical to an id that never existed, so the
vault cannot be used to probe for other people's item ids.

---

## Status codes at a glance

| Code | Used for |
|---|---|
| `200` | Read, or an update that returns the new state |
| `201` | Register, vault create |
| `204` | Logout, password change, session revoke, vault delete |
| `400` | Malformed input, weak password |
| `401` | Not authenticated, or credentials rejected |
| `403` | Authenticated but not permitted; CSRF failure |
| `404` | No such route or resource — also used instead of `403` where existence is itself a secret |
| `409` | Email already registered |
| `413` | Body over 32 kB |
| `423` | Account locked |
| `429` | Rate limited |
| `500` | Unexpected; never leaks internals in production |
