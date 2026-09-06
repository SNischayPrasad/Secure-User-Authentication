/** The API surface, as published on the landing page. Kept in step with docs/api.md and the README. */

export type Endpoint = {
  method: "GET" | "POST" | "PATCH" | "DELETE";
  path: string;
  auth: "public" | "bearer" | "cookie";
  purpose: string;
  success: string;
};

export const ENDPOINTS: Endpoint[] = [
  { method: "GET", path: "/api/health", auth: "public", purpose: "Liveness and version", success: "200" },
  { method: "GET", path: "/api/v1/auth/csrf", auth: "public", purpose: "Issue the double-submit token", success: "200" },
  { method: "POST", path: "/api/v1/auth/register", auth: "public", purpose: "Create an account and sign in", success: "201" },
  { method: "POST", path: "/api/v1/auth/login", auth: "public", purpose: "Exchange credentials for tokens", success: "200" },
  { method: "POST", path: "/api/v1/auth/refresh", auth: "cookie", purpose: "Rotate the refresh token", success: "200" },
  { method: "POST", path: "/api/v1/auth/logout", auth: "cookie", purpose: "Revoke this session", success: "204" },
  { method: "POST", path: "/api/v1/auth/logout-all", auth: "bearer", purpose: "Revoke every session", success: "204" },
  { method: "GET", path: "/api/v1/me", auth: "bearer", purpose: "The signed-in account", success: "200" },
  { method: "PATCH", path: "/api/v1/me", auth: "bearer", purpose: "Change the display name", success: "200" },
  { method: "POST", path: "/api/v1/me/password", auth: "bearer", purpose: "Change the password", success: "204" },
  { method: "GET", path: "/api/v1/me/sessions", auth: "bearer", purpose: "List active sessions", success: "200" },
  { method: "DELETE", path: "/api/v1/me/sessions/:id", auth: "bearer", purpose: "Revoke one session", success: "204" },
  { method: "GET", path: "/api/v1/me/activity", auth: "bearer", purpose: "Recent auth events", success: "200" },
  { method: "GET", path: "/api/v1/vault", auth: "bearer", purpose: "Private notes for this account", success: "200" },
  { method: "POST", path: "/api/v1/vault", auth: "bearer", purpose: "Add a note", success: "201" },
  { method: "PATCH", path: "/api/v1/vault/:id", auth: "bearer", purpose: "Edit a note", success: "200" },
  { method: "DELETE", path: "/api/v1/vault/:id", auth: "bearer", purpose: "Delete a note", success: "204" },
];

