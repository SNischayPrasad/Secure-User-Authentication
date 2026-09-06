import * as wire from "./wire";

/**
 * The single HTTP client for the app.
 *
 * Two decisions here carry most of the client-side security weight:
 *
 *  1. The access token lives in a module-level variable, never in localStorage or
 *     sessionStorage. Anything readable by injected script is a token an attacker can
 *     exfiltrate; a variable dies with the tab. Durable sessions come from the
 *     httpOnly refresh cookie instead, which script cannot read at all.
 *
 *  2. A 401 TOKEN_EXPIRED triggers exactly one refresh, shared by every request that
 *     is waiting on it. Without the shared promise, a page that fires six requests on
 *     mount would send six refreshes, and rotation would make five of them look like
 *     token reuse — which the server correctly treats as an attack and answers by
 *     revoking the whole family.
 */

const BASE = "/api/v1";

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;
let onAuthLost: (() => void) | null = null;

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type FieldIssue = { field: string; message: string };

/** Pulls the per-field issues out of a 400 response, if the server sent any. */
export function fieldIssues(error: unknown): FieldIssue[] {
  if (!(error instanceof ApiError) || !Array.isArray(error.details)) return [];
  return (error.details as unknown[]).filter(
    (d): d is FieldIssue =>
      typeof d === "object" && d !== null && "field" in d && "message" in d,
  );
}

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

/** Registers the callback used when a refresh fails and the session is genuinely over. */
export function setAuthLostHandler(handler: (() => void) | null): void {
  onAuthLost = handler;
}

/** Reads the readable half of the double-submit CSRF pair. */
function readCsrfCookie(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

type RequestOptions = {
  method?: string;
  body?: unknown;
  /** Set for the refresh call itself, so a failed refresh never recurses. */
  skipRefresh?: boolean;
};

async function send<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = { Accept: "application/json" };

  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

  if (MUTATING.has(method)) {
    const csrf = readCsrfCookie();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const started = performance.now();
  const response = await fetch(`${BASE}${path}`, {
    method,
    headers,
    credentials: "include",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  let payload: unknown = null;
  if (response.status !== 204) {
    const text = await response.text();
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }
    }
  }

  const envelope =
    payload && typeof payload === "object" && "error" in payload
      ? (payload as { error: { code: string; message: string; details?: unknown } }).error
      : null;

  wire.record({
    method,
    path: `${BASE}${path}`,
    status: response.status,
    code: envelope?.code ?? null,
    ms: Math.round(performance.now() - started),
    requestId: response.headers.get("X-Request-Id"),
    authenticated: Boolean(accessToken),
  });

  if (response.ok) return payload as T;

  // One shared refresh, then replay the original request exactly once.
  if (response.status === 401 && envelope?.code === "TOKEN_EXPIRED" && !options.skipRefresh) {
    const recovered = await refreshOnce();
    if (recovered) return send<T>(path, { ...options, skipRefresh: true });
  }

  throw new ApiError(
    response.status,
    envelope?.code ?? "REQUEST_FAILED",
    envelope?.message ?? `Request failed with status ${response.status}.`,
    envelope?.details,
  );
}

/**
 * Refreshes the access token. Concurrent callers all await the same promise, so the
 * rotating refresh token is presented exactly once.
 */
export function refreshOnce(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const result = await send<{ accessToken: string; expiresIn: number }>("/auth/refresh", {
        method: "POST",
        skipRefresh: true,
      });
      accessToken = result.accessToken;
      return true;
    } catch {
      accessToken = null;
      onAuthLost?.();
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

export const api = {
  get: <T>(path: string) => send<T>(path),
  post: <T>(path: string, body?: unknown) => send<T>(path, { method: "POST", body }),
  patch: <T>(path: string, body?: unknown) => send<T>(path, { method: "PATCH", body }),
  del: <T>(path: string) => send<T>(path, { method: "DELETE" }),
};
