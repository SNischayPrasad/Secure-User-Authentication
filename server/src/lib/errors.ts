/**
 * The one error type the HTTP layer understands.
 *
 * Anything thrown that is NOT an `AppError` is treated by `errorHandler` as an unexpected
 * failure and collapsed into a generic 500, so an accidental `throw` can never turn an internal
 * message (a SQL string, a file path, a stack) into part of an API response.
 */
export class AppError extends Error {
  /** HTTP status to send. */
  readonly status: number;

  /** Stable machine-readable code from the contract's error table, e.g. `VALIDATION_FAILED`. */
  readonly code: string;

  /** Optional extra payload; only validation-style errors populate it. */
  readonly details?: unknown;

  /**
   * Builds an error the API is allowed to describe to the caller.
   * @param status HTTP status code.
   * @param code contract error code.
   * @param message human-readable message — assume the client will display it verbatim.
   * @param details optional structured detail, e.g. `[{ field, message }]`.
   */
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = "AppError";
    this.status = status;
    this.code = code;
    this.details = details;
    Error.captureStackTrace(this, AppError);
  }
}

/** 400 — the request was understood but is not acceptable (validation, weak password, …). */
export function badRequest(code: string, message: string, details?: unknown): AppError {
  return new AppError(400, code, message, details);
}

/**
 * 401 — the caller is not authenticated. Keep messages generic for credential failures so the
 * response cannot be used to enumerate which accounts exist.
 */
export function unauthorized(code: string, message: string, details?: unknown): AppError {
  return new AppError(401, code, message, details);
}

/** 403 — authenticated, but not permitted (CSRF mismatch, insufficient role). */
export function forbidden(code: string, message: string, details?: unknown): AppError {
  return new AppError(403, code, message, details);
}

/**
 * 404 — resource absent. Also returned for resources owned by another user, so the API does not
 * confirm that someone else's id exists.
 */
export function notFound(code: string, message: string, details?: unknown): AppError {
  return new AppError(404, code, message, details);
}

/** 409 — the request conflicts with existing state, e.g. registering a taken email. */
export function conflict(code: string, message: string, details?: unknown): AppError {
  return new AppError(409, code, message, details);
}

/** 423 — the account is temporarily locked after repeated failed logins (brute-force brake). */
export function locked(code: string, message: string, details?: unknown): AppError {
  return new AppError(423, code, message, details);
}

/** 429 — a rate limiter tripped; the handler must also set a `Retry-After` header. */
export function tooManyRequests(code: string, message: string, details?: unknown): AppError {
  return new AppError(429, code, message, details);
}

/**
 * Narrows an unknown thrown value to `AppError`. Deliberately strict — it matches only errors
 * this module produced (allowing for a duplicated module instance under a test runner), because
 * anything it accepts has its `message` sent to the client verbatim.
 */
export function isAppError(e: unknown): e is AppError {
  if (e instanceof AppError) return true;
  if (!(e instanceof Error) || e.name !== "AppError") return false;
  const candidate = e as Error & { status?: unknown; code?: unknown };
  return typeof candidate.status === "number" && typeof candidate.code === "string";
}
