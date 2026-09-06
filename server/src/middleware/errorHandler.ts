import type { ErrorRequestHandler, RequestHandler } from "express";

import { isProd } from "../config/env.js";
import { AppError } from "../lib/errors.js";

/** The error body every failing request returns, at every status code. */
export type ErrorEnvelope = {
  error: {
    code: string;
    message: string;
    details?: unknown;
  };
  requestId: string;
};

/**
 * Strips control characters and caps length before a caller-supplied path is echoed or logged,
 * so a crafted URL cannot inject newlines into the log stream or bloat a response.
 */
function safePath(value: string): string {
  return value.replace(/[^\w\-./:?=&%@,+~[\]]/g, "").slice(0, 200);
}

/** True when body-parser rejected the JSON body (`express.json` throws a `SyntaxError` with `body`). */
function isMalformedJson(err: unknown): boolean {
  return err instanceof SyntaxError && "body" in err;
}

/** True when body-parser rejected the request for exceeding the 32kb `express.json` limit. */
function isPayloadTooLarge(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    (err as { type?: unknown }).type === "entity.too.large"
  );
}

/**
 * Terminates unmatched `/api` paths with 404 `ROUTE_NOT_FOUND`.
 *
 * Mounted after every route so a typo returns the standard JSON envelope instead of Express's
 * default HTML page, which would leak the framework and the stack in development.
 */
export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(
    new AppError(
      404,
      "ROUTE_NOT_FOUND",
      `No route matches ${req.method} ${safePath(req.originalUrl)}.`,
    ),
  );
};

/**
 * The terminal error handler: maps everything to the standard error envelope.
 *
 * `AppError` keeps its status, code, message and (validation-only) details. Body-parser failures
 * become 400 `MALFORMED_JSON` / 413 `PAYLOAD_TOO_LARGE`. Anything else is an unexpected fault: it
 * is logged server-side with the request id and returned as 500 `INTERNAL_ERROR` whose message is
 * replaced with a generic line in production, because a raw exception message or stack can expose
 * file paths, SQL and library versions to an attacker. No stack is ever sent to the client.
 */
export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }

  const requestId = req.requestId ?? "req_unknown";
  if (!res.getHeader("X-Request-Id")) {
    res.setHeader("X-Request-Id", requestId);
  }

  let status = 500;
  let code = "INTERNAL_ERROR";
  let message = "Something went wrong.";
  let details: unknown;

  if (err instanceof AppError) {
    status = err.status;
    code = err.code;
    message = err.message;
    details = err.details;
  } else if (isPayloadTooLarge(err)) {
    status = 413;
    code = "PAYLOAD_TOO_LARGE";
    message = "The request body is larger than the 32kb limit.";
  } else if (isMalformedJson(err)) {
    status = 400;
    code = "MALFORMED_JSON";
    message = "The request body is not valid JSON.";
  } else {
    // Unknown fault: record the real error server-side, tell the client nothing specific.
    console.error(
      `[error] requestId=${requestId} ${req.method} ${safePath(req.originalUrl)} -> 500`,
      err,
    );
    if (!isProd) {
      const raw = err instanceof Error ? err.message : String(err);
      if (raw.length > 0) message = raw;
    }
  }

  const body: ErrorEnvelope = { error: { code, message }, requestId };
  if (details !== undefined) {
    body.error.details = details;
  }

  res.status(status).json(body);
};
