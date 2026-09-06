import type { RequestHandler } from "express";

import { newId } from "../lib/crypto.js";

/** Response header that carries the correlation id back to the client. */
export const REQUEST_ID_HEADER = "X-Request-Id";

/**
 * Stamps every request with a fresh `req.requestId` and echoes it as `X-Request-Id`.
 *
 * The id is always generated server-side and never taken from an inbound header, so a caller
 * cannot forge or collide with another request's id in the audit log or the error envelope.
 */
export const requestId: RequestHandler = (req, res, next) => {
  const id = newId("req");
  req.requestId = id;
  res.setHeader(REQUEST_ID_HEADER, id);
  next();
};
