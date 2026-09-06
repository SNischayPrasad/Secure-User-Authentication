import type { Request, RequestHandler } from "express";
import type { ZodType } from "zod";

import { AppError } from "../lib/errors.js";

/** The parts of an Express request that {@link validate} can check. */
export type ValidationTarget = "body" | "params" | "query";

/** One user-facing field error, matching the `details` entry shape in the error envelope. */
export type ValidationDetail = {
  field: string;
  message: string;
};

/** Zod schemas to apply, keyed by the request part they validate. */
export type ValidationSchemas = {
  body?: ZodType;
  params?: ZodType;
  query?: ZodType;
};

const TARGETS: readonly ValidationTarget[] = ["body", "params", "query"];

/**
 * Overwrites a request property with its parsed value.
 *
 * `defineProperty` rather than assignment because Express 5 exposes `req.query` as a getter-only
 * accessor; a plain assignment would throw at runtime.
 */
function replaceTarget(req: Request, target: ValidationTarget, value: unknown): void {
  Object.defineProperty(req, target, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

/**
 * Builds a middleware that validates `body`, `params` and/or `query` with zod and, on success,
 * REPLACES each part with the parsed value.
 *
 * Replacing rather than merging is the security-relevant half: unknown keys are stripped, so a
 * caller cannot smuggle extra fields (`role`, `id`, `isAdmin`, ...) past a handler that spreads
 * the request body. Failures raise 400 `VALIDATION_FAILED` carrying every offending field at once.
 */
export function validate(schemas: ValidationSchemas): RequestHandler {
  return (req, _res, next) => {
    const details: ValidationDetail[] = [];
    const parsed = new Map<ValidationTarget, unknown>();

    for (const target of TARGETS) {
      const schema = schemas[target];
      if (!schema) continue;

      const result = schema.safeParse(req[target]);
      if (result.success) {
        parsed.set(target, result.data);
        continue;
      }

      for (const issue of result.error.issues) {
        const path = issue.path.map((segment) => String(segment)).join(".");
        details.push({ field: path.length > 0 ? path : target, message: issue.message });
      }
    }

    if (details.length > 0) {
      next(
        new AppError(
          400,
          "VALIDATION_FAILED",
          "Check the fields listed in details and try again.",
          details,
        ),
      );
      return;
    }

    for (const [target, value] of parsed) {
      replaceTarget(req, target, value);
    }

    next();
  };
}
