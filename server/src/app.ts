import express from "express";
import type { Express } from "express";
import helmet from "helmet";
import cors from "cors";
import morgan from "morgan";
import cookieParser from "cookie-parser";

import { env, isProd } from "./config/env.js";
import { migrate } from "./db/migrate.js";
import { AppError } from "./lib/errors.js";
import { requestId } from "./middleware/requestId.js";
import { globalLimiter } from "./middleware/rateLimit.js";
import { errorHandler } from "./middleware/errorHandler.js";
import healthRouter from "./routes/health.routes.js";
import authRouter from "./routes/auth.routes.js";
import meRouter from "./routes/user.routes.js";
import vaultRouter from "./routes/vault.routes.js";

/**
 * Content-Security-Policy directives for the API.
 *
 * The API serves JSON only, so the policy is deliberately closed down to `'self'` and acts as
 * defence in depth for any HTML an error path might ever emit. Google Fonts is allowed because the
 * web client loads its type from `fonts.googleapis.com` / `fonts.gstatic.com`; in development the
 * Vite dev client additionally needs its HMR WebSocket and its own origin in `connect-src`, which
 * is why those entries are gated on `!isProd` — production keeps `connect-src 'self'`.
 */
function cspDirectives(): Record<string, string[]> {
  const connectSrc = isProd ? ["'self'"] : ["'self'", env.webOrigin, "ws:", "wss:"];

  return {
    defaultSrc: ["'self'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    objectSrc: ["'none'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
    imgSrc: ["'self'", "data:"],
    connectSrc,
  };
}

/**
 * Builds the fully wired Express application without binding a port, so tests can drive it through
 * supertest while `index.ts` owns the listening socket.
 *
 * Middleware order is security-relevant and intentional: the request id exists before anything can
 * log or throw, hardening headers and the CORS allowlist are applied before any body is read, the
 * 32kb JSON limit and cookie parsing come before the rate limiter and the routers, and the terminal
 * error handler is mounted last so every failure below it is serialised through one envelope.
 */
export function createApp(): Express {
  // Schema is idempotent; running it here means anything that imports createApp (tests included)
  // gets a database that is ready before the first request is served.
  migrate();

  const app = express();

  // Do not advertise the framework: it is free reconnaissance for an attacker.
  app.disable("x-powered-by");
  // One reverse proxy in front of us, so req.ip is the real client for rate limiting and audit logs.
  app.set("trust proxy", 1);

  app.use(requestId);

  app.use(
    helmet({
      contentSecurityPolicy: { useDefaults: true, directives: cspDirectives() },
      // The API is called cross-origin by the web client in development; embedding is still denied
      // by frame-ancestors 'none' above.
      crossOriginResourcePolicy: { policy: "cross-origin" },
      referrerPolicy: { policy: "no-referrer" },
      hsts: isProd ? { maxAge: 15552000, includeSubDomains: true } : false,
    }),
  );

  // Exact-origin allowlist plus credentials, because the refresh and CSRF cookies must travel.
  app.use(cors({ origin: env.webOrigin, credentials: true }));

  if (!isProd) {
    app.use(morgan("dev"));
  }

  // Bounded body size: oversized payloads are rejected by the parser and surface as 413.
  app.use(express.json({ limit: "32kb" }));
  app.use(cookieParser());

  app.use("/api", globalLimiter);

  app.use("/api", healthRouter);

  app.use("/api/v1/auth", authRouter);
  app.use("/api/v1/me", meRouter);
  app.use("/api/v1/vault", vaultRouter);

  // Anything under /api that no router claimed is a 404 in the standard error envelope, never HTML.
  // Raised as an AppError so the terminal handler below serialises it like every other failure.
  app.use("/api", (_req, _res, next) => {
    next(new AppError(404, "ROUTE_NOT_FOUND", "This endpoint does not exist. Check the path and the /api/v1 prefix."));
  });

  app.use(errorHandler);

  return app;
}
