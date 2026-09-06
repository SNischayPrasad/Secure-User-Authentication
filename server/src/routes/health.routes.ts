import { Router } from "express";

/**
 * Build version reported by the health check. Read from the npm-injected env var with a literal
 * fallback so the module never has to import package.json into the compiled output.
 */
const SERVER_VERSION = process.env.npm_package_version ?? "1.0.0";

/**
 * Liveness route. Mounted at `/api/health`, outside `/v1` and outside authentication, and it
 * reports build and uptime only — never database, config or dependency detail that would help
 * an unauthenticated caller profile the deployment.
 */
const router = Router();

/** Endpoint 1 — GET /api/health. */
router.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    uptime: Math.round(process.uptime() * 1000) / 1000,
    version: SERVER_VERSION,
    time: new Date().toISOString(),
  });
});

/** Router for `/api/health` (endpoint 1). */
export default router;
