import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * The Vercel entry point for the whole API.
 *
 * Vercel's filesystem routing did not apply catch-all semantics to `api/[...path].ts` for this
 * project: `/api/health` reached the function but `/api/v1/me` returned a platform 404, which is
 * single-segment behaviour. Rather than depend on that, `vercel.json` rewrites every `/api/*`
 * request here and passes the original path in a `__path` query parameter, which this handler
 * puts back on `req.url` before Express sees it. That is deterministic regardless of whether the
 * platform preserves the original URL through a rewrite.
 *
 * The app itself is the same `createApp()` that `server/src/index.ts` listens with and that the
 * test suite drives through supertest — there is no Vercel-specific branch of the application.
 *
 * It imports the compiled output rather than the TypeScript source because the server is authored
 * for NodeNext, where relative imports carry a `.js` extension the bundler would not resolve back
 * to `.ts`. `npm run build` compiles it first.
 */
import { createApp } from "../server/dist/app.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

let app: Handler | null = null;
let bootError: unknown = null;

// Built once per instance and reused by every warm invocation. A failure here is almost always
// missing configuration — JWT_SECRET or DATABASE_URL, both of which the server deliberately
// refuses to start without in production — so it is reported rather than left as an opaque crash.
try {
  app = createApp() as unknown as Handler;
} catch (error) {
  bootError = error;
}

/** Restores the pre-rewrite path so Express routes on `/api/v1/...` rather than on `/api/index`. */
function restoreOriginalUrl(req: IncomingMessage): void {
  const raw = req.url ?? "/";
  const parsed = new URL(raw, "http://localhost");
  const forwarded = parsed.searchParams.get("__path");
  if (forwarded === null) return;

  parsed.searchParams.delete("__path");
  const query = parsed.searchParams.toString();

  // `searchParams.get` percent-DECODES, so splicing the result straight back into the URL would
  // turn an encoded "%2F" or "%3F" inside a path segment into a real separator and change which
  // route Express matches. Re-encode each segment to put it back exactly as it arrived.
  const path = forwarded
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");

  req.url = `/api/${path}${query ? `?${query}` : ""}`;
}

export default function handler(req: IncomingMessage, res: ServerResponse): void {
  if (!app) {
    const message = bootError instanceof Error ? bootError.message : "The API failed to start.";
    console.error("[api] boot failed:", bootError);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ error: { code: "SERVER_MISCONFIGURED", message } }));
    return;
  }

  restoreOriginalUrl(req);
  app(req, res);
}
