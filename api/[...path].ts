import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * The Vercel entry point for the whole API.
 *
 * A catch-all function file, rather than a rewrite onto `api/index.ts`, so that `req.url`
 * arrives as the real path — `/api/v1/me` — and Express routes on it unchanged. The same
 * `createApp()` that `server/src/index.ts` listens with, and that the test suite drives through
 * supertest, is the one running here: there is no Vercel-specific branch of the application.
 *
 * It imports the compiled output rather than the TypeScript source because the server is
 * authored for NodeNext, where relative imports carry a `.js` extension that the bundler would
 * not resolve back to `.ts`. `npm run build` compiles it first.
 */
import { createApp } from "../server/dist/app.js";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

let app: Handler | null = null;
let bootError: unknown = null;

// Built once per instance and reused by every warm invocation. A failure here is almost always
// missing configuration — most often JWT_SECRET, which the server deliberately refuses to boot
// without in production — so it is captured and reported instead of crashing the function
// with an unexplained stack.
try {
  app = createApp() as unknown as Handler;
} catch (error) {
  bootError = error;
}

export default function handler(req: IncomingMessage, res: ServerResponse): void {
  if (!app) {
    const message = bootError instanceof Error ? bootError.message : "The API failed to start.";
    console.error("[api] boot failed:", bootError);
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    res.end(
      JSON.stringify({
        error: {
          code: "SERVER_MISCONFIGURED",
          message,
        },
      }),
    );
    return;
  }

  app(req, res);
}
