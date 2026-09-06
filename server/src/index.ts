import type { Server } from "node:http";

import { createApp } from "./app.js";
import { env } from "./config/env.js";
import { closeDb } from "./db/index.js";

/** How long a shutdown may wait for in-flight requests before the process is killed anyway. */
const SHUTDOWN_GRACE_MS = 10_000;

const app = createApp();

const server: Server = app.listen(env.port, () => {
  const baseUrl = `http://localhost:${env.port}`;
  console.log("");
  console.log("  secure-user-auth api");
  console.log(`  env      ${env.nodeEnv}`);
  console.log(`  base     ${baseUrl}/api/v1`);
  console.log(`  health   ${baseUrl}/api/health`);
  console.log(`  origin   ${env.webOrigin}`);
  console.log("");
});

server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    console.error(`Port ${env.port} is already in use. Stop the other process or set PORT.`);
  } else {
    console.error("HTTP server error:", err);
  }
  process.exit(1);
});

let shuttingDown = false;

/**
 * Stops accepting connections, drains in-flight requests, then closes SQLite.
 *
 * Guarded against re-entry so a second Ctrl-C (or SIGTERM arriving after SIGINT) cannot close the
 * database twice or race the exit; a hard timer guarantees the process still dies if a request
 * hangs, and the WAL is checkpointed by `closeDb()` rather than being left to a killed process.
 */
function shutdown(signal: NodeJS.Signals): void {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`\n${signal} received — shutting down.`);

  const forceExit = setTimeout(() => {
    console.error("Shutdown timed out; exiting now.");
    process.exit(1);
  }, SHUTDOWN_GRACE_MS);
  forceExit.unref();

  server.close((err?: Error) => {
    clearTimeout(forceExit);

    if (err) {
      console.error("Error while closing HTTP server:", err);
    }

    try {
      closeDb();
    } catch (dbErr) {
      console.error("Error while closing the database:", dbErr);
      process.exit(1);
    }

    console.log("Shutdown complete.");
    process.exit(err ? 1 : 0);
  });

  // Keep-alive sockets would otherwise hold the server open for the full grace period.
  server.closeIdleConnections();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
