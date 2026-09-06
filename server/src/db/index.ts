import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import Database from "better-sqlite3";
import { env } from "../config/env.js";

/**
 * The literal SQLite filename that means "keep the whole database in RAM".
 * Tests use it so each suite gets a disposable database with no file to clean up.
 */
const IN_MEMORY = ":memory:";

/**
 * Opens the SQLite database, creating the parent directory first, and applies the
 * connection pragmas. WAL keeps readers from blocking the writer, `foreign_keys = ON`
 * is required for the `ON DELETE CASCADE` that wipes a deleted user's sessions and
 * vault items (SQLite disables FK enforcement by default), and `busy_timeout` makes
 * concurrent writes wait rather than immediately throwing SQLITE_BUSY.
 */
function openDatabase(): Database.Database {
  const file = env.databaseFile;

  if (file !== IN_MEMORY) {
    // `recursive: true` is a no-op when the directory already exists.
    mkdirSync(dirname(resolve(file)), { recursive: true });
  }

  const database = new Database(file);

  // On an in-memory database `journal_mode = WAL` is silently kept as "memory";
  // it is harmless to request it unconditionally.
  database.pragma("journal_mode = WAL");
  database.pragma("foreign_keys = ON");
  database.pragma("busy_timeout = 5000");

  return database;
}

/**
 * The single process-wide SQLite connection. better-sqlite3 is synchronous and
 * fully serialised, so one shared connection is both correct and fastest here.
 */
export const db: Database.Database = openDatabase();

/**
 * Closes the connection, flushing the WAL back into the main database file.
 * Idempotent, so shutdown hooks and test teardown can both call it safely.
 */
export function closeDb(): void {
  if (db.open) {
    db.close();
  }
}
