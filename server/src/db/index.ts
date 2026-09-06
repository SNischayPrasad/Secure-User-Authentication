import pg from "pg";
import type { PGlite } from "@electric-sql/pglite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { env, isProd } from "../config/env.js";

/**
 * One database interface, two drivers, one SQL dialect.
 *
 * Production (Vercel, Neon) uses node-postgres over a pooled connection string. Local
 * development and the test suite use PGlite, which is real PostgreSQL compiled to WebAssembly
 * and run in-process.
 *
 * Using Postgres in both places is the whole point: a clone still needs no database server
 * installed, and the SQL that runs against Neon is byte-for-byte the SQL the tests ran. A
 * SQLite-locally / Postgres-in-production split would mean the dialect that ships is the one
 * nothing ever tested.
 */

export type QueryResult<T> = { rows: T[]; rowCount: number };

export interface Db {
  /** Runs a parameterised statement. Placeholders are Postgres-style: $1, $2, … */
  query<T = Record<string, unknown>>(sql: string, params?: readonly unknown[]): Promise<QueryResult<T>>;
  /** Runs one or more statements with no parameters. Used by the migration only. */
  exec(sql: string): Promise<void>;
  /** Runs `fn` inside a transaction, rolling back if it throws. */
  transaction<T>(fn: (tx: Db) => Promise<T>): Promise<T>;
}

/**
 * node-postgres returns BIGINT (oid 20) as a string, because a 64-bit integer does not always
 * fit a JS number. Every BIGINT in this schema is an epoch-millisecond timestamp, which stays
 * far below Number.MAX_SAFE_INTEGER until the year 287396, so parsing to a number here keeps
 * the row shapes identical to what PGlite returns. Without this, `createdAt` would arrive as a
 * string in production and as a number in every test.
 */
pg.types.setTypeParser(pg.types.builtins.INT8, (value: string) => Number.parseInt(value, 10));

/** True when the error is a Postgres unique-constraint violation, on either driver. */
export function isUniqueViolation(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as { code?: unknown }).code === "23505";
}

let instance: Promise<Db> | null = null;
let closer: (() => Promise<void>) | null = null;

function wrapPool(pool: pg.Pool): Db {
  const asDb = (runner: pg.Pool | pg.PoolClient): Db => ({
    async query(sql, params) {
      const result = await runner.query(sql, params as unknown[]);
      return { rows: result.rows, rowCount: result.rowCount ?? result.rows.length };
    },
    async exec(sql) {
      await runner.query(sql);
    },
    async transaction(fn) {
      // A nested transaction reuses the client it is already inside rather than opening
      // a second connection, which would deadlock against its own uncommitted rows.
      if (runner !== pool) return fn(asDb(runner));

      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const value = await fn(asDb(client));
        await client.query("COMMIT");
        return value;
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    },
  });

  return asDb(pool);
}

function wrapPglite(lite: PGlite): Db {
  const asDb = (runner: Pick<PGlite, "query" | "exec" | "transaction">): Db => ({
    async query(sql, params) {
      const result = await runner.query(sql, params as unknown[]);
      return { rows: result.rows as never[], rowCount: result.affectedRows ?? result.rows.length };
    },
    async exec(sql) {
      await runner.exec(sql);
    },
    async transaction(fn) {
      if (runner !== lite) return fn(asDb(runner));
      return lite.transaction(async (tx) =>
        fn({
          query: async (sql, params) => {
            const result = await tx.query(sql, params as unknown[]);
            return { rows: result.rows as never[], rowCount: result.affectedRows ?? result.rows.length };
          },
          exec: async (sql) => {
            await tx.exec(sql);
          },
          transaction: async (nested) => nested(asDb(tx as never)),
        }),
      ) as never;
    },
  });

  return asDb(lite);
}

async function connect(): Promise<Db> {
  if (env.databaseUrl) {
    const pool = new pg.Pool({
      connectionString: env.databaseUrl,
      // Managed Postgres (Neon and friends) terminates plaintext connections. Certificate
      // verification is left to the driver default for the platform CA.
      ssl: env.databaseUrl.includes("localhost") ? false : { rejectUnauthorized: false },
      // Serverless invocations are short and numerous; a small ceiling per instance keeps the
      // provider's connection limit from being exhausted by concurrent cold starts.
      max: isProd ? 3 : 10,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
    });
    closer = () => pool.end();
    return wrapPool(pool);
  }

  // No connection string: run Postgres in-process.
  //
  // Imported dynamically, not at module scope: PGlite carries a multi-megabyte WebAssembly
  // build of Postgres, and a static import would pull all of it into the serverless bundle
  // that never uses it.
  const { PGlite: Lite } = await import("@electric-sql/pglite");

  const memory = env.databaseFile === ":memory:";
  if (!memory) mkdirSync(dirname(env.databaseFile), { recursive: true });

  const lite = new Lite(memory ? undefined : env.databaseFile);
  await lite.waitReady;
  closer = () => lite.close();
  return wrapPglite(lite);
}

/**
 * The shared connection. Cached at module scope so a warm serverless instance reuses its pool
 * across invocations instead of opening a new one per request.
 */
export function getDb(): Promise<Db> {
  if (!instance) instance = connect();
  return instance;
}

/** Closes the connection. Used by graceful shutdown and by the seed script. */
export async function closeDb(): Promise<void> {
  if (!instance) return;
  const pending = instance;
  instance = null;
  await pending.catch(() => undefined);
  const close = closer;
  closer = null;
  if (close) await close();
}
