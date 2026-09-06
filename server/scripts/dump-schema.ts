import { writeFileSync } from "node:fs";
import { SCHEMA_SQL } from "../src/db/migrate.js";

/**
 * Regenerates src/db/schema.sql from the authoritative SCHEMA_SQL string.
 *
 * The .sql file is documentation only — nothing reads it at runtime — so generating it removes
 * any chance of the readable copy drifting from the DDL that actually runs.
 */
const header = `-- =============================================================================
-- Secure User Authentication — database schema (DOCUMENTATION COPY)
-- =============================================================================
--
-- GENERATED FILE. Do not edit by hand.
--
-- The authoritative DDL is the exported \`SCHEMA_SQL\` string in src/db/migrate.ts.
-- tsc does not copy .sql assets into dist/, so a runtime read of this path would
-- work under tsx and then fail on a production boot. Regenerate with:
--
--     npm run schema:dump --workspace server
--
-- Dialect: PostgreSQL — Neon in production, PGlite (in-process) in development
-- and tests, so the SQL that ships is the SQL the tests ran.
--
-- All timestamps are BIGINT epoch milliseconds. BIGINT, not INTEGER: Date.now()
-- is ~1.79e12 and a Postgres INTEGER tops out at 2.15e9.
-- =============================================================================

`;

writeFileSync(new URL("../src/db/schema.sql", import.meta.url), header + SCHEMA_SQL.trimStart());
console.log("[schema] src/db/schema.sql regenerated from SCHEMA_SQL");
