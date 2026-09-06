import { defineConfig } from "vitest/config";

/**
 * Vitest configuration for the server integration suite.
 *
 * A single forked process is used because better-sqlite3 is a native addon and the whole
 * suite shares one database handle; `env` is set here (and again at the top of
 * tests/helpers.ts) so `config/env.ts` sees a valid, deterministic configuration no matter
 * how early it is evaluated. The generous timeout exists because Argon2id is deliberately
 * slow — that slowness is the security property, so tests must not fight it.
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    pool: "forks",
    poolOptions: {
      forks: {
        singleFork: true,
      },
    },
    testTimeout: 30_000,
    hookTimeout: 30_000,
    env: {
      NODE_ENV: "test",
      DATABASE_FILE: ":memory:",
      // Names a fixture account so the demo-account guard is exercised by the suite.
      DEMO_ACCOUNT_EMAIL: "demo-fixture@example.test",
      JWT_SECRET: "test-secret-that-is-definitely-long-enough-32",
    },
  },
});
