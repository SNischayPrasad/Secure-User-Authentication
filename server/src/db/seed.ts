import { platform } from "node:process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { closeDb, db } from "./index.js";
import { migrate } from "./migrate.js";
import { newId } from "../lib/crypto.js";
import { hashPassword } from "../lib/password.js";

/** Email of the demo account. Also the idempotency key for this script. */
export const DEMO_EMAIL = "ada@example.com";

/** Display name of the demo account. */
export const DEMO_NAME = "Ada Lovelace";

/**
 * Password of the demo account. Published on purpose: this is a throwaway local
 * fixture, never a production credential, and it is hashed with the real
 * `hashPassword` path so the seeded row is indistinguishable from a registration.
 */
export const DEMO_PASSWORD = "correct-horse-battery-staple-9";

/** What `seed()` did, so tests and the CLI can assert on it instead of parsing logs. */
export type SeedResult = {
  created: boolean;
  userId: string;
  email: string;
  vaultItemsCreated: number;
};

/** Demo vault contents — the protected resource the UI reads once authenticated. */
const DEMO_VAULT_ITEMS: ReadonlyArray<{ title: string; body: string }> = [
  {
    title: "Recovery codes — analytical engine console",
    body: [
      "Single-use backup codes for the hardware console. Each one works once, then it is dead.",
      "",
      "  7F3K-QP82-LM40",
      "  D9XR-2VHT-6BCE",
      "  A1ZW-58NG-KJ7Q",
      "  M4TY-K0RD-3PVX",
      "",
      "Stored here instead of in a drawer because the drawer is not encrypted at rest.",
      "Regenerate the whole set after using two of them.",
    ].join("\n"),
  },
  {
    title: "Note G — deployment checklist",
    body: [
      "Before the Bernoulli-number job goes to the production engine:",
      "",
      "1. Confirm JWT_SECRET is set from the secret store, not the dev fallback.",
      "2. Rotate the refresh-token family for every operator account.",
      "3. Verify WAL checkpointing after the nightly backup copies the sqlite file.",
      "4. Re-read the audit log for token_reuse_detected events from the last 7 days.",
      "5. Confirm the card punchers are logging failures, not swallowing them.",
    ].join("\n"),
  },
  {
    title: "Correspondence — Babbage, on the engine's memory",
    body: [
      "Draft reply, not yet sent.",
      "",
      "The engine does not originate anything; it can only do whatever we know how to order",
      "it to perform. That is precisely why the ordering must be written down, reviewed, and",
      "kept somewhere only I can open. The store is the argument, not the machine.",
      "",
      "Ask about the cost of the second store before agreeing to the revised plan.",
    ].join("\n"),
  },
];

/**
 * Creates the demo user and their vault items if the demo email is not already
 * present. Idempotent, so it is safe on every boot and in test setup. The password
 * goes through the real Argon2id hasher rather than a pasted literal, so the seeded
 * account exercises exactly the same verification path as a registered one.
 */
export async function seed(): Promise<SeedResult> {
  migrate();

  const existing = db
    .prepare<[string], { id: string }>("SELECT id FROM users WHERE email_canonical = ?")
    .get(DEMO_EMAIL);

  if (existing) {
    console.log(`[seed] ${DEMO_EMAIL} already exists (${existing.id}) — nothing to do.`);
    return { created: false, userId: existing.id, email: DEMO_EMAIL, vaultItemsCreated: 0 };
  }

  const passwordHash = await hashPassword(DEMO_PASSWORD);
  const now = Date.now();
  const userId = newId("usr");

  const insertUser = db.prepare<{
    id: string;
    email: string;
    emailCanonical: string;
    name: string;
    passwordHash: string;
    passwordChangedAt: number;
    createdAt: number;
    updatedAt: number;
  }>(
    `INSERT INTO users (
       id, email, email_canonical, name, password_hash, password_algo, role,
       failed_attempts, locked_until, password_changed_at, created_at, updated_at
     ) VALUES (
       @id, @email, @emailCanonical, @name, @passwordHash, 'argon2id', 'user',
       0, NULL, @passwordChangedAt, @createdAt, @updatedAt
     )`,
  );

  const insertItem = db.prepare<{
    id: string;
    userId: string;
    title: string;
    body: string;
    createdAt: number;
    updatedAt: number;
  }>(
    `INSERT INTO vault_items (id, user_id, title, body, created_at, updated_at)
     VALUES (@id, @userId, @title, @body, @createdAt, @updatedAt)`,
  );

  const insertAll = db.transaction((): number => {
    insertUser.run({
      id: userId,
      email: DEMO_EMAIL,
      emailCanonical: DEMO_EMAIL,
      name: DEMO_NAME,
      passwordHash,
      passwordChangedAt: now,
      createdAt: now,
      updatedAt: now,
    });

    let count = 0;
    for (const item of DEMO_VAULT_ITEMS) {
      // Stagger updated_at so the "most recently updated first" ordering is stable.
      const stamp = now - count * 60_000;
      insertItem.run({
        id: newId("itm"),
        userId,
        title: item.title,
        body: item.body,
        createdAt: stamp,
        updatedAt: stamp,
      });
      count += 1;
    }
    return count;
  });

  const vaultItemsCreated = insertAll();

  console.log(`[seed] created user ${DEMO_NAME} <${DEMO_EMAIL}> (${userId})`);
  console.log(`[seed] created ${vaultItemsCreated} vault items`);
  console.log(`[seed] demo password (local fixture only): ${DEMO_PASSWORD}`);

  return { created: true, userId, email: DEMO_EMAIL, vaultItemsCreated };
}

/**
 * True when this module is the process entry point, so importing it from a test
 * never runs the CLI branch or closes the shared connection out from under it.
 */
function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (entry === undefined) return false;
  const normalise = (p: string): string => {
    const abs = resolve(p);
    return platform === "win32" ? abs.replace(/\\/g, "/").toLowerCase() : abs;
  };
  return normalise(entry) === normalise(fileURLToPath(import.meta.url));
}

if (isDirectRun()) {
  seed()
    .then(() => {
      closeDb();
    })
    .catch((error: unknown) => {
      console.error("[seed] failed:", error);
      closeDb();
      process.exitCode = 1;
    });
}
