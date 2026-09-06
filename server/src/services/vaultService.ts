import { getDb } from "../db/index.js";
import { newId } from "../lib/crypto.js";
import { AppError } from "../lib/errors.js";

/**
 * Vault item data access — the protected resource behind `Bearer` auth.
 *
 * Every query is scoped by `user_id` in the WHERE clause rather than filtered after the fact, and
 * an item owned by someone else is reported exactly like an item that does not exist (`undefined`
 * / `false`, so the route answers 404 and never 403). Without that, the 403-vs-404 difference would
 * let any signed-in user probe for other people's item ids.
 *
 * Writes use `RETURNING` rather than a write followed by a select. On a serverless deployment
 * every extra statement is another network round trip to the database, and the two-statement form
 * is also racy: another request could change the row in between.
 */

/** A `vault_items` row exactly as stored. */
export interface VaultItemRecord {
  id: string;
  user_id: string;
  title: string;
  body: string;
  created_at: number;
  updated_at: number;
}

/** The vault item shape returned to clients: camelCase timestamps, no `user_id`. */
export interface PublicVaultItem {
  id: string;
  title: string;
  body: string;
  createdAt: number;
  updatedAt: number;
}

const SELECT_COLUMNS = `id, user_id, title, body, created_at, updated_at`;

/** Maps a row to the client shape; `user_id` is dropped because the caller is always the owner. */
export function toPublicVaultItem(row: VaultItemRecord): PublicVaultItem {
  return {
    id: row.id,
    title: row.title,
    body: row.body,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/** Lists one user's items, most recently updated first. */
export async function listForUser(userId: string): Promise<VaultItemRecord[]> {
  const db = await getDb();
  const { rows } = await db.query<VaultItemRecord>(
    `SELECT ${SELECT_COLUMNS} FROM vault_items WHERE user_id = $1 ORDER BY updated_at DESC`,
    [userId],
  );
  return rows;
}

/** Loads one item owned by `userId`; anything else returns `undefined` so the route answers 404 rather than confirming the id exists. */
export async function findById(userId: string, id: string): Promise<VaultItemRecord | undefined> {
  const db = await getDb();
  const { rows } = await db.query<VaultItemRecord>(
    `SELECT ${SELECT_COLUMNS} FROM vault_items WHERE id = $1 AND user_id = $2`,
    [id, userId],
  );
  return rows[0];
}

/** Creates an item owned by `userId` and returns the stored row. */
export async function create(
  userId: string,
  input: { title: string; body: string },
): Promise<VaultItemRecord> {
  const db = await getDb();
  const now = Date.now();
  const id = newId("itm");

  const { rows } = await db.query<VaultItemRecord>(
    `INSERT INTO vault_items (id, user_id, title, body, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING ${SELECT_COLUMNS}`,
    [id, userId, input.title.trim(), input.body.trim(), now, now],
  );

  const row = rows[0];
  if (!row) throw new AppError(500, "INTERNAL_ERROR", "The item could not be saved.");
  return row;
}

/**
 * Applies a partial update in a single ownership-scoped statement, so there is no window between
 * checking the owner and writing. Returns `undefined` when the item is missing or owned by
 * someone else — indistinguishable on purpose, so the vault cannot be used to probe for ids.
 */
export async function update(
  userId: string,
  id: string,
  patch: { title?: string; body?: string },
): Promise<VaultItemRecord | undefined> {
  const db = await getDb();
  const title = patch.title === undefined ? null : patch.title.trim();
  const body = patch.body === undefined ? null : patch.body.trim();

  const { rows } = await db.query<VaultItemRecord>(
    `UPDATE vault_items
        SET title = COALESCE($1, title), body = COALESCE($2, body), updated_at = $3
      WHERE id = $4 AND user_id = $5
      RETURNING ${SELECT_COLUMNS}`,
    [title, body, Date.now(), id, userId],
  );

  return rows[0];
}

/** Deletes an item the caller owns; `false` means missing *or* not theirs, so the route answers 404 either way. */
export async function remove(userId: string, id: string): Promise<boolean> {
  const db = await getDb();
  const { rowCount } = await db.query(
    `DELETE FROM vault_items WHERE id = $1 AND user_id = $2`,
    [id, userId],
  );
  return rowCount > 0;
}
