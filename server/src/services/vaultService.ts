import type Database from "better-sqlite3";
import { db } from "../db/index.js";
import { newId } from "../lib/crypto.js";
import { AppError } from "../lib/errors.js";

/**
 * Vault item data access — the protected resource behind `Bearer` auth.
 *
 * Every query is scoped by `user_id` in the WHERE clause rather than filtered after the fact, and
 * an item owned by someone else is reported exactly like an item that does not exist (`undefined`
 * / `false`, so the route answers 404 and never 403). Without that, the 403-vs-404 difference would
 * let any signed-in user probe for other people's item ids.
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

const statements = new Map<string, Database.Statement<unknown[], unknown>>();

/**
 * Lazily prepares and caches a statement. Lazy because module import happens before
 * `migrate()` runs, so preparing at import time would fail with "no such table".
 */
function stmt<R = unknown>(sql: string): Database.Statement<unknown[], R> {
  const cached = statements.get(sql);
  if (cached) return cached as Database.Statement<unknown[], R>;
  const prepared = db.prepare<unknown[], R>(sql);
  statements.set(sql, prepared as Database.Statement<unknown[], unknown>);
  return prepared;
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
export function listForUser(userId: string): VaultItemRecord[] {
  return stmt<VaultItemRecord>(
    `SELECT ${SELECT_COLUMNS} FROM vault_items WHERE user_id = ? ORDER BY updated_at DESC`,
  ).all(userId);
}

/** Loads one item owned by `userId`; anything else returns `undefined` so the route answers 404 rather than confirming the id exists. */
export function findById(userId: string, id: string): VaultItemRecord | undefined {
  return stmt<VaultItemRecord>(
    `SELECT ${SELECT_COLUMNS} FROM vault_items WHERE id = ? AND user_id = ?`,
  ).get(id, userId);
}

/** Creates an item owned by `userId` and returns the stored row. */
export function create(userId: string, input: { title: string; body: string }): VaultItemRecord {
  const now = Date.now();
  const id = newId("itm");

  stmt(
    `INSERT INTO vault_items (id, user_id, title, body, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(id, userId, input.title.trim(), input.body.trim(), now, now);

  const row = findById(userId, id);
  if (!row) throw new AppError(500, "INTERNAL_ERROR", "The item could not be saved.");
  return row;
}

/**
 * Applies a partial update in a single ownership-scoped statement, so there is no window between
 * checking the owner and writing. Returns `undefined` when the item is missing or owned by
 * someone else — indistinguishable on purpose, so the vault cannot be used to probe for ids.
 */
export function update(
  userId: string,
  id: string,
  patch: { title?: string; body?: string },
): VaultItemRecord | undefined {
  const title = patch.title === undefined ? null : patch.title.trim();
  const body = patch.body === undefined ? null : patch.body.trim();

  const info = stmt(
    `UPDATE vault_items
        SET title = COALESCE(?, title), body = COALESCE(?, body), updated_at = ?
      WHERE id = ? AND user_id = ?`,
  ).run(title, body, Date.now(), id, userId);

  if (info.changes === 0) return undefined;
  return findById(userId, id);
}

/** Deletes an item the caller owns; `false` means missing *or* not theirs, so the route answers 404 either way. */
export function remove(userId: string, id: string): boolean {
  const info = stmt(`DELETE FROM vault_items WHERE id = ? AND user_id = ?`).run(id, userId);
  return info.changes > 0;
}
